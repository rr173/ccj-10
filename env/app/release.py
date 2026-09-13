"""索引版本发布管理（index version release management）。

在审计因果索引、增量派生与差异比较能力之上，管理员可以把一份**已完成**的
因果索引登记为一个逻辑**版本**，提交带**生效时间**的发布计划。系统在
**登记**与**发布（生效）**两个时刻分别冻结索引摘要、快照信息以及可选的
比较结果；计划支持延迟生效、取消、服务中断后的恢复与稳定查询。

两个冻结时刻
============
1. **登记（register）**：在同一事务里冻结
   - 索引摘要 ``frozen_index_summary``：标识、作用域、对象、历史节点、
     节点总数、链摘要、文档总校验值、核验标记；
   - 快照信息 ``frozen_snapshot``：索引的 ``snapshot_seq`` / ``node_seq``
     与登记时刻的全局 ``latest_seq``；
   - 可选比较结果 ``frozen_compare``：登记前对 ``compare_with_index_id``
     做完整（全分页）只读比较并规范化冻结，另存比较摘要 ``compare_digest``。
2. **发布（activate）**：生效时间到达后，在同一事务里再次冻结
   ``activate_index_summary`` / ``activate_snapshot`` /
   ``activate_compare``，并重算原索引当前链摘要，与登记冻结值逐一核对。

失败即终态（可解释）
====================
发布过程中发现下列任一情况，计划置为 ``failed`` 并保留 ``error_code`` /
``error_detail``（路径、双方值），绝不静默发布被掉包的索引：

- 原索引被删除 → ``release_index_deleted``；
- 原索引不再是完成态 → ``release_index_not_completed``；
- 原索引链摘要/总校验值/核验标记与登记冻结值不一致 →
  ``release_index_tampered``（从冻结节点重算的链摘要也对不上时
  ``path=index.chain_digest_recomputed``，连冻结摘要一起被伪造时给
  ``path=index.chain_digest`` 等）；
- 比较对象缺失/未完成 → ``release_compare_target_not_ready``；
- 比较结果与登记冻结结果不一致 → ``release_comparison_changed``。

幂等与冲突（显式化）
====================
- 相同版本号 + 相同幂等键：重复登记只返回同一计划（200 + ``replayed``），
  计划状态（active/cancelled/failed）也原样返回；
- 同一幂等键换索引、换生效时间或换比较对象 → 409
  ``release_id_conflict``，``first_difference`` 给出首个差异字段与双方值。
  幂等键比对先于索引存在性/完成态校验：重试把索引标识改成不存在的值
  时同样返回 409 并保留原计划标识，索引不存在（404）不改变冲突语义；
- 版本号已被别的幂等键占用 → 409 ``release_version_conflict``。
  版本别名一旦登记永不复用（已取消/已失败也不能重新登记同名版本）。

延迟生效、取消与中断恢复
========================
- ``effective_at_ms`` 晚于登记墙钟即进入 ``scheduled``：后台 worker
  （``process_due``，与归档/证据包/因果 worker 同一轮询循环）到点发布，
  查询入口也会在锁内惰性扫描，到点必生效；
- 取消只允许针对仍 ``scheduled`` 的计划（``cancel`` 对已取消幂等回放）；
- 生效时间早于登记时刻 → 登记事务内立即发布（同步得到 active/failed）；
- 服务中断（进程重启）后：启动即 ``process_due``，错过生效时间的计划在
  重启后立即发布；``failed`` 计划可用 ``retry`` 手动重新发布。

稳定查询
========
- ``GET /audit/index-versions/<version>``：只解析**冻结的索引指针**
  （发布行里的冻结摘要/快照），不读可变运行态；附带对原索引当前状态的
  只读 ``live`` 诊断（被篡改/删除时显式标注），冻结视图本身永远不变；
- ``.../chain`` / ``.../nodes/<node_id>`` / ``.../download``：版本别名
  服务前再次核对原索引当前链摘要与登记冻结值——一致则转发到该索引的
  冻结查询（被篡改/删除 → 409/404，绝不把被掉包的内容当作版本内容）；
- 旧版本仍可按原索引标识（``/audit/causal-indexes/<id>``）查询，
  发布、取消、登记与查询都**绝不修改**原索引、派生任务、租约、委托、
  审计历史、源归档或证据包（只写 ``index_releases`` 一张自有表）。
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .archive import (
    ArchiveError,
    canonical_json,
    first_diff,
)
from .audit import AuditBadRequest
from .causal import (
    STATUS_COMPLETED,
    CausalIndexManager,
    CausalNotFound,
    CausalNotReady,
)

# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class ReleaseError(ArchiveError):
    code = "index_release_error"


class ReleaseNotFound(ReleaseError):
    code = "index_release_not_found"
    status = 404


class ReleaseNotReady(ReleaseError):
    """计划尚未生效（仍 scheduled / 已取消 / 已失败）（409）。"""

    code = "index_release_not_effective"
    status = 409


class ReleaseCancelled(ReleaseError):
    code = "index_release_cancelled"
    status = 409


class ReleaseFailed(ReleaseError):
    code = "index_release_failed"
    status = 409


class ReleaseIdConflict(ReleaseError):
    """同一幂等键被索引/生效时间/比较对象不同的登记请求占用（409）。"""

    code = "release_id_conflict"
    status = 409


class ReleaseVersionConflict(ReleaseError):
    """版本号已被另一个幂等键的发布计划占用（409）。"""

    code = "release_version_conflict"
    status = 409


class ReleaseBadState(ReleaseError):
    """当前状态不允许该操作（取消/重试的状态前提不满足，409）。"""

    code = "release_bad_state"
    status = 409


class ReleaseIndexDeleted(ReleaseError):
    """原索引已被删除。

    - 发布激活时只作为失败原因落库（计划 failed，error_code 取本类 code）；
    - 版本别名服务时直接抛给客户端，按 not_found 语义返回 404。
    """

    code = "release_index_deleted"
    status = 404


class ReleaseIndexNotCompleted(ReleaseError):
    """发布时原索引不再是完成态（409）。"""

    code = "release_index_not_completed"
    status = 409


class ReleaseIndexTampered(ReleaseError):
    """发布/版本服务时原索引链摘要或内容与登记冻结值不一致（409）。"""

    code = "release_index_tampered"
    status = 409


class ReleaseCompareTargetNotReady(ReleaseError):
    """发布时比较对象缺失或不再是完成态（409）。"""

    code = "release_compare_target_not_ready"
    status = 409


class ReleaseComparisonChanged(ReleaseError):
    """发布时比较结果与登记冻结结果不一致（409）。"""

    code = "release_comparison_changed"
    status = 409


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

STATUS_SCHEDULED = "scheduled"
STATUS_ACTIVE = "active"
STATUS_CANCELLED = "cancelled"
STATUS_FAILED = "failed"
RELEASE_STATUSES = (STATUS_SCHEDULED, STATUS_ACTIVE, STATUS_CANCELLED,
                    STATUS_FAILED)

MAX_ATTEMPTS = 5

# 比较报告里的分页/只读元数据不属于冻结内容：同一对索引不同页参数、不同
# 时刻查询都应得到相同的比较摘要。
_COMPARE_META_KEYS = ("limit", "next", "next_cursor", "reached_end",
                      "total_field_changes", "read_only")


# ---------------------------------------------------------------------------
# 纯函数：指纹 / 摘要 / 规范化
# ---------------------------------------------------------------------------


def index_summary_of(row) -> dict[str, Any]:
    """从 causal_indexes 行提取登记时刻冻结的索引摘要。"""
    return {
        "index_id": row["index_id"],
        "scope": row["scope"],
        "resource": row["resource"] or None,
        "credential_id": row["credential_id"] or None,
        "package_id": row["package_id"] or None,
        "node_seq": row["node_seq"],
        "snapshot_seq": row["snapshot_seq"],
        "total_nodes": row["total_nodes"],
        "chain_digest": row["chain_digest"],
        "content_sha256": row["content_sha256"],
        "status": row["status"],
        "verify_status": row["verify_status"],
    }


def snapshot_of(row, latest_seq: int) -> dict[str, Any]:
    """登记/发布时刻冻结的快照信息。"""
    return {
        "index_id": row["index_id"],
        "snapshot_seq": row["snapshot_seq"],   # 索引创建时钉死的稳定视图上界
        "node_seq": row["node_seq"],           # 索引冻结的历史节点
        "latest_seq": latest_seq,              # 本次冻结时刻的全局最新序号
    }


def plan_fingerprint(*, version: str, index_id: str, effective_at_ms: int,
                     compare_with_index_id: str,
                     compare_digest: str | None) -> str:
    """对登记规格计算指纹（含版本、索引、生效时间、比较对象与其结果摘要）。"""
    spec = {
        "version": version,
        "index_id": index_id,
        "effective_at_ms": effective_at_ms,
        "compare_with_index_id": compare_with_index_id or None,
        "compare_digest": compare_digest,
    }
    return hashlib.sha256(canonical_json(spec).encode("utf-8")).hexdigest()


def normalize_comparison(report: dict[str, Any]) -> dict[str, Any]:
    """剥离分页元数据，只保留可比较的业务内容，键排序规范化。"""
    return {k: v for k, v in sorted(report.items())
            if k not in _COMPARE_META_KEYS}


# ---------------------------------------------------------------------------
# 管理器
# ---------------------------------------------------------------------------


class IndexReleaseManager:
    """索引版本发布计划的登记、发布、取消、重试与稳定版本查询。

    与其他管理器共用 Store 的进程锁与连接：登记时在锁内一次性冻结摘要/
    快照/比较结果，并发写入要么整体在快照之前、要么在之后。除
    ``index_releases`` 外不写任何表；比较复用差异比较能力（纯只读）。
    """

    def __init__(self, store: Any, causal: CausalIndexManager,
                 derivation: Any):
        self._store = store
        self._causal = causal
        self._derivation = derivation

    # ======================================================================
    # 登记
    # ======================================================================
    def register_release(
        self,
        *,
        version: Any,
        index_id: Any,
        idempotency_key: Any,
        effective_at_ms: Any,
        compare_with_index_id: Any = None,
    ) -> tuple[dict[str, Any], bool]:
        """登记发布计划，返回 (计划视图, 是否新建)。"""
        if not isinstance(version, str) or not version.strip():
            raise AuditBadRequest(
                "version 必填：登记后即成为不可再分配的逻辑版本别名")
        version = version.strip()
        if not isinstance(index_id, str) or not index_id.strip():
            raise AuditBadRequest("index_id 必填：必须指定一份已完成的"
                                  "因果索引作为发布对象")
        index_id = index_id.strip()
        if not isinstance(idempotency_key, str) \
                or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：相同版本号和幂等键重复登记只会"
                "得到同一个发布计划")
        key = idempotency_key.strip()
        if isinstance(effective_at_ms, bool) or effective_at_ms in (None, ""):
            raise AuditBadRequest(
                "effective_at_ms 必填：发布计划的生效墙钟时间（毫秒整数），"
                "取当前时刻或更早表示立即生效")
        try:
            effective_at = int(effective_at_ms)
        except (TypeError, ValueError):
            raise AuditBadRequest("effective_at_ms 必须是整数毫秒时间戳",
                                  effective_at_ms=effective_at_ms)

        compare_id = ""
        if compare_with_index_id not in (None, ""):
            if not isinstance(compare_with_index_id, str) \
                    or not compare_with_index_id.strip():
                raise AuditBadRequest(
                    "compare_with_index_id 必须是已完成因果索引的标识")
            compare_id = compare_with_index_id.strip()

        store = self._store
        with store._lock:  # noqa: SLF001 - 与其他管理器共用同一把锁
            conn = store._conn  # noqa: SLF001
            # 到点计划先惰性发布：同键回放也必须返回计划的当前（生效后）
            # 状态，而不是登记瞬间的 scheduled 快照
            self._sweep_due_locked(conn)

            # 幂等键先行：同键即回放或显式冲突。规格比对必须先于发布对象
            # 的存在性/完成态校验——重试若把索引标识改成不存在的值，也必须
            # 按首次登记的规格判定冲突（409 release_id_conflict，保留原
            # 计划标识），不能让"索引不存在"（404）改变冲突语义
            prev = conn.execute(
                "SELECT * FROM index_releases WHERE idempotency_key=?",
                (key,)).fetchone()
            if prev is not None:
                diff = self._first_spec_diff(
                    prev, version, index_id, effective_at, compare_id)
                # 标量规格一致且带比较对象：比较结果摘要也必须仍与首次
                # 登记一致（比较对象在两次登记间被改动时同键也必须显式
                # 冲突，绝不静默换成另一份比较结果）。摘要需重算比较，
                # 只在标量一致后核对
                if diff is None and compare_id \
                        and prev["compare_digest"] is not None:
                    current = self._full_comparison_locked(
                        conn, index_id, compare_id)
                    if prev["compare_digest"] != current["_digest"]:
                        diff = {"path": "compare_digest",
                                "field": "compare_digest",
                                "existing": prev["compare_digest"],
                                "requested": current["_digest"]}
                if diff is None:
                    return self._view(prev), False
                raise ReleaseIdConflict(
                    f"幂等键 {key} 已用于发布计划 {prev['release_id']}"
                    f"（版本 {prev['version']}），本次请求与首次登记不"
                    f"一致：首个差异位于 {diff['path']}",
                    release_id=prev["release_id"],
                    existing_version=prev["version"],
                    first_difference=diff)

            # 发布对象必须存在且已完成（登记即要求，延迟期间其变化在发布时
            # 再复核；比较对象同此规则，登记时也必须已完成）
            index_row = conn.execute(
                "SELECT * FROM causal_indexes WHERE index_id=?",
                (index_id,)).fetchone()
            if index_row is None:
                raise CausalNotFound(
                    f"要发布的因果索引 {index_id} 不存在，无法登记版本",
                    index_id=index_id)
            if index_row["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"要发布的因果索引 {index_id} 尚未生成完成（当前状态 "
                    f"{index_row['status']}），只有已完成的索引才能登记"
                    "发布计划",
                    index_id=index_id, status=index_row["status"])

            comparison = None
            compare_digest = None
            if compare_id:
                comparison = self._full_comparison_locked(
                    conn, index_id, compare_id)
                compare_digest = comparison["_digest"]

            now = store.clock.wall_ms()

            # 版本别名全局唯一：换索引/换生效时间/换比较对象必须明确冲突，
            # 已取消/已失败的版本号也不能再分配
            prev_version = conn.execute(
                "SELECT * FROM index_releases WHERE version=?",
                (version,)).fetchone()
            if prev_version is not None:
                raise ReleaseVersionConflict(
                    f"版本号 {version} 已被发布计划 "
                    f"{prev_version['release_id']}（幂等键 "
                    f"{prev_version['idempotency_key']}，状态 "
                    f"{prev_version['status']}）占用：版本别名一旦登记即"
                    "不可再分配，换索引、换生效时间或换比较对象必须使用"
                    "新版本号；重复提交请使用原幂等键",
                    version=version,
                    release_id=prev_version["release_id"],
                    existing_idempotency_key=
                    prev_version["idempotency_key"],
                    existing_status=prev_version["status"])

            latest = conn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            latest_seq = int(latest["m"]) if latest["m"] is not None else 0
            frozen_summary = index_summary_of(index_row)
            frozen_snapshot = snapshot_of(index_row, latest_seq)
            fingerprint = plan_fingerprint(
                version=version, index_id=index_id,
                effective_at_ms=effective_at,
                compare_with_index_id=compare_id,
                compare_digest=compare_digest)

            release_id = uuid.uuid4().hex
            logical = store.clock.logical()
            status = STATUS_SCHEDULED
            conn.execute(
                "INSERT INTO index_releases(release_id, version, "
                "idempotency_key, index_id, effective_at_ms, status, "
                "plan_fingerprint, frozen_index_summary_json, "
                "frozen_snapshot_json, frozen_compare_json, "
                "compare_with_index_id, compare_digest, attempts, "
                "created_logical, created_at_ms, updated_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (release_id, version, key, index_id, effective_at, status,
                 fingerprint, canonical_json(frozen_summary),
                 canonical_json(frozen_snapshot),
                 canonical_json(comparison["report"]) if comparison else None,
                 compare_id, compare_digest, 0, logical, now, now))

            # 生效时间已到（含过去）：登记事务内立即发布，同步得到
            # active/failed；否则保持 scheduled 等待 worker/惰性扫描
            row = self._get_row(conn, release_id)
            if effective_at <= now:
                self._activate_locked(conn, row)
                row = self._get_row(conn, release_id)
            conn.commit()
            return self._view(row), True

    @staticmethod
    def _first_spec_diff(prev, version, index_id, effective_at,
                         compare_id) -> dict | None:
        """比较登记规格的标量字段，返回首个差异字段（路径/双方值）。

        只比对请求报文直接给出的字段，不访问索引现态：同键重试即使指向
        不存在的索引，也必须在此显式冲突。比较结果摘要（compare_digest）
        需重算比较才能核对，由调用方在标量一致后补充。
        """
        checks = [
            ("version", prev["version"], version),
            ("index_id", prev["index_id"], index_id),
            ("effective_at_ms", prev["effective_at_ms"], effective_at),
            ("compare_with_index_id",
             prev["compare_with_index_id"] or "", compare_id),
        ]
        for field, old, new in checks:
            if old != new:
                return {"path": field, "field": field,
                        "existing": old, "requested": new}
        return None

    def _full_comparison_locked(self, conn, a_index_id: str,
                                 b_index_id: str) -> dict[str, Any]:
        """对两份已完成索引做完整（全分页）只读比较并规范化冻结。

        复用差异比较能力；其源存在性/完成态校验在此提前给出发布语义的
        明确错误（比较对象未完成时计划要失败并保留可解释原因；登记阶段
        同样不允许指向未完成对象）。
        """
        target = conn.execute(
            "SELECT * FROM causal_indexes WHERE index_id=?",
            (b_index_id,)).fetchone()
        if target is None:
            raise CausalNotFound(
                f"比较对象索引 {b_index_id} 不存在，无法冻结比较结果",
                index_id=b_index_id)
        if target["status"] != STATUS_COMPLETED:
            raise CausalNotReady(
                f"比较对象索引 {b_index_id} 尚未生成完成（当前状态 "
                f"{target['status']}）：比较对象必须已完成才能随版本"
                "发布计划冻结比较结果",
                index_id=b_index_id, status=target["status"])

        # 拉全部分页：比较 API 的游标是变化项序号（-1 起，after 之后取下
        # 一页），与因果链分页同语义
        pages: list[dict[str, Any]] = []
        cursor = -1
        while True:
            page = self._derivation._compare_indexes_conn(  # noqa: SLF001
                conn, a_index_id, b_index_id, cursor, 1000)
            pages.append(page)
            if page["reached_end"]:
                break
            cursor = page["next_cursor"]

        first = pages[0]
        changes: list[dict[str, Any]] = []
        for p in pages:
            changes.extend(p["field_changes"])
        # 防御性去重（分页边界若重叠一条）并按稳定顺序排列
        dedup: dict[tuple, dict[str, Any]] = {}
        for ch in changes:
            dedup[(ch["node_id"], ch["path"])] = ch
        changes = sorted(dedup.values(),
                         key=lambda c: (c["position_a"], c["node_id"],
                                        c["path"]))
        merged = dict(first)
        merged["field_changes"] = changes
        merged["total_field_changes"] = first["total_field_changes"]
        merged["reached_end"] = True
        merged["next"] = None
        merged["next_cursor"] = None
        merged["limit"] = 1000
        normalized = normalize_comparison(merged)
        return {"report": normalized,
                "_digest": hashlib.sha256(
                    canonical_json(normalized).encode("utf-8")
                ).hexdigest()}

    # ======================================================================
    # 发布（生效）：登记事务内立即发布 / worker 到点发布 / 惰性扫描
    # ======================================================================
    def process_due(self, *, now_ms: int | None = None) -> int:
        """发布所有 effective_at_ms 已到且仍 scheduled 的计划。

        每个计划独立事务：单个计划失败置 failed 并保留原因，不影响其它
        计划。返回本次发布的计划数（成功或失败都算处理过）。
        """
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            now = now_ms if now_ms is not None else store.clock.wall_ms()
            rows = conn.execute(
                "SELECT release_id FROM index_releases WHERE status=? "
                "AND effective_at_ms<=? ORDER BY effective_at_ms ASC, "
                "release_id ASC", (STATUS_SCHEDULED, now)).fetchall()
            conn.rollback()
        n = 0
        for r in rows:
            if self._activate_by_id(r["release_id"]):
                n += 1
        return n

    def _activate_by_id(self, release_id: str) -> bool:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, release_id)
            if row is None or row["status"] != STATUS_SCHEDULED:
                return False
            self._activate_locked(conn, row)
            conn.commit()
            return True

    def _activate_locked(self, conn, row) -> None:
        """把一个 scheduled 计划发布为 active；任何复核失败置 failed。

        调用方已持锁、负责外层 commit。复核顺序（首个失败即终态，并把
        可解释的 error_code / error_detail 落库）：
        1. 原索引存在、仍是完成态；
        2. 原索引链摘要/总校验值/节点数/核验标记与登记冻结摘要一致，
           且从冻结节点重算的链摘要也一致（连行内摘要一起被伪造时显形）；
        3. 比较对象仍存在且完成，比较结果与登记冻结结果逐项一致。
        """
        release_id = row["release_id"]
        now = self._store.clock.wall_ms()
        try:
            failure = self._activation_failure_locked(conn, row, now)
        except Exception as exc:  # noqa: BLE001 - 任何意外都留可解释原因
            failure = {
                "code": ReleaseIndexTampered.code,
                "message": f"发布复核时发生异常：{type(exc).__name__}: {exc}",
                "detail": {"path": "activation", "message": str(exc)},
            }
        if failure is not None:
            conn.execute(
                "UPDATE index_releases SET status=?, attempts=attempts+1, "
                "error=?, error_code=?, error_detail_json=?, failed_at_ms=?, "
                "updated_at_ms=? WHERE release_id=?",
                (STATUS_FAILED, failure["message"], failure["code"],
                 canonical_json(failure["detail"]), now, now, release_id))
            return

        # 全部复核通过：冻结发布时刻的摘要/快照/比较结果并置 active
        index_row = conn.execute(
            "SELECT * FROM causal_indexes WHERE index_id=?",
            (row["index_id"],)).fetchone()
        latest = conn.execute(
            "SELECT MAX(seq) AS m FROM lease_events").fetchone()
        latest_seq = int(latest["m"]) if latest["m"] is not None else 0
        activate_summary = index_summary_of(index_row)
        activate_snapshot = snapshot_of(index_row, latest_seq)
        recomputed_digest = self._recompute_chain_digest_locked(
            conn, row["index_id"])
        activate_compare = None
        if row["compare_with_index_id"]:
            comp = self._full_comparison_locked(
                conn, row["index_id"], row["compare_with_index_id"])
            activate_compare = comp["report"]
        conn.execute(
            "UPDATE index_releases SET status=?, attempts=attempts+1, "
            "activate_index_summary_json=?, activate_snapshot_json=?, "
            "activate_compare_json=?, activate_index_chain_digest=?, "
            "activated_at_ms=?, failed_at_ms=NULL, error=NULL, "
            "error_code=NULL, error_detail_json=NULL, updated_at_ms=? "
            "WHERE release_id=?",
            (STATUS_ACTIVE, canonical_json(activate_summary),
             canonical_json(activate_snapshot),
             canonical_json(activate_compare)
             if activate_compare is not None else None,
             recomputed_digest, now, now, release_id))

    def _activation_failure_locked(self, conn, row, now) -> dict | None:
        """返回首个失败描述 {code, message, detail}；全部通过返回 None。"""
        frozen = json.loads(row["frozen_index_summary_json"])
        index_row = conn.execute(
            "SELECT * FROM causal_indexes WHERE index_id=?",
            (row["index_id"],)).fetchone()
        if index_row is None:
            return {
                "code": ReleaseIndexDeleted.code,
                "message": f"发布失败：原索引 {row['index_id']} 在发布时"
                           "已被删除",
                "detail": {"path": "index.index_id",
                           "frozen": row["index_id"], "current": "<missing>"}}
        if index_row["status"] != STATUS_COMPLETED:
            return {
                "code": ReleaseIndexNotCompleted.code,
                "message": f"发布失败：原索引 {row['index_id']} 在发布时不"
                           f"再是完成态（当前 {index_row['status']}）",
                "detail": {"path": "index.status",
                           "frozen": STATUS_COMPLETED,
                           "current": index_row["status"]}}

        current = index_summary_of(index_row)
        # 1) 行内冻结字段逐项比对（登记后这些列若被改动在此显形）
        for field in ("scope", "resource", "credential_id", "package_id",
                      "node_seq", "snapshot_seq", "total_nodes",
                      "chain_digest", "content_sha256", "verify_status"):
            if current[field] != frozen[field]:
                return {
                    "code": ReleaseIndexTampered.code,
                    "message": f"发布失败：原索引 {row['index_id']} 的 "
                               f"{field} 与登记冻结值不一致，索引在发布前"
                               "可能被篡改",
                    "detail": {"path": f"index.{field}",
                               "frozen": frozen[field],
                               "current": current[field]}}

        # 2) 从冻结节点独立重算链摘要：连行内 chain_digest 一起被伪造时
        #    仍能发现（重算值同时应等于行内值与登记冻结值）
        recomputed = self._recompute_chain_digest_locked(
            conn, row["index_id"])
        if recomputed != frozen["chain_digest"]:
            return {
                "code": ReleaseIndexTampered.code,
                "message": f"发布失败：从冻结节点重算的原索引 "
                           f"{row['index_id']} 链摘要与登记冻结值不一致，"
                           "索引节点载荷可能被篡改",
                "detail": {"path": "index.chain_digest_recomputed",
                           "frozen": frozen["chain_digest"],
                           "current": recomputed}}

        # 3) 比较对象与比较结果
        if row["compare_with_index_id"]:
            cmp_id = row["compare_with_index_id"]
            target = conn.execute(
                "SELECT * FROM causal_indexes WHERE index_id=?",
                (cmp_id,)).fetchone()
            if target is None:
                return {
                    "code": ReleaseCompareTargetNotReady.code,
                    "message": f"发布失败：比较对象索引 {cmp_id} 在发布时"
                               "已不存在",
                    "detail": {"path": "comparison.compare_with_index_id",
                               "frozen": cmp_id, "current": "<missing>"}}
            if target["status"] != STATUS_COMPLETED:
                return {
                    "code": ReleaseCompareTargetNotReady.code,
                    "message": f"发布失败：比较对象索引 {cmp_id} 在发布时"
                               f"不再是完成态（{target['status']}）",
                    "detail": {"path": "comparison.status",
                               "frozen": STATUS_COMPLETED,
                               "current": target["status"]}}
            try:
                comp = self._full_comparison_locked(
                    conn, row["index_id"], cmp_id)
            except (CausalNotFound, CausalNotReady) as exc:
                return {
                    "code": ReleaseCompareTargetNotReady.code,
                    "message": f"发布失败：比较对象不可用——{exc}",
                    "detail": {"path": "comparison", "message": str(exc)}}
            frozen_compare = json.loads(row["frozen_compare_json"])
            diff = first_diff(frozen_compare, comp["report"], "comparison")
            if diff is not None:
                return {
                    "code": ReleaseComparisonChanged.code,
                    "message": "发布失败：比较结果与登记时冻结的结果不"
                               f"一致，首个差异位于 {diff['path']}",
                    "detail": diff}
        return None

    @staticmethod
    def _recompute_chain_digest_locked(conn, index_id: str) -> str | None:
        """从冻结成员/节点表按因果顺序独立重算索引链摘要。

        与 CausalIndexManager._compute_chain_digest 同算法；节点缺失
        （索引行还在但冻结节点被删）返回 None。
        """
        rows = conn.execute(
            "SELECT n.payload AS payload FROM causal_index_nodes n "
            "JOIN causal_index_members m ON m.index_id=n.index_id "
            "AND m.node_id=n.node_id WHERE n.index_id=? "
            "ORDER BY m.position ASC", (index_id,)).fetchall()
        total_row = conn.execute(
            "SELECT total_nodes FROM causal_indexes WHERE index_id=?",
            (index_id,)).fetchone()
        if total_row is None:
            return None
        if len(rows) != int(total_row["total_nodes"]):
            return None
        nodes = [json.loads(r["payload"]) for r in rows]
        return CausalIndexManager._compute_chain_digest(nodes)  # noqa: SLF001

    # ======================================================================
    # 取消 / 重试
    # ======================================================================
    def cancel_release(self, release_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            # 到点的计划先惰性发布，绝不允许取消一个实际已生效的版本
            self._sweep_due_locked(conn)
            row = self._get_row(conn, release_id)
            if row is None:
                raise ReleaseNotFound(
                    f"发布计划 {release_id} 不存在", release_id=release_id)
            if row["status"] == STATUS_CANCELLED:
                # 幂等：重复取消直接回放当前状态
                return self._view(row)
            if row["status"] == STATUS_ACTIVE:
                raise ReleaseBadState(
                    f"发布计划 {release_id}（版本 {row['version']}）已经"
                    "生效，生效版本不可取消",
                    release_id=release_id, status=row["status"])
            if row["status"] == STATUS_FAILED:
                raise ReleaseBadState(
                    f"发布计划 {release_id}（版本 {row['version']}）已经"
                    "失败，取消没有意义；可用 retry 重新发布",
                    release_id=release_id, status=row["status"])
            now = store.clock.wall_ms()
            conn.execute(
                "UPDATE index_releases SET status=?, cancelled_at_ms=?, "
                "updated_at_ms=? WHERE release_id=?",
                (STATUS_CANCELLED, now, now, release_id))
            conn.commit()
            return self._view(self._get_row(conn, release_id))

    def retry_release(self, release_id: str) -> dict[str, Any]:
        """failed 计划重新发布：立即再复核一次（不改变生效时间）。"""
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, release_id)
            if row is None:
                raise ReleaseNotFound(
                    f"发布计划 {release_id} 不存在", release_id=release_id)
            if row["status"] != STATUS_FAILED:
                raise ReleaseBadState(
                    f"发布计划 {release_id} 当前状态为 {row['status']}，"
                    "只有 failed 的计划需要重试；scheduled 计划会在生效"
                    "时间自动发布",
                    release_id=release_id, status=row["status"])
            # 回到 scheduled 后立即发布（其 effective_at_ms 必已过去）
            now = store.clock.wall_ms()
            conn.execute(
                "UPDATE index_releases SET status=?, error=NULL, "
                "error_code=NULL, error_detail_json=NULL, failed_at_ms=NULL, "
                "updated_at_ms=? WHERE release_id=?",
                (STATUS_SCHEDULED, now, release_id))
            conn.commit()
            row = self._get_row(conn, release_id)
            self._activate_locked(conn, row)
            conn.commit()
            return self._view(self._get_row(conn, release_id))

    # ======================================================================
    # 查询
    # ======================================================================
    @staticmethod
    def _get_row(conn, release_id):
        return conn.execute(
            "SELECT * FROM index_releases WHERE release_id=?",
            (release_id,)).fetchone()

    def _get_version_row(self, conn, version: str):
        return conn.execute(
            "SELECT * FROM index_releases WHERE version=?",
            (version,)).fetchone()

    def get_release(self, release_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._sweep_due_locked(conn)
            row = self._get_row(conn, release_id)
            if row is None:
                raise ReleaseNotFound(
                    f"发布计划 {release_id} 不存在", release_id=release_id)
            try:
                return self._view(row)
            finally:
                conn.rollback()

    def get_release_by_version(self, version: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._sweep_due_locked(conn)
            row = self._get_version_row(conn, version)
            if row is None:
                raise ReleaseNotFound(
                    f"版本 {version} 没有对应的发布计划", version=version)
            try:
                return self._view(row)
            finally:
                conn.rollback()

    def list_releases(self, *, status=None, version=None, index_id=None,
                      limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        if status is not None and status not in RELEASE_STATUSES:
            raise AuditBadRequest(
                "status 只能取 scheduled/active/cancelled/failed",
                status=status)
        where, args = [], []
        if status:
            where.append("status=?")
            args.append(status)
        if version:
            where.append("version=?")
            args.append(str(version))
        if index_id:
            where.append("index_id=?")
            args.append(str(index_id))
        sql = "SELECT * FROM index_releases"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at_ms ASC, release_id ASC LIMIT ?"
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._sweep_due_locked(conn)
            rows = conn.execute(sql, (*args, limit)).fetchall()
            try:
                return {"releases": [self._view(r) for r in rows],
                        "limit": limit}
            finally:
                conn.rollback()

    def _view(self, row) -> dict[str, Any]:
        return {
            "release_id": row["release_id"],
            "version": row["version"],
            "idempotency_key": row["idempotency_key"],
            "index_id": row["index_id"],
            "effective_at_ms": row["effective_at_ms"],
            "status": row["status"],
            "plan_fingerprint": row["plan_fingerprint"],
            "frozen_index_summary":
                json.loads(row["frozen_index_summary_json"]),
            "frozen_snapshot": json.loads(row["frozen_snapshot_json"]),
            "frozen_comparison": (json.loads(row["frozen_compare_json"])
                                  if row["frozen_compare_json"] else None),
            "compare_with_index_id": row["compare_with_index_id"] or None,
            "compare_digest": row["compare_digest"],
            "activate_index_summary":
                (json.loads(row["activate_index_summary_json"])
                 if row["activate_index_summary_json"] else None),
            "activate_snapshot":
                (json.loads(row["activate_snapshot_json"])
                 if row["activate_snapshot_json"] else None),
            "activate_comparison":
                (json.loads(row["activate_compare_json"])
                 if row["activate_compare_json"] else None),
            "activate_index_chain_digest":
                row["activate_index_chain_digest"],
            "attempts": row["attempts"],
            "error": row["error"],
            "error_code": row["error_code"],
            "error_detail": (json.loads(row["error_detail_json"])
                             if row["error_detail_json"] else None),
            "created_logical": row["created_logical"],
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
            "activated_at_ms": row["activated_at_ms"],
            "cancelled_at_ms": row["cancelled_at_ms"],
            "failed_at_ms": row["failed_at_ms"],
            "effective_now": row["status"] == STATUS_ACTIVE,
            "chain_url": f"/audit/index-versions/{row['version']}/chain",
            "download_url":
                f"/audit/index-versions/{row['version']}/download",
        }

    # ---- 版本别名：稳定查询 ---------------------------------------------
    def resolve_version(self, version: str) -> dict[str, Any]:
        """按版本别名解析冻结的索引指针（稳定查询入口）。

        响应主体只来自发布行冻结字段，永远不随后续变化漂移；另附对原索引
        当前状态的只读 ``live`` 诊断（被篡改/删除显式标注，但不改变冻结
        视图）。
        """
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._sweep_due_locked(conn)
            row = self._get_version_row(conn, version)
            if row is None:
                raise ReleaseNotFound(
                    f"版本 {version} 没有对应的发布计划", version=version)
            if row["status"] == STATUS_SCHEDULED:
                raise ReleaseNotReady(
                    f"版本 {version} 的发布计划尚未生效（生效时间 "
                    f"{row['effective_at_ms']}）",
                    version=version, effective_at_ms=row["effective_at_ms"])
            if row["status"] == STATUS_CANCELLED:
                raise ReleaseCancelled(
                    f"版本 {version} 的发布计划已被取消",
                    version=version,
                    cancelled_at_ms=row["cancelled_at_ms"])
            if row["status"] == STATUS_FAILED:
                raise ReleaseFailed(
                    f"版本 {version} 的发布计划已失败：{row['error']}",
                    version=version, error_code=row["error_code"],
                    error_detail=json.loads(row["error_detail_json"])
                    if row["error_detail_json"] else None)
            live = self._live_index_state(conn, row)
            try:
                return {
                    "version": version,
                    "release_id": row["release_id"],
                    "status": row["status"],
                    "effective_at_ms": row["effective_at_ms"],
                    "activated_at_ms": row["activated_at_ms"],
                    # 冻结指针：别名只指向发布时冻结的索引
                    "index": {
                        "index_id": row["index_id"],
                        "frozen": json.loads(
                            row["activate_index_summary_json"]
                            or row["frozen_index_summary_json"]),
                        "snapshot": json.loads(
                            row["activate_snapshot_json"]
                            or row["frozen_snapshot_json"]),
                        "activate_chain_digest":
                            row["activate_index_chain_digest"],
                    },
                    "comparison": {
                        "compare_with_index_id":
                            row["compare_with_index_id"] or None,
                        "compare_digest": row["compare_digest"],
                        "frozen": json.loads(row["activate_compare_json"])
                        if row["activate_compare_json"]
                        else (json.loads(row["frozen_compare_json"])
                              if row["frozen_compare_json"] else None),
                    },
                    # 对原索引当前状态的只读诊断（不改变冻结视图的稳定性）
                    "live": live,
                    "stable": live["state"] == "intact",
                    "read_only": True,
                }
            finally:
                conn.rollback()

    def _live_index_state(self, conn, row) -> dict[str, Any]:
        """只读核对原索引当前状态（存在/完成/链摘要是否仍是冻结值）。"""
        index_row = conn.execute(
            "SELECT * FROM causal_indexes WHERE index_id=?",
            (row["index_id"],)).fetchone()
        if index_row is None:
            return {"state": "deleted", "index_id": row["index_id"],
                    "message": "原索引已被删除；版本冻结视图仍可独立解析，"
                               "但链路服务不可用"}
        recomputed = self._recompute_chain_digest_locked(
            conn, row["index_id"])
        frozen_digest = row["activate_index_chain_digest"]
        intact = (index_row["status"] == STATUS_COMPLETED
                  and recomputed == frozen_digest
                  and index_row["chain_digest"] == frozen_digest)
        if intact:
            return {"state": "intact", "index_id": row["index_id"],
                    "status": index_row["status"],
                    "chain_digest": frozen_digest,
                    "message": "原索引当前链摘要与版本冻结值一致"}
        return {"state": "tampered", "index_id": row["index_id"],
                "status": index_row["status"],
                "frozen_chain_digest": frozen_digest,
                "current_chain_digest": recomputed,
                "stored_chain_digest": index_row["chain_digest"],
                "message": "原索引当前内容与版本冻结值不一致：链路服务"
                           "拒绝把被改动的内容当作版本内容"}

    def _require_active_index_intact(self, conn, version: str):
        """版本别名服务（chain/nodes/download）前的完整性闸门。

        返回发布行；原索引被删/被篡改时给明确 409/404，绝不静默转发被
        掉包的内容。
        """
        row = self._get_version_row(conn, version)
        if row is None:
            raise ReleaseNotFound(
                f"版本 {version} 没有对应的发布计划", version=version)
        if row["status"] == STATUS_SCHEDULED:
            raise ReleaseNotReady(
                f"版本 {version} 的发布计划尚未生效（生效时间 "
                f"{row['effective_at_ms']}）",
                version=version, effective_at_ms=row["effective_at_ms"])
        if row["status"] == STATUS_CANCELLED:
            raise ReleaseCancelled(
                f"版本 {version} 的发布计划已被取消", version=version)
        if row["status"] == STATUS_FAILED:
            raise ReleaseFailed(
                f"版本 {version} 的发布计划已失败：{row['error']}",
                version=version, error_code=row["error_code"])
        index_row = conn.execute(
            "SELECT * FROM causal_indexes WHERE index_id=?",
            (row["index_id"],)).fetchone()
        if index_row is None:
            raise ReleaseIndexDeleted(
                f"版本 {version} 指向的原索引 {row['index_id']} 已被"
                "删除：版本别名无法提供链路服务（冻结指针见 "
                "GET /audit/index-versions/<version>）",
                version=version, index_id=row["index_id"])
        if index_row["status"] != STATUS_COMPLETED:
            raise ReleaseIndexNotCompleted(
                f"版本 {version} 指向的原索引 {row['index_id']} 当前不"
                f"再是完成态（{index_row['status']}）：拒绝按版本别名"
                "提供内容",
                version=version, index_id=row["index_id"],
                status=index_row["status"])
        recomputed = self._recompute_chain_digest_locked(
            conn, row["index_id"])
        frozen_digest = row["activate_index_chain_digest"]
        # 节点表被删/不全导致无法重算：等同原索引缺失/被破坏
        if recomputed is None:
            raise ReleaseIndexDeleted(
                f"版本 {version} 指向的原索引 {row['index_id']} 的冻结"
                "节点已缺失：版本别名无法提供链路服务",
                version=version, index_id=row["index_id"])
        if recomputed != frozen_digest \
                or index_row["chain_digest"] != frozen_digest:
            raise ReleaseIndexTampered(
                f"版本 {version} 指向的原索引 {row['index_id']} 当前链"
                "摘要与发布冻结值不一致：拒绝按版本别名提供被改动的内容",
                version=version, index_id=row["index_id"],
                frozen_chain_digest=frozen_digest,
                current_chain_digest=recomputed,
                first_difference={
                    "path": "index.chain_digest",
                    "frozen": frozen_digest,
                    "current": recomputed})
        return row

    def version_chain(self, version: str, *, after=None,
                      limit: Any = 100) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._sweep_due_locked(conn)
            row = self._require_active_index_intact(conn, version)
            result = self._causal.get_chain(
                row["index_id"], after=after, limit=limit)
            conn.rollback()
        result["version"] = version
        result["release_id"] = row["release_id"]
        result["served_index_id"] = row["index_id"]
        result["frozen_at_ms"] = row["activated_at_ms"]
        return result

    def version_node(self, version: str, node_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._sweep_due_locked(conn)
            row = self._require_active_index_intact(conn, version)
            result = self._causal.get_frozen_node(row["index_id"], node_id)
            conn.rollback()
        result["version"] = version
        result["release_id"] = row["release_id"]
        result["served_index_id"] = row["index_id"]
        return result

    def version_download(self, version: str) -> tuple[str, dict[str, Any]]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._sweep_due_locked(conn)
            row = self._require_active_index_intact(conn, version)
            result = self._causal.download(row["index_id"])
            conn.rollback()
        text, view = result
        view = dict(view)
        view["version"] = version
        view["release_id"] = row["release_id"]
        view["served_index_id"] = row["index_id"]
        view["frozen_at_ms"] = row["activated_at_ms"]
        return text, view

    # ---- 到点惰性扫描 ---------------------------------------------------
    def _sweep_due_locked(self, conn) -> int:
        """查询入口在锁内把到点的 scheduled 计划发布掉。

        保证即使后台 worker 轮询间隙（或服务中断重启后首个请求）也能稳定
        # 观察到"到点必生效"；只写 index_releases 自有表。
        """
        now = self._store.clock.wall_ms()
        rows = conn.execute(
            "SELECT release_id FROM index_releases WHERE status=? "
            "AND effective_at_ms<=? ORDER BY effective_at_ms ASC, "
            "release_id ASC", (STATUS_SCHEDULED, now)).fetchall()
        n = 0
        for r in rows:
            cur = self._get_row(conn, r["release_id"])
            self._activate_locked(conn, cur)
            n += 1
        if n:
            conn.commit()
        return n


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _as_int(value, name: str, *, default=None):
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise AuditBadRequest(f"参数 {name} 必须是整数", **{name: value})


def _bounded_limit(value) -> int:
    limit = _as_int(value, "limit", default=100)
    if limit < 1:
        raise AuditBadRequest("limit 必须 >= 1", limit=limit)
    return min(limit, 1000)
