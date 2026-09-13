"""因果索引增量派生与索引差异比较（incremental derivation & index diff）。

在已完成的**审计因果索引**之上提供两类管理员能力：

1. **增量派生**：指定一份已完成因果索引作为基线，在新的冻结快照上派生一条
   新链。创建时一次性冻结新的 ``snapshot_seq``、范围与过滤条件，并把基线的
   快照信息（``baseline_snapshot_seq`` / ``baseline_node_seq`` /
   ``baseline_chain_digest`` / ``baseline_content_sha256`` / 基线节点总数）
   原样保留；成员集合在创建事务里分类落库：

   - ``reused``：基线中仍然有效的节点。其载荷体从基线的冻结节点副本**逐字
     节复制**，只重盖链环字段（position / prev / next），因此基线之后源数据
     再被改动也污染不了派生链；
   - ``added``：基线快照之后才出现的新事件、新源归档、新证据包条目，由冻结
     的审计事件与归档清单重建；
   - 基线有而新范围不再包含的节点计入 ``removed``（例如过滤变窄）。

2. **差异比较**：对任意两份**已完成**索引做纯只读比较，返回共同节点、首个
   分叉位置、各自新增/缺失节点与逐字段变化（每项都带节点标识与双方值）。

冻结与不可变性
==============
派生任务创建后，基线或源数据在生成期间发生任何变化都不能改写已冻结的派生
链：复用节点的载荷来自基线冻结副本而非实时源；新增节点在生成时再次核对源
完整性（源归档/证据包条目缺失或哈希与成员冻结描述不一致即判失败，绝不静默
收录被掉包的内容）。基线链摘要在定稿与核验时都会重算并与创建时冻结值比对，
基线被篡改会得到明确的差异报告。

幂等与冲突
==========
- 同基线、同范围、同快照节点、同过滤、同幂等键重复提交 → 同一派生任务
  （HTTP 200 + ``replayed``）；
- 同幂等键换基线/换快照节点/换范围/换过滤 → 409
  ``causal_derivation_id_conflict``，给出首个差异字段与双方值；
- 同基线+同节点+同过滤但换幂等键 → 409 ``causal_derivation_spec_conflict``，
  同一派生规格不允许产生两份互相独立的"原件"。

生成控制
========
后台 worker 按块还原节点（``CAUSAL_DERIVATION_CHUNK_SIZE`` 个成员/块），
每块一个事务、进度落库；服务重启或失败后从已保存位置继续，节点表主键
``(derivation_id, node_id)`` + ``INSERT OR IGNORE`` 保证重试不重复写入。
另支持显式暂停（``paused``，worker 跳过）与暂停后恢复（回到 ``pending``）；
``failed`` 任务可手动复位重试（进度保留）。

只读边界
========
本模块只写 causal_derivations / causal_derivation_members /
causal_derivation_nodes 三张自有表；比较、派生、查询、暂停/恢复与重试都
绝不修改原索引、租约、委托、审计历史、源归档或证据包。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from .archive import (
    ArchiveError,
    canonical_json,
    content_sha256,
    first_diff,
)
from .audit import AuditBadRequest, NodeOutOfRange, event_dict, project
from .causal import (
    LAYER,
    MAX_ATTEMPTS,
    NODE_ARCHIVE,
    NODE_DELEGATION,
    NODE_EVIDENCE_ENTRY,
    SCOPE_EVIDENCE,
    STATUS_BUILDING,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    CausalIndexManager,
    CausalNotFound,
    CausalNotReady,
    archive_node_id,
    evidence_entry_node_id,
    member_sort_key,
    normalize_filters,
    payload_sha,
)

# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class DerivationError(ArchiveError):
    code = "causal_derivation_error"


class DerivationNotFound(DerivationError):
    code = "causal_derivation_not_found"
    status = 404


class DerivationNotReady(DerivationError):
    code = "causal_derivation_not_ready"
    status = 409


class DerivationBaselineNotFound(DerivationError):
    """基线因果索引不存在（404）。"""

    code = "causal_derivation_baseline_not_found"
    status = 404


class DerivationBaselineNotReady(DerivationError):
    """基线因果索引尚未完成，不能作为派生基线（409）。"""

    code = "causal_derivation_baseline_not_ready"
    status = 409


class DerivationIdConflict(DerivationError):
    """同一幂等键被规格不同的派生请求占用（409）。"""

    code = "causal_derivation_id_conflict"
    status = 409


class DerivationSpecConflict(DerivationError):
    """同一派生规格（基线+节点+过滤）已用别的幂等键创建过（409）。"""

    code = "causal_derivation_spec_conflict"
    status = 409


class DerivationBadState(DerivationError):
    """当前状态不允许该操作（暂停/恢复/重试的状态前提不满足，409）。"""

    code = "causal_derivation_bad_state"
    status = 409


class DerivationSourceChanged(DerivationError):
    """新增节点的源数据在创建后缺失或被篡改（生成失败，409 级明确错误）。"""

    code = "causal_derivation_source_changed"
    status = 409


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

STATUS_PAUSED = "paused"
DERIVATION_STATUSES = (STATUS_PENDING, STATUS_BUILDING, STATUS_PAUSED,
                       STATUS_COMPLETED, STATUS_FAILED)

VERIFY_UNVERIFIED = "unverified"
VERIFY_VERIFIED = "verified"
VERIFY_FAILED = "verify_failed"

ORIGIN_REUSED = "reused"
ORIGIN_ADDED = "added"

DERIVATION_CHAIN_V1 = "sha256-causal-derivation-chain-v1"
_MISSING = "<missing>"

# 链上字段不属于节点载荷体：复用基线节点时只重盖这三个字段
_LINK_FIELDS = ("position", "prev_node_id", "next_node_id")


def derivation_seed() -> str:
    return hashlib.sha256(
        b"lease-audit-causal-derivation-chain-v1").hexdigest()


# ---------------------------------------------------------------------------
# 纯函数：规格指纹 / 派生链摘要 / 差异叶子收集
# ---------------------------------------------------------------------------


def spec_fingerprint(*, baseline_index_id: str, scope: str, resource: str,
                     credential_id: str, package_id: str, node_seq: int,
                     filt: dict[str, Any]) -> str:
    """对创建者可控的派生规格计算指纹（不含幂等键本身）。"""
    spec = {
        "baseline_index_id": baseline_index_id,
        "scope": scope,
        "resource": resource,
        "credential_id": credential_id,
        "package_id": package_id,
        "node_seq": node_seq,
        "filters": filt,
    }
    return hashlib.sha256(canonical_json(spec).encode("utf-8")).hexdigest()


def compute_derivation_digest(nodes: list[dict[str, Any]]) -> str:
    """顺序敏感的派生链摘要，规则与因果链一致但使用独立初值。"""
    digest = derivation_seed()
    for position, n in enumerate(nodes):
        body = {k: v for k, v in n.items() if k not in _LINK_FIELDS}
        node_sha = hashlib.sha256(
            canonical_json(body).encode("utf-8")).hexdigest()
        h = hashlib.sha256()
        h.update(digest.encode("ascii"))
        h.update(b"|")
        h.update(str(position).encode("ascii"))
        h.update(b"|")
        h.update(n["node_id"].encode("utf-8"))
        h.update(b"|")
        h.update(node_sha.encode("ascii"))
        digest = h.hexdigest()
    return digest


def collect_field_diffs(a: Any, b: Any, path: str, out: list[dict]) -> None:
    """深度收集两个 JSON 对象的全部叶子差异（确定性顺序）。

    与 first_diff 只报首个差异不同，这里收集全部差异用于比较报告；列表按
    下标比对，长度不同时在该路径给一条结构性差异（双方完整值）。
    """
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            sub = f"{path}.{key}"
            if key not in a:
                out.append({"path": sub, "value_a": _MISSING,
                            "value_b": b[key]})
            elif key not in b:
                out.append({"path": sub, "value_a": a[key],
                            "value_b": _MISSING})
            else:
                collect_field_diffs(a[key], b[key], sub, out)
        return
    if isinstance(a, list) and isinstance(b, list):
        for i in range(min(len(a), len(b))):
            collect_field_diffs(a[i], b[i], f"{path}[{i}]", out)
        if len(a) != len(b):
            out.append({"path": f"{path}.length", "value_a": len(a),
                        "value_b": len(b)})
        return
    if a != b or type(a) is not type(b):
        out.append({"path": path, "value_a": a, "value_b": b})


# ---------------------------------------------------------------------------
# 管理器
# ---------------------------------------------------------------------------


class DerivationManager:
    """增量派生任务的创建、分块生成、暂停/恢复/重试、查询与独立核验，
    以及两份已完成因果索引的纯只读差异比较。

    与其他管理器共用 Store 的进程锁与连接：创建时在锁内钉死新快照、范围、
    过滤与成员分类，并发写入要么整体在快照之前、要么之后。
    """

    def __init__(self, store: Any, audit: Any, causal: CausalIndexManager,
                 *, chunk_size: int = 100):
        self._store = store
        self._audit = audit
        self._causal = causal
        self.chunk_size = max(1, int(chunk_size))

    # ======================================================================
    # 创建
    # ======================================================================
    def create_derivation(
        self,
        *,
        baseline_index_id: Any,
        at_seq: Any = None,
        at_wall_ms: Any = None,
        head: bool = False,
        filters: Any = None,
        idempotency_key: Any = None,
        scope: Any = None,
        resource: Any = None,
        credential_id: Any = None,
        package_id: Any = None,
    ) -> tuple[dict[str, Any], bool]:
        """创建增量派生任务，返回 (视图, 是否新建)。"""
        if not isinstance(baseline_index_id, str) \
                or not baseline_index_id.strip():
            raise AuditBadRequest("baseline_index_id 必填：必须指定一份已"
                                  "完成的因果索引作为派生基线")
        baseline_id = baseline_index_id.strip()
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：同基线+同范围+同快照节点+同过滤+"
                "同幂等键重复提交只会得到同一个派生任务")
        key = idempotency_key.strip()

        store = self._store
        with store._lock:  # noqa: SLF001 - 与存储/因果索引共用同一把锁
            conn = store._conn  # noqa: SLF001
            base = conn.execute(
                "SELECT * FROM causal_indexes WHERE index_id=?",
                (baseline_id,)).fetchone()
            if base is None:
                raise DerivationBaselineNotFound(
                    f"基线因果索引 {baseline_id} 不存在，无法创建增量派生",
                    baseline_index_id=baseline_id)
            if base["status"] != STATUS_COMPLETED:
                raise DerivationBaselineNotReady(
                    f"基线因果索引 {baseline_id} 尚未生成完成（当前状态 "
                    f"{base['status']}），只有已完成的索引才能作为派生基线",
                    baseline_index_id=baseline_id, status=base["status"])

            b_scope = base["scope"]
            b_res, b_cid, b_pid = (base["resource"], base["credential_id"],
                                   base["package_id"])
            # 作用域与对象继承自基线；若请求显式给出则必须与基线完全一致，
            # 绝不允许借派生把基线链挂到别的对象上
            self._check_scope_override(
                scope, resource, credential_id, package_id,
                b_scope, b_res, b_cid, b_pid)

            row = conn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = int(row["m"]) if row is not None and row["m"] else 0

            if b_scope == SCOPE_EVIDENCE:
                if at_seq not in (None, "") or at_wall_ms not in (None, "") \
                        or head:
                    raise AuditBadRequest(
                        "证据包作用域的历史节点在证据包创建时已钉死，派生"
                        "不能再给 at_seq / at_wall_ms / head")
                node_seq = int(base["node_seq"])
                if filters is not None:
                    filt = normalize_filters(filters)
                    if any(v is not None for v in filt.values()):
                        raise AuditBadRequest(
                            "scope=evidence_package 不支持 filters：包条目"
                            "与其源归档覆盖的事件整体进入因果链")
                else:
                    filt = json.loads(base["filters_json"])
            else:
                seq = _as_int(at_seq, "at_seq")
                wall = _as_int(at_wall_ms, "at_wall_ms")
                # 缺省在当前 head 上做增量；给了选择器则必须三选一
                if seq is None and wall is None and not head:
                    head = True
                _exactly_one_node(seq, wall, head)
                if b_scope == "resource":
                    node = self._audit._resolve_node(  # noqa: SLF001
                        conn, max_seq, b_res, seq=seq, wall_ms=wall,
                        head=head)
                else:
                    node, _r, _c = self._audit._resolve_credential_node(  # noqa: SLF001
                        conn, max_seq, b_cid, seq=seq, wall_ms=wall,
                        head=head)
                node_seq = int(node["seq"])
                if node_seq < int(base["node_seq"]):
                    raise AuditBadRequest(
                        f"派生的历史节点 seq={node_seq} 早于基线节点 "
                        f"seq={base['node_seq']}：增量派生只能向前延伸；"
                        "需要更早视图请直接以相应节点新建因果索引",
                        requested_node_seq=node_seq,
                        baseline_node_seq=int(base["node_seq"]))
                filt = (normalize_filters(filters) if filters is not None
                        else json.loads(base["filters_json"]))

            fingerprint = spec_fingerprint(
                baseline_index_id=baseline_id, scope=b_scope,
                resource=b_res, credential_id=b_cid, package_id=b_pid,
                node_seq=node_seq, filt=filt)

            # 幂等键先行：同键即回放或冲突
            prev = conn.execute(
                "SELECT * FROM causal_derivations WHERE idempotency_key=?",
                (key,)).fetchone()
            if prev is not None:
                diff = self._first_spec_diff(
                    prev, baseline_id, b_scope, b_res, b_cid, b_pid,
                    node_seq, filt)
                if diff is None:
                    return self._view(prev), False
                raise DerivationIdConflict(
                    f"幂等键 {key} 已用于派生任务 {prev['derivation_id']}，"
                    f"本次请求与首次创建不一致：首个差异位于 {diff['path']}",
                    derivation_id=prev["derivation_id"],
                    first_difference=diff)

            # 同规格换键：明确冲突，不产生第二份原件
            prev_spec = conn.execute(
                "SELECT * FROM causal_derivations WHERE spec_fingerprint=?",
                (fingerprint,)).fetchone()
            if prev_spec is not None:
                raise DerivationSpecConflict(
                    "同一基线、同一快照节点、同一范围与过滤的派生任务已经"
                    f"存在（{prev_spec['derivation_id']}，幂等键 "
                    f"{prev_spec['idempotency_key']}）；换基线、换快照节点或"
                    "换过滤才能创建新派生，重复提交请使用原幂等键",
                    derivation_id=prev_spec["derivation_id"],
                    existing_idempotency_key=prev_spec["idempotency_key"])

            # 新链完整成员集合（与创建一份同规格新索引完全相同的算法）
            members = self._causal._build_members_locked(  # noqa: SLF001
                conn, b_scope, b_res, b_cid, b_pid, node_seq, filt)
            ordered = sorted(members, key=member_sort_key)

            # 基线成员：node_id -> (position, descriptor_json)
            base_rows = conn.execute(
                "SELECT node_id, position, descriptor_json FROM "
                "causal_index_members WHERE index_id=? ORDER BY position ASC",
                (baseline_id,)).fetchall()
            base_map = {r["node_id"]: r for r in base_rows}
            base_ids = set(base_map)

            classified = []
            added = 0
            for m in ordered:
                bm = base_map.get(m["node_id"])
                if bm is None:
                    origin, baseline_position = ORIGIN_ADDED, None
                    added += 1
                else:
                    # 同一节点标识：不可变描述必须逐字节一致。描述里钉死了
                    # 源归档内容哈希等，描述变化只可能来自源数据被改动。
                    desc_text = canonical_json(m["descriptor"])
                    if desc_text != bm["descriptor_json"]:
                        old_desc = json.loads(bm["descriptor_json"])
                        diff = first_diff(old_desc, m["descriptor"],
                                          f"members.{m['node_id']}.descriptor")
                        raise DerivationSourceChanged(
                            f"节点 {m['node_id']} 的源数据与基线冻结描述不"
                            "一致：基线建立后该源可能被篡改，派生创建被拒绝",
                            node_id=m["node_id"],
                            baseline_index_id=baseline_id,
                            first_difference=diff)
                    origin, baseline_position = ORIGIN_REUSED, bm["position"]
                classified.append((m, origin, baseline_position))

            new_ids = {m["node_id"] for m, _o, _p in classified}
            removed = len(base_ids - new_ids)

            derivation_id = uuid.uuid4().hex
            now = store.clock.wall_ms()
            logical = store.clock.logical()
            try:
                conn.execute(
                    "INSERT INTO causal_derivations(derivation_id, "
                    "idempotency_key, spec_fingerprint, baseline_index_id, "
                    "scope, resource, credential_id, package_id, node_seq, "
                    "snapshot_seq, filters_json, baseline_snapshot_seq, "
                    "baseline_node_seq, baseline_total_nodes, "
                    "baseline_chain_digest, baseline_content_sha256, status, "
                    "total_nodes, last_position, reused_nodes, added_nodes, "
                    "removed_nodes, created_logical, created_at_ms, "
                    "updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                    "?,?,?,?,?,?,?,?,?)",
                    (derivation_id, key, fingerprint, baseline_id, b_scope,
                     b_res, b_cid, b_pid, node_seq, max_seq,
                     canonical_json(filt), int(base["snapshot_seq"]),
                     int(base["node_seq"]), int(base["total_nodes"]),
                     base["chain_digest"], base["content_sha256"],
                     STATUS_PENDING, len(classified), -1,
                     len(classified) - added, added, removed,
                     logical, now, now))
                for position, (m, origin, bpos) in enumerate(classified):
                    conn.execute(
                        "INSERT INTO causal_derivation_members(derivation_id, "
                        "position, node_id, node_type, object_id, anchor_seq, "
                        "origin, baseline_position, descriptor_json) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (derivation_id, position, m["node_id"],
                         m["node_type"], m["object_id"], m["anchor_seq"],
                         origin, bpos, canonical_json(m["descriptor"])))
                conn.commit()
            except sqlite3.IntegrityError:
                # 唯一索引兜底（锁内不会走到，防御性保留）
                conn.rollback()
                prev = conn.execute(
                    "SELECT * FROM causal_derivations WHERE idempotency_key=?",
                    (key,)).fetchone()
                if prev is not None:
                    diff = self._first_spec_diff(
                        prev, baseline_id, b_scope, b_res, b_cid, b_pid,
                        node_seq, filt)
                    if diff is None:
                        return self._view(prev), False
                    raise DerivationIdConflict(
                        f"幂等键 {key} 已用于规格不同的派生任务",
                        derivation_id=prev["derivation_id"])
                prev_spec = conn.execute(
                    "SELECT * FROM causal_derivations WHERE "
                    "spec_fingerprint=?", (fingerprint,)).fetchone()
                if prev_spec is not None:
                    raise DerivationSpecConflict(
                        "同一规格的派生任务已经存在",
                        derivation_id=prev_spec["derivation_id"])
                raise
            return self._view(self._get_row(conn, derivation_id)), True

    @staticmethod
    def _check_scope_override(scope, resource, credential_id, package_id,
                              b_scope, b_res, b_cid, b_pid) -> None:
        pairs = [
            ("scope", scope, b_scope),
            ("resource", resource, b_res or None),
            ("credential_id", credential_id, b_cid or None),
            ("package_id", package_id, b_pid or None),
        ]
        for field, given, expected in pairs:
            if given is not None and str(given) != str(expected):
                raise AuditBadRequest(
                    f"{field} 必须与基线一致（派生链只能继承基线作用域）："
                    f"请求给出 {given!r}，基线为 {expected!r}",
                    **{field: given, "baseline_" + field: expected})

    @staticmethod
    def _first_spec_diff(prev, baseline_id, scope, res, cid, pid, node_seq,
                         filt) -> dict | None:
        """比较创建规格，返回首个差异字段（路径/双方值）。"""
        checks = [
            ("baseline_index_id", prev["baseline_index_id"], baseline_id),
            ("scope", prev["scope"], scope),
            ("resource", prev["resource"] or "", res),
            ("credential_id", prev["credential_id"] or "", cid),
            ("package_id", prev["package_id"] or "", pid),
            ("node_seq", prev["node_seq"], node_seq),
        ]
        for field, old, new in checks:
            if old != new:
                return {"path": field, "field": field,
                        "existing": old, "requested": new}
        old_filters = json.loads(prev["filters_json"])
        if old_filters != filt:
            diff = first_diff(old_filters, filt, "filters")
            return diff or {"path": "filters", "field": "filters",
                            "existing": old_filters, "requested": filt}
        return None

    # ======================================================================
    # 查询
    # ======================================================================
    @staticmethod
    def _get_row(conn, derivation_id):
        return conn.execute(
            "SELECT * FROM causal_derivations WHERE derivation_id=?",
            (derivation_id,)).fetchone()

    def get_derivation(self, derivation_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            try:
                return self._view(row)
            finally:
                conn.rollback()

    def list_derivations(self, *, status=None, baseline_index_id=None,
                         limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        if status is not None and status not in DERIVATION_STATUSES:
            raise AuditBadRequest(
                "status 只能取 pending/building/paused/completed/failed",
                status=status)
        where, args = [], []
        if status:
            where.append("status=?")
            args.append(status)
        if baseline_index_id:
            where.append("baseline_index_id=?")
            args.append(str(baseline_index_id))
        sql = "SELECT * FROM causal_derivations"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at_ms ASC, derivation_id ASC LIMIT ?"
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            rows = conn.execute(sql, (*args, limit)).fetchall()
            try:
                return {"derivations": [self._view(r) for r in rows],
                        "limit": limit}
            finally:
                conn.rollback()

    def _baseline_view(self, row) -> dict[str, Any]:
        return {
            "index_id": row["baseline_index_id"],
            "node_seq": row["baseline_node_seq"],
            "snapshot_seq": row["baseline_snapshot_seq"],
            "total_nodes": row["baseline_total_nodes"],
            "chain_digest": row["baseline_chain_digest"],
            "content_sha256": row["baseline_content_sha256"],
        }

    def _view(self, row) -> dict[str, Any]:
        total, done = row["total_nodes"], row["processed_nodes"]
        return {
            "derivation_id": row["derivation_id"],
            "idempotency_key": row["idempotency_key"],
            "spec_fingerprint": row["spec_fingerprint"],
            "scope": row["scope"],
            "resource": row["resource"] or None,
            "credential_id": row["credential_id"] or None,
            "package_id": row["package_id"] or None,
            "node_seq": row["node_seq"],
            "snapshot_seq": row["snapshot_seq"],
            "filters": json.loads(row["filters_json"]),
            "baseline": self._baseline_view(row),
            "baseline_index_id": row["baseline_index_id"],
            "increment": {
                "reused_nodes": row["reused_nodes"],
                "added_nodes": row["added_nodes"],
                "removed_nodes": row["removed_nodes"],
                "has_changes": row["added_nodes"] > 0
                or row["removed_nodes"] > 0,
            },
            "status": row["status"],
            "progress": {
                "processed_nodes": done,
                "total_nodes": total,
                "remaining_nodes": max(total - done, 0),
                "percent": round(100.0 * done / total, 1) if total else 100.0,
                "done": done >= total,
                "last_position": row["last_position"],
            },
            "attempts": row["attempts"],
            "error": row["error"],
            "chain_digest": row["chain_digest"],
            "content_sha256": row["content_sha256"],
            "verify_status": row["verify_status"],
            "verify_detail": (json.loads(row["verify_detail"])
                              if row["verify_detail"] else None),
            "verified_at_ms": row["verified_at_ms"],
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
            "completed_at_ms": row["completed_at_ms"],
            "chain_url":
                f"/audit/causal-derivations/{row['derivation_id']}/chain",
            "download_url":
                f"/audit/causal-derivations/{row['derivation_id']}/download",
        }

    # ---- 链路查询 -------------------------------------------------------
    def get_chain(self, derivation_id: str, *, after: Any = None,
                  limit: Any = 100) -> dict[str, Any]:
        after_pos = _as_int(after, "after", default=-1)
        if after_pos < -1:
            raise AuditBadRequest("after 不能为负数", after=after_pos)
        limit = _bounded_limit(limit)
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            if row["status"] != STATUS_COMPLETED:
                raise DerivationNotReady(
                    f"派生任务 {derivation_id} 尚未生成完成（当前状态 "
                    f"{row['status']}，进度 {row['processed_nodes']}/"
                    f"{row['total_nodes']}），暂不能查询链路",
                    derivation_id=derivation_id, status=row["status"])
            total = row["total_nodes"]
            if after_pos > total - 1:
                raise _range_error(after_pos, total)
            start = after_pos + 1
            node_rows = conn.execute(
                "SELECT n.*, m.position AS position, m.origin AS origin "
                "FROM causal_derivation_nodes n JOIN "
                "causal_derivation_members m ON m.derivation_id=n.derivation_id "
                "AND m.node_id=n.node_id WHERE n.derivation_id=? "
                "AND m.position>=? ORDER BY m.position ASC LIMIT ?",
                (derivation_id, start, limit + 1)).fetchall()
            page = node_rows[:limit]
            has_more = len(node_rows) > limit
            nodes = [self._chain_node_view(r) for r in page]
            anomalies = self._anomalies(conn, row)
            summary = _summarize(anomalies)
            try:
                return {
                    "derivation_id": derivation_id,
                    "scope": row["scope"],
                    "node_seq": row["node_seq"],
                    "snapshot_seq": row["snapshot_seq"],
                    "filters": json.loads(row["filters_json"]),
                    "baseline": self._baseline_view(row),
                    "increment": {
                        "reused_nodes": row["reused_nodes"],
                        "added_nodes": row["added_nodes"],
                        "removed_nodes": row["removed_nodes"]},
                    "nodes": nodes,
                    "limit": limit,
                    "next": (page[-1]["position"] + 1)
                    if has_more and page else None,
                    "next_cursor": (page[-1]["position"] + 1)
                    if has_more and page else None,
                    "reached_end": not has_more,
                    "total_nodes": total,
                    "anomalies": anomalies,
                    "anomaly_summary": summary,
                    "consistent": summary["errors"] == 0,
                    "view": {"snapshot_seq": row["snapshot_seq"],
                             "baseline_snapshot_seq":
                                 row["baseline_snapshot_seq"],
                             "order": "causal ASC (layer, anchor_seq, node_id)"},
                    "read_only": True,
                }
            finally:
                conn.rollback()

    @staticmethod
    def _chain_node_view(nrow) -> dict[str, Any]:
        payload = json.loads(nrow["payload"])
        return {
            "position": nrow["position"],
            "node_id": payload["node_id"],
            "node_type": payload["node_type"],
            "object_id": payload["object_id"],
            "origin": nrow["origin"],
            "seq": payload.get("seq"),
            "anchor_seq": payload.get("anchor_seq"),
            "layer": LAYER[payload["node_type"]],
            "prev": payload.get("prev_node_id"),
            "next": payload.get("next_node_id"),
            "node": payload,
        }

    def get_frozen_node(self, derivation_id: str, node_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            if row["status"] != STATUS_COMPLETED:
                raise DerivationNotReady(
                    f"派生任务 {derivation_id} 尚未生成完成（{row['status']}）"
                    "，节点尚不可查询",
                    derivation_id=derivation_id, status=row["status"])
            member = conn.execute(
                "SELECT * FROM causal_derivation_members WHERE derivation_id=? "
                "AND node_id=?", (derivation_id, node_id)).fetchone()
            if member is None:
                raise DerivationNotFound(
                    f"节点 {node_id} 不在派生链 {derivation_id} 中",
                    derivation_id=derivation_id, node_id=node_id)
            nrow = conn.execute(
                "SELECT * FROM causal_derivation_nodes WHERE derivation_id=? "
                "AND node_id=?", (derivation_id, node_id)).fetchone()
            try:
                payload = json.loads(nrow["payload"])
                return {
                    "derivation_id": derivation_id,
                    "position": member["position"],
                    "node_id": node_id,
                    "node_type": member["node_type"],
                    "object_id": member["object_id"],
                    "origin": member["origin"],
                    "baseline_position": member["baseline_position"],
                    "seq": payload.get("seq"),
                    "anchor_seq": payload.get("anchor_seq"),
                    "prev": payload.get("prev_node_id"),
                    "next": payload.get("next_node_id"),
                    "node": payload,
                    "read_only": True,
                }
            finally:
                conn.rollback()

    def download(self, derivation_id: str) -> tuple[str, dict[str, Any]]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            if row["status"] != STATUS_COMPLETED:
                raise DerivationNotReady(
                    f"派生任务 {derivation_id} 尚未生成完成（当前状态 "
                    f"{row['status']}），暂不能下载",
                    derivation_id=derivation_id, status=row["status"])
            try:
                return row["content"], self._view(row)
            finally:
                conn.rollback()

    # ======================================================================
    # 后台生成
    # ======================================================================
    def process_pending(self, *, max_derivations: int | None = None,
                        max_chunks_per_derivation: int | None = None) -> int:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            # paused 显式排除：暂停的任务只有 resume 才能继续
            rows = conn.execute(
                "SELECT derivation_id FROM causal_derivations "
                "WHERE status IN (?,?) OR (status=? AND attempts<?) "
                "ORDER BY created_at_ms ASC, derivation_id ASC",
                (STATUS_PENDING, STATUS_BUILDING, STATUS_FAILED,
                 MAX_ATTEMPTS)).fetchall()
            conn.rollback()
        ids = [r["derivation_id"] for r in rows]
        if max_derivations is not None:
            ids = ids[:max_derivations]
        n = 0
        for derivation_id in ids:
            if self._process_one(derivation_id,
                                 max_chunks=max_chunks_per_derivation):
                n += 1
        return n

    def _process_one(self, derivation_id: str, *,
                     max_chunks: int | None) -> bool:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None or row["status"] == STATUS_COMPLETED:
                return False
            try:
                if row["status"] in (STATUS_PENDING, STATUS_FAILED):
                    conn.execute(
                        "UPDATE causal_derivations SET status=?, "
                        "attempts=attempts+1, error=NULL, updated_at_ms=? "
                        "WHERE derivation_id=?",
                        (STATUS_BUILDING, store.clock.wall_ms(),
                         derivation_id))
                    conn.commit()
                chunks = 0
                while True:
                    row = self._get_row(conn, derivation_id)
                    if row["status"] == STATUS_PAUSED:
                        return True  # 块间暂停点：立即让出，进度已落库
                    if row["processed_nodes"] >= row["total_nodes"]:
                        break
                    if max_chunks is not None and chunks >= max_chunks:
                        return True
                    self._build_chunk_locked(row)
                    chunks += 1
                self._finalize_locked(derivation_id)
                return True
            except Exception as exc:  # noqa: BLE001 - 失败落库后可续跑
                detail = None
                if isinstance(exc, DerivationError):
                    detail = json.dumps(exc.to_response(),
                                        ensure_ascii=False)
                conn.rollback()
                conn.execute(
                    "UPDATE causal_derivations SET status=?, error=?, "
                    "updated_at_ms=? WHERE derivation_id=?",
                    (STATUS_FAILED,
                     f"{type(exc).__name__}: {exc}"
                     + (f" [{detail}]" if detail else ""),
                     store.clock.wall_ms(), derivation_id))
                conn.commit()
                return True

    def _build_chunk_locked(self, row) -> int:
        """还原下一块成员：reused 复制基线冻结载荷，added 从冻结源重建。"""
        conn = self._store._conn  # noqa: SLF001
        derivation_id = row["derivation_id"]
        members = conn.execute(
            "SELECT * FROM causal_derivation_members WHERE derivation_id=? "
            "AND position>? ORDER BY position ASC LIMIT ?",
            (derivation_id, row["last_position"], self.chunk_size)).fetchall()
        if not members:
            conn.execute(
                "UPDATE causal_derivations SET processed_nodes=total_nodes, "
                "updated_at_ms=? WHERE derivation_id=?",
                (self._store.clock.wall_ms(), derivation_id))
            conn.commit()
            return 0

        total = row["total_nodes"]
        for m in members:
            desc = json.loads(m["descriptor_json"])
            if m["origin"] == ORIGIN_REUSED:
                payload = self._reused_payload(conn, row, m)
            else:
                payload = self._added_payload(conn, row, desc,
                                              m["position"], total)
            conn.execute(
                "INSERT OR IGNORE INTO causal_derivation_nodes(derivation_id, "
                "node_id, node_type, position, origin, payload_sha256, payload)"
                " VALUES(?,?,?,?,?,?,?)",
                (derivation_id, payload["node_id"], payload["node_type"],
                 m["position"], m["origin"], payload_sha(payload),
                 canonical_json(payload)))
        conn.execute(
            "UPDATE causal_derivations SET processed_nodes=processed_nodes+?, "
            "last_position=?, updated_at_ms=? WHERE derivation_id=?",
            (len(members), members[-1]["position"],
             self._store.clock.wall_ms(), derivation_id))
        conn.commit()
        return len(members)

    def _reused_payload(self, conn, drow, member) -> dict[str, Any]:
        """复用节点：载荷体逐字节复制自基线冻结副本，只重盖链环字段。

        绝不回源重建——基线之后源归档/证据包即便被改动，复用节点仍保持
        基线冻结时的内容，派生链不被污染。
        """
        baseline_id = drow["baseline_index_id"]
        brow = conn.execute(
            "SELECT payload FROM causal_index_nodes WHERE index_id=? "
            "AND node_id=?", (baseline_id, member["node_id"])).fetchone()
        if brow is None:
            raise DerivationError(
                f"基线 {baseline_id} 的冻结节点 {member['node_id']} 缺失，"
                "无法复用：基线索引的冻结副本可能被删除",
                node_id=member["node_id"], baseline_index_id=baseline_id)
        payload = json.loads(brow["payload"])
        return self._stamp_links(conn, drow, payload, member["position"])

    def _added_payload(self, conn, drow, desc, position, total
                        ) -> dict[str, Any]:
        """新增节点：从冻结的审计事件与归档清单重建，生成时再次核对源完整性。"""
        kind = desc["kind"]
        if kind == "event_ref":
            payload = self._causal._payload_event(conn, desc["seq"])  # noqa: SLF001
        elif kind == "write_ref":
            payload = self._causal._payload_write(  # noqa: SLF001
                conn, desc["write_id"], desc["seq"])
        elif kind == "delegation_ref":
            payload = self._payload_delegation(conn, drow,
                                               desc["credential_id"])
        elif kind == "archive_ref":
            self._require_archive_source(conn, desc)
            payload = self._causal._payload_archive(conn, desc)  # noqa: SLF001
        elif kind == "evidence_entry_ref":
            self._require_evidence_source(conn, desc)
            payload = self._causal._payload_evidence_entry(conn, desc)  # noqa: SLF001
        else:
            raise DerivationError(f"未知成员类型 {kind}")
        return self._stamp_links(conn, drow, payload, position)

    def _stamp_links(self, conn, drow, payload, position) -> dict[str, Any]:
        derivation_id = drow["derivation_id"]
        total = drow["total_nodes"]
        payload["position"] = position
        payload["prev_node_id"] = self._node_id_at(conn, derivation_id,
                                                   position - 1)
        payload["next_node_id"] = (self._node_id_at(conn, derivation_id,
                                                    position + 1)
                                   if position + 1 < total else None)
        return payload

    @staticmethod
    def _node_id_at(conn, derivation_id, position):
        if position < 0:
            return None
        r = conn.execute(
            "SELECT node_id FROM causal_derivation_members "
            "WHERE derivation_id=? AND position=?",
            (derivation_id, position)).fetchone()
        return r["node_id"] if r else None

    def _payload_delegation(self, conn, drow, credential_id) -> dict[str, Any]:
        """委托节点：状态由冻结事件纯重放（与因果索引同语义，回放上界按
        evidence_package 作用域取派生链内该资源被覆盖到的最大归档节点）。"""
        grant = conn.execute(
            "SELECT * FROM lease_events WHERE credential_id=? AND event="
            "'delegate_grant' AND outcome='ok' ORDER BY seq ASC LIMIT 1",
            (credential_id,)).fetchone()
        if grant is None:
            raise DerivationError(
                f"委托凭证 {credential_id} 的冻结发放事件缺失，无法还原节点")
        resource = grant["resource"]
        ceil = self._delegation_replay_ceil(conn, drow, resource)
        ev_rows = conn.execute(
            "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
            "ORDER BY seq ASC", (resource, ceil)).fetchall()
        st = project(resource, [event_dict(r) for r in ev_rows],
                     check_clocks=False)
        d = st.delegations.get(credential_id)
        return {
            "kind": NODE_DELEGATION,
            "node_id": f"delegation:{credential_id}",
            "node_type": NODE_DELEGATION,
            "object_id": credential_id,
            "seq": grant["seq"],
            "anchor_seq": grant["seq"],
            "delegation": d.view() if d is not None else None,
        }

    def _delegation_replay_ceil(self, conn, drow, resource) -> int:
        if drow["scope"] in ("resource", "credential"):
            return int(drow["node_seq"])
        archive_ids = [
            json.loads(r["descriptor_json"])["archive_id"]
            for r in conn.execute(
                "SELECT descriptor_json FROM causal_derivation_members "
                "WHERE derivation_id=? AND node_type=?",
                (drow["derivation_id"], NODE_ARCHIVE)).fetchall()]
        ceil = 0
        for aid in archive_ids:
            a = conn.execute(
                "SELECT node_seq, resource FROM archives WHERE archive_id=?",
                (aid,)).fetchone()
            if a is not None and a["resource"] == resource:
                ceil = max(ceil, int(a["node_seq"]))
        return ceil or int(drow["node_seq"])

    # ---- 新增节点的源完整性（生成时硬校验，篡改即失败） -----------------
    @staticmethod
    def _require_archive_source(conn, desc) -> None:
        aid = desc["archive_id"]
        r = conn.execute(
            "SELECT * FROM archives WHERE archive_id=?", (aid,)).fetchone()
        node_id = archive_node_id(aid)
        if r is None:
            raise DerivationSourceChanged(
                f"新增源归档节点 {node_id} 的源归档 {aid} 已不存在，"
                "拒绝生成被掉包的派生链",
                node_id=node_id, archive_id=aid,
                path="sources.archive_id", section="sources",
                archived=aid, recomputed=_MISSING)
        if r["status"] != STATUS_COMPLETED:
            raise DerivationSourceChanged(
                f"新增源归档节点 {node_id} 的源归档 {aid} 当前不是完成态"
                f"（{r['status']}）",
                node_id=node_id, archive_id=aid,
                path="sources.status", section="sources",
                archived=STATUS_COMPLETED, recomputed=r["status"])
        if r["content_sha256"] != desc["frozen_content_sha256"]:
            raise DerivationSourceChanged(
                f"新增源归档节点 {node_id} 的内容校验值与成员冻结描述不"
                "一致：源归档在派生创建后被改动，拒绝生成",
                node_id=node_id, archive_id=aid,
                path="sources.content_sha256", section="sources",
                archived=desc["frozen_content_sha256"],
                recomputed=r["content_sha256"])

    @staticmethod
    def _require_evidence_source(conn, desc) -> None:
        pid, position = desc["package_id"], desc["position"]
        node_id = evidence_entry_node_id(pid, position)
        pkg = conn.execute(
            "SELECT * FROM evidence_packages WHERE package_id=?",
            (pid,)).fetchone()
        if pkg is None:
            raise DerivationSourceChanged(
                f"新增证据包条目节点 {node_id} 的证据包 {pid} 已不存在",
                node_id=node_id, package_id=pid, position=position,
                path="sources.package_id", section="sources",
                archived=pid, recomputed=_MISSING)
        entry = conn.execute(
            "SELECT * FROM evidence_entries WHERE package_id=? AND position=?",
            (pid, position)).fetchone()
        if entry is None:
            raise DerivationSourceChanged(
                f"证据包 {pid} 缺少第 {position} 个条目",
                node_id=node_id, package_id=pid, position=position,
                path="sources.entry", section="sources",
                archived="<present>", recomputed=_MISSING)
        if entry["archive_id"] != desc["archive_id"]:
            raise DerivationSourceChanged(
                f"证据包 {pid} 第 {position} 个条目的归档标识与冻结描述"
                "不一致",
                node_id=node_id, package_id=pid, position=position,
                path="sources.archive_id", section="sources",
                archived=desc["archive_id"], recomputed=entry["archive_id"])
        if entry["source_sha256"] != desc["frozen_source_sha256"]:
            raise DerivationSourceChanged(
                f"证据包 {pid} 第 {position} 个条目的源哈希与冻结描述不"
                "一致：源归档内容可能被改动",
                node_id=node_id, package_id=pid, position=position,
                path="sources.source_sha256", section="sources",
                archived=desc["frozen_source_sha256"],
                recomputed=entry["source_sha256"])
        content_row = conn.execute(
            "SELECT payload FROM evidence_entry_contents WHERE package_id=? "
            "AND position=?", (pid, position)).fetchone()
        if content_row is None:
            raise DerivationSourceChanged(
                f"证据包 {pid} 第 {position} 个条目的冻结载荷缺失",
                node_id=node_id, package_id=pid, position=position,
                path="sources.payload", section="sources",
                archived="<present>", recomputed=_MISSING)
        current_frozen = hashlib.sha256(
            content_row["payload"].encode("utf-8")).hexdigest()
        if desc["frozen_sha256"] is not None \
                and current_frozen != desc["frozen_sha256"]:
            raise DerivationSourceChanged(
                f"证据包 {pid} 第 {position} 个条目的冻结载荷哈希与冻结"
                "描述不一致：载荷可能被篡改",
                node_id=node_id, package_id=pid, position=position,
                path="sources.frozen_sha256", section="sources",
                archived=desc["frozen_sha256"],
                recomputed=current_frozen)

    # ---- 定稿 -----------------------------------------------------------
    def _finalize_locked(self, derivation_id: str) -> None:
        conn = self._store._conn  # noqa: SLF001
        row = self._get_row(conn, derivation_id)
        node_rows = conn.execute(
            "SELECT n.payload AS payload FROM causal_derivation_nodes n "
            "JOIN causal_derivation_members m ON m.derivation_id=n.derivation_id "
            "AND m.node_id=n.node_id WHERE n.derivation_id=? "
            "ORDER BY m.position ASC", (derivation_id,)).fetchall()
        nodes = [json.loads(r["payload"]) for r in node_rows]
        if len(nodes) != row["total_nodes"]:
            raise DerivationError(
                f"节点数不一致：成员 {row['total_nodes']}，已还原 "
                f"{len(nodes)}")

        structural = self._causal._structural_anomalies_from_payloads(nodes)  # noqa: SLF001
        digest = compute_derivation_digest(nodes)

        # 基线链摘要定稿时重算一次：基线在生成期间被篡改会在此显形
        baseline_digest_now, baseline_intact = self._baseline_digest_now(
            conn, row)
        anomalies = list(structural)
        if not baseline_intact:
            anomalies.append({
                "code": "baseline_chain_changed", "severity": "error",
                "node_id": None, "seq": None, "node_type": None,
                "message": "基线因果链摘要与派生创建时冻结的值不一致："
                           "基线索引在派生生成期间被改动",
                "frozen": row["baseline_chain_digest"],
                "current": baseline_digest_now})

        added_meta, removed_meta = self._increment_meta(conn, row)
        core = {
            "kind": "lease_audit_causal_derivation",
            "version": 1,
            "derivation_id": derivation_id,
            "idempotency_key": row["idempotency_key"],
            "spec_fingerprint": row["spec_fingerprint"],
            "scope": row["scope"],
            "resource": row["resource"] or None,
            "credential_id": row["credential_id"] or None,
            "package_id": row["package_id"] or None,
            "node_seq": row["node_seq"],
            "snapshot_seq": row["snapshot_seq"],
            "filters": json.loads(row["filters_json"]),
            "baseline": {
                **self._baseline_view(row),
                "chain_digest_at_finalize": baseline_digest_now,
                "intact": baseline_intact,
            },
            "increment": {
                "reused_nodes": row["reused_nodes"],
                "added_nodes": row["added_nodes"],
                "removed_nodes": row["removed_nodes"],
                "added": added_meta,
                "removed": removed_meta,
            },
            "chain_order": {
                "algorithm": DERIVATION_CHAIN_V1,
                "rule": "layer (lease_event < write/delegation < "
                        "source_archive < evidence_entry), then anchor_seq, "
                        "then node_id",
                "total_nodes": len(nodes),
            },
            "nodes": nodes,
            "anomalies": anomalies,
            "anomaly_summary": _summarize(anomalies),
            "created_at_ms": row["created_at_ms"],
            "created_logical": row["created_logical"],
        }
        core["chain_digest"] = digest
        core["content_sha256"] = content_sha256(core)
        text = json.dumps(core, ensure_ascii=False, sort_keys=True)
        now = self._store.clock.wall_ms()
        conn.execute(
            "UPDATE causal_derivations SET status=?, content=?, "
            "content_sha256=?, chain_digest=?, processed_nodes=total_nodes, "
            "completed_at_ms=?, updated_at_ms=? WHERE derivation_id=?",
            (STATUS_COMPLETED, text, core["content_sha256"], digest,
             now, now, derivation_id))
        conn.commit()

    def _baseline_digest_now(self, conn, drow) -> tuple[str | None, bool]:
        """重算基线当前链摘要，返回 (当前摘要, 是否与冻结值一致)。"""
        rows = conn.execute(
            "SELECT n.payload AS payload FROM causal_index_nodes n "
            "JOIN causal_index_members m ON m.index_id=n.index_id "
            "AND m.node_id=n.node_id WHERE n.index_id=? "
            "ORDER BY m.position ASC",
            (drow["baseline_index_id"],)).fetchall()
        if not rows:
            return None, drow["baseline_chain_digest"] is None
        nodes = [json.loads(r["payload"]) for r in rows]
        digest = CausalIndexManager._compute_chain_digest(nodes)  # noqa: SLF001
        return digest, digest == drow["baseline_chain_digest"]

    def _increment_meta(self, conn, drow) -> tuple[list, list]:
        members = conn.execute(
            "SELECT position, node_id, node_type, anchor_seq, origin, "
            "baseline_position FROM causal_derivation_members "
            "WHERE derivation_id=? ORDER BY position ASC",
            (drow["derivation_id"],)).fetchall()
        new_ids = {r["node_id"] for r in members}
        added = [{"node_id": r["node_id"], "node_type": r["node_type"],
                  "anchor_seq": r["anchor_seq"], "position": r["position"]}
                 for r in members if r["origin"] == ORIGIN_ADDED]
        base_rows = conn.execute(
            "SELECT position, node_id, node_type, anchor_seq FROM "
            "causal_index_members WHERE index_id=? ORDER BY position ASC",
            (drow["baseline_index_id"],)).fetchall()
        removed = [{"node_id": r["node_id"], "node_type": r["node_type"],
                    "anchor_seq": r["anchor_seq"],
                    "baseline_position": r["position"]}
                   for r in base_rows if r["node_id"] not in new_ids]
        return added, removed

    # ---- 异常报告（结构 + 源漂移 + 基线漂移，纯只读） -------------------
    def _anomalies(self, conn, drow) -> list[dict]:
        issues: list[dict] = []
        # 结构异常：载入派生链冻结节点后复用因果链的纯载荷判定
        rows = conn.execute(
            "SELECT n.payload AS payload FROM causal_derivation_nodes n "
            "JOIN causal_derivation_members m ON m.derivation_id=n.derivation_id "
            "AND m.node_id=n.node_id WHERE n.derivation_id=? "
            "ORDER BY m.position ASC", (drow["derivation_id"],)).fetchall()
        nodes = [json.loads(r["payload"]) for r in rows]
        issues += self._causal._structural_anomalies_from_payloads(nodes)  # noqa: SLF001
        # 源归档/证据包条目当前状态（只读检查，不给任何源对象落状态）
        members = conn.execute(
            "SELECT node_id, node_type, descriptor_json FROM "
            "causal_derivation_members WHERE derivation_id=? "
            "AND node_type IN (?,?) ORDER BY position ASC",
            (drow["derivation_id"], NODE_ARCHIVE,
             NODE_EVIDENCE_ENTRY)).fetchall()
        for m in members:
            desc = json.loads(m["descriptor_json"])
            if m["node_type"] == NODE_ARCHIVE:
                self._causal._check_archive_source(conn, desc, issues)  # noqa: SLF001
            else:
                self._causal._check_evidence_entry_source(conn, desc, issues)  # noqa: SLF001
        # 基线漂移
        digest_now, intact = self._baseline_digest_now(conn, drow)
        if not intact:
            issues.append({
                "code": "baseline_chain_changed", "severity": "error",
                "node_id": None, "seq": None,
                "message": "基线因果链摘要与派生创建时冻结的值不一致："
                           "基线可能已被篡改",
                "frozen": drow["baseline_chain_digest"],
                "current": digest_now})
        return issues

    # ======================================================================
    # 暂停 / 恢复 / 重试
    # ======================================================================
    def pause(self, derivation_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            # 幂等：暂停一个已暂停的任务直接回放当前状态
            if row["status"] == STATUS_PAUSED:
                return self._view(row)
            if row["status"] not in (STATUS_PENDING, STATUS_BUILDING):
                raise DerivationBadState(
                    f"派生任务 {derivation_id} 当前状态为 {row['status']}，"
                    "只有进行中（pending/building）的任务可以暂停",
                    derivation_id=derivation_id, status=row["status"])
            conn.execute(
                "UPDATE causal_derivations SET status=?, updated_at_ms=? "
                "WHERE derivation_id=?",
                (STATUS_PAUSED, store.clock.wall_ms(), derivation_id))
            conn.commit()
            return self._view(self._get_row(conn, derivation_id))

    def resume(self, derivation_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            if row["status"] == STATUS_PENDING:
                # 幂等：尚未开始的任务本来就在待跑队列里
                return self._view(row)
            if row["status"] == STATUS_PAUSED:
                conn.execute(
                    "UPDATE causal_derivations SET status=?, updated_at_ms=? "
                    "WHERE derivation_id=?",
                    (STATUS_PENDING, store.clock.wall_ms(), derivation_id))
                conn.commit()
                return self._view(self._get_row(conn, derivation_id))
            raise DerivationBadState(
                f"派生任务 {derivation_id} 当前状态为 {row['status']}，"
                "只有 paused 的任务需要恢复；未开始的任务直接等待 worker，"
                "失败任务请用 retry",
                derivation_id=derivation_id, status=row["status"])

    def retry(self, derivation_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            if row["status"] != STATUS_FAILED:
                raise DerivationBadState(
                    f"派生任务 {derivation_id} 当前状态为 {row['status']}，"
                    "只有 failed 的任务需要重试；暂停的任务请用 resume",
                    derivation_id=derivation_id, status=row["status"])
            conn.execute(
                "UPDATE causal_derivations SET status=?, attempts=0, "
                "error=NULL, updated_at_ms=? WHERE derivation_id=?",
                (STATUS_PENDING, store.clock.wall_ms(), derivation_id))
            conn.commit()
            return self._view(self._get_row(conn, derivation_id))

    # ======================================================================
    # 独立核验
    # ======================================================================
    def verify(self, derivation_id: str) -> dict[str, Any]:
        """按序核验：文档总校验值 → 基线链仍存在/完成且链摘要未变 →
        源归档/证据包条目可用且哈希未变 → 成员集合可由冻结事件/归档清单
        重算 → 复用节点与基线冻结载荷逐字段一致、新增节点可独立重建 →
        派生链摘要。只写 causal_derivations 核验标记，绝不触碰源对象。
        """
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, derivation_id)
            if row is None:
                raise DerivationNotFound(
                    f"派生任务 {derivation_id} 不存在",
                    derivation_id=derivation_id)
            if row["status"] != STATUS_COMPLETED:
                raise DerivationNotReady(
                    f"派生任务 {derivation_id} 尚未生成完成（{row['status']}）"
                    "，不能核验",
                    derivation_id=derivation_id, status=row["status"])
            content = json.loads(row["content"])

            divergence = self._check_checksum(row, content)
            if divergence is None:
                divergence = self._check_baseline(conn, row)
            if divergence is None:
                divergence = self._check_sources(conn, row)
            if divergence is None:
                divergence = self._check_membership(conn, row)
            if divergence is None:
                divergence = self._check_nodes(conn, row, content)
            if divergence is None:
                divergence = self._check_digest(content)

            now = store.clock.wall_ms()
            if divergence is None:
                conn.execute(
                    "UPDATE causal_derivations SET verify_status=?, "
                    "verify_detail=NULL, verified_at_ms=?, updated_at_ms=? "
                    "WHERE derivation_id=?",
                    (VERIFY_VERIFIED, now, now, derivation_id))
                result = {
                    "derivation_id": derivation_id,
                    "verify_status": VERIFY_VERIFIED,
                    "first_divergence": None,
                    "message": "独立核验通过：总校验值、基线链摘要、源归档/"
                               "证据包条目、成员集合、复用/新增节点载荷与"
                               "派生链摘要全部一致"}
            else:
                conn.execute(
                    "UPDATE causal_derivations SET verify_status=?, "
                    "verify_detail=?, verified_at_ms=?, updated_at_ms=? "
                    "WHERE derivation_id=?",
                    (VERIFY_FAILED,
                     json.dumps(divergence, ensure_ascii=False), now, now,
                     derivation_id))
                result = {
                    "derivation_id": derivation_id,
                    "verify_status": VERIFY_FAILED,
                    "first_divergence": divergence,
                    "message": "核验失败：首个差异位于 "
                               f"{divergence.get('path')}（节点 "
                               f"{divergence.get('node_id')}："
                               f"{divergence.get('message', '内容不一致')}）"}
            conn.commit()
            result["verified_at_ms"] = now
            result["content_sha256"] = row["content_sha256"]
            result["chain_digest"] = row["chain_digest"]
            return result

    @staticmethod
    def _check_checksum(row, content) -> dict | None:
        core = {k: v for k, v in content.items() if k != "content_sha256"}
        actual = content_sha256(core)
        if actual != content.get("content_sha256") or \
                actual != row["content_sha256"]:
            return {"section": "checksum", "path": "content_sha256",
                    "node_id": None,
                    "expected": row["content_sha256"],
                    "archived": content.get("content_sha256"),
                    "recomputed": actual,
                    "message": "派生文档与保存的总校验值不符，文档可能被篡改"}
        return None

    def _check_baseline(self, conn, row) -> dict | None:
        base = conn.execute(
            "SELECT * FROM causal_indexes WHERE index_id=?",
            (row["baseline_index_id"],)).fetchone()
        if base is None:
            return {"section": "baseline", "path": "baseline.index_id",
                    "node_id": None, "archived": row["baseline_index_id"],
                    "recomputed": _MISSING,
                    "message": "基线因果索引已不存在，派生链的复用部分无法"
                               "溯源"}
        if base["status"] != STATUS_COMPLETED:
            return {"section": "baseline", "path": "baseline.status",
                    "node_id": None, "archived": STATUS_COMPLETED,
                    "recomputed": base["status"],
                    "message": "基线因果索引当前不是完成态"}
        digest_now, intact = self._baseline_digest_now(conn, row)
        if not intact:
            return {"section": "baseline", "path": "baseline.chain_digest",
                    "node_id": None,
                    "archived": row["baseline_chain_digest"],
                    "recomputed": digest_now,
                    "message": "基线因果链摘要与派生创建时冻结值不一致："
                               "基线在派生建立后被改动（可能被篡改）"}
        return None

    def _check_sources(self, conn, row) -> dict | None:
        issues = self._anomalies(conn, row)
        source_issues = [i for i in issues
                         if i["code"] not in ("chain_broken", "chain_cycle",
                                              "duplicate_seq",
                                              "baseline_chain_changed")]
        if not source_issues:
            return None
        i0 = source_issues[0]
        return {"section": "sources",
                "path": f"sources.{i0['code']}",
                "node_id": i0.get("node_id"),
                "archive_id": i0.get("archive_id"),
                "package_id": i0.get("package_id"),
                "position": i0.get("position"),
                "archived": i0.get("frozen"),
                "recomputed": i0.get("current"),
                "message": i0["message"]}

    def _check_membership(self, conn, row, content=None) -> dict | None:
        """从冻结事件/归档清单重算新链成员，与冻结成员（含 origin）比对。"""
        filt = json.loads(row["filters_json"])
        try:
            recomputed = self._causal._build_members_locked(  # noqa: SLF001
                conn, row["scope"], row["resource"], row["credential_id"],
                row["package_id"], row["node_seq"], filt)
        except (ArchiveError, AuditBadRequest) as exc:
            return {"section": "membership", "path": "members",
                    "node_id": None, "archived": "<present>",
                    "recomputed": _MISSING, "message": str(exc)}
        recomputed.sort(key=member_sort_key)
        frozen_rows = conn.execute(
            "SELECT node_id, node_type, object_id, anchor_seq, origin, "
            "baseline_position FROM causal_derivation_members "
            "WHERE derivation_id=? ORDER BY position ASC",
            (row["derivation_id"],)).fetchall()
        frozen = [{"node_id": r["node_id"], "node_type": r["node_type"],
                   "object_id": r["object_id"], "anchor_seq": r["anchor_seq"]}
                  for r in frozen_rows]
        fresh = [{"node_id": m["node_id"], "node_type": m["node_type"],
                  "object_id": m["object_id"], "anchor_seq": m["anchor_seq"]}
                 for m in recomputed]
        diff = first_diff(frozen, fresh, "members")
        if diff is not None:
            return {**diff, "section": "membership", "node_id": None,
                    "message": "从冻结审计事件与归档清单重算的成员集合与"
                               "冻结成员不一致（历史或源归档可能被删改）"}
        # origin 分类也要可重算：基线有即 reused、无即 added
        base_ids = {r["node_id"] for r in conn.execute(
            "SELECT node_id FROM causal_index_members WHERE index_id=?",
            (row["baseline_index_id"],)).fetchall()}
        for r in frozen_rows:
            expected_origin = (ORIGIN_REUSED if r["node_id"] in base_ids
                               else ORIGIN_ADDED)
            if r["origin"] != expected_origin:
                return {"section": "membership",
                        "path": f"members[{r['baseline_position']}].origin",
                        "node_id": r["node_id"],
                        "archived": r["origin"],
                        "recomputed": expected_origin,
                        "message": "成员的 reused/added 分类无法由基线成员"
                                   "集合重算得到"}
        return None

    def _check_nodes(self, conn, row, content) -> dict | None:
        derivation_id = row["derivation_id"]
        members = conn.execute(
            "SELECT * FROM causal_derivation_members WHERE derivation_id=? "
            "ORDER BY position ASC", (derivation_id,)).fetchall()
        frozen_by_id = {n["node_id"]: n for n in conn.execute(
            "SELECT * FROM causal_derivation_nodes WHERE derivation_id=?",
            (derivation_id,)).fetchall()}
        doc_by_id = {n.get("node_id"): n for n in content.get("nodes", [])}
        for m in members:
            if m["origin"] == ORIGIN_REUSED:
                divergence = self._check_reused_node(conn, row, m,
                                                     frozen_by_id, doc_by_id)
            else:
                divergence = self._check_added_node(conn, row, m,
                                                    frozen_by_id, doc_by_id)
            if divergence is not None:
                return divergence
        doc_ids = [n["node_id"] for n in content.get("nodes", [])]
        member_ids = [m["node_id"] for m in members]
        if doc_ids != member_ids:
            return {"section": "nodes", "path": "nodes", "node_id": None,
                    "archived": member_ids, "recomputed": doc_ids,
                    "message": "派生文档节点顺序与冻结成员顺序不一致"}
        return None

    @staticmethod
    def _body(payload) -> dict:
        return {k: v for k, v in payload.items() if k not in _LINK_FIELDS}

    def _check_reused_node(self, conn, row, member, frozen_by_id,
                           doc_by_id) -> dict | None:
        """复用节点：载荷体必须与基线冻结副本逐字段一致。"""
        node_id = member["node_id"]
        brow = conn.execute(
            "SELECT payload FROM causal_index_nodes WHERE index_id=? "
            "AND node_id=?", (row["baseline_index_id"], node_id)).fetchone()
        if brow is None:
            return {"section": "nodes",
                    "path": f"nodes[{member['position']}]",
                    "node_id": node_id, "archived": "<present>",
                    "recomputed": _MISSING,
                    "message": "基线冻结节点缺失，复用节点无法溯源"}
        base_body = self._body(json.loads(brow["payload"]))
        doc_node = doc_by_id.get(node_id)
        if doc_node is not None:
            diff = first_diff(self._body(doc_node), base_body,
                              f"nodes[{member['position']}]")
            if diff is not None:
                return {**diff, "section": "nodes", "node_id": node_id,
                        "message": "派生文档中的复用节点与基线冻结载荷不"
                                   "一致（文档可能被篡改）"}
        frozen_body = self._body(
            json.loads(frozen_by_id[node_id]["payload"]))
        diff = first_diff(frozen_body, base_body,
                          f"nodes[{member['position']}]")
        if diff is not None:
            return {**diff, "section": "nodes", "node_id": node_id,
                    "message": "复用节点载荷与基线冻结副本不一致"}
        return None

    def _check_added_node(self, conn, row, member, frozen_by_id,
                          doc_by_id) -> dict | None:
        """新增节点：从冻结事件/归档清单独立重建并逐字段比对。"""
        node_id = member["node_id"]
        desc = json.loads(member["descriptor_json"])
        try:
            recomputed = self._added_payload(
                conn, row, desc, member["position"], row["total_nodes"])
        except DerivationError as exc:
            return {"section": "nodes",
                    "path": f"nodes[{member['position']}]",
                    "node_id": node_id, "archived": "<present>",
                    "recomputed": _MISSING, "message": str(exc)}
        doc_node = doc_by_id.get(node_id)
        if doc_node is not None:
            diff = first_diff(doc_node, recomputed,
                              f"nodes[{member['position']}]")
            if diff is not None:
                return {**diff, "section": "nodes", "node_id": node_id,
                        "message": "派生文档中的新增节点无法由冻结事件/"
                                   "归档清单独立重建得到"}
        frozen = json.loads(frozen_by_id[node_id]["payload"])
        diff = first_diff(frozen, recomputed,
                          f"nodes[{member['position']}]")
        if diff is not None:
            return {**diff, "section": "nodes", "node_id": node_id,
                    "message": "新增节点载荷无法由冻结事件/归档清单独立"
                               "重建得到"}
        return None

    @staticmethod
    def _check_digest(content) -> dict | None:
        digest = compute_derivation_digest(content.get("nodes", []))
        if digest != content.get("chain_digest"):
            return {"section": "chain_digest", "path": "chain_digest",
                    "node_id": None, "archived": content.get("chain_digest"),
                    "recomputed": digest,
                    "message": "派生链摘要无法由冻结节点按因果顺序独立重算"
                               "得到：顺序或某节点内容可能被改动"}
        return None

    # ======================================================================
    # 索引差异比较（纯只读，绝不落库）
    # ======================================================================
    def compare_indexes(self, a_index_id: str, b_index_id: str, *,
                        after: Any = None, limit: Any = 100) -> dict[str, Any]:
        """比较两份已完成因果索引的冻结链。

        返回共同节点、首个分叉位置、双方各自新增/缺失节点与逐字段变化。
        字段变化按 (a 侧位置, node_id, 路径) 确定性排序，支持固定游标分页；
        游标越过末位 → 416。整个比较只读且无副作用。
        """
        after_pos = _as_int(after, "after", default=-1)
        if after_pos < -1:
            raise AuditBadRequest("after 不能为负数", after=after_pos)
        limit = _bounded_limit(limit)
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            a = conn.execute(
                "SELECT * FROM causal_indexes WHERE index_id=?",
                (a_index_id,)).fetchone()
            if a is None:
                raise CausalNotFound(
                    f"比较方 A 的因果索引 {a_index_id} 不存在",
                    index_id=a_index_id)
            b = conn.execute(
                "SELECT * FROM causal_indexes WHERE index_id=?",
                (b_index_id,)).fetchone()
            if b is None:
                raise CausalNotFound(
                    f"比较方 B 的因果索引 {b_index_id} 不存在",
                    index_id=b_index_id)
            if a["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"比较方 A 的因果索引 {a_index_id} 尚未完成（"
                    f"{a['status']}），不能比较",
                    index_id=a_index_id, status=a["status"])
            if b["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"比较方 B 的因果索引 {b_index_id} 尚未完成（"
                    f"{b['status']}），不能比较",
                    index_id=b_index_id, status=b["status"])

            a_nodes = self._ordered_index_nodes(conn, a_index_id)
            b_nodes = self._ordered_index_nodes(conn, b_index_id)
            a_ids = [n["payload"]["node_id"] for n in a_nodes]
            b_ids = [n["payload"]["node_id"] for n in b_nodes]
            a_set, b_set = set(a_ids), set(b_ids)
            common_ids = a_set & b_set
            added_ids = [nid for nid in b_ids if nid not in a_set]    # B 有 A 无
            removed_ids = [nid for nid in a_ids if nid not in b_set]  # A 有 B 无
            a_map = {n["payload"]["node_id"]: n for n in a_nodes}
            b_map = {n["payload"]["node_id"]: n for n in b_nodes}

            first_divergence = self._first_divergence(
                a_ids, b_ids, a_map, b_map)

            field_changes = []
            change_index = 0
            for nid in a_ids:  # 以 A 的因果顺序作为变化排序主轴
                if nid not in common_ids:
                    continue
                na, nb = a_map[nid], b_map[nid]
                leaf_diffs: list[dict] = []
                collect_field_diffs(self._body(na["payload"]),
                                    self._body(nb["payload"]),
                                    "node", leaf_diffs)
                for d in leaf_diffs:
                    field_changes.append({
                        "_index": change_index,
                        "node_id": nid,
                        "node_type": na["payload"]["node_type"],
                        "seq": na["payload"].get("seq"),
                        "anchor_seq": na["payload"].get("anchor_seq"),
                        "position_a": na["position"],
                        "position_b": nb["position"],
                        "field": d["path"][len("node."):],
                        "path": d["path"],
                        "value_a": d["value_a"],
                        "value_b": d["value_b"],
                    })
                    change_index += 1

            total_changes = len(field_changes)
            if total_changes and after_pos > total_changes - 1:
                raise _compare_range_error(after_pos, total_changes)
            start = after_pos + 1
            page = field_changes[start: start + limit]
            has_more = start + limit < total_changes

            def node_brief(nid, side):
                n = (a_map if side == "a" else b_map)[nid]
                p = n["payload"]
                return {"node_id": nid, "node_type": p["node_type"],
                        "object_id": p.get("object_id"),
                        "seq": p.get("seq"),
                        "anchor_seq": p.get("anchor_seq"),
                        "position": n["position"]}

            try:
                return {
                    "comparison": "a_to_b",
                    "a": {"index_id": a_index_id, "scope": a["scope"],
                          "node_seq": a["node_seq"],
                          "snapshot_seq": a["snapshot_seq"],
                          "total_nodes": a["total_nodes"],
                          "chain_digest": a["chain_digest"]},
                    "b": {"index_id": b_index_id, "scope": b["scope"],
                          "node_seq": b["node_seq"],
                          "snapshot_seq": b["snapshot_seq"],
                          "total_nodes": b["total_nodes"],
                          "chain_digest": b["chain_digest"]},
                    "same_snapshot": (a["snapshot_seq"] == b["snapshot_seq"]
                                      and a["node_seq"] == b["node_seq"]),
                    "summary": {
                        "common_nodes": len(common_ids),
                        "added_nodes": len(added_ids),
                        "removed_nodes": len(removed_ids),
                        "field_changes": total_changes,
                        "identical": (not added_ids and not removed_ids
                                      and total_changes == 0),
                    },
                    "first_divergence": first_divergence,
                    "common_nodes": [
                        {"node_id": nid,
                          "node_type": a_map[nid]["payload"]["node_type"],
                          "position_a": a_map[nid]["position"],
                          "position_b": b_map[nid]["position"]}
                        for nid in a_ids if nid in common_ids],
                    "added_nodes": [node_brief(nid, "b")
                                    for nid in added_ids],
                    "removed_nodes": [node_brief(nid, "a")
                                      for nid in removed_ids],
                    "field_changes": [
                        {k: v for k, v in ch.items() if k != "_index"}
                        for ch in page],
                    "limit": limit,
                    "next": page[-1]["_index"]
                    if has_more and page else None,
                    "next_cursor": page[-1]["_index"]
                    if has_more and page else None,
                    "reached_end": not has_more,
                    "total_field_changes": total_changes,
                    "read_only": True,
                }
            finally:
                conn.rollback()

    @staticmethod
    def _ordered_index_nodes(conn, index_id) -> list[dict]:
        rows = conn.execute(
            "SELECT n.payload AS payload, m.position AS position "
            "FROM causal_index_nodes n JOIN causal_index_members m "
            "ON m.index_id=n.index_id AND m.node_id=n.node_id "
            "WHERE n.index_id=? ORDER BY m.position ASC",
            (index_id,)).fetchall()
        return [{"position": r["position"],
                 "payload": json.loads(r["payload"])} for r in rows]

    @staticmethod
    def _first_divergence(a_ids, b_ids, a_map, b_map) -> dict | None:
        """按因果位置逐位比较，返回首个分叉位置与双方节点标识。"""
        for i, (ia, ib) in enumerate(zip(a_ids, b_ids)):
            if ia != ib:
                kind = "changed"
                return {"position": i, "kind": kind,
                        "node_a": _brief_fork(a_map.get(ia)),
                        "node_b": _brief_fork(b_map.get(ib))}
        if len(a_ids) == len(b_ids):
            return None
        i = min(len(a_ids), len(b_ids))
        if len(a_ids) < len(b_ids):
            return {"position": i, "kind": "a_ends_b_extends",
                    "node_a": None,
                    "node_b": _brief_fork(b_map.get(b_ids[i]))}
        return {"position": i, "kind": "b_ends_a_extends",
                "node_a": _brief_fork(a_map.get(a_ids[i])),
                "node_b": None}


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _brief_fork(node) -> dict | None:
    if node is None:
        return None
    p = node["payload"]
    return {"node_id": p["node_id"], "node_type": p["node_type"],
            "object_id": p.get("object_id"),
            "seq": p.get("seq"), "anchor_seq": p.get("anchor_seq"),
            "position": node["position"]}


def _summarize(issues: list[dict]) -> dict[str, Any]:
    by_code: dict[str, int] = {}
    errors = 0
    for i in issues:
        by_code[i["code"]] = by_code.get(i["code"], 0) + 1
        if i["severity"] == "error":
            errors += 1
    return {"total": len(issues), "errors": errors,
            "issues_by_code": dict(sorted(by_code.items())),
            "consistent": errors == 0}


def _range_error(after_pos, total) -> Exception:
    return NodeOutOfRange(
        f"翻页游标 after={after_pos} 已越过派生链末位（共 {total} 个节点，"
        f"合法游标 -1..{total - 1}）",
        after=after_pos, available_min_cursor=-1,
        available_max_cursor=total - 1)


def _compare_range_error(after_pos, total) -> Exception:
    return NodeOutOfRange(
        f"翻页游标 after={after_pos} 已越过字段变化末位（共 {total} 项，"
        f"合法游标 -1..{total - 1}）",
        after=after_pos, available_min_cursor=-1,
        available_max_cursor=total - 1)


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


def _exactly_one_node(seq, wall, head) -> None:
    if sum([seq is not None, wall is not None, bool(head)]) != 1:
        raise AuditBadRequest(
            "必须且只能用一种方式指定历史节点：at_seq / at_wall_ms / head")
