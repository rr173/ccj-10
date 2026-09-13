"""审计因果索引（audit causal index）。

在租约服务、审计回放、可验证归档与审计证据包能力之上，把一次管理员任务
作用范围内的**租约事件、写入、委托、源归档、证据包条目**组织成一条可查询
的**有向因果链**，并提供创建进度、链路查询、节点重建与独立完整性核验。

冻结语义（创建时一次性钉死，之后任何操作都改不动链）
====================================================
1. ``snapshot_seq``：创建时刻的稳定视图上界；
2. 查询范围：作用域（resource / credential / evidence_package）、历史
   节点选择器（at_seq / at_wall_ms / head，证据包作用域为包创建时钉死的
   快照节点）以及墙钟/序号窗口；
3. 过滤条件：outcome / event 过滤器（规范化 JSON 落库）。

任务创建时即在同一事务里把**成员集合**（节点标识、类型、对象标识、锚点
序号、不可变描述）落进 ``causal_index_members``：链包含哪些节点、按什么
因果顺序排列在创建时就固定。生成期间新增的租约事件、再次核验源归档、
新增归档或证据包都进不了已经冻结的链。

节点因果分层（同层按锚点序号，节点顺序即因果顺序）
==================================================
``lease_event``（租约事件）→ ``write``（接受写入）/ ``delegation``
（委托凭证）→ ``source_archive``（源归档）→ ``evidence_entry``
（证据包条目）。每个节点记录其在链上的前置/后继，第一层按全局审计序号
交错，天然支持跨资源混合链路。

可续跑的后台生成
================
成员是轻量描述，worker 按块（``CAUSAL_CHUNK_SIZE`` 个成员/块）从冻结的
审计事件与归档清单还原节点载荷并写 ``causal_index_nodes``，每块一个事务、
进度落库（``processed_nodes`` / ``last_position``）。服务重启或后台失败
后从已保存位置继续；节点表主键 ``(index_id, node_id)`` +
``INSERT OR IGNORE`` 保证失败重试不会重复写入。

幂等与冲突
==========
- 同作用域、同快照节点、同过滤条件、同幂等键重复创建 → 同一份索引
  （HTTP 200 + ``replayed``）；
- 同一幂等键换作用域/换节点/换范围/换过滤 → 409 ``causal_index_id_conflict``，
  响应给出首个差异字段与双方值。

链路查询
========
按因果顺序返回每个节点的事件序号、对象标识、前置、后继；支持固定快照的
游标分页（游标是节点序号 position），游标越界给 416；响应同时报告断链、
环路、重复序号、缺失源归档或证据包条目等异常。

节点重建
========
``rebuild_node`` 不写任何表：按当前数据库从冻结的成员描述独立重算单个
节点，与冻结节点逐字段比对，返回重建载荷、是否一致与首个差异。

独立核验（verified / verify_failed）
====================================
重新从冻结的审计事件与归档清单计算整条链路：文档总校验值、链摘要、
节点集合、每个节点载荷、前置/后继结构、源归档存在性与其自身核验可信、
源归档/证据包当前内容哈希。任一失败给出**首个差异节点标识、字段路径与
双方值**。

只读边界
========
本模块只写 causal_indexes / causal_index_members / causal_index_nodes
三张自有表，绝不修改租约、委托、原始审计历史、源归档或证据包。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from .archive import (
    ArchiveError,
    VERIFY_FAILED as ARCHIVE_VERIFY_FAILED,
    canonical_json,
    content_sha256,
    first_diff,
)
from .audit import AuditBadRequest, AuditReader, event_dict, project

# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class CausalError(ArchiveError):
    code = "causal_index_error"


class CausalNotFound(CausalError):
    code = "causal_index_not_found"
    status = 404


class CausalNotReady(CausalError):
    code = "causal_index_not_ready"
    status = 409


class CausalIdConflict(CausalError):
    """同一幂等键被作用域/节点/范围/过滤不同的请求占用（409）。"""

    code = "causal_index_id_conflict"
    status = 409


class CausalSourceNotFound(CausalError):
    """证据包作用域指向的证据包不存在（404）。"""

    code = "causal_source_not_found"
    status = 404


class CausalBadState(CausalError):
    """当前状态不允许该操作（如对非 failed 的索引发起重试，409）。"""

    code = "causal_index_bad_state"
    status = 409


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SCOPE_RESOURCE = "resource"
SCOPE_CREDENTIAL = "credential"
SCOPE_EVIDENCE = "evidence_package"
SCOPES = (SCOPE_RESOURCE, SCOPE_CREDENTIAL, SCOPE_EVIDENCE)

NODE_EVENT = "lease_event"
NODE_WRITE = "write"
NODE_DELEGATION = "delegation"
NODE_ARCHIVE = "source_archive"
NODE_EVIDENCE_ENTRY = "evidence_entry"
NODE_TYPES = (NODE_EVENT, NODE_WRITE, NODE_DELEGATION,
              NODE_ARCHIVE, NODE_EVIDENCE_ENTRY)

# 因果分层：数值小的层是数值大的层的原因，同层按锚点序号
LAYER = {
    NODE_EVENT: 0,
    NODE_WRITE: 1,
    NODE_DELEGATION: 1,
    NODE_ARCHIVE: 2,
    NODE_EVIDENCE_ENTRY: 3,
}

STATUS_PENDING = "pending"
STATUS_BUILDING = "building"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUSES = (STATUS_PENDING, STATUS_BUILDING, STATUS_COMPLETED, STATUS_FAILED)

VERIFY_UNVERIFIED = "unverified"
VERIFY_VERIFIED = "verified"
VERIFY_FAILED = "verify_failed"

MAX_ATTEMPTS = 5
CHAIN_V1 = "sha256-causal-chain-v1"
_MISSING = "<missing>"


def chain_seed() -> str:
    return hashlib.sha256(b"lease-audit-causal-chain-v1").hexdigest()


# ---------------------------------------------------------------------------
# 纯函数：过滤条件 / 成员排序 / 节点标识
# ---------------------------------------------------------------------------


def normalize_filters(raw: Any) -> dict[str, Any]:
    """把请求里的过滤参数规范化为一个可冻结、可比较的字典。

    固定键集合保证"相同过滤条件"有唯一表示：outcomes / event_types 为
    排序后的列表（缺省为 None），时间/序号窗口为整数或 None。
    """
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise AuditBadRequest("filters 必须是对象（JSON）")

    # 只允许已知过滤维度：未知键（含拼写错误，如 ``outcome`` 少个 s）必须
    # 明确 400，绝不能被静默丢弃——否则两份"过滤条件不同"的请求会规范化成
    # 同一规格，从而错误地命中幂等回放，把不同派生任务当成同一个任务。
    known = {"outcomes", "event_types", "events", "from_ms", "to_ms",
             "seq_min", "seq_max"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise AuditBadRequest(
            "filters 含不支持的过滤字段：" + "、".join(unknown)
            + "；可用字段为 outcomes / event_types / from_ms / to_ms / "
              "seq_min / seq_max",
            unknown_filters=unknown)

    def as_int(value, name):
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            raise AuditBadRequest(f"filters.{name} 必须是整数", **{name: value})

    outcomes_raw = raw.get("outcomes")
    outcomes = None
    if outcomes_raw not in (None, "", []):
        if isinstance(outcomes_raw, str):
            outcomes = [o for o in outcomes_raw.split(",") if o]
        elif isinstance(outcomes_raw, list):
            outcomes = [str(o) for o in outcomes_raw]
        else:
            raise AuditBadRequest("filters.outcomes 必须是数组或逗号分隔字符串")
        bad = [o for o in outcomes if o not in ("ok", "rejected")]
        if bad:
            raise AuditBadRequest(
                "filters.outcomes 只能包含 ok / rejected", bad_outcomes=bad)
        outcomes = sorted(set(outcomes)) or None

    events_raw = raw.get("event_types", raw.get("events"))
    event_types = None
    if events_raw not in (None, "", []):
        if isinstance(events_raw, str):
            event_types = [e for e in events_raw.split(",") if e]
        elif isinstance(events_raw, list):
            event_types = [str(e) for e in events_raw]
        else:
            raise AuditBadRequest(
                "filters.event_types 必须是数组或逗号分隔字符串")
        if not all(isinstance(e, str) and e for e in event_types):
            raise AuditBadRequest("filters.event_types 含非法事件类型")
        event_types = sorted(set(event_types)) or None

    t_lo = as_int(raw.get("from_ms"), "from_ms")
    t_hi = as_int(raw.get("to_ms"), "to_ms")
    s_lo = as_int(raw.get("seq_min"), "seq_min")
    s_hi = as_int(raw.get("seq_max"), "seq_max")
    if t_lo is not None and t_hi is not None and t_lo > t_hi:
        raise AuditBadRequest("filters.from_ms 不能大于 filters.to_ms",
                              from_ms=t_lo, to_ms=t_hi)
    if s_lo is not None and s_hi is not None and s_lo > s_hi:
        raise AuditBadRequest("filters.seq_min 不能大于 filters.seq_max",
                              seq_min=s_lo, seq_max=s_hi)

    return {
        "from_ms": t_lo,
        "to_ms": t_hi,
        "seq_min": s_lo,
        "seq_max": s_hi,
        "outcomes": outcomes,
        "event_types": event_types,
    }


def event_passes_filters(ev: dict[str, Any], filt: dict[str, Any]) -> bool:
    if filt.get("from_ms") is not None and ev["wall_ms"] < filt["from_ms"]:
        return False
    if filt.get("to_ms") is not None and ev["wall_ms"] > filt["to_ms"]:
        return False
    if filt.get("seq_min") is not None and ev["seq"] < filt["seq_min"]:
        return False
    if filt.get("seq_max") is not None and ev["seq"] > filt["seq_max"]:
        return False
    if filt.get("outcomes") and ev["outcome"] not in filt["outcomes"]:
        return False
    if filt.get("event_types") and ev["event"] not in filt["event_types"]:
        return False
    return True


def event_node_id(seq: int) -> str:
    return f"event:{seq}"


def write_node_id(write_id: int) -> str:
    return f"write:{write_id}"


def delegation_node_id(cid: str) -> str:
    return f"delegation:{cid}"


def archive_node_id(aid: str) -> str:
    return f"archive:{aid}"


def evidence_entry_node_id(pid: str, position: int) -> str:
    return f"evidence:{pid}:{position}"


def member_sort_key(m: dict[str, Any]) -> tuple:
    """因果顺序：先按因果分层，同层按锚点序号（全局 seq 交错），
    再按节点标识兜底，保证确定性。"""
    return (LAYER[m["node_type"]], m["anchor_seq"], m["node_id"])


# ---------------------------------------------------------------------------
# 因果索引管理器
# ---------------------------------------------------------------------------


class CausalIndexManager:
    """因果索引的创建、分块生成、链路查询、节点重建、独立核验与重试。

    与归档/证据包一样刻意与 Store 共用同一把进程锁与连接：创建时在锁内
    钉死快照、范围与成员集合，并发写入要么整体在快照之前、要么在之后。
    """

    def __init__(self, store: Any, audit: AuditReader, *,
                 chunk_size: int = 100):
        self._store = store
        self._audit = audit
        self.chunk_size = max(1, int(chunk_size))

    # ======================================================================
    # 创建（幂等 + 冲突显式化）
    # ======================================================================
    def create_index(
        self,
        *,
        scope: Any,
        resource: Any = None,
        credential_id: Any = None,
        package_id: Any = None,
        at_seq: Any = None,
        at_wall_ms: Any = None,
        head: bool = False,
        filters: Any = None,
        idempotency_key: Any = None,
    ) -> tuple[dict[str, Any], bool]:
        if scope not in SCOPES:
            raise AuditBadRequest(
                "scope 只能取 resource / credential / evidence_package",
                scope=scope)
        if scope == SCOPE_RESOURCE and not resource:
            raise AuditBadRequest("scope=resource 时必须给出 resource")
        if scope == SCOPE_CREDENTIAL and not credential_id:
            raise AuditBadRequest(
                "scope=credential 时必须给出 credential_id")
        if scope == SCOPE_EVIDENCE and not package_id:
            raise AuditBadRequest(
                "scope=evidence_package 时必须给出 package_id")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：同作用域+同快照节点+同范围+同过滤"
                "+同幂等键重复创建只会得到同一份因果索引")
        key = idempotency_key.strip()
        filt = normalize_filters(filters)

        if scope == SCOPE_EVIDENCE:
            if at_seq not in (None, "") or at_wall_ms not in (None, "") \
                    or head:
                raise AuditBadRequest(
                    "scope=evidence_package 的历史节点在证据包创建时已钉死，"
                    "不能再给 at_seq / at_wall_ms / head")
            # 证据包作用域的成员（包条目+源归档覆盖事件）整体冻结，不支持
            # 事件级过滤；需要过滤请对具体资源/凭证作用域建索引
            if any(v is not None for v in filt.values()):
                raise AuditBadRequest(
                    "scope=evidence_package 不支持 filters：包条目与其源归档"
                    "覆盖的事件整体进入因果链")
        else:
            seq = _as_int(at_seq, "at_seq")
            wall = _as_int(at_wall_ms, "at_wall_ms")
            _exactly_one_node(seq, wall, head)

        store = self._store
        with store._lock:  # noqa: SLF001 - 与存储/归档共用同一把锁
            conn = store._conn  # noqa: SLF001
            row = conn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = (int(row["m"])
                       if row is not None and row["m"] is not None else 0)

            if scope == SCOPE_RESOURCE:
                res = str(resource)
                cid = ""
                pid = ""
                node = self._audit._resolve_node(  # noqa: SLF001
                    conn, max_seq, res, seq=seq, wall_ms=wall, head=head)
                node_seq = node["seq"]
            elif scope == SCOPE_CREDENTIAL:
                res = ""
                cid = str(credential_id)
                pid = ""
                node, resource_name, _chain = \
                    self._audit._resolve_credential_node(  # noqa: SLF001
                        conn, max_seq, cid, seq=seq, wall_ms=wall, head=head)
                res = resource_name
                node_seq = node["seq"]
            else:
                res = ""
                cid = ""
                pid = str(package_id)
                pkg = conn.execute(
                    "SELECT * FROM evidence_packages WHERE package_id=?",
                    (pid,)).fetchone()
                if pkg is None:
                    raise CausalSourceNotFound(
                        f"证据包 {pid} 不存在，无法为其创建因果索引",
                        package_id=pid)
                # 证据包的历史节点 = 包创建时冻结的稳定视图上界
                node_seq = int(pkg["snapshot_seq"])

            # 幂等键全局唯一：同键即回放或冲突
            prev = conn.execute(
                "SELECT * FROM causal_indexes WHERE idempotency_key=?",
                (key,)).fetchone()
            if prev is not None:
                diff = self._first_spec_diff(
                    prev, scope, res, cid, pid, node_seq, filt)
                if diff is None:
                    return self._view(prev), False
                raise CausalIdConflict(
                    f"幂等键 {key} 已用于因果索引 {prev['index_id']}，"
                    f"本次请求与首次创建不一致：首个差异位于 {diff['path']}",
                    index_id=prev["index_id"],
                    first_difference=diff)

            # 成员集合在创建事务里一次性冻结
            members = self._build_members_locked(
                conn, scope, res, cid, pid, node_seq, filt)
            ordered = sorted(members, key=member_sort_key)

            index_id = uuid.uuid4().hex
            now = store.clock.wall_ms()
            logical = store.clock.logical()
            try:
                conn.execute(
                    "INSERT INTO causal_indexes(index_id, idempotency_key, "
                    "scope, resource, credential_id, package_id, node_seq, "
                    "snapshot_seq, filters_json, status, total_nodes, "
                    "last_position, created_logical, created_at_ms, "
                    "updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (index_id, key, scope, res, cid, pid, node_seq, max_seq,
                     canonical_json(filt), STATUS_PENDING, len(ordered), -1,
                     logical, now, now))
                for position, m in enumerate(ordered):
                    conn.execute(
                        "INSERT INTO causal_index_members(index_id, position, "
                        "node_id, node_type, object_id, anchor_seq, "
                        "descriptor_json) VALUES(?,?,?,?,?,?,?)",
                        (index_id, position, m["node_id"], m["node_type"],
                         m["object_id"], m["anchor_seq"],
                         canonical_json(m["descriptor"])))
                conn.commit()
            except sqlite3.IntegrityError:
                # 唯一索引兜底（锁内不会走到，防御性保留）
                conn.rollback()
                prev = conn.execute(
                    "SELECT * FROM causal_indexes WHERE idempotency_key=?",
                    (key,)).fetchone()
                if prev is not None:
                    diff = self._first_spec_diff(
                        prev, scope, res, cid, pid, node_seq, filt)
                    if diff is None:
                        return self._view(prev), False
                    raise CausalIdConflict(
                        f"幂等键 {key} 已用于参数不同的因果索引",
                        index_id=prev["index_id"])
                raise
            return self._view(self._get_row(conn, index_id)), True

    @staticmethod
    def _first_spec_diff(prev, scope, res, cid, pid, node_seq,
                         filt) -> dict | None:
        """比较创建规格，返回首个差异字段（路径/字段/双方值）。"""
        checks = [
            ("scope", prev["scope"], scope),
            ("resource", prev["resource"], res),
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
            if diff is None:
                return {"path": "filters", "field": "filters",
                        "existing": old_filters, "requested": filt}
            # 与其它规格字段统一为 existing/requested，同时保留
            # first_diff 的 path 与 archived/recomputed 别名
            diff.setdefault("field", diff["path"])
            diff["existing"] = diff.get("archived")
            diff["requested"] = diff.get("recomputed")
            return diff
        return None

    # ---- 成员集合（创建时冻结） ----------------------------------------
    def _build_members_locked(self, conn, scope, res, cid, pid, node_seq,
                              filt) -> list[dict[str, Any]]:
        if scope == SCOPE_RESOURCE:
            return self._members_resource(conn, res, node_seq, filt)
        if scope == SCOPE_CREDENTIAL:
            return self._members_credential(conn, cid, res, node_seq, filt)
        return self._members_evidence(conn, pid)

    def _event_rows(self, conn, where_sql, args):
        return [event_dict(r) for r in conn.execute(
            f"SELECT * FROM lease_events WHERE {where_sql} ORDER BY seq ASC",
            tuple(args)).fetchall()]

    def _members_from_event_set(self, conn, events,
                                 delegation_events_by_resource=None
                                 ) -> list[dict[str, Any]]:
        """把一批已确定纳入范围的事件展开成 事件/写入/委托 成员。

        - 事件节点：每个事件一个；
        - 写入节点：仅被接受的 write / delegate_write（其 detail 带
          write_id=N），且 writes 表确有该行；锚点是对应事件序号；
        - 委托节点：以"存在成功发放事件"为准（纯由冻结事件决定，不依赖
          运行态 delegations 表——它可能已被收割改状态），锚点是发放事件
          序号；事件集合若已按结果过滤，没有发放事件的凭证不在链上。
        """
        members: list[dict[str, Any]] = []
        granted: dict[str, int] = {}

        def note_grant(cid, seq):
            granted.setdefault(cid, seq)

        for ev in events:
            members.append({
                "node_id": event_node_id(ev["seq"]),
                "node_type": NODE_EVENT,
                "object_id": str(ev["seq"]),
                "anchor_seq": ev["seq"],
                "descriptor": {"kind": "event_ref", "seq": ev["seq"]},
            })
            if ev["outcome"] == "ok" and ev["event"] in (
                    "write", "delegate_write"):
                wid = _parse_write_id(ev.get("detail"))
                if wid is not None:
                    wrow = conn.execute(
                        "SELECT * FROM writes WHERE id=?", (wid,)).fetchone()
                    if wrow is not None:
                        members.append({
                            "node_id": write_node_id(wid),
                            "node_type": NODE_WRITE,
                            "object_id": str(wid),
                            "anchor_seq": ev["seq"],
                            "descriptor": {"kind": "write_ref",
                                           "write_id": wid, "seq": ev["seq"]},
                        })
            if ev["event"] == "delegate_grant" and ev["outcome"] == "ok" \
                    and ev.get("credential_id"):
                note_grant(ev["credential_id"], ev["seq"])

        # 证据包作用域：按资源传入归档节点覆盖的完整事件流补充委托成员，
        # 即使链上的事件集合本身未显式包含某次发放（实际并集会包含）。
        if delegation_events_by_resource is not None:
            for evs in delegation_events_by_resource.values():
                for ev in evs:
                    if ev["event"] == "delegate_grant" and ev["outcome"] == "ok"\
                            and ev.get("credential_id"):
                        note_grant(ev["credential_id"], ev["seq"])

        for ecid, gseq in granted.items():
            members.append({
                "node_id": delegation_node_id(ecid),
                "node_type": NODE_DELEGATION,
                "object_id": ecid,
                "anchor_seq": gseq,
                "descriptor": {"kind": "delegation_ref",
                               "credential_id": ecid, "grant_seq": gseq},
            })
        return members

    def _members_resource(self, conn, resource, node_seq, filt
                          ) -> list[dict[str, Any]]:
        events = self._event_rows(
            conn, "resource=? AND seq<=?", (resource, node_seq))
        filtered = [e for e in events if event_passes_filters(e, filt)]
        members = self._members_from_event_set(conn, filtered)
        members += self._archive_members(
            conn, scope=SCOPE_RESOURCE, resource=resource, cid="",
            node_seq=node_seq,
            include_tip_seqs={e["seq"] for e in filtered})
        return members

    def _members_credential(self, conn, cid, resource, node_seq, filt
                            ) -> list[dict[str, Any]]:
        events = self._event_rows(
            conn, "credential_id=? AND seq<=?", (cid, node_seq))
        filtered = [e for e in events if event_passes_filters(e, filt)]
        members = self._members_from_event_set(conn, filtered)
        members += self._archive_members(
            conn, scope=SCOPE_CREDENTIAL, resource="", cid=cid,
            node_seq=node_seq,
            include_tip_seqs={e["seq"] for e in filtered})
        return members

    def _archive_members(self, conn, *, scope, resource, cid, node_seq,
                         include_tip_seqs=None) -> list[dict[str, Any]]:
        """创建时已完成、冻结节点在本索引历史节点之前（含）的源归档。

        只收录创建这一刻 status=completed 的归档：pending/failed 归档
        之后才完成也进不了冻结链。描述里钉死归档标识与内容校验值。

        include_tip_seqs 用于带事件过滤的资源/凭证作用域：只有归档的冻结
        节点（其作用域末条事件）本身通过过滤、属于过滤后事件集合时才收录，
        保证"过滤结果为空 → 链为空"。证据包作用域不过滤，传 None。
        """
        if scope == SCOPE_RESOURCE:
            rows = conn.execute(
                "SELECT * FROM archives WHERE scope=? AND resource=? "
                "AND status='completed' AND node_seq<=? "
                "ORDER BY node_seq ASC, archive_id ASC",
                (SCOPE_RESOURCE, resource, node_seq)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM archives WHERE scope=? AND credential_id=? "
                "AND status='completed' AND node_seq<=? "
                "ORDER BY node_seq ASC, archive_id ASC",
                (SCOPE_CREDENTIAL, cid, node_seq)).fetchall()
        members = []
        for r in rows:
            if include_tip_seqs is not None \
                    and int(r["node_seq"]) not in include_tip_seqs:
                continue
            members.append({
                "node_id": archive_node_id(r["archive_id"]),
                "node_type": NODE_ARCHIVE,
                "object_id": r["archive_id"],
                "anchor_seq": int(r["node_seq"]),
                "descriptor": {
                    "kind": "archive_ref",
                    "archive_id": r["archive_id"],
                    "scope": r["scope"],
                    "resource": r["resource"],
                    "credential_id": r["credential_id"] or None,
                    "node_seq": int(r["node_seq"]),
                    "snapshot_seq": int(r["snapshot_seq"]),
                    "frozen_content_sha256": r["content_sha256"],
                },
            })
        return members

    def _members_evidence(self, conn, package_id) -> list[dict[str, Any]]:
        """证据包作用域：包条目 + 每份源归档及其节点范围内的事件/写入/委托。

        集合在创建时钉死；不同资源的事件按全局 seq 在第一层交错，形成
        跨资源混合链路。
        """
        entries = conn.execute(
            "SELECT * FROM evidence_entries WHERE package_id=? "
            "ORDER BY position ASC", (package_id,)).fetchall()
        members: list[dict[str, Any]] = []
        # 按资源收集归档节点覆盖的事件，供委托状态纯重放
        per_resource_events: dict[str, list[dict[str, Any]]] = {}
        all_archive_ids: set[str] = set()

        for e in entries:
            aid = e["archive_id"]
            source = conn.execute(
                "SELECT * FROM archives WHERE archive_id=?",
                (aid,)).fetchone()
            # 创建证据包时已校验源归档存在且完成；这里防御性再确认
            if source is None:
                raise CausalSourceNotFound(
                    f"证据包 {package_id} 第 {e['position']} 份源归档 "
                    f"{aid} 已不存在，无法创建因果索引",
                    package_id=package_id, archive_id=aid,
                    position=e["position"])
            if source["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"源归档 {aid} 尚未完成（{source['status']}），"
                    "不能组织进因果索引",
                    archive_id=aid, position=e["position"])
            all_archive_ids.add(aid)

            # 归档节点（描述与证据范围归档节点一致，另记录被收录方式）
            members.append({
                "node_id": archive_node_id(aid),
                "node_type": NODE_ARCHIVE,
                "object_id": aid,
                "anchor_seq": int(source["node_seq"]),
                "descriptor": {
                    "kind": "archive_ref",
                    "archive_id": aid,
                    "scope": source["scope"],
                    "resource": source["resource"],
                    "credential_id": source["credential_id"] or None,
                    "node_seq": int(source["node_seq"]),
                    "snapshot_seq": int(source["snapshot_seq"]),
                    "frozen_content_sha256": source["content_sha256"],
                },
            })

            # 证据包条目节点
            members.append({
                "node_id": evidence_entry_node_id(package_id, e["position"]),
                "node_type": NODE_EVIDENCE_ENTRY,
                "object_id": f"{package_id}:{e['position']}",
                "anchor_seq": int(source["node_seq"]),
                "descriptor": {
                    "kind": "evidence_entry_ref",
                    "package_id": package_id,
                    "position": e["position"],
                    "archive_id": aid,
                    "include_mode": e["include_mode"],
                    "frozen_source_sha256": e["source_sha256"],
                    "frozen_sha256": e["frozen_sha256"],
                    "node_seq": int(source["node_seq"]),
                },
            })

            # 源归档节点范围内的事件
            ev_rows = conn.execute(
                "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
                "ORDER BY seq ASC",
                (source["resource"], source["node_seq"])).fetchall()
            per_resource_events.setdefault(
                source["resource"], []).extend(
                event_dict(r) for r in ev_rows)

        # 事件/写入/委托成员（去重：多份归档可能覆盖同一批事件）
        dedup_events: dict[int, dict[str, Any]] = {}
        for evs in per_resource_events.values():
            for ev in evs:
                dedup_events[ev["seq"]] = ev
        events = [dedup_events[s] for s in sorted(dedup_events)]
        members += self._members_from_event_set(
            conn, events,
            delegation_events_by_resource=per_resource_events)
        return members

    # ======================================================================
    # 查询
    # ======================================================================
    @staticmethod
    def _get_row(conn, index_id):
        return conn.execute(
            "SELECT * FROM causal_indexes WHERE index_id=?",
            (index_id,)).fetchone()

    def get_index(self, index_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None:
                raise CausalNotFound(
                    f"因果索引 {index_id} 不存在", index_id=index_id)
            try:
                return self._view(row)
            finally:
                conn.rollback()

    def list_indexes(self, *, scope=None, status=None, limit: Any = 100
                     ) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        if scope is not None and scope not in SCOPES:
            raise AuditBadRequest(
                "scope 只能取 resource / credential / evidence_package",
                scope=scope)
        if status is not None and status not in STATUSES:
            raise AuditBadRequest(
                "status 只能取 pending/building/completed/failed",
                status=status)
        where, args = [], []
        if scope:
            where.append("scope=?")
            args.append(scope)
        if status:
            where.append("status=?")
            args.append(status)
        sql = "SELECT * FROM causal_indexes"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at_ms ASC, index_id ASC LIMIT ?"
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            rows = conn.execute(sql, (*args, limit)).fetchall()
            try:
                return {"indexes": [self._view(r) for r in rows],
                        "limit": limit}
            finally:
                conn.rollback()

    def _view(self, row) -> dict[str, Any]:
        total, done = row["total_nodes"], row["processed_nodes"]
        return {
            "index_id": row["index_id"],
            "idempotency_key": row["idempotency_key"],
            "scope": row["scope"],
            "resource": row["resource"] or None,
            "credential_id": row["credential_id"] or None,
            "package_id": row["package_id"] or None,
            "node_seq": row["node_seq"],
            "snapshot_seq": row["snapshot_seq"],
            "filters": json.loads(row["filters_json"]),
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
            "chain_url": f"/audit/causal-indexes/{row['index_id']}/chain",
            "download_url":
                f"/audit/causal-indexes/{row['index_id']}/download",
        }

    # ---- 链路查询（因果顺序 + 固定快照游标分页 + 异常报告） -------------
    def get_chain(self, index_id: str, *, after: Any = None,
                  limit: Any = 100) -> dict[str, Any]:
        after_pos = _as_int(after, "after", default=-1)
        if after_pos < -1:
            raise AuditBadRequest("after 不能为负数", after=after_pos)
        limit = _bounded_limit(limit)
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None:
                raise CausalNotFound(
                    f"因果索引 {index_id} 不存在", index_id=index_id)
            if row["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"因果索引 {index_id} 尚未生成完成（当前状态 "
                    f"{row['status']}，进度 {row['processed_nodes']}/"
                    f"{row['total_nodes']}），暂不能查询链路",
                    index_id=index_id, status=row["status"])
            total = row["total_nodes"]
            # 固定快照：视图上界即冻结的节点总数；游标越过末位 → 416
            if after_pos > total - 1:
                raise _range_error(after_pos, total)
            start = after_pos + 1
            node_rows = conn.execute(
                "SELECT n.*, m.position AS position FROM causal_index_nodes n"
                " JOIN causal_index_members m ON m.index_id=n.index_id "
                "AND m.node_id=n.node_id WHERE n.index_id=? AND m.position>=? "
                "ORDER BY m.position ASC LIMIT ?",
                (index_id, start, limit + 1)).fetchall()
            page = node_rows[:limit]
            has_more = len(node_rows) > limit
            nodes = [self._chain_node_view(conn, row, r) for r in page]

            structural = self._structural_anomalies(conn, index_id)
            source_issues = self._live_source_issues(conn, row)
            anomalies = structural + source_issues
            summary = _summarize_anomalies(anomalies)
            try:
                return {
                    "index_id": index_id,
                    "scope": row["scope"],
                    "node_seq": row["node_seq"],
                    "snapshot_seq": row["snapshot_seq"],
                    "filters": json.loads(row["filters_json"]),
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
                             "frozen_node_seq": row["node_seq"],
                             "order": "causal ASC (layer, anchor_seq, node_id)"},
                    "read_only": True,
                }
            finally:
                conn.rollback()

    def _chain_node_view(self, conn, index_row, nrow) -> dict[str, Any]:
        """对外节点：事件序号、对象标识、前置、后继 + 载荷摘要。"""
        payload = json.loads(nrow["payload"])
        position = nrow["position"]
        total = index_row["total_nodes"]
        return {
            "position": position,
            "node_id": payload["node_id"],
            "node_type": payload["node_type"],
            "object_id": payload["object_id"],
            "seq": payload.get("seq"),
            "anchor_seq": payload.get("anchor_seq"),
            "layer": LAYER[payload["node_type"]],
            "prev": payload.get("prev_node_id"),
            "next": payload.get("next_node_id"),
            "node": payload,
        }

    # ---- 链路异常 -------------------------------------------------------
    def _all_frozen_nodes(self, conn, index_id) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT n.payload AS payload, m.position AS position "
            "FROM causal_index_nodes n JOIN causal_index_members m "
            "ON m.index_id=n.index_id AND m.node_id=n.node_id "
            "WHERE n.index_id=? ORDER BY m.position ASC",
            (index_id,)).fetchall()
        return [{"position": r["position"], **json.loads(r["payload"])}
                for r in rows]

    def _structural_anomalies(self, conn, index_id) -> list[dict[str, Any]]:
        """纯由冻结节点计算的结构异常：断链、环路、重复序号。"""
        nodes = self._all_frozen_nodes(conn, index_id)
        issues: list[dict[str, Any]] = []
        by_id = {n["node_id"]: n for n in nodes}

        # 1) 断链：相邻节点的 prev/next 与实际因果邻接不一致，或指向缺失节点
        for i, n in enumerate(nodes):
            expected_prev = nodes[i - 1]["node_id"] if i > 0 else None
            expected_next = (nodes[i + 1]["node_id"]
                             if i + 1 < len(nodes) else None)
            if n.get("prev_node_id") != expected_prev:
                issues.append(_issue(
                    "chain_broken", "error", n,
                    f"节点 {n['node_id']} 的前置为 "
                    f"{n.get('prev_node_id')}，因果链上实际前置应为 "
                    f"{expected_prev}：链路断裂或被重排"))
            if n.get("next_node_id") != expected_next:
                issues.append(_issue(
                    "chain_broken", "error", n,
                    f"节点 {n['node_id']} 的后继为 "
                    f"{n.get('next_node_id')}，因果链上实际后继应为 "
                    f"{expected_next}：链路断裂或被重排"))
            ref_prev = n.get("prev_node_id")
            if ref_prev is not None and ref_prev not in by_id:
                issues.append(_issue(
                    "chain_broken", "error", n,
                    f"节点 {n['node_id']} 的前置 {ref_prev} 在链中缺失"))
            ref_next = n.get("next_node_id")
            if ref_next is not None and ref_next not in by_id:
                issues.append(_issue(
                    "chain_broken", "error", n,
                    f"节点 {n['node_id']} 的后继 {ref_next} 在链中缺失"))

        # 2) 环路：沿 next 指针前进若重复访问同一节点即存在环
        seen: set[str] = set()
        cur = nodes[0]["node_id"] if nodes else None
        steps = 0
        while cur is not None and cur in by_id:
            if cur in seen:
                n = by_id[cur]
                issues.append(_issue(
                    "chain_cycle", "error", n,
                    f"因果链在节点 {cur} 处形成环路，next 指针无法到达链尾"))
                break
            seen.add(cur)
            cur = by_id[cur].get("next_node_id")
            steps += 1
            if steps > len(nodes) + 1:
                break

        # 3) 重复序号：多个事件节点引用同一个审计 seq
        seq_owner: dict[int, str] = {}
        for n in nodes:
            if n["node_type"] != NODE_EVENT:
                continue
            s = n.get("seq")
            if s is None:
                continue
            if s in seq_owner:
                issues.append(_issue(
                    "duplicate_seq", "error", n,
                    f"审计序号 {s} 同时被事件节点 {seq_owner[s]} 与 "
                    f"{n['node_id']} 引用：重复序号"))
            else:
                seq_owner[s] = n["node_id"]
        return issues

    def _live_source_issues(self, conn, index_row) -> list[dict[str, Any]]:
        """针对当前数据库核对源归档/证据包条目是否仍存在且未被改动。

        只读检查：不修改源归档/证据包，也不修改本索引；任何索引、查询或
        核验都不会给源对象落状态。
        """
        index_id = index_row["index_id"]
        issues: list[dict[str, Any]] = []
        members = conn.execute(
            "SELECT node_id, node_type, descriptor_json FROM "
            "causal_index_members WHERE index_id=? "
            "AND node_type IN (?,?) ORDER BY position ASC",
            (index_id, NODE_ARCHIVE, NODE_EVIDENCE_ENTRY)).fetchall()
        for m in members:
            desc = json.loads(m["descriptor_json"])
            if m["node_type"] == NODE_ARCHIVE:
                self._check_archive_source(conn, desc, issues)
            else:
                self._check_evidence_entry_source(conn, desc, issues)
        return issues

    def _check_archive_source(self, conn, desc, issues) -> None:
        aid = desc["archive_id"]
        row = conn.execute(
            "SELECT * FROM archives WHERE archive_id=?", (aid,)).fetchone()
        node_id = archive_node_id(aid)
        if row is None:
            issues.append({
                "code": "source_archive_missing", "severity": "error",
                "node_id": node_id, "archive_id": aid, "seq": desc["node_seq"],
                "message": f"源归档 {aid} 已不存在：因果链引用的归档缺失"})
            return
        if row["content_sha256"] != desc["frozen_content_sha256"]:
            issues.append({
                "code": "source_archive_changed", "severity": "error",
                "node_id": node_id, "archive_id": aid, "seq": desc["node_seq"],
                "message": f"源归档 {aid} 当前内容校验值与索引冻结值不一致"
                           "（源归档内容可能被改动）",
                "frozen": desc["frozen_content_sha256"],
                "current": row["content_sha256"]})
        if row["verify_status"] == ARCHIVE_VERIFY_FAILED:
            issues.append({
                "code": "source_archive_verify_failed", "severity": "error",
                "node_id": node_id, "archive_id": aid, "seq": desc["node_seq"],
                "message": f"源归档 {aid} 的独立核验已失败（verify_failed），"
                           "其内容不可信，因果链源不可信"})

    def _check_evidence_entry_source(self, conn, desc, issues) -> None:
        pid, position = desc["package_id"], desc["position"]
        node_id = evidence_entry_node_id(pid, position)
        pkg = conn.execute(
            "SELECT * FROM evidence_packages WHERE package_id=?",
            (pid,)).fetchone()
        if pkg is None:
            issues.append({
                "code": "evidence_entry_missing", "severity": "error",
                "node_id": node_id, "package_id": pid, "position": position,
                "message": f"证据包 {pid} 已不存在：条目 {position} 缺失"})
            return
        entry = conn.execute(
            "SELECT * FROM evidence_entries WHERE package_id=? AND position=?",
            (pid, position)).fetchone()
        if entry is None:
            issues.append({
                "code": "evidence_entry_missing", "severity": "error",
                "node_id": node_id, "package_id": pid, "position": position,
                "message": f"证据包 {pid} 缺少第 {position} 个条目"})
            return
        if entry["archive_id"] != desc["archive_id"]:
            issues.append({
                "code": "evidence_entry_changed", "severity": "error",
                "node_id": node_id, "package_id": pid, "position": position,
                "message": f"证据包 {pid} 第 {position} 个条目的归档标识"
                           "与冻结值不一致",
                "frozen": desc["archive_id"],
                "current": entry["archive_id"]})
        if entry["source_sha256"] != desc["frozen_source_sha256"]:
            issues.append({
                "code": "evidence_entry_changed", "severity": "error",
                "node_id": node_id, "package_id": pid, "position": position,
                "message": f"证据包 {pid} 第 {position} 个条目的源哈希"
                           "与冻结值不一致",
                "frozen": desc["frozen_source_sha256"],
                "current": entry["source_sha256"]})
            return
        content_row = conn.execute(
            "SELECT payload FROM evidence_entry_contents WHERE package_id=? "
            "AND position=?", (pid, position)).fetchone()
        if content_row is None:
            issues.append({
                "code": "evidence_entry_missing", "severity": "error",
                "node_id": node_id, "package_id": pid, "position": position,
                "message": f"证据包 {pid} 第 {position} 个条目的冻结载荷缺失"})
            return
        current_frozen = hashlib.sha256(
            content_row["payload"].encode("utf-8")).hexdigest()
        if desc["frozen_sha256"] is not None \
                and current_frozen != desc["frozen_sha256"]:
            issues.append({
                "code": "evidence_entry_changed", "severity": "error",
                "node_id": node_id, "package_id": pid, "position": position,
                "message": f"证据包 {pid} 第 {position} 个条目的冻结载荷"
                           "哈希与索引冻结值不一致（载荷可能被篡改）",
                "frozen": desc["frozen_sha256"],
                "current": current_frozen})

    # ======================================================================
    # 单节点查询
    # ======================================================================
    def get_frozen_node(self, index_id: str, node_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None:
                raise CausalNotFound(
                    f"因果索引 {index_id} 不存在", index_id=index_id)
            if row["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"因果索引 {index_id} 尚未生成完成（{row['status']}），"
                    "节点尚不可查询",
                    index_id=index_id, status=row["status"])
            member = conn.execute(
                "SELECT * FROM causal_index_members WHERE index_id=? "
                "AND node_id=?", (index_id, node_id)).fetchone()
            if member is None:
                raise CausalNotFound(
                    f"节点 {node_id} 不在因果索引 {index_id} 的冻结链中",
                    index_id=index_id, node_id=node_id)
            nrow = conn.execute(
                "SELECT * FROM causal_index_nodes WHERE index_id=? "
                "AND node_id=?", (index_id, node_id)).fetchone()
            try:
                payload = json.loads(nrow["payload"])
                return {
                    "index_id": index_id,
                    "position": member["position"],
                    "node_id": node_id,
                    "node_type": member["node_type"],
                    "object_id": member["object_id"],
                    "seq": payload.get("seq"),
                    "anchor_seq": payload.get("anchor_seq"),
                    "prev": payload.get("prev_node_id"),
                    "next": payload.get("next_node_id"),
                    "node": payload,
                    "read_only": True,
                }
            finally:
                conn.rollback()

    # ======================================================================
    # 下载（落库的链文档，字节稳定）
    # ======================================================================
    def download(self, index_id: str) -> tuple[str, dict[str, Any]]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None:
                raise CausalNotFound(
                    f"因果索引 {index_id} 不存在", index_id=index_id)
            if row["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"因果索引 {index_id} 尚未生成完成（当前状态 "
                    f"{row['status']}），暂不能下载",
                    index_id=index_id, status=row["status"])
            try:
                return row["content"], self._view(row)
            finally:
                conn.rollback()

    # ======================================================================
    # 后台生成：分块还原节点 + 进度落库，可续跑
    # ======================================================================
    def process_pending(self, *, max_indexes: int | None = None,
                        max_chunks_per_index: int | None = None) -> int:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            rows = conn.execute(
                "SELECT index_id FROM causal_indexes WHERE status IN (?,?)"
                " OR (status=? AND attempts<?) "
                "ORDER BY created_at_ms ASC, index_id ASC",
                (STATUS_PENDING, STATUS_BUILDING, STATUS_FAILED,
                 MAX_ATTEMPTS)).fetchall()
            conn.rollback()
        ids = [r["index_id"] for r in rows]
        if max_indexes is not None:
            ids = ids[:max_indexes]
        n = 0
        for index_id in ids:
            if self._process_one(index_id, max_chunks=max_chunks_per_index):
                n += 1
        return n

    def _process_one(self, index_id: str, *, max_chunks: int | None) -> bool:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None or row["status"] == STATUS_COMPLETED:
                return False
            try:
                if row["status"] in (STATUS_PENDING, STATUS_FAILED):
                    conn.execute(
                        "UPDATE causal_indexes SET status=?, "
                        "attempts=attempts+1, error=NULL, updated_at_ms=? "
                        "WHERE index_id=?",
                        (STATUS_BUILDING, store.clock.wall_ms(), index_id))
                    conn.commit()
                chunks = 0
                while True:
                    row = self._get_row(conn, index_id)
                    if row["processed_nodes"] >= row["total_nodes"]:
                        break
                    if max_chunks is not None and chunks >= max_chunks:
                        return True
                    self._build_chunk_locked(row)
                    chunks += 1
                self._finalize_locked(index_id)
                return True
            except Exception as exc:  # noqa: BLE001 - 失败落库后可续跑
                conn.rollback()
                conn.execute(
                    "UPDATE causal_indexes SET status=?, error=?, "
                    "updated_at_ms=? WHERE index_id=?",
                    (STATUS_FAILED, f"{type(exc).__name__}: {exc}",
                     store.clock.wall_ms(), index_id))
                conn.commit()
                return True

    def _build_chunk_locked(self, row) -> int:
        """从冻结成员还原下一块节点载荷（单事务提交一块）。

        节点表主键 (index_id, node_id) + INSERT OR IGNORE：重启续跑/失败
        重试跳过已还原节点，绝不重复写入。载荷由冻结事件与归档清单确定，
        不读可变运行态，因此同一块重试生成的内容逐字节一致。
        """
        conn = self._store._conn  # noqa: SLF001
        index_id = row["index_id"]
        members = conn.execute(
            "SELECT * FROM causal_index_members WHERE index_id=? "
            "AND position>? ORDER BY position ASC LIMIT ?",
            (index_id, row["last_position"], self.chunk_size)).fetchall()
        if not members:
            conn.execute(
                "UPDATE causal_indexes SET processed_nodes=total_nodes, "
                "updated_at_ms=? WHERE index_id=?",
                (self._store.clock.wall_ms(), index_id))
            conn.commit()
            return 0

        total = row["total_nodes"]
        for m in members:
            desc = json.loads(m["descriptor_json"])
            payload = self._build_node_payload(conn, row, desc,
                                               m["position"], total)
            conn.execute(
                "INSERT OR IGNORE INTO causal_index_nodes(index_id, node_id, "
                "node_type, position, payload_sha256, payload) "
                "VALUES(?,?,?,?,?,?)",
                (index_id, payload["node_id"], payload["node_type"],
                 m["position"], payload_sha(payload),
                 canonical_json(payload)))
        conn.execute(
            "UPDATE causal_indexes SET processed_nodes=processed_nodes+?, "
            "last_position=?, updated_at_ms=? WHERE index_id=?",
            (len(members), members[-1]["position"],
             self._store.clock.wall_ms(), index_id))
        conn.commit()
        return len(members)

    # ---- 单节点载荷：从冻结审计事件与归档清单重建 ----------------------
    def _build_node_payload(self, conn, index_row, desc, position, total
                            ) -> dict[str, Any]:
        kind = desc["kind"]
        if kind == "event_ref":
            payload = self._payload_event(conn, desc["seq"])
        elif kind == "write_ref":
            payload = self._payload_write(conn, desc["write_id"], desc["seq"])
        elif kind == "delegation_ref":
            payload = self._payload_delegation(
                conn, index_row, desc["credential_id"])
        elif kind == "archive_ref":
            payload = self._payload_archive(conn, desc)
        elif kind == "evidence_entry_ref":
            payload = self._payload_evidence_entry(conn, desc)
        else:
            raise CausalError(f"未知成员类型 {kind}")
        payload["position"] = position
        payload["prev_node_id"] = self._node_id_at(conn, index_row["index_id"],
                                                   position - 1)
        payload["next_node_id"] = (self._node_id_at(conn, index_row["index_id"],
                                                    position + 1)
                                   if position + 1 < total else None)
        return payload

    def _node_id_at(self, conn, index_id, position):
        if position < 0:
            return None
        r = conn.execute(
            "SELECT node_id FROM causal_index_members WHERE index_id=? "
            "AND position=?", (index_id, position)).fetchone()
        return r["node_id"] if r else None

    def _payload_event(self, conn, seq) -> dict[str, Any]:
        r = conn.execute(
            "SELECT * FROM lease_events WHERE seq=?", (seq,)).fetchone()
        if r is None:
            raise CausalError(
                f"冻结的审计事件 seq={seq} 在原始历史中缺失，无法还原节点；"
                "审计历史可能被删除")
        ev = event_dict(r)
        return {
            "kind": NODE_EVENT,
            "node_id": event_node_id(seq),
            "node_type": NODE_EVENT,
            "object_id": str(seq),
            "seq": seq,
            "anchor_seq": seq,
            "event": {
                "seq": ev["seq"], "resource": ev["resource"],
                "event": ev["event"], "outcome": ev["outcome"],
                "accepted": ev["accepted"], "holder": ev["holder"],
                "peer": ev["peer"], "lease_id": ev["lease_id"],
                "generation": ev["generation"],
                "to_lease_id": ev["to_lease_id"],
                "to_generation": ev["to_generation"],
                "credential_id": ev["credential_id"],
                "detail": ev["detail"], "value": ev["value"],
                "wall_ms": ev["wall_ms"], "logical": ev["logical"],
                "narration": ev["narration"],
            },
        }

    def _payload_write(self, conn, write_id, source_seq) -> dict[str, Any]:
        r = conn.execute(
            "SELECT * FROM writes WHERE id=?", (write_id,)).fetchone()
        if r is None:
            raise CausalError(
                f"冻结的写入 write_id={write_id} 在写入审计中缺失，"
                "无法还原节点")
        # 锚点序号在创建成员时由成功写入事件冻结；当前历史中仍核对一次
        ev = conn.execute(
            "SELECT seq FROM lease_events WHERE resource=? AND event IN "
            "('write','delegate_write') AND outcome='ok' AND detail=? "
            "ORDER BY seq ASC LIMIT 1",
            (r["resource"], f"write_id={write_id}")).fetchone()
        seq = ev["seq"] if ev else source_seq
        return {
            "kind": NODE_WRITE,
            "node_id": write_node_id(write_id),
            "node_type": NODE_WRITE,
            "object_id": str(write_id),
            "seq": seq,
            "anchor_seq": seq,
            "write": {
                "write_id": r["id"], "resource": r["resource"],
                "generation": r["generation"], "lease_id": r["lease_id"],
                "holder": r["holder"], "accepted": bool(r["accepted"]),
                "reject_reason": r["reject_reason"],
                "created_at_ms": r["created_at_ms"],
                "credential_id": r["credential_id"],
                "source_event_seq": seq,
            },
        }

    def _payload_delegation(self, conn, index_row, credential_id
                            ) -> dict[str, Any]:
        """委托状态完全由冻结审计事件纯重放得到（不读运行态 delegations）。"""
        grant = conn.execute(
            "SELECT * FROM lease_events WHERE credential_id=? AND event="
            "'delegate_grant' AND outcome='ok' ORDER BY seq ASC LIMIT 1",
            (credential_id,)).fetchone()
        if grant is None:
            raise CausalError(
                f"委托凭证 {credential_id} 的冻结发放事件缺失，无法还原节点")
        resource = grant["resource"]
        # 重放范围：到索引冻结节点；证据包作用域按该凭证发放资源的全部
        # 归档节点范围并集（创建成员时使用同一并集语义）。
        ceil = self._delegation_replay_ceil(conn, index_row, resource)
        ev_rows = conn.execute(
            "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
            "ORDER BY seq ASC", (resource, ceil)).fetchall()
        st = project(resource, [event_dict(r) for r in ev_rows],
                     check_clocks=False)
        d = st.delegations.get(credential_id)
        state_view = d.view() if d is not None else None
        return {
            "kind": NODE_DELEGATION,
            "node_id": delegation_node_id(credential_id),
            "node_type": NODE_DELEGATION,
            "object_id": credential_id,
            "seq": grant["seq"],
            "anchor_seq": grant["seq"],
            "delegation": state_view,
        }

    def _delegation_replay_ceil(self, conn, index_row, resource) -> int:
        if index_row["scope"] in (SCOPE_RESOURCE, SCOPE_CREDENTIAL):
            return int(index_row["node_seq"])
        # evidence_package：该资源在包内被覆盖到的最大归档节点
        archive_ids = [json.loads(r["descriptor_json"])["archive_id"]
                       for r in conn.execute(
                           "SELECT descriptor_json FROM causal_index_members "
                           "WHERE index_id=? AND node_type=?",
                           (index_row["index_id"], NODE_ARCHIVE)).fetchall()]
        ceil = 0
        for aid in archive_ids:
            a = conn.execute(
                "SELECT node_seq, resource FROM archives WHERE archive_id=?",
                (aid,)).fetchone()
            if a is not None and a["resource"] == resource:
                ceil = max(ceil, int(a["node_seq"]))
        return ceil or int(index_row["node_seq"])

    def _payload_archive(self, conn, desc) -> dict[str, Any]:
        aid = desc["archive_id"]
        r = conn.execute(
            "SELECT * FROM archives WHERE archive_id=?", (aid,)).fetchone()
        current_sha = r["content_sha256"] if r is not None else None
        return {
            "kind": NODE_ARCHIVE,
            "node_id": archive_node_id(aid),
            "node_type": NODE_ARCHIVE,
            "object_id": aid,
            "seq": desc["node_seq"],
            "anchor_seq": desc["node_seq"],
            "source_archive": {
                "archive_id": aid,
                "scope": desc["scope"],
                "resource": desc["resource"],
                "credential_id": desc["credential_id"],
                "node_seq": desc["node_seq"],
                "snapshot_seq": desc["snapshot_seq"],
                "content_sha256": (current_sha
                                  if current_sha is not None
                                  else desc["frozen_content_sha256"]),
                "frozen_content_sha256": desc["frozen_content_sha256"],
                "exists": r is not None,
                "status": r["status"] if r is not None else None,
                "verify_status": r["verify_status"] if r is not None else None,
            },
        }

    def _payload_evidence_entry(self, conn, desc) -> dict[str, Any]:
        pid, position = desc["package_id"], desc["position"]
        entry = conn.execute(
            "SELECT * FROM evidence_entries WHERE package_id=? AND position=?",
            (pid, position)).fetchone()
        content_row = conn.execute(
            "SELECT payload FROM evidence_entry_contents WHERE package_id=? "
            "AND position=?", (pid, position)).fetchone()
        current_frozen_sha = None
        if content_row is not None:
            current_frozen_sha = hashlib.sha256(
                content_row["payload"].encode("utf-8")).hexdigest()
        return {
            "kind": NODE_EVIDENCE_ENTRY,
            "node_id": evidence_entry_node_id(pid, position),
            "node_type": NODE_EVIDENCE_ENTRY,
            "object_id": f"{pid}:{position}",
            "seq": desc["node_seq"],
            "anchor_seq": desc["node_seq"],
            "evidence_entry": {
                "package_id": pid,
                "position": position,
                "archive_id": desc["archive_id"],
                "include_mode": desc["include_mode"],
                "source_sha256": (entry["source_sha256"] if entry is not None
                                  else desc["frozen_source_sha256"]),
                "frozen_source_sha256": desc["frozen_source_sha256"],
                "frozen_sha256": (entry["frozen_sha256"] if entry is not None
                                  else desc["frozen_sha256"]),
                "exists": entry is not None,
                "payload_present": content_row is not None,
                "current_payload_sha256": current_frozen_sha,
            },
        }

    # ---- 定稿：组装链文档、链摘要与总校验值 ----------------------------
    def _finalize_locked(self, index_id: str) -> None:
        conn = self._store._conn  # noqa: SLF001
        row = self._get_row(conn, index_id)
        node_rows = conn.execute(
            "SELECT n.payload AS payload FROM causal_index_nodes n "
            "JOIN causal_index_members m ON m.index_id=n.index_id "
            "AND m.node_id=n.node_id WHERE n.index_id=? "
            "ORDER BY m.position ASC", (index_id,)).fetchall()
        nodes = [json.loads(r["payload"]) for r in node_rows]
        if len(nodes) != row["total_nodes"]:
            raise CausalError(
                f"节点数不一致：成员 {row['total_nodes']}，已还原 {len(nodes)}")

        structural = self._structural_anomalies_from_payloads(nodes)
        digest = self._compute_chain_digest(nodes)
        core = {
            "kind": "lease_audit_causal_index",
            "version": 1,
            "index_id": index_id,
            "idempotency_key": row["idempotency_key"],
            "scope": row["scope"],
            "resource": row["resource"] or None,
            "credential_id": row["credential_id"] or None,
            "package_id": row["package_id"] or None,
            "node_seq": row["node_seq"],
            "snapshot_seq": row["snapshot_seq"],
            "filters": json.loads(row["filters_json"]),
            "chain_order": {
                "algorithm": CHAIN_V1,
                "rule": "layer (lease_event < write/delegation < "
                        "source_archive < evidence_entry), then anchor_seq, "
                        "then node_id",
                "total_nodes": len(nodes),
            },
            "nodes": nodes,
            "anomalies": structural,
            "anomaly_summary": _summarize_anomalies(structural),
            "created_at_ms": row["created_at_ms"],
            "created_logical": row["created_logical"],
        }
        core["chain_digest"] = digest
        core["content_sha256"] = content_sha256(core)
        text = json.dumps(core, ensure_ascii=False, sort_keys=True)
        now = self._store.clock.wall_ms()
        conn.execute(
            "UPDATE causal_indexes SET status=?, content=?, content_sha256=?,"
            " chain_digest=?, processed_nodes=total_nodes, "
            "completed_at_ms=?, updated_at_ms=? WHERE index_id=?",
            (STATUS_COMPLETED, text, core["content_sha256"], digest,
             now, now, index_id))
        conn.commit()

    @staticmethod
    def _compute_chain_digest(nodes) -> str:
        """顺序敏感的链摘要：从固定初值起，逐步混入位置、节点标识与节点载荷
        哈希。断链/重排/改任一节点内容都会改变摘要。"""
        digest = chain_seed()
        for position, n in enumerate(nodes):
            node_payload = {k: v for k, v in n.items()
                            if k not in ("position", "prev_node_id",
                                         "next_node_id")}
            node_sha = hashlib.sha256(
                canonical_json(node_payload).encode("utf-8")).hexdigest()
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

    def _structural_anomalies_from_payloads(self, nodes) -> list[dict[str, Any]]:
        """与 _structural_anomalies 同语义，但输入是定稿时的载荷列表。"""
        issues: list[dict[str, Any]] = []
        by_id = {n["node_id"]: n for n in nodes}
        for i, n in enumerate(nodes):
            expected_prev = nodes[i - 1]["node_id"] if i > 0 else None
            expected_next = (nodes[i + 1]["node_id"]
                             if i + 1 < len(nodes) else None)
            if n.get("prev_node_id") != expected_prev or \
                    n.get("next_node_id") != expected_next:
                issues.append(_issue(
                    "chain_broken", "error", n,
                    f"节点 {n['node_id']} 的前置/后继与因果邻接不一致："
                    "链路断裂或被重排"))
            for ref, label in ((n.get("prev_node_id"), "前置"),
                               (n.get("next_node_id"), "后继")):
                if ref is not None and ref not in by_id:
                    issues.append(_issue(
                        "chain_broken", "error", n,
                        f"节点 {n['node_id']} 的{label} {ref} 在链中缺失"))
        seen: set[str] = set()
        cur = nodes[0]["node_id"] if nodes else None
        steps = 0
        while cur is not None and cur in by_id:
            if cur in seen:
                issues.append(_issue(
                    "chain_cycle", "error", by_id[cur],
                    f"因果链在节点 {cur} 处形成环路"))
                break
            seen.add(cur)
            cur = by_id[cur].get("next_node_id")
            steps += 1
            if steps > len(nodes) + 1:
                break
        seq_owner: dict[int, str] = {}
        for n in nodes:
            if n["node_type"] != NODE_EVENT:
                continue
            s = n.get("seq")
            if s is None:
                continue
            if s in seq_owner:
                issues.append(_issue(
                    "duplicate_seq", "error", n,
                    f"审计序号 {s} 被多个事件节点引用：重复序号"))
            else:
                seq_owner[s] = n["node_id"]
        return issues

    # ======================================================================
    # 节点重建（只读，独立重算单节点并与冻结节点比对）
    # ======================================================================
    def rebuild_node(self, index_id: str, node_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None:
                raise CausalNotFound(
                    f"因果索引 {index_id} 不存在", index_id=index_id)
            if row["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"因果索引 {index_id} 尚未生成完成（{row['status']}），"
                    "不能重建节点",
                    index_id=index_id, status=row["status"])
            member = conn.execute(
                "SELECT * FROM causal_index_members WHERE index_id=? "
                "AND node_id=?", (index_id, node_id)).fetchone()
            if member is None:
                raise CausalNotFound(
                    f"节点 {node_id} 不在因果索引 {index_id} 的冻结链中",
                    index_id=index_id, node_id=node_id)
            frozen_row = conn.execute(
                "SELECT * FROM causal_index_nodes WHERE index_id=? "
                "AND node_id=?", (index_id, node_id)).fetchone()
            frozen = json.loads(frozen_row["payload"])
            desc = json.loads(member["descriptor_json"])
            rebuild_error = None
            try:
                recomputed = self._build_node_payload(
                    conn, row, desc, member["position"], row["total_nodes"])
            except CausalError as exc:
                # 源事件/写入已被删除等：节点无法从当前库独立重建，
                # 明确报告为该节点的首个差异（不抛 500、不写任何表）
                recomputed = None
                rebuild_error = str(exc)
            if rebuild_error is not None:
                diff = {
                    "path": f"nodes[{member['position']}]",
                    "archived": "<present>",
                    "recomputed": _MISSING,
                    "message": rebuild_error,
                }
            else:
                diff = first_diff(
                    frozen, recomputed, f"nodes[{member['position']}]")
            result = {
                "index_id": index_id,
                "node_id": node_id,
                "position": member["position"],
                "node_type": member["node_type"],
                "frozen": frozen,
                "rebuilt": recomputed,
                "matches": diff is None,
                "first_divergence": diff,
                "read_only": True,
            }
            conn.rollback()  # 纯只读：绝不写任何表
            return result

    # ======================================================================
    # 独立核验
    # ======================================================================
    def verify(self, index_id: str) -> dict[str, Any]:
        """重新从冻结审计事件与归档清单计算整条链路并与冻结内容比对。

        检查顺序（首个失败即标记 verify_failed 并给出首个差异节点标识、
        字段路径与双方值）：
        1. 链文档与保存的总校验值一致；
        2. 源依赖可用：源归档存在、其自身核验未失败、内容哈希未变；证据
           包条目存在且归档标识/源哈希未变（缺失源归档/证据包条目在此
           明确报告，而不是退化成节点载荷差异）；
        3. 冻结成员集合与从冻结事件/归档清单重算的成员集合一致；
        4. 每个事件/写入/委托节点载荷可由当前数据库独立重建，且与冻结
           节点逐字段一致（源归档/证据条目节点只在第 2 步核对）；
        5. 链摘要可由冻结节点独立重算。
        核验只写 causal_indexes 的核验标记，绝不触碰源对象。
        """
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None:
                raise CausalNotFound(
                    f"因果索引 {index_id} 不存在", index_id=index_id)
            if row["status"] != STATUS_COMPLETED:
                raise CausalNotReady(
                    f"因果索引 {index_id} 尚未生成完成（{row['status']}），"
                    "不能核验",
                    index_id=index_id, status=row["status"])
            content = json.loads(row["content"])

            divergence = self._check_checksum(row, content)
            if divergence is None:
                divergence = self._check_sources(conn, row)
            if divergence is None:
                divergence = self._check_membership(conn, row, content)
            if divergence is None:
                divergence = self._check_nodes(conn, row, content)
            if divergence is None:
                divergence = self._check_chain_digest(content)
            now = store.clock.wall_ms()
            if divergence is None:
                conn.execute(
                    "UPDATE causal_indexes SET verify_status=?, "
                    "verify_detail=NULL, verified_at_ms=?, updated_at_ms=? "
                    "WHERE index_id=?",
                    (VERIFY_VERIFIED, now, now, index_id))
                result = {
                    "index_id": index_id,
                    "verify_status": VERIFY_VERIFIED,
                    "first_divergence": None,
                    "message": "独立核验通过：总校验值、成员集合、逐节点载荷、"
                               "链摘要与全部源归档/证据包条目均一致",
                }
            else:
                detail = json.dumps(divergence, ensure_ascii=False)
                conn.execute(
                    "UPDATE causal_indexes SET verify_status=?, "
                    "verify_detail=?, verified_at_ms=?, updated_at_ms=? "
                    "WHERE index_id=?",
                    (VERIFY_FAILED, detail, now, now, index_id))
                result = {
                    "index_id": index_id,
                    "verify_status": VERIFY_FAILED,
                    "first_divergence": divergence,
                    "message": "核验失败：首个差异位于 "
                               f"{divergence.get('path')}（节点 "
                               f"{divergence.get('node_id')}："
                               f"{divergence.get('message', '内容不一致')}）",
                }
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
            return {
                "section": "checksum", "path": "content_sha256",
                "node_id": None,
                "expected": row["content_sha256"],
                "archived": content.get("content_sha256"),
                "recomputed": actual,
                "message": "因果索引文档与保存的总校验值不符，文档可能被篡改",
            }
        return None

    def _check_membership(self, conn, row, content) -> dict | None:
        """从冻结的审计事件与归档清单重算成员集合，与冻结成员比对。"""
        scope = row["scope"]
        filt = json.loads(row["filters_json"])
        node_seq = row["node_seq"]
        try:
            recomputed = self._build_members_locked(
                conn, scope, row["resource"], row["credential_id"],
                row["package_id"], node_seq, filt)
        except CausalError as exc:
            return {
                "section": "membership", "path": "members", "node_id": None,
                "archived": "<present>", "recomputed": _MISSING,
                "message": str(exc)}
        recomputed.sort(key=member_sort_key)
        frozen_members = [
            {"node_id": r["node_id"], "node_type": r["node_type"],
             "object_id": r["object_id"], "anchor_seq": r["anchor_seq"]}
            for r in conn.execute(
                "SELECT node_id, node_type, object_id, anchor_seq FROM "
                "causal_index_members WHERE index_id=? ORDER BY position ASC",
                (row["index_id"],)).fetchall()]
        fresh_members = [
            {"node_id": m["node_id"], "node_type": m["node_type"],
             "object_id": m["object_id"], "anchor_seq": m["anchor_seq"]}
            for m in recomputed]
        diff = first_diff(frozen_members, fresh_members, "members")
        if diff is not None:
            return {**diff, "section": "membership", "node_id": None,
                    "message": "从冻结审计事件与归档清单重算的成员集合与"
                               "冻结成员不一致（历史或源归档可能被删改）"}
        return None

    def _check_nodes(self, conn, row, content) -> dict | None:
        index_id = row["index_id"]
        members = conn.execute(
            "SELECT * FROM causal_index_members WHERE index_id=? "
            "ORDER BY position ASC", (index_id,)).fetchall()
        frozen_by_id = {n["node_id"]: n for n in conn.execute(
            "SELECT * FROM causal_index_nodes WHERE index_id=?",
            (index_id,)).fetchall()}
        doc_by_id = {n.get("node_id"): n for n in content.get("nodes", [])}
        for m in members:
            # 源归档/证据包条目节点的源可用性由 _check_sources 专门核对，
            # 这里只独立重算事件/写入/委托三类派生节点
            if m["node_type"] in (NODE_ARCHIVE, NODE_EVIDENCE_ENTRY):
                continue
            desc = json.loads(m["descriptor_json"])
            try:
                recomputed = self._build_node_payload(
                    conn, row, desc, m["position"], row["total_nodes"])
            except CausalError as exc:
                return {
                    "section": "nodes",
                    "path": f"nodes[{m['position']}]",
                    "node_id": m["node_id"],
                    "archived": "<present>", "recomputed": _MISSING,
                    "message": str(exc)}
            # 先核对下载文档中的节点（文档可能被单独篡改），再核对冻结表
            doc_node = doc_by_id.get(m["node_id"])
            if doc_node is not None:
                diff = first_diff(doc_node, recomputed,
                                  f"nodes[{m['position']}]")
                if diff is not None:
                    return {**diff, "section": "nodes",
                            "node_id": m["node_id"],
                            "message": f"链文档节点 {m['node_id']} 无法从冻结"
                                       "审计事件独立重建得到（文档可能被篡改）"}
            frozen = json.loads(frozen_by_id[m["node_id"]]["payload"])
            diff = first_diff(frozen, recomputed,
                              f"nodes[{m['position']}]")
            if diff is not None:
                return {**diff, "section": "nodes",
                        "node_id": m["node_id"],
                        "message": f"节点 {m['node_id']} 的载荷无法从冻结"
                                   "审计事件/归档清单独立重建得到"}
        # 文档内节点顺序与成员位置一致
        doc_ids = [n["node_id"] for n in content.get("nodes", [])]
        member_ids = [m["node_id"] for m in members]
        if doc_ids != member_ids:
            diff = first_diff(member_ids, doc_ids, "nodes")
            return {**(diff or {"path": "nodes", "archived": member_ids,
                                "recomputed": doc_ids}),
                    "section": "nodes", "node_id": None,
                    "message": "链文档节点顺序与冻结成员顺序不一致"}
        return None

    def _check_chain_digest(self, content) -> dict | None:
        nodes = content.get("nodes", [])
        digest = self._compute_chain_digest(nodes)
        if digest != content.get("chain_digest"):
            return {
                "section": "chain_digest", "path": "chain_digest",
                "node_id": None, "archived": content.get("chain_digest"),
                "recomputed": digest,
                "message": "链摘要无法由冻结节点按因果顺序独立重算得到："
                           "顺序或某节点内容可能被改动"}
        return None

    def _check_sources(self, conn, row) -> dict | None:
        issues = self._live_source_issues(conn, row)
        if not issues:
            return None
        i0 = issues[0]
        return {
            "section": "sources",
            "path": f"sources.{i0['code']}",
            "node_id": i0.get("node_id"),
            "archive_id": i0.get("archive_id"),
            "package_id": i0.get("package_id"),
            "position": i0.get("position"),
            "archived": i0.get("frozen"),
            "recomputed": i0.get("current"),
            "message": i0["message"],
        }

    # ======================================================================
    # 失败重试（手动复位）
    # ======================================================================
    def retry(self, index_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, index_id)
            if row is None:
                raise CausalNotFound(
                    f"因果索引 {index_id} 不存在", index_id=index_id)
            if row["status"] != STATUS_FAILED:
                raise CausalBadState(
                    f"因果索引 {index_id} 当前状态为 {row['status']}，"
                    "只有 failed 的索引需要重试",
                    index_id=index_id, status=row["status"])
            conn.execute(
                "UPDATE causal_indexes SET status=?, attempts=0, error=NULL, "
                "updated_at_ms=? WHERE index_id=?",
                (STATUS_PENDING, store.clock.wall_ms(), index_id))
            conn.commit()
            return self._view(self._get_row(conn, index_id))


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def payload_sha(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json(payload).encode("utf-8")).hexdigest()


def _issue(code, severity, node, message) -> dict[str, Any]:
    return {
        "code": code, "severity": severity,
        "node_id": node.get("node_id"), "seq": node.get("seq"),
        "node_type": node.get("node_type"), "message": message,
    }


def _summarize_anomalies(issues: list[dict]) -> dict[str, Any]:
    by_code: dict[str, int] = {}
    sev = {"error": 0, "warning": 0, "info": 0}
    for i in issues:
        by_code[i["code"]] = by_code.get(i["code"], 0) + 1
        sev[i["severity"]] = sev.get(i["severity"], 0) + 1
    return {
        "total": len(issues),
        "errors": sev["error"],
        "warnings": sev["warning"],
        "infos": sev["info"],
        "issues_by_code": dict(sorted(by_code.items())),
        "consistent": sev["error"] == 0,
    }


def _range_error(after_pos, total) -> Exception:
    from .audit import NodeOutOfRange
    return NodeOutOfRange(
        f"翻页游标 after={after_pos} 已越过因果链末位（共 {total} 个节点，"
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


def _parse_write_id(detail: str | None) -> int | None:
    if detail and detail.startswith("write_id="):
        try:
            return int(detail.split("=", 1)[1])
        except ValueError:
            return None
    return None
