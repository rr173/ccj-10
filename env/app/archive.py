"""可验证审计归档（verifiable audit archive）。

在审计回放能力之上，把某个**资源**或某张**委托凭证**在某个稳定历史节点
上的"当时状态"冻结成一份只读归档：

- **固定事件范围**：创建时解析出的节点 seq 即事件上界，归档只含
  ``seq <= node_seq`` 的作用域事件；生成期间再有新租约写入也进不来
  （历史只增，上界已钉死），绝不会读到半套事件；
- **固定回放状态与诊断结果**：由冻结事件纯重放得到的投影与诊断，
  与创建时刻之后发生的任何操作无关；
- **内容校验值**：对规范化内容（排序键 JSON）计算 SHA-256，
  下载者可独立复算；
- **幂等创建**：``(scope, resource, credential_id, idempotency_key)``
  唯一。同对象、同节点、同键重复创建返回同一份归档（200 + replayed）；
  同键配不同节点直接 409，绝不会生成两份互相矛盾的归档；
- **可续跑的后台生成**：事件分块冻结，每块提交后进度落库
  （``processed_events`` / ``last_frozen_seq``）。进程重启或后台失败后，
  从已保存的进度继续；``archive_events`` 主键 ``(archive_id, seq)``
  + ``INSERT OR IGNORE`` 保证失败重试不会重复写入；
- **独立核验**：完成后可把归档标记为 ``verified`` / ``verify_failed``。
  核验重新比对"冻结副本 ↔ 原始审计历史 ↔ 归档内容 ↔ 校验值"，
  失败时给出**首个差异位置**（section / path / seq / 双方取值）；
- **只读边界**：归档的创建、生成、下载、核验只写
  ``archives`` / ``archive_events`` 两张自有表，绝不修改正在运行的
  租约、委托和原始审计历史（lease_events/writes/leases/delegations/...）。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from .audit import (
    AuditBadRequest,
    AuditError,
    AuditReader,
    event_dict,
    project,
)

# ---------------------------------------------------------------------------
# 错误（与审计错误一样映射为明确的 HTTP 状态码）
# ---------------------------------------------------------------------------


class ArchiveError(AuditError):
    code = "archive_error"
    status = 400


class ArchiveNotFound(ArchiveError):
    code = "archive_not_found"
    status = 404


class ArchiveNotReady(ArchiveError):
    """归档尚未生成完成，不能下载/核验（409）。"""

    code = "archive_not_ready"
    status = 409


class ArchiveConflict(ArchiveError):
    """幂等键被参数不同的归档创建请求占用（409）。"""

    code = "archive_id_conflict"
    status = 409


class ArchiveBadState(ArchiveError):
    """当前状态不允许该操作（如对未失败的归档发起重试，409）。"""

    code = "archive_bad_state"
    status = 409


# ---------------------------------------------------------------------------
# 规范化与校验值
# ---------------------------------------------------------------------------


def canonical_json(obj: Any) -> str:
    """规范化 JSON：键排序、紧凑分隔符。同一对象永远得到同一字符串。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def content_sha256(core: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(core).encode("utf-8")).hexdigest()


_MISSING = "<missing>"


def first_diff(archived: Any, recomputed: Any, path: str) -> dict | None:
    """深度比对两个 JSON 对象，返回首个差异位置（确定性顺序）。

    字典按键排序遍历、列表按下标遍历，因此"首个差异"对同一份输入
    永远相同。返回 None 表示两者完全一致。
    """
    if isinstance(archived, dict) and isinstance(recomputed, dict):
        for key in sorted(set(archived) | set(recomputed)):
            if key not in archived:
                return {"path": f"{path}.{key}", "archived": _MISSING,
                        "recomputed": recomputed[key]}
            if key not in recomputed:
                return {"path": f"{path}.{key}", "archived": archived[key],
                        "recomputed": _MISSING}
            diff = first_diff(archived[key], recomputed[key],
                              f"{path}.{key}")
            if diff is not None:
                return diff
        return None
    if isinstance(archived, list) and isinstance(recomputed, list):
        for i in range(min(len(archived), len(recomputed))):
            diff = first_diff(archived[i], recomputed[i], f"{path}[{i}]")
            if diff is not None:
                return diff
        if len(archived) != len(recomputed):
            i = min(len(archived), len(recomputed))
            return {
                "path": f"{path}[{i}]",
                "archived": archived[i] if i < len(archived) else _MISSING,
                "recomputed": (recomputed[i] if i < len(recomputed)
                               else _MISSING),
            }
        return None
    if archived != recomputed or type(archived) is not type(recomputed):
        return {"path": path, "archived": archived, "recomputed": recomputed}
    return None


# ---------------------------------------------------------------------------
# 归档管理器
# ---------------------------------------------------------------------------

SCOPE_RESOURCE = "resource"
SCOPE_CREDENTIAL = "credential"

STATUS_PENDING = "pending"
STATUS_BUILDING = "building"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

VERIFY_UNVERIFIED = "unverified"
VERIFY_VERIFIED = "verified"
VERIFY_FAILED = "verify_failed"

MAX_ATTEMPTS = 5  # 后台自动重试上限；失败后可用 retry 复位


class ArchiveManager:
    """归档的创建、生成、查询、下载与核验。

    与 AuditReader 一样刻意与 Store 共用同一把进程锁与连接：
    创建/续跑在锁内钉死快照上界并分块落库，并发写入要么整体在
    节点之前、要么在之后，归档永远不会读到半套事件。
    """

    def __init__(self, store: Any, audit: AuditReader, *,
                 chunk_size: int = 100):
        self._store = store
        self._audit = audit
        self.chunk_size = max(1, int(chunk_size))

    # ---- 创建（幂等） ---------------------------------------------------
    def create_archive(
        self,
        *,
        scope: Any,
        resource: Any,
        credential_id: Any,
        at_seq: Any,
        at_wall_ms: Any,
        head: bool,
        idempotency_key: Any,
    ) -> tuple[dict[str, Any], bool]:
        """创建归档，返回 (归档视图, 是否新建)。

        同对象+同节点+同幂等键 → 返回既有归档（created=False）；
        同对象+同键+不同节点 → 409，绝不生成第二份矛盾归档。
        """
        if scope not in (SCOPE_RESOURCE, SCOPE_CREDENTIAL):
            raise AuditBadRequest(
                "scope 只能取 resource / credential", scope=scope)
        if scope == SCOPE_RESOURCE and not resource:
            raise AuditBadRequest("scope=resource 时必须给出 resource")
        if scope == SCOPE_CREDENTIAL and not credential_id:
            raise AuditBadRequest(
                "scope=credential 时必须给出 credential_id")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：同一对象+同一节点+同一幂等键"
                "重复创建只会得到同一份归档")
        key = idempotency_key.strip()
        seq = _as_int(at_seq, "at_seq")
        wall = _as_int(at_wall_ms, "at_wall_ms")
        _exactly_one_node(seq, wall, head)

        store = self._store
        with store._lock:  # noqa: SLF001 - 与存储/审计刻意共用同一把锁
            conn = store._conn  # noqa: SLF001
            row = conn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = (int(row["m"])
                       if row is not None and row["m"] is not None else 0)

            if scope == SCOPE_RESOURCE:
                res = str(resource)
                cid = ""
                node = self._audit._resolve_node(  # noqa: SLF001
                    conn, max_seq, res, seq=seq, wall_ms=wall, head=head)
            else:
                cid = str(credential_id)
                node, res, _chain = self._audit._resolve_credential_node(  # noqa: SLF001
                    conn, max_seq, cid, seq=seq, wall_ms=wall, head=head)
            node_seq = node["seq"]

            prev = self._find_by_key(conn, scope, res, cid, key)
            if prev is not None:
                if prev["node_seq"] == node_seq:
                    # 同一对象、同一节点、同一幂等键：就是同一份归档
                    return self._view(prev), False
                raise ArchiveConflict(
                    f"幂等键 {key} 已用于该对象在节点 seq="
                    f"{prev['node_seq']} 的归档，本次请求节点 seq={node_seq} "
                    "不一致，被拒绝（不会生成两份互相矛盾的归档）",
                    archive_id=prev["archive_id"],
                    existing_node_seq=prev["node_seq"],
                    requested_node_seq=node_seq,
                )

            total = self._count_scope_events(conn, scope, res, cid, node_seq)
            archive_id = uuid.uuid4().hex
            now = store.clock.wall_ms()
            try:
                conn.execute(
                    "INSERT INTO archives(archive_id, scope, resource, "
                    "credential_id, node_seq, snapshot_seq, idempotency_key, "
                    "status, total_events, created_at_ms, updated_at_ms) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (archive_id, scope, res, cid, node_seq, max_seq, key,
                     STATUS_PENDING, total, now, now),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                # 唯一索引兜底（并发下锁内不会走到，防御性保留）：
                # 键已存在即返回既有归档，绝不产生第二份
                conn.rollback()
                prev = self._find_by_key(conn, scope, res, cid, key)
                if prev is not None and prev["node_seq"] == node_seq:
                    return self._view(prev), False
                raise
            row = self._get_row(conn, archive_id)
            return self._view(row), True

    @staticmethod
    def _find_by_key(conn, scope, resource, credential_id, key):
        return conn.execute(
            "SELECT * FROM archives WHERE scope=? AND resource=? "
            "AND credential_id=? AND idempotency_key=?",
            (scope, resource, credential_id, key),
        ).fetchone()

    @staticmethod
    def _count_scope_events(conn, scope, resource, credential_id,
                            node_seq) -> int:
        if scope == SCOPE_RESOURCE:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM lease_events "
                "WHERE resource=? AND seq<=?", (resource, node_seq),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM lease_events "
                "WHERE credential_id=? AND seq<=?", (credential_id, node_seq),
            ).fetchone()
        return int(row["c"])

    # ---- 查询 -----------------------------------------------------------
    @staticmethod
    def _get_row(conn, archive_id):
        return conn.execute(
            "SELECT * FROM archives WHERE archive_id=?", (archive_id,),
        ).fetchone()

    def get_archive(self, archive_id: str) -> dict[str, Any]:
        with self._store._lock:  # noqa: SLF001
            conn = self._store._conn  # noqa: SLF001
            row = self._get_row(conn, archive_id)
            if row is None:
                raise ArchiveNotFound(
                    f"归档 {archive_id} 不存在", archive_id=archive_id)
            try:
                return self._view(row)
            finally:
                conn.rollback()

    def list_archives(self, *, scope=None, resource=None, credential_id=None,
                      status=None, limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        where, args = [], []
        if scope:
            where.append("scope=?")
            args.append(scope)
        if resource:
            where.append("resource=?")
            args.append(resource)
        if credential_id:
            where.append("credential_id=?")
            args.append(credential_id)
        if status:
            if status not in (STATUS_PENDING, STATUS_BUILDING,
                              STATUS_COMPLETED, STATUS_FAILED):
                raise AuditBadRequest(
                    "status 只能取 pending/building/completed/failed",
                    status=status)
            where.append("status=?")
            args.append(status)
        sql = "SELECT * FROM archives"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at_ms ASC, archive_id ASC LIMIT ?"
        with self._store._lock:  # noqa: SLF001
            conn = self._store._conn  # noqa: SLF001
            rows = conn.execute(sql, (*args, limit)).fetchall()
            try:
                return {"archives": [self._view(r) for r in rows],
                        "limit": limit}
            finally:
                conn.rollback()

    def _view(self, row) -> dict[str, Any]:
        total = row["total_events"]
        done = row["processed_events"]
        return {
            "archive_id": row["archive_id"],
            "scope": row["scope"],
            "resource": row["resource"],
            "credential_id": row["credential_id"] or None,
            "node_seq": row["node_seq"],
            "snapshot_seq": row["snapshot_seq"],
            "idempotency_key": row["idempotency_key"],
            "status": row["status"],
            "progress": {
                "processed_events": done,
                "total_events": total,
                "remaining_events": max(total - done, 0),
                "percent": round(100.0 * done / total, 1) if total else 100.0,
                "done": done >= total,
            },
            "attempts": row["attempts"],
            "error": row["error"],
            "content_sha256": row["content_sha256"],
            "verify_status": row["verify_status"],
            "verify_detail": (json.loads(row["verify_detail"])
                              if row["verify_detail"] else None),
            "verified_at_ms": row["verified_at_ms"],
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
            "completed_at_ms": row["completed_at_ms"],
            "download_url": f"/audit/archives/{row['archive_id']}/download",
        }

    # ---- 下载 -----------------------------------------------------------
    def download(self, archive_id: str) -> tuple[str, dict[str, Any]]:
        """返回 (归档文档原文, 归档视图)。文档就是落库时的字节，重启不变。"""
        with self._store._lock:  # noqa: SLF001
            conn = self._store._conn  # noqa: SLF001
            row = self._get_row(conn, archive_id)
            if row is None:
                raise ArchiveNotFound(
                    f"归档 {archive_id} 不存在", archive_id=archive_id)
            if row["status"] != STATUS_COMPLETED:
                raise ArchiveNotReady(
                    f"归档 {archive_id} 尚未生成完成（当前状态 "
                    f"{row['status']}，进度 {row['processed_events']}/"
                    f"{row['total_events']}），暂不能下载",
                    archive_id=archive_id, status=row["status"],
                )
            try:
                return row["content"], self._view(row)
            finally:
                conn.rollback()

    # ---- 后台生成：分块冻结 + 进度落库，可续跑 ---------------------------
    def process_pending(self, *, max_archives: int | None = None,
                        max_chunks_per_archive: int | None = None) -> int:
        """推进待生成的归档，返回本轮处理过的归档数。

        每个归档按 chunk_size 分块把事件冻结进 archive_events 并逐块
        提交；进程崩溃/重启后从 last_frozen_seq 继续。failed 的归档在
        重试上限内自动重试（INSERT OR IGNORE 保证不重复写入）。
        """
        with self._store._lock:  # noqa: SLF001
            conn = self._store._conn  # noqa: SLF001
            rows = conn.execute(
                "SELECT archive_id FROM archives WHERE status IN (?,?) "
                "OR (status=? AND attempts<?) "
                "ORDER BY created_at_ms ASC, archive_id ASC",
                (STATUS_PENDING, STATUS_BUILDING, STATUS_FAILED,
                 MAX_ATTEMPTS),
            ).fetchall()
            conn.rollback()
        ids = [r["archive_id"] for r in rows]
        if max_archives is not None:
            ids = ids[:max_archives]
        n = 0
        for archive_id in ids:
            if self._process_one(archive_id,
                                 max_chunks=max_chunks_per_archive):
                n += 1
        return n

    def _process_one(self, archive_id: str, *,
                     max_chunks: int | None) -> bool:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, archive_id)
            if row is None or row["status"] == STATUS_COMPLETED:
                return False
            try:
                if row["status"] in (STATUS_PENDING, STATUS_FAILED):
                    # pending → 首次尝试；failed → 自动重试（进度保留）
                    conn.execute(
                        "UPDATE archives SET status=?, attempts=attempts+1, "
                        "error=NULL, updated_at_ms=? WHERE archive_id=?",
                        (STATUS_BUILDING, store.clock.wall_ms(), archive_id),
                    )
                    conn.commit()
                chunks = 0
                while True:
                    row = self._get_row(conn, archive_id)
                    if row["processed_events"] >= row["total_events"]:
                        break
                    if max_chunks is not None and chunks >= max_chunks:
                        return True  # 本轮先到这，下轮从已存进度继续
                    self._freeze_chunk_locked(row)
                    chunks += 1
                self._finalize_locked(archive_id)
                return True
            except Exception as exc:  # noqa: BLE001 - 失败落库后可续跑
                conn.rollback()  # 回滚未提交的分块，进度停在上一个已提交块
                conn.execute(
                    "UPDATE archives SET status=?, error=?, updated_at_ms=? "
                    "WHERE archive_id=?",
                    (STATUS_FAILED, f"{type(exc).__name__}: {exc}",
                     store.clock.wall_ms(), archive_id),
                )
                conn.commit()
                return True

    def _freeze_chunk_locked(self, row) -> int:
        """把下一批作用域事件冻结进 archive_events（单事务提交一块）。

        事件上界 node_seq 在创建时钉死，历史只增，因此无论生成期间
        发生多少新写入，冻结到的事件集合都固定不变。
        """
        conn = self._store._conn  # noqa: SLF001
        if row["scope"] == SCOPE_RESOURCE:
            rows = conn.execute(
                "SELECT * FROM lease_events WHERE resource=? AND seq>? "
                "AND seq<=? ORDER BY seq ASC LIMIT ?",
                (row["resource"], row["last_frozen_seq"], row["node_seq"],
                 self.chunk_size),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM lease_events WHERE credential_id=? AND seq>? "
                "AND seq<=? ORDER BY seq ASC LIMIT ?",
                (row["credential_id"], row["last_frozen_seq"],
                 row["node_seq"], self.chunk_size),
            ).fetchall()
        archive_id = row["archive_id"]
        now = self._store.clock.wall_ms()
        if not rows:
            # 防御：事件计数与实际不符时直接收敛到完成态，避免空转
            conn.execute(
                "UPDATE archives SET processed_events=total_events, "
                "updated_at_ms=? WHERE archive_id=?",
                (now, archive_id),
            )
            conn.commit()
            return 0
        for r in rows:
            # INSERT OR IGNORE：失败重试/重复执行同一块都不会重复写入
            conn.execute(
                "INSERT OR IGNORE INTO archive_events(archive_id, seq, "
                "payload) VALUES(?,?,?)",
                (archive_id, r["seq"], canonical_json(event_dict(r))),
            )
        conn.execute(
            "UPDATE archives SET processed_events=processed_events+?, "
            "last_frozen_seq=?, updated_at_ms=? WHERE archive_id=?",
            (len(rows), rows[-1]["seq"], now, archive_id),
        )
        conn.commit()
        return len(rows)

    def _finalize_locked(self, archive_id: str) -> None:
        """全部事件冻结完毕后生成归档文档与校验值（单事务落库）。

        内容完全由冻结输入决定（不含可变时间戳），失败重试生成的
        内容逐字节一致；对 archives 行是单次 UPDATE，不会重复写入。
        """
        conn = self._store._conn  # noqa: SLF001
        row = self._get_row(conn, archive_id)
        events = self._frozen_events(conn, archive_id)
        content = self._build_content_locked(row, events)
        text = json.dumps(content, ensure_ascii=False, sort_keys=True)
        now = self._store.clock.wall_ms()
        conn.execute(
            "UPDATE archives SET status=?, content=?, content_sha256=?, "
            "processed_events=total_events, completed_at_ms=?, "
            "updated_at_ms=? WHERE archive_id=?",
            (STATUS_COMPLETED, text, content["content_sha256"], now, now,
             archive_id),
        )
        conn.commit()

    @staticmethod
    def _frozen_events(conn, archive_id) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT payload FROM archive_events WHERE archive_id=? "
            "ORDER BY seq ASC", (archive_id,),
        ).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def _build_content_locked(self, row, events) -> dict[str, Any]:
        """由冻结事件构建归档文档：事件范围 + 回放状态 + 诊断 + 校验值。"""
        conn = self._store._conn  # noqa: SLF001
        scope = row["scope"]
        resource = row["resource"]
        cid = row["credential_id"] or None
        node_seq = row["node_seq"]

        if scope == SCOPE_RESOURCE:
            st = project(resource, events, check_clocks=True)
            replay_state = st.replay_view()
            issues = list(st.issues)
        else:
            # 凭证归档：回放状态需要当时整个资源的上下文。原始历史只增，
            # 按 node_seq 截断重放的结果与创建时一致；核验时重放同一截断
            # 区间，若原始历史被删改，这里会产生差异并被核验发现。
            resource_events = [
                event_dict(r) for r in conn.execute(
                    "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
                    "ORDER BY seq ASC", (resource, node_seq),
                ).fetchall()
            ]
            st = project(resource, resource_events, check_clocks=True)
            replay_state = st.replay_view()
            d = st.delegations.get(cid)
            replay_state["credential"] = None if d is None else d.view()
            issues = [i for i in st.issues if i.get("credential_id") == cid]
            issues += self._audit._credential_chain_checks(events)  # noqa: SLF001

        issues.sort(key=lambda i: (i["seq"] is None, i["seq"] or 0,
                                   i["code"]))
        core = {
            "kind": "lease_audit_archive",
            "version": 1,
            "archive_id": row["archive_id"],
            "scope": scope,
            "resource": resource,
            "credential_id": cid,
            "node_seq": node_seq,
            "snapshot_seq": row["snapshot_seq"],
            "node": events[-1] if events else None,
            "event_range": {
                "first_seq": events[0]["seq"] if events else None,
                "last_seq": events[-1]["seq"] if events else None,
                "count": len(events),
            },
            "events": events,
            "replay_state": replay_state,
            "diagnosis": {
                "basis": "pure_replay_over_archived_events",
                "issues": issues,
                "summary": AuditReader._summarize(issues, events),  # noqa: SLF001
            },
            "created_at_ms": row["created_at_ms"],
        }
        return {**core, "content_sha256": content_sha256(core)}

    # ---- 独立核验：标记 verified / verify_failed（含首个差异位置） -------
    def verify(self, archive_id: str) -> dict[str, Any]:
        """独立核验已完成的归档，并把结果标记在归档上。

        三层检查（任一失败即 verify_failed，并给出首个差异位置）：
        1. 归档文档与保存的内容校验值一致（内容未被改动）；
        2. 归档事件与原始审计历史逐条逐字段一致（历史未被删改）；
        3. 回放状态与诊断可由归档事件独立重算得到（派生内容自洽）。
        只写 archives 自有表，绝不触碰租约/委托/原始历史。
        """
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, archive_id)
            if row is None:
                raise ArchiveNotFound(
                    f"归档 {archive_id} 不存在", archive_id=archive_id)
            if row["status"] != STATUS_COMPLETED:
                raise ArchiveNotReady(
                    f"归档 {archive_id} 尚未生成完成（当前状态 "
                    f"{row['status']}），不能核验",
                    archive_id=archive_id, status=row["status"],
                )
            content = json.loads(row["content"])

            divergence = self._check_checksum(row, content)
            if divergence is None:
                divergence = self._check_events_against_history(conn, row,
                                                                content)
            if divergence is None:
                divergence = self._check_derivation(row, content)

            now = store.clock.wall_ms()
            if divergence is None:
                conn.execute(
                    "UPDATE archives SET verify_status=?, verify_detail=NULL,"
                    " verified_at_ms=?, updated_at_ms=? WHERE archive_id=?",
                    (VERIFY_VERIFIED, now, now, archive_id),
                )
                result = {
                    "archive_id": archive_id,
                    "verify_status": VERIFY_VERIFIED,
                    "first_divergence": None,
                    "message": "独立核验通过：内容校验值、归档事件与原始审计"
                               "历史、回放状态与诊断全部一致",
                }
            else:
                detail = json.dumps(divergence, ensure_ascii=False)
                conn.execute(
                    "UPDATE archives SET verify_status=?, verify_detail=?, "
                    "verified_at_ms=?, updated_at_ms=? WHERE archive_id=?",
                    (VERIFY_FAILED, detail, now, now, archive_id),
                )
                result = {
                    "archive_id": archive_id,
                    "verify_status": VERIFY_FAILED,
                    "first_divergence": divergence,
                    "message": "核验失败：首个差异位于 "
                               f"{divergence.get('path')}（"
                               f"{divergence.get('message', '内容不一致')}）",
                }
            conn.commit()
            result["verified_at_ms"] = now
            result["content_sha256"] = row["content_sha256"]
            return result

    @staticmethod
    def _check_checksum(row, content) -> dict | None:
        core = {k: v for k, v in content.items() if k != "content_sha256"}
        actual = content_sha256(core)
        if actual != content.get("content_sha256") or \
                actual != row["content_sha256"]:
            return {
                "section": "checksum",
                "path": "content_sha256",
                "expected": row["content_sha256"],
                "actual": actual,
                "message": "归档内容与保存的内容校验值不符，内容可能被篡改",
            }
        return None

    def _check_events_against_history(self, conn, row,
                                      content) -> dict | None:
        frozen = self._frozen_events(conn, row["archive_id"])
        # 1) 归档文档内的事件与冻结副本一致（存储层自身完好）
        diff = first_diff(content.get("events"), frozen, "events")
        if diff is not None:
            return {**diff, "section": "events",
                    "message": "归档文档中的事件与冻结事件副本不一致"}
        # 2) 冻结副本与原始审计历史（同范围）逐条一致
        if row["scope"] == SCOPE_RESOURCE:
            rows = conn.execute(
                "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
                "ORDER BY seq ASC", (row["resource"], row["node_seq"]),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM lease_events WHERE credential_id=? AND seq<=? "
                "ORDER BY seq ASC", (row["credential_id"], row["node_seq"]),
            ).fetchall()
        current = [event_dict(r) for r in rows]
        # 先比序号序列：事件被删/被插入时，首个序号分叉位置即首个差异位置
        frozen_seqs = [e["seq"] for e in frozen]
        current_seqs = [e["seq"] for e in current]
        if frozen_seqs != current_seqs:
            i = next(
                (k for k in range(min(len(frozen_seqs), len(current_seqs)))
                 if frozen_seqs[k] != current_seqs[k]),
                min(len(frozen_seqs), len(current_seqs)),
            )
            archived_seq = frozen_seqs[i] if i < len(frozen_seqs) else _MISSING
            current_seq = (current_seqs[i] if i < len(current_seqs)
                           else _MISSING)
            return {
                "section": "events",
                "path": f"events[{i}]",
                "seq": archived_seq if archived_seq != _MISSING else None,
                "archived": archived_seq,
                "recomputed": current_seq,
                "message": f"归档第 {i} 条事件的序号与原始审计历史不一致"
                           f"（归档 seq={archived_seq}，当前历史 "
                           f"seq={current_seq}）：历史可能被删改",
            }
        # 序号序列一致 → 逐条逐字段比对内容
        for i, (archived_ev, current_ev) in enumerate(zip(frozen, current)):
            diff = first_diff(archived_ev, current_ev, f"events[{i}]")
            if diff is not None:
                return {
                    **diff, "section": "events", "seq": archived_ev["seq"],
                    "message": f"归档事件与原始审计历史在第 "
                               f"{archived_ev['seq']} 号事件处首次出现差异",
                }
        return None

    def _check_derivation(self, row, content) -> dict | None:
        # 调用方（verify）已持有 store 锁
        conn = self._store._conn  # noqa: SLF001
        frozen = self._frozen_events(conn, row["archive_id"])
        recomputed = self._build_content_locked(row, frozen)
        for section in ("replay_state", "diagnosis"):
            diff = first_diff(content.get(section), recomputed.get(section),
                              section)
            if diff is not None:
                return {
                    **diff, "section": section,
                    "message": f"归档的{section}无法由冻结事件独立重算得到",
                }
        return None

    # ---- 失败重试（手动复位） -------------------------------------------
    def retry(self, archive_id: str) -> dict[str, Any]:
        """把失败的归档复位为 pending，由后台从已保存的进度继续。"""
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, archive_id)
            if row is None:
                raise ArchiveNotFound(
                    f"归档 {archive_id} 不存在", archive_id=archive_id)
            if row["status"] != STATUS_FAILED:
                raise ArchiveBadState(
                    f"归档 {archive_id} 当前状态为 {row['status']}，"
                    "只有 failed 的归档需要重试",
                    archive_id=archive_id, status=row["status"],
                )
            conn.execute(
                "UPDATE archives SET status=?, attempts=0, error=NULL, "
                "updated_at_ms=? WHERE archive_id=?",
                (STATUS_PENDING, store.clock.wall_ms(), archive_id),
            )
            conn.commit()
            return self._view(self._get_row(conn, archive_id))


# ---------------------------------------------------------------------------
# 参数小工具（与 audit 模块同语义，避免循环依赖重新实现）
# ---------------------------------------------------------------------------


def _as_int(value, name: str):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise AuditBadRequest(f"参数 {name} 必须是整数", **{name: value})


def _bounded_limit(value) -> int:
    limit = _as_int(value, "limit")
    if limit is None:
        return 100
    if limit < 1:
        raise AuditBadRequest("limit 必须 >= 1", limit=limit)
    return min(limit, 1000)


def _exactly_one_node(seq, wall, head) -> None:
    if sum([seq is not None, wall is not None, bool(head)]) != 1:
        raise AuditBadRequest(
            "必须且只能用一种方式指定历史节点：at_seq / at_wall_ms / head")
