"""审计通知多端投递（audit notification fan-out delivery）。

一条审计通知可以同时投递给多个**独立接收端**；通知创建时把送达策略
**冻结**成快照（接收端集合、所需成功数、策略版本），之后策略再怎么改
都只影响新通知。整条通知何时算完成，完全由这份冻结快照判定。

送达策略（三种完成模式）
========================
- ``all``：冻结集合里的接收端**全部**成功才算完成；
- ``any``：任一接收端成功即完成；
- ``quorum``：成功接收端数达到冻结的 ``required_successes``（等于策略
  的 ``quorum_count``）即完成。

策略是**版本化**的：每次创建策略产生一个单调递增的版本号，通知创建时
把当前（或指定）版本的模式、所需成功数与接收端集合一起冻结进通知行；
之后再创建新版本策略，已在途的通知仍按自己的冻结快照判定。

不可能满足即明确失败
====================
每次状态变化后在锁内重估：``仍可能成功的接收端数 = 总数 - 已终止数``，
若已小于冻结的所需成功数，策略**永远不可能满足**，整条通知立即置为
``failed`` 并冻结判定快照 ``decision``（原因 + 参与判定的每个接收端
当时的状态/尝试次数/最后结果）。判定一旦落库即终态：迟到回执与迟到
失败上报一律 409 ``fanout_notification_decided``，绝不能把已失败（或
已完成）的通知翻案。

接收端生命周期
==============
``pending → succeeded``（成功回执）或 ``pending → terminal_failed``
（失败重试达到该接收端自己的 ``max_attempts``）。每个接收端有自己的
最大尝试次数；失败可以重试，达到上限进入终止态。管理员可暂停/恢复
某个接收端：暂停只是拒收新的回执与失败上报（409
``fanout_recipient_paused``），不改状态、不减计数——暂停已成功的
接收端改变不了既有完成结论（成功计数读的是 ``state``，不是
``paused``；已落库的终态判定更是永远不变）。

回执幂等
========
成功回执按 ``(notification_id, recipient_id, idempotency_key)`` 幂等：

- 相同回执重复到达 → 只返回首次处理结果（200 回放，不重复计尝试）；
- 同一幂等键配不同内容 → 409 ``fanout_receipt_conflict``（给出首个
  差异位置与双方值）；
- 接收端已成功后又来新键回执 → 不重复计尝试，返回等效成功结果
  （``already_succeeded``）。

持久化与重启
============
策略、通知快照、接收端、逐次尝试记录（含顺序）、回执幂等记录与最终
判定全部落 SQLite（与租约/订阅同一 WAL 库，共用 Store 的进程锁与
连接，不在内存里缓存任何判定状态）。进程重启后：策略快照、尝试顺序、
幂等回放与最终判定原样保留。

只写 ``audit_fanout_*`` 自有表，绝不修改租约、委托、审计历史、归档、
证据包、因果索引、发布计划或订阅投递。
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .archive import canonical_json, first_diff
from .audit import AuditBadRequest, AuditError

# ---------------------------------------------------------------------------
# 错误（与审计错误一样映射为明确的 HTTP 状态码）
# ---------------------------------------------------------------------------


class FanoutError(AuditError):
    code = "fanout_error"
    status = 400


class FanoutPolicyNotFound(FanoutError):
    """指定版本的策略不存在，或当前还没有任何策略（404）。"""

    code = "fanout_policy_not_found"
    status = 404


class FanoutNoCurrentPolicy(FanoutError):
    """创建通知时还没有任何可用策略（409）。"""

    code = "fanout_no_current_policy"
    status = 409


class FanoutNotificationNotFound(FanoutError):
    code = "fanout_notification_not_found"
    status = 404


class FanoutRecipientNotFound(FanoutError):
    """接收端不在该通知的冻结集合里（404）。"""

    code = "fanout_recipient_not_found"
    status = 404


class FanoutReceiptConflict(FanoutError):
    """同一幂等键被内容不同的回执占用（409）。"""

    code = "fanout_receipt_conflict"
    status = 409


class FanoutNotificationDecided(FanoutError):
    """通知已有最终判定：迟到回执/迟到失败上报一律拒绝（409）。"""

    code = "fanout_notification_decided"
    status = 409


class FanoutRecipientPaused(FanoutError):
    """接收端被管理员暂停：回执与失败上报暂不受理（409）。"""

    code = "fanout_recipient_paused"
    status = 409


class FanoutRecipientTerminal(FanoutError):
    """接收端已达尝试上限进入终止态（409）。"""

    code = "fanout_recipient_terminal"
    status = 409


class FanoutRecipientSucceeded(FanoutError):
    """接收端已成功：不能再对它上报失败（409）。"""

    code = "fanout_recipient_succeeded"
    status = 409


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

MODE_ALL = "all"        # 全部接收端成功才算完成
MODE_ANY = "any"        # 任一接收端成功即完成
MODE_QUORUM = "quorum"  # 成功数达到 quorum_count 即完成
MODES = (MODE_ALL, MODE_ANY, MODE_QUORUM)

STATUS_PENDING = "pending"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
NOTIFICATION_STATUSES = (STATUS_PENDING, STATUS_COMPLETED, STATUS_FAILED)

R_PENDING = "pending"
R_SUCCEEDED = "succeeded"
R_TERMINAL = "terminal_failed"

RESULT_SUCCESS = "success"
RESULT_FAILURE = "failure"

DEFAULT_MAX_ATTEMPTS = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_fanout_policies (
    policy_id     TEXT PRIMARY KEY,
    version       INTEGER NOT NULL UNIQUE,  -- 单调递增的策略版本号
    mode          TEXT NOT NULL,            -- all / any / quorum
    quorum_count  INTEGER,                  -- 仅 quorum：所需成功数
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_fanout_notifications (
    notification_id    TEXT PRIMARY KEY,
    payload_json       TEXT NOT NULL,        -- 通知内容（规范化 JSON）
    status             TEXT NOT NULL DEFAULT 'pending',
    policy_version     INTEGER NOT NULL,     -- 冻结：策略版本
    mode               TEXT NOT NULL,        -- 冻结：完成模式
    quorum_count       INTEGER,              -- 冻结：quorum 原始值
    required_successes INTEGER NOT NULL,     -- 冻结：所需成功数
    decision_json      TEXT,                 -- 终态判定快照（含接收端状态）
    created_at_ms      INTEGER NOT NULL,
    decided_at_ms      INTEGER
);
CREATE TABLE IF NOT EXISTS audit_fanout_recipients (
    notification_id TEXT NOT NULL,
    recipient_id    TEXT NOT NULL,
    position        INTEGER NOT NULL,        -- 冻结集合中的顺序
    max_attempts    INTEGER NOT NULL,        -- 该接收端自己的尝试上限
    state           TEXT NOT NULL DEFAULT 'pending',
    paused          INTEGER NOT NULL DEFAULT 0,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_result     TEXT,                    -- success / failure / NULL
    last_detail     TEXT,
    updated_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (notification_id, recipient_id)
);
CREATE TABLE IF NOT EXISTS audit_fanout_attempts (
    attempt_id      INTEGER PRIMARY KEY AUTOINCREMENT,  -- 全局尝试顺序
    notification_id TEXT NOT NULL,
    recipient_id    TEXT NOT NULL,
    seq             INTEGER NOT NULL,        -- 该接收端的第几次尝试（1 起）
    result          TEXT NOT NULL,           -- success / failure
    detail          TEXT,
    idempotency_key TEXT,                    -- 成功回执的幂等键
    created_at_ms   INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fanout_attempt_seq
    ON audit_fanout_attempts(notification_id, recipient_id, seq);
CREATE INDEX IF NOT EXISTS idx_fanout_attempt_notification
    ON audit_fanout_attempts(notification_id, attempt_id);
CREATE TABLE IF NOT EXISTS audit_fanout_receipts (
    notification_id TEXT NOT NULL,
    recipient_id    TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    content_json    TEXT NOT NULL,   -- 规范化回执内容（冲突比对用）
    request_hash    TEXT NOT NULL,
    response_json   TEXT NOT NULL,   -- 首次处理结果（回放原文）
    created_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (notification_id, recipient_id, idempotency_key)
);
"""


class FanoutManager:
    """多端投递的策略管理、通知生命周期、回执幂等与完成判定。

    与其他管理器共用 Store 的进程锁与连接：回执受理、失败上报与完成
    判定在同一事务里落库，并发请求要么整体在判定之前、要么在之后。
    除 ``audit_fanout_*`` 外不写任何表。
    """

    def __init__(self, store: Any):
        self._store = store
        with store._lock:  # noqa: SLF001 - 与其他管理器共用同一把锁
            # 幂等兜底：IF NOT EXISTS 不影响既有表，重启/多实例安全
            store._conn.executescript(SCHEMA)  # noqa: SLF001
            store._conn.commit()  # noqa: SLF001

    # ======================================================================
    # 内部工具
    # ======================================================================
    def _now(self) -> int:
        return self._store.clock.wall_ms()

    @staticmethod
    def _require_str(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise AuditBadRequest(f"{name} 必填：非空字符串")
        return value.strip()

    @staticmethod
    def _require_int(value: Any, name: str, *, minimum: int) -> int:
        if isinstance(value, bool):
            raise AuditBadRequest(f"{name} 必须是整数")
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise AuditBadRequest(f"{name} 必须是整数", **{name: value})
        if number < minimum:
            raise AuditBadRequest(
                f"{name} 必须 >= {minimum}", **{name: number})
        return number

    def _get_notification_row(self, conn: Any, nid: str):
        row = conn.execute(
            "SELECT * FROM audit_fanout_notifications"
            " WHERE notification_id=?", (nid,)).fetchone()
        if row is None:
            raise FanoutNotificationNotFound(
                "通知不存在", notification_id=nid)
        return row

    def _get_recipient_row(self, conn: Any, nid: str, rid: str):
        row = conn.execute(
            "SELECT * FROM audit_fanout_recipients"
            " WHERE notification_id=? AND recipient_id=?",
            (nid, rid)).fetchone()
        if row is None:
            raise FanoutRecipientNotFound(
                "接收端不在该通知的冻结集合里",
                notification_id=nid, recipient_id=rid)
        return row

    def _recipient_rows(self, conn: Any, nid: str):
        return conn.execute(
            "SELECT * FROM audit_fanout_recipients WHERE notification_id=?"
            " ORDER BY position", (nid,)).fetchall()

    # ----------------------------------------------------------------------
    # 视图
    # ----------------------------------------------------------------------
    @staticmethod
    def _policy_view(row) -> dict[str, Any]:
        return {
            "policy_id": row["policy_id"],
            "version": row["version"],
            "mode": row["mode"],
            "quorum_count": row["quorum_count"],
            "created_at_ms": row["created_at_ms"],
        }

    @staticmethod
    def _recipient_view(row) -> dict[str, Any]:
        remaining = 0
        if row["state"] == R_PENDING:
            remaining = max(0, row["max_attempts"] - row["attempts"])
        return {
            "recipient_id": row["recipient_id"],
            "state": row["state"],
            "paused": bool(row["paused"]),
            "attempts": row["attempts"],
            "max_attempts": row["max_attempts"],
            "remaining_attempts": remaining,
            "last_result": row["last_result"],
            "last_detail": row["last_detail"],
            "updated_at_ms": row["updated_at_ms"],
        }

    @staticmethod
    def _progress(rows, required: int) -> dict[str, Any]:
        """离完成还差多少 / 策略是否仍可能满足（按当前接收端状态计算）。"""
        succeeded = sum(1 for r in rows if r["state"] == R_SUCCEEDED)
        terminated = sum(1 for r in rows if r["state"] == R_TERMINAL)
        total = len(rows)
        return {
            "recipients_total": total,
            "required_successes": required,
            "succeeded": succeeded,
            "terminal_failed": terminated,
            "pending": total - succeeded - terminated,
            "paused": sum(1 for r in rows if r["paused"]),
            "remaining_successes": max(0, required - succeeded),
            "satisfiable": (total - terminated) >= required,
        }

    @classmethod
    def _policy_snapshot(cls, notif) -> dict[str, Any]:
        """通知创建时冻结的策略快照（判定只认这份，不认策略表的现值）。"""
        return {
            "version": notif["policy_version"],
            "mode": notif["mode"],
            "quorum_count": notif["quorum_count"],
            "required_successes": notif["required_successes"],
        }

    def _notification_view(self, notif, rows) -> dict[str, Any]:
        return {
            "notification_id": notif["notification_id"],
            "payload": json.loads(notif["payload_json"]),
            "status": notif["status"],
            "policy": self._policy_snapshot(notif),
            "progress": self._progress(rows, notif["required_successes"]),
            "recipients": [self._recipient_view(r) for r in rows],
            "decision": (json.loads(notif["decision_json"])
                         if notif["decision_json"] else None),
            "created_at_ms": notif["created_at_ms"],
            "decided_at_ms": notif["decided_at_ms"],
        }

    def _summary_view(self, notif, rows) -> dict[str, Any]:
        return {
            "notification_id": notif["notification_id"],
            "status": notif["status"],
            "policy": self._policy_snapshot(notif),
            "progress": self._progress(rows, notif["required_successes"]),
            "created_at_ms": notif["created_at_ms"],
            "decided_at_ms": notif["decided_at_ms"],
        }

    # ----------------------------------------------------------------------
    # 完成判定：在锁内重估冻结策略是否达成 / 已不可能达成
    # ----------------------------------------------------------------------
    @staticmethod
    def _decision_snapshot(rows, required: int, reason: str) -> dict[str, Any]:
        """终态判定快照：原因 + 参与判定的每个接收端当时的状态。"""
        return {
            "reason": reason,
            "required_successes": required,
            "succeeded": sum(1 for r in rows if r["state"] == R_SUCCEEDED),
            "terminal_failed":
                sum(1 for r in rows if r["state"] == R_TERMINAL),
            "recipients": [
                {
                    "recipient_id": r["recipient_id"],
                    "state": r["state"],
                    "paused": bool(r["paused"]),
                    "attempts": r["attempts"],
                    "max_attempts": r["max_attempts"],
                    "last_result": r["last_result"],
                }
                for r in rows
            ],
        }

    def _evaluate_locked(self, conn: Any, nid: str) -> None:
        """按冻结快照重估通知；达成/不可能达成即冻结终态与判定快照。

        已终态的通知直接返回：判定一旦落库永远不变，迟到事件不能翻案。
        """
        notif = self._get_notification_row(conn, nid)
        if notif["status"] != STATUS_PENDING:
            return
        rows = self._recipient_rows(conn, nid)
        required = notif["required_successes"]
        succeeded = sum(1 for r in rows if r["state"] == R_SUCCEEDED)
        terminated = sum(1 for r in rows if r["state"] == R_TERMINAL)
        now = self._now()
        if succeeded >= required:
            decision = self._decision_snapshot(
                rows, required, "policy_satisfied")
            conn.execute(
                "UPDATE audit_fanout_notifications SET status=?,"
                " decision_json=?, decided_at_ms=?"
                " WHERE notification_id=?",
                (STATUS_COMPLETED, canonical_json(decision), now, nid))
        elif len(rows) - terminated < required:
            # 仍可能成功的接收端数已不足冻结的所需成功数：明确失败
            decision = self._decision_snapshot(
                rows, required, "policy_unsatisfiable")
            conn.execute(
                "UPDATE audit_fanout_notifications SET status=?,"
                " decision_json=?, decided_at_ms=?"
                " WHERE notification_id=?",
                (STATUS_FAILED, canonical_json(decision), now, nid))

    # ======================================================================
    # 策略管理（版本化；修改策略 = 创建新版本，只影响之后创建的通知）
    # ======================================================================
    def create_policy(self, *, mode: Any,
                      quorum_count: Any = None) -> dict[str, Any]:
        if not isinstance(mode, str) or not mode.strip():
            raise AuditBadRequest(
                "mode 必填：all（全部成功）/ any（任一成功）/"
                "quorum（指定人数成功）")
        mode = mode.strip().lower()
        if mode not in MODES:
            raise AuditBadRequest(
                "mode 只能是 all / any / quorum", mode=mode)
        quorum: int | None = None
        if mode == MODE_QUORUM:
            if quorum_count in (None, ""):
                raise AuditBadRequest(
                    "quorum 模式必须给出 quorum_count（所需成功数）")
            quorum = self._require_int(
                quorum_count, "quorum_count", minimum=1)
        elif quorum_count is not None:
            raise AuditBadRequest(
                "quorum_count 仅 quorum 模式使用：all/any 的所需成功数"
                "由冻结的接收端集合决定")
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            try:
                version = conn.execute(
                    "SELECT COALESCE(MAX(version), 0) + 1 AS v"
                    " FROM audit_fanout_policies").fetchone()["v"]
                conn.execute(
                    "INSERT INTO audit_fanout_policies"
                    " (policy_id, version, mode, quorum_count,"
                    "  created_at_ms) VALUES (?,?,?,?,?)",
                    (uuid.uuid4().hex, version, mode, quorum, self._now()))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            row = conn.execute(
                "SELECT * FROM audit_fanout_policies WHERE version=?",
                (version,)).fetchone()
            return self._policy_view(row)

    def list_policies(self, *, limit: Any = 100) -> dict[str, Any]:
        limit = min(int(limit), 1000)
        store = self._store
        with store._lock:  # noqa: SLF001
            rows = store._conn.execute(  # noqa: SLF001
                "SELECT * FROM audit_fanout_policies"
                " ORDER BY version LIMIT ?", (limit,)).fetchall()
        return {"policies": [self._policy_view(r) for r in rows],
                "count": len(rows)}

    def get_policy(self, version: Any) -> dict[str, Any]:
        version = self._require_int(version, "version", minimum=1)
        store = self._store
        with store._lock:  # noqa: SLF001
            row = store._conn.execute(  # noqa: SLF001
                "SELECT * FROM audit_fanout_policies WHERE version=?",
                (version,)).fetchone()
        if row is None:
            raise FanoutPolicyNotFound(
                "策略版本不存在", version=version)
        return self._policy_view(row)

    def current_policy(self) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            row = store._conn.execute(  # noqa: SLF001
                "SELECT * FROM audit_fanout_policies"
                " ORDER BY version DESC LIMIT 1").fetchone()
        if row is None:
            raise FanoutPolicyNotFound(
                "当前还没有任何送达策略：先创建策略再创建通知")
        return self._policy_view(row)

    # ======================================================================
    # 通知创建（冻结策略快照 + 接收端集合）
    # ======================================================================
    def create_notification(
        self,
        *,
        payload: Any,
        recipients: Any,
        policy_version: Any = None,
    ) -> dict[str, Any]:
        if payload is None:
            raise AuditBadRequest("payload 必填：审计通知内容")
        if not isinstance(recipients, (list, tuple)) or not recipients:
            raise AuditBadRequest(
                "recipients 必填：非空接收端列表，创建后集合即冻结")
        specs: list[tuple[str, int]] = []
        seen: set[str] = set()
        for item in recipients:
            if isinstance(item, str):
                rid, max_attempts = item, DEFAULT_MAX_ATTEMPTS
            elif isinstance(item, dict):
                rid = item.get("recipient_id")
                max_attempts = item.get("max_attempts", DEFAULT_MAX_ATTEMPTS)
            else:
                raise AuditBadRequest(
                    "recipients 元素必须是接收端标识字符串或"
                    " {recipient_id, max_attempts?} 对象")
            rid = self._require_str(rid, "recipient_id")
            if rid in seen:
                raise AuditBadRequest(
                    "同一通知内接收端标识不能重复", recipient_id=rid)
            seen.add(rid)
            max_attempts = self._require_int(
                max_attempts, "max_attempts", minimum=1)
            specs.append((rid, max_attempts))

        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            try:
                if policy_version in (None, ""):
                    policy = conn.execute(
                        "SELECT * FROM audit_fanout_policies"
                        " ORDER BY version DESC LIMIT 1").fetchone()
                    if policy is None:
                        raise FanoutNoCurrentPolicy(
                            "还没有任何送达策略：先创建策略再创建通知")
                else:
                    version = self._require_int(
                        policy_version, "policy_version", minimum=1)
                    policy = conn.execute(
                        "SELECT * FROM audit_fanout_policies"
                        " WHERE version=?", (version,)).fetchone()
                    if policy is None:
                        raise FanoutPolicyNotFound(
                            "策略版本不存在", version=version)
                # 冻结：策略版本、完成模式、所需成功数、接收端集合
                mode = policy["mode"]
                quorum = policy["quorum_count"]
                if mode == MODE_ALL:
                    required = len(specs)
                elif mode == MODE_ANY:
                    required = 1
                else:
                    required = quorum
                if mode == MODE_QUORUM and quorum > len(specs):
                    raise AuditBadRequest(
                        "quorum_count 超过接收端数量：策略对该接收端集合"
                        "永远不可能满足",
                        quorum_count=quorum, recipients=len(specs))
                nid = uuid.uuid4().hex
                now = self._now()
                conn.execute(
                    "INSERT INTO audit_fanout_notifications"
                    " (notification_id, payload_json, status,"
                    "  policy_version, mode, quorum_count,"
                    "  required_successes, decision_json,"
                    "  created_at_ms, decided_at_ms)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (nid, canonical_json(payload), STATUS_PENDING,
                     policy["version"], mode, quorum, required,
                     None, now, None))
                for position, (rid, max_attempts) in enumerate(specs):
                    conn.execute(
                        "INSERT INTO audit_fanout_recipients"
                        " (notification_id, recipient_id, position,"
                        "  max_attempts, state, paused, attempts,"
                        "  last_result, last_detail, updated_at_ms)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (nid, rid, position, max_attempts, R_PENDING,
                         0, 0, None, None, now))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            notif = self._get_notification_row(conn, nid)
            return self._notification_view(notif, self._recipient_rows(conn, nid))

    def get_notification(self, notification_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            notif = self._get_notification_row(conn, notification_id)
            return self._notification_view(
                notif, self._recipient_rows(conn, notification_id))

    def list_notifications(self, *, status: Any = None,
                           limit: Any = 100) -> dict[str, Any]:
        limit = min(int(limit), 1000)
        where, args = "", ()
        if status not in (None, ""):
            if status not in NOTIFICATION_STATUSES:
                raise AuditBadRequest(
                    "status 只能取 pending / completed / failed",
                    status=status)
            where, args = " WHERE status=?", (status,)
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            notifs = conn.execute(
                "SELECT * FROM audit_fanout_notifications" + where +
                " ORDER BY created_at_ms, notification_id LIMIT ?",
                (*args, limit)).fetchall()
            items = [
                self._summary_view(n, self._recipient_rows(
                    conn, n["notification_id"]))
                for n in notifs
            ]
        return {"notifications": items, "count": len(items)}

    # ======================================================================
    # 成功回执（按 通知+接收端+幂等键 幂等）
    # ======================================================================
    def submit_receipt(
        self,
        notification_id: str,
        *,
        recipient_id: Any,
        idempotency_key: Any,
        content: Any = None,
    ) -> tuple[dict[str, Any], bool]:
        """受理成功回执，返回 (结果视图, 是否首次记录)。

        幂等查找先于一切状态校验：相同回执重复到达只回放首次结果
        （即使通知此后已终态）；同键不同内容显式 409 冲突。
        """
        nid = self._require_str(notification_id, "notification_id")
        rid = self._require_str(recipient_id, "recipient_id")
        key = self._require_str(idempotency_key, "idempotency_key")
        receipt_content = {"recipient_id": rid, "content": content}
        content_canon = canonical_json(receipt_content)
        request_hash = hashlib.sha256(
            content_canon.encode("utf-8")).hexdigest()

        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            try:
                notif = self._get_notification_row(conn, nid)
                recip = self._get_recipient_row(conn, nid, rid)

                prev = conn.execute(
                    "SELECT * FROM audit_fanout_receipts"
                    " WHERE notification_id=? AND recipient_id=?"
                    " AND idempotency_key=?",
                    (nid, rid, key)).fetchone()
                if prev is not None:
                    if prev["request_hash"] != request_hash:
                        diff = first_diff(
                            json.loads(prev["content_json"]),
                            receipt_content, "receipt")
                        if diff is not None:
                            diff = {"path": diff["path"],
                                    "stored": diff["archived"],
                                    "received": diff["recomputed"]}
                        raise FanoutReceiptConflict(
                            "同一幂等键被内容不同的回执占用",
                            notification_id=nid, recipient_id=rid,
                            idempotency_key=key, first_difference=diff)
                    # 相同回执重复到达：只返回首次结果，不重复计尝试
                    return json.loads(prev["response_json"]), False

                if notif["status"] != STATUS_PENDING:
                    # 迟到回执：不能复活已失败的通知，也不能改动已完成
                    raise FanoutNotificationDecided(
                        "通知已有最终判定，回执迟到",
                        notification_id=nid,
                        notification_status=notif["status"],
                        decision=(json.loads(notif["decision_json"])
                                  if notif["decision_json"] else None))
                if recip["paused"]:
                    raise FanoutRecipientPaused(
                        "接收端已被管理员暂停，回执暂不受理",
                        notification_id=nid, recipient_id=rid)
                if recip["state"] == R_TERMINAL:
                    raise FanoutRecipientTerminal(
                        "接收端已达尝试上限进入终止态",
                        notification_id=nid, recipient_id=rid,
                        attempts=recip["attempts"],
                        max_attempts=recip["max_attempts"])
                if recip["state"] == R_SUCCEEDED:
                    # 成功幂等：新键重复回执不重复计尝试
                    response = self._receipt_response_locked(
                        conn, nid, rid, key, already_succeeded=True)
                    created = False
                else:
                    now = self._now()
                    seq = recip["attempts"] + 1
                    conn.execute(
                        "INSERT INTO audit_fanout_attempts"
                        " (notification_id, recipient_id, seq, result,"
                        "  detail, idempotency_key, created_at_ms)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (nid, rid, seq, RESULT_SUCCESS, None, key, now))
                    conn.execute(
                        "UPDATE audit_fanout_recipients SET state=?,"
                        " attempts=?, last_result=?, last_detail=?,"
                        " updated_at_ms=? WHERE notification_id=?"
                        " AND recipient_id=?",
                        (R_SUCCEEDED, seq, RESULT_SUCCESS, None, now,
                         nid, rid))
                    self._evaluate_locked(conn, nid)
                    response = self._receipt_response_locked(
                        conn, nid, rid, key, already_succeeded=False)
                    created = True
                conn.execute(
                    "INSERT INTO audit_fanout_receipts"
                    " (notification_id, recipient_id, idempotency_key,"
                    "  content_json, request_hash, response_json,"
                    "  created_at_ms) VALUES (?,?,?,?,?,?,?)",
                    (nid, rid, key, content_canon, request_hash,
                     canonical_json(response), self._now()))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            return response, created

    def _receipt_response_locked(
        self, conn: Any, nid: str, rid: str, key: str, *,
        already_succeeded: bool,
    ) -> dict[str, Any]:
        notif = self._get_notification_row(conn, nid)
        rows = self._recipient_rows(conn, nid)
        recip = next(r for r in rows if r["recipient_id"] == rid)
        return {
            "notification_id": nid,
            "recipient_id": rid,
            "idempotency_key": key,
            "recipient_state": recip["state"],
            "attempts": recip["attempts"],
            "notification_status": notif["status"],
            "already_succeeded": already_succeeded,
            "progress": self._progress(rows, notif["required_successes"]),
        }

    # ======================================================================
    # 失败重试（每次调用记一次失败尝试；达到该接收端上限即终止）
    # ======================================================================
    def record_failure(
        self,
        notification_id: str,
        recipient_id: str,
        *,
        detail: Any = None,
    ) -> dict[str, Any]:
        nid = self._require_str(notification_id, "notification_id")
        rid = self._require_str(recipient_id, "recipient_id")
        if detail is not None and not isinstance(detail, str):
            raise AuditBadRequest("detail 必须是字符串")
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            try:
                notif = self._get_notification_row(conn, nid)
                recip = self._get_recipient_row(conn, nid, rid)
                if notif["status"] != STATUS_PENDING:
                    # 迟到失败上报：不能改变既有判定
                    raise FanoutNotificationDecided(
                        "通知已有最终判定，失败上报迟到",
                        notification_id=nid,
                        notification_status=notif["status"],
                        decision=(json.loads(notif["decision_json"])
                                  if notif["decision_json"] else None))
                if recip["paused"]:
                    raise FanoutRecipientPaused(
                        "接收端已被管理员暂停，失败上报暂不受理",
                        notification_id=nid, recipient_id=rid)
                if recip["state"] == R_SUCCEEDED:
                    raise FanoutRecipientSucceeded(
                        "接收端已成功，不能再上报失败",
                        notification_id=nid, recipient_id=rid)
                if recip["state"] == R_TERMINAL:
                    raise FanoutRecipientTerminal(
                        "接收端已达尝试上限进入终止态",
                        notification_id=nid, recipient_id=rid,
                        attempts=recip["attempts"],
                        max_attempts=recip["max_attempts"])
                now = self._now()
                seq = recip["attempts"] + 1
                terminal = seq >= recip["max_attempts"]
                conn.execute(
                    "INSERT INTO audit_fanout_attempts"
                    " (notification_id, recipient_id, seq, result,"
                    "  detail, idempotency_key, created_at_ms)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (nid, rid, seq, RESULT_FAILURE, detail, None, now))
                conn.execute(
                    "UPDATE audit_fanout_recipients SET state=?,"
                    " attempts=?, last_result=?, last_detail=?,"
                    " updated_at_ms=? WHERE notification_id=?"
                    " AND recipient_id=?",
                    (R_TERMINAL if terminal else R_PENDING,
                     seq, RESULT_FAILURE, detail, now, nid, rid))
                if terminal:
                    # 一个接收端终止可能让冻结策略永远不可能满足
                    self._evaluate_locked(conn, nid)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            notif = self._get_notification_row(conn, nid)
            rows = self._recipient_rows(conn, nid)
            recip = next(r for r in rows if r["recipient_id"] == rid)
            return {
                "notification_id": nid,
                "recipient_id": rid,
                "recipient_state": recip["state"],
                "attempts": recip["attempts"],
                "max_attempts": recip["max_attempts"],
                "terminal": recip["state"] == R_TERMINAL,
                "notification_status": notif["status"],
                "progress": self._progress(
                    rows, notif["required_successes"]),
            }

    # ======================================================================
    # 暂停 / 恢复（幂等；只是拒收闸门，不改状态、不减计数、不翻终态）
    # ======================================================================
    def _set_paused(self, notification_id: str, recipient_id: str,
                    paused: bool) -> dict[str, Any]:
        nid = self._require_str(notification_id, "notification_id")
        rid = self._require_str(recipient_id, "recipient_id")
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            try:
                notif = self._get_notification_row(conn, nid)
                recip = self._get_recipient_row(conn, nid, rid)
                if bool(recip["paused"]) != paused:
                    conn.execute(
                        "UPDATE audit_fanout_recipients SET paused=?,"
                        " updated_at_ms=? WHERE notification_id=?"
                        " AND recipient_id=?",
                        (1 if paused else 0, self._now(), nid, rid))
                    conn.commit()
            except Exception:
                conn.rollback()
                raise
            recip = self._get_recipient_row(conn, nid, rid)
            return {
                "notification_id": nid,
                "notification_status": notif["status"],
                "recipient": self._recipient_view(recip),
            }

    def pause_recipient(self, notification_id: str,
                        recipient_id: str) -> dict[str, Any]:
        return self._set_paused(notification_id, recipient_id, True)

    def resume_recipient(self, notification_id: str,
                         recipient_id: str) -> dict[str, Any]:
        return self._set_paused(notification_id, recipient_id, False)

    # ======================================================================
    # 尝试记录（全局顺序 / 单接收端顺序）
    # ======================================================================
    def list_attempts(self, notification_id: str,
                      recipient_id: Any = None,
                      *, limit: Any = 1000) -> dict[str, Any]:
        nid = self._require_str(notification_id, "notification_id")
        limit = min(int(limit), 1000)
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._get_notification_row(conn, nid)
            if recipient_id not in (None, ""):
                rid = self._require_str(recipient_id, "recipient_id")
                self._get_recipient_row(conn, nid, rid)
                rows = conn.execute(
                    "SELECT * FROM audit_fanout_attempts"
                    " WHERE notification_id=? AND recipient_id=?"
                    " ORDER BY seq", (nid, rid)).fetchall()
            else:
                rid = None
                rows = conn.execute(
                    "SELECT * FROM audit_fanout_attempts"
                    " WHERE notification_id=? ORDER BY attempt_id",
                    (nid,)).fetchall()
            rows = rows[:limit]
        attempts = [
            {
                "attempt_id": r["attempt_id"],
                "notification_id": r["notification_id"],
                "recipient_id": r["recipient_id"],
                "seq": r["seq"],
                "result": r["result"],
                "detail": r["detail"],
                "idempotency_key": r["idempotency_key"],
                "created_at_ms": r["created_at_ms"],
            }
            for r in rows
        ]
        return {
            "notification_id": nid,
            "recipient_id": rid,
            "attempts": attempts,
            "count": len(attempts),
        }
