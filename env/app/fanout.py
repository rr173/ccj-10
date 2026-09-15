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

投递席位与有序备用接收端
========================
通知创建时可以用 ``seats`` 替代扁平的 ``recipients``：每个**投递席位**
冻结一份**有序候选列表**（第 1 位是主接收端，其余按顺序是备用接收端）
与**切换期限** ``switch_after_ms``（当前接收端的处理时长上限）。

- 席位先由主接收端处理；主接收端在期限内成功，席位**立即成功**，备用
  接收端永远不再启用（切换接口对已成功的席位一律 409）。
- 期限到达（超时）或管理员手动放弃当前接收端时，系统按顺序启用下一位
  备用接收端；每次启用都重算 ``deadline_at_ms = 启用时刻 +
  switch_after_ms``。同一席位无论切换多少次，最多只给整条通知贡献
  **一次**成功（成功计数读的是席位状态，不是候选）。
- 被替换接收端之后到达的回执/失败上报一律 409
  ``fanout_candidate_superseded`` 明确拒绝并记入席位历史，绝不算到
  当前席位；拒绝原因里带``胜负信息``（谁赢了：成功回执 / 哪次切换），
  调用方能据此判断输赢。
- 当前接收端的成功回执与超时/手动切换并发时，进程锁把两个请求串行化，
  **先结算者赢**：期限是硬边界（``deadline_at_ms <= now`` 一律算超时
  赢），后到者收到带胜负信息的 409 冲突。
- 一个席位的所有候选都失败（达到各自 ``max_attempts``）或被放弃后，
  席位进入终止态 ``exhausted``，参与原送达策略是否还能满足的判定：
  ``仍可能成功的席位数 = 席位总数 - 已终止数`` 低于冻结的所需成功数时，
  整条通知明确失败。

管理员可查看每个席位当前由谁处理、下一位备用接收端、切换期限、最近一次
切换原因与完整历史（启用/替换/回执受理与拒绝/失败/席位成败全部落
``audit_fanout_seat_events``），并可手动触发切换（支持幂等键与
``expected_recipient_id`` 防并发误切）。期限结算有三条路径结果一致：
后台 worker、``POST /audit/fanout/notifications/process-deadlines``
显式触发、各席位相关接口惰性结算。期限以绝对墙钟落库，服务重启后按
**原期限**继续，切换历史原样保留。

持久化与重启
============
策略、通知快照、接收端、席位与候选、逐次尝试记录（含顺序）、回执幂等
记录、席位事件历史与最终判定全部落 SQLite（与租约/订阅同一 WAL 库，
共用 Store 的进程锁与连接，不在内存里缓存任何判定状态）。进程重启后：
策略快照、尝试顺序、幂等回放、切换期限与最终判定原样保留。

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


class FanoutSeatNotFound(FanoutError):
    """席位不在该通知的冻结席位集合里（404）。"""

    code = "fanout_seat_not_found"
    status = 404


class FanoutSeatSucceeded(FanoutError):
    """席位已成功：不能再切换/上报失败（409，带成功回执的胜负信息）。"""

    code = "fanout_seat_succeeded"
    status = 409


class FanoutSeatExhausted(FanoutError):
    """席位候选全部失败或被放弃，已进入终止态（409）。"""

    code = "fanout_seat_exhausted"
    status = 409


class FanoutCandidateSuperseded(FanoutError):
    """接收端已被替换：其迟到回执/失败上报明确拒绝（409，带胜负信息）。"""

    code = "fanout_candidate_superseded"
    status = 409


class FanoutSeatSwitchConflict(FanoutError):
    """手动切换指定的期望接收端与当前接收端不符：他人已先切换（409）。"""

    code = "fanout_seat_switch_conflict"
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

# 通知结构：扁平接收端集合 / 投递席位（有序备用 + 切换期限）
STRUCT_RECIPIENTS = "recipients"
STRUCT_SEATS = "seats"

# 席位状态
SEAT_PENDING = "pending"      # 有当前接收端在处理
SEAT_SUCCEEDED = "succeeded"  # 某候选在期限内成功（立即成功，备用永不启用）
SEAT_EXHAUSTED = "exhausted"  # 终止态：所有候选都失败或被放弃

# 候选状态
CAND_WAITING = "waiting"        # 备用，尚未启用
CAND_ACTIVE = "active"          # 当前正在处理该席位的接收端
CAND_SUCCEEDED = "succeeded"    # 在期限内成功
CAND_SUPERSEDED = "superseded"  # 被替换（超时/手动放弃/失败达到上限）

# 候选被替换的原因（end_reason；同时是切换事件与手动切换的 reason）
REASON_TIMEOUT = "timeout_expired"    # 切换期限到达
REASON_MANUAL = "manual_abandon"      # 管理员手动放弃当前接收端
REASON_FAILED = "candidate_failed"    # 失败重试达到该候选自己的上限

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
    structure          TEXT NOT NULL DEFAULT 'recipients',  -- recipients/seats
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
CREATE TABLE IF NOT EXISTS audit_fanout_seats (
    notification_id TEXT NOT NULL,
    seat_id         TEXT NOT NULL,
    position        INTEGER NOT NULL,        -- 冻结席位集合中的顺序
    switch_after_ms INTEGER NOT NULL,        -- 每个候选的处理期限（时长）
    state           TEXT NOT NULL DEFAULT 'pending',
    current_seq     INTEGER,                 -- 当前候选序号（终止态为 NULL）
    succeeded_by    TEXT,                    -- 让席位成功的接收端
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (notification_id, seat_id)
);
CREATE TABLE IF NOT EXISTS audit_fanout_seat_candidates (
    notification_id TEXT NOT NULL,
    seat_id         TEXT NOT NULL,
    seq             INTEGER NOT NULL,  -- 1=主接收端，之后按顺序为备用
    recipient_id    TEXT NOT NULL,
    max_attempts    INTEGER NOT NULL,  -- 该候选自己的失败上限
    state           TEXT NOT NULL DEFAULT 'waiting',
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_result     TEXT,
    last_detail     TEXT,
    activated_at_ms INTEGER,           -- 启用时刻（NULL=未启用）
    deadline_at_ms  INTEGER,           -- 切换期限（启用时刻+switch_after_ms）
    ended_at_ms     INTEGER,
    end_reason      TEXT,              -- timeout_expired/manual_abandon/
                                       -- candidate_failed
    PRIMARY KEY (notification_id, seat_id, seq)
);
-- 同一通知内接收端标识唯一（跨席位也不重复），回执才能确定路由到哪个席位
CREATE UNIQUE INDEX IF NOT EXISTS idx_fanout_seat_candidate_recipient
    ON audit_fanout_seat_candidates(notification_id, recipient_id);
CREATE TABLE IF NOT EXISTS audit_fanout_seat_events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,  -- 席位历史顺序
    notification_id TEXT NOT NULL,
    seat_id         TEXT NOT NULL,
    event           TEXT NOT NULL,     -- seat_created/candidate_activated/
                                       -- candidate_superseded/receipt_accepted/
                                       -- receipt_rejected/failure_recorded/
                                       -- failure_rejected/seat_succeeded/
                                       -- seat_exhausted
    candidate_seq   INTEGER,
    recipient_id    TEXT,
    reason          TEXT,              -- 切换/拒绝原因
    detail          TEXT,              -- JSON：期限、幂等键、胜负信息等
    created_at_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fanout_seat_events
    ON audit_fanout_seat_events(notification_id, seat_id, event_id);
CREATE TABLE IF NOT EXISTS audit_fanout_seat_commands (
    notification_id TEXT NOT NULL,
    seat_id         TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    response_json   TEXT NOT NULL,     -- 手动切换首次处理结果（回放原文）
    created_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (notification_id, seat_id, idempotency_key)
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
            # 老库迁移：通知行增加结构标记（扁平接收端 / 投递席位）
            cols = {r["name"] for r in store._conn.execute(  # noqa: SLF001
                "PRAGMA table_info(audit_fanout_notifications)")}
            if "structure" not in cols:
                store._conn.execute(  # noqa: SLF001
                    "ALTER TABLE audit_fanout_notifications"
                    " ADD COLUMN structure TEXT NOT NULL"
                    " DEFAULT 'recipients'")
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

    def _get_seat_row(self, conn: Any, nid: str, sid: str):
        row = conn.execute(
            "SELECT * FROM audit_fanout_seats"
            " WHERE notification_id=? AND seat_id=?",
            (nid, sid)).fetchone()
        if row is None:
            raise FanoutSeatNotFound(
                "席位不在该通知的冻结席位集合里",
                notification_id=nid, seat_id=sid)
        return row

    def _seat_rows(self, conn: Any, nid: str):
        return conn.execute(
            "SELECT * FROM audit_fanout_seats WHERE notification_id=?"
            " ORDER BY position", (nid,)).fetchall()

    def _candidate_rows(self, conn: Any, nid: str, sid: str):
        return conn.execute(
            "SELECT * FROM audit_fanout_seat_candidates"
            " WHERE notification_id=? AND seat_id=? ORDER BY seq",
            (nid, sid)).fetchall()

    def _candidate_by_recipient(self, conn: Any, nid: str, rid: str):
        return conn.execute(
            "SELECT * FROM audit_fanout_seat_candidates"
            " WHERE notification_id=? AND recipient_id=?",
            (nid, rid)).fetchone()

    @staticmethod
    def _active_candidate(candidates):
        return next((c for c in candidates if c["state"] == CAND_ACTIVE),
                    None)

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

    @staticmethod
    def _seat_progress(seats, required: int) -> dict[str, Any]:
        """席位通知的进度：成功/终止席位数与策略是否仍可能满足。"""
        succeeded = sum(1 for s in seats if s["state"] == SEAT_SUCCEEDED)
        exhausted = sum(1 for s in seats if s["state"] == SEAT_EXHAUSTED)
        total = len(seats)
        return {
            "seats_total": total,
            "required_successes": required,
            "succeeded": succeeded,
            "exhausted": exhausted,
            "pending": total - succeeded - exhausted,
            "remaining_successes": max(0, required - succeeded),
            "satisfiable": (total - exhausted) >= required,
        }

    @staticmethod
    def _candidate_view(c, now: int) -> dict[str, Any]:
        remaining_ms = None
        if c["state"] == CAND_ACTIVE and c["deadline_at_ms"] is not None:
            remaining_ms = max(0, c["deadline_at_ms"] - now)
        return {
            "seq": c["seq"],
            "recipient_id": c["recipient_id"],
            "state": c["state"],
            "end_reason": c["end_reason"],
            "attempts": c["attempts"],
            "max_attempts": c["max_attempts"],
            "last_result": c["last_result"],
            "last_detail": c["last_detail"],
            "activated_at_ms": c["activated_at_ms"],
            "deadline_at_ms": c["deadline_at_ms"],
            "remaining_ms": remaining_ms,
            "ended_at_ms": c["ended_at_ms"],
        }

    def _seat_view(self, conn: Any, seat, now: Any = None) -> dict[str, Any]:
        """管理员席位视图：当前处理人、下一位备用、切换期限、最近切换原因。"""
        if now is None:
            now = self._now()
        nid, sid = seat["notification_id"], seat["seat_id"]
        candidates = self._candidate_rows(conn, nid, sid)
        current = self._active_candidate(candidates)
        nxt = None
        if seat["state"] == SEAT_PENDING:
            nxt = next((c for c in candidates
                        if c["state"] == CAND_WAITING), None)
        last = conn.execute(
            "SELECT * FROM audit_fanout_seat_events"
            " WHERE notification_id=? AND seat_id=? AND event=?"
            " ORDER BY event_id DESC LIMIT 1",
            (nid, sid, "candidate_superseded")).fetchone()
        last_switch = None
        if last is not None:
            last_switch = {
                "from_seq": last["candidate_seq"],
                "from_recipient_id": last["recipient_id"],
                "reason": last["reason"],
                "at_ms": last["created_at_ms"],
                "to_seq": seat["current_seq"],
                "to_recipient_id": (current["recipient_id"]
                                    if current is not None else None),
            }
        return {
            "seat_id": sid,
            "state": seat["state"],
            "switch_after_ms": seat["switch_after_ms"],
            "current": (self._candidate_view(current, now)
                        if current is not None else None),
            "next_candidate": ({"seq": nxt["seq"],
                                "recipient_id": nxt["recipient_id"]}
                               if nxt is not None else None),
            "succeeded_by": seat["succeeded_by"],
            "last_switch": last_switch,
            "candidates": [self._candidate_view(c, now) for c in candidates],
            "created_at_ms": seat["created_at_ms"],
            "updated_at_ms": seat["updated_at_ms"],
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

    def _notification_view(self, conn: Any, notif, rows) -> dict[str, Any]:
        view = {
            "notification_id": notif["notification_id"],
            "payload": json.loads(notif["payload_json"]),
            "status": notif["status"],
            "structure": notif["structure"],
            "policy": self._policy_snapshot(notif),
            "decision": (json.loads(notif["decision_json"])
                         if notif["decision_json"] else None),
            "created_at_ms": notif["created_at_ms"],
            "decided_at_ms": notif["decided_at_ms"],
        }
        if notif["structure"] == STRUCT_SEATS:
            seats = self._seat_rows(conn, notif["notification_id"])
            now = self._now()
            view["seats"] = [self._seat_view(conn, s, now) for s in seats]
            view["progress"] = self._seat_progress(
                seats, notif["required_successes"])
        else:
            view["recipients"] = [self._recipient_view(r) for r in rows]
            view["progress"] = self._progress(
                rows, notif["required_successes"])
        return view

    def _summary_view(self, conn: Any, notif, rows) -> dict[str, Any]:
        if notif["structure"] == STRUCT_SEATS:
            seats = self._seat_rows(conn, notif["notification_id"])
            progress = self._seat_progress(seats, notif["required_successes"])
        else:
            progress = self._progress(rows, notif["required_successes"])
        return {
            "notification_id": notif["notification_id"],
            "status": notif["status"],
            "structure": notif["structure"],
            "policy": self._policy_snapshot(notif),
            "progress": progress,
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

    def _seat_decision_snapshot(self, conn: Any, seats, required: int,
                                reason: str) -> dict[str, Any]:
        """席位通知的终态判定快照：原因 + 每个席位与其全部候选当时的状态。"""
        nid = seats[0]["notification_id"] if seats else None
        seat_items = []
        for s in seats:
            candidates = self._candidate_rows(conn, nid, s["seat_id"])
            current = self._active_candidate(candidates)
            seat_items.append({
                "seat_id": s["seat_id"],
                "state": s["state"],
                "succeeded_by": s["succeeded_by"],
                "current_recipient_id": (current["recipient_id"]
                                         if current is not None else None),
                "candidates": [
                    {
                        "seq": c["seq"],
                        "recipient_id": c["recipient_id"],
                        "state": c["state"],
                        "end_reason": c["end_reason"],
                        "attempts": c["attempts"],
                        "max_attempts": c["max_attempts"],
                    }
                    for c in candidates
                ],
            })
        return {
            "reason": reason,
            "required_successes": required,
            "succeeded": sum(1 for s in seats if s["state"] == SEAT_SUCCEEDED),
            "exhausted": sum(1 for s in seats if s["state"] == SEAT_EXHAUSTED),
            "seats": seat_items,
        }

    def _evaluate_locked(self, conn: Any, nid: str) -> None:
        """按冻结快照重估通知；达成/不可能达成即冻结终态与判定快照。

        已终态的通知直接返回：判定一旦落库永远不变，迟到事件不能翻案。
        """
        notif = self._get_notification_row(conn, nid)
        if notif["status"] != STATUS_PENDING:
            return
        required = notif["required_successes"]
        now = self._now()
        if notif["structure"] == STRUCT_SEATS:
            # 席位通知：席位成功数达标即完成；仍可能成功的席位数
            # （总数 - 已终止）低于所需成功数时明确失败
            seats = self._seat_rows(conn, nid)
            succeeded = sum(1 for s in seats if s["state"] == SEAT_SUCCEEDED)
            exhausted = sum(1 for s in seats if s["state"] == SEAT_EXHAUSTED)
            if succeeded >= required:
                decision = self._seat_decision_snapshot(
                    conn, seats, required, "policy_satisfied")
                conn.execute(
                    "UPDATE audit_fanout_notifications SET status=?,"
                    " decision_json=?, decided_at_ms=?"
                    " WHERE notification_id=?",
                    (STATUS_COMPLETED, canonical_json(decision), now, nid))
            elif len(seats) - exhausted < required:
                decision = self._seat_decision_snapshot(
                    conn, seats, required, "policy_unsatisfiable")
                conn.execute(
                    "UPDATE audit_fanout_notifications SET status=?,"
                    " decision_json=?, decided_at_ms=?"
                    " WHERE notification_id=?",
                    (STATUS_FAILED, canonical_json(decision), now, nid))
            return
        rows = self._recipient_rows(conn, nid)
        succeeded = sum(1 for r in rows if r["state"] == R_SUCCEEDED)
        terminated = sum(1 for r in rows if r["state"] == R_TERMINAL)
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
    # 通知创建（冻结策略快照 + 接收端集合 / 投递席位）
    # ======================================================================
    def _parse_seat_specs(self, seats: Any):
        """解析并校验席位配置：每个席位冻结有序候选列表与切换期限。"""
        if not isinstance(seats, (list, tuple)) or not seats:
            raise AuditBadRequest(
                "seats 必填：非空席位列表，创建后席位、候选顺序与切换期限"
                "即冻结")
        specs = []
        seen_seats: set[str] = set()
        seen_recipients: set[str] = set()
        for index, item in enumerate(seats, start=1):
            if not isinstance(item, dict):
                raise AuditBadRequest(
                    "seats 元素必须是 {seat_id?, switch_after_ms,"
                    " candidates:[...]} 对象")
            seat_id = item.get("seat_id") or f"seat-{index}"
            seat_id = self._require_str(seat_id, "seat_id")
            if seat_id in seen_seats:
                raise AuditBadRequest(
                    "同一通知内席位标识不能重复", seat_id=seat_id)
            seen_seats.add(seat_id)
            switch_after_ms = self._require_int(
                item.get("switch_after_ms"), "switch_after_ms", minimum=1)
            candidates = item.get("candidates")
            if not isinstance(candidates, (list, tuple)) or not candidates:
                raise AuditBadRequest(
                    "每个席位必须给出非空 candidates：第 1 位是主接收端，"
                    "其余按顺序为备用接收端", seat_id=seat_id)
            cand_specs: list[tuple[str, int]] = []
            for c in candidates:
                if isinstance(c, str):
                    rid, max_attempts = c, DEFAULT_MAX_ATTEMPTS
                elif isinstance(c, dict):
                    rid = c.get("recipient_id")
                    max_attempts = c.get("max_attempts", DEFAULT_MAX_ATTEMPTS)
                else:
                    raise AuditBadRequest(
                        "candidates 元素必须是接收端标识字符串或"
                        " {recipient_id, max_attempts?} 对象")
                rid = self._require_str(rid, "recipient_id")
                if rid in seen_recipients:
                    raise AuditBadRequest(
                        "同一通知内接收端标识不能重复（跨席位也不能重复，"
                        "否则回执无法路由到唯一席位）", recipient_id=rid)
                seen_recipients.add(rid)
                max_attempts = self._require_int(
                    max_attempts, "max_attempts", minimum=1)
                cand_specs.append((rid, max_attempts))
            specs.append((seat_id, switch_after_ms, cand_specs))
        return specs

    def create_notification(
        self,
        *,
        payload: Any,
        recipients: Any = None,
        seats: Any = None,
        policy_version: Any = None,
    ) -> dict[str, Any]:
        if payload is None:
            raise AuditBadRequest("payload 必填：审计通知内容")
        if recipients is not None and seats is not None:
            raise AuditBadRequest(
                "recipients 与 seats 只能二选一：扁平接收端集合或投递席位")
        if recipients is None and seats is None:
            raise AuditBadRequest(
                "recipients 或 seats 必填其一，创建后集合即冻结")
        specs: list[tuple[str, int]] | None = None
        seat_specs = None
        if seats is not None:
            seat_specs = self._parse_seat_specs(seats)
            structure = STRUCT_SEATS
            unit_count = len(seat_specs)
        else:
            if not isinstance(recipients, (list, tuple)) or not recipients:
                raise AuditBadRequest(
                    "recipients 必填：非空接收端列表，创建后集合即冻结")
            specs = []
            seen: set[str] = set()
            for item in recipients:
                if isinstance(item, str):
                    rid, max_attempts = item, DEFAULT_MAX_ATTEMPTS
                elif isinstance(item, dict):
                    rid = item.get("recipient_id")
                    max_attempts = item.get("max_attempts",
                                            DEFAULT_MAX_ATTEMPTS)
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
            structure = STRUCT_RECIPIENTS
            unit_count = len(specs)

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
                # 冻结：策略版本、完成模式、所需成功数、接收端集合/席位
                mode = policy["mode"]
                quorum = policy["quorum_count"]
                if mode == MODE_ALL:
                    required = unit_count
                elif mode == MODE_ANY:
                    required = 1
                else:
                    required = quorum
                if mode == MODE_QUORUM and quorum > unit_count:
                    raise AuditBadRequest(
                        "quorum_count 超过接收端/席位数量：策略对该集合"
                        "永远不可能满足",
                        quorum_count=quorum, units=unit_count)
                nid = uuid.uuid4().hex
                now = self._now()
                conn.execute(
                    "INSERT INTO audit_fanout_notifications"
                    " (notification_id, payload_json, status, structure,"
                    "  policy_version, mode, quorum_count,"
                    "  required_successes, decision_json,"
                    "  created_at_ms, decided_at_ms)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (nid, canonical_json(payload), STATUS_PENDING, structure,
                     policy["version"], mode, quorum, required,
                     None, now, None))
                if structure == STRUCT_RECIPIENTS:
                    for position, (rid, max_attempts) in enumerate(specs):
                        conn.execute(
                            "INSERT INTO audit_fanout_recipients"
                            " (notification_id, recipient_id, position,"
                            "  max_attempts, state, paused, attempts,"
                            "  last_result, last_detail, updated_at_ms)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (nid, rid, position, max_attempts, R_PENDING,
                             0, 0, None, None, now))
                else:
                    for position, (seat_id, switch_after_ms,
                                   cand_specs) in enumerate(seat_specs):
                        conn.execute(
                            "INSERT INTO audit_fanout_seats"
                            " (notification_id, seat_id, position,"
                            "  switch_after_ms, state, current_seq,"
                            "  succeeded_by, created_at_ms, updated_at_ms)"
                            " VALUES (?,?,?,?,?,?,?,?,?)",
                            (nid, seat_id, position, switch_after_ms,
                             SEAT_PENDING, 1, None, now, now))
                        for seq, (rid, max_attempts) in enumerate(
                                cand_specs, start=1):
                            primary = seq == 1
                            conn.execute(
                                "INSERT INTO audit_fanout_seat_candidates"
                                " (notification_id, seat_id, seq,"
                                "  recipient_id, max_attempts, state,"
                                "  attempts, last_result, last_detail,"
                                "  activated_at_ms, deadline_at_ms,"
                                "  ended_at_ms, end_reason)"
                                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (nid, seat_id, seq, rid, max_attempts,
                                 CAND_ACTIVE if primary else CAND_WAITING,
                                 0, None, None,
                                 now if primary else None,
                                 now + switch_after_ms if primary else None,
                                 None, None))
                        # 席位创建与主接收端启用都进入完整历史
                        self._record_seat_event_locked(
                            conn, nid, seat_id, "seat_created",
                            detail=canonical_json({
                                "switch_after_ms": switch_after_ms,
                                "candidates": [rid for rid, _
                                               in cand_specs],
                            }))
                        self._record_seat_event_locked(
                            conn, nid, seat_id, "candidate_activated",
                            candidate_seq=1, recipient_id=cand_specs[0][0],
                            reason="initial",
                            detail=canonical_json({
                                "deadline_at_ms": now + switch_after_ms}))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            notif = self._get_notification_row(conn, nid)
            return self._notification_view(
                conn, notif, self._recipient_rows(conn, nid))

    def get_notification(self, notification_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            notif = self._get_notification_row(conn, notification_id)
            if notif["structure"] == STRUCT_SEATS:
                # 惰性结算到期的切换期限：查询看到的永远是结算后的状态
                self._apply_due_switches_locked(conn, notification_id)
                notif = self._get_notification_row(conn, notification_id)
            return self._notification_view(
                conn, notif, self._recipient_rows(conn, notification_id))

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
            self._apply_due_switches_locked(conn)  # 列表同样先结算到期切换
            notifs = conn.execute(
                "SELECT * FROM audit_fanout_notifications" + where +
                " ORDER BY created_at_ms, notification_id LIMIT ?",
                (*args, limit)).fetchall()
            items = [
                self._summary_view(conn, n, self._recipient_rows(
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
            notif = self._get_notification_row(conn, nid)
            is_seats = notif["structure"] == STRUCT_SEATS
            if is_seats:
                # 先结算到期的超时切换（独立提交）：回执与超时并发时
                # 期限是硬边界——deadline_at_ms <= now 一律算超时赢，
                # 迟到的回执随后按"被替换接收端"明确拒绝
                self._apply_due_switches_locked(conn, nid)
                notif = self._get_notification_row(conn, nid)
            try:
                if is_seats:
                    cand = self._candidate_by_recipient(conn, nid, rid)
                    if cand is None:
                        raise FanoutRecipientNotFound(
                            "接收端不在该通知的冻结席位候选里",
                            notification_id=nid, recipient_id=rid)
                    seat = self._get_seat_row(conn, nid, cand["seat_id"])
                    recip = None
                else:
                    cand = seat = None
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

                if notif["status"] != STATUS_PENDING and not is_seats:
                    # 迟到回执：不能复活已失败的通知，也不能改动已完成
                    raise FanoutNotificationDecided(
                        "通知已有最终判定，回执迟到",
                        notification_id=nid,
                        notification_status=notif["status"],
                        decision=(json.loads(notif["decision_json"])
                                  if notif["decision_json"] else None))
                if is_seats:
                    # 席位通知：候选级路由先于通知级判定——被替换候选的
                    # 迟到回执永远得到带胜负信息的明确拒绝
                    response, created = self._accept_seat_receipt_locked(
                        conn, nid, seat, cand, key, notif)
                elif recip["paused"]:
                    raise FanoutRecipientPaused(
                        "接收端已被管理员暂停，回执暂不受理",
                        notification_id=nid, recipient_id=rid)
                elif recip["state"] == R_TERMINAL:
                    raise FanoutRecipientTerminal(
                        "接收端已达尝试上限进入终止态",
                        notification_id=nid, recipient_id=rid,
                        attempts=recip["attempts"],
                        max_attempts=recip["max_attempts"])
                elif recip["state"] == R_SUCCEEDED:
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
            notif = self._get_notification_row(conn, nid)
            is_seats = notif["structure"] == STRUCT_SEATS
            if is_seats:
                # 与回执一致：先结算到期超时切换，再判定这次失败上报
                self._apply_due_switches_locked(conn, nid)
                notif = self._get_notification_row(conn, nid)
            try:
                if is_seats:
                    cand = self._candidate_by_recipient(conn, nid, rid)
                    if cand is None:
                        raise FanoutRecipientNotFound(
                            "接收端不在该通知的冻结席位候选里",
                            notification_id=nid, recipient_id=rid)
                    seat = self._get_seat_row(conn, nid, cand["seat_id"])
                    recip = None
                else:
                    cand = seat = None
                    recip = self._get_recipient_row(conn, nid, rid)
                if notif["status"] != STATUS_PENDING:
                    # 迟到失败上报：不能改变既有判定
                    raise FanoutNotificationDecided(
                        "通知已有最终判定，失败上报迟到",
                        notification_id=nid,
                        notification_status=notif["status"],
                        decision=(json.loads(notif["decision_json"])
                                  if notif["decision_json"] else None))
                if is_seats:
                    result = self._record_seat_failure_locked(
                        conn, nid, seat, cand, detail)
                    conn.commit()
                    return result
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
                recip = conn.execute(
                    "SELECT 1 FROM audit_fanout_recipients"
                    " WHERE notification_id=? AND recipient_id=?",
                    (nid, rid)).fetchone()
                if recip is None:
                    cand = conn.execute(
                        "SELECT 1 FROM audit_fanout_seat_candidates"
                        " WHERE notification_id=? AND recipient_id=?",
                        (nid, rid)).fetchone()
                    if cand is None:
                        raise FanoutRecipientNotFound(
                            "接收端不在该通知的冻结集合里",
                            notification_id=nid, recipient_id=rid)
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

    # ======================================================================
    # 投递席位：有序备用接收端 + 切换期限
    # ======================================================================
    def _record_seat_event_locked(
        self, conn: Any, nid: str, sid: str, event: str, *,
        candidate_seq: Any = None, recipient_id: Any = None,
        reason: Any = None, detail: Any = None,
    ) -> None:
        """席位历史只追加：启用/替换/回执受理与拒绝/失败/席位成败。"""
        conn.execute(
            "INSERT INTO audit_fanout_seat_events"
            " (notification_id, seat_id, event, candidate_seq,"
            "  recipient_id, reason, detail, created_at_ms)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (nid, sid, event, candidate_seq, recipient_id, reason,
             detail, self._now()))

    def _switch_locked(self, conn: Any, seat, *,
                       reason: str, detail: Any = None) -> dict | None:
        """放弃当前候选并按顺序启用下一位备用；没有备用则席位终止。

        三种触发共用同一段路径：超时（timeout_expired）、管理员手动放弃
        （manual_abandon）、当前候选失败达到上限（candidate_failed）。
        返回切换描述（谁被替换 / 谁接任 / 新期限 / 时间），调用方负责
        事务与通知级重估。
        """
        nid, sid = seat["notification_id"], seat["seat_id"]
        candidates = self._candidate_rows(conn, nid, sid)
        current = self._active_candidate(candidates)
        if current is None:
            return None  # 没有当前候选（已被并发路径处理），无需切换
        now = self._now()
        conn.execute(
            "UPDATE audit_fanout_seat_candidates SET state=?, end_reason=?,"
            " ended_at_ms=? WHERE notification_id=? AND seat_id=?"
            " AND seq=?",
            (CAND_SUPERSEDED, reason, now, nid, sid, current["seq"]))
        self._record_seat_event_locked(
            conn, nid, sid, "candidate_superseded",
            candidate_seq=current["seq"],
            recipient_id=current["recipient_id"],
            reason=reason, detail=detail)
        nxt = next((c for c in candidates if c["state"] == CAND_WAITING),
                   None)
        if nxt is None:
            # 候选全部耗尽：席位进入终止态，参与策略可满足性判定
            conn.execute(
                "UPDATE audit_fanout_seats SET state=?, current_seq=NULL,"
                " updated_at_ms=? WHERE notification_id=? AND seat_id=?",
                (SEAT_EXHAUSTED, now, nid, sid))
            self._record_seat_event_locked(
                conn, nid, sid, "seat_exhausted",
                candidate_seq=current["seq"],
                recipient_id=current["recipient_id"], reason=reason)
            to = None
        else:
            deadline = now + seat["switch_after_ms"]
            conn.execute(
                "UPDATE audit_fanout_seat_candidates SET state=?,"
                " activated_at_ms=?, deadline_at_ms=?"
                " WHERE notification_id=? AND seat_id=? AND seq=?",
                (CAND_ACTIVE, now, deadline, nid, sid, nxt["seq"]))
            conn.execute(
                "UPDATE audit_fanout_seats SET current_seq=?,"
                " updated_at_ms=? WHERE notification_id=? AND seat_id=?",
                (nxt["seq"], now, nid, sid))
            self._record_seat_event_locked(
                conn, nid, sid, "candidate_activated",
                candidate_seq=nxt["seq"],
                recipient_id=nxt["recipient_id"], reason=reason,
                detail=canonical_json({"deadline_at_ms": deadline}))
            to = {"seq": nxt["seq"], "recipient_id": nxt["recipient_id"],
                  "deadline_at_ms": deadline}
        return {
            "notification_id": nid,
            "seat_id": sid,
            "from": {"seq": current["seq"],
                     "recipient_id": current["recipient_id"],
                     "reason": reason},
            "to": to,
            "seat_state": SEAT_PENDING if to is not None else SEAT_EXHAUSTED,
            "at_ms": now,
        }

    def _apply_due_switches_locked(self, conn: Any,
                                   nid: Any = None) -> list[dict]:
        """结算所有已到期的切换期限（超时启用下一位备用）。

        期限是硬边界：deadline_at_ms <= now 的当前候选一律被替换。
        后台 worker、显式 process-deadlines 接口与各席位相关接口的惰性
        结算都走这里，三条路径结果一致；有实际切换时独立提交，保证随后
        的回执/切换请求看到的是已结算状态。
        """
        now = self._now()
        sql = (
            "SELECT s.* FROM audit_fanout_seats s"
            " JOIN audit_fanout_notifications n"
            " ON n.notification_id = s.notification_id"
            " WHERE n.status = ? AND s.state = ?")
        args: list[Any] = [STATUS_PENDING, SEAT_PENDING]
        if nid not in (None, ""):
            sql += " AND s.notification_id = ?"
            args.append(nid)
        seats = conn.execute(sql, args).fetchall()
        applied: list[dict] = []
        for seat in seats:
            current = conn.execute(
                "SELECT * FROM audit_fanout_seat_candidates"
                " WHERE notification_id=? AND seat_id=? AND state=?",
                (seat["notification_id"], seat["seat_id"],
                 CAND_ACTIVE)).fetchone()
            if current is None or current["deadline_at_ms"] is None:
                continue
            if current["deadline_at_ms"] <= now:
                info = self._switch_locked(conn, seat, reason=REASON_TIMEOUT)
                if info is not None:
                    applied.append(info)
                    # 席位终止可能让冻结策略不再可能满足
                    self._evaluate_locked(conn, seat["notification_id"])
        if applied:
            conn.commit()
        return applied

    def process_due_seats(self) -> dict[str, Any]:
        """管理/演练入口：结算全部到期的切换期限，返回本次发生的切换。"""
        store = self._store
        with store._lock:  # noqa: SLF001
            applied = self._apply_due_switches_locked(
                store._conn)  # noqa: SLF001
        return {"now_ms": self._now(), "switches": applied,
                "count": len(applied)}

    def _seat_winner_locked(self, conn: Any, seat, cand) -> dict[str, Any]:
        """席位当前的胜负状态：回执输了的话，赢的是谁（用于 409 判断）。"""
        if seat["state"] == SEAT_SUCCEEDED:
            return {
                "type": "receipt",
                "recipient_id": seat["succeeded_by"],
                "seat_state": SEAT_SUCCEEDED,
                "at_ms": seat["updated_at_ms"],
            }
        if seat["state"] == SEAT_EXHAUSTED:
            return {
                "type": "exhausted",
                "seat_state": SEAT_EXHAUSTED,
                "at_ms": seat["updated_at_ms"],
            }
        current = conn.execute(
            "SELECT * FROM audit_fanout_seat_candidates"
            " WHERE notification_id=? AND seat_id=? AND state=?",
            (seat["notification_id"], seat["seat_id"],
             CAND_ACTIVE)).fetchone()
        return {
            "type": "switch",
            "reason": cand["end_reason"],
            "at_ms": cand["ended_at_ms"],
            "current_candidate": (
                {
                    "seq": current["seq"],
                    "recipient_id": current["recipient_id"],
                    "deadline_at_ms": current["deadline_at_ms"],
                }
                if current is not None else None),
        }

    def _reject_seat_receipt_locked(self, conn: Any, nid: str, seat, cand,
                                    key: str, *, reason: str) -> None:
        """记录被拒回执并独立提交（随后的 409 不会回滚这条历史）。"""
        winner = self._seat_winner_locked(conn, seat, cand)
        self._record_seat_event_locked(
            conn, nid, seat["seat_id"], "receipt_rejected",
            candidate_seq=cand["seq"], recipient_id=cand["recipient_id"],
            reason=reason,
            detail=canonical_json(
                {"idempotency_key": key, "winner": winner}))
        conn.commit()

    def _accept_seat_receipt_locked(self, conn: Any, nid: str, seat, cand,
                                    key: str, notif
                                    ) -> tuple[dict[str, Any], bool]:
        """席位回执路由：只认当前候选；被替换候选的迟到回执明确拒绝。"""
        sid = seat["seat_id"]
        rid = cand["recipient_id"]
        now = self._now()
        if cand["state"] == CAND_ACTIVE and seat["state"] == SEAT_PENDING:
            if notif["status"] != STATUS_PENDING:
                # 通知已因其他席位终态：当前候选的回执同样迟到
                self._reject_seat_receipt_locked(
                    conn, nid, seat, cand, key,
                    reason="notification_decided")
                raise FanoutNotificationDecided(
                    "通知已有最终判定，回执迟到",
                    notification_id=nid,
                    notification_status=notif["status"],
                    decision=(json.loads(notif["decision_json"])
                              if notif["decision_json"] else None))
            # 当前候选在期限内成功：席位立即成功，备用永远不再启用
            attempt_seq = cand["attempts"] + 1
            conn.execute(
                "INSERT INTO audit_fanout_attempts"
                " (notification_id, recipient_id, seq, result,"
                "  detail, idempotency_key, created_at_ms)"
                " VALUES (?,?,?,?,?,?,?)",
                (nid, rid, attempt_seq, RESULT_SUCCESS, None, key, now))
            conn.execute(
                "UPDATE audit_fanout_seat_candidates SET state=?,"
                " attempts=?, last_result=?, last_detail=NULL,"
                " ended_at_ms=? WHERE notification_id=? AND seat_id=?"
                " AND seq=?",
                (CAND_SUCCEEDED, attempt_seq, RESULT_SUCCESS, now,
                 nid, sid, cand["seq"]))
            conn.execute(
                "UPDATE audit_fanout_seats SET state=?, succeeded_by=?,"
                " updated_at_ms=? WHERE notification_id=? AND seat_id=?",
                (SEAT_SUCCEEDED, rid, now, nid, sid))
            self._record_seat_event_locked(
                conn, nid, sid, "receipt_accepted",
                candidate_seq=cand["seq"], recipient_id=rid,
                detail=canonical_json({"idempotency_key": key}))
            self._record_seat_event_locked(
                conn, nid, sid, "seat_succeeded",
                candidate_seq=cand["seq"], recipient_id=rid)
            self._evaluate_locked(conn, nid)
            return (self._seat_receipt_response_locked(
                        conn, nid, sid, rid, key, already_succeeded=False),
                    True)
        if cand["state"] == CAND_SUCCEEDED:
            # 该候选已让席位成功：新键重复回执不重复计尝试
            return (self._seat_receipt_response_locked(
                        conn, nid, sid, rid, key, already_succeeded=True),
                    False)
        # 被替换/被放弃候选的迟到回执：明确拒绝，绝不算到当前席位
        winner = self._seat_winner_locked(conn, seat, cand)
        self._record_seat_event_locked(
            conn, nid, sid, "receipt_rejected",
            candidate_seq=cand["seq"], recipient_id=rid,
            reason="candidate_superseded",
            detail=canonical_json(
                {"idempotency_key": key, "winner": winner}))
        conn.commit()  # 拒绝事件独立落库，随后的 409 不回滚它
        raise FanoutCandidateSuperseded(
            "接收端已被替换，迟到回执明确拒绝（不计入当前席位）",
            notification_id=nid, seat_id=sid, recipient_id=rid,
            candidate_state=cand["state"], end_reason=cand["end_reason"],
            winner=winner)

    def _seat_receipt_response_locked(self, conn: Any, nid: str, sid: str,
                                      rid: str, key: str, *,
                                      already_succeeded: bool
                                      ) -> dict[str, Any]:
        notif = self._get_notification_row(conn, nid)
        seat = self._get_seat_row(conn, nid, sid)
        cand = self._candidate_by_recipient(conn, nid, rid)
        seats = self._seat_rows(conn, nid)
        return {
            "notification_id": nid,
            "seat_id": sid,
            "recipient_id": rid,
            "candidate_seq": cand["seq"],
            "idempotency_key": key,
            "seat_state": seat["state"],
            "candidate_state": cand["state"],
            "attempts": cand["attempts"],
            "notification_status": notif["status"],
            "already_succeeded": already_succeeded,
            "progress": self._seat_progress(
                seats, notif["required_successes"]),
        }

    def _record_seat_failure_locked(self, conn: Any, nid: str, seat, cand,
                                    detail: Any) -> dict[str, Any]:
        """席位失败上报：只认当前候选；达到其上限即被替换并启用下一位。"""
        sid = seat["seat_id"]
        rid = cand["recipient_id"]
        if seat["state"] == SEAT_SUCCEEDED:
            raise FanoutSeatSucceeded(
                "席位已成功，不能再上报失败",
                notification_id=nid, seat_id=sid,
                winner=self._seat_winner_locked(conn, seat, cand))
        if seat["state"] == SEAT_EXHAUSTED:
            raise FanoutSeatExhausted(
                "席位候选已全部失败或被放弃，进入终止态",
                notification_id=nid, seat_id=sid,
                winner=self._seat_winner_locked(conn, seat, cand))
        if cand["state"] != CAND_ACTIVE:
            # 被替换候选的迟到失败上报：明确拒绝并记入历史
            winner = self._seat_winner_locked(conn, seat, cand)
            self._record_seat_event_locked(
                conn, nid, sid, "failure_rejected",
                candidate_seq=cand["seq"], recipient_id=rid,
                reason="candidate_superseded",
                detail=canonical_json({"winner": winner}))
            conn.commit()
            raise FanoutCandidateSuperseded(
                "接收端已被替换，迟到失败上报明确拒绝",
                notification_id=nid, seat_id=sid, recipient_id=rid,
                candidate_state=cand["state"], end_reason=cand["end_reason"],
                winner=winner)
        now = self._now()
        seq = cand["attempts"] + 1
        terminal = seq >= cand["max_attempts"]
        conn.execute(
            "INSERT INTO audit_fanout_attempts"
            " (notification_id, recipient_id, seq, result,"
            "  detail, idempotency_key, created_at_ms)"
            " VALUES (?,?,?,?,?,?,?)",
            (nid, rid, seq, RESULT_FAILURE, detail, None, now))
        conn.execute(
            "UPDATE audit_fanout_seat_candidates SET attempts=?,"
            " last_result=?, last_detail=? WHERE notification_id=?"
            " AND seat_id=? AND seq=?",
            (seq, RESULT_FAILURE, detail, nid, sid, cand["seq"]))
        self._record_seat_event_locked(
            conn, nid, sid, "failure_recorded",
            candidate_seq=cand["seq"], recipient_id=rid,
            detail=canonical_json({"attempts": seq, "detail": detail}))
        switched = None
        if terminal:
            # 该候选失败达到自己的上限：被替换，按顺序启用下一位备用
            switched = self._switch_locked(
                conn, seat, reason=REASON_FAILED, detail=detail)
            self._evaluate_locked(conn, nid)
        notif = self._get_notification_row(conn, nid)
        seat_now = self._get_seat_row(conn, nid, sid)
        cand_now = conn.execute(
            "SELECT * FROM audit_fanout_seat_candidates"
            " WHERE notification_id=? AND seat_id=? AND seq=?",
            (nid, sid, cand["seq"])).fetchone()
        seats = self._seat_rows(conn, nid)
        return {
            "notification_id": nid,
            "seat_id": sid,
            "recipient_id": rid,
            "candidate_seq": cand["seq"],
            "candidate_state": cand_now["state"],
            "seat_state": seat_now["state"],
            "attempts": cand_now["attempts"],
            "max_attempts": cand_now["max_attempts"],
            "terminal": terminal,
            "switched_to": switched["to"] if switched else None,
            "notification_status": notif["status"],
            "progress": self._seat_progress(
                seats, notif["required_successes"]),
        }

    # ----------------------------------------------------------------------
    # 手动切换（管理员放弃当前接收端；幂等键 + expected_recipient_id 防误切）
    # ----------------------------------------------------------------------
    def switch_seat(self, notification_id: str, seat_id: str, *,
                    reason: Any = None,
                    expected_recipient_id: Any = None,
                    idempotency_key: Any = None,
                    ) -> tuple[dict[str, Any], bool]:
        nid = self._require_str(notification_id, "notification_id")
        sid = self._require_str(seat_id, "seat_id")
        if reason is not None and not isinstance(reason, str):
            raise AuditBadRequest("reason 必须是字符串")
        expected = None
        if expected_recipient_id not in (None, ""):
            expected = self._require_str(expected_recipient_id,
                                         "expected_recipient_id")
        key = None
        if idempotency_key not in (None, ""):
            key = self._require_str(idempotency_key, "idempotency_key")
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            notif = self._get_notification_row(conn, nid)
            seat = self._get_seat_row(conn, nid, sid)
            # 超时优先结算：期限已到的候选先被系统替换，手动切换随后
            # 作用于结算后的当前候选（胜负由此确定）
            self._apply_due_switches_locked(conn, nid)
            notif = self._get_notification_row(conn, nid)
            seat = self._get_seat_row(conn, nid, sid)
            if key is not None:
                prev = conn.execute(
                    "SELECT * FROM audit_fanout_seat_commands"
                    " WHERE notification_id=? AND seat_id=?"
                    " AND idempotency_key=?",
                    (nid, sid, key)).fetchone()
                if prev is not None:
                    # 同一幂等键重复提交：只回放首次切换结果
                    return json.loads(prev["response_json"]), False
            if seat["state"] == SEAT_SUCCEEDED:
                # 席位已成功：成功回执赢了这次并发，切换请求落败
                raise FanoutSeatSucceeded(
                    "席位已成功，不能再启用备用接收端",
                    notification_id=nid, seat_id=sid,
                    winner={"type": "receipt",
                            "recipient_id": seat["succeeded_by"],
                            "seat_state": SEAT_SUCCEEDED,
                            "at_ms": seat["updated_at_ms"]})
            if seat["state"] == SEAT_EXHAUSTED:
                raise FanoutSeatExhausted(
                    "席位候选已全部失败或被放弃，进入终止态",
                    notification_id=nid, seat_id=sid,
                    winner={"type": "exhausted",
                            "seat_state": SEAT_EXHAUSTED,
                            "at_ms": seat["updated_at_ms"]})
            if notif["status"] != STATUS_PENDING:
                raise FanoutNotificationDecided(
                    "通知已有最终判定，不能再切换席位",
                    notification_id=nid,
                    notification_status=notif["status"],
                    decision=(json.loads(notif["decision_json"])
                              if notif["decision_json"] else None))
            current = conn.execute(
                "SELECT * FROM audit_fanout_seat_candidates"
                " WHERE notification_id=? AND seat_id=? AND state=?",
                (nid, sid, CAND_ACTIVE)).fetchone()
            if current is None:
                raise FanoutSeatExhausted(
                    "席位没有正在处理的接收端",
                    notification_id=nid, seat_id=sid)
            if expected is not None and current["recipient_id"] != expected:
                # 期望放弃的接收端已不是当前接收端：他人已先切换
                raise FanoutSeatSwitchConflict(
                    "当前接收端与 expected_recipient_id 不符："
                    "该席位已被他人先行切换",
                    notification_id=nid, seat_id=sid,
                    expected_recipient_id=expected,
                    current_candidate={
                        "seq": current["seq"],
                        "recipient_id": current["recipient_id"],
                        "deadline_at_ms": current["deadline_at_ms"],
                    })
            try:
                info = self._switch_locked(
                    conn, seat, reason=REASON_MANUAL, detail=reason)
                self._evaluate_locked(conn, nid)
                notif = self._get_notification_row(conn, nid)
                seat_now = self._get_seat_row(conn, nid, sid)
                seats = self._seat_rows(conn, nid)
                response = {
                    "notification_id": nid,
                    "seat_id": sid,
                    "switch": info,
                    "seat": self._seat_view(conn, seat_now),
                    "notification_status": notif["status"],
                    "progress": self._seat_progress(
                        seats, notif["required_successes"]),
                }
                if key is not None:
                    conn.execute(
                        "INSERT INTO audit_fanout_seat_commands"
                        " (notification_id, seat_id, idempotency_key,"
                        "  response_json, created_at_ms)"
                        " VALUES (?,?,?,?,?)",
                        (nid, sid, key, canonical_json(response),
                         self._now()))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            return response, True

    # ----------------------------------------------------------------------
    # 席位状态查询与完整历史
    # ----------------------------------------------------------------------
    def list_seats(self, notification_id: str) -> dict[str, Any]:
        nid = self._require_str(notification_id, "notification_id")
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            notif = self._get_notification_row(conn, nid)
            self._apply_due_switches_locked(conn, nid)
            notif = self._get_notification_row(conn, nid)
            seats = self._seat_rows(conn, nid)
            return {
                "notification_id": nid,
                "structure": notif["structure"],
                "notification_status": notif["status"],
                "seats": [self._seat_view(conn, s) for s in seats],
                "count": len(seats),
            }

    def get_seat(self, notification_id: str, seat_id: str) -> dict[str, Any]:
        nid = self._require_str(notification_id, "notification_id")
        sid = self._require_str(seat_id, "seat_id")
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            notif = self._get_notification_row(conn, nid)
            self._apply_due_switches_locked(conn, nid)
            notif = self._get_notification_row(conn, nid)
            seat = self._get_seat_row(conn, nid, sid)
            seats = self._seat_rows(conn, nid)
            return {
                "notification_id": nid,
                "notification_status": notif["status"],
                "seat": self._seat_view(conn, seat),
                "progress": self._seat_progress(
                    seats, notif["required_successes"]),
            }

    def seat_history(self, notification_id: str, seat_id: str, *,
                     limit: Any = 200) -> dict[str, Any]:
        nid = self._require_str(notification_id, "notification_id")
        sid = self._require_str(seat_id, "seat_id")
        limit = min(int(limit), 1000)
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            self._get_notification_row(conn, nid)
            self._apply_due_switches_locked(conn, nid)  # 历史含已到期切换
            self._get_seat_row(conn, nid, sid)
            rows = conn.execute(
                "SELECT * FROM audit_fanout_seat_events"
                " WHERE notification_id=? AND seat_id=?"
                " ORDER BY event_id LIMIT ?", (nid, sid, limit)).fetchall()
        events = []
        for r in rows:
            detail = r["detail"]
            if detail:
                try:
                    detail = json.loads(detail)
                except (TypeError, ValueError):
                    pass
            events.append({
                "event_id": r["event_id"],
                "event": r["event"],
                "candidate_seq": r["candidate_seq"],
                "recipient_id": r["recipient_id"],
                "reason": r["reason"],
                "detail": detail,
                "created_at_ms": r["created_at_ms"],
            })
        return {"notification_id": nid, "seat_id": sid,
                "events": events, "count": len(events)}
