"""SQLite 持久层。所有状态落库，服务重启后从这些表完整恢复。

关键并发约束：
- activations 上对 (sub_id) 的部分唯一索引（active=1）保证同一订阅同时只有
  一个生效版本；两个并发事务在 BEGIN IMMEDIATE 下只有一个能提交。
- notifications(sub_id, seq) 主键保证同一事件只有一条通知（重试不重复）。
- idempotency 表承载所有写操作的幂等键冲突。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS subscriptions (
    id           TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    scan_seq     INTEGER NOT NULL DEFAULT 0,   -- 已扫描到的最后一个序号（下一个为 scan_seq+1）
    stable_seq   INTEGER NOT NULL DEFAULT 0,   -- 稳定历史水位（最后一个不可变事件序号）
    next_queue_pos INTEGER NOT NULL DEFAULT 1  -- 接收端自己的单调排队位置（原通知与后续通知共享）
);

CREATE TABLE IF NOT EXISTS events (
    sub_id       TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    raw_payload  TEXT NOT NULL,
    ingested_at  REAL NOT NULL,
    PRIMARY KEY (sub_id, seq)
);

CREATE TABLE IF NOT EXISTS contracts (
    event_type   TEXT NOT NULL,
    version      TEXT NOT NULL,
    spec_json    TEXT NOT NULL,
    created_at   REAL NOT NULL,
    PRIMARY KEY (event_type, version)
);

CREATE TABLE IF NOT EXISTS activations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id       TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    version      TEXT NOT NULL,
    effective_seq INTEGER NOT NULL,
    active       INTEGER NOT NULL DEFAULT 1,
    revoked_at   REAL,
    revoke_seq   INTEGER,                 -- 撤销生效序号（撤销点之后不再治理）
    created_at   REAL NOT NULL,
    idem_key     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_activation
    ON activations(sub_id, event_type) WHERE active = 1;

CREATE TABLE IF NOT EXISTS dry_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id          TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    version         TEXT NOT NULL,
    spec_json       TEXT NOT NULL,
    from_seq        INTEGER NOT NULL,
    to_seq          INTEGER NOT NULL,
    status          TEXT NOT NULL,            -- running / passed / failed
    blocking_errors INTEGER NOT NULL DEFAULT 0,
    created_at      REAL NOT NULL,
    finished_at     REAL,
    idem_key        TEXT
);
CREATE TABLE IF NOT EXISTS dry_run_findings (
    dry_run_id  INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    severity    TEXT NOT NULL,                -- block / info
    path        TEXT NOT NULL,
    reason      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    sub_id           TEXT NOT NULL,
    seq              INTEGER NOT NULL,
    notification_id  TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    contract_version TEXT,
    frozen_payload   TEXT NOT NULL,
    digest           TEXT NOT NULL,
    validation       TEXT NOT NULL,           -- {valid, errors, infos}
    status           TEXT NOT NULL,           -- queued / sending / delivered / blocked / cancelled
    created_at       REAL NOT NULL,
    queue_position   INTEGER,                 -- 接收端单调排队位置（与后续通知共享一条队列）
    delivery_token   TEXT,                    -- 发送租约令牌：claim 发放，ack/nack 必须出示
    claimed_at       REAL,
    delivered_at     REAL,
    cancelled_at     REAL,
    superseded       INTEGER NOT NULL DEFAULT 0,  -- 原通知是否被更正原位替换（1=行内保留最新载荷，历史在 revisions）
    PRIMARY KEY (sub_id, seq)
);

-- 通知原位修订（只追加）：未发送更正"用同一排队位置替换"时，通知行原地更新
-- 为新载荷，但每一代载荷、契约版本、摘要与签名都在此留档，旧内容不丢失。
CREATE TABLE IF NOT EXISTS notification_revisions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id            TEXT NOT NULL,
    seq               INTEGER NOT NULL,
    notification_id   TEXT NOT NULL,          -- 始终是同一投递身份
    revision_no       INTEGER NOT NULL,       -- 1 = 首次冻结；每次原位更正 +1
    contract_version  TEXT,
    frozen_payload    TEXT NOT NULL,
    digest            TEXT NOT NULL,
    validation        TEXT NOT NULL,
    signature_json    TEXT,
    created_at        REAL NOT NULL,
    UNIQUE (sub_id, seq, revision_no)
);

-- 管理员处置请求（撤回/撤回原事件通知）。同一 (sub_id,seq) 同时至多一个
-- 未终结处置；终结后可再发起（链式处置），每次独立留档。
CREATE TABLE IF NOT EXISTS dispositions (
    id              TEXT PRIMARY KEY,         -- disp_<uuid>
    sub_id          TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    action          TEXT NOT NULL,            -- retract / correct
    reason          TEXT NOT NULL,
    event_type      TEXT,                     -- 非空时校验必须与原事件类型一致
    corrected_payload TEXT,                   -- 更正的新载荷（JSON）；撤回为 NULL
    actor           TEXT,
    status          TEXT NOT NULL,            -- pending / applied / failed
    idem_key        TEXT,
    fingerprint     TEXT,
    created_at      REAL NOT NULL,
    finished_at     REAL
);
CREATE INDEX IF NOT EXISTS ix_dispositions_event
    ON dispositions(sub_id, seq, created_at);

-- 处置在每个接收端上的独立结果（本实现中一个订阅即一个接收端；
-- 批量按接收端逐条独立落库，互不回滚）。
CREATE TABLE IF NOT EXISTS disposition_targets (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    disposition_id    TEXT NOT NULL,
    sub_id            TEXT NOT NULL,
    seq               INTEGER NOT NULL,
    state             TEXT NOT NULL,          -- pending / cancelled / replaced / followup_queued / failed
    outcome_action    TEXT NOT NULL,          -- retract / correct
    original_status   TEXT NOT NULL,          -- 决策时读到的原通知发送状态
    original_notification_id TEXT,
    result_notification_id TEXT,              -- 追加的后续通知 id（followup_queued）
    failure_stage     TEXT,                   -- validation / provenance / signing / precondition
    failure_reason    TEXT,
    fail_detail_json  TEXT,
    created_at        REAL NOT NULL,
    finished_at       REAL,
    UNIQUE (disposition_id, sub_id, seq)
);

-- 处置时间线（只追加）：原通知状态迁移、处置决策、后续通知入队全部在此，
-- 管理员按原事件可重建完整先后顺序。
CREATE TABLE IF NOT EXISTS disposition_timeline (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id        TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    at            REAL NOT NULL,
    event         TEXT NOT NULL,              -- 见下方事件名约定
    detail_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_disposition_timeline
    ON disposition_timeline(sub_id, seq, id);

-- 已送达/已确认后只能追加的后续通知（撤回通知或更正通知）。
-- 它们排在原通知之后、各自有独立投递身份与签名；原通知行绝不删除/改写。
CREATE TABLE IF NOT EXISTS disposition_notices (
    id                 TEXT PRIMARY KEY,      -- ntf_<uuid>（独立投递身份）
    sub_id             TEXT NOT NULL,
    seq                INTEGER NOT NULL,      -- 锚定的原事件序号
    disposition_id     TEXT NOT NULL,
    kind               TEXT NOT NULL,         -- retraction / correction
    event_type         TEXT NOT NULL,
    envelope_json      TEXT NOT NULL,         -- 待投递信封（含 relation 关联）
    payload_digest     TEXT NOT NULL,
    contract_version   TEXT,                  -- 更正：当前生效契约版本；撤回可为 NULL
    signature_json     TEXT NOT NULL,
    status             TEXT NOT NULL,         -- queued / sending / delivered
    queue_position     INTEGER NOT NULL,      -- 严格大于原通知的排队位置
    delivery_token     TEXT,
    claimed_at         REAL,
    delivered_at       REAL,
    created_at         REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_disposition_notices_queue
    ON disposition_notices(sub_id, queue_position);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid        TEXT PRIMARY KEY,
    key_no     INTEGER NOT NULL UNIQUE,
    secret     TEXT NOT NULL,                 -- 仅服务端持有，绝不外发
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    rotated_at REAL
);

CREATE TABLE IF NOT EXISTS quarantines (
    sub_id           TEXT NOT NULL,
    seq              INTEGER NOT NULL,
    notification_id  TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    expected_version TEXT,                    -- 隔离发生时的生效契约版本（重试基准）
    raw_digest       TEXT NOT NULL,
    errors_json      TEXT NOT NULL,
    status           TEXT NOT NULL,           -- blocked / recovered / dead
    created_at       REAL NOT NULL,
    recovered_at     REAL,
    retry_count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (sub_id, seq)
);

CREATE TABLE IF NOT EXISTS mappings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id       TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    seq          INTEGER,                     -- NULL = 订阅级通用映射
    op           TEXT NOT NULL,               -- rename / default / drop
    src_path     TEXT,
    dst_path     TEXT,
    value        TEXT,                        -- default 的固定值（JSON）
    contract_version TEXT NOT NULL,
    created_at   REAL NOT NULL,
    idem_key     TEXT
);

CREATE TABLE IF NOT EXISTS audit_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id      TEXT,                         -- NULL = 全局（契约登记等）
    at          REAL NOT NULL,
    category    TEXT NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency (
    scope       TEXT NOT NULL,
    idem_key    TEXT NOT NULL,
    response    TEXT NOT NULL,
    fingerprint TEXT,                          -- 首次请求的规范化内容指纹（不一致即冲突）
    at          REAL NOT NULL,
    PRIMARY KEY (scope, idem_key)
);

-- 每次投递尝试（首次冻结 + 每次失败/成功的重试）。只追加：
-- 重试绝不 UPDATE/删除历史尝试行；同一幂等键回放不产生新行。
CREATE TABLE IF NOT EXISTS delivery_attempts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id            TEXT NOT NULL,
    seq               INTEGER NOT NULL,
    notification_id   TEXT NOT NULL,           -- 投递身份：整个生命周期保持不变
    event_type        TEXT NOT NULL,
    attempt_no        INTEGER NOT NULL,        -- 1 = 首次冻结；之后严格 +1
    kind              TEXT NOT NULL,           -- initial_freeze / retry
    status            TEXT NOT NULL,           -- queued / blocked / retry_failed / recovered / ungoverned
    contract_version  TEXT,                    -- 该次尝试冻结时治理的契约版本
    payload_digest    TEXT NOT NULL,           -- 该次尝试输入载荷的规范化摘要（原始/派生计份）
    frozen_digest     TEXT,                    -- 最终冻结载荷摘要（失败尝试可能无冻结载荷）
    applied_json      TEXT NOT NULL,           -- 本次作用的映射规则摘要（无映射为 []）
    idem_key          TEXT,                    -- 触发本次尝试的幂等键（仅记录，不参与回放）
    created_at        REAL NOT NULL,
    UNIQUE (sub_id, seq, attempt_no)
);

-- 来源说明：每次尝试一份，写入后不可被任何后续契约/映射规则修改。
-- 只记录路径、类型、规则标识、内容摘要（sha256），绝不复制原始字段值。
CREATE TABLE IF NOT EXISTS provenance_explanations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id             TEXT NOT NULL,
    seq                INTEGER NOT NULL,
    attempt_no         INTEGER NOT NULL,
    notification_id    TEXT NOT NULL,          -- 绑定投递身份
    contract_version   TEXT,                   -- 绑定当时冻结的契约版本
    payload_digest     TEXT NOT NULL,          -- 绑定该次尝试的载荷摘要
    origin_event_digest TEXT NOT NULL,         -- 绑定原始审计事件摘要
    entries_json       TEXT NOT NULL,          -- 逐字段来源条目（路径/类型/规则/摘要）
    record_digest      TEXT NOT NULL,          -- 本行内容的规范化 sha256（防篡改自校验）
    prev_record_digest TEXT,                   -- 哈希链：上一尝试的 record_digest（attempt 1 为 NULL）
    created_at         REAL NOT NULL,
    UNIQUE (sub_id, seq, attempt_no)
);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()
        # 签名器与库同生命周期（密钥持久化在 signing_keys 表）
        from .signing import Signer
        self.signer = Signer(self.conn)
        self.conn.commit()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.conn.execute(
            "PRAGMA table_info(activations)").fetchall()}
        if "revoke_seq" not in cols:
            self.conn.execute(
                "ALTER TABLE activations ADD COLUMN revoke_seq INTEGER")
        idem_cols = {r["name"] for r in self.conn.execute(
            "PRAGMA table_info(idempotency)").fetchall()}
        if "fingerprint" not in idem_cols:
            self.conn.execute(
                "ALTER TABLE idempotency ADD COLUMN fingerprint TEXT")
        # 发送状态机 / 排队位置 / 处置锚定列（旧库迁移）
        notif_cols = {r["name"] for r in self.conn.execute(
            "PRAGMA table_info(notifications)").fetchall()}
        for name, decl in (
                ("queue_position", "INTEGER"),
                ("delivery_token", "TEXT"),
                ("claimed_at", "REAL"),
                ("delivered_at", "REAL"),
                ("cancelled_at", "REAL"),
                ("superseded", "INTEGER NOT NULL DEFAULT 0")):
            if name not in notif_cols:
                self.conn.execute(
                    f"ALTER TABLE notifications ADD COLUMN {name} {decl}")
        sub_cols = {r["name"] for r in self.conn.execute(
            "PRAGMA table_info(subscriptions)").fetchall()}
        if "next_queue_pos" not in sub_cols:
            self.conn.execute(
                "ALTER TABLE subscriptions ADD COLUMN "
                "next_queue_pos INTEGER NOT NULL DEFAULT 1")
        # 排队位置回填：旧库已冻结的原通知按 (sub, seq) 顺序占住 1..N，
        # 保证重启恢复后后续通知的位置严格在原通知之后。
        for r in self.conn.execute(
                "SELECT id FROM subscriptions ORDER BY id").fetchall():
            sub_id = r["id"]
            missing = self.conn.execute(
                "SELECT COUNT(*) c FROM notifications "
                "WHERE sub_id=? AND queue_position IS NULL", (sub_id,)).fetchone()
            if missing["c"]:
                pos = 1
                for n in self.conn.execute(
                        "SELECT seq FROM notifications WHERE sub_id=? "
                        "ORDER BY seq", (sub_id,)).fetchall():
                    self.conn.execute(
                        "UPDATE notifications SET queue_position=? "
                        "WHERE sub_id=? AND seq=? AND queue_position IS NULL",
                        (pos, sub_id, n["seq"]))
                    pos += 1
                self.conn.execute(
                    "UPDATE subscriptions SET next_queue_pos=? WHERE id=?",
                    (pos, sub_id))
        # 计数器必须严格大于已分配的最大位置（原通知与后续通知一并考虑），
        # 否则回填/旧库恢复后新入队的通知会撞号、破坏先后顺序
        for r in self.conn.execute(
                "SELECT s.id AS sid, COALESCE(MAX(q.pos), 0) AS max_pos "
                "FROM subscriptions s LEFT JOIN ("
                "  SELECT sub_id, queue_position AS pos FROM notifications "
                "  UNION ALL SELECT sub_id, queue_position FROM disposition_notices"
                ") q ON q.sub_id = s.id GROUP BY s.id").fetchall():
            self.conn.execute(
                "UPDATE subscriptions SET next_queue_pos=? "
                "WHERE id=? AND next_queue_pos<=?",
                (r["max_pos"] + 1, r["sid"], r["max_pos"]))

    # -- 基础工具 ----------------------------------------------------------- #
    def begin(self) -> sqlite3.Connection:
        """开启串行写事务。SQLite 的锁在事务结束前保持。"""
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # -- 幂等缓存 ----------------------------------------------------------- #
    def idem_get(self, scope: str, key: str) -> Optional[Any]:
        row = self.query_one(
            "SELECT response, fingerprint FROM idempotency "
            "WHERE scope=? AND idem_key=?",
            (scope, key),
        )
        if not row:
            return None
        # 信封键用下划线前缀，避免与响应体自身字段碰撞
        return {"_response": json.loads(row["response"]),
                "_fingerprint": row["fingerprint"]}

    def idem_put(self, scope: str, key: str, response: Any,
                 fingerprint: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO idempotency(scope, idem_key, response, "
            "fingerprint, at) VALUES (?,?,?,?,strftime('%s','now'))",
            (scope, key, json.dumps(response, ensure_ascii=False), fingerprint),
        )

    def close(self) -> None:
        with self._lock:
            self.conn.close()
