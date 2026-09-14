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
    stable_seq   INTEGER NOT NULL DEFAULT 0    -- 稳定历史水位（最后一个不可变事件序号）
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
    status           TEXT NOT NULL,           -- queued / delivered / blocked
    created_at       REAL NOT NULL,
    PRIMARY KEY (sub_id, seq)
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
