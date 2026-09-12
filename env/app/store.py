"""SQLite 持久化层：租约、世代号、资源、写入审计、系统元数据。

所有会改变状态的操作都在一把进程内互斥锁 + 单连接事务中完成，
SQLite 开 WAL，保证重启后正在生效的租约和世代号都不丢。

租约过期判定（双时钟，两个条件同时满足才算活）：

1. wall_ms < hard_wall_deadline_ms
   —— 硬墙钟上限。发放后固定，续约不能越过。
      即使逻辑钟彻底卡死（永远不 tick），租约到时也必死，
      不会出现"租约永不结束"。

2. wall_ms < wall_deadline_ms 或 逻辑钟宽限仍有效
   —— 软墙钟 TTL。墙钟被拨快只会越过软 deadline；
      只要逻辑钟在 (logical_grace + 续约时刻的逻辑钟) 之内
      仍在推进，就证明持有者还在干活，不能误回收。
      逻辑钟宽限是否有效 = 当前逻辑钟 <= last_seen_logical + grace。
"""

from __future__ import annotations

import threading
import uuid
from typing import Any

from .clock import Clock

STATE_ACTIVE = "active"
STATE_EXPIRED = "expired"
STATE_RELEASED = "released"
STATE_TRANSFERRED = "transferred"   # 已转移：旧持有者即刻失去一切权限

# 过期原因（state=expired 时）
REASON_HARD_WALL = "hard_wall_deadline_reached"       # 逻辑钟卡死也救不了：到硬上限
REASON_SOFT_WALL_AND_LOGICAL_STALL = "wall_ttl_passed_and_logical_stalled"  # 双重沉默

MIN_TTL_MS = 50                 # 客户端可请求的最小 TTL，避免 0 导致立即死
DEFAULT_TTL_MS = 15_000
DEFAULT_MAX_TTL_MS = 60_000
DEFAULT_HARD_TTL_MS = 60_000    # 硬上限相对发放时刻；必须大于环境中最大时钟跳变
DEFAULT_LOGICAL_GRACE = 3       # 续约后逻辑钟最多容忍落后多少 tick


class Conflict(Exception):
    """世代号栅栏冲突或状态前提不满足（映射为 HTTP 409/412）。"""


class LeaseGone(Conflict):
    """资源上不存在可操作的生效租约（HTTP 412）。"""


class GenerationTooSmall(Conflict):
    """写入携带的世代号 <= 资源已放行的最大世代号（HTTP 409）。"""


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    id                     TEXT PRIMARY KEY,
    resource               TEXT NOT NULL,
    holder                 TEXT NOT NULL,
    generation             INTEGER NOT NULL,
    granted_wall_ms        INTEGER NOT NULL,
    wall_deadline_ms       INTEGER NOT NULL,
    hard_wall_deadline_ms  INTEGER NOT NULL,
    logical_grace          INTEGER NOT NULL,
    last_seen_logical      INTEGER NOT NULL,
    renewed_count          INTEGER NOT NULL DEFAULT 0,
    state                  TEXT NOT NULL DEFAULT 'active',
    expire_reason          TEXT,
    created_at_ms          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resources (
    resource        TEXT PRIMARY KEY,
    current_gen     INTEGER NOT NULL,           -- 单调递增，世代号源头
    last_passed_gen INTEGER NOT NULL DEFAULT 0, -- 已放行写入的最大世代号（栅栏）
    value           TEXT,
    updated_by_gen  INTEGER,
    updated_at_ms   INTEGER
);
CREATE TABLE IF NOT EXISTS writes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    resource           TEXT NOT NULL,
    generation         INTEGER NOT NULL,        -- 是哪一代租约放行的
    lease_id           TEXT NOT NULL,
    holder             TEXT NOT NULL,
    accepted           INTEGER NOT NULL,        -- 1 放行 / 0 拒绝
    reject_reason      TEXT,
    created_at_ms      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_writes_resource ON writes(resource, id);
-- 转移记录：transfer_id 是幂等键，重复提交同一笔转移直接回放首次结果
CREATE TABLE IF NOT EXISTS transfers (
    transfer_id     TEXT PRIMARY KEY,
    resource        TEXT NOT NULL,
    from_holder     TEXT NOT NULL,
    to_holder       TEXT NOT NULL,
    from_lease_id   TEXT NOT NULL,
    from_generation INTEGER NOT NULL,
    new_lease_id    TEXT NOT NULL,
    new_generation  INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL
);
-- 统一租约历史：每次获取/续约/释放/转移/写入（含被拒绝的）都留一条，
-- seq 全局单调递增即审计顺序，落库后重启不丢。
-- lease_id 记录操作发生时生效的租约（被拒绝的操作也一样），
-- 仅当当时没有生效租约时才为 NULL；generation 是请求携带的世代号。
CREATE TABLE IF NOT EXISTS lease_events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    resource      TEXT NOT NULL,
    event         TEXT NOT NULL,        -- acquire/renew/release/transfer/write
    outcome       TEXT NOT NULL,        -- ok / rejected
    holder        TEXT NOT NULL,        -- 操作发起者
    peer          TEXT,                 -- 另一方：transfer 的接收者 / acquire 冲突时的持有者
    lease_id      TEXT,
    generation    INTEGER,
    to_lease_id   TEXT,                 -- 仅 transfer：产生的新租约
    to_generation INTEGER,
    detail        TEXT,                 -- 拒绝原因 / write_id 等补充
    wall_ms       INTEGER NOT NULL,
    logical       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_resource ON lease_events(resource, seq);
"""


class Store:
    def __init__(
        self,
        db_path: str,
        *,
        ttl_ms: int = DEFAULT_TTL_MS,
        max_ttl_ms: int = DEFAULT_MAX_TTL_MS,
        hard_ttl_ms: int = DEFAULT_HARD_TTL_MS,
        logical_grace: int = DEFAULT_LOGICAL_GRACE,
    ):
        self._lock = threading.RLock()
        # check_same_thread=False + 全局互斥锁保证多线程访问安全
        import sqlite3

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

        self.default_ttl_ms = ttl_ms
        self.max_ttl_ms = max_ttl_ms
        self.hard_ttl_ms = hard_ttl_ms
        self.logical_grace = logical_grace

        self.clock = Clock(lambda: self._get_meta("wall_offset_ms", 0))
        self.clock.set_logical(self._get_meta("logical_clock", 0))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- 元数据 ---------------------------------------------------------
    def _get_meta(self, key: str, default: int = 0) -> int:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def _set_meta(self, key: str, value: int) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---- 统一历史：与状态变更同事务写入，调用方负责 commit --------------
    def _record_event_locked(
        self,
        resource: str,
        event: str,
        outcome: str,
        holder: str,
        *,
        peer: str | None = None,
        lease_id: str | None = None,
        generation: int | None = None,
        to_lease_id: str | None = None,
        to_generation: int | None = None,
        detail: str | None = None,
        now: int | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO lease_events(resource, event, outcome, holder, peer, "
            "lease_id, generation, to_lease_id, to_generation, detail, "
            "wall_ms, logical) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                resource, event, outcome, holder, peer, lease_id, generation,
                to_lease_id, to_generation, detail,
                now if now is not None else self.clock.wall_ms(),
                self.clock.logical(),
            ),
        )

    # ---- 逻辑钟推进（后台 ticker / 测试接口调用） -----------------------
    def tick(self, steps: int = 1) -> int:
        with self._lock:
            value = self.clock.advance_logical(steps)
            self._set_meta("logical_clock", value)
            self._conn.commit()
            self._reap_locked()
            return value

    # ---- 调试用：拨墙钟（不持久化偏移就无法在重启后复现故障） ----------
    def shift_wall(self, delta_ms: int) -> int:
        with self._lock:
            offset = self._get_meta("wall_offset_ms", 0) + int(delta_ms)
            self._set_meta("wall_offset_ms", offset)
            self._conn.commit()
            self._reap_locked()
            return self.clock.wall_ms()

    # ---- 过期判定 -------------------------------------------------------
    def _classify_locked(self, lease) -> dict[str, Any]:
        """返回 {state, expire_reason}。纯函数式读取，不写库。"""
        wall = self.clock.wall_ms()
        logical = self.clock.logical()
        if lease["state"] != STATE_ACTIVE:
            return {"state": lease["state"], "expire_reason": lease["expire_reason"]}

        if wall >= lease["hard_wall_deadline_ms"]:
            # 硬上限：逻辑钟再怎么跳也没用，保证租约必然结束
            return {"state": STATE_EXPIRED, "expire_reason": REASON_HARD_WALL}

        soft_ok = wall < lease["wall_deadline_ms"]
        logical_ok = logical <= lease["last_seen_logical"] + lease["logical_grace"]
        if not soft_ok and not logical_ok:
            # 墙钟说过期、逻辑钟也沉默：双时钟一致，才能回收
            return {
                "state": STATE_EXPIRED,
                "expire_reason": REASON_SOFT_WALL_AND_LOGICAL_STALL,
            }
        return {"state": STATE_ACTIVE, "expire_reason": None}

    def _get_active_locked(self, resource: str, for_update: bool = True):
        row = self._conn.execute(
            "SELECT * FROM leases WHERE resource=? AND state='active' "
            "ORDER BY generation DESC LIMIT 1",
            (resource,),
        ).fetchone()
        if row is None:
            return None
        status = self._classify_locked(row)
        if status["state"] != STATE_ACTIVE:
            self._expire_locked(row, status["expire_reason"])
            return None
        return row

    def _expire_locked(self, row, reason: str) -> None:
        self._conn.execute(
            "UPDATE leases SET state=?, expire_reason=? WHERE id=?",
            (STATE_EXPIRED, reason, row["id"]),
        )
        self._conn.commit()

    def _reap_locked(self) -> int:
        """扫描所有 active 租约，按双时钟规则收尾，返回收割数量。"""
        rows = self._conn.execute(
            "SELECT * FROM leases WHERE state='active'"
        ).fetchall()
        n = 0
        for row in rows:
            status = self._classify_locked(row)
            if status["state"] != STATE_ACTIVE:
                self._expire_locked(row, status["expire_reason"])
                n += 1
        if n:
            self._conn.commit()
        return n

    # ---- 获取租约 -------------------------------------------------------
    def acquire(
        self, resource: str, holder: str, ttl_ms: int | None
    ) -> tuple[dict[str, Any], bool]:
        """成功返回 (lease视图, True)；同一持有者复用当前租约返回 (视图, False)。"""
        with self._lock:
            self._reap_locked()
            existing = self._conn.execute(
                "SELECT * FROM leases WHERE resource=? AND state='active' "
                "ORDER BY generation DESC LIMIT 1",
                (resource,),
            ).fetchone()
            if existing is not None:
                if existing["holder"] == holder:
                    self._record_event_locked(
                        resource, "acquire", "ok", holder,
                        lease_id=existing["id"],
                        generation=existing["generation"],
                        detail="reused_existing",
                    )
                    self._conn.commit()
                    return self._lease_view_locked(existing), False
                self._record_event_locked(
                    resource, "acquire", "rejected", holder,
                    peer=existing["holder"], lease_id=existing["id"],
                    generation=existing["generation"],
                    detail="resource_held_by_other",
                )
                self._conn.commit()
                raise Conflict(f"资源 {resource} 已被 {existing['holder']} 持有")

            ttl = self._clamp_ttl(ttl_ms)
            now = self.clock.wall_ms()
            gen = self._next_generation_locked(resource)
            lease_id = str(uuid.uuid4())
            logical = self.clock.logical()
            self._conn.execute(
                "INSERT INTO leases(id, resource, holder, generation, "
                "granted_wall_ms, wall_deadline_ms, hard_wall_deadline_ms, "
                "logical_grace, last_seen_logical, created_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    lease_id, resource, holder, gen, now, now + ttl,
                    now + self.hard_ttl_ms, self.logical_grace, logical, now,
                ),
            )
            self._record_event_locked(
                resource, "acquire", "ok", holder,
                lease_id=lease_id, generation=gen, now=now,
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM leases WHERE id=?", (lease_id,)
            ).fetchone()
            return self._lease_view_locked(row), True

    def _clamp_ttl(self, ttl_ms: int | None) -> int:
        ttl = int(ttl_ms) if ttl_ms is not None else self.default_ttl_ms
        return max(MIN_TTL_MS, min(ttl, self.max_ttl_ms))

    def _next_generation_locked(self, resource: str) -> int:
        self._conn.execute(
            "INSERT INTO resources(resource, current_gen) VALUES(?, 1) "
            "ON CONFLICT(resource) DO UPDATE SET "
            "current_gen = resources.current_gen + 1",
            (resource,),
        )
        row = self._conn.execute(
            "SELECT current_gen FROM resources WHERE resource=?", (resource,)
        ).fetchone()
        return row["current_gen"]

    # ---- 续约 -----------------------------------------------------------
    def renew(self, resource: str, holder: str, generation: int) -> dict[str, Any]:
        with self._lock:
            self._reap_locked()
            row = self._get_active_locked(resource)
            if row is None:
                self._record_event_locked(
                    resource, "renew", "rejected", holder,
                    generation=generation, detail="no_active_lease",
                )
                self._conn.commit()
                raise LeaseGone(f"资源 {resource} 没有生效中的租约，续约被拒绝；"
                                "请重新获取并取得更大的世代号")
            if row["holder"] != holder or row["generation"] != generation:
                self._record_event_locked(
                    resource, "renew", "rejected", holder,
                    lease_id=row["id"], generation=generation,
                    detail="holder_or_generation_mismatch",
                )
                self._conn.commit()
                raise Conflict("持有者或世代号与当前生效租约不符")

            now = self.clock.wall_ms()
            # 软 deadline 顺延，但永远不能越过发放时定死的硬墙钟上限
            new_soft = min(
                now + self.default_ttl_ms, row["hard_wall_deadline_ms"] - 1
            )
            self._conn.execute(
                "UPDATE leases SET wall_deadline_ms=?, last_seen_logical=?, "
                "renewed_count=renewed_count+1 WHERE id=?",
                (new_soft, self.clock.logical(), row["id"]),
            )
            self._record_event_locked(
                resource, "renew", "ok", holder,
                lease_id=row["id"], generation=generation, now=now,
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM leases WHERE id=?", (row["id"],)
            ).fetchone()
            return self._lease_view_locked(row)

    # ---- 释放 -----------------------------------------------------------
    def release(self, resource: str, holder: str, generation: int) -> None:
        with self._lock:
            self._reap_locked()
            row = self._get_active_locked(resource)
            if row is None:
                self._record_event_locked(
                    resource, "release", "rejected", holder,
                    generation=generation, detail="no_active_lease",
                )
                self._conn.commit()
                raise LeaseGone(f"资源 {resource} 没有生效中的租约")
            if row["holder"] != holder or row["generation"] != generation:
                self._record_event_locked(
                    resource, "release", "rejected", holder,
                    lease_id=row["id"], generation=generation,
                    detail="holder_or_generation_mismatch",
                )
                self._conn.commit()
                raise Conflict("持有者或世代号与当前生效租约不符")
            self._conn.execute(
                "UPDATE leases SET state=? WHERE id=?",
                (STATE_RELEASED, row["id"]),
            )
            self._record_event_locked(
                resource, "release", "ok", holder,
                lease_id=row["id"], generation=generation,
            )
            self._conn.commit()

    # ---- 安全转移 -------------------------------------------------------
    def transfer(
        self,
        resource: str,
        holder: str,
        generation: int,
        to_holder,
        transfer_id=None,
        ttl_ms: int | None = None,
    ) -> dict[str, Any]:
        """把生效中的租约原子地转给 to_holder。

        单事务内完成：旧租约置为 transferred（旧持有者即刻失去写权限）、
        资源世代号 +1、以更大世代号发放新租约（新持有者即刻可写）、
        落转移记录与历史事件。崩溃只会整体回滚，不留半完成状态。

        transfer_id 是幂等键：同一笔转移重复提交直接回放首次结果，
        不会再次转移；同一 transfer_id 配不同参数则拒绝。
        """
        with self._lock:
            self._reap_locked()
            now = self.clock.wall_ms()
            if transfer_id is not None:
                transfer_id = str(transfer_id)

            # 当时的生效租约（无则 None）：无论转移成败，历史事件都要能
            # 关联到它；下面的凭证校验也复用这一行，不再重复查询
            row = self._get_active_locked(resource)
            active_lease_id = row["id"] if row else None

            # 1) 幂等键先行：已执行过的转移，参数一致 -> 回放首次结果
            if transfer_id:
                prev = self._conn.execute(
                    "SELECT * FROM transfers WHERE transfer_id=?",
                    (transfer_id,),
                ).fetchone()
                if prev is not None:
                    same = (
                        prev["resource"] == resource
                        and prev["from_holder"] == holder
                        and prev["from_generation"] == generation
                        and prev["to_holder"] == to_holder
                    )
                    if not same:
                        self._record_event_locked(
                            resource, "transfer", "rejected", holder,
                            peer=to_holder if isinstance(to_holder, str)
                            else None,
                            lease_id=active_lease_id,
                            generation=generation,
                            detail="transfer_id_conflict", now=now,
                        )
                        self._conn.commit()
                        raise Conflict(
                            f"transfer_id {transfer_id} 已被一笔参数不同的"
                            "转移占用，本次请求被拒绝"
                        )
                    lease_row = self._conn.execute(
                        "SELECT * FROM leases WHERE id=?",
                        (prev["new_lease_id"],),
                    ).fetchone()
                    return self._transfer_view_locked(prev, lease_row,
                                                      replayed=True)

            # 2) 接收者资格：非空字符串、不能转给当前持有者自己
            if not isinstance(to_holder, str) or not to_holder.strip():
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    lease_id=active_lease_id,
                    generation=generation, detail="ineligible_recipient",
                    now=now,
                )
                self._conn.commit()
                raise Conflict("接收者不符合条件：to_holder 必须是非空字符串")
            if to_holder == holder:
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    peer=to_holder, lease_id=active_lease_id,
                    generation=generation,
                    detail="ineligible_recipient:self", now=now,
                )
                self._conn.commit()
                raise Conflict("接收者不符合条件：不能转移给当前持有者自己")

            # 3) 旧凭证校验：必须是当前生效租约的持有者与世代号
            if row is None:
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    peer=to_holder, generation=generation,
                    detail="no_active_lease", now=now,
                )
                self._conn.commit()
                raise LeaseGone(f"资源 {resource} 没有生效中的租约，转移被拒绝")
            if row["holder"] != holder or row["generation"] != generation:
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    peer=to_holder, lease_id=row["id"], generation=generation,
                    detail="holder_or_generation_mismatch", now=now,
                )
                self._conn.commit()
                raise Conflict("持有者或世代号与当前生效租约不符，转移被拒绝")

            # 4) 原子交接：以下全部写操作一次 commit，要么全成要么全不成
            transfer_id = transfer_id or str(uuid.uuid4())
            new_gen = self._next_generation_locked(resource)
            new_lease_id = str(uuid.uuid4())
            ttl = self._clamp_ttl(ttl_ms)
            logical = self.clock.logical()
            self._conn.execute(
                "UPDATE leases SET state=? WHERE id=?",
                (STATE_TRANSFERRED, row["id"]),
            )
            self._conn.execute(
                "INSERT INTO leases(id, resource, holder, generation, "
                "granted_wall_ms, wall_deadline_ms, hard_wall_deadline_ms, "
                "logical_grace, last_seen_logical, created_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    new_lease_id, resource, to_holder, new_gen, now,
                    now + ttl, now + self.hard_ttl_ms, self.logical_grace,
                    logical, now,
                ),
            )
            self._conn.execute(
                "INSERT INTO transfers(transfer_id, resource, from_holder, "
                "to_holder, from_lease_id, from_generation, new_lease_id, "
                "new_generation, created_at_ms) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    transfer_id, resource, holder, to_holder, row["id"],
                    row["generation"], new_lease_id, new_gen, now,
                ),
            )
            self._record_event_locked(
                resource, "transfer", "ok", holder,
                peer=to_holder, lease_id=row["id"],
                generation=row["generation"], to_lease_id=new_lease_id,
                to_generation=new_gen, now=now,
            )
            self._conn.commit()
            transfer_row = self._conn.execute(
                "SELECT * FROM transfers WHERE transfer_id=?", (transfer_id,)
            ).fetchone()
            lease_row = self._conn.execute(
                "SELECT * FROM leases WHERE id=?", (new_lease_id,)
            ).fetchone()
            return self._transfer_view_locked(transfer_row, lease_row,
                                              replayed=False)

    def _transfer_view_locked(self, t, lease_row, *, replayed: bool):
        lease_view = None
        if lease_row is not None:
            status = self._classify_locked(lease_row)
            lease_view = self._lease_view_locked(lease_row,
                                                 state=status["state"])
            if status["state"] != STATE_ACTIVE:
                lease_view["expire_reason"] = status["expire_reason"]
        return {
            "transfer_id": t["transfer_id"],
            "resource": t["resource"],
            "replayed": replayed,
            "from": {
                "holder": t["from_holder"],
                "lease_id": t["from_lease_id"],
                "generation": t["from_generation"],
            },
            "to": {
                "holder": t["to_holder"],
                "lease_id": t["new_lease_id"],
                "generation": t["new_generation"],
            },
            "lease": lease_view,
            "created_at_ms": t["created_at_ms"],
        }

    # ---- 受租约保护的写入（栅栏点） -------------------------------------
    def write(
        self, resource: str, holder: str, generation: int, value: str
    ) -> dict[str, Any]:
        with self._lock:
            self._reap_locked()
            row = self._get_active_locked(resource)
            now = self.clock.wall_ms()

            def record(accepted: bool, reason: str | None) -> dict[str, Any]:
                cur = self._conn.execute(
                    "INSERT INTO writes(resource, generation, lease_id, "
                    "holder, accepted, reject_reason, created_at_ms) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        resource, generation, row["id"] if row else "",
                        holder, 1 if accepted else 0, reason, now,
                    ),
                )
                self._record_event_locked(
                    resource, "write", "ok" if accepted else "rejected",
                    holder, lease_id=row["id"] if row else None,
                    generation=generation,
                    detail=f"write_id={cur.lastrowid}" if accepted else reason,
                    now=now,
                )
                self._conn.commit()
                return {
                    "write_id": cur.lastrowid, "resource": resource,
                    "holder": holder, "generation": generation,
                    "accepted": accepted, "reject_reason": reason,
                }

            if row is None:
                record(False, "no_active_lease")
                raise LeaseGone(f"资源 {resource} 没有生效中的租约")
            if row["holder"] != holder or row["generation"] != generation:
                record(False, "generation_fence")
                raise GenerationTooSmall(
                    f"世代号 {generation} 不是资源 {resource} 的当前世代 "
                    f"{row['generation']}（持有者 {row['holder']}），写入被拒绝"
                )

            res = self._conn.execute(
                "SELECT * FROM resources WHERE resource=?", (resource,)
            ).fetchone()
            # 栅栏不变量：当前世代号不落后于已放行号。
            # 同一租约可重复写入（generation == last_passed_gen 属正常），
            # 只有更旧的世代号才越界——而上面的生效租约校验已排除这种情况。
            assert generation >= res["last_passed_gen"]
            self._conn.execute(
                "UPDATE resources SET value=?, updated_by_gen=?, updated_at_ms=?, "
                "last_passed_gen=? WHERE resource=?",
                (value, generation, now, generation, resource),
            )
            out = record(True, None)
            out["value"] = value
            return out

    # ---- 查询 -----------------------------------------------------------
    def get_lease(self, resource: str) -> dict[str, Any] | None:
        with self._lock:
            self._reap_locked()
            row = self._conn.execute(
                "SELECT * FROM leases WHERE resource=? "
                "ORDER BY generation DESC LIMIT 1", (resource,),
            ).fetchone()
            if row is None:
                return None
            status = self._classify_locked(row)
            if status["state"] == STATE_ACTIVE:
                return self._lease_view_locked(row)
            return {
                "resource": resource,
                "state": status["state"],
                "expire_reason": status["expire_reason"],
            }

    def get_resource(self, resource: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM resources WHERE resource=?", (resource,)
            ).fetchone()
            if row is None:
                return None
            return {
                "resource": resource,
                "current_generation": row["current_gen"],
                "last_passed_generation": row["last_passed_gen"],
                "value": row["value"],
                "updated_by_generation": row["updated_by_gen"],
                "updated_at_ms": row["updated_at_ms"],
            }

    def list_writes(self, resource: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM writes WHERE resource=? ORDER BY id DESC LIMIT ?",
                (resource, int(limit)),
            ).fetchall()
            return [
                {
                    "write_id": r["id"], "resource": r["resource"],
                    "generation": r["generation"], "lease_id": r["lease_id"],
                    "holder": r["holder"], "accepted": bool(r["accepted"]),
                    "reject_reason": r["reject_reason"],
                    "created_at_ms": r["created_at_ms"],
                }
                for r in rows
            ]

    def get_write(self, write_id: int) -> dict[str, Any] | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM writes WHERE id=?", (int(write_id),)
            ).fetchone()
            if r is None:
                return None
            return {
                "write_id": r["id"], "resource": r["resource"],
                "generation": r["generation"], "lease_id": r["lease_id"],
                "holder": r["holder"], "accepted": bool(r["accepted"]),
                "reject_reason": r["reject_reason"],
                "created_at_ms": r["created_at_ms"],
            }

    def list_history(self, resource: str, limit: int = 200) -> list[dict[str, Any]]:
        """按资源返回统一租约历史，按审计顺序（seq）从旧到新排列。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM lease_events WHERE resource=? "
                "ORDER BY seq DESC LIMIT ?",
                (resource, int(limit)),
            ).fetchall()
            return [
                {
                    "seq": r["seq"], "resource": r["resource"],
                    "event": r["event"], "outcome": r["outcome"],
                    "holder": r["holder"], "peer": r["peer"],
                    "lease_id": r["lease_id"], "generation": r["generation"],
                    "to_lease_id": r["to_lease_id"],
                    "to_generation": r["to_generation"],
                    "detail": r["detail"],
                    "wall_ms": r["wall_ms"], "logical": r["logical"],
                }
                for r in reversed(rows)
            ]

    def _lease_view_locked(self, row, state: str = STATE_ACTIVE) -> dict[str, Any]:
        logical = self.clock.logical()
        return {
            "resource": row["resource"],
            "lease_id": row["id"],
            "holder": row["holder"],
            "generation": row["generation"],
            "state": state,
            "granted_wall_ms": row["granted_wall_ms"],
            "wall_deadline_ms": row["wall_deadline_ms"],
            "hard_wall_deadline_ms": row["hard_wall_deadline_ms"],
            "last_seen_logical": row["last_seen_logical"],
            "current_logical": logical,
            "logical_grace": row["logical_grace"],
            "logical_stall_after": row["last_seen_logical"] + row["logical_grace"],
            "renewed_count": row["renewed_count"],
        }
