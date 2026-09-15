"""批次通知接收端额度策略与事件优先级排队（quota & priority queue）。

在窗口批次封存生成通知（事务发件箱）之后，本模块把每条通知按冻结接收端
列表拆成**每接收端一个发送任务**进入优先级队列，由发送方通过 HTTP 接口
主动领取执行：

核心不变量
==========
1. **排队身份稳定**：每个任务在接收端维度分配单调递增的 ``queue_seq``
   （``UNIQUE(recipient_id, queue_seq)`` 兜底）。发送失败回到 pending
   不改变 ``queue_seq``、不换新任务——重试保持原排队身份。
2. **发送失败不扣额度**：只有发送成功（complete）才在
   ``audit_batch_quota_usage`` 落一条消耗记录；发送失败（fail）只增加
   尝试次数、释放认领，额度分毫不动。领取时额度按
   ``窗口内成功数 + 未过期认领数`` 预留，防止并发超额领取。
3. **策略版本化、只重排未发送任务**：接收端额度策略与事件优先级均按
   对象版本化（每次配置产生递增版本）。优先级新版本生效时只重排
   ``pending`` 任务的冻结优先级；已认领（正在发送）与已发送任务永远
   保持入队时的冻结值。额度新版本只影响之后的领取判定。
4. **并发领取唯一、租约过期可接管**：认领是带唯一 ``claim_token`` 的
   条件 UPDATE，并发领取同一任务只有一个成功；认领带租约
   （``claim_expires_at_ms``），租约过期后其他领取者可接管该任务，
   旧令牌即刻失效（迟到完成/失败上报一律 409）。
5. **只写自有表**：只写 ``audit_batch_quota_policies`` /
   ``audit_batch_priorities`` / ``audit_batch_send_tasks`` /
   ``audit_batch_quota_usage`` 四张表，绝不修改租约、委托、审计历史、
   归档、证据包、因果索引、发布计划、订阅、多端投递的任何表；批次与
   通知表只读。
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from .audit import AuditError

# ---------------------------------------------------------------------------
# 错误（映射为明确的 HTTP 状态码）
# ---------------------------------------------------------------------------


class BatchQueueError(AuditError):
    code = "batch_queue_error"
    status = 400


class BatchQueueNotFound(BatchQueueError):
    """发送任务 / 额度策略 / 优先级策略 / 接收端队列不存在（404）。"""

    code = "batch_queue_not_found"
    status = 404


class BatchQueueConflict(BatchQueueError):
    """幂等规格冲突、认领令牌冲突（任务已被接管/完成）（409）。"""

    code = "batch_queue_conflict"
    status = 409


class BatchQueueBadState(BatchQueueError):
    """状态前提不满足（任务未被认领就完成/上报失败等，409）。"""

    code = "batch_queue_bad_state"
    status = 409


DEFAULT_CLAIM_LEASE_MS = 60_000
MAX_CLAIM_TASKS = 100


def _gid() -> str:
    return uuid.uuid4().hex


class BatchQueueManager:
    def __init__(self, store: Any, *,
                 claim_lease_ms: int = DEFAULT_CLAIM_LEASE_MS):
        self._store = store
        self._claim_lease_ms = int(claim_lease_ms)

    # ---- 连接/锁/时钟（与其他模块共用同一连接与进程锁） ------------------
    @property
    def _conn(self):
        return self._store._conn  # noqa: SLF001

    @property
    def _lock(self):
        return self._store._lock  # noqa: SLF001

    def _now(self) -> int:
        return int(self._store.clock.wall_ms())

    # =====================================================================
    # 接收端额度策略（按接收端版本化）
    # =====================================================================
    def configure_quota_policy(
        self,
        recipient_id: str,
        *,
        max_sends: int,
        window_ms: int,
        idempotency_key: str | None = None,
    ) -> tuple[dict, bool]:
        if not isinstance(recipient_id, str) or not recipient_id:
            raise BatchQueueError("recipient_id 必须是非空字符串")
        max_sends = int(max_sends)
        window_ms = int(window_ms)
        if max_sends <= 0:
            raise BatchQueueError("max_sends 必须为正整数", max_sends=max_sends)
        if window_ms <= 0:
            raise BatchQueueError("window_ms 必须为正整数", window_ms=window_ms)
        now = self._now()
        with self._lock:
            if idempotency_key:
                hit = self._conn.execute(
                    "SELECT * FROM audit_batch_quota_policies WHERE "
                    "recipient_id=? AND idempotency_key=?",
                    (recipient_id, idempotency_key),
                ).fetchone()
                if hit is not None:
                    if hit["max_sends"] != max_sends \
                            or hit["window_ms"] != window_ms:
                        raise BatchQueueConflict(
                            "同一幂等键配置了不同的额度策略规格",
                            idempotency_key=idempotency_key)
                    return self._quota_view(hit), False
            ver = int(self._conn.execute(
                "SELECT COALESCE(MAX(version),0)+1 AS v FROM "
                "audit_batch_quota_policies WHERE recipient_id=?",
                (recipient_id,),
            ).fetchone()["v"])
            policy_id = f"qp_{_gid()}"
            self._conn.execute(
                "INSERT INTO audit_batch_quota_policies(policy_id, "
                "recipient_id, version, max_sends, window_ms, "
                "idempotency_key, created_at_ms) VALUES(?,?,?,?,?,?,?)",
                (policy_id, recipient_id, ver, max_sends, window_ms,
                 idempotency_key, now),
            )
            self._conn.commit()
            return self._quota_view(self._conn.execute(
                "SELECT * FROM audit_batch_quota_policies WHERE policy_id=?",
                (policy_id,)).fetchone()), True

    @staticmethod
    def _quota_view(row) -> dict:
        return {
            "policy_id": row["policy_id"],
            "recipient_id": row["recipient_id"],
            "version": row["version"],
            "max_sends": row["max_sends"],
            "window_ms": row["window_ms"],
            "idempotency_key": row["idempotency_key"],
            "created_at_ms": row["created_at_ms"],
        }

    def list_quota_policies(self, recipient_id: str | None = None) -> dict:
        with self._lock:
            if recipient_id:
                rows = self._conn.execute(
                    "SELECT * FROM audit_batch_quota_policies WHERE "
                    "recipient_id=? ORDER BY version", (recipient_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_batch_quota_policies ORDER BY "
                    "recipient_id, version").fetchall()
            return {"policies": [self._quota_view(r) for r in rows]}

    def _current_quota_locked(self, recipient_id: str):
        return self._conn.execute(
            "SELECT * FROM audit_batch_quota_policies WHERE recipient_id=? "
            "ORDER BY version DESC LIMIT 1", (recipient_id,),
        ).fetchone()

    def get_quota_policy(self, recipient_id: str) -> dict:
        with self._lock:
            row = self._current_quota_locked(recipient_id)
            if row is None:
                raise BatchQueueNotFound(
                    f"接收端 {recipient_id} 尚未配置额度策略",
                    recipient_id=recipient_id)
            return self._quota_view(row)

    # =====================================================================
    # 事件优先级策略（按事件类型版本化）
    # =====================================================================
    def configure_priority(
        self,
        event_type: str,
        *,
        priority: int,
        idempotency_key: str | None = None,
    ) -> tuple[dict, bool]:
        if not isinstance(event_type, str) or not event_type:
            raise BatchQueueError("event_type 必须是非空字符串")
        priority = int(priority)
        now = self._now()
        with self._lock:
            if idempotency_key:
                hit = self._conn.execute(
                    "SELECT * FROM audit_batch_priorities WHERE event_type=? "
                    "AND idempotency_key=?", (event_type, idempotency_key),
                ).fetchone()
                if hit is not None:
                    if hit["priority"] != priority:
                        raise BatchQueueConflict(
                            "同一幂等键配置了不同的优先级规格",
                            idempotency_key=idempotency_key)
                    return self._priority_view(hit), False
            ver = int(self._conn.execute(
                "SELECT COALESCE(MAX(version),0)+1 AS v FROM "
                "audit_batch_priorities WHERE event_type=?", (event_type,),
            ).fetchone()["v"])
            priority_id = f"pr_{_gid()}"
            self._conn.execute(
                "INSERT INTO audit_batch_priorities(priority_id, event_type,"
                " version, priority, idempotency_key, created_at_ms) "
                "VALUES(?,?,?,?,?,?)",
                (priority_id, event_type, ver, priority, idempotency_key, now),
            )
            # 策略变化只重排未发送任务：已认领/已发送任务保持入队时冻结的
            # 优先级，pending 任务按新策略重排
            self._conn.execute(
                "UPDATE audit_batch_send_tasks SET priority=? WHERE "
                "event_type=? AND status='pending'",
                (priority, event_type),
            )
            self._conn.commit()
            return self._priority_view(self._conn.execute(
                "SELECT * FROM audit_batch_priorities WHERE priority_id=?",
                (priority_id,)).fetchone()), True

    @staticmethod
    def _priority_view(row) -> dict:
        return {
            "priority_id": row["priority_id"],
            "event_type": row["event_type"],
            "version": row["version"],
            "priority": row["priority"],
            "idempotency_key": row["idempotency_key"],
            "created_at_ms": row["created_at_ms"],
        }

    def list_priorities(self, event_type: str | None = None) -> dict:
        with self._lock:
            if event_type:
                rows = self._conn.execute(
                    "SELECT * FROM audit_batch_priorities WHERE event_type=? "
                    "ORDER BY version", (event_type,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_batch_priorities ORDER BY "
                    "event_type, version").fetchall()
            return {"priorities": [self._priority_view(r) for r in rows]}

    def _current_priority_locked(self, event_type: str):
        return self._conn.execute(
            "SELECT * FROM audit_batch_priorities WHERE event_type=? "
            "ORDER BY version DESC LIMIT 1", (event_type,),
        ).fetchone()

    def get_priority(self, event_type: str) -> dict:
        with self._lock:
            row = self._current_priority_locked(event_type)
            if row is None:
                raise BatchQueueNotFound(
                    f"事件类型 {event_type} 尚未配置优先级",
                    event_type=event_type)
            return self._priority_view(row)

    # =====================================================================
    # 入队（由批次封存同事务调用）
    # =====================================================================
    def enqueue_tasks_locked(
        self,
        notification_id: str,
        batch_id: str,
        event_type: str,
        recipients: list[str],
        now: int,
    ) -> list[str]:
        """为新建通知按冻结接收端列表生成发送任务（与通知创建同事务）。

        返回新建 task_id 列表。``UNIQUE(notification_id, recipient_id)``
        兜底：通知唯一，任务也唯一，并发/重放不会重复入队。
        """
        prio_row = self._current_priority_locked(event_type)
        priority = int(prio_row["priority"]) if prio_row is not None else 0
        task_ids: list[str] = []
        for rid in recipients:
            seq = int(self._conn.execute(
                "SELECT COALESCE(MAX(queue_seq),0)+1 AS s FROM "
                "audit_batch_send_tasks WHERE recipient_id=?", (rid,),
            ).fetchone()["s"])
            task_id = f"tsk_{_gid()}"
            try:
                self._conn.execute(
                    "INSERT INTO audit_batch_send_tasks(task_id, "
                    "notification_id, batch_id, event_type, recipient_id, "
                    "priority, queue_seq, status, created_at_ms, "
                    "updated_at_ms) VALUES(?,?,?,?,?,?,?,'pending',?,?)",
                    (task_id, notification_id, batch_id, event_type, rid,
                     priority, seq, now, now),
                )
            except sqlite3.IntegrityError:
                # 同一通知同一接收端已有任务（极端并发兜底）：不重复入队
                continue
            task_ids.append(task_id)
        return task_ids

    # =====================================================================
    # 队列状态
    # =====================================================================
    def queue_status(
        self, recipient_id: str | None = None, *, limit: int = 20
    ) -> dict:
        limit = min(max(int(limit), 1), 1000)
        with self._lock:
            if recipient_id is not None:
                if not self._recipient_known_locked(recipient_id):
                    raise BatchQueueNotFound(
                        f"接收端 {recipient_id} 没有排队任务，也未配置额度策略",
                        recipient_id=recipient_id)
                return self._recipient_queue_view_locked(recipient_id, limit)
            rids = {
                r["recipient_id"] for r in self._conn.execute(
                    "SELECT recipient_id FROM audit_batch_send_tasks "
                    "GROUP BY recipient_id").fetchall()
            } | {
                r["recipient_id"] for r in self._conn.execute(
                    "SELECT recipient_id FROM audit_batch_quota_policies "
                    "GROUP BY recipient_id").fetchall()
            }
            return {
                "recipients": [
                    self._recipient_queue_view_locked(rid, limit)
                    for rid in sorted(rids)
                ],
            }

    def _recipient_known_locked(self, recipient_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM audit_batch_send_tasks WHERE recipient_id=? "
            "LIMIT 1", (recipient_id,),
        ).fetchone()
        if row is not None:
            return True
        return self._conn.execute(
            "SELECT 1 FROM audit_batch_quota_policies WHERE recipient_id=? "
            "LIMIT 1", (recipient_id,),
        ).fetchone() is not None

    def _recipient_queue_view_locked(self, recipient_id: str,
                                     limit: int) -> dict:
        now = self._now()
        counts = {"pending": 0, "claimed": 0, "sent": 0}
        for r in self._conn.execute(
            "SELECT status, COUNT(*) AS c FROM audit_batch_send_tasks "
            "WHERE recipient_id=? GROUP BY status", (recipient_id,),
        ).fetchall():
            counts[r["status"]] = r["c"]
        rows = self._conn.execute(
            "SELECT * FROM audit_batch_send_tasks WHERE recipient_id=? AND "
            "status IN ('pending','claimed') ORDER BY priority DESC, "
            "queue_seq ASC LIMIT ?", (recipient_id, limit),
        ).fetchall()
        return {
            "recipient_id": recipient_id,
            "counts": counts,
            "quota": self._quota_status_locked(recipient_id, now),
            "tasks": [self._task_view(r) for r in rows],
        }

    def _quota_status_locked(self, recipient_id: str, now: int) -> dict | None:
        policy = self._current_quota_locked(recipient_id)
        if policy is None:
            return None
        used = int(self._conn.execute(
            "SELECT COUNT(*) AS c FROM audit_batch_quota_usage WHERE "
            "recipient_id=? AND consumed_at_ms>?",
            (recipient_id, now - int(policy["window_ms"])),
        ).fetchone()["c"])
        reserved = int(self._conn.execute(
            "SELECT COUNT(*) AS c FROM audit_batch_send_tasks WHERE "
            "recipient_id=? AND status='claimed' AND claim_expires_at_ms>?",
            (recipient_id, now),
        ).fetchone()["c"])
        return {
            "configured": True,
            "policy_version": policy["version"],
            "max_sends": policy["max_sends"],
            "window_ms": policy["window_ms"],
            "used": used,
            "reserved": reserved,
            "remaining": max(0, int(policy["max_sends"]) - used - reserved),
        }

    # =====================================================================
    # 领取（并发唯一 + 租约接管）
    # =====================================================================
    def claim(
        self,
        recipient_id: str,
        worker_id: str,
        *,
        max_tasks: int = 1,
        lease_ms: int | None = None,
    ) -> dict:
        if not isinstance(recipient_id, str) or not recipient_id:
            raise BatchQueueError("recipient_id 必须是非空字符串")
        if not isinstance(worker_id, str) or not worker_id:
            raise BatchQueueError("worker_id 必须是非空字符串")
        max_tasks = int(max_tasks)
        if max_tasks <= 0:
            raise BatchQueueError("max_tasks 必须为正整数", max_tasks=max_tasks)
        max_tasks = min(max_tasks, MAX_CLAIM_TASKS)
        lease_ms = self._claim_lease_ms if lease_ms is None else int(lease_ms)
        if lease_ms <= 0:
            raise BatchQueueError("lease_ms 必须为正整数", lease_ms=lease_ms)
        now = self._now()
        with self._lock:
            quota = self._quota_status_locked(recipient_id, now)
            grant = max_tasks if quota is None else min(
                max_tasks, quota["remaining"])
            claimed: list[dict] = []
            if grant > 0:
                # 可领取 = pending，或租约已过期的 claimed（崩溃接管）；
                # 优先级高者优先，同优先级按排队身份（queue_seq）先后
                rows = self._conn.execute(
                    "SELECT * FROM audit_batch_send_tasks WHERE recipient_id=?"
                    " AND (status='pending' OR (status='claimed' AND "
                    "claim_expires_at_ms<=?)) ORDER BY priority DESC, "
                    "queue_seq ASC LIMIT ?",
                    (recipient_id, now, grant),
                ).fetchall()
                for r in rows:
                    token = _gid()
                    # 条件 UPDATE：并发领取同一任务只有一个成功；
                    # 租约未过期的他人认领不可被抢走
                    cur = self._conn.execute(
                        "UPDATE audit_batch_send_tasks SET status='claimed',"
                        " claimed_by=?, claim_token=?, claim_expires_at_ms=?,"
                        " updated_at_ms=? WHERE task_id=? AND "
                        "(status='pending' OR (status='claimed' AND "
                        "claim_expires_at_ms<=?))",
                        (worker_id, token, now + lease_ms, now,
                         r["task_id"], now),
                    )
                    if cur.rowcount == 0:
                        continue  # 被并发领取者抢走（进程锁下的 DB 兜底）
                    fresh = self._conn.execute(
                        "SELECT * FROM audit_batch_send_tasks WHERE task_id=?",
                        (r["task_id"],),
                    ).fetchone()
                    claimed.append(self._claimed_view(fresh))
            self._conn.commit()
            return {
                "recipient_id": recipient_id,
                "worker_id": worker_id,
                "lease_ms": lease_ms,
                "claimed_count": len(claimed),
                "claimed": claimed,
                "quota": self._quota_status_locked(recipient_id, now),
            }

    def _claimed_view(self, row) -> dict:
        view = self._task_view(row)
        view["claim_token"] = row["claim_token"]
        payload_row = self._conn.execute(
            "SELECT payload_json FROM audit_batch_notifications WHERE "
            "notification_id=?", (row["notification_id"],),
        ).fetchone()
        view["payload"] = (
            json.loads(payload_row["payload_json"])
            if payload_row is not None else None
        )
        return view

    # =====================================================================
    # 完成 / 失败上报
    # =====================================================================
    def complete_task(self, task_id: str, claim_token: str) -> dict:
        """发送成功：落一条额度消耗记录（发送失败不扣额度，成功才扣）。

        同一任务用同一令牌重复完成是幂等回放（不重复计额度）。
        """
        if not claim_token:
            raise BatchQueueError("claim_token 必填")
        now = self._now()
        with self._lock:
            row = self._get_task(task_id)
            if row["status"] == "sent":
                if row["claim_token"] == claim_token:
                    return {**self._task_view(row), "replayed": True}
                raise BatchQueueConflict(
                    "任务已被其他认领者完成，令牌不匹配", task_id=task_id)
            if row["status"] != "claimed":
                raise BatchQueueBadState(
                    f"任务当前为 {row['status']}，未被认领，不能完成",
                    task_id=task_id, status=row["status"])
            if row["claim_token"] != claim_token:
                raise BatchQueueConflict(
                    "认领令牌不匹配（租约过期后任务可能已被他人接管）",
                    task_id=task_id)
            self._conn.execute(
                "UPDATE audit_batch_send_tasks SET status='sent', sent_at_ms=?,"
                " updated_at_ms=? WHERE task_id=? AND status='claimed' AND "
                "claim_token=?", (now, now, task_id, claim_token),
            )
            # 只有成功才扣额度；主键 (recipient_id, task_id) 保证同一任务
            # 重复成功也只计一次
            self._conn.execute(
                "INSERT OR IGNORE INTO audit_batch_quota_usage(recipient_id,"
                " task_id, consumed_at_ms) VALUES(?,?,?)",
                (row["recipient_id"], task_id, now),
            )
            self._conn.commit()
            return {**self._task_view(self._get_task(task_id)),
                    "replayed": False}

    def fail_task(
        self, task_id: str, claim_token: str, *, error: str | None = None
    ) -> dict:
        """发送失败：回到 pending 等待重试。

        ``queue_seq`` 不变（重试保持原排队身份），只记一次尝试与失败原因，
        不落额度消耗记录（发送失败不扣额度）。
        """
        if not claim_token:
            raise BatchQueueError("claim_token 必填")
        now = self._now()
        with self._lock:
            row = self._get_task(task_id)
            if row["status"] != "claimed":
                raise BatchQueueBadState(
                    f"任务当前为 {row['status']}，不能上报失败",
                    task_id=task_id, status=row["status"])
            if row["claim_token"] != claim_token:
                raise BatchQueueConflict(
                    "认领令牌不匹配（租约过期后任务可能已被他人接管）",
                    task_id=task_id)
            self._conn.execute(
                "UPDATE audit_batch_send_tasks SET status='pending',"
                " attempts=attempts+1, last_error=?, claimed_by=NULL,"
                " claim_token=NULL, claim_expires_at_ms=NULL, updated_at_ms=?"
                " WHERE task_id=? AND status='claimed' AND claim_token=?",
                (error, now, task_id, claim_token),
            )
            self._conn.commit()
            return self._task_view(self._get_task(task_id))

    # =====================================================================
    # 任务查询
    # =====================================================================
    def get_task(self, task_id: str) -> dict:
        with self._lock:
            return self._task_view(self._get_task(task_id))

    def _get_task(self, task_id: str):
        row = self._conn.execute(
            "SELECT * FROM audit_batch_send_tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise BatchQueueNotFound(f"发送任务 {task_id} 不存在",
                                     task_id=task_id)
        return row

    @staticmethod
    def _task_view(row) -> dict:
        # 对外视图不含 claim_token（令牌只在领取响应中下发）
        return {
            "task_id": row["task_id"],
            "notification_id": row["notification_id"],
            "batch_id": row["batch_id"],
            "event_type": row["event_type"],
            "recipient_id": row["recipient_id"],
            "priority": row["priority"],
            "queue_seq": row["queue_seq"],
            "status": row["status"],
            "attempts": row["attempts"],
            "last_error": row["last_error"],
            "claimed_by": row["claimed_by"],
            "claim_expires_at_ms": row["claim_expires_at_ms"],
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
            "sent_at_ms": row["sent_at_ms"],
        }
