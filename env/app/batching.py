"""审计事件窗口批次聚合（audit event window batching）。

把按事件发生时间（occurred_at_ms）到达的审计事件，按管理员为每种事件类型
配置的**固定时长窗口 + 分组字段 + 允许迟到时长**聚合成可验证的通知批次。

核心不变量
==========
1. **每来源独立 watermark**：``(source_id, seq)`` 是来源内稳定审计序号，
   来源之间互不影响；watermark 是来源已确认的事件时间上界，只进不退，
   回退显式 409 拒绝且不改变状态。
2. **按发生时间落固定窗口**：窗口相对 Unix 纪元对齐，半开区间
   ``[window_start, window_end)``，同一分组（group_field 取值）+ 同一窗口
   + 同一规则版本归入同一主批次。
3. **封存条件唯一**：仅当
   ``window_end_ms + allowed_lateness_ms <= source.watermark_ms``
   时主批次才能封存。封存一次性冻结成员事件、聚合摘要与 sha256 校验值，
   并在**同一事务**里创建**唯一一条**多接收端通知（UNIQUE(batch_id) 兜底，
   并发/重放绝不会有第二条）。
4. **成员归属唯一**：``audit_batch_members`` 上的
   ``UNIQUE(source_id, event_id)`` 保证任何事件在整个系统内至多属于一个
   批次——并发扫描、重复处理同一段历史都不会让事件进两个批次，也不会
   生成重复通知。
5. **迟到不改写**：所属主批次已封存（或窗口已过封存线）后才到达的事件
   进入迟到区，管理员三选一：``retain`` 保留隔离 / ``forward`` 放入下一
   个尚未封存的窗口 / ``supplement`` 生成只含迟到事件的补充批次。任何
   处理都绝不 UPDATE/DELETE 原批次的成员、摘要或校验值。
6. **规则版本化**：规则按事件类型版本化，批次冻结命中的规则版本（窗口
   时长/分组字段/迟到时长/接收端快照）；切换规则产生新版本，只影响之后
   创建的批次，已存在（哪怕仍 open）的批次继续按旧版本聚合与封存。
7. **通知发件箱**：通知与封存同事务落库，实际"发送"在事务外执行；发送
   失败标记 failed 可重试，重启把可能在途（sending）的通知复位为 pending
   重新投递，批次始终只关联同一条通知。挂接发送队列后，同一事务还会按
   冻结接收端列表为每个接收端入队一个发送任务（额度/优先级排队，见
   ``batchqueue`` 模块）。

只写 ``audit_batch_*`` 自有表，绝不修改租约、委托、审计历史、归档、证据
包、因果索引、发布计划、订阅或多端投递的任何表。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from typing import Any

from .archive import canonical_json, first_diff
from .audit import AuditError

# ---------------------------------------------------------------------------
# 错误（映射为明确的 HTTP 状态码）
# ---------------------------------------------------------------------------


class BatchError(AuditError):
    code = "batch_error"
    status = 400


class BatchNotFound(BatchError):
    code = "batch_not_found"
    status = 404


class BatchSourceNotFound(BatchError):
    code = "batch_source_not_found"
    status = 404


class BatchRuleNotFound(BatchError):
    """该事件类型在给定事件发生时间没有任何生效规则（409）。"""

    code = "batch_rule_not_found"
    status = 409


class BatchBadState(BatchError):
    """状态前提不满足（未封存不能核验/已封存不能并入等，409）。"""

    code = "batch_bad_state"
    status = 409


class BatchConflict(BatchError):
    """幂等/规格冲突、watermark 回退、事件已被处理等（409）。"""

    code = "batch_conflict"
    status = 409


class BatchVerifyFailed(BatchError):
    """批次内容被篡改：重算校验值与封存冻结值不一致（409）。"""

    code = "batch_verify_failed"
    status = 409


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

GROUP_NULL = "__null__"          # 分组字段缺失/为 null 时的组键


def _gid() -> str:
    return uuid.uuid4().hex


def _json_loads(raw: Any, default: Any = None) -> Any:
    if raw is None:
        return default
    return json.loads(raw)


def _group_key_of(payload: Any, group_field: str) -> str:
    """按点路径从事件载荷取分组值；缺失/None 归入固定空组。"""
    cur = payload
    for part in group_field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return GROUP_NULL
    if cur is None:
        return GROUP_NULL
    if isinstance(cur, str):
        return cur
    return canonical_json(cur)


class BatchManager:
    def __init__(self, store: Any):
        self._store = store
        # 仅用于故障演练：当次请求内让"发送"抛错（不影响事务结果）
        self._fail_delivery = threading.local()
        # 发送任务队列（attach_queue 挂接）：封存创建通知时同事务入队
        self._queue: Any = None

    def attach_queue(self, queue: Any) -> None:
        """挂接接收端额度/优先级发送队列（同事务入队，可空则不挂）。"""
        self._queue = queue

    # ---- 连接/锁/时钟 ---------------------------------------------------
    @property
    def _conn(self):
        return self._store._conn  # noqa: SLF001 - 与其他模块共用同一连接/锁

    @property
    def _lock(self):
        return self._store._lock  # noqa: SLF001

    def _now(self) -> int:
        return int(self._store.clock.wall_ms())

    # =====================================================================
    # 来源与 watermark
    # =====================================================================
    def create_source(
        self, source_id: str, *, initial_watermark_ms: int | None = None
    ) -> tuple[dict, bool]:
        now = self._now()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_batch_sources WHERE source_id=?",
                (source_id,),
            ).fetchone()
            if row is not None:
                return self._source_view(row), False
            wm = (
                int(initial_watermark_ms)
                if initial_watermark_ms is not None else None
            )
            self._conn.execute(
                "INSERT INTO audit_batch_sources(source_id, last_seq, "
                "watermark_ms, watermark_seq, created_at_ms, updated_at_ms) "
                "VALUES(?,0,?,NULL,?,?)",
                (source_id, wm, now, now),
            )
            self._conn.commit()
            return self._get_source(source_id), True

    def list_sources(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_batch_sources ORDER BY source_id"
            ).fetchall()
            return {"sources": [self._source_view(r) for r in rows]}

    def _get_source(self, source_id: str) -> dict:
        row = self._conn.execute(
            "SELECT * FROM audit_batch_sources WHERE source_id=?",
            (source_id,),
        ).fetchone()
        if row is None:
            raise BatchSourceNotFound(f"事件来源 {source_id} 不存在",
                                      source_id=source_id)
        return self._source_view(row)

    def get_source(self, source_id: str) -> dict:
        with self._lock:
            return self._get_source(source_id)

    def advance_watermark(
        self,
        source_id: str,
        watermark_ms: int,
        *,
        seq: int | None = None,
        fail_delivery: bool = False,
    ) -> dict:
        """推进来源 watermark（单调不退）并尝试封存到点批次。"""
        watermark_ms = int(watermark_ms)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_batch_sources WHERE source_id=?",
                (source_id,),
            ).fetchone()
            if row is None:
                raise BatchSourceNotFound(f"事件来源 {source_id} 不存在",
                                          source_id=source_id)
            current = row["watermark_ms"]
            if current is not None and watermark_ms < current:
                # watermark 回退：明确拒绝，原 watermark 与任何批次都不变
                raise BatchConflict(
                    f"watermark 只能前进：当前 {current}，拒绝回退到 "
                    f"{watermark_ms}",
                    source_id=source_id, current_watermark_ms=current,
                    rejected_watermark_ms=watermark_ms,
                )
            now = self._now()
            if current is None or watermark_ms > current:
                self._conn.execute(
                    "UPDATE audit_batch_sources SET watermark_ms=?, "
                    "watermark_seq=?, updated_at_ms=? WHERE source_id=?",
                    (watermark_ms,
                     int(seq) if seq is not None else None, now, source_id),
                )
                self._conn.commit()
            sealed = self._seal_due_locked(source_id, fail_delivery)
            view = self._get_source(source_id)
            view["sealed_batches"] = sealed
            return view

    @staticmethod
    def _source_view(row) -> dict:
        return {
            "source_id": row["source_id"],
            "last_seq": row["last_seq"],
            "watermark_ms": row["watermark_ms"],
            "watermark_seq": row["watermark_seq"],
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
        }

    # =====================================================================
    # 聚合规则（按事件类型版本化）
    # =====================================================================
    def configure_rule(
        self,
        event_type: str,
        *,
        window_ms: int,
        group_field: str,
        allowed_lateness_ms: int,
        recipients: list,
        effective_at_ms: int | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict, bool]:
        window_ms = int(window_ms)
        allowed_lateness_ms = int(allowed_lateness_ms)
        if window_ms <= 0:
            raise BatchError("window_ms 必须为正整数", window_ms=window_ms)
        if allowed_lateness_ms < 0:
            raise BatchError("allowed_lateness_ms 不能为负数",
                             allowed_lateness_ms=allowed_lateness_ms)
        if not isinstance(group_field, str) or not group_field:
            raise BatchError("group_field 必须是非空字符串（点路径）")
        recipients = self._normalize_recipients(recipients)
        now = self._now()
        effective_was_explicit = effective_at_ms is not None
        effective_at_ms = (
            int(effective_at_ms) if effective_was_explicit else now
        )
        with self._lock:
            # 幂等键作用域为事件类型：(event_type, idempotency_key) 重放
            idem_id = f"idem:{event_type}:{idempotency_key}" if idempotency_key \
                else None
            if idem_id:
                hit = self._conn.execute(
                    "SELECT * FROM audit_batch_rules WHERE rule_id=?",
                    (idem_id,),
                ).fetchone()
                if hit is not None:
                    differs = (
                        hit["window_ms"] != window_ms
                        or hit["group_field"] != group_field
                        or hit["allowed_lateness_ms"] != allowed_lateness_ms
                        or _json_loads(hit["recipients_json"]) != recipients
                    )
                    # effective_at_ms 只有在调用方**显式**给出时才参与比较；
                    # 缺省取服务端当前时间，重放时刻不同不应判为规格冲突
                    if effective_was_explicit:
                        differs = differs or \
                            hit["effective_at_ms"] != effective_at_ms
                    if differs:
                        raise BatchConflict(
                            "同一幂等键配置了不同的规则规格",
                            idempotency_key=idempotency_key)
                    return self._rule_view(hit), False

            ver_row = self._conn.execute(
                "SELECT COALESCE(MAX(version),0)+1 AS v FROM "
                "audit_batch_rules WHERE event_type=?", (event_type,),
            ).fetchone()
            version = int(ver_row["v"])
            rule_id = idem_id or f"rule_{_gid()}"
            self._conn.execute(
                "INSERT INTO audit_batch_rules(rule_id, event_type, version, "
                "window_ms, group_field, allowed_lateness_ms, "
                "effective_at_ms, recipients_json, created_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (rule_id, event_type, version, window_ms, group_field,
                 allowed_lateness_ms, effective_at_ms,
                 json.dumps(recipients, ensure_ascii=False), now),
            )
            self._conn.commit()
            return self._get_rule(rule_id), True

    @staticmethod
    def _normalize_recipients(recipients: Any) -> list[str]:
        if not isinstance(recipients, list) or not recipients:
            raise BatchError("recipients 必须是非空接收端列表")
        out: list[str] = []
        for r in recipients:
            if isinstance(r, dict):
                rid = r.get("recipient_id") or r.get("id")
            else:
                rid = r
            if not isinstance(rid, str) or not rid:
                raise BatchError("每个接收端必须有非空 recipient_id")
            if rid not in out:
                out.append(rid)
        return out

    def list_rules(self, event_type: str | None = None) -> dict:
        with self._lock:
            if event_type:
                rows = self._conn.execute(
                    "SELECT * FROM audit_batch_rules WHERE event_type=? "
                    "ORDER BY version", (event_type,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_batch_rules ORDER BY event_type, "
                    "version").fetchall()
            return {"rules": [self._rule_view(r) for r in rows]}

    def _get_rule(self, rule_id: str):
        row = self._conn.execute(
            "SELECT * FROM audit_batch_rules WHERE rule_id=?", (rule_id,),
        ).fetchone()
        if row is None:
            raise BatchNotFound(f"规则 {rule_id} 不存在", rule_id=rule_id)
        return row

    def get_rule(self, rule_id: str) -> dict:
        with self._lock:
            return self._rule_view(self._get_rule(rule_id))

    @staticmethod
    def _rule_view(row) -> dict:
        return {
            "rule_id": row["rule_id"],
            "event_type": row["event_type"],
            "version": row["version"],
            "window_ms": row["window_ms"],
            "group_field": row["group_field"],
            "allowed_lateness_ms": row["allowed_lateness_ms"],
            "effective_at_ms": row["effective_at_ms"],
            "recipients": _json_loads(row["recipients_json"]),
            "created_at_ms": row["created_at_ms"],
        }

    def _rule_for_event_locked(self, event_type: str, occurred_at_ms: int):
        """事件发生时刻适用的规则：effective_at <= 发生时间 的最新版本；
        一个都没有则回退到该类型的第一个版本（规则先于历史事件配置的
        常见情形）。切换规则产生新版本，因此发生时间落在新生效点之后的
        事件命中新版本，只影响之后创建的批次。"""
        row = self._conn.execute(
            "SELECT * FROM audit_batch_rules WHERE event_type=? "
            "AND effective_at_ms<=? ORDER BY version DESC LIMIT 1",
            (event_type, occurred_at_ms),
        ).fetchone()
        if row is None:
            row = self._conn.execute(
                "SELECT * FROM audit_batch_rules WHERE event_type=? "
                "ORDER BY version ASC LIMIT 1", (event_type,),
            ).fetchone()
        if row is None:
            raise BatchRuleNotFound(
                f"事件类型 {event_type} 尚未配置聚合规则，无法归入批次",
                event_type=event_type, occurred_at_ms=occurred_at_ms)
        return row

    # =====================================================================
    # 读取事件（从稳定序号持续读取；重复扫描幂等）
    # =====================================================================
    def ingest_events(
        self,
        source_id: str,
        events: list[dict],
        *,
        fail_delivery: bool = False,
    ) -> dict:
        if not isinstance(events, list) or not events:
            raise BatchError("events 必须是非空事件列表")
        with self._lock:
            src = self._get_source(source_id)
            now = self._now()
            ingested: list[dict] = []
            duplicates: list[dict] = []
            late: list[dict] = []
            prepared: list[dict] = []
            expected_seq = int(src["last_seq"]) + 1
            for raw in events:
                if not isinstance(raw, dict):
                    raise BatchError("每个事件必须是 JSON 对象")
                etype = raw.get("event_type")
                if not isinstance(etype, str) or not etype:
                    raise BatchError("事件缺少 event_type")
                ts = raw.get("occurred_at_ms")
                if ts is None:
                    raise BatchError("事件缺少 occurred_at_ms")
                ts = int(ts)
                seq = raw.get("seq")
                payload = raw.get("payload", {})
                if not isinstance(payload, (dict, list)):
                    raise BatchError("事件 payload 必须是 JSON 对象/数组")

                if seq is not None:
                    seq = int(seq)
                    existed = self._conn.execute(
                        "SELECT * FROM audit_batch_events WHERE source_id=? "
                        "AND seq=?", (source_id, seq),
                    ).fetchone()
                    if existed is not None:
                        # 并发扫描 / 重复处理同一段历史：绝不重复归批。
                        # 已存在的序号必须正好是已读上界（重放最后一段），
                        # 不允许跨过未读序号去重放未来序号。
                        if seq > int(src["last_seq"]):
                            raise BatchConflict(
                                f"序号 {seq} 已存在但超过来源已读上界 "
                                f"{src['last_seq']}：并发写入冲突",
                                source_id=source_id, seq=seq)
                        if existed["event_type"] != etype \
                                or existed["occurred_at_ms"] != ts \
                                or existed["payload_json"] != canonical_json(
                                    payload):
                            raise BatchConflict(
                                f"来源 {source_id} 序号 {seq} 已被不同事件"
                                "占用", source_id=source_id, seq=seq)
                        duplicates.append({
                            "event_id": existed["event_id"], "seq": seq,
                            "event_type": etype, "occurred_at_ms": ts,
                            "rule_id": existed["rule_id"],
                        })
                        continue
                rule = self._rule_for_event_locked(etype, ts)
                group_key = _group_key_of(payload, rule["group_field"])
                if seq is None:
                    seq = expected_seq
                elif seq != expected_seq:
                    # 稳定审计序号必须连续读取：重复序号上面已走 duplicate；
                    # 缺口回填或跳号都拒绝（持续顺序读取的前提）
                    raise BatchConflict(
                        f"稳定序号必须连续：来源 {source_id} 下一序号应为 "
                        f"{expected_seq}，收到 {seq}（不允许缺口/跳号/乱序）",
                        source_id=source_id, seq=seq,
                        expected_seq=expected_seq)
                expected_seq += 1
                event_id = (
                    raw.get("event_id")
                    if isinstance(raw.get("event_id"), str)
                    and raw["event_id"] else f"evt_{_gid()}"
                )
                dup_id = self._conn.execute(
                    "SELECT 1 FROM audit_batch_events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                if dup_id is not None:
                    raise BatchConflict("event_id 已存在", event_id=event_id)

                prepared.append({
                    "event_id": event_id, "seq": seq, "event_type": etype,
                    "ts": ts, "payload": payload, "group_key": group_key,
                    "rule": rule,
                })

            for p in prepared:
                pjson = canonical_json(p["payload"])
                try:
                    self._conn.execute(
                        "INSERT INTO audit_batch_events(event_id, source_id, "
                        "seq, event_type, occurred_at_ms, ingested_at_ms, "
                        "payload_json, group_key, rule_id) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (p["event_id"], source_id, p["seq"], p["event_type"],
                         p["ts"], now, pjson, p["group_key"],
                         p["rule"]["rule_id"]),
                    )
                except sqlite3.IntegrityError:
                    # 并发扫描同一稳定序号：由 UNIQUE(source_id,seq) 兜底
                    raise BatchConflict(
                        f"来源 {source_id} 序号 {p['seq']} 与并发扫描冲突，"
                        "事件不会进入两个批次",
                        source_id=source_id, seq=p["seq"])
                self._advance_last_seq_locked(source_id, p["seq"])
                assignment = self._assign_event_locked(source_id, p, now)
                p["assignment"] = assignment
                if assignment["late"]:
                    late.append({
                        "event_id": p["event_id"], "seq": p["seq"],
                        "event_type": p["event_type"],
                        "occurred_at_ms": p["ts"],
                        "group_key": p["group_key"],
                        "rule_id": p["rule"]["rule_id"],
                        "sealed_batch_id": assignment["batch_id"],
                        "reason": assignment.get("reason"),
                    })
                ingested.append({
                    "event_id": p["event_id"], "seq": p["seq"],
                    "event_type": p["event_type"],
                    "occurred_at_ms": p["ts"],
                    "group_key": p["group_key"],
                    "rule_id": p["rule"]["rule_id"],
                    "window_start_ms": assignment.get("window_start_ms"),
                    "batch_id": assignment["batch_id"],
                    "late": assignment["late"],
                })
            self._conn.commit()
            # 归批时惰性封存产生的通知在事务外发送（失败只标记该通知）
            assigned_notifications = {
                p["assignment"].get("notification_id")
                for p in prepared
                if p.get("assignment", {}).get("notification_id")
            }
            for nid in assigned_notifications:
                self._dispatch_one(nid, fail_delivery)

            sealed = self._seal_due_locked(source_id, fail_delivery)
            source_view = self._get_source(source_id)
            return {
                "source_id": source_id,
                "ingested_count": len(ingested),
                "duplicate_count": len(duplicates),
                "late_count": len(late),
                "ingested": ingested,
                "duplicates": duplicates,
                "late_events": late,
                "sealed_batches": sealed,
                "source": source_view,
            }

    def _source_last_seq(self, source_id: str) -> int:
        row = self._conn.execute(
            "SELECT last_seq FROM audit_batch_sources WHERE source_id=?",
            (source_id,),
        ).fetchone()
        return int(row["last_seq"]) if row else 0

    def _advance_last_seq_locked(self, source_id: str, seq: int) -> None:
        self._conn.execute(
            "UPDATE audit_batch_sources SET last_seq=? WHERE source_id=? "
            "AND last_seq<?", (seq, source_id, seq),
        )

    def list_events(
        self, source_id: str, *, from_seq: int | None = None,
        to_seq: int | None = None, limit: int = 1000,
    ) -> dict:
        limit = min(max(int(limit), 1), 1000)
        with self._lock:
            self._get_source(source_id)
            where = ["source_id=?"]
            args: list[Any] = [source_id]
            if from_seq is not None:
                where.append("seq>=?")
                args.append(int(from_seq))
            if to_seq is not None:
                where.append("seq<=?")
                args.append(int(to_seq))
            rows = self._conn.execute(
                "SELECT * FROM audit_batch_events WHERE "
                + " AND ".join(where) + " ORDER BY seq ASC LIMIT ?",
                (*args, limit),
            ).fetchall()
            return {
                "source_id": source_id,
                "events": [self._event_view(r) for r in rows],
                "limit": limit,
            }

    @staticmethod
    def _event_view(row, *, member_of: str | None = None,
                    late_status: str | None = None) -> dict:
        return {
            "event_id": row["event_id"],
            "source_id": row["source_id"],
            "seq": row["seq"],
            "event_type": row["event_type"],
            "occurred_at_ms": row["occurred_at_ms"],
            "ingested_at_ms": row["ingested_at_ms"],
            "payload": _json_loads(row["payload_json"]),
            "group_key": row["group_key"],
            "rule_id": row["rule_id"],
            "member_batch_id": member_of,
            "late_status": late_status,
        }

    # =====================================================================
    # 归批（open 批次持续累积；已封存窗口 → 迟到区）
    # =====================================================================
    def _window_bounds(self, ts: int, window_ms: int) -> tuple[int, int]:
        start = (ts // window_ms) * window_ms
        return start, start + window_ms

    def _watermark_locked(self, source_id: str):
        return self._conn.execute(
            "SELECT watermark_ms FROM audit_batch_sources WHERE source_id=?",
            (source_id,),
        ).fetchone()["watermark_ms"]

    def _assign_event_locked(
        self, source_id: str, p: dict, now: int
    ) -> dict:
        """把已落库事件归入主批次或迟到区。

        返回 {batch_id, late, notification_id?, ...}。若所属 open 批次此刻
        才越过封存线，先在**同一事务**封存它（冻结旧成员 + 建通知），再把
        本事件判为迟到——迟到超过允许时长的事件绝不能混进即将封存的批次。
        """
        rule = p["rule"]
        w_start, w_end = self._window_bounds(p["ts"], rule["window_ms"])
        seal_line = w_end + rule["allowed_lateness_ms"]

        existing = self._conn.execute(
            "SELECT * FROM audit_batch_batches WHERE source_id=? AND rule_id=? "
            "AND group_key=? AND window_start_ms=? AND batch_type='primary'",
            (source_id, rule["rule_id"], p["group_key"], w_start),
        ).fetchone()
        watermark = self._watermark_locked(source_id)
        due = watermark is not None and seal_line <= watermark

        sealed_notification_id = None
        if existing is not None and existing["status"] == "open" and due:
            # 到点但尚未封存：先封存（冻结的是此前成员，不含本事件）
            sealed_notification_id = self._seal_one_locked(existing)
            existing = self._get_batch_row(existing["batch_id"])

        if existing is not None and existing["status"] == "open":
            batch_id = existing["batch_id"]
        elif (existing is not None and existing["status"] == "sealed") \
                or (existing is None and due):
            # 窗口已经封存，或窗口虽没有批次但已越过封存线（封存后才到达）
            self._route_late_locked(
                source_id, p,
                sealed_batch_id=existing["batch_id"] if existing else None,
                reason=("batch_already_sealed" if existing
                        else "window_closed_before_arrival"),
                now=now)
            return {
                "batch_id": existing["batch_id"] if existing else None,
                "window_start_ms": w_start, "late": True,
                "notification_id": sealed_notification_id,
                "reason": "batch_already_sealed" if existing
                else "window_closed_before_arrival",
            }
        else:
            batch_id = f"batch_{_gid()}"
            self._conn.execute(
                "INSERT INTO audit_batch_batches(batch_id, source_id, "
                "event_type, rule_id, group_key, window_start_ms, "
                "window_end_ms, allowed_lateness_ms, batch_type, "
                "parent_batch_id, status, created_at_ms, updated_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,'primary',NULL,'open',?,?)",
                (batch_id, source_id, p["event_type"], rule["rule_id"],
                 p["group_key"], w_start, w_end,
                 rule["allowed_lateness_ms"], now, now),
            )

        pos_row = self._conn.execute(
            "SELECT COALESCE(MAX(position),-1)+1 AS p FROM "
            "audit_batch_members WHERE batch_id=?", (batch_id,),
        ).fetchone()
        # UNIQUE(source_id,event_id) 兜底：并发下事件也不可能进两个批次
        try:
            cur = self._conn.execute(
                "INSERT INTO audit_batch_members(batch_id, source_id, "
                "event_id, seq, position, added_at_ms) VALUES(?,?,?,?,?,?)",
                (batch_id, source_id, p["event_id"], p["seq"],
                 int(pos_row["p"]), now),
            )
        except sqlite3.IntegrityError:
            raise BatchConflict(
                "事件已属于其他批次，不能重复归批", event_id=p["event_id"])
        if cur.rowcount == 0:
            raise BatchConflict(
                "事件已属于其他批次，不能重复归批", event_id=p["event_id"])
        self._refresh_batch_counters_locked(batch_id)
        return {"batch_id": batch_id, "window_start_ms": w_start,
                "late": False, "notification_id": sealed_notification_id}

    def _route_late_locked(
        self, source_id: str, p: dict, *, sealed_batch_id: str | None,
        reason: str, now: int,
    ) -> None:
        self._conn.execute(
            "INSERT INTO audit_batch_late_events(source_id, event_id, status, "
            "sealed_batch_id, reason) VALUES(?,?,'pending',?,?) "
            "ON CONFLICT(source_id,event_id) DO NOTHING",
            (source_id, p["event_id"], sealed_batch_id, reason),
        )

    def _refresh_batch_counters_locked(self, batch_id: str) -> None:
        mtable = self._member_table_locked(batch_id)
        row = self._conn.execute(
            f"SELECT COUNT(*) AS c, MIN(m.seq) AS lo, MAX(m.seq) AS hi, "
            "MIN(e.occurred_at_ms) AS tlo, MAX(e.occurred_at_ms) AS thi "
            f"FROM {mtable} m JOIN audit_batch_events e "
            "ON e.event_id=m.event_id WHERE m.batch_id=?",
            (batch_id,),
        ).fetchone()
        self._conn.execute(
            "UPDATE audit_batch_batches SET event_count=?, min_seq=?, "
            "max_seq=?, min_occurred_at_ms=?, max_occurred_at_ms=?, "
            "updated_at_ms=? WHERE batch_id=?",
            (row["c"], row["lo"], row["hi"], row["tlo"], row["thi"],
             self._now(), batch_id),
        )

    def _member_table_locked(self, batch_id: str) -> str:
        """补充批次用独立成员表（迟到事件已可能属于原窗口主批次）。"""
        t = self._conn.execute(
            "SELECT batch_type FROM audit_batch_batches WHERE batch_id=?",
            (batch_id,),
        ).fetchone()
        if t is not None and t["batch_type"] == "supplement":
            return "audit_batch_supplement_members"
        return "audit_batch_members"

    # =====================================================================
    # 封存：冻结成员/摘要/校验值 + 同事务创建唯一通知（发件箱）
    # =====================================================================
    def _seal_due_locked(
        self, source_id: str | None, fail_delivery: bool = False,
        *, dispatch: bool = True,
    ) -> list[dict]:
        """封存所有到点 open 主批次；返回新封存批次视图。

        通知只在本方法内随封存提交，并且只投递**本次封存新建**的通知，
        历史遗留 failed/pending 通知由 recover/process/retry 显式处理。
        批量流程（process/recover）传 dispatch=False，封存全部来源后统一
        派发一次，避免一次调用把同一条通知连算多次尝试。
        """
        sql = (
            "SELECT b.* FROM audit_batch_batches b JOIN "
            "audit_batch_sources s ON s.source_id=b.source_id "
            "WHERE b.status='open' AND b.batch_type='primary' AND "
            "s.watermark_ms IS NOT NULL AND "
            "b.window_end_ms + b.allowed_lateness_ms <= s.watermark_ms")
        args: list[Any] = []
        if source_id is not None:
            sql += " AND b.source_id=?"
            args.append(source_id)
        sql += " ORDER BY b.window_end_ms, b.batch_id"
        due = self._conn.execute(sql, args).fetchall()
        sealed: list[dict] = []
        new_notification_ids: list[str] = []
        for b in due:
            nid = self._seal_one_locked(b)
            sealed.append(self.get_batch(b["batch_id"]))
            if nid:
                new_notification_ids.append(nid)
        if due:
            self._conn.commit()
            if dispatch:
                for nid in new_notification_ids:
                    self._dispatch_one(nid, fail_delivery)
        return sealed

    def _seal_one_locked(self, b) -> str | None:
        """封存单个批次并创建唯一通知；返回新建通知 ID（已封存则 None）。"""
        batch_id = b["batch_id"]
        members = self._member_event_rows_locked(batch_id)
        core = self._build_checksum_core_locked(b, members)
        digest = hashlib.sha256(
            canonical_json(core).encode("utf-8")).hexdigest()
        summary = self._build_summary_locked(b, members, digest)
        now = self._now()
        # 条件 UPDATE：并发下只有一个封存者成功（另一个会 0 行后跳过通知）
        cur = self._conn.execute(
            "UPDATE audit_batch_batches SET status='sealed', summary_json=?, "
            "checksum=?, checksum_alg='sha256', sealed_at_ms=?, "
            "updated_at_ms=? WHERE batch_id=? AND status='open'",
            (canonical_json(summary), digest, now, now, batch_id),
        )
        if cur.rowcount == 0:
            return None
        recipients = _json_loads(
            self._conn.execute(
                "SELECT recipients_json FROM audit_batch_rules WHERE rule_id=?",
                (b["rule_id"],)).fetchone()["recipients_json"])
        notification_payload = {
            "kind": "audit_batch_sealed",
            "batch_id": batch_id,
            "source_id": b["source_id"],
            "event_type": b["event_type"],
            "group_key": b["group_key"],
            "window": {
                "start_ms": b["window_start_ms"],
                "end_ms": b["window_end_ms"],
            },
            "batch_type": b["batch_type"],
            "summary": summary,
            "checksum": digest,
            "checksum_alg": "sha256",
            "sealed_at_ms": now,
        }
        notification_id = f"ntf_{_gid()}"
        # 同事务创建唯一一条多接收端通知；UNIQUE(batch_id) 双重兜底
        try:
            self._conn.execute(
                "INSERT INTO audit_batch_notifications(notification_id,"
                " batch_id, recipients_json, payload_json, status, "
                "created_at_ms) VALUES(?,?,?,?,'pending',?)",
                (notification_id, batch_id,
                 canonical_json(recipients), canonical_json(notification_payload),
                 now),
            )
        except sqlite3.IntegrityError:
            # 极端并发下另一事务已建通知：不会有第二条
            return None
        if self._queue is not None:
            # 同事务为每个冻结接收端入队一个发送任务（额度/优先级排队）
            self._queue.enqueue_tasks_locked(
                notification_id, batch_id, b["event_type"], recipients, now)
        return notification_id

    # ---- 校验值与摘要（确定性、可独立复算） -----------------------------
    def _member_event_rows_locked(self, batch_id: str):
        mtable = self._member_table_locked(batch_id)
        return self._conn.execute(
            f"SELECT e.* FROM {mtable} m JOIN audit_batch_events e "
            "ON e.event_id=m.event_id WHERE m.batch_id=? "
            "ORDER BY m.position ASC", (batch_id,),
        ).fetchall()

    def _event_record(self, row) -> dict:
        return {
            "event_id": row["event_id"],
            "seq": row["seq"],
            "event_type": row["event_type"],
            "occurred_at_ms": row["occurred_at_ms"],
            "group_key": row["group_key"],
            "payload": _json_loads(row["payload_json"]),
        }

    def _build_checksum_core_locked(self, b, members) -> dict:
        return {
            "batch": {
                "source_id": b["source_id"],
                "event_type": b["event_type"],
                "rule_id": b["rule_id"],
                "group_key": b["group_key"],
                "window_start_ms": b["window_start_ms"],
                "window_end_ms": b["window_end_ms"],
                "allowed_lateness_ms": b["allowed_lateness_ms"],
                "batch_type": b["batch_type"],
                "parent_batch_id": b["parent_batch_id"],
            },
            "members": [self._event_record(r) for r in members],
        }

    def _build_summary_locked(self, b, members, digest: str) -> dict:
        records = [self._event_record(r) for r in members]
        seqs = [r["seq"] for r in records]
        times = [r["occurred_at_ms"] for r in records]
        # 载荷分布：按 payload 规范化字符串计数，给出可核验的内容摘要
        payload_counts: dict[str, int] = {}
        for r in records:
            key = canonical_json(r["payload"])
            payload_counts[key] = payload_counts.get(key, 0) + 1
        members_digest = hashlib.sha256(
            "\n".join(
                hashlib.sha256(
                    canonical_json(r).encode("utf-8")).hexdigest()
                for r in records
            ).encode("utf-8")).hexdigest()
        return {
            "event_count": len(records),
            "seq_range": [min(seqs), max(seqs)] if seqs else [None, None],
            "time_range_ms": [min(times), max(times)] if times
            else [None, None],
            "window_ms": b["window_end_ms"] - b["window_start_ms"],
            "group_key": b["group_key"],
            "distinct_payloads": len(payload_counts),
            "payload_counts": [
                {"payload": _json_loads(k), "count": c}
                for k, c in sorted(payload_counts.items())
            ],
            "members_digest": members_digest,
            "checksum": digest,
            "checksum_alg": "sha256",
        }

    def recompute_checksum(self, batch_id: str) -> dict:
        """从当前成员独立重算校验值（不改写任何冻结内容）。"""
        with self._lock:
            b = self._get_batch_row(batch_id)
            members = self._member_event_rows_locked(batch_id)
            core = self._build_checksum_core_locked(b, members)
            digest = hashlib.sha256(
                canonical_json(core).encode("utf-8")).hexdigest()
            return {
                "batch_id": batch_id,
                "recomputed_checksum": digest,
                "stored_checksum": b["checksum"],
                "member_count": len(members),
            }

    def verify_batch(self, batch_id: str) -> dict:
        """独立核验封存批次：重算成员/摘要/校验值与冻结值比对。"""
        with self._lock:
            b = self._get_batch_row(batch_id)
            if b["status"] != "sealed":
                raise BatchBadState(
                    f"批次 {batch_id} 尚未封存，无冻结校验值可核验",
                    batch_id=batch_id, status=b["status"])
            members = self._member_event_rows_locked(batch_id)
            core = self._build_checksum_core_locked(b, members)
            recomputed = hashlib.sha256(
                canonical_json(core).encode("utf-8")).hexdigest()
            stored_summary = _json_loads(b["summary_json"])
            recomputed_summary = self._build_summary_locked(
                b, members, recomputed)
            ok = recomputed == b["checksum"]
            # 先比摘要（可定位到具体成员/范围字段），再比整体校验值
            diff = None
            if stored_summary != recomputed_summary:
                diff = first_diff(stored_summary, recomputed_summary,
                                  "frozen.summary")
            elif not ok:
                diff = {"path": "frozen.checksum",
                        "archived": b["checksum"],
                        "recomputed": recomputed}
            result = {
                "batch_id": batch_id,
                "valid": ok,
                "stored_checksum": b["checksum"],
                "recomputed_checksum": recomputed,
                "frozen_event_count": b["event_count"],
                "current_event_count": len(members),
                "first_diff": diff,
            }
            if not ok:
                raise BatchVerifyFailed(
                    "批次内容与封存冻结值不一致（成员或摘要被篡改）",
                    **result)
            return result

    # =====================================================================
    # 批次查询与成员
    # =====================================================================
    def list_batches(
        self, *, source_id: str | None = None, event_type: str | None = None,
        group_key: str | None = None, status: str | None = None,
        batch_type: str | None = None, limit: int = 200,
    ) -> dict:
        limit = min(max(int(limit), 1), 1000)
        where, args = [], []
        for col, val in (("source_id", source_id), ("event_type", event_type),
                         ("group_key", group_key), ("status", status),
                         ("batch_type", batch_type)):
            if val is not None:
                where.append(f"{col}=?")
                args.append(val)
        sql = "SELECT * FROM audit_batch_batches"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY window_start_ms, batch_id LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (*args, limit)).fetchall()
            return {"batches": [self._batch_view(r) for r in rows],
                    "limit": limit}

    def _get_batch_row(self, batch_id: str):
        row = self._conn.execute(
            "SELECT * FROM audit_batch_batches WHERE batch_id=?",
            (batch_id,),
        ).fetchone()
        if row is None:
            raise BatchNotFound(f"批次 {batch_id} 不存在", batch_id=batch_id)
        return row

    def get_batch(self, batch_id: str) -> dict:
        with self._lock:
            return self._batch_view(self._get_batch_row(batch_id))

    def _batch_view(self, row) -> dict:
        notification = self._conn.execute(
            "SELECT notification_id, status, attempts, last_error, sent_at_ms "
            "FROM audit_batch_notifications WHERE batch_id=?",
            (row["batch_id"],),
        ).fetchone()
        return {
            "batch_id": row["batch_id"],
            "source_id": row["source_id"],
            "event_type": row["event_type"],
            "rule_id": row["rule_id"],
            "group_key": row["group_key"],
            "window_start_ms": row["window_start_ms"],
            "window_end_ms": row["window_end_ms"],
            "allowed_lateness_ms": row["allowed_lateness_ms"],
            "batch_type": row["batch_type"],
            "parent_batch_id": row["parent_batch_id"],
            "status": row["status"],
            "event_count": row["event_count"],
            "seq_range": [row["min_seq"], row["max_seq"]],
            "time_range_ms": [row["min_occurred_at_ms"],
                              row["max_occurred_at_ms"]],
            "summary": _json_loads(row["summary_json"]),
            "checksum": row["checksum"],
            "checksum_alg": row["checksum_alg"],
            "sealed_at_ms": row["sealed_at_ms"],
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
            "notification": (
                None if notification is None else {
                    "notification_id": notification["notification_id"],
                    "status": notification["status"],
                    "attempts": notification["attempts"],
                    "last_error": notification["last_error"],
                    "sent_at_ms": notification["sent_at_ms"],
                }),
        }

    def list_members(self, batch_id: str) -> dict:
        with self._lock:
            self._get_batch_row(batch_id)
            mtable = self._member_table_locked(batch_id)
            rows = self._conn.execute(
                f"SELECT e.*, m.position AS pos FROM {mtable} m "
                "JOIN audit_batch_events e ON e.event_id=m.event_id "
                "WHERE m.batch_id=? ORDER BY m.position", (batch_id,),
            ).fetchall()
            events = []
            for r in rows:
                v = self._event_view(r, member_of=batch_id)
                v["position"] = r["pos"]
                events.append(v)
            return {"batch_id": batch_id, "members": events,
                    "count": len(events)}

    # =====================================================================
    # 迟到区与三种处理（不改写原批次）
    # =====================================================================
    def list_late_events(
        self, *, source_id: str | None = None,
        status: str | None = None, limit: int = 200,
    ) -> dict:
        limit = min(max(int(limit), 1), 1000)
        where, args = [], []
        if source_id is not None:
            where.append("l.source_id=?")
            args.append(source_id)
        if status is not None:
            where.append("l.status=?")
            args.append(status)
        sql = (
            "SELECT l.*, e.seq AS seq, e.event_type AS event_type, "
            "e.occurred_at_ms AS occurred_at_ms, e.group_key AS group_key, "
            "e.rule_id AS rule_id, e.payload_json AS payload_json "
            "FROM audit_batch_late_events l JOIN audit_batch_events e "
            "ON e.source_id=l.source_id AND e.event_id=l.event_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY e.source_id, e.seq LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (*args, limit)).fetchall()
            return {"late_events": [self._late_view(r) for r in rows],
                    "limit": limit}

    @staticmethod
    def _late_view(row) -> dict:
        return {
            "source_id": row["source_id"],
            "event_id": row["event_id"],
            "seq": row["seq"],
            "event_type": row["event_type"],
            "occurred_at_ms": row["occurred_at_ms"],
            "group_key": row["group_key"],
            "rule_id": row["rule_id"],
            "payload": _json_loads(row["payload_json"]),
            "status": row["status"],
            "sealed_batch_id": row["sealed_batch_id"],
            "target_batch_id": row["target_batch_id"],
            "reason": row["reason"],
            "note": row["note"],
            "handled_at_ms": row["handled_at_ms"],
        }

    def handle_late_event(
        self,
        source_id: str,
        event_id: str,
        action: str,
        *,
        note: str | None = None,
        fail_delivery: bool = False,
    ) -> dict:
        if action not in ("retain", "forward", "supplement"):
            raise BatchError(
                "action 只能是 retain / forward / supplement")
        with self._lock:
            self._get_source(source_id)
            late = self._conn.execute(
                "SELECT * FROM audit_batch_late_events WHERE source_id=? "
                "AND event_id=?", (source_id, event_id),
            ).fetchone()
            if late is None:
                raise BatchNotFound(
                    f"迟到事件 {event_id} 不在来源 {source_id} 的迟到区",
                    source_id=source_id, event_id=event_id)
            if late["status"] not in ("pending", "retained"):
                raise BatchBadState(
                    f"迟到事件已处理为 {late['status']}，不能再次处理",
                    event_id=event_id, status=late["status"])
            ev = self._conn.execute(
                "SELECT * FROM audit_batch_events WHERE source_id=? "
                "AND event_id=?", (source_id, event_id),
            ).fetchone()
            rule = self._get_rule(ev["rule_id"])
            now = self._now()

            if action == "retain":
                self._conn.execute(
                    "UPDATE audit_batch_late_events SET status='retained', "
                    "note=?, handled_at_ms=? WHERE source_id=? AND event_id=?",
                    (note, now, source_id, event_id))
                self._conn.commit()
                return {"action": "retain",
                        "late_event": self._get_late(source_id, event_id)}

            if action == "forward":
                target = self._forward_event_locked(ev, rule, now)
                self._mark_late_handled_locked(
                    source_id, event_id, "forwarded", target["batch_id"],
                    now, note)
                self._conn.commit()
                sealed = self._seal_due_locked(source_id, fail_delivery)
                return {
                    "action": "forward",
                    "target_batch_id": target["batch_id"],
                    "late_event": self._get_late(source_id, event_id),
                    "sealed_batches": sealed,
                }

            # supplement：立即封存的只含迟到事件的补充批次 + 独立通知，
            # 原批次一行都不改
            parent_id = late["sealed_batch_id"]
            if parent_id is not None:
                self._get_batch_row(parent_id)
            sup_id, sup_notification_id = self._create_supplement_locked(
                ev, rule, parent_id, now)
            self._mark_late_handled_locked(
                source_id, event_id, "supplemented", sup_id, now, note)
            self._conn.commit()
            if sup_notification_id:
                self._dispatch_one(sup_notification_id, fail_delivery)
            return {
                "action": "supplement",
                "supplement_batch_id": sup_id,
                "late_event": self._get_late(source_id, event_id),
                "supplement_batch": self.get_batch(sup_id),
            }

    def _get_late(self, source_id: str, event_id: str) -> dict:
        row = self._conn.execute(
            "SELECT l.*, e.seq AS seq, e.event_type AS event_type, "
            "e.occurred_at_ms AS occurred_at_ms, e.group_key AS group_key, "
            "e.rule_id AS rule_id, e.payload_json AS payload_json "
            "FROM audit_batch_late_events l JOIN audit_batch_events e "
            "ON e.source_id=l.source_id AND e.event_id=l.event_id "
            "WHERE l.source_id=? AND l.event_id=?",
            (source_id, event_id),
        ).fetchone()
        return self._late_view(row)

    def _mark_late_handled_locked(
        self, source_id, event_id, status, target_batch_id, now, note,
    ) -> None:
        self._conn.execute(
            "UPDATE audit_batch_late_events SET status=?, target_batch_id=?, "
            "handled_at_ms=?, note=? WHERE source_id=? AND event_id=?",
            (status, target_batch_id, now, note, source_id, event_id),
        )

    def _forward_event_locked(self, ev, rule, now: int) -> dict:
        """放入同分组下一个**尚未封存**的窗口批次（迟到窗口之后）。"""
        w = self._window_bounds(ev["occurred_at_ms"], rule["window_ms"])
        candidate_start = w[1]      # 下一窗口起点
        watermark = self._watermark_locked(ev["source_id"])
        while True:
            candidate_end = candidate_start + rule["window_ms"]
            if watermark is not None and \
                    candidate_end + rule["allowed_lateness_ms"] <= watermark:
                # 下一窗口也已过封存线，继续向未来找，直到未封存窗口
                candidate_start = candidate_end
                continue
            break
        row = self._conn.execute(
            "SELECT * FROM audit_batch_batches WHERE source_id=? AND rule_id=?"
            " AND group_key=? AND window_start_ms=? AND batch_type='primary'",
            (ev["source_id"], rule["rule_id"], ev["group_key"],
             candidate_start),
        ).fetchone()
        if row is not None:
            if row["status"] != "open":
                raise BatchBadState(
                    "目标窗口批次已封存，无法 forward",
                    batch_id=row["batch_id"])
            batch_id = row["batch_id"]
        else:
            batch_id = f"batch_{_gid()}"
            self._conn.execute(
                "INSERT INTO audit_batch_batches(batch_id, source_id, "
                "event_type, rule_id, group_key, window_start_ms, "
                "window_end_ms, allowed_lateness_ms, batch_type, "
                "parent_batch_id, status, created_at_ms, updated_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,'primary',NULL,'open',?,?)",
                (batch_id, ev["source_id"], ev["event_type"], rule["rule_id"],
                 ev["group_key"], candidate_start,
                 candidate_start + rule["window_ms"],
                 rule["allowed_lateness_ms"], now, now),
            )
        pos = int(self._conn.execute(
            "SELECT COALESCE(MAX(position),-1)+1 AS p FROM "
            "audit_batch_members WHERE batch_id=?", (batch_id,),
        ).fetchone()["p"])
        try:
            inserted = self._conn.execute(
                "INSERT INTO audit_batch_members(batch_id, source_id, "
                "event_id, seq, position, added_at_ms) VALUES(?,?,?,?,?,?)",
                (batch_id, ev["source_id"], ev["event_id"], ev["seq"], pos, now),
            )
        except sqlite3.IntegrityError:
            raise BatchConflict(
                "事件已属于其他批次，不能 forward", event_id=ev["event_id"])
        if inserted.rowcount == 0:
            raise BatchConflict(
                "事件已属于其他批次，不能 forward", event_id=ev["event_id"])
        self._refresh_batch_counters_locked(batch_id)
        return {"batch_id": batch_id}

    def _create_supplement_locked(
        self, ev, rule, parent_id: str | None, now: int,
    ) -> tuple[str, str | None]:
        sup_id = f"sup_{_gid()}"
        # 补充批次窗口取事件自身所在窗口（仅用于描述），立即封存
        w_start, w_end = self._window_bounds(
            ev["occurred_at_ms"], rule["window_ms"])
        self._conn.execute(
            "INSERT INTO audit_batch_batches(batch_id, source_id, event_type,"
            " rule_id, group_key, window_start_ms, window_end_ms, "
            "allowed_lateness_ms, batch_type, parent_batch_id, status, "
            "created_at_ms, updated_at_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,'open',?,?)",
            (sup_id, ev["source_id"], ev["event_type"], rule["rule_id"],
             ev["group_key"], w_start, w_end, rule["allowed_lateness_ms"],
             "supplement", parent_id, now, now),
        )
        # 补充批次用独立成员表：全局归属唯一约束仍保证一条迟到事件至多进
        # 一个补充批次，且原批次成员一行都不改
        self._conn.execute(
            "INSERT INTO audit_batch_supplement_members(batch_id, source_id, "
            "event_id, seq, position, added_at_ms) VALUES(?,?,?,?,0,?)",
            (sup_id, ev["source_id"], ev["event_id"], ev["seq"], now),
        )
        self._refresh_batch_counters_locked(sup_id)
        sup_row = self._get_batch_row(sup_id)
        sup_notification_id = self._seal_one_locked(sup_row)
        return sup_id, sup_notification_id

    # =====================================================================
    # 通知（发件箱）：发送在事务外；失败可重试；重启收敛在途通知
    # =====================================================================
    def list_notifications(
        self, *, status: str | None = None, source_id: str | None = None,
        batch_id: str | None = None, limit: int = 200,
    ) -> dict:
        limit = min(max(int(limit), 1), 1000)
        where, args = [], []
        if status:
            where.append("n.status=?")
            args.append(status)
        if source_id:
            where.append("b.source_id=?")
            args.append(source_id)
        if batch_id:
            where.append("n.batch_id=?")
            args.append(batch_id)
        sql = ("SELECT n.* FROM audit_batch_notifications n JOIN "
               "audit_batch_batches b ON b.batch_id=n.batch_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY n.created_at_ms, n.notification_id LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (*args, limit)).fetchall()
            return {"notifications": [self._notification_view(r)
                                      for r in rows], "limit": limit}

    def get_notification(self, notification_id: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_batch_notifications WHERE notification_id=?",
                (notification_id,)).fetchone()
            if row is None:
                raise BatchNotFound(f"通知 {notification_id} 不存在",
                                    notification_id=notification_id)
            return self._notification_view(row)

    @staticmethod
    def _notification_view(row) -> dict:
        return {
            "notification_id": row["notification_id"],
            "batch_id": row["batch_id"],
            "recipients": _json_loads(row["recipients_json"]),
            "payload": _json_loads(row["payload_json"]),
            "status": row["status"],
            "attempts": row["attempts"],
            "last_error": row["last_error"],
            "created_at_ms": row["created_at_ms"],
            "sent_at_ms": row["sent_at_ms"],
        }

    def retry_notification(
        self, notification_id: str, *, fail_delivery: bool = False
    ) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_batch_notifications WHERE notification_id=?",
                (notification_id,)).fetchone()
            if row is None:
                raise BatchNotFound(f"通知 {notification_id} 不存在",
                                    notification_id=notification_id)
            if row["status"] == "sent":
                return self._notification_view(row)
            result = self._dispatch_one(row["notification_id"], fail_delivery)
            return result

    def _deliver(self, notification: dict) -> None:
        """模拟把一条多接收端通知投递给全部接收端。

        演练故障：fail_delivery 置位时抛错，调用方把通知标记 failed；
        封存事务早已提交，重试只复用这同一条通知。
        """
        fail = getattr(self._fail_delivery, "on", False)
        if fail:
            raise RuntimeError("模拟通知发送失败（接收端不可达）")
        # 真实实现里这里会并发投递给 notification["recipients"]；
        # 此处只做确定性的本地投递，耗时忽略不计。
        _ = (notification["notification_id"], notification["recipients"])

    def _dispatch_pending(self, fail_delivery: bool = False) -> list[dict]:
        rows = self._conn.execute(
            "SELECT notification_id FROM audit_batch_notifications "
            "WHERE status IN ('pending','failed') ORDER BY created_at_ms"
        ).fetchall()
        out = []
        for r in rows:
            out.append(self._dispatch_one(r["notification_id"], fail_delivery))
        return out

    def _dispatch_one(self, notification_id: str, fail_delivery: bool) -> dict:
        prev = getattr(self._fail_delivery, "on", False)
        self._fail_delivery.on = fail_delivery
        try:
            row = self._conn.execute(
                "SELECT * FROM audit_batch_notifications WHERE notification_id=?",
                (notification_id,)).fetchone()
            view = self._notification_view(row)
            try:
                self._deliver(view)
            except Exception as exc:  # noqa: BLE001 - 投递失败必须落库可重试
                self._conn.execute(
                    "UPDATE audit_batch_notifications SET status='failed', "
                    "attempts=attempts+1, last_error=? WHERE notification_id=?",
                    (str(exc), notification_id),
                )
                self._conn.commit()
                return self._notification_view(self._conn.execute(
                    "SELECT * FROM audit_batch_notifications WHERE "
                    "notification_id=?", (notification_id,)).fetchone())
            self._conn.execute(
                "UPDATE audit_batch_notifications SET status='sent', "
                "attempts=attempts+1, last_error=NULL, sent_at_ms=? "
                "WHERE notification_id=?",
                (self._now(), notification_id),
            )
            self._conn.commit()
            return self._notification_view(self._conn.execute(
                "SELECT * FROM audit_batch_notifications WHERE "
                "notification_id=?", (notification_id,)).fetchone())
        finally:
            self._fail_delivery.on = prev

    def recover_interrupted(self) -> dict:
        """启动/管理恢复：把可能在途（sending）通知复位为 pending 并重投，
        同时尝试封存各来源已到点的批次。幂等：重复调用不产生重复通知。"""
        with self._lock:
            self._conn.execute(
                "UPDATE audit_batch_notifications SET status='pending' "
                "WHERE status='sending'")
            self._conn.commit()
            sources = [r["source_id"] for r in self._conn.execute(
                "SELECT source_id FROM audit_batch_sources").fetchall()]
            sealed = []
            for sid in sources:
                sealed += self._seal_due_locked(sid, dispatch=False)
            pending = self._dispatch_pending()
            return {"recovered_sources": sources, "sealed_batches": sealed,
                    "dispatched": len(pending)}

    def process(self, *, fail_delivery: bool = False) -> dict:
        """管理/演练入口：封存所有来源到点批次并投递待发通知。"""
        with self._lock:
            sources = [r["source_id"] for r in self._conn.execute(
                "SELECT source_id FROM audit_batch_sources").fetchall()]
            sealed = []
            for sid in sources:
                sealed += self._seal_due_locked(
                    sid, fail_delivery, dispatch=False)
            dispatched = self._dispatch_pending(fail_delivery)
            return {"sources": sources, "sealed_batches": sealed,
                    "dispatched_notifications": len(dispatched)}

    # =====================================================================
    # 调试：直接篡改成员事件载荷（绕过业务路径），用于演示校验值能发现
    # =====================================================================
    def debug_tamper_event(self, event_id: str, payload: Any) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_batch_events WHERE event_id=?",
                (event_id,)).fetchone()
            if row is None:
                raise BatchNotFound(f"事件 {event_id} 不存在",
                                    event_id=event_id)
            self._conn.execute(
                "UPDATE audit_batch_events SET payload_json=? WHERE event_id=?",
                (canonical_json(payload), event_id))
            self._conn.commit()
            mrow = self._conn.execute(
                "SELECT batch_id FROM audit_batch_members WHERE event_id=? "
                "UNION ALL SELECT batch_id FROM audit_batch_supplement_members "
                "WHERE event_id=?", (event_id, event_id)).fetchone()
            return {"tampered": True, "event_id": event_id,
                    "batch_id": mrow["batch_id"] if mrow else None}
