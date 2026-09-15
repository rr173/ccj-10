"""审计事件处置：管理员对已进入通知链路的事件发布更正（correct）或撤回（retract）。

每个**接收端**（本实现中一个订阅即一个接收端）独立决策，决策只取决于该接收端
原通知的发送状态：

- queued / blocked（尚未开始发送）：
  - 撤回 → **原子取消**原任务（通知行置 cancelled，不产生任何新通知）；
  - 更正 → **同一排队位置原位替换**为新通知（同一 notification_id，
    旧载荷在 notification_revisions 留档）。
- delivered（已确认送达）：原通知**绝不删除/改写**，只能在其后**追加**一条
  带明确关联（relation）的撤回/更正通知（disposition_notices），排队位置严格更大。
- sending（正在发送）：处置落为 pending 挂起；发送结果（ack/nack）与处置在
  同一把写锁下竞争，只有一个先发生：
  - ack 先生效（→delivered）：挂起处置落地为"追加后续通知"；
  - nack 先生效（→queued）：挂起处置落地为"取消/原位替换"。
  最终稳定落在两种结果之一，不漏发、不重复、不颠倒。

更正内容必须依次通过：当前生效载荷契约校验 → 逐字段来源说明 → 签名，
任何一步失败都不改原通知；失败按接收端独立落档（failed），不影响其他接收端。
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

from . import contracts as C
from . import provenance as P
from .signing import SigningError

# 时间线事件名
TL_DISPOSITION_REQUESTED = "disposition_requested"
TL_DISPOSITION_PARKED = "disposition_parked_sending"
TL_NOTIFICATION_CLAIMED = "notification_claimed"
TL_NOTIFICATION_ACKED = "notification_acked"
TL_NOTIFICATION_NACKED = "notification_nacked"
TL_NOTIFICATION_CANCELLED = "notification_cancelled"
TL_NOTIFICATION_SUPERSEDED = "notification_superseded"
TL_NOTICE_ENQUEUED = "followup_notice_enqueued"
TL_DISPOSITION_FAILED = "disposition_failed"
TL_NOTICE_CLAIMED = "followup_notice_claimed"
TL_NOTICE_ACKED = "followup_notice_acked"
TL_NOTICE_NACKED = "followup_notice_nacked"


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #
def _now() -> float:
    return time.time()


def _timeline(conn, sub_id: int, seq: int, event: str, detail: dict) -> None:
    conn.execute(
        "INSERT INTO disposition_timeline(sub_id, seq, at, event, detail_json) "
        "VALUES (?,?,?,?,?)",
        (sub_id, seq, _now(), event, json.dumps(detail, ensure_ascii=False)))


def _origin_event_digest(svc, sub_id: str, seq: int) -> str:
    ev = svc.store.query_one(
        "SELECT raw_payload FROM events WHERE sub_id=? AND seq=?", (sub_id, seq))
    return C.digest(C.canonical_payload(json.loads(ev["raw_payload"])))


def _next_queue_position(conn, sub_id: str) -> int:
    row = conn.execute(
        "SELECT next_queue_pos FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
    pos = row["next_queue_pos"]
    conn.execute("UPDATE subscriptions SET next_queue_pos=? WHERE id=?",
                 (pos + 1, sub_id))
    return pos


# --------------------------------------------------------------------------- #
# 创建处置
# --------------------------------------------------------------------------- #
def create_disposition(svc, *, sub_id: str, seq: int, action: str,
                       reason: str, corrected_payload: Any = None,
                       event_type: Optional[str] = None,
                       actor: Optional[str] = None,
                       idem_key: Optional[str] = None) -> dict:
    if action not in ("retract", "correct"):
        svc._reject(400, "invalid_disposition_action", {"action": action})
    if not isinstance(reason, str) or not reason.strip():
        svc._reject(400, "reason_required",
                    {"reason": "处置必须说明原因（非空字符串）"})
    if action == "correct":
        if corrected_payload is None or not isinstance(corrected_payload, dict):
            svc._reject(400, "corrected_payload_required",
                        {"reason": "更正处置必须携带对象类型的 corrected_payload"})
    svc._require_sub(sub_id)
    ev = svc.store.query_one(
        "SELECT event_type FROM events WHERE sub_id=? AND seq=?", (sub_id, seq))
    if not ev:
        svc._reject(404, "event_not_found", {"sub_id": sub_id, "seq": seq})
    if event_type is not None and event_type != ev["event_type"]:
        svc._reject(409, "event_type_mismatch",
                    {"expected": ev["event_type"], "given": event_type})

    fingerprint = svc._fingerprint({
        "sub_id": sub_id, "seq": seq, "action": action, "reason": reason,
        "event_type": event_type, "actor": actor,
        "corrected_payload": corrected_payload
        if action == "correct" else None})

    # 幂等：全局作用域——同一键改原事件/方式/原因/更正内容都必须显式冲突
    scope = "disposition"
    with svc.store.lock:
        hit = svc.store.idem_get(scope, idem_key) if idem_key else None
        if hit is not None:
            rec = svc._idem_cached(hit)
            if rec.get("_fingerprint") is not None \
                    and rec["_fingerprint"] != fingerprint:
                svc._reject(409, "idempotency_request_conflict", {
                    "operation": "disposition", "idempotency_key": idem_key,
                    "reason": "同一幂等键绑定的处置请求内容与首次提交不一致"
                              "（原事件/处置方式/原因/更正内容任一变化都必须显式冲突）",
                    "first_request_fingerprint": rec["_fingerprint"],
                    "request_fingerprint": fingerprint})
            disp_id = rec["_response"]["disposition_id"]
            return _view(svc, disp_id, replayed=True)

        # 同一接收端同一原事件同时只允许一个未终结处置
        inflight = svc.store.query_one(
            "SELECT id FROM dispositions WHERE sub_id=? AND seq=? AND status='pending' "
            "ORDER BY created_at DESC LIMIT 1", (sub_id, seq))
        if inflight:
            svc._reject(409, "disposition_already_pending",
                        {"sub_id": sub_id, "seq": seq,
                         "pending_disposition_id": inflight["id"],
                         "reason": "该原事件已有进行中的处置，请等其终结后再发起"})

        disp_id = f"disp_{uuid.uuid4().hex}"
        conn = svc.store.begin()
        conn.execute(
            "INSERT INTO dispositions(id, sub_id, seq, action, reason, event_type, "
            "corrected_payload, actor, status, idem_key, fingerprint, created_at) "
            "VALUES (?,?,?,?,?,?,?,?, 'pending', ?, ?, ?)",
            (disp_id, sub_id, seq, action, reason, event_type,
             json.dumps(corrected_payload, ensure_ascii=False)
             if corrected_payload is not None else None,
             actor, idem_key, fingerprint, _now()))
        conn.execute(
            "INSERT INTO disposition_targets(disposition_id, sub_id, seq, state, "
            "outcome_action, original_status, created_at) "
            "VALUES (?,?,?, 'pending', ?, ?, ?)",
            (disp_id, sub_id, seq, action,
             _original_status(svc, sub_id, seq), _now()))
        _timeline(conn, sub_id, seq, TL_DISPOSITION_REQUESTED, {
            "disposition_id": disp_id, "action": action, "reason": reason,
            "actor": actor, "idempotency_key": idem_key})
        svc.audit("disposition_requested", {
            "disposition_id": disp_id, "sub_id": sub_id, "seq": seq,
            "action": action}, sub_id)
        svc.store.commit()

        _process_target(svc, disp_id)

        if idem_key:
            conn = svc.store.begin()
            svc.store.idem_put(scope, idem_key, {"disposition_id": disp_id},
                               fingerprint)
            svc.store.commit()

    return _view(svc, disp_id)


def _original_status(svc, sub_id: str, seq: int) -> str:
    n = svc.store.query_one(
        "SELECT status FROM notifications WHERE sub_id=? AND seq=?", (sub_id, seq))
    return n["status"] if n else "not_frozen"


# --------------------------------------------------------------------------- #
# 接收端决策（每接收端独立事务；失败只落本接收端 failed，不改原通知）
# --------------------------------------------------------------------------- #
def _process_target(svc, disp_id: str) -> None:
    """按原通知当前发送状态把处置落到唯一一种稳定结果。调用方持锁。"""
    disp = svc.store.query_one(
        "SELECT * FROM dispositions WHERE id=?", (disp_id,))
    target = svc.store.query_one(
        "SELECT * FROM disposition_targets WHERE disposition_id=?", (disp_id,))
    if not disp or not target or target["state"] != "pending":
        return
    sub_id, seq = disp["sub_id"], disp["seq"]
    notif = svc.store.query_one(
        "SELECT * FROM notifications WHERE sub_id=? AND seq=?", (sub_id, seq))

    if not notif:
        _fail_target(svc, disp, target, "precondition", "notification_not_frozen",
                     "原事件尚未冻结出通知（未扫描/无治理契约），无可处置对象")
        return
    status = notif["status"]
    if status == "sending":
        # 与发送结果竞争：挂起，等 ack/nack（或重启续跑）裁决，只落一种结果
        conn = svc.store.begin()
        _timeline(conn, sub_id, seq, TL_DISPOSITION_PARKED, {
            "disposition_id": disp_id,
            "notification_id": notif["notification_id"],
            "reason": "原通知正在发送：处置挂起，等待发送结果裁决"
                      "（ack→追加后续通知；nack→取消/原位替换）"})
        svc.store.commit()
        return
    if status == "cancelled":
        _fail_target(svc, disp, target, "precondition",
                     "original_notification_cancelled",
                     "原通知已被先前处置原子取消：既未发送也不能在其后追加通知")
        return
    if status in ("queued", "blocked"):
        if disp["action"] == "retract":
            _atomic_cancel(svc, disp, target, notif)
        else:
            _atomic_replace(svc, disp, target, notif)
        return
    if status == "delivered":
        _append_followup(svc, disp, target, notif)
        return
    _fail_target(svc, disp, target, "precondition", "unexpected_notification_status",
                 f"原通知状态 {status!r} 不允许处置")  # pragma: no cover


def _fail_target(svc, disp, target, stage: str, reason: str,
                 message: str, detail: Optional[dict] = None) -> None:
    conn = svc.store.begin()
    conn.execute(
        "UPDATE disposition_targets SET state='failed', failure_stage=?, "
        "failure_reason=?, fail_detail_json=?, finished_at=? WHERE id=?",
        (stage, reason,
         json.dumps(detail or {"message": message}, ensure_ascii=False),
         _now(), target["id"]))
    conn.execute("UPDATE dispositions SET status='failed', finished_at=? WHERE id=?",
                 (_now(), disp["id"]))
    _timeline(conn, disp["sub_id"], disp["seq"], TL_DISPOSITION_FAILED, {
        "disposition_id": disp["id"], "action": disp["action"],
        "failure_stage": stage, "failure_reason": reason, "message": message})
    svc.audit("disposition_failed", {
        "disposition_id": disp["id"], "sub_id": disp["sub_id"],
        "seq": disp["seq"], "action": disp["action"],
        "failure_stage": stage, "failure_reason": reason}, disp["sub_id"])
    svc.store.commit()


def _prepare_correction(svc, disp, notif) -> dict:
    """更正内容三关：当前生效契约校验 → 来源说明 →（签名留给调用方）。

    任何一步失败：抛 Reject，调用方捕获后落 failed，绝不改原通知。
    """
    sub_id, seq = disp["sub_id"], disp["seq"]
    payload = json.loads(disp["corrected_payload"])
    current = svc._contract_at(sub_id, notif["event_type"], seq)
    if current is None:
        svc._reject(422, "correction_no_active_contract", {
            "seq": seq, "reason": "更正内容必须重新经过当前生效载荷契约校验，"
                                  "但该序号当前没有生效契约"})
    version, spec = current["version"], current["spec"]
    normalized, errors, infos = C.check_and_normalize(spec, payload)
    if errors:
        svc._reject(422, "correction_contract_validation_failed", {
            "seq": seq, "contract_version": version, "errors": errors})
    entries = P.build_correction_entries(spec, normalized, infos)
    frozen = C.canonical_payload(normalized)
    return {"payload": normalized, "spec": spec, "version": version,
            "entries": entries, "frozen": frozen,
            "digest": C.digest(frozen), "infos": infos}


def _sign_notice(svc, *, kind: str, notification_id: str, notif,
                 payload_digest: str, disp, prepared: Optional[dict],
                 include_payload: bool) -> dict:
    """构造关联信封并签名；签名失败抛 SigningError（调用方不得落库任何结果）。"""
    relation = {
        "original_notification_id": notif["notification_id"],
        "original_seq": disp["seq"],
        "original_event_digest": _origin_event_digest(svc, disp["sub_id"], disp["seq"]),
        "disposition_id": disp["id"],
        "action": disp["action"],
    }
    envelope = svc.store.signer.build_envelope(
        kind=kind, notification_id=notification_id,
        event_type=notif["event_type"], payload_digest=payload_digest,
        sub_id=disp["sub_id"], seq=disp["seq"], relation=relation)
    envelope["reason"] = disp["reason"]
    if disp["actor"] is not None:
        envelope["actor"] = disp["actor"]
    if include_payload:
        envelope["payload"] = prepared["payload"]
        envelope["contract_version"] = prepared["version"]
        envelope["field_provenance"] = prepared["entries"]
    signature = svc.store.signer.sign(envelope)
    return {"envelope": envelope, "signature": signature}


def _atomic_cancel(svc, disp, target, notif) -> None:
    """未开始发送的撤回：原子取消原任务，不产生任何新通知。"""
    sub_id, seq = disp["sub_id"], disp["seq"]
    conn = svc.store.begin()
    cur = conn.execute(
        "SELECT status FROM notifications WHERE sub_id=? AND seq=?",
        (sub_id, seq)).fetchone()
    if cur is None or cur["status"] not in ("queued", "blocked"):
        svc.store.rollback()
        _process_target(svc, disp["id"])  # 状态已迁移（重启/并发）：重新裁决
        return
    was_blocked = cur["status"] == "blocked"
    # 条件更新：只有仍是未发送状态才取消；affected==0 意味着发送结果抢先
    cur = conn.execute(
        "UPDATE notifications SET status='cancelled', cancelled_at=? "
        "WHERE sub_id=? AND seq=? AND status IN ('queued','blocked')",
        (_now(), sub_id, seq))
    if cur.rowcount == 0:
        svc.store.rollback()
        _process_target(svc, disp["id"])
        return
    # 来源链追加一次"撤回取消"尝试（载荷摘要保持旧值，链不断、绑定一致）
    attempt_no = svc._next_attempt_no(sub_id, seq)
    prev_digest = svc._latest_record_digest(sub_id, seq)
    svc._append_attempt_locked(
        sub_id, seq, notif["notification_id"], notif["event_type"],
        attempt_no, "disposition_retract", "cancelled",
        notif["contract_version"], notif["digest"], notif["digest"],
        [], prev_digest, idem_key=disp["idem_key"], applied=[])
    if was_blocked:
        conn.execute(
            "UPDATE quarantines SET status='dead', recovered_at=? "
            "WHERE sub_id=? AND seq=? AND status='blocked'",
            (_now(), sub_id, seq))
        conn.execute("UPDATE subscriptions SET scan_seq=? WHERE id=?", (seq, sub_id))
    conn.execute(
        "UPDATE disposition_targets SET state='cancelled', "
        "original_notification_id=?, finished_at=? WHERE id=?",
        (notif["notification_id"], _now(), target["id"]))
    conn.execute("UPDATE dispositions SET status='applied', finished_at=? WHERE id=?",
                 (_now(), disp["id"]))
    _timeline(conn, sub_id, seq, TL_NOTIFICATION_CANCELLED, {
        "disposition_id": disp["id"],
        "notification_id": notif["notification_id"],
        "queue_position": notif["queue_position"],
        "reason": "原通知尚未开始发送，撤回原子取消原任务（无后续通知）"})
    svc.audit("disposition_applied", {
        "disposition_id": disp["id"], "sub_id": sub_id, "seq": seq,
        "action": "retract", "result": "cancelled"}, sub_id)
    svc.store.commit()
    if was_blocked:
        svc._pump_locked(sub_id)  # 解除 HOL，后续通知继续（顺序不变）


def _atomic_replace(svc, disp, target, notif) -> None:
    """未开始发送的更正：同一排队位置原位替换为新通知（身份不变）。"""
    sub_id, seq = disp["sub_id"], disp["seq"]
    # 三关前两关：契约校验 + 来源说明（失败不改原通知）
    try:
        prepared = _prepare_correction(svc, disp, notif)
    except Exception as e:
        svc.store.rollback()
        _record_prepare_failure(svc, disp, target, notif, e)
        return

    conn = svc.store.begin()
    cur = conn.execute(
        "SELECT status FROM notifications WHERE sub_id=? AND seq=?",
        (sub_id, seq)).fetchone()
    if cur is None or cur["status"] not in ("queued", "blocked"):
        svc.store.rollback()
        _process_target(svc, disp["id"])
        return
    was_blocked = cur["status"] == "blocked"
    # 第三关：签名必须在任何写入之前完成；失败则整笔回滚，原通知原样不动
    try:
        signed = _sign_notice(
            svc, kind="corrected",
            notification_id=notif["notification_id"], notif=notif,
            payload_digest=prepared["digest"], disp=disp,
            prepared=prepared, include_payload=False)
    except SigningError as e:
        svc.store.rollback()
        _fail_target(svc, disp, target, "signing", "correction_signing_failed",
                     str(e), {"message": "更正签名失败，原通知未改变"})
        return
    upd = conn.execute(
        "UPDATE notifications SET contract_version=?, frozen_payload=?, digest=?, "
        "validation=?, status='queued', superseded=1 "
        "WHERE sub_id=? AND seq=? AND status IN ('queued','blocked')",
        (prepared["version"], prepared["frozen"].decode("utf-8"),
         prepared["digest"],
         json.dumps({"valid": True, "corrected": True,
                     "supersedes_notification_id": notif["notification_id"],
                     "disposition_id": disp["id"], "errors": [],
                     "infos": prepared["infos"]}, ensure_ascii=False),
         sub_id, seq))
    if upd.rowcount == 0:
        svc.store.rollback()
        _process_target(svc, disp["id"])
        return
    rev_no = conn.execute(
        "SELECT COALESCE(MAX(revision_no),0)+1 n FROM notification_revisions "
        "WHERE sub_id=? AND seq=?", (sub_id, seq)).fetchone()["n"]
    conn.execute(
        "INSERT INTO notification_revisions(sub_id, seq, notification_id, revision_no, "
        "contract_version, frozen_payload, digest, validation, signature_json, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (sub_id, seq, notif["notification_id"], rev_no, prepared["version"],
         prepared["frozen"].decode("utf-8"), prepared["digest"],
         json.dumps({"valid": True, "corrected": True}, ensure_ascii=False),
         json.dumps(signed["signature"], ensure_ascii=False), _now()))
    attempt_no = svc._next_attempt_no(sub_id, seq)
    prev_digest = svc._latest_record_digest(sub_id, seq)
    svc._append_attempt_locked(
        sub_id, seq, notif["notification_id"], notif["event_type"],
        attempt_no, "disposition_correct", "replaced",
        prepared["version"], prepared["digest"], prepared["digest"],
        prepared["entries"], prev_digest, idem_key=disp["idem_key"], applied=[])
    if was_blocked:
        conn.execute(
            "UPDATE quarantines SET status='recovered', recovered_at=?, "
            "retry_count=retry_count+1 WHERE sub_id=? AND seq=? AND status='blocked'",
            (_now(), sub_id, seq))
        conn.execute("UPDATE subscriptions SET scan_seq=? WHERE id=?", (seq, sub_id))
    conn.execute(
        "UPDATE disposition_targets SET state='replaced', original_status=?, "
        "original_notification_id=?, result_notification_id=?, finished_at=? WHERE id=?",
        (("blocked" if was_blocked else "queued"), notif["notification_id"],
         notif["notification_id"], _now(), target["id"]))
    conn.execute("UPDATE dispositions SET status='applied', finished_at=? WHERE id=?",
                 (_now(), disp["id"]))
    _timeline(conn, sub_id, seq, TL_NOTIFICATION_SUPERSEDED, {
        "disposition_id": disp["id"],
        "notification_id": notif["notification_id"],
        "revision_no": rev_no, "queue_position": notif["queue_position"],
        "contract_version": prepared["version"], "digest": prepared["digest"],
        "signature_kid": signed["signature"]["kid"],
        "reason": "原通知尚未开始发送，更正在同一排队位置原位替换（投递身份不变）"})
    svc.audit("disposition_applied", {
        "disposition_id": disp["id"], "sub_id": sub_id, "seq": seq,
        "action": "correct", "result": "replaced",
        "revision_no": rev_no, "digest": prepared["digest"]}, sub_id)
    svc.store.commit()
    if was_blocked:
        svc._pump_locked(sub_id)


def _record_prepare_failure(svc, disp, target, notif, exc) -> None:
    """契约校验/来源说明阶段失败：按 failed 落档，原通知不变。"""
    from .service import Reject
    if isinstance(exc, Reject):
        _fail_target(svc, disp, target, "validation", exc.reason,
                     "更正内容未通过当前生效载荷契约校验/来源说明", exc.detail)
    else:  # pragma: no cover
        _fail_target(svc, disp, target, "validation", "correction_prepare_failed",
                     str(exc))


def _append_followup(svc, disp, target, notif) -> None:
    """已送达后：原通知不动，在其后追加一条带关联的撤回/更正通知。"""
    sub_id, seq = disp["sub_id"], disp["seq"]
    prepared = None
    if disp["action"] == "correct":
        try:
            prepared = _prepare_correction(svc, disp, notif)
        except Exception as e:
            _record_prepare_failure(svc, disp, target, notif, e)
            return
        payload_digest = prepared["digest"]
        kind = "correction"
        include_payload = True
    else:
        payload_digest = notif["digest"]
        kind = "retraction"
        include_payload = False

    notice_id = f"ntf_{uuid.uuid4().hex}"
    try:
        signed = _sign_notice(
            svc, kind=kind, notification_id=notice_id, notif=notif,
            payload_digest=payload_digest, disp=disp,
            prepared=prepared, include_payload=include_payload)
    except SigningError as e:
        _fail_target(svc, disp, target, "signing", "followup_signing_failed",
                     str(e), {"message": "后续通知签名失败，原送达通知未改变"})
        return

    conn = svc.store.begin()
    # 再次确认原通知仍已送达（发送状态不会从 delivered 回退，这是稳定终态）
    cur = conn.execute(
        "SELECT status FROM notifications WHERE sub_id=? AND seq=?",
        (sub_id, seq)).fetchone()
    if cur is None or cur["status"] != "delivered":
        svc.store.rollback()
        _process_target(svc, disp["id"])
        return
    pos = _next_queue_position(conn, sub_id)
    conn.execute(
        "INSERT INTO disposition_notices(id, sub_id, seq, disposition_id, kind, "
        "event_type, envelope_json, payload_digest, contract_version, signature_json, "
        "status, queue_position, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (notice_id, sub_id, seq, disp["id"], kind, notif["event_type"],
         json.dumps(signed["envelope"], ensure_ascii=False), payload_digest,
         prepared["version"] if prepared else None,
         json.dumps(signed["signature"], ensure_ascii=False),
         "queued", pos, _now()))
    conn.execute(
        "UPDATE disposition_targets SET state='followup_queued', original_status=?, "
        "original_notification_id=?, result_notification_id=?, finished_at=? WHERE id=?",
        ("delivered", notif["notification_id"], notice_id, _now(), target["id"]))
    conn.execute("UPDATE dispositions SET status='applied', finished_at=? WHERE id=?",
                 (_now(), disp["id"]))
    _timeline(conn, sub_id, seq, TL_NOTICE_ENQUEUED, {
        "disposition_id": disp["id"], "notice_id": notice_id, "kind": kind,
        "after_notification_id": notif["notification_id"],
        "queue_position": pos, "original_queue_position": notif["queue_position"],
        "signature_kid": signed["signature"]["kid"],
        "reason": "原通知已确认送达，不可删除/改写；在其后追加带明确关联的后续通知"})
    svc.audit("disposition_applied", {
        "disposition_id": disp["id"], "sub_id": sub_id, "seq": seq,
        "action": disp["action"], "result": "followup_queued",
        "notice_id": notice_id, "queue_position": pos}, sub_id)
    svc.store.commit()


# --------------------------------------------------------------------------- #
# 发送侧：claim / ack / nack（原通知与后续通知各一套，令牌防错认）
# --------------------------------------------------------------------------- #
def claim_notification(svc, sub_id: str, seq: int, force: bool = False) -> dict:
    svc._require_sub(sub_id)
    with svc.store.lock:
        conn = svc.store.begin()
        notif = conn.execute(
            "SELECT * FROM notifications WHERE sub_id=? AND seq=?",
            (sub_id, seq)).fetchone()
        if not notif:
            svc.store.rollback()
            svc._reject(404, "notification_not_found", {"sub_id": sub_id, "seq": seq})
        if notif["status"] == "sending" and not force:
            svc.store.rollback()
            svc._reject(409, "notification_already_sending",
                        {"seq": seq, "delivery_token": notif["delivery_token"],
                         "reason": "同一通知同时只能被一个发送端领取；"
                                   "如确认前任发送端已死亡（如服务重启），可用 force_reclaim"})
        if notif["status"] not in ("queued", "sending"):
            svc.store.rollback()
            svc._reject(409, "notification_not_claimable",
                        {"seq": seq, "status": notif["status"]})
        token = "tok_" + uuid.uuid4().hex
        conn.execute(
            "UPDATE notifications SET status='sending', delivery_token=?, "
            "claimed_at=? WHERE sub_id=? AND seq=?",
            (token, _now(), sub_id, seq))
        _timeline(conn, sub_id, seq, TL_NOTIFICATION_CLAIMED, {
            "notification_id": notif["notification_id"],
            "delivery_token": token, "force_reclaim": force})
        svc.store.commit()
    return {"sub_id": sub_id, "seq": seq,
            "notification_id": notif["notification_id"],
            "event_type": notif["event_type"],
            "contract_version": notif["contract_version"],
            "payload": json.loads(notif["frozen_payload"]),
            "digest": notif["digest"], "queue_position": notif["queue_position"],
            "delivery_token": token, "status": "sending",
            "force_reclaimed": force and notif["status"] == "sending"}


def _finish_notification(svc, sub_id: str, seq: int, token: str, ack: bool) -> dict:
    with svc.store.lock:
        conn = svc.store.begin()
        notif = conn.execute(
            "SELECT * FROM notifications WHERE sub_id=? AND seq=?",
            (sub_id, seq)).fetchone()
        if not notif:
            svc.store.rollback()
            svc._reject(404, "notification_not_found", {"seq": seq})
        if notif["status"] not in ("sending", "delivered"):
            svc.store.rollback()
            svc._reject(409, "notification_not_sending",
                        {"seq": seq, "status": notif["status"]})
        if notif["delivery_token"] != token:
            svc.store.rollback()
            svc._reject(409, "delivery_token_mismatch",
                        {"seq": seq, "reason": "发送结果必须出示 claim 时发放的令牌"})
        if ack:
            if notif["status"] != "delivered":
                conn.execute(
                    "UPDATE notifications SET status='delivered', delivered_at=? "
                    "WHERE sub_id=? AND seq=? AND status='sending' AND delivery_token=?",
                    (_now(), sub_id, seq, token))
                _timeline(conn, sub_id, seq, TL_NOTIFICATION_ACKED, {
                    "notification_id": notif["notification_id"]})
                svc.audit("notification_delivered",
                          {"sub_id": sub_id, "seq": seq,
                           "notification_id": notif["notification_id"]}, sub_id)
            svc.store.commit()
            _resolve_pending(svc, sub_id, seq)  # 送达裁决：挂起处置→追加后续
            return {"seq": seq, "status": "delivered",
                    "notification_id": notif["notification_id"]}
        # nack：发送失败，通知退回 queued 等待重领；挂起处置按"未发送"裁决
        conn.execute(
            "UPDATE notifications SET status='queued', delivery_token=NULL, "
            "claimed_at=NULL WHERE sub_id=? AND seq=? AND status='sending' "
            "AND delivery_token=?",
            (sub_id, seq, token))
        _timeline(conn, sub_id, seq, TL_NOTIFICATION_NACKED, {
            "notification_id": notif["notification_id"],
            "reason": "发送端报告失败，通知退回队列；挂起处置按未发送裁决"})
        svc.store.commit()
        _resolve_pending(svc, sub_id, seq)
        return {"seq": seq, "status": "queued",
                "notification_id": notif["notification_id"]}


def claim_notice(svc, sub_id: str, notice_id: str, force: bool = False) -> dict:
    svc._require_sub(sub_id)
    with svc.store.lock:
        conn = svc.store.begin()
        row = conn.execute(
            "SELECT * FROM disposition_notices WHERE sub_id=? AND id=?",
            (sub_id, notice_id)).fetchone()
        if not row:
            svc.store.rollback()
            svc._reject(404, "followup_notice_not_found", {"notice_id": notice_id})
        # 顺序保证：前面还有可领取（未送达）的后续通知时不能跳领，
        # 避免后续通知相对原通知或彼此乱序
        if row["status"] == "queued":
            blocker = conn.execute(
                "SELECT id FROM disposition_notices WHERE sub_id=? "
                "AND queue_position<? AND status!='delivered' ORDER BY queue_position LIMIT 1",
                (sub_id, row["queue_position"])).fetchone()
            if blocker:
                svc.store.rollback()
                svc._reject(409, "followup_out_of_order", {
                    "notice_id": notice_id,
                    "blocked_by_notice_id": blocker["id"],
                    "reason": "必须按排队位置顺序领取后续通知"})
        if row["status"] == "sending" and not force:
            svc.store.rollback()
            svc._reject(409, "notice_already_sending", {"notice_id": notice_id})
        if row["status"] not in ("queued", "sending"):
            svc.store.rollback()
            svc._reject(409, "notice_not_claimable",
                        {"notice_id": notice_id, "status": row["status"]})
        token = "tok_" + uuid.uuid4().hex
        conn.execute(
            "UPDATE disposition_notices SET status='sending', delivery_token=?, "
            "claimed_at=? WHERE id=? AND sub_id=?",
            (token, _now(), notice_id, sub_id))
        _timeline(conn, sub_id, row["seq"], TL_NOTICE_CLAIMED,
                  {"notice_id": notice_id, "delivery_token": token,
                   "kind": row["kind"], "force_reclaim": force})
        svc.store.commit()
    envelope = json.loads(row["envelope_json"])
    return {"notice_id": notice_id, "sub_id": sub_id, "seq": row["seq"],
            "kind": row["kind"], "event_type": row["event_type"],
            "queue_position": row["queue_position"],
            "envelope": envelope,
            "signature": json.loads(row["signature_json"]),
            "payload_digest": row["payload_digest"],
            "delivery_token": token, "status": "sending"}


def _finish_notice(svc, sub_id: str, notice_id: str, token: str, ack: bool) -> dict:
    with svc.store.lock:
        conn = svc.store.begin()
        row = conn.execute(
            "SELECT * FROM disposition_notices WHERE sub_id=? AND id=?",
            (sub_id, notice_id)).fetchone()
        if not row:
            svc.store.rollback()
            svc._reject(404, "followup_notice_not_found", {"notice_id": notice_id})
        if row["status"] not in ("sending", "delivered"):
            svc.store.rollback()
            svc._reject(409, "notice_not_sending",
                        {"notice_id": notice_id, "status": row["status"]})
        if row["delivery_token"] != token:
            svc.store.rollback()
            svc._reject(409, "delivery_token_mismatch",
                        {"notice_id": notice_id})
        if ack:
            if row["status"] != "delivered":
                conn.execute(
                    "UPDATE disposition_notices SET status='delivered', "
                    "delivered_at=? WHERE id=? AND sub_id=? AND status='sending' "
                    "AND delivery_token=?",
                    (_now(), notice_id, sub_id, token))
                _timeline(conn, sub_id, row["seq"], TL_NOTICE_ACKED,
                          {"notice_id": notice_id, "kind": row["kind"]})
            svc.store.commit()
            return {"notice_id": notice_id, "status": "delivered"}
        conn.execute(
            "UPDATE disposition_notices SET status='queued', delivery_token=NULL, "
            "claimed_at=NULL WHERE id=? AND sub_id=? AND status='sending' "
            "AND delivery_token=?",
            (notice_id, sub_id, token))
        _timeline(conn, sub_id, row["seq"], TL_NOTICE_NACKED,
                  {"notice_id": notice_id, "kind": row["kind"]})
        svc.store.commit()
        return {"notice_id": notice_id, "status": "queued"}


# --------------------------------------------------------------------------- #
# 挂起处置裁决与重启续跑
# --------------------------------------------------------------------------- #
def _resolve_pending(svc, sub_id: str, seq: int) -> None:
    """发送结果落定后裁决挂起处置。调用方持锁。

    与发送结果在同一串行写锁下：状态迁移已经提交，这里读到的必然是
    delivered 或 queued 之一，处置只可能落到追加或取消/替换，稳定唯一。
    """
    rows = svc.store.query(
        "SELECT id FROM dispositions WHERE sub_id=? AND seq=? AND status='pending' "
        "ORDER BY created_at", (sub_id, seq))
    for r in rows:
        _process_target(svc, r["id"])


def resume_on_startup(svc) -> None:
    """重启后续跑未终结处置：按原通知当前状态重新裁决。

    - 原通知已送达 → 追加后续通知；
    - 已退回未发送 → 取消/原位替换；
    - 仍在 sending（发送端持有令牌、尚未报结果）→ 继续挂起，等 ack/nack。
    排队位置、关联通知、通知身份全部在表里，续跑不产生重复或乱序。
    """
    with svc.store.lock:
        rows = svc.store.query(
            "SELECT id FROM dispositions WHERE status='pending' ORDER BY created_at")
        for r in rows:
            try:
                _process_target(svc, r["id"])
            except Exception:  # pragma: no cover - 单条失败保留 pending，等下次续跑
                pass


# --------------------------------------------------------------------------- #
# 查询视图
# --------------------------------------------------------------------------- #
def _target_view(t) -> dict:
    return {
        "state": t["state"], "action": t["outcome_action"],
        "original_status_at_request": t["original_status"],
        "original_notification_id": t["original_notification_id"],
        "result_notification_id": t["result_notification_id"],
        "failure_stage": t["failure_stage"],
        "failure_reason": t["failure_reason"],
        "fail_detail": json.loads(t["fail_detail_json"])
        if t["fail_detail_json"] else None,
        "created_at": t["created_at"], "finished_at": t["finished_at"],
    }


def get_disposition(svc, disp_id: str) -> dict:
    return _view(svc, disp_id)


def _view(svc, disp_id: str, replayed: bool = False) -> dict:
    disp = svc.store.query_one(
        "SELECT * FROM dispositions WHERE id=?", (disp_id,))
    if not disp:
        svc._reject(404, "disposition_not_found", {"disposition_id": disp_id})
    targets = svc.store.query(
        "SELECT * FROM disposition_targets WHERE disposition_id=? ORDER BY id",
        (disp_id,))
    out = {
        "disposition_id": disp["id"], "sub_id": disp["sub_id"],
        "seq": disp["seq"], "action": disp["action"], "reason": disp["reason"],
        "event_type": disp["event_type"], "actor": disp["actor"],
        "status": disp["status"],
        "created_at": disp["created_at"], "finished_at": disp["finished_at"],
        "targets": [_target_view(t) for t in targets],
    }
    if replayed:
        out["replayed"] = True
    return out


def event_dispositions(svc, sub_id: str, seq: int) -> dict:
    """按原事件查看：原通知状态、各接收端处置、关联通知、失败原因、时间线。"""
    svc._require_sub(sub_id)
    ev = svc.store.query_one(
        "SELECT event_type, raw_payload FROM events WHERE sub_id=? AND seq=?",
        (sub_id, seq))
    if not ev:
        svc._reject(404, "event_not_found", {"sub_id": sub_id, "seq": seq})
    notif = svc.store.query_one(
        "SELECT * FROM notifications WHERE sub_id=? AND seq=?", (sub_id, seq))
    original = None
    if notif:
        revisions = svc.store.query(
            "SELECT revision_no, contract_version, digest, signature_json, created_at "
            "FROM notification_revisions WHERE sub_id=? AND seq=? ORDER BY revision_no",
            (sub_id, seq))
        original = {
            "notification_id": notif["notification_id"],
            "event_type": notif["event_type"],
            "contract_version": notif["contract_version"],
            "status": notif["status"],
            "digest": notif["digest"],
            "queue_position": notif["queue_position"],
            "superseded": bool(notif["superseded"]),
            "claimed_at": notif["claimed_at"],
            "delivered_at": notif["delivered_at"],
            "cancelled_at": notif["cancelled_at"],
            "revisions": [{
                "revision_no": r["revision_no"],
                "contract_version": r["contract_version"],
                "digest": r["digest"],
                "signature": json.loads(r["signature_json"])
                if r["signature_json"] else None,
                "created_at": r["created_at"]} for r in revisions],
        }
    disps = svc.store.query(
        "SELECT id FROM dispositions WHERE sub_id=? AND seq=? ORDER BY created_at",
        (sub_id, seq))
    notices = svc.store.query(
        "SELECT id, kind, status, queue_position, disposition_id, payload_digest, "
        "contract_version, signature_json, created_at, delivered_at "
        "FROM disposition_notices WHERE sub_id=? AND seq=? ORDER BY queue_position",
        (sub_id, seq))
    timeline = svc.store.query(
        "SELECT at, event, detail_json FROM disposition_timeline "
        "WHERE sub_id=? AND seq=? ORDER BY id", (sub_id, seq))
    return {
        "sub_id": sub_id, "seq": seq, "event_type": ev["event_type"],
        "original_event_digest": C.digest(
            C.canonical_payload(json.loads(ev["raw_payload"]))),
        "original_notification": original,
        "dispositions": [_view(svc, d["id"]) for d in disps],
        "followup_notices": [{
            "notice_id": n["id"], "kind": n["kind"], "status": n["status"],
            "queue_position": n["queue_position"],
            "disposition_id": n["disposition_id"],
            "payload_digest": n["payload_digest"],
            "contract_version": n["contract_version"],
            "signature_kid": (json.loads(n["signature_json"]).get("kid")
                              if n["signature_json"] else None),
            "created_at": n["created_at"], "delivered_at": n["delivered_at"],
        } for n in notices],
        "timeline": [{
            "at": r["at"], "event": r["event"],
            "detail": json.loads(r["detail_json"])} for r in timeline],
    }


def delivery_queue(svc, sub_id: str) -> dict:
    """接收端统一投递队列：原通知与后续通知按排队位置合并、严格有序。"""
    svc._require_sub(sub_id)
    items: List[dict] = []
    for n in svc.store.query(
            "SELECT seq, notification_id, event_type, status, queue_position, digest, "
            "cancelled_at, delivered_at, claimed_at, superseded "
            "FROM notifications WHERE sub_id=? ORDER BY queue_position", (sub_id,)):
        items.append({"kind": "original", "seq": n["seq"],
                      "notification_id": n["notification_id"],
                      "event_type": n["event_type"], "status": n["status"],
                      "queue_position": n["queue_position"], "digest": n["digest"],
                      "superseded": bool(n["superseded"])})
    for n in svc.store.query(
            "SELECT id, seq, kind, event_type, status, queue_position, payload_digest "
            "FROM disposition_notices WHERE sub_id=? ORDER BY queue_position",
            (sub_id,)):
        items.append({"kind": n["kind"], "seq": n["seq"],
                      "notification_id": n["id"],
                      "event_type": n["event_type"], "status": n["status"],
                      "queue_position": n["queue_position"],
                      "digest": n["payload_digest"]})
    items.sort(key=lambda x: x["queue_position"])
    return {"sub_id": sub_id, "queue": items}


def verify_notice_signature(svc, sub_id: str, notice_id: str) -> dict:
    """重算后续通知的信封签名（管理员/接收端校验关联通知真实性）。"""
    row = svc.store.query_one(
        "SELECT envelope_json, signature_json FROM disposition_notices "
        "WHERE sub_id=? AND id=?", (sub_id, notice_id))
    if not row:
        svc._reject(404, "followup_notice_not_found", {"notice_id": notice_id})
    envelope = json.loads(row["envelope_json"])
    signature = json.loads(row["signature_json"])
    ok, problems = svc.store.signer.verify(envelope, signature)
    return {"notice_id": notice_id, "verified": ok, "problems": problems,
            "kid": signature.get("kid"),
            "relation": envelope.get("relation")}
