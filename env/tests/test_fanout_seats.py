"""投递席位：有序备用接收端 + 切换期限。

覆盖：主接收端按时成功、超时启用备用、手动提前切换、旧接收端迟到回执、
成功与切换并发（两个方向 + 真线程竞争）、候选全部耗尽、多个席位独立
推进、回执幂等与服务重启后继续原期限和切换历史。
"""

import threading

from app.app import create_app


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def make_policy(client, mode="all", quorum_count=None, expect=201):
    data = {"mode": mode}
    if quorum_count is not None:
        data["quorum_count"] = quorum_count
    rv = client.post("/audit/fanout/policies", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json() if expect == 201 else rv


def make_seat_notification(client, seats, payload=None, expect=201, **kw):
    data = {
        "payload": payload if payload is not None else {"audit": "evt-1"},
        "seats": seats,
    }
    data.update(kw)
    rv = client.post("/audit/fanout/notifications", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json() if expect == 201 else rv


def new_seat_notification(client, seats, mode="all", quorum_count=None):
    """新建一个策略版本 + 一条席位通知，返回通知视图。"""
    make_policy(client, mode, quorum_count)
    return make_seat_notification(client, seats)


def receipt(client, nid, rid, key, content=None, expect=201):
    data = {"recipient_id": rid, "idempotency_key": key}
    if content is not None:
        data["content"] = content
    rv = client.post(f"/audit/fanout/notifications/{nid}/receipts", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def failure(client, nid, rid, detail="boom", expect=200):
    rv = client.post(
        f"/audit/fanout/notifications/{nid}/recipients/{rid}/failures",
        json={"detail": detail})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def switch(client, nid, sid, expect=201, **data):
    rv = client.post(
        f"/audit/fanout/notifications/{nid}/seats/{sid}/switch",
        json=data or None)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def get_notification(client, nid, expect=200):
    rv = client.get(f"/audit/fanout/notifications/{nid}")
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def get_seat(client, nid, sid, expect=200):
    rv = client.get(f"/audit/fanout/notifications/{nid}/seats/{sid}")
    assert rv.status_code == expect, rv.get_json()
    if expect != 200:
        return rv.get_json()
    return rv.get_json()["seat"]


def list_seats(client, nid):
    rv = client.get(f"/audit/fanout/notifications/{nid}/seats")
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


def seat_history(client, nid, sid):
    rv = client.get(f"/audit/fanout/notifications/{nid}/seats/{sid}/history")
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()["events"]


def process_deadlines(client):
    rv = client.post("/audit/fanout/notifications/process-deadlines")
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


def wall_shift(client, delta_ms):
    rv = client.post("/debug/wall-shift", json={"delta_ms": delta_ms})
    assert rv.status_code == 200, rv.get_json()


def event_names(events):
    return [e["event"] for e in events]


def strip_remaining(seat):
    """remaining_ms 是读取时刻的实时计算值，跨重启比较时剔除。"""
    seat = dict(seat)
    if seat.get("current"):
        seat["current"] = {k: v for k, v in seat["current"].items()
                           if k != "remaining_ms"}
    seat["candidates"] = [
        {k: v for k, v in c.items() if k != "remaining_ms"}
        for c in seat["candidates"]]
    return seat


# ---------------------------------------------------------------------------
# 主接收端在期限内成功：席位立即成功，备用永远不再启用
# ---------------------------------------------------------------------------

def test_primary_success_within_deadline(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000,
         "candidates": ["p", "b1", "b2"]},
    ])
    nid = view["notification_id"]
    assert view["structure"] == "seats"
    assert view["policy"]["required_successes"] == 1
    seat = view["seats"][0]
    assert seat["state"] == "pending"
    assert seat["current"]["recipient_id"] == "p"
    assert seat["current"]["seq"] == 1
    assert seat["current"]["deadline_at_ms"] is not None
    assert seat["next_candidate"] == {"seq": 2, "recipient_id": "b1"}
    assert [c["state"] for c in seat["candidates"]] == [
        "active", "waiting", "waiting"]

    r = receipt(client, nid, "p", "k-p")
    assert r["seat_state"] == "succeeded"
    assert r["candidate_state"] == "succeeded"
    assert r["notification_status"] == "completed"
    assert r["already_succeeded"] is False

    seat = get_seat(client, nid, "s1")
    assert seat["state"] == "succeeded"
    assert seat["succeeded_by"] == "p"
    assert seat["current"] is None            # 席位已定，没有处理人
    assert seat["next_candidate"] is None     # 备用永远不再启用
    assert [c["state"] for c in seat["candidates"]] == [
        "succeeded", "waiting", "waiting"]

    # 已成功的席位不能再切换
    s = switch(client, nid, "s1", expect=409)
    assert s["error"] == "fanout_seat_succeeded"
    assert s["winner"]["type"] == "receipt"
    assert s["winner"]["recipient_id"] == "p"

    # 备用候选保持 waiting，迟到回执明确拒绝
    late = receipt(client, nid, "b1", "k-b1", expect=409)
    assert late["error"] == "fanout_candidate_superseded"
    assert late["winner"]["type"] == "receipt"
    assert late["winner"]["recipient_id"] == "p"

    # 完整历史：创建 -> 主接收端启用 -> 回执受理 -> 席位成功 -> 拒绝迟到回执
    events = seat_history(client, nid, "s1")
    assert event_names(events) == [
        "seat_created", "candidate_activated", "receipt_accepted",
        "seat_succeeded", "receipt_rejected"]
    assert events[1]["recipient_id"] == "p"
    assert events[1]["reason"] == "initial"
    assert events[4]["recipient_id"] == "b1"
    assert events[4]["reason"] == "candidate_superseded"


# ---------------------------------------------------------------------------
# 超时启用备用：期限到达按顺序启用下一位
# ---------------------------------------------------------------------------

def test_timeout_activates_next_backup_in_order(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1_000,
         "candidates": ["p", "b1", "b2"]},
    ])
    nid = view["notification_id"]
    first_deadline = view["seats"][0]["current"]["deadline_at_ms"]

    # 期限未到：不切换（留足余量，真实墙钟流逝不影响判定）
    wall_shift(client, 500)
    assert process_deadlines(client)["count"] == 0
    assert get_seat(client, nid, "s1")["current"]["recipient_id"] == "p"

    # 期限到达：p 被替换，b1 按顺序接任并重算期限
    wall_shift(client, 600)
    result = process_deadlines(client)
    assert result["count"] == 1
    sw = result["switches"][0]
    assert sw["seat_id"] == "s1"
    assert sw["from"] == {"seq": 1, "recipient_id": "p",
                          "reason": "timeout_expired"}
    assert sw["to"]["seq"] == 2
    assert sw["to"]["recipient_id"] == "b1"
    assert sw["to"]["deadline_at_ms"] > first_deadline

    seat = get_seat(client, nid, "s1")
    assert seat["state"] == "pending"
    assert seat["current"]["recipient_id"] == "b1"
    assert seat["next_candidate"] == {"seq": 2 + 1, "recipient_id": "b2"}
    assert seat["last_switch"]["reason"] == "timeout_expired"
    assert seat["last_switch"]["from_recipient_id"] == "p"
    assert seat["last_switch"]["to_recipient_id"] == "b1"
    assert [c["state"] for c in seat["candidates"]] == [
        "superseded", "active", "waiting"]
    assert seat["candidates"][0]["end_reason"] == "timeout_expired"

    # 再超时一次：b1 -> b2
    wall_shift(client, 1_001)
    assert process_deadlines(client)["count"] == 1
    seat = get_seat(client, nid, "s1")
    assert seat["current"]["recipient_id"] == "b2"
    assert seat["next_candidate"] is None

    # 最后一位备用在期限内成功：席位成功，此后不再有切换
    r = receipt(client, nid, "b2", "k-b2")
    assert r["seat_state"] == "succeeded"
    assert r["notification_status"] == "completed"
    wall_shift(client, 10_000)
    assert process_deadlines(client)["count"] == 0

    # 历史里两次超时切换原因完整
    events = seat_history(client, nid, "s1")
    superseded = [e for e in events if e["event"] == "candidate_superseded"]
    assert [(e["recipient_id"], e["reason"]) for e in superseded] == [
        ("p", "timeout_expired"), ("b1", "timeout_expired")]
    activated = [e for e in events if e["event"] == "candidate_activated"]
    assert [e["recipient_id"] for e in activated] == ["p", "b1", "b2"]


# ---------------------------------------------------------------------------
# 手动提前切换：管理员放弃当前接收端
# ---------------------------------------------------------------------------

def test_manual_switch_abandons_current_and_activates_backup(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000,
         "candidates": ["p", "b1", "b2"]},
    ])
    nid = view["notification_id"]

    # 指错期望接收端：409，可判断当前实际由谁处理
    bad = switch(client, nid, "s1", expect=409,
                 expected_recipient_id="ghost")
    assert bad["error"] == "fanout_seat_switch_conflict"
    assert bad["expected_recipient_id"] == "ghost"
    assert bad["current_candidate"]["recipient_id"] == "p"

    # 带原因与幂等键的手动切换
    s = switch(client, nid, "s1", reason="主接收端失联",
               expected_recipient_id="p", idempotency_key="sw-1")
    assert s["replayed"] is False
    assert s["switch"]["from"] == {"seq": 1, "recipient_id": "p",
                                   "reason": "manual_abandon"}
    assert s["switch"]["to"]["recipient_id"] == "b1"
    assert s["seat"]["current"]["recipient_id"] == "b1"
    assert s["seat"]["last_switch"]["reason"] == "manual_abandon"

    # 同幂等键重放：200 回放首次结果，不产生第二次切换
    replay = switch(client, nid, "s1", expect=200, reason="主接收端失联",
                    expected_recipient_id="p", idempotency_key="sw-1")
    assert replay["replayed"] is True
    assert replay["switch"] == s["switch"]
    assert get_seat(client, nid, "s1")["current"]["recipient_id"] == "b1"
    superseded = [e for e in seat_history(client, nid, "s1")
                  if e["event"] == "candidate_superseded"]
    assert len(superseded) == 1

    # 再手动放弃 b1 -> b2，b2 成功
    switch(client, nid, "s1", idempotency_key="sw-2")
    r = receipt(client, nid, "b2", "k-b2")
    assert r["notification_status"] == "completed"


# ---------------------------------------------------------------------------
# 旧接收端的迟到回执：明确拒绝，不算到当前席位
# ---------------------------------------------------------------------------

def test_late_receipt_from_replaced_recipient_rejected(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1_000,
         "candidates": ["p", "b1"]},
        {"seat_id": "s2", "switch_after_ms": 60_000,
         "candidates": ["q"]},
    ])
    nid = view["notification_id"]

    # 手动切换后，旧接收端 p 的迟到回执：409 + 胜负信息
    switch(client, nid, "s1", idempotency_key="sw-1")
    late = receipt(client, nid, "p", "k-p", expect=409)
    assert late["error"] == "fanout_candidate_superseded"
    assert late["seat_id"] == "s1"
    assert late["end_reason"] == "manual_abandon"
    assert late["winner"]["type"] == "switch"
    assert late["winner"]["reason"] == "manual_abandon"
    assert late["winner"]["current_candidate"]["recipient_id"] == "b1"

    # 迟到回执不算数：p 没有尝试记录，席位仍 pending
    seat = get_seat(client, nid, "s1")
    assert seat["state"] == "pending"
    assert seat["candidates"][0]["attempts"] == 0
    rv = client.get(f"/audit/fanout/notifications/{nid}/recipients/p/attempts")
    assert rv.get_json()["attempts"] == []

    # 超时切换后，b1 的迟到回执同样被拒（原因换成 timeout_expired）
    wall_shift(client, 1_001)
    process_deadlines(client)  # s1 候选耗尽 -> 席位终止
    late2 = receipt(client, nid, "b1", "k-b1", expect=409)
    assert late2["error"] == "fanout_candidate_superseded"
    assert late2["winner"]["type"] == "exhausted"

    # 拒绝都进了完整历史
    rejected = [e for e in seat_history(client, nid, "s1")
                if e["event"] == "receipt_rejected"]
    assert [e["recipient_id"] for e in rejected] == ["p", "b1"]

    # s2 不受影响，q 成功即完成（all 模式里 s1 已终止 -> 通知已失败）
    final = get_notification(client, nid)
    assert final["status"] == "failed"  # all：s1 终止即不可能满足
    r = receipt(client, nid, "q", "k-q", expect=409)
    assert r["error"] == "fanout_notification_decided"


# ---------------------------------------------------------------------------
# 成功回执与切换并发：只有一个结果生效，另一个拿到可判断胜负的 409
# ---------------------------------------------------------------------------

def test_receipt_then_switch_conflict_shows_winner(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000,
         "candidates": ["p", "b1"]},
    ])
    nid = view["notification_id"]
    receipt(client, nid, "p", "k-p")  # 回执先到：席位成功

    s = switch(client, nid, "s1", expect=409)
    assert s["error"] == "fanout_seat_succeeded"
    assert s["winner"]["type"] == "receipt"
    assert s["winner"]["recipient_id"] == "p"
    # 切换没有发生：备用仍是 waiting
    seat = get_seat(client, nid, "s1")
    assert seat["candidates"][1]["state"] == "waiting"


def test_switch_then_receipt_conflict_shows_winner(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000,
         "candidates": ["p", "b1"]},
    ])
    nid = view["notification_id"]
    switch(client, nid, "s1", idempotency_key="sw-1")  # 切换先到

    r = receipt(client, nid, "p", "k-p", expect=409)
    assert r["error"] == "fanout_candidate_superseded"
    assert r["winner"]["type"] == "switch"
    assert r["winner"]["reason"] == "manual_abandon"
    assert r["winner"]["current_candidate"]["recipient_id"] == "b1"
    # 席位没有因为迟到回执成功
    assert get_seat(client, nid, "s1")["state"] == "pending"


def test_receipt_vs_timeout_deadline_is_hard_cutoff(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1_000,
         "candidates": ["p", "b1"]},
    ])
    nid = view["notification_id"]

    # 期限之后到达的回执：超时赢，回执 409 且能判断输给了哪次切换
    wall_shift(client, 1_001)
    r = receipt(client, nid, "p", "k-p", expect=409)
    assert r["error"] == "fanout_candidate_superseded"
    assert r["winner"]["type"] == "switch"
    assert r["winner"]["reason"] == "timeout_expired"
    assert r["winner"]["current_candidate"]["recipient_id"] == "b1"
    assert get_seat(client, nid, "s1")["current"]["recipient_id"] == "b1"


def test_receipt_before_deadline_wins_over_timeout(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1_000,
         "candidates": ["p", "b1"]},
    ])
    nid = view["notification_id"]
    wall_shift(client, 500)
    r = receipt(client, nid, "p", "k-p")  # 期限内：回执赢
    assert r["seat_state"] == "succeeded"
    # 之后再结算期限：席位已成功，没有切换发生
    wall_shift(client, 5_000)
    assert process_deadlines(client)["count"] == 0
    assert get_seat(client, nid, "s1")["state"] == "succeeded"


def test_concurrent_receipt_and_switch_exactly_one_wins(tmp_path):
    """真线程竞争：回执与手动切换同时到达，恰好一个成功、一个 409。"""
    db = tmp_path / "race.db"
    app = create_app(str(db), start_ticker=False, enable_debug_api=True,
                     start_archive_worker=False)
    app.config.update(TESTING=True)
    client = app.test_client()
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 3_600_000,
         "candidates": ["p", "b1"]},
    ])
    nid = view["notification_id"]

    results = {}

    def do_receipt():
        with app.test_client() as c:
            rv = c.post(f"/audit/fanout/notifications/{nid}/receipts",
                        json={"recipient_id": "p", "idempotency_key": "k-p"})
            results["receipt"] = (rv.status_code, rv.get_json())

    def do_switch():
        with app.test_client() as c:
            rv = c.post(f"/audit/fanout/notifications/{nid}/seats/s1/switch",
                        json={"idempotency_key": "sw-race"})
            results["switch"] = (rv.status_code, rv.get_json())

    threads = [threading.Thread(target=do_receipt),
               threading.Thread(target=do_switch)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = sorted(results[k][0] for k in ("receipt", "switch"))
    assert codes == [201, 409]  # 恰好一个赢家

    receipt_code, receipt_body = results["receipt"]
    switch_code, switch_body = results["switch"]
    seat = get_seat(client, nid, "s1")
    if receipt_code == 201:
        # 回执赢：席位成功，切换方收到带胜负信息的 409
        assert switch_body["error"] == "fanout_seat_succeeded"
        assert switch_body["winner"]["type"] == "receipt"
        assert seat["state"] == "succeeded"
        assert seat["succeeded_by"] == "p"
    else:
        # 切换赢：回执方收到带胜负信息的 409，席位由 b1 处理
        assert receipt_code == 409
        assert receipt_body["error"] == "fanout_candidate_superseded"
        assert receipt_body["winner"]["type"] == "switch"
        assert seat["state"] == "pending"
        assert seat["current"]["recipient_id"] == "b1"


# ---------------------------------------------------------------------------
# 候选全部耗尽：席位进入终止态，参与原送达策略可满足性判定
# ---------------------------------------------------------------------------

def test_all_candidates_failed_exhausts_seat_and_fails_notification(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000,
         "candidates": [{"recipient_id": "p", "max_attempts": 1},
                        {"recipient_id": "b1", "max_attempts": 1}]},
        {"seat_id": "s2", "switch_after_ms": 60_000, "candidates": ["q"]},
    ])
    nid = view["notification_id"]

    # p 失败达到上限：自动切换到 b1（原因 candidate_failed）
    f1 = failure(client, nid, "p", detail="err-1")
    assert f1["terminal"] is True
    assert f1["candidate_state"] == "superseded"
    assert f1["switched_to"]["recipient_id"] == "b1"
    assert f1["seat_state"] == "pending"
    assert f1["notification_status"] == "pending"

    # b1 也失败：候选耗尽，席位终止；all 模式随即明确失败
    f2 = failure(client, nid, "b1", detail="err-2")
    assert f2["seat_state"] == "exhausted"
    assert f2["switched_to"] is None
    assert f2["notification_status"] == "failed"

    final = get_notification(client, nid)
    assert final["status"] == "failed"
    decision = final["decision"]
    assert decision["reason"] == "policy_unsatisfiable"
    assert decision["exhausted"] == 1
    states = {s["seat_id"]: s["state"] for s in decision["seats"]}
    assert states == {"s1": "exhausted", "s2": "pending"}
    # 终止席位的候选快照也冻结进判定
    s1 = next(s for s in decision["seats"] if s["seat_id"] == "s1")
    assert [(c["recipient_id"], c["state"], c["end_reason"])
            for c in s1["candidates"]] == [
        ("p", "superseded", "candidate_failed"),
        ("b1", "superseded", "candidate_failed")]

    # 历史：两次失败记录 + 两次替换 + 席位终止
    events = seat_history(client, nid, "s1")
    assert event_names(events) == [
        "seat_created", "candidate_activated",
        "failure_recorded", "candidate_superseded", "candidate_activated",
        "failure_recorded", "candidate_superseded", "seat_exhausted"]


def test_manual_abandon_to_exhaustion_and_quorum_reevaluation(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000, "candidates": ["p"]},
        {"seat_id": "s2", "switch_after_ms": 60_000, "candidates": ["q"]},
        {"seat_id": "s3", "switch_after_ms": 60_000, "candidates": ["r"]},
    ], mode="quorum", quorum_count=2)
    nid = view["notification_id"]

    # 放弃 s1 唯一的候选：席位立即终止；quorum 仍可能满足（还剩 2 席）
    s = switch(client, nid, "s1", idempotency_key="sw-1")
    assert s["switch"]["to"] is None
    assert s["switch"]["seat_state"] == "exhausted"
    assert s["notification_status"] == "pending"
    assert s["progress"]["satisfiable"] is True

    # 已终止的席位不能再切换
    again = switch(client, nid, "s1", expect=409, idempotency_key="sw-2")
    assert again["error"] == "fanout_seat_exhausted"

    # s2 也终止：quorum=2 不再可能满足 -> 明确失败
    switch(client, nid, "s2", idempotency_key="sw-3")
    final = get_notification(client, nid)
    assert final["status"] == "failed"
    assert final["decision"]["reason"] == "policy_unsatisfiable"
    assert final["progress"]["satisfiable"] is False


# ---------------------------------------------------------------------------
# 多个席位独立推进
# ---------------------------------------------------------------------------

def test_multiple_seats_progress_independently(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1_000, "candidates": ["p1", "b1"]},
        {"seat_id": "s2", "switch_after_ms": 1_000, "candidates": ["p2", "b2"]},
        {"seat_id": "s3", "switch_after_ms": 1_000, "candidates": ["p3", "b3"]},
    ], mode="quorum", quorum_count=2)
    nid = view["notification_id"]

    # 三个席位同时超时：各自独立切换到自己的备用
    wall_shift(client, 1_001)
    result = process_deadlines(client)
    assert result["count"] == 3
    assert {s["seat_id"] for s in result["switches"]} == {"s1", "s2", "s3"}
    seats = {s["seat_id"]: s for s in list_seats(client, nid)["seats"]}
    assert seats["s1"]["current"]["recipient_id"] == "b1"
    assert seats["s2"]["current"]["recipient_id"] == "b2"
    assert seats["s3"]["current"]["recipient_id"] == "b3"

    # s1 备用成功：只推进 s1，其余席位不受影响
    r1 = receipt(client, nid, "b1", "k-b1")
    assert r1["notification_status"] == "pending"
    assert r1["progress"]["succeeded"] == 1
    seats = {s["seat_id"]: s for s in list_seats(client, nid)["seats"]}
    assert seats["s1"]["state"] == "succeeded"
    assert seats["s2"]["state"] == "pending"
    assert seats["s3"]["state"] == "pending"

    # s2 主接收端已被替换，其迟到回执被拒；s2 的备用成功 -> 达到 quorum
    late = receipt(client, nid, "p2", "k-p2", expect=409)
    assert late["error"] == "fanout_candidate_superseded"
    r2 = receipt(client, nid, "b2", "k-b2")
    assert r2["notification_status"] == "completed"

    # s3 一路未动：仍按自己的节奏推进（当前是自己的备用，期限独立）
    s3 = get_seat(client, nid, "s3")
    assert s3["state"] == "pending"
    assert s3["current"]["recipient_id"] == "b3"
    assert s3["last_switch"]["reason"] == "timeout_expired"


# ---------------------------------------------------------------------------
# 席位回执幂等与候选内失败重试
# ---------------------------------------------------------------------------

def test_seat_receipt_idempotency_and_conflict(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000, "candidates": ["p", "b1"]},
        {"seat_id": "s2", "switch_after_ms": 60_000, "candidates": ["q"]},
    ])
    nid = view["notification_id"]

    first = receipt(client, nid, "p", "k-1", content={"sig": "s1"})
    assert first["replayed"] is False
    replay = receipt(client, nid, "p", "k-1",
                     content={"sig": "s1"}, expect=200)
    assert replay["replayed"] is True
    assert {k: v for k, v in replay.items() if k != "replayed"} == \
        {k: v for k, v in first.items() if k != "replayed"}

    # 同键不同内容：409 冲突
    rv = client.post(f"/audit/fanout/notifications/{nid}/receipts",
                     json={"recipient_id": "p", "idempotency_key": "k-1",
                           "content": {"sig": "tampered"}})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "fanout_receipt_conflict"

    # 新键重复回执：等效成功，不重复计尝试
    dup = receipt(client, nid, "p", "k-2", expect=200)
    assert dup["already_succeeded"] is True
    assert dup["attempts"] == 1


def test_candidate_failure_retry_then_success(client):
    view = new_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 60_000,
         "candidates": [{"recipient_id": "p", "max_attempts": 3}, "b1"]},
    ])
    nid = view["notification_id"]
    f1 = failure(client, nid, "p", detail="err-1")
    assert f1["terminal"] is False
    assert f1["candidate_state"] == "active"   # 未到上限不切换
    failure(client, nid, "p", detail="err-2")
    r = receipt(client, nid, "p", "k-p")
    assert r["candidate_state"] == "succeeded"
    assert r["attempts"] == 3
    assert r["notification_status"] == "completed"
    # 失败重试发生在当前候选任期内，不触发切换
    assert get_seat(client, nid, "s1")["candidates"][1]["state"] == "waiting"


# ---------------------------------------------------------------------------
# 服务重启：原期限与切换历史继续
# ---------------------------------------------------------------------------

def test_restart_continues_original_deadlines_and_history(tmp_path):
    db = tmp_path / "seats.db"
    app1 = create_app(str(db), start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c1 = app1.test_client()
    make_policy(c1, "all")
    view = make_seat_notification(c1, [
        {"seat_id": "s1", "switch_after_ms": 5_000,
         "candidates": ["p", "b1", "b2"]},
        {"seat_id": "s2", "switch_after_ms": 60_000, "candidates": ["q"]},
    ])
    nid = view["notification_id"]
    first_deadline = view["seats"][0]["current"]["deadline_at_ms"]

    wall_shift(c1, 2_000)   # 用掉 2 秒
    switch(c1, nid, "s1", reason="主接收端失联", idempotency_key="sw-1")
    seat_before = get_seat(c1, nid, "s1")
    second_deadline = seat_before["current"]["deadline_at_ms"]
    # 手动切换重算期限：第二次期限 = 切换时刻 + 5 秒
    assert second_deadline > first_deadline
    history_before = seat_history(c1, nid, "s1")

    # ---- 重启：同一数据库文件 ----
    app2 = create_app(str(db), start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c2 = app2.test_client()

    seat_after = get_seat(c2, nid, "s1")
    # 当前处理人/期限/历史原样保留（remaining_ms 是实时值，剔除后比较）
    assert strip_remaining(seat_after) == strip_remaining(seat_before)
    assert seat_after["current"]["recipient_id"] == "b1"
    assert seat_after["current"]["deadline_at_ms"] == second_deadline
    assert seat_history(c2, nid, "s1") == history_before

    # 重启后期限没有延长：第二次期限 = 手动切换时刻 + 5 秒，
    # 即创建后约 7 秒；拨到约 6 秒不切换，拨过 7 秒准时切换
    wall_shift(c2, 4_000)
    assert process_deadlines(c2)["count"] == 0
    wall_shift(c2, 2_000)
    result = process_deadlines(c2)
    assert result["count"] == 1
    assert result["switches"][0]["from"]["recipient_id"] == "b1"
    assert result["switches"][0]["from"]["reason"] == "timeout_expired"
    assert result["switches"][0]["to"]["recipient_id"] == "b2"

    # 重启后流程继续：b2 与 q 成功 -> 完成
    r = receipt(c2, nid, "b2", "k-b2")
    assert r["notification_status"] == "pending"
    r = receipt(c2, nid, "q", "k-q")
    assert r["notification_status"] == "completed"

    # ---- 再重启：终态、判定与完整历史都在 ----
    app3 = create_app(str(db), start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c3 = app3.test_client()
    final = get_notification(c3, nid)
    assert final["status"] == "completed"
    assert final["decision"]["reason"] == "policy_satisfied"
    events = seat_history(c3, nid, "s1")
    assert event_names(events) == [
        "seat_created", "candidate_activated",
        "candidate_superseded", "candidate_activated",
        "candidate_superseded", "candidate_activated",
        "receipt_accepted", "seat_succeeded"]
    assert [e["reason"] for e in events
            if e["event"] == "candidate_superseded"] == [
        "manual_abandon", "timeout_expired"]
    # 被替换接收端的迟到回执在重启后仍然被明确拒绝
    late = receipt(c3, nid, "p", "k-p", expect=409)
    assert late["error"] == "fanout_candidate_superseded"


# ---------------------------------------------------------------------------
# 参数校验与不存在资源
# ---------------------------------------------------------------------------

def test_seat_validation_errors(client):
    make_policy(client, "quorum", quorum_count=2)

    # recipients 与 seats 二选一
    rv = client.post("/audit/fanout/notifications", json={
        "payload": {}, "recipients": ["a"],
        "seats": [{"switch_after_ms": 1, "candidates": ["b"]}]})
    assert rv.status_code == 400
    # 两者都不给
    rv = client.post("/audit/fanout/notifications", json={"payload": {}})
    assert rv.status_code == 400
    # 空席位列表 / 非对象元素
    make_seat_notification(client, [], expect=400)
    make_seat_notification(client, ["s1"], expect=400)
    # 缺切换期限 / 期限非法
    make_seat_notification(
        client, [{"candidates": ["a"]}], expect=400)
    make_seat_notification(
        client, [{"switch_after_ms": 0, "candidates": ["a"]}], expect=400)
    # 空候选列表
    make_seat_notification(
        client, [{"switch_after_ms": 1000, "candidates": []}], expect=400)
    # 席位标识重复
    make_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1000, "candidates": ["a"]},
        {"seat_id": "s1", "switch_after_ms": 1000, "candidates": ["b"]},
    ], expect=400)
    # 接收端跨席位重复（回执无法路由）
    make_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1000, "candidates": ["a", "b"]},
        {"seat_id": "s2", "switch_after_ms": 1000, "candidates": ["a"]},
    ], expect=400)
    # quorum 超过席位数
    make_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1000, "candidates": ["a"]},
    ], expect=400)

    view = make_seat_notification(client, [
        {"seat_id": "s1", "switch_after_ms": 1000, "candidates": ["a", "b"]},
        {"seat_id": "s2", "switch_after_ms": 1000, "candidates": ["c"]},
    ])
    nid = view["notification_id"]
    # 不存在的席位 / 通知
    get_seat(client, nid, "ghost", expect=404)
    rv = client.get("/audit/fanout/notifications/nope/seats")
    assert rv.status_code == 404
    switch(client, nid, "ghost", expect=404)
    # 冻结集合外的接收端
    receipt(client, nid, "ghost", "k", expect=404)
    # 扁平通知没有席位
    make_policy(client, "all")
    rv = client.post("/audit/fanout/notifications",
                     json={"payload": {}, "recipients": ["x"]})
    flat_nid = rv.get_json()["notification_id"]
    get_seat(client, flat_nid, "s1", expect=404)
    assert list_seats(client, flat_nid)["count"] == 0
