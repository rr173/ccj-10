"""审计通知多端投递：冻结策略快照、三种完成模式、回执幂等、暂停/恢复、
尝试上限、迟到回执、策略不可满足与服务重启持久性。"""

import pytest

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


def make_notification(client, recipients, payload=None, expect=201, **kw):
    data = {
        "payload": payload if payload is not None else {"audit": "evt-1"},
        "recipients": recipients,
    }
    data.update(kw)
    rv = client.post("/audit/fanout/notifications", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json() if expect == 201 else rv


def new_notification(client, recipients, mode="all", quorum_count=None):
    """新建一个策略版本 + 一条按它投递的通知，返回通知视图。"""
    make_policy(client, mode, quorum_count)
    return make_notification(client, recipients)


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


def pause(client, nid, rid, expect=200):
    rv = client.post(
        f"/audit/fanout/notifications/{nid}/recipients/{rid}/pause")
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def resume(client, nid, rid, expect=200):
    rv = client.post(
        f"/audit/fanout/notifications/{nid}/recipients/{rid}/resume")
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def get_notification(client, nid, expect=200):
    rv = client.get(f"/audit/fanout/notifications/{nid}")
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def get_attempts(client, nid, rid=None):
    if rid is None:
        rv = client.get(f"/audit/fanout/notifications/{nid}/attempts")
    else:
        rv = client.get(
            f"/audit/fanout/notifications/{nid}/recipients/{rid}/attempts")
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()["attempts"]


def recipient_of(view, rid):
    return next(r for r in view["recipients"] if r["recipient_id"] == rid)


# ---------------------------------------------------------------------------
# 三种完成策略
# ---------------------------------------------------------------------------

def test_all_mode_completes_only_when_every_recipient_succeeds(client):
    view = new_notification(client, ["a", "b", "c"], mode="all")
    nid = view["notification_id"]
    # 冻结快照：接收端集合、所需成功数、策略版本
    assert view["status"] == "pending"
    assert view["policy"] == {
        "version": 1, "mode": "all", "quorum_count": None,
        "required_successes": 3,
    }
    assert [r["recipient_id"] for r in view["recipients"]] == ["a", "b", "c"]

    r1 = receipt(client, nid, "a", "k-a")
    assert r1["notification_status"] == "pending"
    assert r1["progress"]["remaining_successes"] == 2
    r2 = receipt(client, nid, "b", "k-b")
    assert r2["notification_status"] == "pending"
    assert r2["progress"]["remaining_successes"] == 1

    r3 = receipt(client, nid, "c", "k-c")
    assert r3["notification_status"] == "completed"

    view = get_notification(client, nid)
    assert view["status"] == "completed"
    assert view["decision"]["reason"] == "policy_satisfied"
    assert view["decision"]["succeeded"] == 3
    assert view["decided_at_ms"] is not None


def test_any_mode_completes_on_first_success(client):
    view = new_notification(client, ["a", "b", "c"], mode="any")
    nid = view["notification_id"]
    assert view["policy"]["required_successes"] == 1

    r = receipt(client, nid, "b", "k-b")
    assert r["notification_status"] == "completed"

    view = get_notification(client, nid)
    assert view["status"] == "completed"
    # 其余接收端保持 pending，终态不替他们做决定
    assert recipient_of(view, "a")["state"] == "pending"
    assert recipient_of(view, "c")["state"] == "pending"


def test_quorum_mode_completes_at_required_count(client):
    view = new_notification(client, ["a", "b", "c"], mode="quorum",
                            quorum_count=2)
    nid = view["notification_id"]
    assert view["policy"] == {
        "version": 1, "mode": "quorum", "quorum_count": 2,
        "required_successes": 2,
    }

    r1 = receipt(client, nid, "a", "k-a")
    assert r1["notification_status"] == "pending"
    r2 = receipt(client, nid, "c", "k-c")
    assert r2["notification_status"] == "completed"
    assert r2["progress"]["succeeded"] == 2


# ---------------------------------------------------------------------------
# 策略变更边界：修改策略只影响新通知
# ---------------------------------------------------------------------------

def test_policy_change_only_affects_new_notifications(client):
    make_policy(client, "all")                       # v1
    n1 = make_notification(client, ["a", "b", "c"])
    make_policy(client, "any")                       # v2：修改策略
    n2 = make_notification(client, ["x", "y"])

    # 新通知用当前策略 v2；旧通知仍冻结在 v1
    assert n2["policy"]["version"] == 2
    assert n2["policy"]["required_successes"] == 1
    n1_now = get_notification(client, n1["notification_id"])
    assert n1_now["policy"]["version"] == 1
    assert n1_now["policy"]["mode"] == "all"
    assert n1_now["policy"]["required_successes"] == 3

    # v2 的 any：一个成功即完成；v1 的 all：两个成功仍不够
    r = receipt(client, n2["notification_id"], "x", "k-x")
    assert r["notification_status"] == "completed"
    receipt(client, n1["notification_id"], "a", "k-a")
    r = receipt(client, n1["notification_id"], "b", "k-b")
    assert r["notification_status"] == "pending"
    assert r["progress"]["remaining_successes"] == 1

    # 策略历史两个版本都可查，当前版本是 v2
    policies = client.get("/audit/fanout/policies").get_json()
    assert [p["version"] for p in policies["policies"]] == [1, 2]
    current = client.get("/audit/fanout/policies/current").get_json()
    assert current["version"] == 2
    v1 = client.get("/audit/fanout/policies/1").get_json()
    assert v1["mode"] == "all"

    # 显式按旧版本创建通知也可以，快照仍冻结在 v1
    n3 = make_notification(client, ["p", "q"], policy_version=1)
    assert n3["policy"]["version"] == 1
    assert n3["policy"]["required_successes"] == 2


def test_frozen_recipient_set_is_part_of_snapshot(client):
    make_policy(client, "all")
    view = make_notification(
        client,
        [{"recipient_id": "a", "max_attempts": 2},
         {"recipient_id": "b", "max_attempts": 5}])
    nid = view["notification_id"]
    # 冻结集合外的接收端不属于这条通知
    rv = client.post(f"/audit/fanout/notifications/{nid}/receipts",
                     json={"recipient_id": "ghost", "idempotency_key": "k"})
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "fanout_recipient_not_found"
    # 每个接收端自己的尝试上限随集合一起冻结
    assert recipient_of(view, "a")["max_attempts"] == 2
    assert recipient_of(view, "b")["max_attempts"] == 5


# ---------------------------------------------------------------------------
# 回执幂等：重复回执与幂等键冲突
# ---------------------------------------------------------------------------

def test_duplicate_receipt_replays_first_result(client):
    view = new_notification(client, ["a", "b"], mode="quorum", quorum_count=2)
    nid = view["notification_id"]

    first = receipt(client, nid, "a", "k-1", content={"sig": "s1"})
    assert first["replayed"] is False
    assert first["notification_status"] == "pending"

    # 相同回执重复到达：只返回首次结果
    replay = receipt(client, nid, "a", "k-1",
                     content={"sig": "s1"}, expect=200)
    assert replay["replayed"] is True
    assert {k: v for k, v in replay.items() if k != "replayed"} == \
        {k: v for k, v in first.items() if k != "replayed"}

    # 不重复计尝试：接收端 a 仍然只有 1 次成功尝试
    attempts = get_attempts(client, nid, "a")
    assert len(attempts) == 1
    assert attempts[0]["result"] == "success"
    assert attempts[0]["idempotency_key"] == "k-1"

    # 通知完成后再次重复同一回执：仍回放首次结果（当时的 pending），
    # 绝不因为重放而改写任何状态
    receipt(client, nid, "b", "k-2")
    assert get_notification(client, nid)["status"] == "completed"
    replay2 = receipt(client, nid, "a", "k-1",
                      content={"sig": "s1"}, expect=200)
    assert replay2["notification_status"] == "pending"  # 首次处理时的结果
    assert replay2["replayed"] is True
    assert len(get_attempts(client, nid, "a")) == 1


def test_same_key_different_content_conflicts(client):
    view = new_notification(client, ["a", "b"], mode="all")
    nid = view["notification_id"]
    receipt(client, nid, "a", "k-1", content={"sig": "s1"})

    rv = client.post(f"/audit/fanout/notifications/{nid}/receipts",
                     json={"recipient_id": "a", "idempotency_key": "k-1",
                           "content": {"sig": "tampered"}})
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "fanout_receipt_conflict"
    assert body["first_difference"]["path"] == "receipt.content.sig"
    assert body["first_difference"]["stored"] == "s1"
    assert body["first_difference"]["received"] == "tampered"

    # 冲突请求不产生任何副作用
    assert len(get_attempts(client, nid, "a")) == 1
    # 幂等键作用域是 (通知, 接收端)：另一个接收端用同一个键互不干扰
    r = receipt(client, nid, "b", "k-1", content={"sig": "s1"})
    assert r["recipient_state"] == "succeeded"
    assert get_notification(client, nid)["status"] == "completed"


def test_duplicate_success_with_new_key_adds_no_attempt(client):
    view = new_notification(client, ["a", "b"], mode="all")
    nid = view["notification_id"]
    receipt(client, nid, "a", "k-1")

    # 接收端已成功，新键重复回执：等效成功结果，不重复计尝试
    dup = receipt(client, nid, "a", "k-2", expect=200)
    assert dup["already_succeeded"] is True
    assert dup["attempts"] == 1
    assert len(get_attempts(client, nid, "a")) == 1
    # 新键也被记录：之后同键同内容仍按幂等回放
    again = receipt(client, nid, "a", "k-2", expect=200)
    assert again["already_succeeded"] is True


# ---------------------------------------------------------------------------
# 接收端暂停 / 恢复
# ---------------------------------------------------------------------------

def test_pause_blocks_receipt_and_failure_until_resume(client):
    view = new_notification(client, ["a", "b"], mode="all")
    nid = view["notification_id"]

    p = pause(client, nid, "a")
    assert p["recipient"]["paused"] is True
    assert p["recipient"]["state"] == "pending"
    # 暂停是幂等的
    assert pause(client, nid, "a")["recipient"]["paused"] is True

    # 暂停期间：回执与失败上报都被拒，且不计尝试
    r = receipt(client, nid, "a", "k-1", expect=409)
    assert r["error"] == "fanout_recipient_paused"
    f = failure(client, nid, "a", expect=409)
    assert f["error"] == "fanout_recipient_paused"
    assert get_attempts(client, nid, "a") == []

    # 恢复后一切照旧；恢复也是幂等的
    assert resume(client, nid, "a")["recipient"]["paused"] is False
    assert resume(client, nid, "a")["recipient"]["paused"] is False
    ok = receipt(client, nid, "a", "k-1")
    assert ok["recipient_state"] == "succeeded"


def test_pausing_succeeded_recipient_keeps_completion(client):
    view = new_notification(client, ["a", "b", "c"], mode="quorum",
                            quorum_count=2)
    nid = view["notification_id"]
    receipt(client, nid, "a", "k-a")

    # 暂停已成功的接收端：成功计数不减少
    p = pause(client, nid, "a")
    assert p["recipient"]["state"] == "succeeded"
    assert p["recipient"]["paused"] is True
    mid = get_notification(client, nid)
    assert mid["progress"]["succeeded"] == 1

    # 第二个成功到达：暂停过的成功仍然作数，通知完成
    r = receipt(client, nid, "b", "k-b")
    assert r["notification_status"] == "completed"

    # 完成后再暂停另一个成功接收端：既有完成结论不变
    pause(client, nid, "b")
    final = get_notification(client, nid)
    assert final["status"] == "completed"
    assert final["decision"]["reason"] == "policy_satisfied"
    assert final["decision"]["succeeded"] == 2
    assert final["progress"]["succeeded"] == 2
    assert final["progress"]["paused"] == 2


def test_pause_does_not_make_policy_unsatisfiable(client):
    # 暂停不是终止：被暂停的接收端可以恢复，策略仍然可能满足
    view = new_notification(
        client, [{"recipient_id": "a", "max_attempts": 1}, "b"],
        mode="all")
    nid = view["notification_id"]
    failure(client, nid, "a")  # a 终止：all 已不可能满足 -> failed
    assert get_notification(client, nid)["status"] == "failed"

    view2 = new_notification(client, ["x", "y"], mode="all")
    nid2 = view2["notification_id"]
    pause(client, nid2, "x")
    # 暂停不触发失败判定
    assert get_notification(client, nid2)["status"] == "pending"


# ---------------------------------------------------------------------------
# 失败重试与尝试上限
# ---------------------------------------------------------------------------

def test_failure_retry_until_max_attempts_then_terminal(client):
    view = new_notification(
        client, [{"recipient_id": "a", "max_attempts": 2}, "b"], mode="any")
    nid = view["notification_id"]

    f1 = failure(client, nid, "a", detail="timeout-1")
    assert f1["attempts"] == 1
    assert f1["terminal"] is False
    assert f1["recipient_state"] == "pending"

    f2 = failure(client, nid, "a", detail="timeout-2")
    assert f2["attempts"] == 2
    assert f2["terminal"] is True
    assert f2["recipient_state"] == "terminal_failed"

    # 达到上限后：失败上报与回执都被拒
    f3 = failure(client, nid, "a", expect=409)
    assert f3["error"] == "fanout_recipient_terminal"
    r = receipt(client, nid, "a", "k-a", expect=409)
    assert r["error"] == "fanout_recipient_terminal"

    # 尝试记录按顺序完整保留
    attempts = get_attempts(client, nid, "a")
    assert [(a["seq"], a["result"], a["detail"]) for a in attempts] == [
        (1, "failure", "timeout-1"), (2, "failure", "timeout-2")]

    # any 模式还有 b：通知仍 pending，b 成功即完成
    r = receipt(client, nid, "b", "k-b")
    assert r["notification_status"] == "completed"


def test_failure_then_success_counts_as_retry(client):
    view = new_notification(
        client, [{"recipient_id": "a", "max_attempts": 3}], mode="all")
    nid = view["notification_id"]
    failure(client, nid, "a", detail="err-1")
    failure(client, nid, "a", detail="err-2")
    r = receipt(client, nid, "a", "k-a")
    assert r["recipient_state"] == "succeeded"
    assert r["attempts"] == 3
    assert r["notification_status"] == "completed"
    attempts = get_attempts(client, nid, "a")
    assert [a["result"] for a in attempts] == [
        "failure", "failure", "success"]

    # 已成功接收端不能再上报失败
    f = failure(client, nid, "a", expect=409)
    assert f["error"] == "fanout_notification_decided"  # 通知已完成
    view2 = new_notification(client, ["z"], mode="all")
    nid2 = view2["notification_id"]
    receipt(client, nid2, "z", "k-z")
    f = failure(client, nid2, "z", expect=409)
    assert f["error"] == "fanout_notification_decided"


# ---------------------------------------------------------------------------
# 策略不可能满足 -> 明确失败；迟到回执不能翻案
# ---------------------------------------------------------------------------

def test_unsatisfiable_quorum_fails_with_recipient_states(client):
    view = new_notification(
        client,
        [{"recipient_id": "a", "max_attempts": 1},
         {"recipient_id": "b", "max_attempts": 1},
         {"recipient_id": "c", "max_attempts": 2}],
        mode="quorum", quorum_count=2)
    nid = view["notification_id"]

    f1 = failure(client, nid, "a")
    assert f1["notification_status"] == "pending"  # 还剩 b、c，可能满足
    f2 = failure(client, nid, "b")
    assert f2["notification_status"] == "failed"   # 只剩 c，达不到 2

    view = get_notification(client, nid)
    assert view["status"] == "failed"
    decision = view["decision"]
    assert decision["reason"] == "policy_unsatisfiable"
    assert decision["required_successes"] == 2
    assert decision["succeeded"] == 0
    assert decision["terminal_failed"] == 2
    # 参与判定的接收端状态被冻结进判定快照
    states = {r["recipient_id"]: r["state"] for r in decision["recipients"]}
    assert states == {
        "a": "terminal_failed", "b": "terminal_failed", "c": "pending"}
    attempts = {r["recipient_id"]: r["attempts"]
                for r in decision["recipients"]}
    assert attempts == {"a": 1, "b": 1, "c": 0}


def test_all_mode_fails_on_first_terminal_recipient(client):
    view = new_notification(
        client, [{"recipient_id": "a", "max_attempts": 1}, "b"], mode="all")
    nid = view["notification_id"]
    receipt(client, nid, "b", "k-b")  # b 已成功
    f = failure(client, nid, "a")
    assert f["notification_status"] == "failed"
    decision = get_notification(client, nid)["decision"]
    assert decision["succeeded"] == 1
    assert decision["terminal_failed"] == 1


def test_any_mode_fails_only_when_every_recipient_terminal(client):
    view = new_notification(
        client, [{"recipient_id": "a", "max_attempts": 1},
                 {"recipient_id": "b", "max_attempts": 1}], mode="any")
    nid = view["notification_id"]
    f1 = failure(client, nid, "a")
    assert f1["notification_status"] == "pending"
    f2 = failure(client, nid, "b")
    assert f2["notification_status"] == "failed"
    assert get_notification(client, nid)["decision"]["reason"] == \
        "policy_unsatisfiable"


def test_late_receipt_cannot_revive_failed_notification(client):
    view = new_notification(
        client, [{"recipient_id": "a", "max_attempts": 1},
                 {"recipient_id": "b", "max_attempts": 1}], mode="all")
    nid = view["notification_id"]
    failure(client, nid, "a")
    before = get_notification(client, nid)
    assert before["status"] == "failed"

    # 迟到回执：明确拒绝，通知维持 failed，判定快照不变
    r = receipt(client, nid, "b", "k-b", expect=409)
    assert r["error"] == "fanout_notification_decided"
    assert r["notification_status"] == "failed"
    assert r["decision"]["reason"] == "policy_unsatisfiable"
    after = get_notification(client, nid)
    assert after["status"] == "failed"
    assert after["decision"] == before["decision"]
    assert get_attempts(client, nid, "b") == []

    # 迟到失败上报同样不能改变既有判定
    f = failure(client, nid, "b", expect=409)
    assert f["error"] == "fanout_notification_decided"


def test_late_receipt_on_completed_notification_rejected(client):
    view = new_notification(client, ["a", "b"], mode="any")
    nid = view["notification_id"]
    receipt(client, nid, "a", "k-a")
    assert get_notification(client, nid)["status"] == "completed"

    r = receipt(client, nid, "b", "k-b", expect=409)
    assert r["error"] == "fanout_notification_decided"
    assert r["notification_status"] == "completed"
    # 已完成的通知里 b 保持 pending，没有新增尝试
    assert recipient_of(get_notification(client, nid), "b")["state"] == \
        "pending"
    assert get_attempts(client, nid, "b") == []


# ---------------------------------------------------------------------------
# 管理员视图：进度与尝试记录
# ---------------------------------------------------------------------------

def test_admin_view_tracks_progress_and_attempts(client):
    view = new_notification(
        client,
        [{"recipient_id": "a", "max_attempts": 2},
         {"recipient_id": "b", "max_attempts": 2},
         {"recipient_id": "c", "max_attempts": 2},
         {"recipient_id": "d", "max_attempts": 2}],
        mode="quorum", quorum_count=3)
    nid = view["notification_id"]

    failure(client, nid, "a", detail="err")
    receipt(client, nid, "b", "k-b")
    pause(client, nid, "c")

    view = get_notification(client, nid)
    progress = view["progress"]
    assert progress["recipients_total"] == 4
    assert progress["required_successes"] == 3
    assert progress["succeeded"] == 1
    assert progress["remaining_successes"] == 2   # 离完成还差 2 个成功
    assert progress["pending"] == 3
    assert progress["paused"] == 1
    assert progress["satisfiable"] is True

    a = recipient_of(view, "a")
    assert a["attempts"] == 1
    assert a["last_result"] == "failure"
    assert a["last_detail"] == "err"
    assert a["remaining_attempts"] == 1
    b = recipient_of(view, "b")
    assert b["state"] == "succeeded"
    assert b["last_result"] == "success"

    # 整条通知的尝试记录按全局顺序排列
    attempts = get_attempts(client, nid)
    assert [(a["recipient_id"], a["result"]) for a in attempts] == [
        ("a", "failure"), ("b", "success")]

    # 列表视图带同样的进度摘要
    listed = client.get("/audit/fanout/notifications").get_json()
    assert listed["count"] == 1
    assert listed["notifications"][0]["progress"]["remaining_successes"] == 2
    failed_list = client.get(
        "/audit/fanout/notifications?status=failed").get_json()
    assert failed_list["count"] == 0


# ---------------------------------------------------------------------------
# 服务重启：策略快照、尝试顺序与最终判定原样保留
# ---------------------------------------------------------------------------

def test_restart_preserves_snapshot_attempts_and_verdict(tmp_path):
    db = tmp_path / "fanout.db"
    app1 = create_app(str(db), start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c1 = app1.test_client()

    make_policy(c1, "quorum", quorum_count=2)   # v1
    make_policy(c1, "all")                      # v2（不影响已建通知）
    n = make_notification(
        c1,
        [{"recipient_id": "a", "max_attempts": 2},
         {"recipient_id": "b", "max_attempts": 2},
         {"recipient_id": "c", "max_attempts": 2}],
        policy_version=1)
    nid = n["notification_id"]

    failure(c1, nid, "a", detail="err-1")
    first = receipt(c1, nid, "a", "k-a", content={"sig": "s1"})
    failure(c1, nid, "b", detail="err-1")
    failure(c1, nid, "b", detail="err-2")       # b 终止
    pause(c1, nid, "c")
    before = get_notification(c1, nid)
    assert before["status"] == "pending"        # a 成功 + c 暂停，仍可能满足
    attempts_before = get_attempts(c1, nid)

    # ---- 进程重启：重新建 app，复用同一个数据库文件 ----
    app2 = create_app(str(db), start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c2 = app2.test_client()

    after = get_notification(c2, nid)
    assert after == before                      # 快照/进度/暂停标记全保留
    assert after["policy"]["version"] == 1
    assert after["policy"]["required_successes"] == 2
    assert recipient_of(after, "c")["paused"] is True
    assert get_attempts(c2, nid) == attempts_before  # 尝试顺序不变

    # 幂等记录在重启后仍然生效：同一回执回放首次结果
    replay = receipt(c2, nid, "a", "k-a", content={"sig": "s1"}, expect=200)
    assert replay["replayed"] is True
    assert replay["notification_status"] == \
        first["notification_status"]
    # 同键不同内容仍然 409
    rv = c2.post(f"/audit/fanout/notifications/{nid}/receipts",
                 json={"recipient_id": "a", "idempotency_key": "k-a",
                       "content": {"sig": "other"}})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "fanout_receipt_conflict"

    # 重启后继续流程：恢复 c，c 成功 -> 达到 quorum 完成
    resume(c2, nid, "c")
    r = receipt(c2, nid, "c", "k-c")
    assert r["notification_status"] == "completed"

    # ---- 再重启一次：最终判定依然在 ----
    app3 = create_app(str(db), start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c3 = app3.test_client()
    final = get_notification(c3, nid)
    assert final["status"] == "completed"
    assert final["decision"]["reason"] == "policy_satisfied"
    # 迟到回执在重启后仍然不能翻案
    r = receipt(c3, nid, "b", "k-b", expect=409)
    assert r["error"] == "fanout_notification_decided"


def test_restart_preserves_failed_verdict(tmp_path):
    db = tmp_path / "fanout-failed.db"
    app1 = create_app(str(db), start_ticker=False, start_archive_worker=False)
    c1 = app1.test_client()
    make_policy(c1, "all")
    n = make_notification(
        c1, [{"recipient_id": "a", "max_attempts": 1},
             {"recipient_id": "b", "max_attempts": 1}])
    nid = n["notification_id"]
    failure(c1, nid, "a")
    before = get_notification(c1, nid)
    assert before["status"] == "failed"

    app2 = create_app(str(db), start_ticker=False, start_archive_worker=False)
    c2 = app2.test_client()
    after = get_notification(c2, nid)
    assert after == before
    assert after["decision"]["reason"] == "policy_unsatisfiable"
    # 迟到回执不能复活已失败的通知（重启后同样成立）
    r = receipt(c2, nid, "b", "k-b", expect=409)
    assert r["error"] == "fanout_notification_decided"
    assert get_notification(c2, nid)["status"] == "failed"


# ---------------------------------------------------------------------------
# 参数校验与不存在资源
# ---------------------------------------------------------------------------

def test_validation_errors(client):
    # 策略校验
    rv = client.post("/audit/fanout/policies", json={"mode": "majority"})
    assert rv.status_code == 400
    rv = client.post("/audit/fanout/policies", json={"mode": "quorum"})
    assert rv.status_code == 400                      # quorum 缺 quorum_count
    rv = client.post("/audit/fanout/policies",
                     json={"mode": "all", "quorum_count": 2})
    assert rv.status_code == 400                      # all 不接受 quorum_count
    rv = client.post("/audit/fanout/policies",
                     json={"mode": "quorum", "quorum_count": 0})
    assert rv.status_code == 400

    # 还没有任何策略时创建通知 -> 409
    rv = client.post("/audit/fanout/notifications",
                     json={"payload": {}, "recipients": ["a"]})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "fanout_no_current_policy"

    make_policy(client, "quorum", quorum_count=2)
    # 通知校验
    make_notification(client, [], expect=400)          # 空接收端集合
    make_notification(client, ["a", "a"], expect=400)  # 接收端重复
    make_notification(client, ["a"], expect=400)       # quorum 超过集合大小
    make_notification(client, [{"recipient_id": "a", "max_attempts": 0}],
                      expect=400)                      # 上限至少 1
    make_notification(client, ["a"], policy_version=99, expect=404)
    rv = client.post("/audit/fanout/notifications",
                     json={"recipients": ["a"]})
    assert rv.status_code == 400                       # 缺 payload

    # 不存在资源
    rv = client.get("/audit/fanout/notifications/nope")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "fanout_notification_not_found"
    rv = client.get("/audit/fanout/policies/99")
    assert rv.status_code == 404
    view = make_notification(client, ["a", "b"])
    nid = view["notification_id"]
    rv = client.post(f"/audit/fanout/notifications/{nid}/receipts",
                     json={"recipient_id": "a"})
    assert rv.status_code == 400                       # 缺幂等键
    rv = client.post(
        f"/audit/fanout/notifications/{nid}/recipients/ghost/pause")
    assert rv.status_code == 404
    rv = client.get("/audit/fanout/policies/current")
    assert rv.status_code == 200                       # 已有策略
