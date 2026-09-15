"""批次通知额度与优先级排队：HTTP 端到端测试。

覆盖：
- 封存通知时同事务按冻结接收端入队发送任务（排队状态可查）
- 接收端额度策略：版本化、幂等回放、同键换规格 409、领取受额度约束
- 事件优先级：版本化、队列按优先级排序、策略变化只重排未发送任务
- 领取：并发领取唯一、租约未过期不可抢、租约过期后可接管（旧令牌失效）
- 发送失败不扣额度、重试保持原排队身份（queue_seq 不变）
- 完成幂等回放不重复计额度、令牌/状态错误显式 409/404
- 服务重启后队列/认领/额度消耗状态恢复
"""

import threading

from app.app import create_app

T0 = 1_000_000_000_000
W = 60_000
BASE = (T0 // W) * W
LAT = 10_000


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def make_source(client, sid="s1"):
    rv = client.post("/audit/batch/sources", json={"source_id": sid})
    assert rv.status_code in (200, 201), rv.get_json()
    return rv.get_json()


def make_rule(client, event_type="login", recipients=("r1",), **kw):
    data = {
        "event_type": event_type, "window_ms": kw.get("window_ms", W),
        "group_field": "region",
        "allowed_lateness_ms": kw.get("allowed_lateness_ms", LAT),
        "recipients": list(recipients),
    }
    rv = client.post("/audit/batch/rules", json=data)
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()


def scan(client, sid, events, expect=200):
    rv = client.post(f"/audit/batch/sources/{sid}/events/scan",
                     json={"events": events})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def watermark(client, sid, wm):
    rv = client.post(f"/audit/batch/sources/{sid}/watermark",
                     json={"watermark_ms": wm})
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


def evt(seq, ts, event_type="login", region="cn"):
    return {"seq": seq, "event_type": event_type, "occurred_at_ms": ts,
            "payload": {"region": region}}


def seal_one_batch(client, sid="s1", event_type="login",
                   recipients=("r1",), seq=1):
    """造一个封存批次：来源+规则+一个事件+推进 watermark。"""
    make_rule(client, event_type, recipients)
    scan(client, sid, [evt(seq, BASE + 1_000, event_type)])
    watermark(client, sid, BASE + W + LAT)


def queue(client, rid, expect=200):
    rv = client.get(f"/audit/batch/queue/{rid}")
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def claim(client, rid, worker, *, max_tasks=1, lease_ms=None, expect=200):
    data = {"recipient_id": rid, "worker_id": worker, "max_tasks": max_tasks}
    if lease_ms is not None:
        data["lease_ms"] = lease_ms
    rv = client.post("/audit/batch/queue/claim", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def complete(client, task_id, token, expect=200):
    rv = client.post(f"/audit/batch/queue/tasks/{task_id}/complete",
                     json={"claim_token": token})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def fail(client, task_id, token, error="boom", expect=200):
    rv = client.post(f"/audit/batch/queue/tasks/{task_id}/fail",
                     json={"claim_token": token, "error": error})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def quota_policy(client, rid, max_sends, window_ms, *, key=None, expect=201):
    data = {"recipient_id": rid, "max_sends": max_sends,
            "window_ms": window_ms}
    if key is not None:
        data["idempotency_key"] = key
    rv = client.post("/audit/batch/quota-policies", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def priority(client, event_type, prio, *, key=None, expect=201):
    data = {"event_type": event_type, "priority": prio}
    if key is not None:
        data["idempotency_key"] = key
    rv = client.post("/audit/batch/priorities", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


# ---------------------------------------------------------------------------
# 入队与排队状态
# ---------------------------------------------------------------------------

def test_seal_enqueues_one_task_per_recipient(client):
    make_source(client)
    make_rule(client, "login", ("sec-a", "sec-b"))
    scan(client, "s1", [evt(1, BASE + 1_000)])
    watermark(client, "s1", BASE + W + LAT)

    for rid in ("sec-a", "sec-b"):
        q = queue(client, rid)
        assert q["counts"] == {"pending": 1, "claimed": 0, "sent": 0}
        assert q["quota"] is None                      # 未配置额度策略
        assert len(q["tasks"]) == 1
        t = q["tasks"][0]
        assert t["recipient_id"] == rid and t["status"] == "pending"
        assert t["queue_seq"] == 1 and t["priority"] == 0
        assert t["event_type"] == "login"
        assert "claim_token" not in t                  # 令牌只在领取时下发
    # 两个接收端的任务各自独立
    ta = queue(client, "sec-a")["tasks"][0]
    tb = queue(client, "sec-b")["tasks"][0]
    assert ta["task_id"] != tb["task_id"]
    assert ta["notification_id"] == tb["notification_id"]
    # 任务详情接口
    rv = client.get(f"/audit/batch/queue/tasks/{ta['task_id']}")
    assert rv.status_code == 200
    assert rv.get_json()["task_id"] == ta["task_id"]
    # 全部接收端视图
    allq = client.get("/audit/batch/queue").get_json()
    assert {r["recipient_id"] for r in allq["recipients"]} == {"sec-a", "sec-b"}
    # 未知接收端 404
    queue(client, "ghost", expect=404)


def test_queue_seq_monotonic_per_recipient(client):
    make_source(client)
    make_rule(client, "login", ("r1",))
    # 两个窗口 → 两条通知 → 两个任务，queue_seq 递增
    scan(client, "s1", [evt(1, BASE + 1_000), evt(2, BASE + W + 1_000)])
    watermark(client, "s1", BASE + 2 * W + LAT)
    tasks = client.get("/audit/batch/queue/r1").get_json()["tasks"]
    assert [t["queue_seq"] for t in tasks] == [1, 2]


# ---------------------------------------------------------------------------
# 额度策略
# ---------------------------------------------------------------------------

def test_quota_policy_versioning_and_idempotency(client):
    p1 = quota_policy(client, "r1", 5, 60_000, key="k1")
    assert p1["version"] == 1 and p1["replayed"] is False
    # 同键同规格回放
    again = quota_policy(client, "r1", 5, 60_000, key="k1", expect=200)
    assert again["policy_id"] == p1["policy_id"] and again["replayed"] is True
    # 同键换规格 409
    quota_policy(client, "r1", 6, 60_000, key="k1", expect=409)
    # 换键产生新版本，当前策略指向最新版
    p2 = quota_policy(client, "r1", 10, 120_000)
    assert p2["version"] == 2
    cur = client.get("/audit/batch/quota-policies/r1").get_json()
    assert cur["version"] == 2 and cur["max_sends"] == 10
    lst = client.get("/audit/batch/quota-policies",
                     query_string={"recipient_id": "r1"}).get_json()["policies"]
    assert [p["version"] for p in lst] == [1, 2]
    # 未配置 404；参数非法 400
    rv = client.get("/audit/batch/quota-policies/ghost")
    assert rv.status_code == 404
    rv = client.post("/audit/batch/quota-policies",
                     json={"recipient_id": "r1", "max_sends": 0,
                           "window_ms": 1000})
    assert rv.status_code == 400


def test_claim_limited_by_quota(client):
    make_source(client)
    quota_policy(client, "r1", 1, 60_000)
    make_rule(client, "login", ("r1",))
    scan(client, "s1", [evt(1, BASE + 1_000), evt(2, BASE + W + 1_000)])
    watermark(client, "s1", BASE + 2 * W + LAT)

    # 额度 1：第一次领取占住预留，第二次为空
    r = claim(client, "r1", "w1", max_tasks=5)
    assert r["claimed_count"] == 1
    assert r["quota"]["remaining"] == 0
    r = claim(client, "r1", "w2", max_tasks=5)
    assert r["claimed_count"] == 0
    # 租约到期后被接管并完成，额度 used=1
    client.post("/debug/wall-shift", json={"delta_ms": 61_000})
    r = claim(client, "r1", "w2")
    assert r["claimed_count"] == 1
    tok = r["claimed"][0]["claim_token"]
    done = complete(client, r["claimed"][0]["task_id"], tok)
    assert done["status"] == "sent"
    q = queue(client, "r1")
    assert q["quota"]["used"] == 1 and q["quota"]["remaining"] == 0
    assert claim(client, "r1", "w3")["claimed_count"] == 0
    # 窗口滑出后额度释放，可继续领取
    client.post("/debug/wall-shift", json={"delta_ms": 61_000})
    assert claim(client, "r1", "w3")["claimed_count"] == 1


# ---------------------------------------------------------------------------
# 事件优先级
# ---------------------------------------------------------------------------

def test_priority_orders_queue_and_reorders_only_unsent(client):
    make_source(client)
    priority(client, "login", 1)
    priority(client, "alert", 10)
    make_rule(client, "login", ("r1",))
    make_rule(client, "alert", ("r1",))
    scan(client, "s1", [evt(1, BASE + 1_000, "login"),
                        evt(2, BASE + 1_000, "alert")])
    watermark(client, "s1", BASE + W + LAT)

    tasks = queue(client, "r1")["tasks"]
    assert [t["event_type"] for t in tasks] == ["alert", "login"]  # 优先级序
    assert [t["priority"] for t in tasks] == [10, 1]

    # 领走 alert（冻结优先级 10），随后调大 login 优先级：
    # 只有未发送的 login 任务被重排，已认领的 alert 保持冻结值
    got = claim(client, "r1", "w1")
    assert got["claimed"][0]["event_type"] == "alert"
    alert_task = got["claimed"][0]
    priority(client, "login", 100)
    tasks = queue(client, "r1")["tasks"]
    by_type = {t["event_type"]: t for t in tasks}
    assert by_type["login"]["priority"] == 100        # pending 被重排
    assert by_type["alert"]["priority"] == 10         # claimed 保持冻结
    # 完成后策略再变也不影响已发送任务
    complete(client, alert_task["task_id"], alert_task["claim_token"])
    priority(client, "alert", 7)
    sent = client.get(
        f"/audit/batch/queue/tasks/{alert_task['task_id']}").get_json()
    assert sent["priority"] == 10 and sent["status"] == "sent"

    # 幂等：同键回放、同键换规格 409
    p = priority(client, "login", 3, key="pk")
    assert p["version"] == 3
    again = priority(client, "login", 3, key="pk", expect=200)
    assert again["priority_id"] == p["priority_id"]
    priority(client, "login", 4, key="pk", expect=409)
    cur = client.get("/audit/batch/priorities/login").get_json()
    assert cur["priority"] == 3
    rv = client.get("/audit/batch/priorities/ghost")
    assert rv.status_code == 404


def test_enqueue_uses_current_priority(client):
    make_source(client)
    priority(client, "login", 42)
    make_rule(client, "login", ("r1",))
    scan(client, "s1", [evt(1, BASE + 1_000)])
    watermark(client, "s1", BASE + W + LAT)
    t = queue(client, "r1")["tasks"][0]
    assert t["priority"] == 42                        # 入队时冻结当前策略


# ---------------------------------------------------------------------------
# 领取：并发唯一 + 租约接管
# ---------------------------------------------------------------------------

def test_concurrent_claim_is_unique(client):
    make_source(client)
    seal_one_batch(client)

    bar = threading.Barrier(4)
    results = []

    def worker(i):
        c = client.application.test_client()
        bar.wait()
        rv = c.post("/audit/batch/queue/claim",
                    json={"recipient_id": "r1", "worker_id": f"w{i}"})
        results.append(rv.get_json())

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    wins = [r for r in results if r["claimed_count"] == 1]
    assert len(wins) == 1, results                     # 恰好一个领取者成功
    assert sum(r["claimed_count"] for r in results) == 1
    # 任务只有一条，被认领后其他人再领为空
    assert claim(client, "r1", "w9")["claimed_count"] == 0


def test_claim_lease_expiry_allows_takeover(client):
    make_source(client)
    seal_one_batch(client)

    r1 = claim(client, "r1", "w1", lease_ms=1_000)
    task = r1["claimed"][0]
    old_token = task["claim_token"]
    assert task["claimed_by"] == "w1"
    # 租约未过期：别人领不到
    assert claim(client, "r1", "w2")["claimed_count"] == 0
    # 拨表越过租约：w2 接管，拿到新令牌
    client.post("/debug/wall-shift", json={"delta_ms": 2_000})
    r2 = claim(client, "r1", "w2")
    assert r2["claimed_count"] == 1
    new_task = r2["claimed"][0]
    assert new_task["task_id"] == task["task_id"]      # 同一个任务
    assert new_task["claimed_by"] == "w2"
    assert new_task["claim_token"] != old_token
    # 旧令牌即刻失效：迟到完成/失败上报一律 409
    complete(client, task["task_id"], old_token, expect=409)
    fail(client, task["task_id"], old_token, expect=409)
    # 新持有者正常完成
    done = complete(client, task["task_id"], new_task["claim_token"])
    assert done["status"] == "sent"


def test_claim_validation(client):
    make_source(client)
    seal_one_batch(client)
    rv = client.post("/audit/batch/queue/claim", json={"recipient_id": "r1"})
    assert rv.status_code == 409                       # 缺 worker_id（require）
    rv = client.post("/audit/batch/queue/claim",
                     json={"recipient_id": "r1", "worker_id": "w",
                           "lease_ms": 0})
    assert rv.status_code == 400
    rv = client.post("/audit/batch/queue/claim",
                     json={"recipient_id": "r1", "worker_id": "w",
                           "max_tasks": 0})
    assert rv.status_code == 400


# ---------------------------------------------------------------------------
# 失败不扣额度 / 重试保持排队身份 / 完成幂等
# ---------------------------------------------------------------------------

def test_failure_keeps_quota_and_queue_identity(client):
    make_source(client)
    quota_policy(client, "r1", 1, 60_000)
    make_rule(client, "login", ("r1",))
    scan(client, "s1", [evt(1, BASE + 1_000), evt(2, BASE + W + 1_000)])
    watermark(client, "s1", BASE + 2 * W + LAT)

    got = claim(client, "r1", "w1")
    task = got["claimed"][0]
    # 发送失败：不扣额度、回到 pending、排队身份不变
    f = fail(client, task["task_id"], task["claim_token"], error="smtp down")
    assert f["status"] == "pending" and f["attempts"] == 1
    assert f["queue_seq"] == task["queue_seq"] == 1
    assert f["last_error"] == "smtp down"
    q = queue(client, "r1")
    assert q["quota"]["used"] == 0 and q["quota"]["reserved"] == 0
    # 重试领到的还是同一个任务（同一 task_id、同一 queue_seq）
    got2 = claim(client, "r1", "w1")
    retry = got2["claimed"][0]
    assert retry["task_id"] == task["task_id"]
    assert retry["queue_seq"] == task["queue_seq"]
    # 成功才扣额度
    done = complete(client, task["task_id"], retry["claim_token"])
    assert done["status"] == "sent" and done["replayed"] is False
    q = queue(client, "r1")
    assert q["quota"]["used"] == 1 and q["quota"]["remaining"] == 0
    # 额度占满：第二个任务领不到
    assert claim(client, "r1", "w1")["claimed_count"] == 0


def test_complete_idempotent_replay_counts_quota_once(client):
    make_source(client)
    quota_policy(client, "r1", 5, 60_000)
    seal_one_batch(client)
    got = claim(client, "r1", "w1")
    task = got["claimed"][0]
    done = complete(client, task["task_id"], task["claim_token"])
    assert done["replayed"] is False
    # 同令牌重复完成：幂等回放，不重复计额度
    replay = complete(client, task["task_id"], task["claim_token"])
    assert replay["replayed"] is True and replay["status"] == "sent"
    assert queue(client, "r1")["quota"]["used"] == 1
    # 已发送任务用别的令牌完成 → 409
    complete(client, task["task_id"], "wrong-token", expect=409)
    # 已发送任务上报失败 → 409
    fail(client, task["task_id"], task["claim_token"], expect=409)


def test_complete_fail_state_and_token_errors(client):
    make_source(client)
    seal_one_batch(client)
    task = queue(client, "r1")["tasks"][0]
    # 未认领就完成/失败 → 409
    complete(client, task["task_id"], "tok", expect=409)
    fail(client, task["task_id"], "tok", expect=409)
    # 任务不存在 → 404
    complete(client, "tsk_ghost", "tok", expect=404)
    fail(client, "tsk_ghost", "tok", expect=404)
    rv = client.get("/audit/batch/queue/tasks/tsk_ghost")
    assert rv.status_code == 404
    # 认领后令牌不匹配 → 409
    got = claim(client, "r1", "w1")
    real = got["claimed"][0]
    complete(client, real["task_id"], "bad-token", expect=409)
    fail(client, real["task_id"], "bad-token", expect=409)
    # 缺 claim_token → 409（require 必填）
    rv = client.post(f"/audit/batch/queue/tasks/{real['task_id']}/complete",
                     json={})
    assert rv.status_code == 409


# ---------------------------------------------------------------------------
# 重启恢复
# ---------------------------------------------------------------------------

def test_restart_preserves_queue_claims_and_quota(tmp_path):
    db = str(tmp_path / "q.db")

    def factory():
        return create_app(db, start_ticker=False, enable_debug_api=True,
                          start_archive_worker=False)

    app = factory()
    with app.test_client() as c:
        make_source(c)
        quota_policy(c, "r1", 3, 60_000)
        priority(c, "login", 9)
        make_rule(c, "login", ("r1",))
        scan(c, "s1", [evt(1, BASE + 1_000), evt(2, BASE + W + 1_000)])
        watermark(c, "s1", BASE + 2 * W + LAT)
        got = claim(c, "r1", "w1")
        token = got["claimed"][0]["claim_token"]
        task_id = got["claimed"][0]["task_id"]

    # 进程重启：队列、认领、优先级、额度策略全部恢复
    app2 = factory()
    with app2.test_client() as c:
        q = queue(c, "r1")
        assert q["counts"] == {"pending": 1, "claimed": 1, "sent": 0}
        assert q["quota"]["reserved"] == 1
        claimed = [t for t in q["tasks"] if t["status"] == "claimed"]
        assert claimed[0]["task_id"] == task_id
        assert claimed[0]["claimed_by"] == "w1"
        assert claimed[0]["priority"] == 9
        # 原令牌重启后仍有效，完成扣额度
        done = complete(c, task_id, token)
        assert done["status"] == "sent"
        assert queue(c, "r1")["quota"]["used"] == 1

    # 再次重启：已发送与额度消耗依旧
    app3 = factory()
    with app3.test_client() as c:
        q = queue(c, "r1")
        assert q["counts"]["sent"] == 1
        assert q["quota"]["used"] == 1
        # 剩余任务可继续领取
        assert claim(c, "r1", "w2")["claimed_count"] == 1
