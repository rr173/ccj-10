"""审计变更订阅与可靠通知：创建、投递、确认、重试、死信、暂停恢复、
重启持久化、严格顺序与幂等冲突。

覆盖场景：
- 正常投递（签名载荷、字段齐全、按历史序号与订阅序号严格有序）
- 空结果（起始序号之后无本订阅事件；过滤零匹配）
- 过滤（只有匹配过滤条件的事件才生成通知，未匹配事件只推进游标）
- 重复确认（幂等回放，不重复推进；错误签名 401 不改状态）
- 并发投递（多线程同时 process_due，每个事件恰好投递一次）
- 回调失败/超时/非成功状态（尝试次数、下次重试时间、退避后成功）
- 死信与恢复（超上限进死信并挡住后续事件，查看原因，重新放回后续传）
- 暂停后恢复（暂停不投递，恢复后从队首继续）
- 服务重启（inflight 回收、位置/状态/已确认记录持久化、不丢不重）
- 起始序号越界（416）
- 幂等冲突（同键同订阅 200；换过滤/回调/起始序号 409）
- 创建期间新事件不被塞入更早快照
- 从指定序号重新开始（保留历史投递记录、已确认事件不重复确认）
- 取消后迟到通知不再发送
- 凭证/因果索引/发布版本三种额外作用域
- 分页读取投递历史
- 订阅流程不改写源审计历史/租约/委托/索引/归档/证据包/发布计划
"""

import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.app import create_app
from app.subscription import (
    D_AWAITING,
    D_CONFIRMED,
    D_DEAD,
    D_INFLIGHT,
    D_PENDING,
    HttpDeliveryResult,
    canonical_json,
)


# ---------------------------------------------------------------------------
# fixture 与辅助
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        str(tmp_path / "sub.db"), start_ticker=False,
        enable_debug_api=True, start_archive_worker=False)
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    with app.test_client() as c:
        yield c


class ScriptedCallback:
    """可编排的假回调：按 event_seq 给出成功/失败脚本，记录全部通知。"""

    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()
        # event_seq -> list[HttpDeliveryResult]，逐个弹出
        self.script: dict[int, list] = {}
        self.default = HttpDeliveryResult(ok=True)

    def fail(self, n=1, *, status=500, permanent=False):
        r = HttpDeliveryResult(status=410 if permanent else status,
                               permanent_reject=permanent,
                               error=None if permanent else f"http_status_{status}")
        return [r] * n

    def timeout(self, n=1):
        return [HttpDeliveryResult(error="timeout: timed out")] * n

    def set_script(self, mapping):
        self.script = {int(k): list(v) for k, v in mapping.items()}

    def __call__(self, url, payload, signature):
        with self.lock:
            self.calls.append({
                "url": url, "payload": payload, "signature": signature})
            seq = payload["event_seq"]
            outcomes = self.script.get(seq)
            if outcomes:
                return outcomes.pop(0)
            return self.default


@pytest.fixture()
def cb(app):
    callback = ScriptedCallback()
    app.extensions["subscriptions"]._deliver_cb = callback
    return callback


def subs(client):
    return client.application.extensions["subscriptions"]


def store(client):
    return client.application.extensions["store"]


def acquire(client, resource, holder="h1", ttl_ms=60_000):
    rv = client.post("/leases/acquire", json={
        "resource": resource, "holder": holder, "ttl_ms": ttl_ms})
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()["lease"]


def write_ok(client, resource, holder="h1", generation=1, value="v"):
    rv = client.post(f"/resources/{resource}/writes", json={
        "holder": holder, "generation": generation, "value": value})
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()


def create_sub(client, *, scope="resource", resource="r1", key="k1",
               start_seq=0, callback_url="http://callback.test/hook",
               filters=None, expect=201, **extra):
    body = {"scope": scope, "callback_url": callback_url,
            "start_seq": start_seq, "idempotency_key": key}
    if scope == "resource":
        body["resource"] = resource
    if scope == "credential":
        body["credential_id"] = resource
    if scope == "causal_index":
        body["index_id"] = resource
    if scope == "release":
        body["release_id"] = resource
    if filters is not None:
        body["filters"] = filters
    body.update(extra)
    rv = client.post("/audit/subscriptions", json=body)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def tick_process(client):
    rv = client.post("/audit/subscriptions/process", json={})
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


def global_max_seq(client):
    rv = client.get("/audit/events?limit=1000")
    assert rv.status_code == 200
    events = rv.get_json()["events"]
    return events[-1]["seq"] if events else 0


def history_seqs(client):
    rv = client.get("/resources/r1/audit/events?limit=1000")
    assert rv.status_code == 200
    return [e["seq"] for e in rv.get_json()["events"]]


def delivered_seqs(cb):
    return [c["payload"]["event_seq"] for c in cb.calls]


# ---------------------------------------------------------------------------
# 1. 正常投递：字段齐全、签名可校验、按历史序号严格顺序
# ---------------------------------------------------------------------------


def test_normal_delivery_signed_and_ordered(client, cb):
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"], value="v1")
    write_ok(client, "r1", generation=lease["generation"], value="v2")

    sub = create_sub(client, key="k1")
    sid = sub["subscription_id"]
    assert sub["status"] == "active"
    assert sub["snapshot_seq"] >= 3
    assert "secret" not in sub  # 密钥不外泄

    # 三次处理：每个订阅每轮只投递队首一行（严格顺序）
    for _ in range(3):
        tick_process(client)

    seqs = delivered_seqs(cb)
    assert seqs == sorted(seqs) and len(seqs) == 3

    secret = _secret(client, sid)
    for i, call in enumerate(cb.calls, start=1):
        p = call["payload"]
        # 通知必带字段
        assert p["event_seq"] == seqs[i - 1]
        assert p["subscription_seq"] == i          # 订阅序号连续
        assert p["event_type"] in ("acquire", "write")
        assert p["object_id"] == f"lease_event:{p['event_seq']}"
        assert p["object"]["resource"] == "r1"
        assert "summary" in p and "digest_sha256" in p["summary"]
        # 签名可由订阅密钥校验
        expect_sig = hmac.new(
            secret.encode(), canonical_json(p).encode(),
            hashlib.sha256).hexdigest()
        assert hmac.compare_digest(expect_sig, call["signature"])

    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["counters"]["confirmed"] == 3
    assert st["delivered_seq"] == seqs[-1]


def test_reads_observe_latest_commits_from_other_connection(client, cb):
    """长生命周期的订阅连接不能停在旧 WAL 快照（worker 线程提交后
    GET 必须看到最新状态）。"""
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"])
    sub = create_sub(client, key="k-wal")
    sid = sub["subscription_id"]
    # 先做若干次只读调用，让连接上存在已结束的读事务痕迹
    for _ in range(3):
        client.get(f"/audit/subscriptions/{sid}")
    tick_process(client)
    tick_process(client)  # 严格顺序：逐轮确认 seq1、seq2
    # 紧接 GET（与 worker 写同一连接的不同调用路径）必须看到最新状态
    d = client.get(
        f"/audit/subscriptions/{sid}/deliveries?limit=10").get_json()
    assert [x["status"] for x in d["deliveries"]] == \
        [D_CONFIRMED, D_CONFIRMED]
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["counters"]["confirmed"] == 2


def test_secret_never_exposed(client, cb):
    acquire(client, "r1")
    sub = create_sub(client)
    assert "secret" not in sub
    rv = client.get(f"/audit/subscriptions/{sub['subscription_id']}")
    assert "secret" not in rv.get_json()
    rv = client.get(
        f"/audit/subscriptions/{sub['subscription_id']}/deliveries")
    for d in rv.get_json()["deliveries"]:
        assert "secret" not in d


# ---------------------------------------------------------------------------
# 2. 空结果
# ---------------------------------------------------------------------------


def test_empty_when_start_after_scope_events(client, cb):
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"])
    # 另一个资源产生更大全局序号，使 start_seq 不越界
    lease2 = acquire(client, "r2")
    write_ok(client, "r2", generation=lease2["generation"])
    max_seq = global_max_seq(client)

    # 全局末条是 r2 的事件（seq=max_seq）；订阅 r1 从 max_seq 开始：
    # 不越界，但该位置之后没有属于 r1 的事件（空结果）
    sub = create_sub(client, resource="r1", key="k-empty",
                     start_seq=max_seq)
    assert tick_process(client) == {"enqueued": 0, "delivered": 0}
    assert cb.calls == []
    st = client.get(f"/audit/subscriptions/{sub['subscription_id']}").get_json()
    # 游标越过视图上界，无投递
    assert st["counters"]["confirmed"] == 0


def test_empty_when_filters_match_nothing(client, cb):
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"])
    sub = create_sub(client, key="k-f",
                     filters={"event_types": ["no_such_event"]})
    tick_process(client)
    assert cb.calls == []
    # 未匹配事件只推进游标，不生成投递记录
    rv = client.get(
        f"/audit/subscriptions/{sub['subscription_id']}/deliveries")
    assert rv.get_json()["deliveries"] == []
    st = client.get(f"/audit/subscriptions/{sub['subscription_id']}").get_json()
    assert st["position_seq"] > st["snapshot_seq"] or \
        st["position_seq"] == st["snapshot_seq"] + 1


# ---------------------------------------------------------------------------
# 3. 过滤
# ---------------------------------------------------------------------------


def test_filters_only_matching_events_delivered(client, cb):
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"], value="a")
    write_ok(client, "r1", generation=lease["generation"], value="b")
    sub = create_sub(client, key="k-f2",
                     filters={"event_types": ["write"]})
    for _ in range(2):
        tick_process(client)
    types = [c["payload"]["event_type"] for c in cb.calls]
    assert types == ["write", "write"]
    # 订阅序号对匹配事件从 1 连续编号
    assert [c["payload"]["subscription_seq"] for c in cb.calls] == [1, 2]
    rv = client.get(
        f"/audit/subscriptions/{sub['subscription_id']}/deliveries")
    assert len(rv.get_json()["deliveries"]) == 2


def test_filter_outcome_rejected(client, cb):
    # 无租约写入被拒也入历史；只订阅 rejected
    rv = client.post("/resources/r1/writes", json={
        "holder": "x", "generation": 1, "value": "v"})
    assert rv.status_code == 412
    sub = create_sub(client, key="k-f3",
                     filters={"outcomes": ["rejected"]})
    tick_process(client)
    assert len(cb.calls) == 1
    assert cb.calls[0]["payload"]["summary"]["outcome"] == "rejected"


# ---------------------------------------------------------------------------
# 4. 重复确认 / 错误签名
# ---------------------------------------------------------------------------


def test_duplicate_ack_does_not_advance_twice(client, cb):
    acquire(client, "r1")
    sub = create_sub(client, key="k-ack")
    sid = sub["subscription_id"]
    tick_process(client)
    seq = cb.calls[0]["payload"]["event_seq"]
    sig = cb.calls[0]["signature"]

    # 回调已 2xx 隐式确认；再用正确签名显式确认 -> 幂等回放
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{seq}/ack",
        json={"signature": sig})
    assert rv.status_code == 200
    assert rv.get_json()["replayed"] is True
    rv2 = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{seq}/ack",
        json={"signature": sig})
    assert rv2.status_code == 200 and rv2.get_json()["replayed"] is True

    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["counters"]["confirmed"] == 1
    # 投递记录仍只有一行
    rv = client.get(f"/audit/subscriptions/{sid}/deliveries")
    assert len(rv.get_json()["deliveries"]) == 1


def test_bad_signature_ack_does_not_change_state(app, client):
    cb2 = ScriptedCallback()
    # 回调返回 202：等待显式确认
    cb2.default = HttpDeliveryResult(status=202, ack_pending=True)
    app.extensions["subscriptions"]._deliver_cb = cb2
    acquire(client, "r1")
    sub = create_sub(client, key="k-badsig")
    sid = sub["subscription_id"]
    tick_process(client)
    seq = cb2.calls[0]["payload"]["event_seq"]

    # 错误签名：401，状态保持 awaiting_confirm
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{seq}/ack",
        json={"signature": "0" * 64})
    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_signature"
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/{seq}").get_json()
    assert d["status"] == D_AWAITING

    # 签名也可放 X-Signature 头
    good = cb2.calls[0]["signature"]
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{seq}/ack",
        json={}, headers={"X-Signature": good})
    assert rv.status_code == 200
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/{seq}").get_json()
    assert d["status"] == D_CONFIRMED


def test_ack_unknown_delivery_404(client, cb):
    acquire(client, "r1")
    sub = create_sub(client, key="k-404")
    sid = sub["subscription_id"]
    tick_process(client)
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/999999/ack",
        json={"signature": "x"})
    assert rv.status_code == 404


# ---------------------------------------------------------------------------
# 5. 并发投递：每个事件恰好投递一次
# ---------------------------------------------------------------------------


def test_concurrent_ack_confirms_once(app, client):
    """同一投递的并发确认只能确认一次，状态不回退、不重复推进。"""
    c2 = ScriptedCallback()
    c2.default = HttpDeliveryResult(status=202, ack_pending=True)
    app.extensions["subscriptions"]._deliver_cb = c2
    acquire(client, "r1")
    write_ok(client, "r1", generation=1)
    sub = create_sub(client, key="k-concack")
    sid = sub["subscription_id"]
    tick_process(client)
    # seq1 返回 202 后停在 awaiting_confirm，严格顺序挡住 seq2
    assert len(c2.calls) == 1
    sig = c2.calls[0]["signature"]
    seq = c2.calls[0]["payload"]["event_seq"]
    assert seq == 1

    outcomes = []
    barrier = threading.Barrier(8)

    def ack():
        c = app.test_client()
        barrier.wait()
        rv = c.post(
            f"/audit/subscriptions/{sid}/deliveries/{seq}/ack",
            json={"signature": sig})
        outcomes.append(rv.status_code)

    threads = [threading.Thread(target=ack) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 只有一个确认把状态从 awaiting 推到 confirmed；其余要么 200 幂等回放、
    # 要么 409（状态竞争），绝不出现重复确认/重复推进
    assert set(outcomes) <= {200, 409}
    d = client.get(
        f"/audit/subscriptions/{sid}/deliveries/{seq}").get_json()
    assert d["status"] == D_CONFIRMED
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["counters"]["confirmed"] == 1

    # seq1 确认后 seq2 严格接上（202 → 等待显式确认）
    tick_process(client)
    assert [x["payload"]["event_seq"] for x in c2.calls] == [1, 2]


def test_concurrent_dispatch_exactly_once(app, client, cb):
    lease = acquire(client, "r1")
    for i in range(5):
        write_ok(client, "r1", generation=lease["generation"], value=f"v{i}")
    create_sub(client, key="k-conc")
    subs(client).scan_and_enqueue()  # 先入队，再并发投递

    errors = []

    def worker():
        try:
            for _ in range(10):
                subs(client).process_due()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []

    # 每个事件恰好投递一次
    seqs = delivered_seqs(cb)
    assert sorted(seqs) == sorted(set(seqs))
    # 全部 6 条（acquire + 5 writes）最终确认
    assert len(seqs) == 6


# ---------------------------------------------------------------------------
# 6. 回调失败 / 超时 / 非成功状态：退避重试后成功
# ---------------------------------------------------------------------------


def test_failure_retry_with_backoff_then_success(client, cb):
    acquire(client, "r1")
    cb.set_script({1: cb.fail(2, status=503)})
    sub = create_sub(client, key="k-retry")
    sid = sub["subscription_id"]

    tick_process(client)  # 第 1 次尝试失败
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d["status"] == D_PENDING and d["attempts"] == 1
    assert d["last_error"] == "http_status_503"
    first_retry = d["next_retry_at_ms"]
    assert first_retry >= store(client).clock.wall_ms()

    # 退避未到点：不重复投递
    tick_process(client)
    assert len(cb.calls) == 1

    # 时间推进过首个退避点：第 2 次尝试失败，按 2 倍退避重新排队
    client.post("/debug/wall-shift", json={"delta_ms": 5_000})
    tick_process(client)
    assert len(cb.calls) == 2
    tick_process(client)  # 仍在退避窗口
    assert len(cb.calls) == 2

    # 再推进过 2 倍退避点：第 3 次尝试成功（脚本中失败已用完）
    client.post("/debug/wall-shift", json={"delta_ms": 60_000})
    tick_process(client)
    assert len(cb.calls) == 3
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d["status"] == D_CONFIRMED and d["attempts"] == 3


def test_timeout_treated_as_failure(client, cb):
    subs(client).base_backoff_ms = 0
    acquire(client, "r1")
    cb.set_script({1: cb.timeout(1)})
    sub = create_sub(client, key="k-timeout")
    sid = sub["subscription_id"]
    tick_process(client)
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d["status"] == D_PENDING and d["attempts"] == 1
    assert "timeout" in d["last_error"]
    tick_process(client)
    assert client.get(
        f"/audit/subscriptions/{sid}/deliveries/1").get_json()["status"] \
        == D_CONFIRMED


def test_head_failure_blocks_later_events(client, cb):
    """严格顺序：队首未确认，后来事件不能插到前面。"""
    subs(client).base_backoff_ms = 10_000_000
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"])
    cb.set_script({1: cb.fail(5, status=500)})
    create_sub(client, key="k-block", max_attempts=10)
    for _ in range(3):
        tick_process(client)
    # seq1 一直失败退避；seq2 从未投递
    assert delivered_seqs(cb) == [1]


# ---------------------------------------------------------------------------
# 7. 死信与恢复
# ---------------------------------------------------------------------------


def test_dead_letter_blocks_queue_and_requeue_resumes(client, cb):
    subs(client).base_backoff_ms = 0
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"])
    write_ok(client, "r1", generation=lease["generation"])
    cb.set_script({1: cb.fail(3, status=500)})  # 始终失败
    create_sub(client, key="k-dead", max_attempts=3)

    for _ in range(5):
        tick_process(client)

    sid = client.get("/audit/subscriptions?scope=resource").get_json()[
        "subscriptions"][0]["subscription_id"]
    d1 = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d1["status"] == D_DEAD
    assert d1["dead_letter_reason"] == "max_attempts_exceeded"
    assert d1["attempts"] == 3

    # 订阅被死信挡住，seq2/3 没有投递（3 次失败尝试都只针对 seq1）
    assert delivered_seqs(cb) == [1, 1, 1]
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["blocked"] is True
    assert st["counters"]["dead_letter"] == 1

    # 死信列表可见原因
    dl = client.get("/audit/subscriptions/dead-letters").get_json()
    assert len(dl["dead_letters"]) == 1
    assert dl["dead_letters"][0]["last_error"] == "http_status_500"
    dl2 = client.get(
        f"/audit/subscriptions/dead-letters?subscription_id={sid}").get_json()
    assert len(dl2["dead_letters"]) == 1

    # 让回调恢复成功，重新放回队列
    cb.set_script({})
    rv = client.post(
        f"/audit/subscriptions/{sid}/dead-letters/1/requeue", json={})
    assert rv.status_code == 200
    assert rv.get_json()["status"] == D_PENDING
    assert rv.get_json()["attempts"] == 0
    for _ in range(4):
        tick_process(client)
    # 死信重新投递成功后，严格按顺序继续 2、3（无跳过）
    assert delivered_seqs(cb) == [1, 1, 1, 1, 2, 3]
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["blocked"] is False
    assert st["counters"]["dead_letter"] == 0


def test_permanent_reject_410_goes_straight_to_dead_letter(client, cb):
    acquire(client, "r1")
    cb.set_script({1: cb.fail(1, permanent=True)})
    create_sub(client, key="k-410", max_attempts=10)
    tick_process(client)
    sid = client.get("/audit/subscriptions").get_json()["subscriptions"][0][
        "subscription_id"]
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d["status"] == D_DEAD
    assert d["attempts"] == 1
    assert d["dead_letter_reason"] == "permanent_reject_410"


def test_requeue_non_dead_letter_is_409(client, cb):
    acquire(client, "r1")
    create_sub(client, key="k-rq")
    sid = client.get("/audit/subscriptions").get_json()["subscriptions"][0][
        "subscription_id"]
    tick_process(client)
    rv = client.post(
        f"/audit/subscriptions/{sid}/dead-letters/1/requeue", json={})
    assert rv.status_code == 409


# ---------------------------------------------------------------------------
# 8. 暂停 / 恢复
# ---------------------------------------------------------------------------


def test_pause_blocks_resume_continues_in_order(client, cb):
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"])
    sub = create_sub(client, key="k-pause")
    sid = sub["subscription_id"]

    rv = client.post(f"/audit/subscriptions/{sid}/pause", json={})
    assert rv.status_code == 200 and rv.get_json()["status"] == "paused"
    assert tick_process(client) == {"enqueued": 0, "delivered": 0}
    assert cb.calls == []

    # 重复暂停幂等
    assert client.post(f"/audit/subscriptions/{sid}/pause",
                       json={}).get_json()["status"] == "paused"
    # 恢复（重复恢复也幂等）
    rv = client.post(f"/audit/subscriptions/{sid}/resume", json={})
    assert rv.get_json()["status"] == "active"
    rv = client.post(f"/audit/subscriptions/{sid}/resume", json={})
    assert rv.get_json()["status"] == "active"

    for _ in range(2):
        tick_process(client)
    assert len(cb.calls) == 2
    assert delivered_seqs(cb) == sorted(delivered_seqs(cb))


def test_pause_during_inflight_is_recovered_on_resume(app, client):
    """投递回调期间暂停：迟到成功不确认；恢复时回收 inflight 继续投递。"""
    gate = threading.Event()
    proceed = threading.Event()

    def deliver(url, payload, signature):
        if payload["event_seq"] == 1:
            gate.set()
            proceed.wait(2.0)
        return HttpDeliveryResult(ok=True)

    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"])
    sub = create_sub(client, key="k-pi")
    sid = sub["subscription_id"]
    app.extensions["subscriptions"]._deliver_cb = deliver

    t = threading.Thread(
        target=lambda: app.test_client().post(
            "/audit/subscriptions/process", json={}))
    t.start()
    assert gate.wait(2.0)
    client.post(f"/audit/subscriptions/{sid}/pause", json={})
    proceed.set()
    t.join()

    # 暂停后的迟到成功不确认（行仍为 inflight，队列未推进）
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d["status"] in (D_INFLIGHT, D_PENDING)
    # 恢复时回收 inflight，继续投递并确认
    client.post(f"/audit/subscriptions/{sid}/resume", json={})
    for _ in range(3):
        tick_process(client)
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d["status"] == D_CONFIRMED
    seqs = client.get(
        f"/audit/subscriptions/{sid}/deliveries?limit=10").get_json()
    assert [x["event_seq"] for x in seqs["deliveries"]] == [1, 2]


def test_cancel_then_late_success_is_ignored(app, client):
    """取消后进行中回调的迟到成功响应不能再推进任何东西。"""
    worker_client = app.test_client()
    gate = threading.Event()
    cancel_now = threading.Event()

    def deliver(url, payload, signature):
        if payload["event_seq"] == 1:
            # 在回调进行中由另一个线程（独立请求上下文）取消订阅，
            # 再返回一个"迟到的成功"
            cancel_now.set()
            gate.wait(2.0)
            return HttpDeliveryResult(ok=True)
        return HttpDeliveryResult(ok=True)

    acquire(client, "r1")
    write_ok(client, "r1", generation=1)
    sub = create_sub(client, key="k-cancel")
    sid = sub["subscription_id"]
    app.extensions["subscriptions"]._deliver_cb = deliver

    def process():
        worker_client.post("/audit/subscriptions/process", json={})

    t = threading.Thread(target=process)
    t.start()
    assert cancel_now.wait(2.0)
    rv = client.post(f"/audit/subscriptions/{sid}/cancel", json={})
    assert rv.status_code == 200
    gate.set()
    t.join()

    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["status"] == "cancelled"
    # 行保持 discarded，没有被迟到成功改成 confirmed
    d = client.get(f"/audit/subscriptions/{sid}/deliveries/1").get_json()
    assert d["status"] == "discarded"
    # 取消后扫描不再入队、不再投递
    write_ok(client, "r1", generation=1)
    assert tick_process(client) == {"enqueued": 0, "delivered": 0}


def test_cancel_is_idempotent_and_cannot_resume(client, cb):
    acquire(client, "r1")
    sub = create_sub(client, key="k-cancel2")
    sid = sub["subscription_id"]
    assert client.post(f"/audit/subscriptions/{sid}/cancel",
                       json={}).status_code == 200
    assert client.post(f"/audit/subscriptions/{sid}/cancel",
                       json={}).status_code == 200
    assert client.post(f"/audit/subscriptions/{sid}/resume",
                       json={}).status_code == 409
    assert client.post(f"/audit/subscriptions/{sid}/pause",
                       json={}).status_code == 409


# ---------------------------------------------------------------------------
# 9. 服务重启：inflight 回收、状态持久化、不丢不重不乱序
# ---------------------------------------------------------------------------


def test_restart_reclaims_inflight_and_continues(tmp_path, cb_unused=None):
    db = str(tmp_path / "restart.db")
    app1 = create_app(db, start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c1 = app1.test_client()
    cb1 = ScriptedCallback()
    app1.extensions["subscriptions"]._deliver_cb = cb1

    lease = acquire(c1, "r1")
    write_ok(c1, "r1", generation=lease["generation"])
    sub = create_sub(c1, key="k-restart")
    sid = sub["subscription_id"]
    tick_process(c1)  # seq1 确认
    assert delivered_seqs(cb1) == [1]

    # 模拟崩溃：seq2 的投递正进行中（inflight），进程随即死亡
    sconn = store(c1)
    mgr1 = app1.extensions["subscriptions"]
    with mgr1._lock:
        now = sconn.clock.wall_ms()
        mgr1._conn.execute(
            "UPDATE audit_subscription_deliveries SET status='inflight', "
            "dispatch_token='ghost', claimed_at_ms=?, updated_at_ms=? "
            "WHERE event_seq=2", (now, now))
        mgr1._conn.commit()

    # ---- 进程重启：新 app 复用同一数据库 ----
    app2 = create_app(db, start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    c2 = app2.test_client()
    cb2 = ScriptedCallback()
    app2.extensions["subscriptions"]._deliver_cb = cb2

    # 启动即把残留 inflight 回收为 pending（attempts 不增加）
    d = c2.get(f"/audit/subscriptions/{sid}/deliveries/2").get_json()
    assert d["status"] == D_PENDING and d["attempts"] == 0
    # 订阅与已确认记录都还在
    st = c2.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["counters"]["confirmed"] == 1
    tick_process(c2)
    assert delivered_seqs(cb2) == [2]
    assert c2.get(
        f"/audit/subscriptions/{sid}/deliveries/1").get_json()["status"] \
        == D_CONFIRMED


def test_restart_paused_and_position_survive(tmp_path):
    db = str(tmp_path / "restart2.db")
    app1 = create_app(db, start_ticker=False, start_archive_worker=False)
    c1 = app1.test_client()
    app1.extensions["subscriptions"]._deliver_cb = ScriptedCallback()
    acquire(c1, "r1")
    sub = create_sub(c1, key="k-pr")
    sid = sub["subscription_id"]
    subs(c1).scan_and_enqueue()  # 入队后再暂停：投递行已存在
    c1.post(f"/audit/subscriptions/{sid}/pause", json={})
    subs(c1).process_due()  # 暂停状态不投递

    app2 = create_app(db, start_ticker=False, start_archive_worker=False)
    c2 = app2.test_client()
    st = c2.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["status"] == "paused"
    # 暂停期间已扫描入队但未投递的记录仍在
    rv = c2.get(f"/audit/subscriptions/{sid}/deliveries").get_json()
    assert len(rv["deliveries"]) == 1
    assert rv["deliveries"][0]["status"] == D_PENDING


# ---------------------------------------------------------------------------
# 10. 起始序号越界
# ---------------------------------------------------------------------------


def test_start_seq_out_of_range_is_416(client, cb):
    acquire(client, "r1")
    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "r1",
        "callback_url": "http://x/y", "start_seq": 999999,
        "idempotency_key": "k-oor"})
    assert rv.status_code == 416
    body = rv.get_json()
    assert body["error"] == "subscription_seq_out_of_range"
    assert body["available_max_seq"] == 1


def test_negative_start_seq_is_400(client, cb):
    acquire(client, "r1")
    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "r1",
        "callback_url": "http://x/y", "start_seq": -1,
        "idempotency_key": "k-neg"})
    assert rv.status_code == 400


def test_unknown_target_is_404(client, cb):
    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "ghost",
        "callback_url": "http://x/y", "start_seq": 0,
        "idempotency_key": "k-ghost"})
    assert rv.status_code == 404


# ---------------------------------------------------------------------------
# 11. 幂等：同键同订阅回放；换过滤/回调/起始序号冲突
# ---------------------------------------------------------------------------


def test_idempotent_key_returns_same_subscription(client, cb):
    acquire(client, "r1")
    s1 = create_sub(client, key="k-idem", start_seq=1,
                    filters={"event_types": ["write"]})
    s2 = create_sub(client, key="k-idem", start_seq=1,
                    filters={"event_types": ["write"]}, expect=200)
    assert s2["subscription_id"] == s1["subscription_id"]
    assert s2["replayed"] is True
    # 列表也只有一条
    items = client.get("/audit/subscriptions").get_json()["subscriptions"]
    assert len(items) == 1


def test_idempotency_conflict_on_changed_filter(client, cb):
    acquire(client, "r1")
    create_sub(client, key="k-ic", filters={"event_types": ["write"]})
    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "r1",
        "callback_url": "http://callback.test/hook", "start_seq": 0,
        "filters": {"event_types": ["acquire"]}, "idempotency_key": "k-ic"})
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "subscription_id_conflict"
    assert body["first_difference"]["path"] == "filters"


def test_idempotency_conflict_on_changed_url_and_start(client, cb):
    acquire(client, "r1")
    create_sub(client, key="k-ic2", start_seq=1)
    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "r1",
        "callback_url": "http://other.example/hook", "start_seq": 1,
        "idempotency_key": "k-ic2"})
    assert rv.status_code == 409
    assert rv.get_json()["first_difference"]["path"] == "callback_url"

    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "r1",
        "callback_url": "http://callback.test/hook", "start_seq": 0,
        "idempotency_key": "k-ic2"})
    # start_seq 相同时在 callback_url 处先撞；这里换成一致 url 再试 start
    assert rv.status_code == 409
    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "r1",
        "callback_url": "http://callback.test/hook",
        "start_seq": 0 if False else 1, "idempotency_key": "k-ic2"})
    assert rv.status_code == 200  # 完全一致回放
    rv = client.post("/audit/subscriptions", json={
        "scope": "resource", "resource": "r1",
        "callback_url": "http://callback.test/hook", "start_seq": 0,
        "idempotency_key": "k-ic2"})
    assert rv.status_code == 409
    assert rv.get_json()["first_difference"]["path"] == "start_seq"


# ---------------------------------------------------------------------------
# 12. 创建期间的新事件不被塞入更早快照
# ---------------------------------------------------------------------------


def test_idempotent_replay_omits_optional_max_attempts(client, cb):
    """省略的可选参数不参与幂等冲突比较；显式给出不同值仍 409。"""
    acquire(client, "r1")
    payload = {"scope": "resource", "resource": "r1",
               "callback_url": "http://callback.test/hook", "start_seq": 0}
    r1 = client.post("/audit/subscriptions",
                     json={**payload, "idempotency_key": "k-ma",
                           "max_attempts": 7})
    assert r1.status_code == 201
    # 重放时省略 max_attempts：同一订阅
    r2 = client.post("/audit/subscriptions",
                     json={**payload, "idempotency_key": "k-ma"})
    assert r2.status_code == 200
    assert r2.get_json()["subscription_id"] == \
        r1.get_json()["subscription_id"]
    # 显式给不同值：冲突
    r3 = client.post("/audit/subscriptions",
                     json={**payload, "idempotency_key": "k-ma",
                           "max_attempts": 8})
    assert r3.status_code == 409
    assert r3.get_json()["first_difference"]["path"] == "max_attempts"


def test_concurrent_create_with_same_idempotency_key_returns_one(app):
    # 先在主客户端上准备历史
    main = app.test_client()
    acquire(main, "r1")

    results = []
    barrier = threading.Barrier(8)

    def create():
        # Flask 测试客户端的请求上下文是 contextvar，每线程独立客户端
        c = app.test_client()
        barrier.wait()
        rv = c.post("/audit/subscriptions", json={
            "scope": "resource", "resource": "r1",
            "callback_url": "http://callback.test/hook",
            "start_seq": 0, "idempotency_key": "k-race"})
        results.append((rv.status_code, rv.get_json()["subscription_id"]))

    threads = [threading.Thread(target=create) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {sid for _, sid in results}
    assert len(ids) == 1                       # 只产生一个订阅
    assert all(code in (200, 201) for code, _ in results)
    items = main.get("/audit/subscriptions").get_json()["subscriptions"]
    assert len(items) == 1


def test_events_after_create_keep_strict_order_and_snapshot(client, cb):
    lease = acquire(client, "r1")  # seq1
    sub = create_sub(client, key="k-snap")
    sid = sub["subscription_id"]
    snapshot = sub["snapshot_seq"]

    write_ok(client, "r1", generation=lease["generation"])  # seq snapshot+1
    write_ok(client, "r1", generation=lease["generation"])  # seq snapshot+2
    for _ in range(3):
        tick_process(client)

    seqs = delivered_seqs(cb)
    assert seqs == [1, snapshot + 1, snapshot + 2]
    # 订阅视图里的快照上界不随新事件改变
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["snapshot_seq"] == snapshot


# ---------------------------------------------------------------------------
# 13. 从指定序号重新开始：保留历史、已确认不重复确认
# ---------------------------------------------------------------------------


def test_restart_from_retains_history_and_continues(client, cb):
    lease = acquire(client, "r1")                              # seq1
    write_ok(client, "r1", generation=lease["generation"])     # seq2
    write_ok(client, "r1", generation=lease["generation"])     # seq3
    cb.set_script({2: cb.fail(5, status=500)})
    sub = create_sub(client, key="k-rf", max_attempts=10)
    sid = sub["subscription_id"]
    tick_process(client)            # seq1 投递成功
    tick_process(client)            # seq2 投递失败，退避 1s
    assert delivered_seqs(cb) == [1, 2]
    # 用手动重试驱动后续两次失败尝试（忽略退避），seq3 始终被挡
    client.post(f"/audit/subscriptions/{sid}/deliveries/2/retry", json={})
    tick_process(client)
    client.post(f"/audit/subscriptions/{sid}/deliveries/2/retry", json={})
    tick_process(client)
    assert delivered_seqs(cb) == [1, 2, 2, 2]

    # 新事件在重新开始之前落库
    write_ok(client, "r1", generation=lease["generation"])     # seq4

    rv = client.post(f"/audit/subscriptions/{sid}/restart-from",
                     json={"from_seq": 2})
    assert rv.status_code == 200
    # 区间内事件已重新扫描入队，游标停在当前历史末端做尾部追平
    assert rv.get_json()["position_seq"] >= 5

    # 历史投递记录全部保留（包括 seq1 confirmed、seq2 的失败尝试痕迹被复位）
    rv = client.get(
        f"/audit/subscriptions/{sid}/deliveries?limit=100").get_json()
    seqs = [d["event_seq"] for d in rv["deliveries"]]
    assert seqs == [1, 2, 3, 4]
    d1 = next(d for d in rv["deliveries"] if d["event_seq"] == 1)
    assert d1["status"] == D_CONFIRMED  # 已确认行不被重置
    d2 = next(d for d in rv["deliveries"] if d["event_seq"] == 2)
    assert d2["status"] == D_PENDING and d2["attempts"] == 0

    # 回调恢复：重新投递 seq2 后严格按顺序继续 3、4
    cb.set_script({})
    for _ in range(4):
        tick_process(client)
    assert delivered_seqs(cb) == [1, 2, 2, 2, 2, 3, 4]
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["counters"]["confirmed"] == 4
    # seq1 自始至终只有一次确认
    assert sum(1 for c in cb.calls if c["payload"]["event_seq"] == 1) == 1


def test_restart_from_cancelled_is_409_and_range_416(client, cb):
    acquire(client, "r1")
    sub = create_sub(client, key="k-rf2")
    sid = sub["subscription_id"]
    client.post(f"/audit/subscriptions/{sid}/cancel", json={})
    rv = client.post(f"/audit/subscriptions/{sid}/restart-from",
                     json={"from_seq": 1})
    assert rv.status_code == 409
    rv = client.post("/audit/subscriptions/does-not-exist/restart-from",
                     json={"from_seq": 1})
    assert rv.status_code == 404
    client.post(f"/audit/subscriptions/{sid}/resume", json={})  # noop 409


def test_restart_from_unknown_subscription_404(client):
    rv = client.post("/audit/subscriptions/nope/restart-from",
                     json={"from_seq": 0})
    assert rv.status_code == 404


# ---------------------------------------------------------------------------
# 14. 分页读取投递历史
# ---------------------------------------------------------------------------


def test_delivery_history_pagination(client, cb):
    lease = acquire(client, "r1")
    for i in range(5):
        write_ok(client, "r1", generation=lease["generation"], value=str(i))
    sub = create_sub(client, key="k-page")
    sid = sub["subscription_id"]
    for _ in range(6):
        tick_process(client)

    seen = []
    after = None
    pages = 0
    while True:
        url = f"/audit/subscriptions/{sid}/deliveries?limit=2"
        if after is not None:
            url += f"&after={after}"
        body = client.get(url).get_json()
        pages += 1
        batch = body["deliveries"]
        seen.extend(d["event_seq"] for d in batch)
        if body["next"] is None:
            assert body["reached_end"] is True
            break
        after = body["next"]
    assert pages == 3
    assert seen == sorted(seen) and len(seen) == 6

    # 状态过滤
    body = client.get(
        f"/audit/subscriptions/{sid}/deliveries?status=confirmed").get_json()
    assert all(d["status"] == D_CONFIRMED for d in body["deliveries"])
    assert len(body["deliveries"]) == 6


# ---------------------------------------------------------------------------
# 15. 其他作用域：委托凭证 / 因果索引 / 发布版本
# ---------------------------------------------------------------------------


def test_credential_scope_subscription(client, cb):
    lease = acquire(client, "r1")
    rv = client.post("/leases/delegations", json={
        "resource": "r1", "holder": "h1",
        "generation": lease["generation"],
        "collaborator": "c1", "ttl_ms": 60_000})
    assert rv.status_code == 201
    cid = rv.get_json()["delegation"]["credential_id"]

    create_sub(client, scope="credential", resource=cid,
               key="k-cid", start_seq=0)
    # 协作者用凭证写两次
    for v in ("a", "b"):
        rv = client.post("/resources/r1/writes", json={
            "holder": "c1", "credential_id": cid, "value": v})
        assert rv.status_code == 201
    for _ in range(4):
        tick_process(client)

    # 收到的全部是该凭证的事件（发放 + 两次使用）
    assert cb.calls
    for call in cb.calls:
        assert call["payload"]["object"]["credential_id"] == cid
    types = [c["payload"]["event_type"] for c in cb.calls]
    assert types == ["delegate_grant", "delegate_write", "delegate_write"]


def _build_completed_causal_index(client, resource="r1",
                                  existing_lease=None):
    if existing_lease is None:
        lease = acquire(client, resource)
        write_ok(client, resource, generation=lease["generation"])
    else:
        lease = existing_lease
    rv = client.post("/audit/causal-indexes", json={
        "scope": "resource", "resource": resource, "head": True,
        "idempotency_key": "ci-" + resource})
    assert rv.status_code == 201, rv.get_json()
    index_id = rv.get_json()["index_id"]
    mgr = client.application.extensions["causal"]
    for _ in range(100):
        mgr.process_pending()
        st = client.get(f"/audit/causal-indexes/{index_id}").get_json()
        if st["status"] == "completed":
            return index_id, lease
        assert st["status"] != "failed", st
    raise AssertionError("因果索引未能完成")


def test_causal_index_scope_and_frozen_boundary(client, cb):
    index_id, lease = _build_completed_causal_index(client, "r1")
    create_sub(client, scope="causal_index", resource=index_id,
               key="k-ci", start_seq=0)
    for _ in range(3):
        tick_process(client)
    # 冻结成员里的事件全部投递（acquire + write）
    assert delivered_seqs(cb) == [1, 2]

    # 索引冻结之后产生的新事件进不了订阅范围（成员集合已冻结）
    write_ok(client, "r1", generation=lease["generation"])
    tick_process(client)
    assert delivered_seqs(cb) == [1, 2]


def test_release_scope_subscription(client, cb):
    index_id, _ = _build_completed_causal_index(client, "r1")
    now = store(client).clock.wall_ms()
    rv = client.post("/audit/index-releases", json={
        "version": "v1", "index_id": index_id,
        "idempotency_key": "rel-1", "effective_at_ms": now - 1})
    assert rv.status_code == 201, rv.get_json()
    release_id = rv.get_json()["release_id"]
    create_sub(client, scope="release", resource=release_id,
               key="k-rel", start_seq=0)
    for _ in range(3):
        tick_process(client)
    assert delivered_seqs(cb) == [1, 2]
    assert cb.calls[0]["payload"]["object"]["release_id"] == release_id
    assert cb.calls[0]["payload"]["object"]["index_id"] == index_id


def test_unknown_causal_index_and_release_404(client, cb):
    rv = client.post("/audit/subscriptions", json={
        "scope": "causal_index", "index_id": "nope",
        "callback_url": "http://x/y", "start_seq": 0,
        "idempotency_key": "kx1"})
    assert rv.status_code == 404
    rv = client.post("/audit/subscriptions", json={
        "scope": "release", "release_id": "nope",
        "callback_url": "http://x/y", "start_seq": 0,
        "idempotency_key": "kx2"})
    assert rv.status_code == 404


# ---------------------------------------------------------------------------
# 稀疏交错事件：扫描按全局序号分窗口，不能因 per-scope LIMIT 跳过事件
# ---------------------------------------------------------------------------


def test_scan_window_does_not_skip_sparse_scope_events(client, cb):
    # r-sparse 事件稀疏地交错在大量 r-other 事件中（全局序号 1、6、8）
    lease1 = acquire(client, "r-sparse")                            # 1
    lease2 = acquire(client, "r-other")                            # 2
    write_ok(client, "r-other", generation=lease2["generation"])   # 3
    write_ok(client, "r-other", generation=lease2["generation"])   # 4
    write_ok(client, "r-other", generation=lease2["generation"])   # 5
    write_ok(client, "r-sparse", generation=lease1["generation"])  # 6
    write_ok(client, "r-other", generation=lease2["generation"])   # 7
    write_ok(client, "r-sparse", generation=lease1["generation"])  # 8

    sub = create_sub(client, resource="r-sparse", key="k-sparse")
    sid = sub["subscription_id"]
    mgr = subs(client)
    # 强制每次只扫描 2 个全局序号的小窗口，多轮也必须覆盖全部事件
    for _ in range(30):
        mgr.scan_and_enqueue(max_events=2)
        mgr.process_due()
    assert delivered_seqs(cb) == [1, 6, 8]
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["position_seq"] == 9


# ---------------------------------------------------------------------------
# 16. 真实 HTTP 回调（urllib + 本地服务器，校验签名头）
# ---------------------------------------------------------------------------


def test_real_http_callback_with_signature_headers(tmp_path):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            received.append({
                "payload": json.loads(body),
                "sig": self.headers.get("X-Signature"),
                "alg": self.headers.get("X-Signature-Algorithm"),
                "sid": self.headers.get("X-Subscription-Id"),
                "sseq": self.headers.get("X-Subscription-Seq"),
            })
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        app = create_app(str(tmp_path / "http.db"), start_ticker=False,
                         enable_debug_api=True, start_archive_worker=False)
        c = app.test_client()
        lease = acquire(c, "r1")
        write_ok(c, "r1", generation=lease["generation"])
        sub = create_sub(
            c, key="k-http",
            callback_url=f"http://127.0.0.1:{port}/hook")
        sid = sub["subscription_id"]
        c.post("/audit/subscriptions/process", json={})
        c.post("/audit/subscriptions/process", json={})
        assert len(received) == 2
        secret = _secret(c, sid)
        for rec in received:
            expect = hmac.new(
                secret.encode(),
                canonical_json(rec["payload"]).encode(),
                hashlib.sha256).hexdigest()
            assert hmac.compare_digest(rec["sig"], expect)
            assert rec["alg"] == "HMAC-SHA256"
            assert rec["sid"] == sid
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# 17. 订阅流程绝不改写源数据
# ---------------------------------------------------------------------------


def test_subscription_flow_never_mutates_sources(client, cb):
    lease = acquire(client, "r1")
    write_ok(client, "r1", generation=lease["generation"], value="orig")
    index_id, _ = _build_completed_causal_index(
        client, "r1", existing_lease=lease)
    now = store(client).clock.wall_ms()
    rv = client.post("/audit/index-releases", json={
        "version": "vX", "index_id": index_id, "idempotency_key": "rel-x",
        "effective_at_ms": now - 1})
    release_id = rv.get_json()["release_id"]

    s = store(client)

    def snapshot_sources():
        conn = s._conn
        with s._lock:
            out = {}
            for table in ("leases", "resources", "writes", "delegations",
                          "lease_events", "transfers", "archives",
                          "archive_events", "evidence_packages",
                          "evidence_entries", "evidence_entry_contents",
                          "causal_indexes", "causal_index_members",
                          "causal_index_nodes", "index_releases"):
                rows = conn.execute(
                    f"SELECT * FROM {table} ORDER BY 1").fetchall()
                out[table] = [dict(r) for r in rows]
            conn.rollback()
        return out

    # 完整生命周期：创建、成功、失败、死信、重新放回、暂停、恢复、重启游标、
    # 错误签名确认、取消（快照在所有源数据操作之后拍摄，订阅流程期间
    # 不再有任何合法的源数据变更）
    write_ok(client, "r1", generation=lease["generation"], value="new")
    before = snapshot_sources()
    subs(client).base_backoff_ms = 0
    cb.set_script({2: cb.fail(1, status=500)})
    sub = create_sub(client, key="k-readonly")
    sid = sub["subscription_id"]
    for _ in range(4):
        tick_process(client)
    client.post(
        f"/audit/subscriptions/{sid}/deliveries/1/ack",
        json={"signature": "bad"})
    client.post(f"/audit/subscriptions/{sid}/dead-letters/999/requeue",
                json={})
    client.post(f"/audit/subscriptions/{sid}/pause", json={})
    client.post(f"/audit/subscriptions/{sid}/resume", json={})
    client.post(f"/audit/subscriptions/{sid}/restart-from",
                json={"from_seq": 1})
    for _ in range(4):
        tick_process(client)
    client.post(f"/audit/subscriptions/{sid}/cancel", json={})

    after = snapshot_sources()
    assert before == after

    # 全局审计诊断仍然一致（seq 无缺号/被改）
    diag = client.get("/audit/diagnose").get_json()
    assert diag["summary"]["consistent"] is True
    # 资源值没被动过
    assert client.get("/resources/r1").get_json()["value"] == "new"


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------


def _secret(client, subscription_id: str) -> str:
    """直接从订阅自有连接读取密钥（测试校验签名用，不经 API 暴露）。"""
    mgr = client.application.extensions["subscriptions"]
    with mgr._lock:
        row = mgr._conn.execute(
            "SELECT secret FROM audit_subscriptions "
            "WHERE subscription_id=?", (subscription_id,)).fetchone()
        mgr._conn.rollback()
        return row["secret"]
