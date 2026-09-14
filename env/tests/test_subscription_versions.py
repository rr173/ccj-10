"""订阅版本切换（subscription version switch）。

覆盖场景：
- 正常预创建与原子激活（版本状态、差异查询、订阅视图镜像）
- 切换前后事件路由：旧版本收尾只到 effective_seq-1，生效序号（含）后只进
  新版本；两个版本各自独立的订阅序号与密钥/回调，队列共享、互不越过
- 预创建等待期间的边界钉住：active 版本不得扫过 effective_seq-1
- 进行中投递按旧版本收尾（202 待确认通知用旧密钥签名/确认，旧回调地址）
- 幂等：创建/激活/取消/死信重试同键重放，换回调/过滤/生效序号/目标订阅/
  版本/操作类型均 409 明确冲突
- 生效序号越过当前稳定历史上界 -> 416 且原订阅不变；早于扫描位置 -> 409
- 并发激活：恰好一个成功，其余重放同一结果
- 死信：按版本分页查看、只重试某版本的死信、严格顺序不被越过
- 服务重启恢复：新 SubscriptionManager 从已保存状态继续，不重复不乱序
- 取消：订阅取消连带取消 prepared 版本；prepared 版本可单独取消
- 暂停订阅上不允许预创建/激活
- 审计：版本创建/激活/取消/重试与全部拒绝原因只追加进订阅自己的审计历史，
  绝不改写租约、委托、lease_events 原始审计事件或已有投递记录
"""

import hashlib
import hmac
import threading

import pytest

from app.app import create_app
from app.subscription import (
    D_AWAITING,
    D_CONFIRMED,
    D_DEAD,
    D_INFLIGHT,
    HttpDeliveryResult,
    canonical_json,
    SubscriptionManager,
    V_ACTIVE,
    V_CANCELLED,
    V_PREPARED,
    V_SUPERSEDED,
)


# ---------------------------------------------------------------------------
# fixture 与辅助
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        str(tmp_path / "subver.db"), start_ticker=False,
        enable_debug_api=True, start_archive_worker=False)
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    with app.test_client() as c:
        yield c


class ScriptedCallback:
    """记录所有通知，可按 event_seq 编排结果；可按 URL 分流。"""

    def __init__(self, *, default_ok=True):
        self.calls = []
        self.lock = threading.Lock()
        self.script = {}
        self.url_script = {}
        self.default = (HttpDeliveryResult(ok=True)
                        if default_ok else None)

    def fail(self, n=1, *, status=500, permanent=False):
        r = HttpDeliveryResult(status=410 if permanent else status,
                               permanent_reject=permanent,
                               error=None if permanent else f"http_status_{status}")
        return [r] * n

    def ack_pending(self):
        return HttpDeliveryResult(status=202, ack_pending=True)

    def set_script(self, mapping):
        self.script = {int(k): list(v) for k, v in mapping.items()}

    def __call__(self, url, payload, signature):
        with self.lock:
            self.calls.append({
                "url": url, "payload": payload, "signature": signature})
            seq = payload["event_seq"]
            for prefix, outcomes in self.url_script.items():
                if url.startswith(prefix):
                    if outcomes:
                        return outcomes.pop(0)
            outcomes = self.script.get(seq)
            if outcomes:
                return outcomes.pop(0)
            return self.default


@pytest.fixture()
def cb(app):
    callback = ScriptedCallback()
    app.extensions["subscriptions"]._deliver_cb = callback
    return callback


def mgr(client):
    return client.application.extensions["subscriptions"]


def acquire(client, resource="r1", holder="h1", ttl_ms=60_000):
    rv = client.post("/leases/acquire", json={
        "resource": resource, "holder": holder, "ttl_ms": ttl_ms})
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()["lease"]


def write_ok(client, resource="r1", holder="h1", generation=1, value="v"):
    rv = client.post(f"/resources/{resource}/writes", json={
        "holder": holder, "generation": generation, "value": value})
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()


def create_sub(client, *, resource="r1", key="sub-k",
               callback_url="http://old.test/hook", filters=None,
               start_seq=0, expect=201):
    body = {"scope": "resource", "resource": resource,
            "callback_url": callback_url, "start_seq": start_seq,
            "idempotency_key": key}
    if filters is not None:
        body["filters"] = filters
    rv = client.post("/audit/subscriptions", json=body)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def prepare(client, sid, *, key, callback_url="http://new.test/hook",
            filters=None, effective_seq=None, expect=201):
    body = {"callback_url": callback_url,
            "idempotency_key": key}
    if filters is not None:
        body["filters"] = filters
    if effective_seq is not None:
        body["effective_seq"] = effective_seq
    rv = client.post(f"/audit/subscriptions/{sid}/versions", json=body)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def activate(client, sid, no, *, key, expect=200):
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/{no}/activate",
        json={"idempotency_key": key})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def cancel_version(client, sid, no, *, key, expect=200):
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/{no}/cancel",
        json={"idempotency_key": key})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def tick(client, *, n=1):
    for _ in range(n):
        rv = client.post("/audit/subscriptions/process", json={})
        assert rv.status_code == 200, rv.get_json()
    return rv.get_json() if n else None


def version_secret(client, sid, no):
    m = mgr(client)
    with m._lock:
        row = m._conn.execute(
            "SELECT secret FROM audit_subscription_versions "
            "WHERE subscription_id=? AND version_no=?",
            (sid, no)).fetchone()
        m._conn.rollback()
        return row["secret"]


def sig(secret, payload):
    return hmac.new(secret.encode(), canonical_json(payload).encode(),
                    hashlib.sha256).hexdigest()


def deliveries(client, sid, **params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"/audit/subscriptions/{sid}/deliveries?limit=1000" + (
        "&" + qs if qs else "")
    rv = client.get(url)
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()["deliveries"]


def history(client, sid):
    out, after = [], None
    while True:
        url = f"/audit/subscriptions/{sid}/history?limit=100"
        if after is not None:
            url += f"&after_id={after}"
        page = client.get(url).get_json()
        out.extend(page["events"])
        if page["reached_end"]:
            return out
        after = page["next"]


def event_rows(client):
    """直接读 lease_events（只读，用于证明订阅侧不改写原始审计历史）。"""
    m = mgr(client)
    rows = m._conn.execute(
        "SELECT seq, event, outcome, resource FROM lease_events "
        "ORDER BY seq ASC").fetchall()
    m._conn.rollback()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# 事件脚手架：r1 上 acquire(seq=1) + 6 次 write(seq=2..7)
# ---------------------------------------------------------------------------


@pytest.fixture()
def seven_events(client):
    lease = acquire(client)
    # 资源审计历史按全局 seq 升序：acquire + 6 次 write
    write_ok(client, generation=lease["generation"], value="w1")
    for i in range(2, 7):
        write_ok(client, generation=lease["generation"], value=f"w{i}")
    hist = client.get("/resources/r1/audit/events?limit=100").get_json()["events"]
    return {
        "acquire": next(e["seq"] for e in hist if e["event"] == "acquire"),
        "writes": [e["seq"] for e in hist if e["event"] == "write"],
    }


# ===========================================================================
# 1. 正常预创建与激活
# ===========================================================================


def test_prepare_and_activate_atomic(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    eff = seven_events["writes"][2]  # 第 3 条 write 起按新版本

    v = prepare(client, sid, key="prep-1", filters={"event_types": ["write"]},
                effective_seq=eff)
    assert v["version_no"] == 2
    assert v["status"] == V_PREPARED
    assert v["effective_seq"] == eff
    assert v["callback_url"] == "http://new.test/hook"
    assert v["replayed"] is False
    assert "secret" not in v

    # 订阅视图出现待激活版本，当前仍是 v1
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["current_version"] == 1
    assert st["pending_version"] == 2
    statuses = {x["version_no"]: x["status"] for x in st["versions"]}
    assert statuses == {1: V_ACTIVE, 2: V_PREPARED}

    # 差异查询
    d = client.get(f"/audit/subscriptions/{sid}/versions/2/diff").get_json()
    assert d["base_version"] == 1 and d["target_version"] == 2
    paths = {x["path"] for x in d["differences"]}
    assert paths == {"callback_url", "filters", "effective_seq"}
    assert d["identical"] is False

    # 激活：原子切换
    a = activate(client, sid, 2, key="act-1")
    assert a["status"] == V_ACTIVE
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["current_version"] == 2 and st["pending_version"] is None
    assert st["callback_url"] == "http://new.test/hook"
    statuses = {x["version_no"]: x["status"] for x in st["versions"]}
    assert statuses == {1: V_SUPERSEDED, 2: V_ACTIVE}


def test_prepare_idempotent_replay(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    eff = seven_events["writes"][1]
    v1 = prepare(client, sid, key="prep-same", effective_seq=eff,
                 filters={"event_types": ["write"]})
    # 同键重放：200 + replayed（helper 默认允许 200/201，单独断言状态码）
    rv = client.post(f"/audit/subscriptions/{sid}/versions", json={
        "callback_url": "http://new.test/hook",
        "filters": {"event_types": ["write"]},
        "effective_seq": eff, "idempotency_key": "prep-same"})
    assert rv.status_code == 200
    v2 = rv.get_json()
    assert v2["version_no"] == v1["version_no"]
    assert v2["replayed"] is True and v1["replayed"] is False
    # 重放不产生新版本行
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert len(st["versions"]) == 2


@pytest.mark.parametrize("change", ["callback", "filters", "effective",
                                   "subscription"])
def test_prepare_conflict_409(seven_events, client, cb, change):
    sub_a = create_sub(client, key="sub-a", resource="r1")
    sub_b = create_sub(client, key="sub-b", resource="r1",
                       callback_url="http://other.test/hook")
    eff = seven_events["writes"][1]
    base = dict(callback_url="http://new.test/hook",
                filters={"event_types": ["write"]}, effective_seq=eff)
    prepare(client, sub_a["subscription_id"], key="shared-prep", **base)

    if change == "callback":
        kw = {**base, "callback_url": "http://changed.test/hook"}
        target = sub_a["subscription_id"]
    elif change == "filters":
        kw = {**base, "filters": {"event_types": ["acquire"]}}
        target = sub_a["subscription_id"]
    elif change == "effective":
        kw = {**base, "effective_seq": eff + 1}
        target = sub_a["subscription_id"]
    else:
        kw = base
        target = sub_b["subscription_id"]  # 换目标订阅
    rv = client.post(f"/audit/subscriptions/{target}/versions",
                     json={"idempotency_key": "shared-prep", **kw})
    assert rv.status_code == 409, rv.get_json()
    body = rv.get_json()
    assert body["error"] == "subscription_version_conflict"
    assert "first_difference" in body
    # 冲突不改变状态
    st = client.get(f"/audit/subscriptions/{sub_a['subscription_id']}").get_json()
    assert st["pending_version"] == 2


def test_prepare_requires_active(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    eff = seven_events["writes"][0]
    client.post(f"/audit/subscriptions/{sid}/pause", json={})
    rv = client.post(f"/audit/subscriptions/{sid}/versions", json={
        "callback_url": "http://new.test/hook",
        "effective_seq": eff, "idempotency_key": "p-prep"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "subscription_version_bad_state"
    # 拒绝进入审计历史
    evs = history(client, sid)
    assert any(e["event"] == "version_rejected" and e["outcome"] == "rejected"
               for e in evs)


def test_prepare_rejects_second_pending(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    eff = seven_events["writes"][1]
    prepare(client, sid, key="prep-a", effective_seq=eff,
            filters={"event_types": ["write"]})
    rv = client.post(f"/audit/subscriptions/{sid}/versions", json={
        "callback_url": "http://other.test/hook", "effective_seq": eff,
        "idempotency_key": "prep-b"})
    assert rv.status_code == 409
    assert rv.get_json()["pending_version"] == 2


# ===========================================================================
# 2. 生效序号越界：416 且原订阅不变；早于扫描位置：409
# ===========================================================================


def test_effective_seq_beyond_stable_history_416(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    rows = event_rows(client)
    max_seq = rows[-1]["seq"]
    before = client.get(f"/audit/subscriptions/{sid}").get_json()

    rv = client.post(f"/audit/subscriptions/{sid}/versions", json={
        "callback_url": "http://new.test/hook",
        "effective_seq": max_seq + 100, "idempotency_key": "oor"})
    assert rv.status_code == 416, rv.get_json()
    body = rv.get_json()
    assert body["error"] == "subscription_version_seq_out_of_range"
    assert body["available_max_seq"] == max_seq

    # 原订阅完全不变
    after = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert after["current_version"] == 1
    assert after["pending_version"] is None
    assert after["callback_url"] == before["callback_url"]
    assert len(after["versions"]) == 1
    # 拒绝原因进入订阅审计历史
    evs = history(client, sid)
    rej = [e for e in evs if e["event"] == "version_rejected"]
    assert rej and rej[-1]["outcome"] == "rejected"
    assert "越过当前稳定历史上界" in rej[-1]["detail"]


def test_effective_seq_before_scan_position_409(seven_events, client, cb):
    # v1 过滤 write：扫描后游标越过 acquire 与前两条 write
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    tick(client, n=2)  # 确认前两条 write
    v1 = client.get(f"/audit/subscriptions/{sid}/versions/1").get_json()
    pos = v1["position_seq"]
    rv = client.post(f"/audit/subscriptions/{sid}/versions", json={
        "callback_url": "http://new.test/hook",
        "filters": {"event_types": ["write"]},
        "effective_seq": 1, "idempotency_key": "early"})
    # effective_seq=1 必然早于已检视位置（acquire 在 seq=1 已被检视）
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "subscription_version_bad_state"
    assert rv.get_json()["min_effective_seq"] == pos


# ===========================================================================
# 3. 切换前后事件路由：旧版本收尾、生效序号后只进新版本、序号/密钥/回调
# ===========================================================================


def test_event_routing_before_and_after_switch(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    acquires = seven_events["acquire"]
    w = seven_events["writes"]
    eff = w[2]  # 前两条 write 归 v1，后三条归 v2；acquire 被 v1 过滤

    # 先预创建（此时一条都还没扫描）：边界立即钉住
    prepare(client, sid, key="prep", effective_seq=eff)
    tick(client, n=2)  # 只投递并确认 w[0]、w[1]，v1 不能越过 eff-1
    assert [c["payload"]["event_seq"] for c in cb.calls] == w[:2]

    activate(client, sid, 2, key="act")
    tick(client, n=4)  # v2：eff 起的 write（acquire 在边界前，不重放）

    calls = cb.calls
    by_version = {1: [], 2: []}
    for c in calls:
        by_version[c["payload"]["version_no"]].append(c)

    v1seqs = [c["payload"]["event_seq"] for c in by_version[1]]
    v2seqs = [c["payload"]["event_seq"] for c in by_version[2]]
    assert v1seqs == w[:2]
    # v2 从生效序号开始：边界后属于 r1 的事件全部进入（此处全是 write）
    assert v2seqs == w[2:]
    assert set(v1seqs) | set(v2seqs) == set(w)  # 不重不漏

    # 回调地址按版本分流
    assert all(c["url"] == "http://old.test/hook" for c in by_version[1])
    assert all(c["url"] == "http://new.test/hook" for c in by_version[2])

    # 每个版本内订阅序号从 1 连续
    assert [c["payload"]["subscription_seq"]
            for c in by_version[1]] == [1, 2]
    assert [c["payload"]["subscription_seq"]
            for c in by_version[2]] == list(range(1, len(w[2:]) + 1))

    # 签名分别用两个版本的密钥校验
    s1 = version_secret(client, sid, 1)
    s2 = version_secret(client, sid, 2)
    assert s1 != s2
    for c in by_version[1]:
        assert hmac.compare_digest(sig(s1, c["payload"]), c["signature"])
    for c in by_version[2]:
        assert hmac.compare_digest(sig(s2, c["payload"]), c["signature"])

    # 投递行带版本号，分页可按版本过滤
    d1 = deliveries(client, sid, version_no=1)
    d2 = deliveries(client, sid, version_no=2)
    assert [d["event_seq"] for d in d1] == w[:2]
    assert [d["event_seq"] for d in d2] == w[2:]
    assert all(d["status"] == D_CONFIRMED for d in d1 + d2)

    # 全局 event_seq 严格顺序投递（队首约束）：实际回调顺序按 seq 升序
    assert [c["payload"]["event_seq"] for c in calls] == sorted(
        c["payload"]["event_seq"] for c in calls)


def test_prepared_version_pins_scan_boundary(seven_events, client, cb):
    """预创建后、激活前：active 版本不能把 eff 之后的事件入旧版本队列。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    eff = seven_events["writes"][3]
    prepare(client, sid, key="prep-pin", effective_seq=eff)
    # 反复扫描：v1 最多只能补齐 eff-1 之前的 write
    tick(client, n=5)
    rows = deliveries(client, sid, version_no=1)
    assert rows, "边界前事件应已入队 v1"
    assert all(d["event_seq"] < eff for d in rows)
    # v2 尚未激活，没有 v2 投递行
    assert deliveries(client, sid, version_no=2) == []
    v1 = client.get(f"/audit/subscriptions/{sid}/versions/1").get_json()
    assert v1["position_seq"] == eff  # 游标停在边界，不越过

    activate(client, sid, 2, key="act-pin")
    tick(client, n=5)
    # 激活后边界事件全部归 v2，v1 不再新增
    n1 = len(deliveries(client, sid, version_no=1))
    rows2 = deliveries(client, sid, version_no=2)
    assert all(d["event_seq"] >= eff for d in rows2)
    assert len(deliveries(client, sid, version_no=1)) == n1


def test_filter_changes_apply_only_after_effective_seq(seven_events, client, cb):
    # v1 只要 write；v2 只要 acquire——但 acquire(seq=1) 在边界之前，
    # 切换后 v2 不会重放它：边界前被旧过滤跳过的事件不回头。
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    eff = seven_events["writes"][3]
    prepare(client, sid, key="prep-f",
            filters={"event_types": ["acquire"]}, effective_seq=eff)
    activate(client, sid, 2, key="act-f")
    tick(client, n=3)  # v1 补齐边界前 write
    tick(client, n=3)  # v2 扫描边界之后
    d1 = deliveries(client, sid, version_no=1)
    d2 = deliveries(client, sid, version_no=2)
    assert all(d["event_seq"] < eff for d in d1)
    # 边界之后没有 acquire（acquire 只在 seq=1），v2 零投递、不重放
    assert d2 == []
    # 再产生 acquire（续租不算，重新获取）与 write：只有 acquire 进 v2
    lease = client.post("/leases/acquire", json={
        "resource": "r2", "holder": "h1", "ttl_ms": 60000})
    assert lease.status_code == 201
    write_ok(client, resource="r2", generation=1, value="x")  # 不属于 r1
    tick(client, n=3)
    # r1 上没有新事件；用 r2 订阅验证略显绕路，这里只断言 r1 的 v2 仍为空
    assert deliveries(client, sid, version_no=2) == []


# ===========================================================================
# 4. 进行中投递按旧版本收尾（202 待确认 + 旧密钥确认）
# ===========================================================================


def test_inflight_awaiting_finishes_on_old_version(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    eff = w[2]
    prepare(client, sid, key="prep-a", effective_seq=eff)
    # 第一条 write 回调 202：停在 awaiting_confirm
    cb.set_script({w[0]: [cb.ack_pending()]})
    tick(client, n=1)
    tick(client, n=1)  # 队首 awaiting，第二条不能越过
    d0 = deliveries(client, sid)
    assert [d["event_seq"] for d in d0][:1] == [w[0]]
    assert d0[0]["status"] == D_AWAITING

    activate(client, sid, 2, key="act-a")
    tick(client, n=5)  # 旧通知仍 awaiting，挡住 v1/v2 后续，不越过

    # 用旧版本密钥对旧载荷显式确认；新版本密钥必须失败
    old_call = next(c for c in cb.calls if c["payload"]["event_seq"] == w[0])
    s1 = version_secret(client, sid, 1)
    s2 = version_secret(client, sid, 2)
    bad = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": sig(s2, old_call["payload"])})
    assert bad.status_code == 401
    good = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": sig(s1, old_call["payload"])})
    assert good.status_code == 200
    assert good.get_json()["status"] == D_CONFIRMED

    # 队首放行：w[1] 走旧地址旧密钥（v1），w[2:] 走新版本
    tick(client, n=6)
    by_ver = {1: [], 2: []}
    for c in cb.calls:
        by_ver[c["payload"]["version_no"]].append(c["payload"]["event_seq"])
    assert w[0] not in by_ver[1] or by_ver[1].count(w[0]) == 1
    assert w[1] in by_ver[1]
    assert by_ver[2] == w[2:]
    # w[0] 只投递过一次（202 不重发）
    assert sum(1 for c in cb.calls
               if c["payload"]["event_seq"] == w[0]) == 1


def test_inflight_delivery_keeps_old_url_after_switch(seven_events, client,
                                                      cb):
    """认领后回调进行中切换版本：迟到成功响应仍按认领令牌确认旧行。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    eff = w[1]

    released = threading.Event()

    def slow_old(url, payload, signature):
        if payload["event_seq"] == w[0]:
            released.wait(5.0)
        return HttpDeliveryResult(ok=True)

    mgr(client)._deliver_cb = slow_old
    prepare(client, sid, key="prep-slow", effective_seq=eff)

    # 直接在工作线程跑管理器一轮（避开测试 client 的非线程安全包装）：
    # 扫描入队后认领 w[0]，回调阻塞在 released 上
    def process_once():
        mgr(client).scan_and_enqueue()
        mgr(client).process_due(max_deliveries=1)

    t = threading.Thread(target=process_once)
    t.start()
    # 等 w[0] 被认领并进入回调
    deadline = 0
    while True:
        d = deliveries(client, sid)
        if d and d[0]["status"] == D_INFLIGHT:
            break
        deadline += 1
        assert deadline < 50
        import time as _t
        _t.sleep(0.02)
    # 回调进行中完成切换
    activate(client, sid, 2, key="act-slow")
    released.set()
    t.join(5.0)
    assert not t.is_alive()
    # 迟到成功响应被认领令牌接受：w[0] 按 v1 确认（旧地址投递）
    d = deliveries(client, sid)
    row0 = next(x for x in d if x["event_seq"] == w[0])
    assert row0["version_no"] == 1 and row0["status"] == D_CONFIRMED


# ===========================================================================
# 5. 激活/取消/重试的幂等与冲突
# ===========================================================================


def test_activate_cancel_replay_and_conflicts(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    eff = seven_events["writes"][1]
    prepare(client, sid, key="prep-x", effective_seq=eff,
            filters={"event_types": ["write"]})

    # 激活重放
    a1 = activate(client, sid, 2, key="act-x")
    a2 = activate(client, sid, 2, key="act-x")
    assert a2["replayed"] is True
    assert a2["version_no"] == a1["version_no"]

    # 激活键用于取消（已 superseded）-> 409 操作冲突
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/1/cancel",
        json={"idempotency_key": "act-x"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "subscription_version_conflict"

    # 取消 prepared 版本的完整幂等
    prepare(client, sid, key="prep-y", effective_seq=eff + 1,
            filters={"event_types": ["write"]})
    c1 = cancel_version(client, sid, 3, key="cancel-y")
    assert c1["status"] == V_CANCELLED
    c2 = cancel_version(client, sid, 3, key="cancel-y")
    assert c2["replayed"] is True and c2["status"] == V_CANCELLED

    # 同键换版本号 -> 409
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/2/cancel",
        json={"idempotency_key": "cancel-y"})
    assert rv.status_code == 409

    # 取消后不能再激活
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/3/activate",
        json={"idempotency_key": "act-z"})
    assert rv.status_code == 409


def test_activate_unknown_version_404(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/9/activate",
        json={"idempotency_key": "act-404"})
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "subscription_version_not_found"


def test_idempotency_key_cannot_cross_prepare_and_ops(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    eff = seven_events["writes"][0]
    prepare(client, sid, key="cross-key", effective_seq=eff,
            filters={"event_types": ["write"]})
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/2/activate",
        json={"idempotency_key": "cross-key"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "subscription_version_conflict"


# ===========================================================================
# 6. 并发激活：恰好一个成功
# ===========================================================================


def test_concurrent_activate_single_winner(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    eff = seven_events["writes"][1]
    prepare(client, sid, key="prep-c", effective_seq=eff,
            filters={"event_types": ["write"]})

    results = []
    # 8 个线程共用同一个幂等键并发激活：恰好一个真正切换（created=True），
    # 其余全部幂等回放同一成功结果（replayed），绝不出现重复/半切换。
    barrier = threading.Barrier(8)
    m = mgr(client)

    def worker():
        barrier.wait()
        try:
            view, created = m.activate_version(sid, 2,
                                              idempotency_key="act-c")
            results.append(("ok", view["status"], created))
        except Exception as exc:  # noqa: BLE001 - 断言里统一检查
            results.append(("err", type(exc).__name__, str(exc)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8
    assert all(r[0] == "ok" and r[1] == V_ACTIVE for r in results), results
    created_flags = [r[2] for r in results]
    assert created_flags.count(True) == 1
    assert created_flags.count(False) == 7

    # HTTP 层重放同样幂等
    replay = client.post(
        f"/audit/subscriptions/{sid}/versions/2/activate",
        json={"idempotency_key": "act-c"})
    assert replay.status_code == 200
    assert replay.get_json()["replayed"] is True

    # 只有一次 version_activated=ok
    evs = history(client, sid)
    assert len([e for e in evs
                if e["event"] == "version_activated" and e["outcome"] == "ok"
                ]) == 1
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["current_version"] == 2

    # 不同幂等键重试激活同一已激活版本：409 且拒绝入审计历史
    other = client.post(
        f"/audit/subscriptions/{sid}/versions/2/activate",
        json={"idempotency_key": "act-other"})
    assert other.status_code == 409
    assert any(e["event"] == "version_rejected"
               for e in history(client, sid))


# ===========================================================================
# 7. 死信：按版本分页 + 只重试某版本 + 严格顺序不越过
# ===========================================================================


@pytest.fixture()
def dead_setup(seven_events, client, cb):
    """v1 的 w[1] 与 v2 的 w[3] 都打成死信（410 永久拒收，一次即死信）。"""
    mgr(client).max_backoff_ms = 0
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    # 预创建先于扫描：边界钉在 w[2]
    prepare(client, sid, key="prep-d", effective_seq=w[2])
    cb.set_script({w[1]: cb.fail(1, permanent=True)})
    tick(client, n=2)  # w[0] 确认；w[1] 410 死信挡住 v1 队尾
    activate(client, sid, 2, key="act-d")

    def deliver_new(url, payload, signature):
        if payload["event_seq"] == w[3]:
            return HttpDeliveryResult(status=410, permanent_reject=True)
        return HttpDeliveryResult(ok=True)

    mgr(client)._deliver_cb = deliver_new
    return sid, w


def test_versioned_dead_letters_list_and_retry(dead_setup, client, cb):
    sid, w = dead_setup
    # 按版本分页查看死信：此刻 v1 有 w[1]，v2 还没有
    dead_v1_before = client.get(
        f"/audit/subscriptions/dead-letters"
        f"?subscription_id={sid}&version_no=1").get_json()["dead_letters"]
    assert [x["event_seq"] for x in dead_v1_before] == [w[1]]
    assert [x["dead_letter_reason"] for x in dead_v1_before] == \
        ["permanent_reject_410"]
    # 重放 v1 死信：w[1] 复位 pending，但仍是队首；先重试再让它成功
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/1/retry-dead-letters",
        json={"idempotency_key": "retry-v1"})
    assert rv.status_code == 200
    body = rv.get_json()
    assert body["requeued"] == 1 and body["version_no"] == 1
    # 幂等重放
    rv2 = client.post(
        f"/audit/subscriptions/{sid}/versions/1/retry-dead-letters",
        json={"idempotency_key": "retry-v1"})
    assert rv2.status_code == 200 and rv2.get_json()["replayed"] is True
    # 换版本号同键 -> 409
    rv3 = client.post(
        f"/audit/subscriptions/{sid}/versions/2/retry-dead-letters",
        json={"idempotency_key": "retry-v1"})
    assert rv3.status_code == 409

    tick(client, n=8)  # w[1] 成功 -> w[2](v2) -> w[3](v2)死信挡住 w[4:]
    d = deliveries(client, sid)
    assert next(x for x in d if x["event_seq"] == w[1])["status"] == D_CONFIRMED
    assert next(x for x in d if x["event_seq"] == w[3])["status"] == D_DEAD
    # w[4] 不能越过死信：没有投递行被确认到它前面……它会有 pending 行吗？
    # 队首约束：w[3] 死信，w[4] 已入队但不投递
    later = [x for x in d if x["event_seq"] >= w[3]]
    assert later[0]["event_seq"] == w[3] and later[0]["status"] == D_DEAD

    # v2 死信已产生且 v1 已清空：按版本分页正确隔离
    dead_v2 = client.get(
        f"/audit/subscriptions/dead-letters"
        f"?subscription_id={sid}&version_no=2").get_json()["dead_letters"]
    assert [x["event_seq"] for x in dead_v2] == [w[3]]
    dead_v1_empty = client.get(
        f"/audit/subscriptions/dead-letters"
        f"?subscription_id={sid}&version_no=1").get_json()["dead_letters"]
    assert dead_v1_empty == []

    # 只重试 v2 死信：先恢复正常回调（否则重投仍 410）
    mgr(client)._deliver_cb = ScriptedCallback()
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/2/retry-dead-letters",
        json={"idempotency_key": "retry-v2"})
    assert rv.get_json()["requeued"] == 1
    tick(client, n=5)
    d = deliveries(client, sid)
    assert all(x["status"] == D_CONFIRMED for x in d)
    # 顺序不重不乱：event_seq 升序、每事件一行
    seqs = [x["event_seq"] for x in d]
    assert seqs == sorted(seqs) and len(seqs) == len(set(seqs))

    dead_all = client.get(
        f"/audit/subscriptions/dead-letters?subscription_id={sid}"
    ).get_json()["dead_letters"]
    # 重试后死信清空
    assert dead_all == []

    # 审计历史记录两次重试
    evs = history(client, sid)
    assert [e["version_no"] for e in evs if e["event"] == "version_retry"] \
        == [1, 2]


# ===========================================================================
# 8. 服务重启恢复
# ===========================================================================


def test_restart_recovers_inflight_and_continues(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    # w[0] 202 待确认、w[1] 投递失败退避中时重启
    cb.set_script({w[0]: [cb.ack_pending()]})
    tick(client, n=2)
    assert deliveries(client, sid)[0]["status"] == D_AWAITING

    # 模拟服务重启：丢弃旧管理器，用同一数据库新建（构造即回收认领行）
    store = client.application.extensions["store"]
    old = mgr(client)
    old.close()
    cb2 = ScriptedCallback()
    fresh = SubscriptionManager(store, deliver=cb2)
    try:
        # awaiting 行被回收为 pending，不增加尝试次数；用新回调器重投
        fresh.scan_and_enqueue()
        fresh.process_due()
        # 回收后重投 w[0]：成功确认；严格顺序继续 w[1..]
        for _ in range(8):
            fresh.scan_and_enqueue()
            fresh.process_due()
        d = fresh.list_deliveries(sid, limit=1000)["deliveries"]
        assert [x["status"] for x in d] == [D_CONFIRMED] * len(w)
        # 每个事件恰好一行、按序；重启没产生重复投递记录
        seqs = [x["event_seq"] for x in d]
        assert seqs == w
        assert all(x["attempts"] >= 1 for x in d)
        # w[0] 第一次是 202（旧 cb），重启回收后成功（cb2 记录一次成功）
        assert [c["payload"]["event_seq"] for c in cb2.calls] == sorted(
            c["payload"]["event_seq"] for c in cb2.calls)
    finally:
        fresh.close()


def test_restart_after_switch_continues_two_versions(seven_events, client, cb):
    """切换完成后、边界前补齐与新版本投递未完成时重启：从已保存状态继续。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    eff = w[2]
    prepare(client, sid, key="prep-r", effective_seq=eff)
    activate(client, sid, 2, key="act-r")
    # 不做任何投递，直接"重启"
    store = client.application.extensions["store"]
    old = mgr(client)
    old.close()
    cb2 = ScriptedCallback()
    fresh = SubscriptionManager(store, deliver=cb2)
    try:
        for _ in range(10):
            fresh.scan_and_enqueue()
            fresh.process_due()
        d = fresh.list_deliveries(sid, limit=1000)["deliveries"]
        assert {x["event_seq"] for x in d if x["version_no"] == 1} == set(w[:2])
        assert {x["event_seq"] for x in d if x["version_no"] == 2} == set(w[2:])
        assert all(x["status"] == D_CONFIRMED for x in d)
        # 旧版本收尾、新版本通知互不越过：回调顺序全局升序
        s = [c["payload"]["event_seq"] for c in cb2.calls]
        assert s == sorted(s)
        v1 = fresh.get_version(sid, 1)
        v2 = fresh.get_version(sid, 2)
        assert v1["status"] == V_SUPERSEDED and v2["status"] == V_ACTIVE
    finally:
        fresh.close()


def test_restart_during_prepared_then_activate(seven_events, client, cb):
    """预创建后重启：prepared 版本与边界钉住状态持久保留，仍可激活。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    eff = w[3]
    prepare(client, sid, key="prep-pr", effective_seq=eff)

    store = client.application.extensions["store"]
    old = mgr(client)
    old.close()
    fresh = SubscriptionManager(store, deliver=ScriptedCallback())
    try:
        for _ in range(5):
            fresh.scan_and_enqueue()
        v1 = fresh.get_version(sid, 1)
        v2 = fresh.get_version(sid, 2)
        assert v1["position_seq"] == eff  # 仍钉在边界
        assert v2["status"] == V_PREPARED
        view, created = fresh.activate_version(sid, 2,
                                               idempotency_key="act-pr")
        assert created and view["status"] == V_ACTIVE
    finally:
        fresh.close()


# ===========================================================================
# 9. 版本取消 / 订阅取消联动
# ===========================================================================


def test_cancel_prepared_version_clears_pending(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    prepare(client, sid, key="prep-cancel", effective_seq=w[3])
    cancel_version(client, sid, 2, key="cancel-prep")
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["pending_version"] is None and st["current_version"] == 1
    v2 = client.get(f"/audit/subscriptions/{sid}/versions/2").get_json()
    assert v2["status"] == V_CANCELLED and v2["cancelled_at_ms"]
    # 取消后边界放开：后续事件重新全部进入 v1
    tick(client, n=6)
    d = deliveries(client, sid)
    assert all(x["version_no"] == 1 for x in d)
    evs = history(client, sid)
    assert any(e["event"] == "version_cancelled" for e in evs)


def test_cancel_subscription_cancels_prepared_and_discards(seven_events,
                                                          client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    prepare(client, sid, key="prep-sc", effective_seq=w[3])
    rv = client.post(f"/audit/subscriptions/{sid}/cancel", json={})
    assert rv.status_code == 200
    st = rv.get_json()
    assert st["status"] == "cancelled"
    assert {x["version_no"]: x["status"] for x in st["versions"]} == {
        1: V_CANCELLED, 2: V_CANCELLED}
    tick(client, n=3)
    # 不再产生任何投递
    assert deliveries(client, sid) == []


# ===========================================================================
# 10. 审计历史与源数据不可变
# ===========================================================================


def test_audit_history_records_lifecycle_and_rejections(seven_events, client,
                                                        cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    # 一次越界拒绝 + 一次正常创建/取消/再创建/激活/重试
    client.post(f"/audit/subscriptions/{sid}/versions", json={
        "callback_url": "http://n.test", "effective_seq": 10 ** 9,
        "idempotency_key": "rej"})
    prepare(client, sid, key="prep-h", effective_seq=w[2])
    cancel_version(client, sid, 2, key="cancel-h")
    prepare(client, sid, key="prep-h2", effective_seq=w[3])
    activate(client, sid, 3, key="act-h")
    tick(client, n=6)
    client.post(
        f"/audit/subscriptions/{sid}/versions/3/retry-dead-letters",
        json={"idempotency_key": "retry-h"})

    evs = history(client, sid)
    kinds = [(e["event"], e["outcome"], e["version_no"]) for e in evs]
    assert ("version_rejected", "rejected", None) in kinds
    assert kinds.count(("version_prepared", "ok", 2)) == 1
    assert ("version_cancelled", "ok", 2) in kinds
    assert ("version_prepared", "ok", 3) in kinds
    assert ("version_activated", "ok", 3) in kinds
    assert ("version_retry", "ok", 3) in kinds
    # 严格只追加：id 升序连续分页
    assert [e["id"] for e in evs] == list(range(1, len(evs) + 1))
    # 事件过滤
    only_rej = client.get(
        f"/audit/subscriptions/{sid}/history?event=version_rejected"
    ).get_json()["events"]
    assert all(e["event"] == "version_rejected" for e in only_rej)


def test_version_flow_does_not_modify_source_data(seven_events, client, cb):
    m = mgr(client)
    before = event_rows(client)
    with m._store._conn:
        lease_count = m._store._conn.execute(
            "SELECT COUNT(*) AS c FROM leases").fetchone()["c"]
        deleg_count = m._store._conn.execute(
            "SELECT COUNT(*) AS c FROM delegations").fetchone()["c"]
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    prepare(client, sid, key="prep-ro", effective_seq=w[2])
    activate(client, sid, 2, key="act-ro")
    tick(client, n=6)
    client.post(
        f"/audit/subscriptions/{sid}/versions/2/retry-dead-letters",
        json={"idempotency_key": "retry-ro"})
    # 原始审计事件逐行不变
    assert event_rows(client) == before
    with m._store._conn:
        assert m._store._conn.execute(
            "SELECT COUNT(*) AS c FROM leases").fetchone()["c"] == lease_count
        assert m._store._conn.execute(
            "SELECT COUNT(*) AS c FROM delegations").fetchone()["c"] \
            == deleg_count
    # 全局诊断一致
    diag = client.get("/audit/diagnose").get_json()
    assert diag["summary"]["consistent"] is True


# ===========================================================================
# 11. 多版本连续切换：v1 -> v2 -> v3
# ===========================================================================


def test_three_version_chain(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    # 两次预创建都在扫描前完成（边界一经预创建即钉住）
    prepare(client, sid, key="p2", callback_url="http://v2.test/hook",
            effective_seq=w[2])
    activate(client, sid, 2, key="a2")
    prepare(client, sid, key="p3", callback_url="http://v3.test/hook",
            effective_seq=w[4])
    activate(client, sid, 3, key="a3")
    tick(client, n=10)
    d = deliveries(client, sid)
    bounds = {1: w[:2], 2: w[2:4], 3: w[4:]}
    for no, seqs in bounds.items():
        got = sorted(x["event_seq"] for x in d if x["version_no"] == no)
        assert got == seqs, (no, got, seqs)
        assert all(x["status"] == D_CONFIRMED
                   for x in d if x["version_no"] == no)
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert {x["version_no"]: x["status"] for x in st["versions"]} == {
        1: V_SUPERSEDED, 2: V_SUPERSEDED, 3: V_ACTIVE}
    # v2 的回调地址只服务它自己的两个事件
    v2calls = [c for c in cb.calls if c["url"] == "http://v2.test/hook"]
    assert sorted(c["payload"]["event_seq"] for c in v2calls) == w[2:4]
    # 各版本订阅序号都从 1 连续
    for no in (1, 2, 3):
        s = sorted((c["payload"]["event_seq"], c["payload"]["subscription_seq"])
                   for c in cb.calls if c["payload"]["version_no"] == no)
        assert [seq for _, seq in s] == list(range(1, len(s) + 1))
