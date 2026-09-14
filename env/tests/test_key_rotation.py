"""订阅通知签名密钥轮换与验证（signing-key rotation & verification）。

覆盖场景：
- 正常预登记与生效（密钥状态、指纹、轮换进度/受影响投递、视图不含明文）
- 生效前通知用旧密钥、生效序号后新通知必须用新密钥、在途旧通知按旧密钥
  在宽限期内完成确认（旧密钥宽限确认；宽限期结束旧密钥确认被拒）
- 幂等冲突：预登记/生效/撤销/重签同键重放，换指纹/生效序号/宽限期/目标
  订阅/操作类型均 409 明确冲突（给出首个差异）
- 生效序号越过稳定历史 -> 416 且当前密钥不变；早于已扫描位置 -> 409
- 并发轮换：同键并发生效恰好一个成功，其余回放同一结果
- 验证失败重签：错误签名确认 -> failed 验证记录（401 不改状态）；只对失败
  的指定密钥投递重签，重签后可用新签名确认，状态/顺序不被破坏
- 按密钥 + 时间范围分页查询验证结果（游标、result 过滤、分页边界）
- 重启/轮换中断恢复：新 KeyRotationManager 从已保存状态继续，宽限到期
  退役旧密钥；不重复确认、不跳过通知
- 审计：轮换事件与所有拒绝原因只追加进订阅自己的审计历史；不改写租约、
  委托、lease_events 原始审计事件、版本行或已有投递状态
"""

import hashlib
import hmac
import threading

import pytest

from app.app import create_app
from app.key_rotation import (
    K_ACTIVE,
    K_GRACE,
    K_PREPARED,
    K_RETIRED,
    K_REVOKED,
    KeyRotationManager,
    secret_fingerprint,
)
from app.subscription import (
    D_AWAITING,
    D_CONFIRMED,
    HttpDeliveryResult,
    SubscriptionManager,
    canonical_json,
)


# ---------------------------------------------------------------------------
# fixture 与辅助
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        str(tmp_path / "keyrot.db"), start_ticker=False,
        enable_debug_api=True, start_archive_worker=False)
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    with app.test_client() as c:
        yield c


class ScriptedCallback:
    def __init__(self, *, default_ok=True):
        self.calls = []
        self.lock = threading.Lock()
        self.script = {}
        self.default = (HttpDeliveryResult(ok=True)
                        if default_ok else None)

    def ack_pending(self):
        return HttpDeliveryResult(status=202, ack_pending=True)

    def set_script(self, mapping):
        self.script = {int(k): list(v) for k, v in mapping.items()}

    def __call__(self, url, payload, signature):
        with self.lock:
            self.calls.append({
                "url": url, "payload": payload, "signature": signature})
            outcomes = self.script.get(payload["event_seq"])
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


def kmgr(client):
    return client.application.extensions["key_rotation"]


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


def prepare_key(client, sid, *, key, effective_seq, secret=None,
                fingerprint=None, grace_ms=0, expect=201):
    body = {"effective_seq": effective_seq, "grace_ms": grace_ms,
            "idempotency_key": key}
    if secret is not None:
        body["secret"] = secret
    if fingerprint is not None:
        body["fingerprint"] = fingerprint
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys", json=body)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def activate_key(client, sid, key_id, *, key, expect=200):
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys/{key_id}/activate",
        json={"idempotency_key": key})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def revoke_key(client, sid, key_id, *, key, expect=200):
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys/{key_id}/revoke",
        json={"idempotency_key": key})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def tick(client, *, n=1):
    rv = None
    for _ in range(n):
        rv = client.post("/audit/subscriptions/process", json={})
        assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


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


def verifications(client, sid, **params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = (f"/audit/subscriptions/{sid}/signature-verifications"
           f"?limit=1000" + ("&" + qs if qs else ""))
    rv = client.get(url)
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()["verifications"]


def sig(secret, payload):
    return hmac.new(secret.encode(), canonical_json(payload).encode(),
                    hashlib.sha256).hexdigest()


def version_secret(client, sid, no=1):
    m = mgr(client)
    row = m._conn.execute(
        "SELECT secret FROM audit_subscription_versions "
        "WHERE subscription_id=? AND version_no=?",
        (sid, no)).fetchone()
    m._conn.rollback()
    return row["secret"]


def key_secret(client, key_id):
    """直接读轮换密钥明文（仅测试用）。"""
    k = kmgr(client)
    row = k._conn.execute(
        "SELECT secret FROM audit_subscription_signing_keys "
        "WHERE key_id=?", (key_id,)).fetchone()
    k._conn.rollback()
    return row["secret"]


def event_rows(client):
    m = mgr(client)
    rows = m._conn.execute(
        "SELECT seq, event, outcome, resource FROM lease_events "
        "ORDER BY seq ASC").fetchall()
    m._conn.rollback()
    return [dict(r) for r in rows]


@pytest.fixture()
def seven_events(client):
    lease = acquire(client)
    write_ok(client, generation=lease["generation"], value="w1")
    for i in range(2, 7):
        write_ok(client, generation=lease["generation"], value=f"w{i}")
    hist = client.get(
        "/resources/r1/audit/events?limit=100").get_json()["events"]
    return {
        "acquire": next(e["seq"] for e in hist if e["event"] == "acquire"),
        "writes": [e["seq"] for e in hist if e["event"] == "write"],
    }


# ===========================================================================
# 1. 正常预登记与生效
# ===========================================================================


def test_prepare_and_activate_key(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    new_secret = "a" * 64
    fp = secret_fingerprint(new_secret)

    k = prepare_key(client, sid, key="prep-k-1", secret=new_secret,
                    effective_seq=w[2], grace_ms=5000)
    assert k["status"] == K_PREPARED
    assert k["key_no"] == 1
    assert k["fingerprint"] == fp
    assert k["grace_ms"] == 5000
    assert k["effective_seq"] == w[2]
    assert "secret" not in k  # 明文绝不通过 API 返回
    assert k["replayed"] is False

    # 列表查询
    lst = client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()
    assert [x["key_no"] for x in lst["keys"]] == [1]

    # 生效
    a = activate_key(client, sid, k["key_id"], key="act-k-1")
    assert a["status"] == K_ACTIVE
    assert a["activated_at_ms"]

    # 审计历史记录
    evs = history(client, sid)
    assert any(e["event"] == "key_prepared" and e["outcome"] == "ok"
               for e in evs)
    assert any(e["event"] == "key_activated" and e["outcome"] == "ok"
               for e in evs)
    # 轮换事件的 version_no 列为 None（与版本切换事件区分）
    assert all(e["version_no"] is None for e in evs
               if e["event"].startswith("key_"))


def test_prepare_idempotent_replay_and_conflicts(seven_events, client, cb):
    sub_a = create_sub(client, key="sub-a")
    sub_b = create_sub(client, key="sub-b",
                       callback_url="http://other.test/hook")
    sid = sub_a["subscription_id"]
    w = seven_events["writes"]
    secret = "b" * 64
    fp = secret_fingerprint(secret)

    k1 = prepare_key(client, sid, key="same-key", secret=secret,
                     effective_seq=w[1], grace_ms=1000)
    # 同键同规格重放
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys",
        json={"secret": secret, "effective_seq": w[1], "grace_ms": 1000,
              "idempotency_key": "same-key"})
    assert rv.status_code == 200
    body = rv.get_json()
    assert body["replayed"] is True
    assert body["key_id"] == k1["key_id"]

    def conflict(payload, *, path_substring):
        r = client.post(f"/audit/subscriptions/{sid}/signing-keys",
                        json=payload)
        assert r.status_code == 409, r.get_json()
        b = r.get_json()
        assert b["error"] == "key_rotation_id_conflict"
        assert path_substring in b["first_difference"]["path"]
        return b

    base = {"effective_seq": w[1], "grace_ms": 1000,
            "idempotency_key": "same-key"}
    # 换指纹（不同 secret -> 不同指纹）
    conflict({**base, "secret": "c" * 64}, path_substring="fingerprint")
    # 换生效序号
    conflict({**base, "secret": secret, "effective_seq": w[2]},
             path_substring="effective_seq")
    # 换宽限期
    conflict({**base, "secret": secret, "grace_ms": 2000},
             path_substring="grace_ms")
    # 换目标订阅
    r = client.post(
        f"/audit/subscriptions/{sub_b['subscription_id']}/signing-keys",
        json={"secret": secret, "effective_seq": w[1], "grace_ms": 1000,
              "idempotency_key": "same-key"})
    assert r.status_code == 409
    assert "subscription_id" in r.get_json()["first_difference"]["path"]
    # 冲突不改变状态：仍只有一把密钥
    st = client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()
    assert len(st["keys"]) == 1 and st["keys"][0]["fingerprint"] == fp


def test_prepare_server_generated_secret_idempotent_replay(seven_events,
                                                           client, cb):
    """不传 secret/fingerprint、由服务端生成密钥：完全相同的幂等请求第二次
    必须回放第一次的密钥记录（同一 key_id/指纹），不能因重新生成随机密钥而
    误报指纹冲突；只有调用方改变指纹/生效序号/宽限期/订阅才 409。"""
    sub_a = create_sub(client, key="sub-sg-a")
    sub_b = create_sub(client, key="sub-sg-b",
                       callback_url="http://other.test/hook")
    sid = sub_a["subscription_id"]
    w = seven_events["writes"]

    body = {"effective_seq": w[1], "grace_ms": 1000,
            "idempotency_key": "sg-same"}
    r1 = client.post(f"/audit/subscriptions/{sid}/signing-keys", json=body)
    assert r1.status_code == 201, r1.get_json()
    k1 = r1.get_json()
    assert k1.get("secret") is None  # 密钥明文永不回传
    # 完全相同的请求重放 -> 200，回放同一密钥记录
    r2 = client.post(f"/audit/subscriptions/{sid}/signing-keys", json=body)
    assert r2.status_code == 200, r2.get_json()
    k2 = r2.get_json()
    assert k2["replayed"] is True
    assert k2["key_id"] == k1["key_id"]
    assert k2["fingerprint"] == k1["fingerprint"]
    # 再放一次：仍回放同一条
    r3 = client.post(f"/audit/subscriptions/{sid}/signing-keys", json=body)
    assert r3.status_code == 200
    assert r3.get_json()["key_id"] == k1["key_id"]
    # 库里只有一把密钥（没有因冲突外的重放插入新行）
    assert len(client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()["keys"]) == 1

    def conflict(payload, *, path_substring):
        rv = client.post(f"/audit/subscriptions/{sid}/signing-keys",
                         json=payload)
        assert rv.status_code == 409, rv.get_json()
        assert rv.get_json()["error"] == "key_rotation_id_conflict"
        assert path_substring in \
            rv.get_json()["first_difference"]["path"]

    # 显式带不同密钥 -> 指纹冲突
    conflict({**body, "secret": "c" * 64}, path_substring="fingerprint")
    # 换生效序号
    conflict({**body, "effective_seq": w[2]},
             path_substring="effective_seq")
    # 换宽限期
    conflict({**body, "grace_ms": 2000}, path_substring="grace_ms")
    # 换目标订阅
    rv = client.post(
        f"/audit/subscriptions/{sub_b['subscription_id']}/signing-keys",
        json=body)
    assert rv.status_code == 409
    assert "subscription_id" in rv.get_json()["first_difference"]["path"]
    # 冲突不改变状态
    st = client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()
    assert len(st["keys"]) == 1 and \
        st["keys"][0]["fingerprint"] == k1["fingerprint"]


def test_fingerprint_mismatch_secret_rejected(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys",
        json={"secret": "d" * 64,
              "fingerprint": secret_fingerprint("e" * 64),
              "effective_seq": w[0], "idempotency_key": "bad-fp"})
    assert rv.status_code == 400
    assert "fingerprint" in rv.get_json()["message"]


def test_activate_revoke_resign_idempotency_conflicts(seven_events, client,
                                                      cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    k = prepare_key(client, sid, key="prep-x", secret="f" * 64,
                    effective_seq=w[1])
    kid = k["key_id"]

    # 激活同键重放
    a1 = activate_key(client, sid, kid, key="act-x")
    a2 = activate_key(client, sid, kid, key="act-x")
    assert a2["replayed"] is True and a2["key_id"] == a1["key_id"]

    # 已激活不能再激活（换键明确 409，且入审计历史）
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys/{kid}/activate",
        json={"idempotency_key": "act-other"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "key_rotation_bad_state"

    # 激活键不能挪用于撤销（操作类型冲突）
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys/{kid}/revoke",
        json={"idempotency_key": "act-x"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] in (
        "key_rotation_id_conflict", "key_rotation_conflict")

    # 预登记键不能用于操作接口
    k2 = prepare_key(client, sid, key="prep-y", secret="11" * 32,
                     effective_seq=w[3])
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys/{k2['key_id']}/revoke",
        json={"idempotency_key": "prep-y"})
    assert rv.status_code == 409

    # 撤销幂等
    r1 = revoke_key(client, sid, k2["key_id"], key="rev-y")
    assert r1["status"] == K_REVOKED
    r2 = revoke_key(client, sid, k2["key_id"], key="rev-y")
    assert r2["replayed"] is True and r2["status"] == K_REVOKED
    # 撤销后不能激活
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys/{k2['key_id']}/activate",
        json={"idempotency_key": "act-y"})
    assert rv.status_code == 409


# ===========================================================================
# 2. 生效序号越界：416 且当前密钥不变；早于已扫描位置：409
# ===========================================================================


def test_effective_seq_beyond_stable_history_416(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    max_seq = event_rows(client)[-1]["seq"]
    before = client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()

    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys",
        json={"secret": "0a" * 32, "effective_seq": max_seq + 100,
              "idempotency_key": "oor"})
    assert rv.status_code == 416, rv.get_json()
    body = rv.get_json()
    assert body["error"] == "key_rotation_seq_out_of_range"
    assert body["available_max_seq"] == max_seq

    # 当前密钥完全不变：没有任何密钥行
    after = client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()
    assert after["keys"] == before["keys"] == []
    # 拒绝原因入审计历史
    rej = [e for e in history(client, sid) if e["event"] == "key_rejected"]
    assert rej and rej[-1]["outcome"] == "rejected"
    assert "越过当前稳定历史上界" in rej[-1]["detail"]


def test_effective_seq_before_scan_position_409(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    tick(client, n=2)  # 扫过前两条 write
    v1 = client.get(f"/audit/subscriptions/{sid}/versions/1").get_json() \
        if False else mgr(client).get_version  # noqa
    pos = mgr(client)._conn.execute(
        "SELECT position_seq FROM audit_subscription_versions "
        "WHERE subscription_id=? AND version_no=1",
        (sid,)).fetchone()["position_seq"]
    mgr(client)._conn.rollback()
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys",
        json={"secret": "0b" * 32, "effective_seq": 1,
              "idempotency_key": "early"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "key_rotation_bad_state"
    assert rv.get_json()["min_effective_seq"] == pos
    # 当前密钥不变
    assert client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()["keys"] == []


def test_prepare_requires_active_subscription(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    client.post(f"/audit/subscriptions/{sid}/pause", json={})
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys",
        json={"secret": "0c" * 32,
              "effective_seq": seven_events["writes"][0],
              "idempotency_key": "paused"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "key_rotation_bad_state"


def test_only_one_pending_key(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    prepare_key(client, sid, key="pk-a", secret="0d" * 32,
                effective_seq=w[1])
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys",
        json={"secret": "0e" * 32, "effective_seq": w[2],
              "idempotency_key": "pk-b"})
    assert rv.status_code == 409
    assert rv.get_json()["pending_key_id"]


# ===========================================================================
# 3. 生效前旧密钥 / 生效后新密钥 / 宽限期旧确认
# ===========================================================================


def test_old_and_new_key_routing(seven_events, client, cb):
    """生效前通知旧密钥签名；生效序号（含）后新通知必须用新密钥。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    old_secret = version_secret(client, sid, 1)
    new_secret = "2" * 64
    eff = w[2]

    k = prepare_key(client, sid, key="kprep", secret=new_secret,
                    effective_seq=eff)
    # 预登记未生效：全部通知仍用旧密钥
    tick(client, n=3)
    pre_calls = list(cb.calls)
    assert {c["payload"]["event_seq"] for c in pre_calls} == set(w[:2])
    for c in pre_calls:
        assert hmac.compare_digest(sig(old_secret, c["payload"]),
                                   c["signature"])
        d = next(x for x in deliveries(client, sid)
                 if x["event_seq"] == c["payload"]["event_seq"])
        assert d["signing_key_id"] is None  # 旧行不钉轮换密钥

    activate_key(client, sid, k["key_id"], key="kact")
    tick(client, n=5)
    by_seq = {c["payload"]["event_seq"]: c for c in cb.calls}
    # 前两条用旧密钥，后三条用新密钥
    for seq in w[:2]:
        assert hmac.compare_digest(sig(old_secret, by_seq[seq]["payload"]),
                                   by_seq[seq]["signature"])
    for seq in w[2:]:
        assert hmac.compare_digest(sig(new_secret, by_seq[seq]["payload"]),
                                   by_seq[seq]["signature"])
    # 新行钉住新密钥 id
    for d in deliveries(client, sid):
        if d["event_seq"] >= eff:
            assert d["signing_key_id"] == k["key_id"]
        else:
            assert d["signing_key_id"] is None
    assert all(d["status"] == D_CONFIRMED for d in deliveries(client, sid))


def test_grace_period_allows_old_key_ack_then_rejects(seven_events, client,
                                                      cb):
    """在途旧通知 202 停在 awaiting：首次轮换生效后宽限期内仍可按版本密钥
    确认（old_key_grace）；宽限结束并完成恢复后旧版本密钥签名被拒（401，
    不标记为已确认）。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    new_secret = "3" * 64
    eff = w[2]

    k = prepare_key(client, sid, key="gprep", secret=new_secret,
                    effective_seq=eff, grace_ms=10_000)
    cb.set_script({w[0]: [cb.ack_pending()]})
    tick(client, n=1)
    tick(client, n=1)  # awaiting 挡住队首
    d0 = deliveries(client, sid)[0]
    assert d0["status"] == D_AWAITING and d0["event_seq"] == w[0]
    old_payload = next(c["payload"] for c in cb.calls
                       if c["payload"]["event_seq"] == w[0])

    activate_key(client, sid, k["key_id"], key="gact")
    kv = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k['key_id']}"
    ).get_json()
    assert kv["status"] == K_ACTIVE
    # 版本密钥处于隐式宽限窗口（首次轮换）
    assert kv["version_key_grace_active"] is True

    old_secret = version_secret(client, sid, 1)
    # 用新密钥签旧通知 -> 401
    bad = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": sig(new_secret, old_payload)})
    assert bad.status_code == 401
    # 状态未变
    assert deliveries(client, sid)[0]["status"] == D_AWAITING
    # failed 验证记录落库
    failed = verifications(client, sid, result="failed")
    assert failed and failed[-1]["event_seq"] == w[0]

    # 宽限期内旧版本密钥确认 -> 200，验证结果 old_key_grace（不再是 ok）
    good = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": sig(old_secret, old_payload)})
    assert good.status_code == 200
    assert good.get_json()["status"] == D_CONFIRMED
    grace_v = verifications(client, sid, result="old_key_grace")
    assert [v["event_seq"] for v in grace_v] == [w[0]]

    # 放行后队首继续：w[1] 旧密钥，w[2:] 新密钥
    tick(client, n=6)
    by_seq = {c["payload"]["event_seq"]: c for c in cb.calls}
    assert hmac.compare_digest(sig(old_secret, by_seq[w[1]]["payload"]),
                               by_seq[w[1]]["signature"])
    for seq in w[2:]:
        assert hmac.compare_digest(sig(new_secret, by_seq[seq]["payload"]),
                                   by_seq[seq]["signature"])


def test_first_rotation_old_ack_rejected_with_no_grace(seven_events, client,
                                                       cb):
    """首次轮换、宽限为 0：生效后版本密钥立即退役，旧签名确认 401 且不改
    状态（宽限为 0 时连窗口都没有）。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    new_secret = "31" * 32

    k = prepare_key(client, sid, key="zprep", secret=new_secret,
                    effective_seq=w[2], grace_ms=0)
    cb.set_script({w[0]: [cb.ack_pending()]})
    tick(client, n=2)
    payload0 = next(c["payload"] for c in cb.calls
                    if c["payload"]["event_seq"] == w[0])
    activate_key(client, sid, k["key_id"], key="zact")

    old_secret = version_secret(client, sid, 1)
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": sig(old_secret, payload0)})
    assert rv.status_code == 401
    assert deliveries(client, sid)[0]["status"] == D_AWAITING


def test_first_rotation_grace_retire_rejects_old_ack(seven_events, client,
                                                     cb):
    """首次轮换给了宽限：旧通知在宽限期内可确认；拨表越过宽限并完成恢复
    处理后，版本密钥退役，旧签名确认一律 401 且投递不被标记为已确认。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    new_secret = "32" * 32

    k = prepare_key(client, sid, key="fgprep", secret=new_secret,
                    effective_seq=w[2], grace_ms=10_000)
    cb.set_script({w[0]: [cb.ack_pending()]})
    tick(client, n=2)
    payload0 = next(c["payload"] for c in cb.calls
                    if c["payload"]["event_seq"] == w[0])
    activate_key(client, sid, k["key_id"], key="fgact")
    old_secret = version_secret(client, sid, 1)

    # 拨表超过宽限并收敛：版本密钥退役（退役计数挂在版本密钥上）
    client.post("/debug/wall-shift", json={"delta_ms": 60_000})
    rec = kmgr(client).recover_interruptions()
    assert rec["version_key_retired"] == 1

    # 旧签名确认 -> 401，投递仍 awaiting（不丢通知，之后可重签）
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": sig(old_secret, payload0)})
    assert rv.status_code == 401
    assert deliveries(client, sid)[0]["status"] == D_AWAITING
    failed = verifications(client, sid, result="failed")
    assert failed[-1]["event_seq"] == w[0]
    # 退役事件入审计历史（版本密钥退役）
    assert any(e["event"] == "key_retired" and e["outcome"] == "ok"
               for e in history(client, sid))


def test_second_rotation_grace_old_key_ack(seven_events, client, cb):
    """第二把轮换密钥生效：第一把进入 grace，grace 期间旧密钥状态可见，
    宽限结束后退役为 retired。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    secret1, secret2 = "4" * 64, "5" * 64
    eff1, eff2 = w[1], w[4]

    # 两次预登记都在扫描前完成（边界一经预登记即钉住）
    k1 = prepare_key(client, sid, key="s1p", secret=secret1,
                     effective_seq=eff1, grace_ms=3_600_000)
    activate_key(client, sid, k1["key_id"], key="s1a")
    k2 = prepare_key(client, sid, key="s2p", secret=secret2,
                     effective_seq=eff2, grace_ms=3_600_000)

    # 扫描只到 eff2-1：w[0] 旧版本密钥，w[1..3] 用 secret1
    tick(client, n=6)
    stamped1 = [d for d in deliveries(client, sid)
                if d["signing_key_id"] == k1["key_id"]]
    assert sorted(d["event_seq"] for d in stamped1) == w[1:4]

    activate_key(client, sid, k2["key_id"], key="s2a")
    k1v = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k1['key_id']}"
    ).get_json()
    assert k1v["status"] == K_GRACE and k1v["grace_active"] is True
    k2v = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k2['key_id']}"
    ).get_json()
    assert k2v["status"] == K_ACTIVE

    # 新通知 w[4:] 必须用 secret2
    tick(client, n=5)
    stamped2 = [d for d in deliveries(client, sid)
                if d["signing_key_id"] == k2["key_id"]]
    assert sorted(d["event_seq"] for d in stamped2) == w[4:]
    calls = {c["payload"]["event_seq"]: c for c in cb.calls}
    for seq in w[1:4]:
        assert hmac.compare_digest(sig(secret1, calls[seq]["payload"]),
                                   calls[seq]["signature"])
    for seq in w[4:]:
        assert hmac.compare_digest(sig(secret2, calls[seq]["payload"]),
                                   calls[seq]["signature"])

    # 宽限到期后：k1 -> retired（驱动恢复）
    rv = client.post("/debug/wall-shift", json={"delta_ms": 4_000_000})
    assert rv.status_code == 200
    rec = kmgr(client).recover_interruptions()
    assert rec["retired"] == 1
    k1v2 = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k1['key_id']}"
    ).get_json()
    assert k1v2["status"] == K_RETIRED
    # 退役事件入审计历史
    assert any(e["event"] == "key_retired" and e["outcome"] == "ok"
               for e in history(client, sid))


def test_old_key_ack_accepted_in_grace_and_rejected_after(seven_events,
                                                          client, cb):
    """用第一把密钥签名的在途通知 202 等待确认：第二把生效后宽限期内仍可
    用第一把密钥确认（old_key_grace）；宽限结束退役后确认被拒（401）。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    secret1, secret2 = "60" * 32, "70" * 32

    # 两把密钥都在扫描前预登记（边界钉住）：eff1=w[1]，eff2=w[4]
    k1 = prepare_key(client, sid, key="g1p", secret=secret1,
                     effective_seq=w[1], grace_ms=3_600_000)
    activate_key(client, sid, k1["key_id"], key="g1a")
    k2 = prepare_key(client, sid, key="g2p", secret=secret2,
                     effective_seq=w[4], grace_ms=3_600_000)
    # 让 w[1]（k1 签名）202 等待确认
    cb.set_script({w[1]: [cb.ack_pending()]})
    tick(client, n=3)  # w[0] 确认；w[1] awaiting 挡住后续（w[2:] 未投递）
    d1 = next(x for x in deliveries(client, sid) if x["event_seq"] == w[1])
    assert d1["status"] == D_AWAITING
    assert d1["signing_key_id"] == k1["key_id"]
    payload1 = next(c["payload"] for c in cb.calls
                    if c["payload"]["event_seq"] == w[1])

    # 第二把密钥生效：k1 进入宽限
    activate_key(client, sid, k2["key_id"], key="g2a")

    # 用新密钥 secret2 确认旧通知 -> 401，状态不变
    bad = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[1]}/ack",
        json={"signature": sig(secret2, payload1)})
    assert bad.status_code == 401
    assert next(x for x in deliveries(client, sid)
                if x["event_seq"] == w[1])["status"] == D_AWAITING

    # 用旧密钥 secret1 在宽限期内确认 -> 200，验证结果 old_key_grace
    good = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[1]}/ack",
        json={"signature": sig(secret1, payload1)})
    assert good.status_code == 200
    assert good.get_json()["status"] == D_CONFIRMED
    grace_v = verifications(client, sid, result="old_key_grace")
    assert [v["event_seq"] for v in grace_v] == [w[1]]
    assert grace_v[0]["key_id"] == k1["key_id"]
    assert grace_v[0]["expected_key_id"] == k1["key_id"]

    # 队首放行后严格顺序继续：w[2..] 投递，w[4:] 用 secret2
    tick(client, n=8)
    calls = {c["payload"]["event_seq"]: c for c in cb.calls}
    for seq in w[2:4]:
        assert hmac.compare_digest(sig(secret1, calls[seq]["payload"]),
                                   calls[seq]["signature"])
    for seq in w[4:]:
        assert hmac.compare_digest(sig(secret2, calls[seq]["payload"]),
                                   calls[seq]["signature"])


def test_grace_rejected_after_retirement(seven_events, client, cb):
    """grace 密钥退役后，用该旧密钥签名的确认必须 401（旧通知未在宽限内
    完成确认）。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    secret1, secret2 = "6" * 64, "7" * 64

    k1 = prepare_key(client, sid, key="r1p", secret=secret1,
                     effective_seq=w[1], grace_ms=1_000)
    activate_key(client, sid, k1["key_id"], key="r1a")
    k2 = prepare_key(client, sid, key="r2p", secret=secret2,
                     effective_seq=w[4], grace_ms=1_000)
    # w[1] 202 等待确认（属于 k1）
    cb.set_script({w[1]: [cb.ack_pending()]})
    tick(client, n=3)
    d1 = next(x for x in deliveries(client, sid) if x["event_seq"] == w[1])
    assert d1["status"] == D_AWAITING
    payload1 = next(c["payload"] for c in cb.calls
                    if c["payload"]["event_seq"] == w[1])

    # 第二把轮换（短宽限 1s）使 k1 进入 grace
    activate_key(client, sid, k2["key_id"], key="r2a")
    # 拨表超过宽限并收敛：k1 retired
    client.post("/debug/wall-shift", json={"delta_ms": 60_000})
    rec = kmgr(client).recover_interruptions()
    assert rec["retired"] == 1

    # 退役后旧密钥确认 -> 401，投递仍 awaiting（不丢通知，之后可重签）
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[1]}/ack",
        json={"signature": sig(secret1, payload1)})
    assert rv.status_code == 401
    assert next(x for x in deliveries(client, sid)
                if x["event_seq"] == w[1])["status"] == D_AWAITING
    failed = verifications(client, sid, result="failed")
    assert [v["event_seq"] for v in failed] == [w[1]]


# ===========================================================================
# 4. 轮换进度与受影响投递
# ===========================================================================


def test_rotation_progress_and_affected_deliveries(seven_events, client,
                                                   cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    eff = w[3]
    k = prepare_key(client, sid, key="progprep", secret="8" * 64,
                    effective_seq=eff)
    activate_key(client, sid, k["key_id"], key="progact")
    # 扫描入队但不投递：边界前旧密钥、边界后新密钥的投递都处于 pending
    mgr(client).scan_and_enqueue()
    prog = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k['key_id']}/progress"
    ).get_json()
    assert prog["progress"]["effective_seq"] == eff
    # 边界后三条 write 钉住新密钥、处于开放状态
    assert prog["progress"]["new_key_deliveries"] == len(w) - 3
    assert prog["progress"]["new_key_stamped"] == len(w) - 3
    assert prog["progress"]["new_key_open"] == len(w) - 3
    # 边界前三条 write 是尚未投递的旧密钥尾巴
    assert prog["progress"]["old_key_open_deliveries"] == 3
    assert prog["progress"]["drained"] is False

    aff = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k['key_id']}"
        "/deliveries?limit=2").get_json()
    assert len(aff["deliveries"]) == 2
    assert aff["reached_end"] is False
    seqs = [d["event_seq"] for d in aff["deliveries"]]
    assert seqs == w[:2]
    assert all(d["side"] == "old_key_tail" for d in aff["deliveries"])
    # 翻页：旧尾巴后接新密钥投递
    page2 = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k['key_id']}"
        f"/deliveries?limit=10&after={aff['next']}").get_json()
    assert [d["event_seq"] for d in page2["deliveries"]] == w[2:]
    assert [d["side"] for d in page2["deliveries"]] == (
        ["old_key_tail"] + ["new_key"] * 3)
    assert page2["reached_end"] is True

    tick(client, n=8)
    prog2 = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k['key_id']}/progress"
    ).get_json()
    assert prog2["progress"]["new_key_confirmed"] == len(w) - 3
    assert prog2["progress"]["new_key_open"] == 0
    # 旧密钥尾巴全部确认：轮换收尾完成
    assert prog2["progress"]["old_key_open_deliveries"] == 0
    assert prog2["progress"]["drained"] is True


# ===========================================================================
# 5. 验证失败重签
# ===========================================================================


def test_failed_verification_resign(seven_events, client, cb):
    # 干净场景：新订阅 + 已生效密钥，第一条投递 202 等待确认
    w = seven_events["writes"]
    sid = create_sub(client, key="sub-rf", filters={"event_types": ["write"]}
                     )["subscription_id"]
    k = prepare_key(client, sid, key="rfprep", secret="a1" * 32,
                    effective_seq=w[0])
    activate_key(client, sid, k["key_id"], key="rfact")
    cb.set_script({w[0]: [cb.ack_pending()]})
    tick(client, n=2)
    d = deliveries(client, sid)[0]
    assert d["status"] == D_AWAITING
    payload = next(c["payload"] for c in cb.calls
                   if c["payload"]["subscription_id"] == sid)
    # 错误签名确认 -> 401 + failed 验证记录，状态不变
    bad = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": sig("00" * 32, payload)})
    assert bad.status_code == 401
    assert deliveries(client, sid)[0]["status"] == D_AWAITING
    fv = verifications(client, sid, result="failed")
    assert [v["event_seq"] for v in fv] == [w[0]]

    # 指定错误密钥重签 -> 404（失败验证不属于该密钥）
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/resign",
        json={"key_id": "nonexistent-key", "idempotency_key": "resign-wrong"})
    assert rv.status_code == 404

    # 另一条没有任何失败记录的投递不能重签
    sid_ok = create_sub(client, key="sub-ok",
                        callback_url="http://ok.test/hook",
                        filters={"event_types": ["write"]})["subscription_id"]
    ok_key = prepare_key(client, sid_ok, key="okprep", secret="a2" * 32,
                         effective_seq=w[0])
    activate_key(client, sid_ok, ok_key["key_id"], key="okact")
    tick(client, n=2)  # 全部成功确认
    rv = client.post(
        f"/audit/subscriptions/{sid_ok}/deliveries/{w[0]}/resign",
        json={"idempotency_key": "resign-nofail"})
    assert rv.status_code == 409

    # 正确重签：用当前应使用的密钥（k 的新密钥）重算签名
    # 先拍快照应有的所有投递行字段：重签不得改写任何一个
    m = mgr(client)
    before_row = dict(m._conn.execute(
        "SELECT * FROM audit_subscription_deliveries "
        "WHERE subscription_id=? AND event_seq=?",
        (sid, w[0])).fetchone())
    m._conn.rollback()
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/resign",
        json={"idempotency_key": "resign-ok"})
    assert rv.status_code == 200, rv.get_json()
    body = rv.get_json()
    assert body["result"] == "resigned" and body["key_id"] == k["key_id"]
    assert body["replayed"] is False
    # 重签幂等回放（连首次算出的新签名一起回放）
    rv2 = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/resign",
        json={"idempotency_key": "resign-ok"})
    assert rv2.status_code == 200 and rv2.get_json()["replayed"] is True
    assert rv2.get_json()["signature"] == body["signature"]
    # 重签不改变投递状态（仍 awaiting）、不增加 attempts
    d2 = deliveries(client, sid)[0]
    assert d2["status"] == D_AWAITING
    assert d2["attempts"] == 1
    # 已有投递记录的所有字段保持原值（含 signature 与 updated_at_ms）
    after_row = dict(m._conn.execute(
        "SELECT * FROM audit_subscription_deliveries "
        "WHERE subscription_id=? AND event_seq=?",
        (sid, w[0])).fetchone())
    m._conn.rollback()
    assert set(after_row.items()) == set(before_row.items())
    # resigned 验证记录可查，新签名只挂在验证记录上
    rv3 = verifications(client, sid, result="resigned")
    assert [v["event_seq"] for v in rv3] == [w[0]]
    assert rv3[0]["new_signature"] == body["signature"]
    # 投递视图的签名仍是原值（重签不改写投递行）
    assert d2["signature"] == before_row["signature"]
    # 用重签后的签名（验证记录里的新签名）确认成功
    good = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
        json={"signature": rv3[0]["new_signature"]})
    assert good.status_code == 200
    assert good.get_json()["status"] == D_CONFIRMED
    # 审计历史记录重签
    assert any(e["event"] == "key_resigned" and e["outcome"] == "ok"
               for e in history(client, sid))


def test_resign_idempotency_conflict(seven_events, client, cb):
    sub = create_sub(client, key="sub-ric", filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    k = prepare_key(client, sid, key="ricprep", secret="b2" * 32,
                    effective_seq=w[0])
    activate_key(client, sid, k["key_id"], key="ricact")
    cb.set_script({w[0]: [cb.ack_pending()]})
    tick(client, n=2)
    client.post(f"/audit/subscriptions/{sid}/deliveries/{w[0]}/ack",
                json={"signature": "00"})
    client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[0]}/resign",
        json={"idempotency_key": "resign-x"})
    # 同键换投递目标 -> 409
    rv = client.post(
        f"/audit/subscriptions/{sid}/deliveries/{w[1]}/resign",
        json={"idempotency_key": "resign-x"})
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "key_rotation_id_conflict"


# ===========================================================================
# 6. 分页查询验证结果（密钥 + 时间范围）
# ===========================================================================


def test_verification_pagination_by_key_and_time(seven_events, client, cb):
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    s1, s2 = "c3" * 32, "d4" * 32
    # 两把密钥都在扫描前预登记（边界钉住）：eff1=w[1]，eff2=w[4]
    k1 = prepare_key(client, sid, key="p1", secret=s1,
                     effective_seq=w[1], grace_ms=10_000)
    activate_key(client, sid, k1["key_id"], key="a1")
    k2 = prepare_key(client, sid, key="p2", secret=s2,
                     effective_seq=w[4], grace_ms=10_000)
    # 让 w[1] 202 等待确认
    cb.set_script({w[1]: [cb.ack_pending()]})
    tick(client, n=3)  # w[0] 确认，w[1] awaiting 挡队
    payload1 = next(c["payload"] for c in cb.calls
                    if c["payload"]["event_seq"] == w[1])
    # 一次错误确认（failed），再用正确密钥确认（ok）
    client.post(f"/audit/subscriptions/{sid}/deliveries/{w[1]}/ack",
                json={"signature": "zz"})
    client.post(f"/audit/subscriptions/{sid}/deliveries/{w[1]}/ack",
                json={"signature": sig(s1, payload1)})
    activate_key(client, sid, k2["key_id"], key="a2")
    tick(client, n=8)

    # 按密钥过滤：k1 上的验证记录
    v_k1 = verifications(client, sid, key_id=k1["key_id"])
    assert all(v["key_id"] == k1["key_id"] for v in v_k1)
    assert {v["result"] for v in v_k1} <= {"ok", "failed", "old_key_grace",
                                          "resigned"}
    # failed 只在 k1（w[1] 那次错误尝试）
    failed_k1 = verifications(client, sid, key_id=k1["key_id"],
                              result="failed")
    assert [v["event_seq"] for v in failed_k1] == [w[1]]

    # 时间范围闭区间
    allv = verifications(client, sid)
    assert len(allv) == 2 and {v["result"] for v in allv} == {
        "ok", "failed"}
    tmin, tmax = allv[0]["created_at_ms"], allv[-1]["created_at_ms"]
    ranged = verifications(client, sid, **{
        "from_ms": tmin, "to_ms": tmax})
    assert ranged == allv
    none_range = verifications(client, sid, **{"from_ms": tmax + 10})
    assert none_range == []

    # 分页：limit=1 复合游标遍历，按 (时间, rowid) 升序，不重不漏
    seen, after = [], None
    while True:
        url = (f"/audit/subscriptions/{sid}/signature-verifications"
               f"?limit=1")
        if after is not None:
            url += f"&after={after}"
        page = client.get(url).get_json()
        seen.extend(page["verifications"])
        if page["reached_end"]:
            break
        after = page["next"]
    assert seen == allv
    assert len(seen) == len(allv)


# ===========================================================================
# 7. 并发轮换：同键并发生效恰好一个成功
# ===========================================================================


def test_concurrent_activate_single_winner(seven_events, client, cb):
    sub = create_sub(client)
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    k = prepare_key(client, sid, key="cprep", secret="e5" * 32,
                    effective_seq=w[1])
    kid = k["key_id"]
    barrier = threading.Barrier(8)
    results = []

    def worker():
        barrier.wait()
        try:
            view, created = kmgr(client).activate_key(
                sid, kid, idempotency_key="cact")
            results.append(("ok", view["status"], created))
        except Exception as exc:  # noqa: BLE001
            results.append(("err", type(exc).__name__, str(exc)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8
    assert all(r[0] == "ok" and r[1] == K_ACTIVE for r in results), results
    assert [r[2] for r in results].count(True) == 1
    assert [r[2] for r in results].count(False) == 7
    # 只有一次 key_activated=ok
    evs = history(client, sid)
    assert len([e for e in evs
                if e["event"] == "key_activated" and e["outcome"] == "ok"
                ]) == 1


# ===========================================================================
# 8. 重启 / 中断恢复
# ===========================================================================


def test_cancel_subscription_revokes_prepared_key(seven_events, client,
                                                  cb):
    """取消订阅连带撤销 prepared 密钥（永不生效）；已生效密钥状态保留。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    k1 = prepare_key(client, sid, key="cp1", secret="ca" * 32,
                     effective_seq=w[1])
    activate_key(client, sid, k1["key_id"], key="ca1")
    k2 = prepare_key(client, sid, key="cp2", secret="cb" * 32,
                     effective_seq=w[3])
    rv = client.post(f"/audit/subscriptions/{sid}/cancel", json={})
    assert rv.status_code == 200
    v2 = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k2['key_id']}"
    ).get_json()
    assert v2["status"] == K_REVOKED
    # 已生效密钥保留（其投递随取消弃置），但不能再生效新密钥
    v1 = client.get(
        f"/audit/subscriptions/{sid}/signing-keys/{k1['key_id']}"
    ).get_json()
    assert v1["status"] == K_ACTIVE
    rv = client.post(
        f"/audit/subscriptions/{sid}/signing-keys/{k2['key_id']}/activate",
        json={"idempotency_key": "ca2"})
    assert rv.status_code == 409


def test_restart_recovers_and_continues(seven_events, client, cb):
    """轮换生效后、投递未完成时重启：新管理器从已保存状态继续，
    不重复确认、不跳过通知。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    new_secret = "f6" * 32
    k = prepare_key(client, sid, key="rprep", secret=new_secret,
                    effective_seq=w[2])
    activate_key(client, sid, k["key_id"], key="ract")

    store = client.application.extensions["store"]
    old_sub = mgr(client)
    old_key = kmgr(client)
    old_sub.close()
    old_key.close()

    cb2 = ScriptedCallback()
    fresh_sub = SubscriptionManager(store, deliver=cb2)
    fresh_key = KeyRotationManager(store, fresh_sub)
    fresh_sub.attach_key_rotation(fresh_key)
    try:
        # 密钥状态持久
        kv = fresh_key.get_key(sid, k["key_id"])
        assert kv["status"] == K_ACTIVE
        for _ in range(10):
            fresh_key.recover_interruptions()
            fresh_sub.scan_and_enqueue()
            fresh_sub.process_due()
        d = fresh_sub.list_deliveries(sid, limit=1000)["deliveries"]
        # 不重不漏：每条 write 一行，全部确认，严格升序
        assert [x["event_seq"] for x in d] == w
        assert all(x["status"] == D_CONFIRMED for x in d)
        # 边界后钉住新密钥并用新密钥签名
        for c in cb2.calls:
            row = next(x for x in d if x["event_seq"]
                       == c["payload"]["event_seq"])
            sec = new_secret if c["payload"]["event_seq"] >= w[2] \
                else fresh_sub._conn.execute(
                    "SELECT secret FROM audit_subscription_versions "
                    "WHERE subscription_id=? AND version_no=1",
                    (sid,)).fetchone()["secret"]
            assert hmac.compare_digest(sig(sec, c["payload"]),
                                       c["signature"])
            if c["payload"]["event_seq"] >= w[2]:
                assert row["signing_key_id"] == k["key_id"]
    finally:
        fresh_sub.close()
        fresh_key.close()


def test_restart_redelivery_uses_frozen_keys(seven_events, client, cb):
    """生效后扫描入队、尚未投递时重启：新管理器重投的签名仍按投递行冻结
    的密钥代际（旧事件旧密钥、生效序号后新密钥），不重复、不跳过。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    new_secret = "08" * 32
    k = prepare_key(client, sid, key="rrprep", secret=new_secret,
                    effective_seq=w[2])
    activate_key(client, sid, k["key_id"], key="rract")
    # 只入队不投递
    mgr(client).scan_and_enqueue()
    rows = deliveries(client, sid)
    assert sorted(x["event_seq"] for x in rows) == w
    # 重启（构造即回收残留认领行；这里本无认领，直接继续严格顺序投递）
    store = client.application.extensions["store"]
    mgr(client).close()
    kmgr(client).close()
    cb2 = ScriptedCallback()
    fresh_sub = SubscriptionManager(store, deliver=cb2)
    fresh_key = KeyRotationManager(store, fresh_sub)
    fresh_sub.attach_key_rotation(fresh_key)
    try:
        for _ in range(8):
            fresh_sub.scan_and_enqueue()
            fresh_sub.process_due()
        v1_secret = fresh_sub._conn.execute(
            "SELECT secret FROM audit_subscription_versions "
            "WHERE subscription_id=? AND version_no=1",
            (sid,)).fetchone()["secret"]
        # 每次投递的签名都与冻结密钥吻合；每事件恰好投递一次
        assert [c["payload"]["event_seq"] for c in cb2.calls] == w
        for c in cb2.calls:
            sec = new_secret if c["payload"]["event_seq"] >= w[2] \
                else v1_secret
            assert hmac.compare_digest(sig(sec, c["payload"]),
                                       c["signature"])
        d = fresh_sub.list_deliveries(sid, limit=1000)["deliveries"]
        assert all(x["status"] == D_CONFIRMED for x in d)
    finally:
        fresh_sub.close()
        fresh_key.close()


def test_restart_during_prepared_then_activate(seven_events, client, cb):
    """预登记后重启：prepared 密钥保留，仍可生效；边界不被越过。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    k = prepare_key(client, sid, key="prprep", secret="07" * 32,
                    effective_seq=w[3])

    store = client.application.extensions["store"]
    mgr(client).close()
    kmgr(client).close()
    fresh_sub = SubscriptionManager(store, deliver=ScriptedCallback())
    fresh_key = KeyRotationManager(store, fresh_sub)
    fresh_sub.attach_key_rotation(fresh_key)
    try:
        for _ in range(4):
            fresh_sub.scan_and_enqueue()
        kv = fresh_key.get_key(sid, k["key_id"])
        assert kv["status"] == K_PREPARED
        # 边界钉住：边界后事件不入旧密钥队列
        d = fresh_sub.list_deliveries(sid, limit=1000)["deliveries"]
        assert all(x["event_seq"] < w[3] for x in d)
        view, created = fresh_key.activate_key(sid, k["key_id"],
                                               idempotency_key="pract")
        assert created and view["status"] == K_ACTIVE
    finally:
        fresh_sub.close()
        fresh_key.close()


# ===========================================================================
# 9. 审计与源数据不可变
# ===========================================================================


def test_rotation_does_not_modify_source_data(seven_events, client, cb):
    m = mgr(client)
    before = event_rows(client)
    with m._store._conn:
        lease_count = m._store._conn.execute(
            "SELECT COUNT(*) AS c FROM leases").fetchone()["c"]
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    k = prepare_key(client, sid, key="roprep", secret="18" * 32,
                    effective_seq=w[2], grace_ms=1000)
    # 一次越界拒绝
    client.post(
        f"/audit/subscriptions/{sid}/signing-keys",
        json={"secret": "19" * 32, "effective_seq": 10 ** 9,
              "idempotency_key": "roreject"})
    activate_key(client, sid, k["key_id"], key="roact")
    # 第二把待生效密钥也在扫描越过其生效序号前预登记（稍后撤销）
    k2 = prepare_key(client, sid, key="ro2prep", secret="1a" * 32,
                     effective_seq=w[4])
    tick(client, n=8)
    # 撤销 prepared 密钥（永不生效，记录保留）
    revoke_key(client, sid, k2["key_id"], key="ro2rev")

    # 原始审计事件逐行不变
    assert event_rows(client) == before
    with m._store._conn:
        assert m._store._conn.execute(
            "SELECT COUNT(*) AS c FROM leases").fetchone()["c"] \
            == lease_count
    # 全局诊断一致
    diag = client.get("/audit/diagnose").get_json()
    assert diag["summary"]["consistent"] is True

    # 订阅审计历史只追加：轮换生命周期 + 拒绝原因
    evs = history(client, sid)
    kinds = [e["event"] for e in evs]
    for expected in ("key_prepared", "key_activated", "key_rejected",
                     "key_revoked"):
        assert expected in kinds, expected
    # 所有轮换事件 version_no 列为 NULL（与版本切换区分）
    assert all(e["version_no"] is None for e in evs
               if e["event"].startswith("key_"))


def test_rotation_orthogonal_to_version_switch(seven_events, client, cb):
    """密钥轮换与版本切换正交：版本切换不改签名密钥代际，轮换不改回调/
    过滤/版本。"""
    sub = create_sub(client, filters={"event_types": ["write"]})
    sid = sub["subscription_id"]
    w = seven_events["writes"]
    new_secret = "2b" * 32
    k = prepare_key(client, sid, key="vsprep", secret=new_secret,
                    effective_seq=w[2])
    activate_key(client, sid, k["key_id"], key="vsact")
    # 版本切换：新回调、新过滤（acquire 不影响后续 write 投递）
    rv = client.post(f"/audit/subscriptions/{sid}/versions", json={
        "callback_url": "http://v2.test/hook",
        "filters": {"event_types": ["write"]},
        "effective_seq": w[4], "idempotency_key": "vprep"})
    assert rv.status_code == 201, rv.get_json()
    rv = client.post(
        f"/audit/subscriptions/{sid}/versions/2/activate",
        json={"idempotency_key": "vact"})
    assert rv.status_code == 200, rv.get_json()
    tick(client, n=10)
    # 轮换密钥仍按 event_seq 生效：w[2..] 用 new_secret，与版本无关
    for c in cb.calls:
        if c["payload"]["event_seq"] >= w[2]:
            assert hmac.compare_digest(
                sig(new_secret, c["payload"]), c["signature"])
    # w[4:] 走新版本回调地址
    later = [c for c in cb.calls if c["payload"]["event_seq"] >= w[4]]
    assert later and all(c["url"] == "http://v2.test/hook" for c in later)
    # 订阅视图同时反映版本与当前密钥状态
    st = client.get(f"/audit/subscriptions/{sid}").get_json()
    assert st["current_version"] == 2
    keys = client.get(
        f"/audit/subscriptions/{sid}/signing-keys").get_json()["keys"]
    assert {x["key_no"]: x["status"] for x in keys} == {1: K_ACTIVE}
