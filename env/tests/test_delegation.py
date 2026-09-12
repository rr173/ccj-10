"""限时委托（time-limited delegation）。

覆盖：
- 持有者发放短期凭证，协作者凭凭证连续写入，世代号锚定授权租约；
- 协作者不能续约/释放/转移/再转委托；
- 撤销、过期、原租约释放/转移/过期后，迟到凭证写入一律拒绝；
- 凭证串资源、协作者冒充、世代号不符一律拒绝；
- 发放/使用/撤销/过期/连带栅栏全部进同一份历史，可按凭证号过滤；
- 重启后凭证状态、审计顺序一致；
- 发放与撤销并发下不存在"既能写又已撤销"的状态。
"""

import threading

from conftest import acquire, renew, write


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def grant(client, lease, collaborator="node-9", ttl_ms=10_000,
          credential_id=None, holder=None, generation=None):
    payload = {
        "resource": lease["resource"],
        "holder": lease["holder"] if holder is None else holder,
        "generation": lease["generation"] if generation is None
        else generation,
        "collaborator": collaborator,
        "ttl_ms": ttl_ms,
    }
    if credential_id is not None:
        payload["credential_id"] = credential_id
    return client.post("/leases/delegations", json=payload)


def revoke(client, lease, credential_id, holder=None, generation=None):
    return client.post("/leases/delegations/revoke", json={
        "resource": lease["resource"],
        "holder": lease["holder"] if holder is None else holder,
        "generation": lease["generation"] if generation is None
        else generation,
        "credential_id": credential_id,
    })


def delegate_write(client, resource, credential_id, collaborator="node-9",
                   value="v", generation=None):
    payload = {
        "holder": collaborator, "credential_id": credential_id,
        "value": value,
    }
    if generation is not None:
        payload["generation"] = generation
    return client.post(f"/resources/{resource}/writes", json=payload)


def wall_shift(client, delta_ms):
    return client.post("/debug/wall-shift", json={"delta_ms": delta_ms})


def history(client, resource, credential_id=None):
    url = f"/resources/{resource}/history"
    if credential_id is not None:
        url += f"?credential_id={credential_id}"
    rv = client.get(url)
    assert rv.status_code == 200
    return rv.get_json()["events"]


# ---------------------------------------------------------------------------
# 发放 + 连续写入
# ---------------------------------------------------------------------------
def test_holder_grants_delegation_and_collaborator_writes_repeatedly(client):
    lease = acquire(client, "cfg-D1", "node-1")

    rv = grant(client, lease, "node-9", ttl_ms=10_000)
    assert rv.status_code == 201, rv.get_json()
    d = rv.get_json()["delegation"]
    assert d["state"] == "active"
    assert d["authorizer"] == "node-1"
    assert d["collaborator"] == "node-9"
    assert d["generation"] == lease["generation"]
    assert d["lease_id"] == lease["lease_id"]
    assert d["resource"] == "cfg-D1"
    assert d["ttl_ms"] == 10_000
    assert d["expires_wall_ms"] == d["granted_wall_ms"] + 10_000
    credential_id = d["credential_id"]

    # 协作者可连续写入，世代号沿用授权租约那一代
    w1 = delegate_write(client, "cfg-D1", credential_id, value="c1")
    assert w1.status_code == 201, w1.get_json()
    body = w1.get_json()
    assert body["accepted"] is True
    assert body["generation"] == lease["generation"]
    assert body["credential_id"] == credential_id
    assert body["holder"] == "node-9"
    assert body["authorizer"] == "node-1"
    assert delegate_write(client, "cfg-D1", credential_id,
                          value="c2").status_code == 201
    assert delegate_write(client, "cfg-D1", credential_id,
                          value="c3").status_code == 201

    res = client.get("/resources/cfg-D1").get_json()
    assert res["value"] == "c3"
    assert res["last_passed_generation"] == lease["generation"]

    # 授权者本人照样能写，互不影响
    assert write(client, lease, "owner").status_code == 201

    # 写入审计里每次委托写都挂着凭证号
    writes = client.get("/resources/cfg-D1/writes").get_json()["writes"]
    cred_writes = [w for w in writes if w["credential_id"] == credential_id]
    assert len(cred_writes) == 3
    assert all(w["generation"] == lease["generation"] for w in cred_writes)
    assert all(w["holder"] == "node-9" for w in cred_writes)


def test_get_delegation_by_credential_id(client):
    lease = acquire(client, "cfg-D2", "node-1")
    d = grant(client, lease, "node-9").get_json()["delegation"]

    rv = client.get(f"/delegations/{d['credential_id']}")
    assert rv.status_code == 200
    got = rv.get_json()
    assert got["credential_id"] == d["credential_id"]
    assert got["authorizer"] == "node-1"
    assert got["collaborator"] == "node-9"
    assert got["generation"] == lease["generation"]
    assert got["expires_wall_ms"] > got["granted_wall_ms"]

    rv = client.get("/delegations/does-not-exist")
    assert rv.status_code == 404

    listed = client.get("/resources/cfg-D2/delegations").get_json()["delegations"]
    assert [x["credential_id"] for x in listed] == [d["credential_id"]]


# ---------------------------------------------------------------------------
# 协作者只有写权限
# ---------------------------------------------------------------------------
def test_collaborator_cannot_renew_release_transfer_or_redelegate(client):
    lease = acquire(client, "cfg-D3", "node-1")
    d = grant(client, lease, "node-9").get_json()["delegation"]
    cid = d["credential_id"]
    gen = lease["generation"]

    # 续约：协作者不是持有者
    rv = client.post("/leases/renew", json={
        "resource": "cfg-D3", "holder": "node-9", "generation": gen})
    assert rv.status_code == 409
    # 释放
    rv = client.post("/leases/release", json={
        "resource": "cfg-D3", "holder": "node-9", "generation": gen})
    assert rv.status_code == 409
    # 转移
    rv = client.post("/leases/transfer", json={
        "resource": "cfg-D3", "holder": "node-9", "generation": gen,
        "to_holder": "node-7", "transfer_id": "t-by-collab"})
    assert rv.status_code == 409
    # 再次转委托：管理入口只认租约持有者
    rv = grant(client, lease, "node-7", holder="node-9")
    assert rv.status_code == 409

    # 授权者本人与原租约毫发无损
    renewed = renew(client, lease)
    assert renewed["generation"] == lease["generation"]
    assert delegate_write(client, "cfg-D3", cid, value="still-ok"
                          ).status_code == 201


def test_only_named_collaborator_can_use_credential(client):
    lease = acquire(client, "cfg-D4", "node-1")
    cid = grant(client, lease, "node-9").get_json()["delegation"]["credential_id"]

    # 别人捡到凭证号也不能用
    rv = delegate_write(client, "cfg-D4", cid, collaborator="node-2")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "delegation_rejected"

    # 连授权者本人也不能以协作者身份用这张凭证（他直接用租约写）
    rv = delegate_write(client, "cfg-D4", cid, collaborator="node-1")
    assert rv.status_code == 409

    # 指定协作者本人正常
    assert delegate_write(client, "cfg-D4", cid).status_code == 201

    writes = client.get("/resources/cfg-D4/writes").get_json()["writes"]
    rejected = [w for w in writes
                if w["credential_id"] == cid and not w["accepted"]]
    assert {w["reject_reason"] for w in rejected} == {"collaborator_mismatch"}


def test_credential_bound_to_single_resource(client):
    lease = acquire(client, "cfg-D5a", "node-1")
    client.post("/leases/acquire", json={
        "resource": "cfg-D5b", "holder": "node-8", "ttl_ms": 2000})
    cid = grant(client, lease, "node-9").get_json()["delegation"]["credential_id"]

    # A 资源的凭证写 B 资源：凭证不存在
    rv = delegate_write(client, "cfg-D5b", cid)
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "not_found"


def test_delegated_write_with_wrong_generation_rejected(client):
    lease = acquire(client, "cfg-D6", "node-1")
    cid = grant(client, lease, "node-9").get_json()["delegation"]["credential_id"]

    rv = delegate_write(client, "cfg-D6", cid,
                        generation=lease["generation"] + 5)
    assert rv.status_code == 409
    # 带对世代号（或不带）都可以
    assert delegate_write(client, "cfg-D6", cid,
                          generation=lease["generation"]).status_code == 201
    assert delegate_write(client, "cfg-D6", cid).status_code == 201


# ---------------------------------------------------------------------------
# 发放校验
# ---------------------------------------------------------------------------
def test_grant_requires_holder_generation_and_eligible_collaborator(client):
    lease = acquire(client, "cfg-D7", "node-1")

    # 非持有者发放
    assert grant(client, lease, "node-9", holder="node-2").status_code == 409
    # 世代号不符
    assert grant(client, lease, "node-9",
                 generation=lease["generation"] + 1).status_code == 409
    # 协作者为空 / 自己
    assert grant(client, lease, "").status_code == 409
    assert grant(client, lease, None).status_code == 409
    assert grant(client, lease, "node-1").status_code == 409

    # 原租约未被影响，正常发放成功
    assert grant(client, lease, "node-9").status_code == 201


def test_grant_without_active_lease_is_412(client):
    # 先建一个资源但不持有租约：直接用伪造世代号发放
    rv = client.post("/leases/delegations", json={
        "resource": "cfg-D8", "holder": "node-1", "generation": 99,
        "collaborator": "node-9", "ttl_ms": 1000})
    assert rv.status_code == 412


def test_delegation_ttl_never_exceeds_lease_hard_deadline(client):
    # 租约硬上限 60s；索要 120s 的委托也只能截到剩余寿命
    lease = acquire(client, "cfg-D9", "node-1")
    d = grant(client, lease, "node-9", ttl_ms=120_000
              ).get_json()["delegation"]
    assert d["expires_wall_ms"] <= lease["hard_wall_deadline_ms"]
    assert d["ttl_ms"] <= 60_000


# ---------------------------------------------------------------------------
# 撤销
# ---------------------------------------------------------------------------
def test_revoke_stops_late_writes_and_is_audited(client):
    lease = acquire(client, "cfg-D10", "node-1")
    cid = grant(client, lease, "node-9").get_json()["delegation"]["credential_id"]
    assert delegate_write(client, "cfg-D10", cid, value="before").status_code == 201

    rv = revoke(client, lease, cid)
    assert rv.status_code == 200, rv.get_json()
    assert rv.get_json()["revoked"] is True
    assert rv.get_json()["delegation"]["state"] == "revoked"

    # 撤销后的迟到写入：一律拒绝
    rv = delegate_write(client, "cfg-D10", cid, value="late")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "delegation_rejected"
    writes = client.get("/resources/cfg-D10/writes").get_json()["writes"]
    late = [w for w in writes
            if w["credential_id"] == cid and w["holder"] == "node-9"]
    last = late[0]  # 倒序，最新一条在前
    assert last["accepted"] is False
    assert last["reject_reason"] == "delegation_revoked"

    # 资源值没有被迟到写污染
    assert client.get("/resources/cfg-D10").get_json()["value"] == "before"

    # 再次撤销：已处于 revoked，拒绝
    assert revoke(client, lease, cid).status_code == 409

    # 只有授权者本人能撤销：协作者不能撤销自己的凭证
    assert revoke(client, lease, cid, holder="node-9").status_code == 409

    # 授权者本人的直接写入不受影响
    assert write(client, lease, "owner-still-writes").status_code == 201


def test_revoke_unknown_credential_is_404_without_polluting_history(client):
    lease = acquire(client, "cfg-D11", "node-1")
    rv = revoke(client, lease, "nope")
    assert rv.status_code == 404
    # 不认识的凭证不应产生任何事件
    events = history(client, "cfg-D11")
    assert all(e["credential_id"] is None for e in events)


# ---------------------------------------------------------------------------
# 过期
# ---------------------------------------------------------------------------
def test_delegation_expires_by_wall_clock_and_late_writes_rejected(client):
    lease = acquire(client, "cfg-D12", "node-1")  # 租约软 TTL 2s
    cid = grant(client, lease, "node-9", ttl_ms=500
                ).get_json()["delegation"]["credential_id"]
    assert delegate_write(client, "cfg-D12", cid, value="ok").status_code == 201

    # 越过委托到期（+1s 尚在租约软 TTL 内，逻辑钟宽限也让租约活着）
    wall_shift(client, 1_000)

    rv = client.get(f"/delegations/{cid}")
    assert rv.get_json()["state"] == "expired"

    rv = delegate_write(client, "cfg-D12", cid, value="late")
    assert rv.status_code == 409
    assert "delegation_expired" in rv.get_json()["message"]

    # 历史里有自动过期事件
    events = history(client, "cfg-D12", credential_id=cid)
    kinds = [(e["event"], e["outcome"]) for e in events]
    assert ("delegate_grant", "ok") in kinds
    assert ("delegate_write", "ok") in kinds
    assert ("delegate_expire", "ok") in kinds
    assert ("delegate_write", "rejected") in kinds
    # 审计顺序：过期严格发生在被拒写入之前
    expire_seq = [e["seq"] for e in events if e["event"] == "delegate_expire"][0]
    rejected_seq = [
        e["seq"] for e in events
        if e["event"] == "delegate_write" and e["outcome"] == "rejected"
    ][0]
    assert expire_seq < rejected_seq


# ---------------------------------------------------------------------------
# 原租约释放 / 转移 / 过期 -> 委托连带栅栏
# ---------------------------------------------------------------------------
def test_release_fences_delegation(client):
    lease = acquire(client, "cfg-D13", "node-1")
    cid = grant(client, lease, "node-9").get_json()["delegation"]["credential_id"]

    client.post("/leases/release", json={
        "resource": "cfg-D13", "holder": "node-1",
        "generation": lease["generation"]})

    rv = delegate_write(client, "cfg-D13", cid, value="late")
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "delegation_rejected"
    assert "source_lease_released" in body["message"]

    d = client.get(f"/delegations/{cid}").get_json()
    assert d["state"] == "fenced"
    assert d["end_reason"] == "source_lease_released"


def test_transfer_fences_delegation_but_new_holder_unaffected(client):
    lease = acquire(client, "cfg-D14", "node-1")
    cid = grant(client, lease, "node-9").get_json()["delegation"]["credential_id"]
    assert delegate_write(client, "cfg-D14", cid, value="via-cred").status_code == 201

    rv = client.post("/leases/transfer", json={
        "resource": "cfg-D14", "holder": "node-1",
        "generation": lease["generation"], "to_holder": "node-2",
        "transfer_id": "xfer-deleg-1"})
    assert rv.status_code == 201
    new = rv.get_json()["lease"]

    # 迟到的委托写入必拒
    rv = delegate_write(client, "cfg-D14", cid, value="late")
    assert rv.status_code == 409
    assert "source_lease_transferred" in rv.get_json()["message"]

    # 新持有者不受影响
    assert write(client, new, "new-owner").status_code == 201

    d = client.get(f"/delegations/{cid}").get_json()
    assert d["state"] == "fenced"
    assert d["end_reason"] == "source_lease_transferred"


def test_lease_hard_expiry_fences_delegation(client):
    lease = acquire(client, "cfg-D15", "node-1")
    cid = grant(client, lease, "node-9", ttl_ms=50_000
                ).get_json()["delegation"]["credential_id"]
    assert delegate_write(client, "cfg-D15", cid, value="ok").status_code == 201

    # 逻辑钟冻结 + 墙钟越过租约硬上限：租约硬过期
    wall_shift(client, 61_000)
    assert client.get("/resources/cfg-D15/leases").get_json()["state"] == "expired"

    rv = delegate_write(client, "cfg-D15", cid, value="late")
    assert rv.status_code == 409
    assert "source_lease_expired" in rv.get_json()["message"]

    d = client.get(f"/delegations/{cid}").get_json()
    assert d["state"] == "fenced"
    assert d["end_reason"] == "source_lease_expired"


# ---------------------------------------------------------------------------
# 统一历史：可按凭证号查到授权者/协作者/有效期/世代号与每次结果
# ---------------------------------------------------------------------------
def test_history_filtered_by_credential_covers_full_lifecycle(client):
    lease = acquire(client, "cfg-D16", "node-1")
    cid = grant(client, lease, "node-9").get_json()["delegation"]["credential_id"]
    delegate_write(client, "cfg-D16", cid, value="w1")
    delegate_write(client, "cfg-D16", cid, collaborator="node-2", value="x")  # 拒绝
    revoke(client, lease, cid)
    delegate_write(client, "cfg-D16", cid, value="late")  # 拒绝

    events = history(client, "cfg-D16", credential_id=cid)
    assert [(e["event"], e["outcome"]) for e in events] == [
        ("delegate_grant", "ok"),
        ("delegate_write", "ok"),
        ("delegate_write", "rejected"),
        ("delegate_revoke", "ok"),
        ("delegate_write", "rejected"),
    ]

    # 每条事件都可回溯到授权者、协作者（peer）、世代号、凭证
    for e in events:
        assert e["credential_id"] == cid
        assert e["holder"] in ("node-1", "node-9", "node-2")
        assert e["generation"] == lease["generation"]
        assert e["wall_ms"] > 0
        assert e["logical"] >= 0
    grant_ev = events[0]
    assert grant_ev["holder"] == "node-1"
    assert grant_ev["peer"] == "node-9"
    assert grant_ev["lease_id"] == lease["lease_id"]
    assert grant_ev["detail"].startswith("expires_wall_ms=")

    # 凭证事件与普通事件同处一份历史、共享同一个审计序号序列
    full = history(client, "cfg-D16")
    assert len(full) > len(events)
    seqs = [e["seq"] for e in full]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


# ---------------------------------------------------------------------------
# 重启持久性
# ---------------------------------------------------------------------------
def test_delegation_state_and_audit_order_survive_restart(tmp_path):
    from app.app import create_app

    db = tmp_path / "deleg.db"
    app1 = create_app(str(db), start_ticker=False)
    c1 = app1.test_client()
    lease = acquire(c1, "cfg-D17", "node-1")
    d1 = grant(c1, lease, "node-9").get_json()["delegation"]
    delegate_write(c1, "cfg-D17", d1["credential_id"], value="v1")
    revoke(c1, lease, d1["credential_id"])
    delegate_write(c1, "cfg-D17", d1["credential_id"], value="late")

    # 第二张：撤销前重启，重启后仍有效
    d2 = grant(c1, lease, "node-7", ttl_ms=30_000
               ).get_json()["delegation"]["credential_id"]
    delegate_write(c1, "cfg-D17", d2, collaborator="node-7", value="v2")

    before = history(c1, "cfg-D17")

    # ---- 重启 ----
    app2 = create_app(str(db), start_ticker=False)
    c2 = app2.test_client()

    # 审计顺序完全一致
    assert history(c2, "cfg-D17") == before

    # 已撤销的凭证：重启后迟到写入仍被拒
    rv = delegate_write(c2, "cfg-D17", d1["credential_id"], value="late2")
    assert rv.status_code == 409
    got = c2.get(f"/delegations/{d1['credential_id']}").get_json()
    assert got["state"] == "revoked"
    assert got["authorizer"] == "node-1"
    assert got["generation"] == lease["generation"]

    # 仍生效的凭证：重启后协作者照常连续写入
    assert delegate_write(c2, "cfg-D17", d2, collaborator="node-7",
                          value="v3").status_code == 201


def test_expired_delegation_stays_dead_after_restart(tmp_path):
    from app.app import create_app

    db = tmp_path / "deleg2.db"
    app1 = create_app(str(db), start_ticker=False)
    c1 = app1.test_client()
    lease = acquire(c1, "cfg-D18", "node-1")
    cid = grant(c1, lease, "node-9", ttl_ms=500
                ).get_json()["delegation"]["credential_id"]
    wall_shift(c1, 1_000)  # 委托到期（重启前）

    app2 = create_app(str(db), start_ticker=False)
    c2 = app2.test_client()
    assert c2.get(f"/delegations/{cid}").get_json()["state"] == "expired"
    assert delegate_write(c2, "cfg-D18", cid, value="late").status_code == 409


# ---------------------------------------------------------------------------
# 并发：发放与撤销竞争，绝不出现"既能写又已撤销"
# ---------------------------------------------------------------------------
def test_concurrent_grant_revoke_write_never_allows_write_after_revoke(tmp_path):
    from app.store import Store

    db = tmp_path / "deleg-conc.db"
    store = Store(str(db))
    lease, _ = store.acquire("cfg-D19", "node-1", 60_000)
    fixed_cid = "fixed-credential-id"
    errors: list[Exception] = []

    n_writers = 6
    start = threading.Barrier(n_writers + 1)   # 发放与写入同时开跑
    granted = threading.Event()
    revoke_done = threading.Event()

    def granter():
        import time
        try:
            start.wait()
            store.grant_delegation(
                "cfg-D19", "node-1", lease["generation"], "node-9",
                ttl_ms=30_000, credential_id=fixed_cid)
            granted.set()
            # 留出明确窗口，让协作者在撤销前并发写若干轮
            time.sleep(0.1)
            store.revoke_delegation(
                "cfg-D19", "node-1", lease["generation"], fixed_cid)
            revoke_done.set()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def writer():
        # 撤销前一直写；撤销后再补写若干轮，全部必须被拒
        start.wait()
        while not revoke_done.is_set():
            try:
                store.write(
                    "cfg-D19", "node-9", None, "race",
                    credential_id=fixed_cid)
            except Exception:  # noqa: BLE001 - 凭证未发出/已撤都是合法结果
                pass
        for _ in range(20):
            try:
                store.write(
                    "cfg-D19", "node-9", None, "after",
                    credential_id=fixed_cid)
                errors.append(AssertionError("撤销后的写入竟被放行"))
            except Exception as exc:  # noqa: BLE001
                if "revoked" not in str(exc):
                    errors.append(exc)

    threads = [
        threading.Thread(target=granter),
        *[threading.Thread(target=writer) for _ in range(n_writers)],
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    # 最终状态：已撤销
    assert store.get_delegation(fixed_cid)["state"] == "revoked"

    # 线性化判据：所有放行的凭证写，其审计序号必须严格早于撤销事件；
    # 撤销之后的凭证写必须全部被拒
    events = store.list_history("cfg-D19", 1000, credential_id=fixed_cid)
    revoke_seq = [
        e["seq"] for e in events
        if e["event"] == "delegate_revoke" and e["outcome"] == "ok"
    ][0]
    accepted = [
        e["seq"] for e in events
        if e["event"] == "delegate_write" and e["outcome"] == "ok"
    ]
    assert accepted, "撤销前窗口里应至少有一次并发写被放行"
    assert max(accepted) < revoke_seq
    assert not [
        e for e in events
        if e["event"] == "delegate_write"
        and e["outcome"] == "ok" and e["seq"] > revoke_seq
    ]
    store.close()
