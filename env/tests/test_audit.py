"""审计回放、稳定视图分页、节点比较与一致性诊断。"""

import json
import threading

from conftest import acquire, renew, wall_shift, write


def grant(client, lease, collaborator="node-x", ttl_ms=60000,
          credential_id=None):
    payload = {
        "resource": lease["resource"], "holder": lease["holder"],
        "generation": lease["generation"], "collaborator": collaborator,
        "ttl_ms": ttl_ms,
    }
    if credential_id is not None:
        payload["credential_id"] = credential_id
    rv = client.post("/leases/delegations", json=payload)
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()["delegation"]


def delegate_write(client, resource, credential_id, holder, value):
    return client.post(f"/resources/{resource}/writes", json={
        "holder": holder, "credential_id": credential_id, "value": value,
    })


def build_history(client, resource="cfg-A"):
    """acquire -> write -> delegate -> delegate_write -> reject -> revoke
    -> late reject -> 第二张凭证(不撤销) -> transfer(连带栅栏) -> write；
    返回各关键对象。"""
    lease = acquire(client, resource, "node-1")
    seqs = {}
    seqs["acquire"] = client.get(
        f"/resources/{resource}/audit/events").get_json()["events"][-1]["seq"]
    assert write(client, lease, "v1").status_code == 201
    d = grant(client, lease)
    cid = d["credential_id"]
    assert delegate_write(
        client, resource, cid, "node-x", "v2").status_code == 201
    # 非指定协作者冒用：拒绝
    assert delegate_write(
        client, resource, cid, "node-y", "bad").status_code == 409
    rv = client.post("/leases/delegations/revoke", json={
        "resource": resource, "holder": "node-1",
        "generation": lease["generation"], "credential_id": cid,
    })
    assert rv.status_code == 200
    # 撤销后迟到写：拒绝
    assert delegate_write(
        client, resource, cid, "node-x", "late").status_code == 409
    # 第二张凭证保持生效：转移时应在同事务被连带栅栏
    d2 = grant(client, lease, collaborator="node-z")
    rv = client.post("/leases/transfer", json={
        "resource": resource, "holder": "node-1",
        "generation": lease["generation"], "to_holder": "node-2",
        "transfer_id": "x-a",
    })
    assert rv.status_code == 201
    new = rv.get_json()["lease"]
    assert write(client, new, "v3").status_code == 201
    return lease, new, cid, d2["credential_id"], seqs["acquire"]


def events(client, url):
    rv = client.get(url)
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


# ---------------------------------------------------------------------------
# 事件流：顺序、分页、稳定视图
# ---------------------------------------------------------------------------

def test_events_order_asc_and_pagination_is_stable(client):
    build_history(client, "cfg-page")
    page1 = events(client, "/resources/cfg-page/audit/events?limit=3")
    seqs1 = [e["seq"] for e in page1["events"]]
    assert seqs1 == sorted(seqs1) and len(seqs1) == 3
    assert page1["reached_end"] is False
    assert page1["next"] == seqs1[-1]

    snap = page1["view"]["snapshot_seq"]
    page2 = client.get(
        f"/resources/cfg-page/audit/events?limit=3&after={page1['next']}"
        f"&snapshot={snap}").get_json()
    seqs2 = [e["seq"] for e in page2["events"]]
    assert seqs2 == sorted(seqs2)
    assert set(seqs1).isdisjoint(seqs2)

    # 一直翻到末尾
    all_seqs = seqs1 + seqs2
    while not page2["reached_end"]:
        nxt = page2["next"]
        page2 = client.get(
            f"/resources/cfg-page/audit/events?limit=3&after={nxt}"
            f"&snapshot={snap}").get_json()
        all_seqs += [e["seq"] for e in page2["events"]]
    assert all_seqs == sorted(all_seqs)
    assert len(all_seqs) == len(set(all_seqs))


def test_snapshot_pins_view_against_concurrent_writes(client):
    lease = acquire(client, "cfg-snap", "node-1")
    first = events(client, "/resources/cfg-snap/audit/events")
    snap = first["view"]["snapshot_seq"]

    # 固定快照：之后再发生写入，查询结果不变
    assert write(client, lease, "new-value").status_code == 201
    pinned = client.get(
        f"/resources/cfg-snap/audit/events?snapshot={snap}").get_json()
    assert [e["seq"] for e in pinned["events"]] == \
        [e["seq"] for e in first["events"]]
    assert pinned["view"]["snapshot_seq"] == snap
    assert pinned["view"]["latest_seq"] > snap

    # 不带快照则看到新事件
    fresh = events(client, "/resources/cfg-snap/audit/events")
    assert len(fresh["events"]) == len(first["events"]) + 1


def test_concurrent_writers_and_readers_never_see_partial_view(
        client, tmp_path, monkeypatch):
    import json as _json
    import urllib.request
    from wsgiref.simple_server import make_server

    # 用独立 app + 真实 HTTP 服务器，避免 Flask 测试客户端的上下文跨线程问题
    from app.app import create_app
    db = str(tmp_path / "conc.db")
    app = create_app(db, start_ticker=False)
    lease = acquire(app.test_client(), "cfg-conc", "node-1")

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []

    def call(method, path, payload=None):
        data = _json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            return resp.status, _json.loads(resp.read())

    def writer():
        try:
            for i in range(30):
                status, _ = call(
                    "POST", "/resources/cfg-conc/writes",
                    {"holder": "node-1", "generation": lease["generation"],
                     "value": f"v{i}"})
                assert status == 201
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def reader():
        try:
            for _ in range(30):
                status, r = call("GET", "/resources/cfg-conc/audit/events")
                assert status == 200
                seqs = [e["seq"] for e in r["events"]]
                assert seqs == sorted(seqs)
                assert max(seqs, default=0) <= r["view"]["snapshot_seq"]
                snap = r["view"]["snapshot_seq"]
                status, d = call(
                    "GET", f"/resources/cfg-conc/audit/diagnose?snapshot={snap}")
                assert status == 200
                assert d["view"]["snapshot_seq"] == snap
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    workers = [threading.Thread(target=writer) for _ in range(2)]
    workers += [threading.Thread(target=reader) for _ in range(3)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    server.shutdown()
    assert not errors


# ---------------------------------------------------------------------------
# 显式错误：历史不存在 / 节点越界 / 窗口为空
# ---------------------------------------------------------------------------

def test_missing_history_returns_404_not_empty_report(client):
    rv = client.get("/resources/ghost/audit/events")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "history_not_found"

    rv = client.get("/resources/ghost/audit/replay?head=1")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "history_not_found"

    rv = client.get("/resources/ghost/audit/diagnose")
    assert rv.status_code == 404


def test_unknown_credential_returns_404(client):
    rv = client.get("/delegations/nope/audit/events")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "credential_not_found"
    rv = client.get("/delegations/nope/audit/replay?head=1")
    assert rv.status_code == 404
    rv = client.get("/delegations/nope/audit/diagnose")
    assert rv.status_code == 404


def test_node_out_of_range_returns_416_with_bounds(client):
    lease, new, cid, cid2, _ = build_history(client, "cfg-416")
    ev = events(client, "/resources/cfg-416/audit/events")
    hi = ev["events"][-1]["seq"]
    lo = ev["events"][0]["seq"]

    rv = client.get(f"/resources/cfg-416/audit/replay?at_seq={hi + 100}")
    assert rv.status_code == 416
    body = rv.get_json()
    assert body["error"] == "node_out_of_range"
    assert body["available_min_seq"] == lo
    assert body["available_max_seq"] == hi

    # 序号属于另一个资源：同样 416，并指明归属
    other = acquire(client, "cfg-other", "node-9")
    other_seq = client.get(
        "/resources/cfg-other/audit/events").get_json()["events"][-1]["seq"]
    rv = client.get(f"/resources/cfg-416/audit/replay?at_seq={other_seq}")
    assert rv.status_code == 416
    assert body is not None
    j = rv.get_json()
    assert j.get("belongs_to_resource") == "cfg-other"

    # 翻页游标越过末条
    rv = client.get(f"/resources/cfg-416/audit/events?after={hi + 50}")
    assert rv.status_code == 416

    # 快照越界（cfg-other 的获取已推进全局 seq，用明确越界的大数）
    latest = ev["view"]["latest_seq"]
    rv = client.get(
        f"/resources/cfg-416/audit/events?snapshot={latest + 1000}")
    assert rv.status_code == 416


def test_empty_filter_window_is_404_not_blank_page(client):
    build_history(client, "cfg-win")
    # outcome 过滤合法但无匹配：404
    rv = client.get(
        "/resources/cfg-win/audit/events?event=delegate_revoke&outcome=rejected")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "no_events_in_range"
    # 时间窗整体落在历史之前
    rv = client.get("/resources/cfg-win/audit/events?to_ms=1")
    assert rv.status_code == 404
    # 序号窗口越过末条
    ev = events(client, "/resources/cfg-win/audit/events")
    hi = ev["events"][-1]["seq"]
    rv = client.get(f"/resources/cfg-win/audit/events?seq_min={hi + 10}")
    assert rv.status_code == 404
    # 翻到过滤集末尾之后：游标仍合法，返回空页 + reached_end（标准分页）
    page = events(
        client,
        "/resources/cfg-win/audit/events?event=write&limit=100")
    last = page["events"][-1]["seq"]
    tail = client.get(
        f"/resources/cfg-win/audit/events?event=write&after={last}")
    assert tail.status_code == 200
    assert tail.get_json()["events"] == []
    assert tail.get_json()["reached_end"] is True
    # 但游标越过该资源最后一条事件仍是 416
    rv = client.get(
        f"/resources/cfg-win/audit/events?event=write&after={hi + 1}")
    assert rv.status_code == 416


def test_replay_requires_exactly_one_node_selector(client):
    acquire(client, "cfg-sel", "node-1")
    assert client.get("/resources/cfg-sel/audit/replay").status_code == 400
    assert client.get(
        "/resources/cfg-sel/audit/replay?head=1&at_seq=1").status_code == 400
    assert client.get(
        "/resources/cfg-sel/audit/compare?a_head=1").status_code == 400


# ---------------------------------------------------------------------------
# 节点回放：资源值、当前租约、委托状态、世代号；每步说明
# ---------------------------------------------------------------------------

def test_replay_reconstructs_value_lease_delegation_and_generation(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "cfg-rep")
    ev = events(client, "/resources/cfg-rep/audit/events")
    by_kind = {}
    for e in ev["events"]:
        by_kind.setdefault(e["event"], []).append(e)

    # 节点 1：第一次委托写入之后 —— 值应为 v2，租约仍是 node-1/gen1，
    # 凭证 active，当前世代号 1
    dw = by_kind["delegate_write"][0]
    r = client.get(
        f"/resources/cfg-rep/audit/replay?at_seq={dw['seq']}").get_json()
    st = r["state_as_of_node"]
    assert st["resource"]["value"] == "v2"
    assert st["resource"]["value_source_seq"] == dw["seq"]
    assert st["resource"]["current_generation"] == 1
    assert st["lease"]["holder"] == "node-1"
    assert st["lease"]["generation"] == 1
    assert st["lease"]["active_at_node"] is True
    cred = st["delegations"][0]
    assert cred["credential_id"] == cid
    assert cred["state"] == "active"
    assert cred["writes_accepted"] == 1

    # 节点 2：撤销事件之后 —— 凭证变 revoked，租约/资源值不变
    revoke_seq = by_kind["delegate_revoke"][0]["seq"]
    r = client.get(
        f"/resources/cfg-rep/audit/replay?at_seq={revoke_seq}").get_json()
    cred = [d for d in r["state_as_of_node"]["delegations"]
            if d["credential_id"] == cid][0]
    assert cred["state"] == "revoked"
    assert cred["end_seq"] == revoke_seq
    assert r["state_as_of_node"]["lease"]["holder"] == "node-1"

    # 节点 3（head）：转移+写入之后 —— 值 v3、当前租约 node-2/gen2、
    # 凭证随转移被栅栏（fence 事件由同事务产生）
    r = client.get(
        "/resources/cfg-rep/audit/replay?head=1").get_json()
    st = r["state_as_of_node"]
    assert st["resource"]["value"] == "v3"
    assert st["resource"]["current_generation"] == 2
    assert st["lease"]["holder"] == "node-2"
    assert st["lease"]["generation"] == 2
    assert st["generations"]["acquired"] == [1, 2]
    cred = [d for d in st["delegations"] if d["credential_id"] == cid][0]
    # 先 revoke 后 fence：终态以先发生的 revoke 为准，fence 事件记录在流里
    assert cred["state"] == "revoked"
    # 保持生效的第二张凭证在转移同事务被连带栅栏
    cred2 = [d for d in st["delegations"] if d["credential_id"] == cid2][0]
    assert cred2["state"] == "fenced"
    assert cred2["end_reason"] == "source_lease_transferred"
    fence = [e for e in ev["events"] if e["event"] == "delegate_fence"]
    assert fence and fence[0]["detail"] == "source_lease_transferred"


def test_every_event_is_narrated_with_actor_verdict_reason(client):
    build_history(client, "cfg-narr")
    ev = events(client, "/resources/cfg-narr/audit/events")["events"]
    for e in ev:
        assert e["narration"]
        assert e["holder"] in e["narration"] or e["event"].startswith("delegate_expire")
        if e["outcome"] == "rejected":
            assert "拒绝" in e["narration"]
            assert e["detail"]  # 拒绝原因非空
        else:
            assert "接受" in e["narration"] or "成功" in e["narration"] \
                or "复用" in e["narration"] or "过期" in e["narration"] \
                or "撤销" in e["narration"] or "栅栏" in e["narration"]
    # 抽查：冒用凭证的拒绝叙述里要有协作者不符原因
    bad = [e for e in ev if e["event"] == "delegate_write"
           and e["outcome"] == "rejected"
           and e["detail"] == "collaborator_mismatch"]
    assert bad and "协作者" in bad[0]["narration"]


def test_replay_by_wall_ms_picks_last_event_at_or_before(client):
    lease = acquire(client, "cfg-wall", "node-1")
    assert write(client, lease, "w1").status_code == 201
    assert write(client, lease, "w2").status_code == 201
    ev = events(client, "/resources/cfg-wall/audit/events")["events"]
    mid = ev[1]["wall_ms"]  # acquire, w1, w2
    r = client.get(
        f"/resources/cfg-wall/audit/replay?at_wall_ms={mid}").get_json()
    assert r["node"]["seq"] == ev[1]["seq"]
    assert r["state_as_of_node"]["resource"]["value"] == "w1"

    # 早于首条事件：416 并给出首条事件时间
    rv = client.get("/resources/cfg-wall/audit/replay?at_wall_ms=1")
    assert rv.status_code == 416
    assert rv.get_json()["first_event_wall_ms"] == ev[0]["wall_ms"]


def test_credential_replay_and_events_scope(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "cfg-cred")
    rv = client.get(f"/delegations/{cid}/audit/events")
    assert rv.status_code == 200
    chain = rv.get_json()["events"]
    kinds = [(e["event"], e["outcome"]) for e in chain]
    assert kinds[0] == ("delegate_grant", "ok")
    assert ("delegate_write", "ok") in kinds
    assert ("delegate_write", "rejected") in kinds
    assert ("delegate_revoke", "ok") in kinds
    assert all(e["credential_id"] == cid for e in chain)

    r = client.get(f"/delegations/{cid}/audit/replay?head=1")
    assert r.status_code == 200
    body = r.get_json()
    assert body["credential"]["credential_id"] == cid
    assert body["credential"]["state"] == "revoked"
    assert body["credential"]["writes_accepted"] == 1
    assert body["credential"]["writes_rejected"] >= 1
    # 节点处的资源上下文也在
    assert body["state_as_of_node"]["resource"]["name"] == "cfg-cred"


# ---------------------------------------------------------------------------
# 两节点比较：第一次产生差异的事件
# ---------------------------------------------------------------------------

def test_compare_finds_first_diverging_event(client):
    lease = acquire(client, "cfg-cmp", "node-1")
    ev = events(client, "/resources/cfg-cmp/audit/events")["events"]
    seq_acquire = ev[0]["seq"]
    assert write(client, lease, "aaa").status_code == 201
    renew(client, lease)
    assert write(client, lease, "bbb").status_code == 201

    r = client.get(
        f"/resources/cfg-cmp/audit/compare?a_at_seq={seq_acquire}&b_head=1"
    ).get_json()
    assert r["identical"] is False
    first = r["first_divergence"]
    # 第一次偏离 acquire 后状态的事件是第一次成功写入（续约不改业务指纹）
    assert first["event"] == "write"
    assert "resource.value" in first["changed_fields"]
    assert r["state_at_first_divergence"] is not None
    assert r["state_at_first_divergence"]["resource.value"]["at_node"] == "aaa"
    # b 点终态值
    assert r["changed_fields_at_b"]["resource.value"]["at_b"] == "bbb"
    # 拒绝事件即便在区间内也不应造成偏离
    assert r["events_between"] >= 3


def test_compare_identical_nodes(client):
    lease = acquire(client, "cfg-eq", "node-1")
    ev = events(client, "/resources/cfg-eq/audit/events")["events"]
    # 同节点比自己
    r = client.get(
        f"/resources/cfg-eq/audit/compare?a_at_seq={ev[0]['seq']}"
        f"&b_at_seq={ev[0]['seq']}").get_json()
    assert r["identical"] is True
    assert r["first_divergence"] is None
    assert r["changed_fields_at_b"] == {}


def test_compare_rejected_write_does_not_diverge(client):
    lease = acquire(client, "cfg-rd", "node-1")
    assert write(client, lease, "only").status_code == 201
    # 非持有者写，被拒
    assert write(client, lease, "nope", holder="intruder").status_code == 409
    ev = events(client, "/resources/cfg-rd/audit/events")["events"]
    first_write = [e for e in ev if e["event"] == "write"
                   and e["outcome"] == "ok"][0]["seq"]
    r = client.get(
        f"/resources/cfg-rd/audit/compare?a_at_seq={first_write}&b_head=1"
    ).get_json()
    assert r["identical"] is True
    rejected = r["rejected_events_between"]
    assert any(x["detail"] == "generation_fence" for x in rejected)


def test_compare_requires_a_before_b(client):
    lease = acquire(client, "cfg-order", "node-1")
    assert write(client, lease, "x").status_code == 201
    ev = events(client, "/resources/cfg-order/audit/events")["events"]
    rv = client.get(
        f"/resources/cfg-order/audit/compare?a_at_seq={ev[-1]['seq']}"
        f"&b_at_seq={ev[0]['seq']}")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "bad_request"


# ---------------------------------------------------------------------------
# 一致性诊断：健康历史无 error；篡改/损坏可被发现
# ---------------------------------------------------------------------------

def test_diagnose_healthy_history_is_consistent(client):
    build_history(client, "cfg-ok2")
    r = client.get("/resources/cfg-ok2/audit/diagnose").get_json()
    assert r["summary"]["consistent"] is True
    assert r["summary"]["errors"] == 0
    # 全局诊断也干净（跨资源 seq 缺口不报）
    g = client.get("/audit/diagnose").get_json()
    assert g["summary"]["consistent"] is True
    seq_codes = [i["code"] for i in g["issues"] if i["code"] == "seq_missing"]
    assert seq_codes == []


def test_diagnose_reports_missing_global_seq(client, tmp_path):
    import sqlite3

    lease = acquire(client, "cfg-corrupt", "node-1")
    assert write(client, lease, "v").status_code == 201
    before = client.get("/audit/diagnose").get_json()
    assert before["summary"]["consistent"] is True

    # 直接在 SQLite 层删掉一条事件（模拟审计被删/损坏）
    path = client.application.extensions["store"]._conn.execute(
        "PRAGMA database_list").fetchone()[2]
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM lease_events WHERE seq=1")
    conn.commit()
    conn.close()

    g = client.get("/audit/diagnose").get_json()
    missing = [i for i in g["issues"] if i["code"] == "seq_missing"]
    assert any(i["seq"] == 1 for i in missing)
    assert g["summary"]["consistent"] is False

    # 资源级诊断里投影也会发现：成功写入找不到获取链（write 无匹配生效租约）
    r = client.get("/resources/cfg-corrupt/audit/diagnose").get_json()
    codes = {i["code"] for i in r["issues"]}
    assert "write_accepted_without_fence_match" in codes


def test_diagnose_flags_out_of_order_or_contradictory_events(client):
    lease = acquire(client, "cfg-contra", "node-1")
    assert write(client, lease, "v").status_code == 201
    # 构造一条"不可能"的成功释放事件：seq 上排在一次成功写入之后，
    # 但 lease_id 指向一个不存在的租约（直接写库）
    path = client.application.extensions["store"]._conn.execute(
        "PRAGMA database_list").fetchone()[2]
    import sqlite3
    conn = sqlite3.connect(path)
    now = conn.execute("SELECT MAX(wall_ms) FROM lease_events").fetchone()[0]
    conn.execute(
        "INSERT INTO lease_events(resource, event, outcome, holder, "
        "lease_id, generation, wall_ms, logical) "
        "VALUES('cfg-contra','release','ok','node-1','fake-lease',1,?,0)",
        (now,),
    )
    conn.commit()
    conn.close()

    r = client.get("/resources/cfg-contra/audit/diagnose").get_json()
    codes = {i["code"] for i in r["issues"]}
    assert "release_accepted_without_matching_active_lease" in codes
    assert r["summary"]["consistent"] is False


def test_diagnose_detects_logical_clock_regression(client):
    lease = acquire(client, "cfg-log", "node-1")
    assert write(client, lease, "v1").status_code == 201
    client.post("/debug/tick", json={"steps": 5})
    assert write(client, lease, "v2").status_code == 201
    # 把较早的写入事件 logical 改成 9（大于后继事件的 5，制造回退痕迹）
    path = client.application.extensions["store"]._conn.execute(
        "PRAGMA database_list").fetchone()[2]
    import sqlite3
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE lease_events SET logical=9 WHERE seq="
        "(SELECT MIN(seq) FROM lease_events WHERE resource='cfg-log' "
        "AND event='write')")
    conn.commit()
    conn.close()
    r = client.get("/resources/cfg-log/audit/diagnose").get_json()
    codes = {i["code"] for i in r["issues"]}
    assert "logical_clock_regressed" in codes


# ---------------------------------------------------------------------------
# 诊断绝不修改运行态
# ---------------------------------------------------------------------------

def test_audit_reads_never_mutate_runtime_or_history(client):
    # 默认 TTL 上限 60s：拨 5s 不越过软/硬期限，租约仍 active
    lease = acquire(client, "cfg-ro", "node-1", ttl_ms=60_000)
    assert write(client, lease, "v1").status_code == 201
    wall_shift(client, 5_000)  # 不越过 TTL，租约仍 active

    before = client.get(
        "/resources/cfg-ro/audit/events").get_json()
    store = client.application.extensions["store"]
    with store._lock:
        meta_before = store._conn.execute(
            "SELECT MAX(seq) m, COUNT(*) c FROM lease_events").fetchone()
        state_before = store._conn.execute(
            "SELECT state FROM leases WHERE id=?",
            (lease["lease_id"],)).fetchone()["state"]

    for url in [
        "/resources/cfg-ro/audit/events",
        "/resources/cfg-ro/audit/replay?head=1",
        "/resources/cfg-ro/audit/diagnose",
        "/audit/events",
        "/audit/diagnose",
        # 翻页 + 过滤 + 固定快照，全部只读路径
        "/resources/cfg-ro/audit/events?limit=1&after=1&snapshot="
        + str(before["view"]["snapshot_seq"]),
    ]:
        assert client.get(url).status_code == 200

    after = client.get("/resources/cfg-ro/audit/events").get_json()
    with store._lock:
        meta_after = store._conn.execute(
            "SELECT MAX(seq) m, COUNT(*) c FROM lease_events").fetchone()
        state_after = store._conn.execute(
            "SELECT state FROM leases WHERE id=?",
            (lease["lease_id"],)).fetchone()["state"]

    # 事件数、最大序号、租约状态全部未被审计改变
    assert tuple(meta_before) == tuple(meta_after)
    assert state_before == state_after == "active"
    assert json.dumps(before, sort_keys=True) == json.dumps(after, sort_keys=True)


# ---------------------------------------------------------------------------
# 重启确定性
# ---------------------------------------------------------------------------

def test_replay_and_diagnosis_identical_after_restart(tmp_path):
    from app.app import create_app

    db = str(tmp_path / "audit.db")
    app1 = create_app(db, start_ticker=False)
    c1 = app1.test_client()
    lease = acquire(c1, "cfg-restart", "node-1")
    assert write(c1, lease, "persist-v").status_code == 201
    d = grant(c1, lease, collaborator="node-z")
    assert delegate_write(
        c1, "cfg-restart", d["credential_id"], "node-z", "persist-v2"
    ).status_code == 201

    ev1 = c1.get("/resources/cfg-restart/audit/events").get_json()
    rep1 = c1.get(
        "/resources/cfg-restart/audit/replay?head=1").get_json()
    diag1 = c1.get(
        "/resources/cfg-restart/audit/diagnose").get_json()
    cred_diag1 = c1.get(
        f"/delegations/{d['credential_id']}/audit/diagnose").get_json()

    app2 = create_app(db, start_ticker=False)
    c2 = app2.test_client()
    ev2 = c2.get("/resources/cfg-restart/audit/events").get_json()
    rep2 = c2.get(
        "/resources/cfg-restart/audit/replay?head=1").get_json()
    diag2 = c2.get(
        "/resources/cfg-restart/audit/diagnose").get_json()
    cred_diag2 = c2.get(
        f"/delegations/{d['credential_id']}/audit/diagnose").get_json()

    assert ev1 == ev2
    assert rep1 == rep2
    assert diag1["issues"] == diag2["issues"]
    assert diag1["summary"] == diag2["summary"]
    assert cred_diag1["issues"] == cred_diag2["issues"]
    # 回放值正确
    assert rep2["state_as_of_node"]["resource"]["value"] == "persist-v2"
    assert rep2["state_as_of_node"]["delegations"][0]["state"] == "active"


# ---------------------------------------------------------------------------
# 全局事件流与跨资源视图
# ---------------------------------------------------------------------------

def test_global_events_interleave_by_global_seq(client):
    a = acquire(client, "g1", "h1")
    b = acquire(client, "g2", "h2")
    assert write(client, a, "1").status_code == 201
    assert write(client, b, "2").status_code == 201
    r = client.get("/audit/events?limit=100").get_json()
    seqs = [e["seq"] for e in r["events"]]
    assert seqs == sorted(seqs)
    assert {e["resource"] for e in r["events"]} == {"g1", "g2"}
    # 空库全局列表是 200 空集（全局列举不属于"针对不存在目标"的查询）
