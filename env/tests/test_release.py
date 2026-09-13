"""索引版本发布管理。

覆盖：
- 立即发布与延迟发布：登记时冻结索引摘要/快照/可选比较结果，到点（worker
  与查询惰性扫描）自动生效，生效时再次冻结并复核；
- 幂等与冲突：相同版本号+幂等键返回同一计划（含到点回放为 active）；同键
  换索引/换生效时间/换比较对象、同版本号换键、同键比较结果漂移均显式 409；
  版本别名一旦登记永不复用（取消/失败后同名仍冲突）；
- 取消：只允许取消 scheduled（幂等），已生效/已失败不可取消；
- 失败：发布期间原索引被篡改（节点内容/行摘要/删除/非完成态）、比较对象
  被删除/未完成/比较结果变化 -> failed 并保留 error_code/error_detail，
  retry 失败仍失败、修复后成功；
- 中断恢复：错过生效时间的计划在服务重启（启动 process_due）后立即发布；
- 稳定查询：版本别名只指向冻结索引（resolve 永远返回冻结视图 + live 诊断），
  生效后原索引被篡改 -> chain/nodes/download 409、被删除 404，旧版本仍可
  按原索引标识查询；
- 只读边界：登记/发布/取消/查询/重试绝不修改原索引、派生任务、租约、委托、
  审计历史、源归档或证据包（只写 index_releases）。
"""

import json

import pytest

from app.app import create_app
from app.release import IndexReleaseManager
from conftest import acquire, write


# ---------------------------------------------------------------------------
# 夹具与辅助
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "release.db"
    app = create_app(str(db), start_ticker=False, enable_debug_api=True,
                     start_archive_worker=False)
    app.extensions["releases"] = IndexReleaseManager(
        app.extensions["store"], app.extensions["causal"],
        app.extensions["derivation"])
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def mgr(client):
    return client.application.extensions["causal"]


def rmgr(client):
    return client.application.extensions["releases"]


def store_of(client):
    return client.application.extensions["store"]


def make_index(client, payload):
    rv = client.post("/audit/causal-indexes", json=payload)
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()["index_id"]


def finish_index(client, index_id):
    m = mgr(client)
    for _ in range(300):
        m.process_pending()
        st = client.get(f"/audit/causal-indexes/{index_id}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("因果索引未完成")


def build_history(client, resource="r1", holder="h1", n=3):
    lease = acquire(client, resource, holder, ttl_ms=200_000)
    for i in range(n):
        rv = write(client, lease, f"v{i}")
        assert rv.status_code == 201, rv.get_json()
    return lease


def two_indexes(client, n_before=2, n_after=1, resource="r1"):
    """同一资源两个快照节点的已完成索引（后者是前者的超集）。"""
    build_history(client, resource=resource, n=n_before)
    a = make_index(client, {"scope": "resource", "resource": resource,
                            "head": True,
                            "idempotency_key": f"ia-{resource}"})
    finish_index(client, a)
    lease = client.get(f"/resources/{resource}/leases").get_json()
    for i in range(n_after):
        assert write(client, lease, f"later-{i}").status_code == 201
    b = make_index(client, {"scope": "resource", "resource": resource,
                            "head": True,
                            "idempotency_key": f"ib-{resource}"})
    finish_index(client, b)
    return a, b


def now_ms(client):
    return client.get("/debug/now").get_json()["wall_ms"]


def register(client, payload):
    return client.post("/audit/index-releases", json=payload)


def register_immediate(client, index_id, version="v1", key="k1", **extra):
    payload = {"version": version, "index_id": index_id,
               "idempotency_key": key,
               "effective_at_ms": _FIXED_PAST_MS}
    payload.update(extra)
    return register(client, payload)


def register_scheduled(client, index_id, version="v1", key="k1", **extra):
    payload = {"version": version, "index_id": index_id,
               "idempotency_key": key,
               "effective_at_ms": now_ms(client) + 60_000}
    payload.update(extra)
    return register(client, payload)


# 固定的过去时刻：立即发布的两次登记必须携带完全相同的生效时间，
# 否则会先在 effective_at_ms 上触发同键冲突
_FIXED_PAST_MS = 1_000_000_000_000


def tamper_index_payload(client, index_id, node_id="event:1",
                         field=("event", "narration"), value="tampered"):
    """直接改冻结节点载荷（模拟有人绕过服务篡改原索引）。"""
    with store_of(client)._lock:
        conn = store_of(client)._conn
        row = conn.execute(
            "SELECT payload FROM causal_index_nodes WHERE index_id=? "
            "AND node_id=?", (index_id, node_id)).fetchone()
        p = json.loads(row["payload"])
        obj = p
        for k in field[:-1]:
            obj = obj[k]
        obj[field[-1]] = value
        conn.execute(
            "UPDATE causal_index_nodes SET payload=? WHERE index_id=? "
            "AND node_id=?",
            (json.dumps(p, sort_keys=True, separators=(",", ":")),
             index_id, node_id))
        conn.commit()


def delete_index(client, index_id):
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("DELETE FROM causal_index_nodes WHERE index_id=?",
                     (index_id,))
        conn.execute("DELETE FROM causal_index_members WHERE index_id=?",
                     (index_id,))
        conn.execute("DELETE FROM causal_indexes WHERE index_id=?",
                     (index_id,))
        conn.commit()


# ---------------------------------------------------------------------------
# 立即发布：登记即冻结
# ---------------------------------------------------------------------------


def test_immediate_release_freezes_summary_snapshot_and_comparison(client):
    a, b = two_indexes(client)
    rv = register_immediate(client, a, "v2026.1", "rel-1",
                            compare_with_index_id=b)
    assert rv.status_code == 201, rv.get_json()
    view = rv.get_json()
    assert view["status"] == "active"
    assert view["effective_now"] is True
    assert view["activated_at_ms"] is not None

    fs = view["frozen_index_summary"]
    assert fs["index_id"] == a
    assert fs["chain_digest"] and fs["content_sha256"]
    assert fs["total_nodes"] > 0
    assert view["frozen_snapshot"]["snapshot_seq"] == fs["snapshot_seq"]
    assert view["frozen_snapshot"]["node_seq"] == fs["node_seq"]
    assert view["frozen_snapshot"]["latest_seq"] >= fs["snapshot_seq"]
    # 生效时再次冻结的内容与登记一致
    av = view["activate_index_summary"]
    assert av["chain_digest"] == fs["chain_digest"]
    assert view["activate_index_chain_digest"] == fs["chain_digest"]
    assert view["activate_snapshot"]["latest_seq"] >= \
        view["frozen_snapshot"]["latest_seq"]
    # 比较结果在登记时冻结
    cmp_ = view["frozen_comparison"]
    assert cmp_["a"]["index_id"] == a and cmp_["b"]["index_id"] == b
    assert cmp_["summary"]["added_nodes"] > 0
    assert view["compare_digest"]
    assert view["activate_comparison"]["summary"] == cmp_["summary"]


def test_register_without_comparison(client):
    a, _ = two_indexes(client)
    rv = register_immediate(client, a, "v1", "k")
    assert rv.status_code == 201
    view = rv.get_json()
    assert view["status"] == "active"
    assert view["frozen_comparison"] is None
    assert view["compare_with_index_id"] is None
    assert view["compare_digest"] is None


def test_release_id_and_plan_getters(client):
    a, _ = two_indexes(client)
    view = register_immediate(client, a, "v1", "k").get_json()
    rid = view["release_id"]
    assert client.get(f"/audit/index-releases/{rid}").get_json()[
        "release_id"] == rid
    assert client.get("/audit/index-versions/v1").get_json()[
        "release_id"] == rid
    listed = client.get("/audit/index-releases").get_json()["releases"]
    assert [r["release_id"] for r in listed] == [rid]
    assert client.get("/audit/index-releases?status=active").get_json()[
        "releases"][0]["release_id"] == rid
    assert client.get("/audit/index-releases?status=scheduled").get_json()[
        "releases"] == []
    assert client.get(f"/audit/index-releases?index_id={a}").get_json()[
        "releases"][0]["release_id"] == rid


# ---------------------------------------------------------------------------
# 幂等与冲突
# ---------------------------------------------------------------------------


def test_same_version_and_idempotency_key_returns_same_plan(client):
    a, b = two_indexes(client)
    eff = now_ms(client) - 1000
    p1 = {"version": "v1", "index_id": a, "idempotency_key": "k",
          "effective_at_ms": eff, "compare_with_index_id": b}
    rv1 = register(client, p1)
    assert rv1.status_code == 201
    rid = rv1.get_json()["release_id"]
    rv2 = register(client, p1)
    assert rv2.status_code == 200
    j2 = rv2.get_json()
    assert j2["replayed"] is True
    assert j2["release_id"] == rid
    assert j2["status"] == "active"


def test_same_key_replay_after_due_activates(client):
    a, _ = two_indexes(client)
    eff = now_ms(client) + 60_000
    p = {"version": "v1", "index_id": a, "idempotency_key": "k",
         "effective_at_ms": eff}
    rv = register(client, p)
    assert rv.get_json()["status"] == "scheduled"
    # 拨墙钟越过生效时间（计划参数不变），同键同参数回放应先惰性发布
    client.post("/debug/wall-shift", json={"delta_ms": 120_000})
    try:
        rv = register(client, p)
        j = rv.get_json()
        assert rv.status_code == 200 and j["replayed"] is True
        assert j["status"] == "active"
    finally:
        client.post("/debug/wall-shift", json={"delta_ms": -120_000})


def test_same_key_different_index_conflicts(client):
    a, _ = two_indexes(client, resource="r1")
    b, _ = two_indexes(client, resource="r2")
    register_immediate(client, a, "v1", "k")
    rv = register_immediate(client, b, "v2", "k")
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "release_id_conflict"
    # version 也不同，但首个差异按检查顺序是 version
    assert body["first_difference"]["path"] == "version"
    # 换索引但保持同版本号（且只改索引）：首个差异落在 index_id
    rv = register_immediate(client, b, "v1", "k")
    assert rv.status_code == 409
    diff = rv.get_json()["first_difference"]
    assert diff["path"] == "index_id"
    assert diff["existing"] == a
    assert diff["requested"] == b


def test_same_key_different_effective_time_conflicts(client):
    a, _ = two_indexes(client)
    register_immediate(client, a, "v1", "k")
    rv = register(client, {"version": "v1", "index_id": a,
                           "idempotency_key": "k",
                           "effective_at_ms": now_ms(client) + 99_999})
    assert rv.status_code == 409
    assert rv.get_json()["first_difference"]["path"] == "effective_at_ms"


def test_same_key_different_compare_target_conflicts(client):
    a, b = two_indexes(client)
    register_immediate(client, a, "v1", "k", compare_with_index_id=b)
    rv = register_immediate(client, a, "v1", "k")
    assert rv.status_code == 409
    assert rv.get_json()["first_difference"]["path"] == \
        "compare_with_index_id"


def test_same_version_different_key_conflicts_forever(client):
    a, b = two_indexes(client)
    register_immediate(client, a, "v1", "k1")
    # 换索引、换幂等键、同名版本 -> 版本冲突
    rv = register_immediate(client, b, "v1", "k2")
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "release_version_conflict"
    assert body["existing_idempotency_key"] == "k1"
    # 同名版本在计划取消后仍不可再分配：登记一个延迟计划再取消
    sched = register_scheduled(client, a, "v2", "ks").get_json()
    client.post(f"/audit/index-releases/{sched['release_id']}/cancel")
    rv = register_immediate(client, a, "v2", "k3")
    assert rv.status_code == 409
    assert rv.get_json()["existing_status"] == "cancelled"
    # 失败后的版本名同样不可再分配
    f = register_scheduled(client, a, "v3", "kf").get_json()
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET status='failed', "
                     "error_code='x' WHERE release_id=?",
                     (f["release_id"],))
        conn.commit()
    rv = register_immediate(client, a, "v3", "k4")
    assert rv.status_code == 409
    assert rv.get_json()["existing_status"] == "failed"


def test_same_key_comparison_result_changed_conflicts(client):
    a, b = two_indexes(client)
    register_immediate(client, a, "v1", "k", compare_with_index_id=b)
    # 比较对象 B 在两次登记间被篡改 -> 同键同比较对象也必须显式冲突
    tamper_index_payload(client, b)
    rv = register_immediate(client, a, "v1", "k", compare_with_index_id=b)
    assert rv.status_code == 409
    assert rv.get_json()["first_difference"]["path"] == "compare_digest"


def test_concurrent_same_version_and_key_returns_single_plan(tmp_path):
    import threading
    import urllib.request
    from wsgiref.simple_server import make_server

    from conftest import acquire, write

    db = str(tmp_path / "release-conc.db")
    app = create_app(db, start_ticker=False, enable_debug_api=True,
                     start_archive_worker=False)
    c = app.test_client()
    lease = acquire(c, "rc-conc", "node-1", ttl_ms=200000)
    assert write(c, lease, "v1").status_code == 201
    aid = make_index(c, {"scope": "resource", "resource": "rc-conc",
                         "head": True, "idempotency_key": "ci-conc"})
    app.extensions["causal"].process_pending()

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    results, errors = [], []

    def worker():
        try:
            payload = json.dumps({
                "version": "vc", "index_id": aid,
                "idempotency_key": "kc",
                "effective_at_ms": _FIXED_PAST_MS}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/audit/index-releases",
                data=payload, method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req) as resp:
                results.append((resp.status,
                                json.loads(resp.read())["release_id"]))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    server.shutdown()
    assert not errors
    assert {s for s, _ in results} <= {200, 201}
    assert 201 in {s for s, _ in results}
    assert len({rid for _, rid in results}) == 1


def test_multiple_distinct_versions_allowed(client):
    a, b = two_indexes(client)
    r1 = register_immediate(client, a, "v1", "k1")
    r2 = register_immediate(client, b, "v2", "k2")
    assert r1.status_code == 201 and r2.status_code == 201
    j1 = client.get("/audit/index-versions/v1").get_json()
    j2 = client.get("/audit/index-versions/v2").get_json()
    assert j1["index"]["frozen"]["index_id"] == a
    assert j2["index"]["frozen"]["index_id"] == b


# ---------------------------------------------------------------------------
# 延迟生效、取消与中断恢复
# ---------------------------------------------------------------------------


def test_scheduled_activates_via_worker_and_lazy_sweep(client):
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    rid = view["release_id"]
    assert view["status"] == "scheduled"
    # 生效时间未到：worker 不发布
    assert rmgr(client).process_due() == 0
    assert client.get(f"/audit/index-releases/{rid}").get_json()[
        "status"] == "scheduled"
    # 生效时间拨到过去：worker 发布
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    assert rmgr(client).process_due() == 1
    assert client.get(f"/audit/index-releases/{rid}").get_json()[
        "status"] == "active"


def test_lazy_sweep_on_query(client):
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?",
                     (now_ms(client) - 1, view["release_id"]))
        conn.commit()
    # 不显式跑 worker：解析版本别名即惰性发布
    j = client.get("/audit/index-versions/v1").get_json()
    assert j["status"] == "active"
    assert j["stable"] is True


def test_cancel_only_scheduled_and_idempotent(client):
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    rid = view["release_id"]
    rv = client.post(f"/audit/index-releases/{rid}/cancel")
    assert rv.status_code == 200 and rv.get_json()["status"] == "cancelled"
    # 幂等取消
    rv = client.post(f"/audit/index-releases/{rid}/cancel")
    assert rv.status_code == 200 and rv.get_json()["status"] == "cancelled"
    # 到点也不再发布
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    rmgr(client).process_due()
    assert client.get(f"/audit/index-releases/{rid}").get_json()[
        "status"] == "cancelled"


def test_cancel_active_or_failed_is_rejected(client):
    a, _ = two_indexes(client)
    view = register_immediate(client, a, "v1", "k").get_json()
    rv = client.post(
        f"/audit/index-releases/{view['release_id']}/cancel")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "release_bad_state"


def test_scheduled_plan_survives_restart_and_activates(tmp_path):
    db = tmp_path / "restart.db"
    app1 = create_app(str(db), start_ticker=False,
                      start_archive_worker=False)
    c1 = app1.test_client()
    build_history(c1)
    aid = make_index(c1, {"scope": "resource", "resource": "r1",
                          "head": True, "idempotency_key": "ia"})
    app1.extensions["causal"].process_pending()
    # 登记一个生效时间在"不远将来"的计划
    now = c1.get("/debug/now").get_json()["wall_ms"]
    rv = c1.post("/audit/index-releases", json={
        "version": "v1", "index_id": aid, "idempotency_key": "k",
        "effective_at_ms": now + 10_000})
    assert rv.status_code == 201 and rv.get_json()["status"] == "scheduled"

    # 服务中断 30s 后重启（墙钟偏移持久化，计划的生效时间已经错过）
    c1.post("/debug/wall-shift", json={"delta_ms": 30_000})

    # start_archive_worker=True：启动即 process_due，错过的计划立即发布
    app2 = create_app(str(db), start_ticker=False,
                      start_archive_worker=True)
    c2 = app2.test_client()
    j = c2.get("/audit/index-versions/v1").get_json()
    assert j["status"] == "active"
    assert j["stable"] is True
    assert j["index"]["frozen"]["index_id"] == aid


# ---------------------------------------------------------------------------
# 发布失败：原索引被篡改/删除/未完成、比较对象未完成、比较结果变化
# ---------------------------------------------------------------------------


def test_activation_fails_when_index_tampered(client):
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    rid = view["release_id"]
    tamper_index_payload(client, a)
    rmgr(client).process_due()  # 计划仍 scheduled（生效时间未到），先拨时间
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    assert rmgr(client).process_due() == 1
    j = client.get(f"/audit/index-releases/{rid}").get_json()
    assert j["status"] == "failed"
    assert j["error_code"] == "release_index_tampered"
    assert j["error_detail"]["path"] == "index.chain_digest_recomputed"
    assert j["error_detail"]["frozen"] != j["error_detail"]["current"]
    # 版本别名明确报告失败原因
    rv = client.get("/audit/index-versions/v1")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "index_release_failed"
    assert rv.get_json()["error_code"] == "release_index_tampered"


def test_activation_fails_when_index_deleted(client):
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    rid = view["release_id"]
    delete_index(client, a)
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    rmgr(client).process_due()
    j = client.get(f"/audit/index-releases/{rid}").get_json()
    assert j["status"] == "failed"
    assert j["error_code"] == "release_index_deleted"
    assert j["error_detail"]["path"] == "index.index_id"


def test_activation_fails_when_compare_target_deleted(client):
    a, b = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k",
                              compare_with_index_id=b).get_json()
    rid = view["release_id"]
    delete_index(client, b)
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    rmgr(client).process_due()
    j = client.get(f"/audit/index-releases/{rid}").get_json()
    assert j["status"] == "failed"
    assert j["error_code"] == "release_compare_target_not_ready"


def test_activation_fails_when_comparison_changed(client):
    a, b = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k",
                              compare_with_index_id=b).get_json()
    rid = view["release_id"]
    # 比较对象 B 在发布前被篡改：比较结果与登记冻结值不同
    tamper_index_payload(client, b)
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    rmgr(client).process_due()
    j = client.get(f"/audit/index-releases/{rid}").get_json()
    assert j["status"] == "failed"
    assert j["error_code"] == "release_comparison_changed"
    assert j["error_detail"]["path"].startswith("comparison.")


def test_failed_plan_retry_fails_again_until_fixed(client):
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    rid = view["release_id"]
    tamper_index_payload(client, a)
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    rmgr(client).process_due()
    assert client.get(f"/audit/index-releases/{rid}").get_json()[
        "status"] == "failed"
    # 未修复就重试：仍失败，attempts 累加
    rv = client.post(f"/audit/index-releases/{rid}/retry")
    assert rv.status_code == 200
    j = rv.get_json()
    assert j["status"] == "failed"
    assert j["attempts"] >= 2
    assert j["error_code"] == "release_index_tampered"
    # 非失败态（active/scheduled/cancelled）不能重试
    a2, _ = two_indexes(client, resource="r2")
    ok = register_immediate(client, a2, "v2", "k2").get_json()
    rv = client.post(f"/audit/index-releases/{ok['release_id']}/retry")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "release_bad_state"
    pend = register_scheduled(client, a2, "v3", "k3").get_json()
    rv = client.post(f"/audit/index-releases/{pend['release_id']}/retry")
    assert rv.status_code == 409
    # 计划不存在 -> 404
    assert client.post("/audit/index-releases/nope/retry").status_code == 404


def test_failed_plan_retry_succeeds_after_source_restored(client):
    """篡改行内 chain_digest（节点载荷保持原样）-> 失败；把行摘要恢复为
    重算值（等同备份修复）-> retry 成功。"""
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    rid = view["release_id"]
    with store_of(client)._lock:
        conn = store_of(client)._conn
        # 只改行内摘要、不动节点：登记冻结的是原摘要，激活时行内值先对不上
        conn.execute("UPDATE causal_indexes SET chain_digest=? "
                     "WHERE index_id=?", ("0" * 64, a))
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?", (now_ms(client) - 1, rid))
        conn.commit()
    rmgr(client).process_due()
    j = client.get(f"/audit/index-releases/{rid}").get_json()
    assert j["status"] == "failed"
    assert j["error_code"] == "release_index_tampered"
    assert j["error_detail"]["path"] == "index.chain_digest"
    # 备份修复：行内摘要恢复为冻结值
    with store_of(client)._lock:
        conn = store_of(client)._conn
        frozen = j["frozen_index_summary"]["chain_digest"]
        conn.execute("UPDATE causal_indexes SET chain_digest=? "
                     "WHERE index_id=?", (frozen, a))
        conn.commit()
    rv = client.post(f"/audit/index-releases/{rid}/retry")
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "active"


def test_register_rejects_unfinished_or_missing_index_and_compare(client):
    a, _ = two_indexes(client, resource="r9")
    pend = make_index(client, {"scope": "resource", "resource": "r9",
                               "head": True, "idempotency_key": "ip-r9"})
    rv = register_immediate(client, pend, "v1", "k")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "causal_index_not_ready"
    rv = register_immediate(client, "missing-index", "v2", "k2")
    assert rv.status_code == 404
    rv = register_immediate(client, a, "v3", "k3",
                            compare_with_index_id=pend)
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "causal_index_not_ready"
    rv = register_immediate(client, a, "v4", "k4",
                            compare_with_index_id="missing")
    assert rv.status_code == 404


def test_register_bad_params(client):
    a, _ = two_indexes(client)
    base = {"version": "v1", "index_id": a, "idempotency_key": "k"}
    for patch in (
        {"version": ""},
        {"index_id": ""},
        {"idempotency_key": ""},
        {"effective_at_ms": None},
        {"effective_at_ms": "not-a-number"},
        {"version": 123},
    ):
        rv = register(client, base | patch |
                      ({} if "effective_at_ms" in patch
                       else {"effective_at_ms": now_ms(client)}))
        assert rv.status_code == 400, (patch, rv.get_json())


# ---------------------------------------------------------------------------
# 稳定查询：版本别名只指向冻结索引
# ---------------------------------------------------------------------------


def test_version_alias_serves_frozen_index_chain_node_download(client):
    a, _ = two_indexes(client)
    register_immediate(client, a, "v1", "k")
    ch = client.get("/audit/index-versions/v1/chain?limit=1000").get_json()
    assert ch["served_index_id"] == a
    assert ch["version"] == "v1"
    assert ch["frozen_at_ms"] is not None
    assert len(ch["nodes"]) == ch["total_nodes"]
    first = ch["nodes"][0]["node_id"]
    n = client.get(f"/audit/index-versions/v1/nodes/{first}").get_json()
    assert n["node_id"] == first and n["served_index_id"] == a
    rv = client.get("/audit/index-versions/v1/download")
    assert rv.status_code == 200
    assert rv.headers["X-Index-Version"] == "v1"
    assert rv.headers["X-Causal-SHA256"]
    doc = json.loads(rv.data)
    assert doc["index_id"] == a


def test_version_alias_rejects_tampered_and_deleted_index(client):
    a, _ = two_indexes(client)
    register_immediate(client, a, "v1", "k")
    tamper_index_payload(client, a)
    rv = client.get("/audit/index-versions/v1/chain")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "release_index_tampered"
    rv = client.get("/audit/index-versions/v1/download")
    assert rv.status_code == 409
    # resolve 仍可返回冻结视图，只把 live 标成 tampered
    j = client.get("/audit/index-versions/v1").get_json()
    assert j["live"]["state"] == "tampered"
    assert j["stable"] is False
    assert j["index"]["frozen"]["index_id"] == a

    delete_index(client, a)
    rv = client.get("/audit/index-versions/v1/chain")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "release_index_deleted"
    j = client.get("/audit/index-versions/v1").get_json()
    assert j["live"]["state"] == "deleted"


def test_version_content_is_frozen_against_later_writes(client):
    """版本生效后再有新写入/新索引，版本别名内容与下载文档字节不变。"""
    a, b = two_indexes(client)
    register_immediate(client, a, "v1", "k1")
    chain_before = client.get(
        "/audit/index-versions/v1/chain?limit=1000").get_json()
    doc_before = client.get("/audit/index-versions/v1/download").data
    total_before = chain_before["total_nodes"]

    # 版本生效后再写并建立更新的索引：版本别名不漂移
    lease = client.get("/resources/r1/leases").get_json()
    assert write(client, lease, "after-release").status_code == 201
    c = make_index(client, {"scope": "resource", "resource": "r1",
                            "head": True, "idempotency_key": "ic-r1"})
    finish_index(client, c)

    chain_after = client.get(
        "/audit/index-versions/v1/chain?limit=1000").get_json()
    doc_after = client.get("/audit/index-versions/v1/download").data
    assert chain_after["total_nodes"] == total_before
    assert chain_after["served_index_id"] == a
    assert doc_after == doc_before
    # 新索引与旧版本互不影响：原标识仍可独立查询
    assert client.get(f"/audit/causal-indexes/{c}").get_json()[
        "progress"]["total_nodes"] > total_before


def test_old_versions_still_queryable_by_original_index_id(client):
    a, b = two_indexes(client)
    register_immediate(client, a, "v1", "k1")
    register_immediate(client, b, "v2", "k2")
    # 两个旧版本各自按原索引标识可查，且内容就是冻结时的索引
    ra = client.get(f"/audit/causal-indexes/{a}").get_json()
    rb = client.get(f"/audit/causal-indexes/{b}").get_json()
    assert ra["status"] == rb["status"] == "completed"
    va = client.get("/audit/index-versions/v1/chain?limit=1000").get_json()
    vb = client.get("/audit/index-versions/v2/chain?limit=1000").get_json()
    assert va["total_nodes"] == ra["progress"]["total_nodes"]
    assert vb["total_nodes"] == rb["progress"]["total_nodes"]


def test_worker_activates_multiple_due_plans_and_reports_failures(client):
    a, b = two_indexes(client, resource="r1")
    c, _ = two_indexes(client, resource="r2")
    r_ok = register_scheduled(client, a, "v1", "k1").get_json()
    r_bad = register_scheduled(client, c, "v2", "k2").get_json()
    r_later = register_scheduled(client, b, "v3", "k3").get_json()
    # v2 的原索引在生效前被删除 -> 该计划失败，其余不受影响
    delete_index(client, c)
    past = now_ms(client) - 1
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id IN (?,?)",
                     (past, r_ok["release_id"], r_bad["release_id"]))
        conn.commit()
    n = rmgr(client).process_due()
    assert n == 2
    assert client.get(
        f"/audit/index-releases/{r_ok['release_id']}").get_json()[
        "status"] == "active"
    bad = client.get(
        f"/audit/index-releases/{r_bad['release_id']}").get_json()
    assert bad["status"] == "failed"
    assert bad["error_code"] == "release_index_deleted"
    # 未到期的计划原样保留
    assert client.get(
        f"/audit/index-releases/{r_later['release_id']}").get_json()[
        "status"] == "scheduled"
    # 再次扫描：没有可处理的计划
    assert rmgr(client).process_due() == 0


def test_immediate_registration_fails_inline_when_source_bad(client):
    """生效时间已到但原索引有问题：登记事务内同步得到 failed。"""
    a, _ = two_indexes(client)
    # 行摘要与冻结节点不一致（模拟备份只恢复了一半）
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE causal_indexes SET chain_digest=? "
                     "WHERE index_id=?", ("f" * 64, a))
        conn.commit()
    rv = register_immediate(client, a, "v1", "k")
    assert rv.status_code == 201
    j = rv.get_json()
    assert j["status"] == "failed"
    assert j["error_code"] == "release_index_tampered"
    assert j["activated_at_ms"] is None


def test_misc_404_and_bad_status_filter(client):
    assert client.get("/audit/index-releases/nope").status_code == 404
    assert client.post(
        "/audit/index-releases/nope/cancel").status_code == 404
    a, _ = two_indexes(client)
    register_immediate(client, a, "v1", "k")
    rv = client.get("/audit/index-releases?status=bogus")
    assert rv.status_code == 400


def test_resolve_errors_for_unknown_scheduled_cancelled(client):
    a, _ = two_indexes(client)
    assert client.get("/audit/index-versions/nope").status_code == 404
    view = register_scheduled(client, a, "v1", "k").get_json()
    rv = client.get("/audit/index-versions/v1")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "index_release_not_effective"
    client.post(f"/audit/index-releases/{view['release_id']}/cancel")
    rv = client.get("/audit/index-versions/v1")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "index_release_cancelled"


# ---------------------------------------------------------------------------
# 只读边界
# ---------------------------------------------------------------------------


def _snapshot_tables(client):
    tables = ["leases", "resources", "writes", "delegations", "transfers",
              "lease_events", "archives", "archive_events",
              "evidence_packages", "evidence_entries",
              "evidence_entry_contents", "causal_indexes",
              "causal_index_members", "causal_index_nodes",
              "causal_derivations", "causal_derivation_members",
              "causal_derivation_nodes"]
    out = {}
    store = store_of(client)
    with store._lock:
        conn = store._conn
        for t in tables:
            rows = conn.execute(
                f"SELECT * FROM {t} ORDER BY 1,2").fetchall()
            out[t] = json.dumps([dict(r) for r in rows], sort_keys=True,
                                default=str)
    return out


def test_release_lifecycle_never_modifies_sources(client):
    a, b = two_indexes(client)
    client.post(f"/audit/causal-indexes/{a}/verify")
    before = _snapshot_tables(client)

    v1 = register_immediate(client, a, "v1", "k1",
                            compare_with_index_id=b).get_json()
    v2 = register_scheduled(client, a, "v2", "k2").get_json()
    rid2 = v2["release_id"]
    # 触发 worker 空转、查询、取消与同键回放
    rmgr(client).process_due()
    client.get("/audit/index-releases")
    client.get(f"/audit/index-releases/{v1['release_id']}")
    client.get("/audit/index-versions/v1")
    client.get("/audit/index-versions/v1/chain?limit=10")
    client.get("/audit/index-versions/v1/download")
    client.post(f"/audit/index-releases/{rid2}/cancel")
    register(client, {"version": "v1", "index_id": a,
                      "idempotency_key": "k1",
                      "effective_at_ms": v1["effective_at_ms"],
                      "compare_with_index_id": b})
    assert _snapshot_tables(client) == before

    # 原索引/派生任务的核验标记与内容未被任何发布接口改动
    ia = client.get(f"/audit/causal-indexes/{a}").get_json()
    assert ia["verify_status"] == "verified"
    ib = client.get(f"/audit/causal-indexes/{b}").get_json()
    assert ib["verify_status"] == "unverified"
    # 租约/资源值照旧
    res = client.get("/resources/r1").get_json()
    assert res["value"] == "later-0"


def test_failed_activation_does_not_modify_index(client):
    a, _ = two_indexes(client)
    view = register_scheduled(client, a, "v1", "k").get_json()
    before = _snapshot_tables(client)
    tamper_index_payload(client, a)
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE index_releases SET effective_at_ms=? "
                     "WHERE release_id=?",
                     (now_ms(client) - 1, view["release_id"]))
        conn.commit()
    rmgr(client).process_due()
    # 失败只写发布行；除被测试手动篡改的节点载荷外，行级字段（核验标记等）
    # 没有被发布流程触碰
    with store_of(client)._lock:
        conn = store_of(client)._conn
        row = conn.execute(
            "SELECT verify_status, content_sha256 FROM causal_indexes "
            "WHERE index_id=?", (a,)).fetchone()
        assert row["verify_status"] == "unverified"
        assert row["content_sha256"]
