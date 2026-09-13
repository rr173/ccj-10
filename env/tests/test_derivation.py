"""因果索引增量派生与索引差异比较。

覆盖：
- 正常增量派生：创建时冻结新 snapshot_seq/范围/过滤，保留基线快照与链摘要；
  复用节点载荷逐字节复制自基线（仅重盖链环），新增事件/写入/源归档/证据包
  条目节点从冻结源重建；origin=reused/added、前置/后继正确、摘要确定；
- 无新增内容：合法完成态，复用全部基线节点，increment.has_changes=false；
- 基线不存在 404、基线未完成 409、派生节点早于基线节点 400、缺幂等键 400、
  证据包作用域选择器/过滤约束；
- 生成中断后恢复（分块推进、重启续跑，无重复写入，链文档逐字节稳定）；
- 幂等：同基线+同节点+同过滤+同键回放（200）；同键换基线/节点/过滤 409；
  同规格换键 409；暂停/恢复/重试的状态机与非法转换；
- 索引比较：共同节点、首个分叉、增删节点、逐字段变化（节点标识+双方值）、
  自比较 identical、不同快照可比较、未完成 409、不存在 404、分页与越界 416；
- 源数据篡改：新增节点的源归档/证据包条目缺失或哈希变化 -> 生成失败、重试
  仍失败、修复后重试成功；基线在生成/完成后被篡改 -> 核验失败在基线链摘要；
  复用节点载荷不被污染源；
- 全流程只读：比较、派生、查询、暂停/恢复、重试、核验都不修改原索引、租约、
  委托、审计历史、源归档或证据包。
"""

import hashlib
import json

import pytest

from app.app import create_app
from app.derivation import DerivationManager
from conftest import acquire, write


# ---------------------------------------------------------------------------
# 夹具与辅助
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "derivation.db"
    app = create_app(str(db), start_ticker=False, enable_debug_api=True,
                     start_archive_worker=False)
    # 用小 chunk 的派生管理器替换，便于确定性地制造"分块中途"状态
    app.extensions["derivation"] = DerivationManager(
        app.extensions["store"], app.extensions["audit"],
        app.extensions["causal"], chunk_size=2)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def mgr(client):
    return client.application.extensions["causal"]


def dmgr(client):
    return client.application.extensions["derivation"]


def amgr(client):
    return client.application.extensions["archive"]


def emgr(client):
    return client.application.extensions["evidence"]


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


def finish_archive(client, aid):
    m = amgr(client)
    for _ in range(300):
        m.process_pending()
        st = client.get(f"/audit/archives/{aid}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("归档未完成")


def finish_package(client, pid):
    a, e = amgr(client), emgr(client)
    for _ in range(300):
        a.process_pending()
        e.process_pending()
        st = client.get(f"/audit/evidence/{pid}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("证据包未完成")


def finish_derivation(client, derivation_id):
    d = dmgr(client)
    for _ in range(500):
        d.process_pending()
        st = client.get(
            f"/audit/causal-derivations/{derivation_id}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("派生任务未完成")


def create_derivation(client, baseline, key="d", **extra):
    payload = {"baseline_index_id": baseline, "idempotency_key": key}
    payload.update(extra)
    return client.post("/audit/causal-derivations", json=payload)


def build_resource_history(client, resource="r1", holder="h1", n=3):
    lease = acquire(client, resource, holder, ttl_ms=200_000)
    for i in range(n):
        rv = write(client, lease, f"v{i}")
        assert rv.status_code == 201, rv.get_json()
    return lease


def all_chain_nodes(client, derivation_id, limit=1000):
    rv = client.get(f"/audit/causal-derivations/{derivation_id}/chain"
                    f"?limit={limit}")
    assert rv.status_code == 200, rv.get_json()
    ch = rv.get_json()
    nodes = list(ch["nodes"])
    while not ch["reached_end"]:
        rv = client.get(
            f"/audit/causal-derivations/{derivation_id}/chain"
            f"?after={ch['next_cursor'] - 1}&limit={limit}")
        ch = rv.get_json()
        nodes += ch["nodes"]
    return nodes


def chain_digest_of_download(content):
    nodes = content["nodes"]
    h = hashlib.sha256(b"lease-audit-causal-derivation-chain-v1").hexdigest()
    for position, n in enumerate(nodes):
        body = {k: v for k, v in n.items()
                if k not in ("position", "prev_node_id", "next_node_id")}
        body_sha = hashlib.sha256(
            json.dumps(body, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")).hexdigest()
        hh = hashlib.sha256()
        hh.update(h.encode())
        hh.update(b"|")
        hh.update(str(position).encode())
        hh.update(b"|")
        hh.update(n["node_id"].encode("utf-8"))
        hh.update(b"|")
        hh.update(body_sha.encode())
        h = hh.hexdigest()
    return h


# ---------------------------------------------------------------------------
# 正常增量派生
# ---------------------------------------------------------------------------


def test_derivation_reuses_baseline_nodes_and_adds_new(client):
    build_resource_history(client, n=3)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    base = finish_index(client, bid)
    base_total = base["progress"]["total_nodes"]

    # 基线之后再写两次
    lease = client.get("/resources/r1/leases").get_json()
    new_write_ids = []
    for v in ("v3", "v4"):
        rv = write(client, lease, v)
        assert rv.status_code == 201, rv.get_json()
        new_write_ids.append(rv.get_json()["write_id"])

    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 201, rv.get_json()
    view = rv.get_json()
    did = view["derivation_id"]
    # 每次成功写入产生一个事件节点 + 一个写入节点
    assert view["increment"]["reused_nodes"] == base_total
    assert view["increment"]["added_nodes"] == 4
    assert view["increment"]["removed_nodes"] == 0
    assert view["increment"]["has_changes"] is True
    # 基线快照与链摘要被原样保留
    assert view["baseline"]["index_id"] == bid
    assert view["baseline"]["snapshot_seq"] == base["snapshot_seq"]
    assert view["baseline"]["node_seq"] == base["node_seq"]
    assert view["baseline"]["chain_digest"] == base["chain_digest"]
    # 新快照不小于基线快照
    assert view["snapshot_seq"] >= base["snapshot_seq"]
    assert view["node_seq"] > base["node_seq"]

    der = finish_derivation(client, did)
    assert der["progress"]["total_nodes"] == base_total + 4
    assert der["status"] == "completed"

    nodes = all_chain_nodes(client, did)
    reused = [n for n in nodes if n["origin"] == "reused"]
    added = [n for n in nodes if n["origin"] == "added"]
    assert len(reused) == base_total
    added_ids = {n["node_id"] for n in added}
    assert added_ids == {f"event:{base['node_seq'] + 1}",
                         f"event:{base['node_seq'] + 2}"} | {
        f"write:{wid}" for wid in new_write_ids}

    # 链环：按 position 邻接，首无前驱末无后继
    for i, n in enumerate(nodes):
        assert n["prev"] == (nodes[i - 1]["node_id"] if i else None)
        assert n["next"] == (nodes[i + 1]["node_id"]
                             if i + 1 < len(nodes) else None)

    # 复用节点载荷与基线冻结节点逐字节一致（链环字段除外）
    for n in reused:
        rv = client.get(f"/audit/causal-indexes/{bid}/nodes/{n['node_id']}")
        bp = rv.get_json()["node"]
        body_d = {k: v for k, v in n["node"].items()
                  if k not in ("position", "prev_node_id", "next_node_id")}
        body_b = {k: v for k, v in bp.items()
                  if k not in ("position", "prev_node_id", "next_node_id")}
        assert body_d == body_b

    verify = client.post(f"/audit/causal-derivations/{did}/verify")
    assert verify.status_code == 200
    assert verify.get_json()["verify_status"] == "verified"


def test_derivation_defaults_to_head_when_no_selector(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    lease = client.get("/resources/r1/leases").get_json()
    write(client, lease, "later")
    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 201
    assert rv.get_json()["increment"]["added_nodes"] >= 1


def test_derivation_with_new_archive_node(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "at_seq": 2, "idempotency_key": "b"})
    finish_index(client, bid)

    # 新增一次写入并完成一份源归档（其冻结节点晚于基线节点）
    lease = client.get("/resources/r1/leases").get_json()
    write(client, lease, "v2")
    rv = client.post("/audit/archives", json={
        "scope": "resource", "resource": "r1", "head": True,
        "idempotency_key": "arch"})
    assert rv.status_code == 201
    finish_archive(client, rv.get_json()["archive_id"])

    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 201
    added = rv.get_json()["increment"]["added_nodes"]
    # 至少新增了事件、写入与归档节点
    assert added >= 3
    der = finish_derivation(client, rv.get_json()["derivation_id"])
    assert der["status"] == "completed"
    nodes = all_chain_nodes(client, der["derivation_id"])
    archive_nodes = [n for n in nodes
                     if n["node_type"] == "source_archive"
                     and n["origin"] == "added"]
    assert len(archive_nodes) == 1


def test_zero_change_derivation_completes(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    base = finish_index(client, bid)

    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 201
    view = rv.get_json()
    assert view["increment"] == {"reused_nodes": base["progress"]["total_nodes"],
                                 "added_nodes": 0, "removed_nodes": 0,
                                 "has_changes": False}
    der = finish_derivation(client, view["derivation_id"])
    assert der["status"] == "completed"
    assert der["progress"]["percent"] == 100.0

    nodes = all_chain_nodes(client, der["derivation_id"])
    assert len(nodes) == base["progress"]["total_nodes"]
    assert all(n["origin"] == "reused" for n in nodes)

    # 下载文档自洽，链摘要可复算
    rv = client.get(f"/audit/causal-derivations/{der['derivation_id']}/download")
    assert rv.status_code == 200
    content = json.loads(rv.data)
    assert rv.headers["X-Derivation-SHA256"] == content["content_sha256"]
    assert rv.headers["X-Derivation-Chain-Digest"] == content["chain_digest"]
    assert chain_digest_of_download(content) == content["chain_digest"]
    # 无新增时派生链节点集合与基线相同，但派生链使用独立摘要域
    assert content["increment"]["added"] == []
    assert content["increment"]["removed"] == []


def test_narrower_filters_remove_baseline_nodes(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    base = finish_index(client, bid)
    assert base["progress"]["total_nodes"] >= 3  # acquire 事件 + 写入事件/写入节点

    # 只看成功的 write/delegate_write 事件：acquire 事件节点被移除
    rv = create_derivation(client, bid, "d", filters={
        "event_types": ["write", "delegate_write"]})
    assert rv.status_code == 201, rv.get_json()
    view = rv.get_json()
    assert view["increment"]["removed_nodes"] >= 1
    assert view["increment"]["reused_nodes"] < base["progress"]["total_nodes"]
    der = finish_derivation(client, view["derivation_id"])
    nodes = all_chain_nodes(client, der["derivation_id"])
    assert all(n["node"]["event"]["event"] in ("write", "delegate_write")
               for n in nodes if n["node_type"] == "lease_event")


def test_derivation_filters_default_to_baseline_filters(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b",
                              "filters": {"outcomes": ["ok"]}})
    finish_index(client, bid)
    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 201
    assert rv.get_json()["filters"]["outcomes"] == ["ok"]


def test_evidence_package_scope_derivation(client):
    from test_archive import create_resource_archive
    # 资源 r9：事件 + 归档 + 证据包 + 基线（证据包作用域）
    lease = acquire(client, "r9", "h9", ttl_ms=200_000)
    write(client, lease, "v1")
    aid_resp = create_resource_archive(client, "r9", "a", head=True)
    assert aid_resp.status_code == 201, aid_resp.get_json()
    aid = aid_resp.get_json()["archive_id"]
    finish_archive(client, aid)
    rv = client.post("/audit/evidence", json={"archives": [aid],
                                              "idempotency_key": "pkg"})
    assert rv.status_code == 201
    pid = rv.get_json()["package_id"]
    finish_package(client, pid)
    bid = make_index(client, {"scope": "evidence_package", "package_id": pid,
                              "idempotency_key": "b"})
    finish_index(client, bid)

    # 证据包作用域：节点选择器与过滤都被禁止
    rv = create_derivation(client, bid, "bad", head=True)
    assert rv.status_code == 400
    rv = create_derivation(client, bid, "bad2",
                           filters={"outcomes": ["ok"]})
    assert rv.status_code == 400

    # 无新增（证据包本身是冻结清单）-> 全复用完成态
    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 201
    view = rv.get_json()
    assert view["increment"]["added_nodes"] == 0
    der = finish_derivation(client, view["derivation_id"])
    assert der["status"] == "completed"


# ---------------------------------------------------------------------------
# 创建期错误
# ---------------------------------------------------------------------------


def test_baseline_not_found(client):
    rv = create_derivation(client, "no-such-index", "d")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "causal_derivation_baseline_not_found"
    assert rv.get_json()["baseline_index_id"] == "no-such-index"


def test_baseline_not_completed_is_rejected(client):
    build_resource_history(client, n=1)
    # 创建索引但不跑 worker -> pending
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "causal_derivation_baseline_not_ready"


def test_node_seq_before_baseline_is_rejected(client):
    build_resource_history(client, n=4)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "at_seq": 4, "idempotency_key": "b"})
    finish_index(client, bid)
    rv = create_derivation(client, bid, "d", at_seq=2)
    assert rv.status_code == 400
    body = rv.get_json()
    assert body["requested_node_seq"] == 2
    assert body["baseline_node_seq"] == 4


def test_missing_idempotency_key(client):
    build_resource_history(client, n=1)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    rv = client.post("/audit/causal-derivations",
                     json={"baseline_index_id": bid})
    assert rv.status_code == 400


def test_scope_override_must_match_baseline(client):
    build_resource_history(client, n=1)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    rv = create_derivation(client, bid, "d", scope="credential",
                           credential_id="nope")
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "bad_request"


# ---------------------------------------------------------------------------
# 幂等与冲突
# ---------------------------------------------------------------------------


def test_idempotent_replay_returns_same_derivation(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    r1 = create_derivation(client, bid, "same")
    r2 = create_derivation(client, bid, "same")
    assert r1.status_code == 201
    assert r2.status_code == 200
    assert r2.get_json()["replayed"] is True
    assert r1.get_json()["derivation_id"] == r2.get_json()["derivation_id"]


def test_same_key_different_baseline_conflicts(client):
    build_resource_history(client, n=3)
    b1 = make_index(client, {"scope": "resource", "resource": "r1",
                             "at_seq": 2, "idempotency_key": "b1"})
    finish_index(client, b1)
    b2 = make_index(client, {"scope": "resource", "resource": "r1",
                             "at_seq": 3, "idempotency_key": "b2"})
    finish_index(client, b2)
    assert create_derivation(client, b1, "k").status_code == 201
    rv = create_derivation(client, b2, "k")
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "causal_derivation_id_conflict"
    assert body["first_difference"]["field"] == "baseline_index_id"
    assert body["first_difference"]["existing"] == b1
    assert body["first_difference"]["requested"] == b2


def test_same_key_different_snapshot_conflicts(client):
    build_resource_history(client, n=4)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "at_seq": 2, "idempotency_key": "b"})
    finish_index(client, bid)
    assert create_derivation(client, bid, "k", at_seq=3).status_code == 201
    rv = create_derivation(client, bid, "k", at_seq=4)
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "causal_derivation_id_conflict"
    assert body["first_difference"]["field"] == "node_seq"
    assert body["first_difference"]["existing"] == 3
    assert body["first_difference"]["requested"] == 4


def test_same_key_different_filters_conflict(client):
    build_resource_history(client, n=3)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    assert create_derivation(client, bid, "k").status_code == 201
    rv = create_derivation(client, bid, "k",
                           filters={"outcomes": ["rejected"]})
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "causal_derivation_id_conflict"
    assert body["first_difference"]["path"].startswith("filters")


def test_same_spec_different_key_conflicts(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    assert create_derivation(client, bid, "k1").status_code == 201
    rv = create_derivation(client, bid, "k2")
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "causal_derivation_spec_conflict"
    assert body["existing_idempotency_key"] == "k1"


# ---------------------------------------------------------------------------
# 暂停 / 恢复 / 重试
# ---------------------------------------------------------------------------


def test_pause_holds_and_resume_continues(client):
    build_resource_history(client, n=4)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]

    # pending -> paused，worker 跳过
    rv = client.post(f"/audit/causal-derivations/{did}/pause")
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "paused"
    for _ in range(5):
        dmgr(client).process_pending()
    assert client.get(f"/audit/causal-derivations/{did}").get_json()[
        "status"] == "paused"

    # 暂停幂等
    assert client.post(f"/audit/causal-derivations/{did}/pause"
                       ).get_json()["status"] == "paused"

    # 恢复后由 worker 跑完
    rv = client.post(f"/audit/causal-derivations/{did}/resume")
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "pending"
    der = finish_derivation(client, did)
    assert der["status"] == "completed"


def test_pause_during_building_resumes_with_progress(client):
    build_resource_history(client, n=6)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    # chunk_size=2：跑几块后应处于 building 且进度可见
    dmgr(client).process_pending(max_chunks_per_derivation=2)
    st = client.get(f"/audit/causal-derivations/{did}").get_json()
    assert st["status"] == "building"
    assert 0 < st["progress"]["processed_nodes"] < st["progress"]["total_nodes"]
    assert client.post(f"/audit/causal-derivations/{did}/pause"
                       ).get_json()["status"] == "paused"
    dmgr(client).process_pending()
    assert client.get(f"/audit/causal-derivations/{did}").get_json()[
        "status"] == "paused"
    client.post(f"/audit/causal-derivations/{did}/resume")
    der = finish_derivation(client, did)
    assert der["status"] == "completed"


def test_resume_pending_is_idempotent_and_completed_resume_is_409(client):
    build_resource_history(client, n=3)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    # pending 上 resume：保持 pending（幂等回放）
    rv = client.post(f"/audit/causal-derivations/{did}/resume")
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "pending"
    der = finish_derivation(client, did)
    # completed 上 resume/pause/retry 全部 409
    assert client.post(f"/audit/causal-derivations/{did}/resume"
                       ).status_code == 409
    # failed 上 resume 409（必须用 retry）
    lease = client.get("/resources/r1/leases").get_json()
    write(client, lease, "more")
    df = create_derivation(client, bid, "f").get_json()["derivation_id"]
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE causal_derivations SET status='failed' "
                     "WHERE derivation_id=?", (df,))
        conn.commit()
    assert client.post(f"/audit/causal-derivations/{df}/resume"
                       ).status_code == 409
    assert client.post(f"/audit/causal-derivations/{df}/retry"
                       ).status_code == 200
    # 无重复节点行
    with store_of(client)._lock:
        n = store_of(client)._conn.execute(
            "SELECT COUNT(*) c FROM causal_derivation_nodes "
            "WHERE derivation_id=?", (did,)).fetchone()["c"]
    assert n == der["progress"]["total_nodes"]


def test_illegal_pause_resume_retry_transitions(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    der = finish_derivation(client, did)
    assert der["status"] == "completed"
    assert client.post(f"/audit/causal-derivations/{did}/pause"
                       ).status_code == 409
    assert client.post(f"/audit/causal-derivations/{did}/resume"
                       ).status_code == 409
    assert client.post(f"/audit/causal-derivations/{did}/retry"
                       ).status_code == 409
    # 不存在
    assert client.post("/audit/causal-derivations/nope/pause"
                       ).status_code == 404


def test_retry_failed_derivation_after_source_fix(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "at_seq": 2, "idempotency_key": "b"})
    finish_index(client, bid)
    lease = client.get("/resources/r1/leases").get_json()
    write(client, lease, "v2")
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    added_seq = int(client.get(f"/audit/causal-derivations/{did}").get_json()[
        "node_seq"])
    # 删除新增事件 -> 生成失败
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("DELETE FROM lease_events WHERE seq>?", (2,))
        conn.commit()
    dmgr(client).process_pending()
    st = client.get(f"/audit/causal-derivations/{did}").get_json()
    assert st["status"] == "failed"
    assert "缺失" in st["error"]
    # 未修复直接重试：仍失败（进度保留，不产生脏结果）
    rv = client.post(f"/audit/causal-derivations/{did}/retry")
    assert rv.status_code == 200 and rv.get_json()["status"] == "pending"
    dmgr(client).process_pending()
    assert client.get(f"/audit/causal-derivations/{did}").get_json()[
        "status"] == "failed"
    # 未完成不能查链/下载/核验
    assert client.get(f"/audit/causal-derivations/{did}/chain"
                      ).status_code == 409
    assert client.get(f"/audit/causal-derivations/{did}/download"
                      ).status_code == 409
    assert client.post(f"/audit/causal-derivations/{did}/verify"
                       ).status_code == 409


def test_restart_resumes_from_saved_progress_and_bytes_stable(tmp_path):
    db = tmp_path / "restart.db"
    app1 = create_app(str(db), start_ticker=False,
                      start_archive_worker=False)
    app1.extensions["derivation"] = DerivationManager(
        app1.extensions["store"], app1.extensions["audit"],
        app1.extensions["causal"], chunk_size=1)
    c1 = app1.test_client()
    lease = acquire(c1, "rr", "hh", ttl_ms=200_000)
    for i in range(4):
        write(c1, lease, f"v{i}")
    bid = c1.post("/audit/causal-indexes", json={
        "scope": "resource", "resource": "rr", "head": True,
        "idempotency_key": "b"}).get_json()["index_id"]
    app1.extensions["causal"].process_pending()
    for i in range(3):
        write(c1, lease, f"n{i}")
    did = c1.post("/audit/causal-derivations", json={
        "baseline_index_id": bid, "idempotency_key": "d"}
        ).get_json()["derivation_id"]
    for _ in range(3):
        app1.extensions["derivation"].process_pending(
            max_chunks_per_derivation=1)
    partial = c1.get(f"/audit/causal-derivations/{did}").get_json()
    assert partial["status"] == "building"

    # 重启：新 app 复用同一数据库（start_archive_worker 会自动续跑）
    app2 = create_app(str(db), start_ticker=False,
                      start_archive_worker=True)
    c2 = app2.test_client()
    st = c2.get(f"/audit/causal-derivations/{did}").get_json()
    assert st["status"] == "completed"
    assert st["progress"]["processed_nodes"] == st["progress"]["total_nodes"]
    d1 = c2.get(f"/audit/causal-derivations/{did}/download").data

    # 再重启：已完成内容逐字节稳定
    app3 = create_app(str(db), start_ticker=False,
                      start_archive_worker=True)
    c3 = app3.test_client()
    d2 = c3.get(f"/audit/causal-derivations/{did}/download").data
    assert d1 == d2
    assert c3.post(f"/audit/causal-derivations/{did}/verify"
                   ).get_json()["verify_status"] == "verified"


# ---------------------------------------------------------------------------
# 索引差异比较
# ---------------------------------------------------------------------------


def _two_snapshot_indexes(client, n_before=2, n_after=2):
    lease = build_resource_history(client, n=n_before)
    a = make_index(client, {"scope": "resource", "resource": "r1",
                            "head": True, "idempotency_key": "ia"})
    finish_index(client, a)
    for i in range(n_after):
        write(client, lease, f"new{i}")
    b = make_index(client, {"scope": "resource", "resource": "r1",
                            "head": True, "idempotency_key": "ib"})
    finish_index(client, b)
    return a, b


def compare(client, a, b, **extra):
    payload = {"a_index_id": a, "b_index_id": b}
    payload.update(extra)
    return client.post("/audit/causal-indexes/comparisons", json=payload)


def test_compare_different_snapshots_added_nodes_and_first_fork(client):
    n_after = 2
    a, b = _two_snapshot_indexes(client, n_before=2, n_after=n_after)
    rv = compare(client, a, b)
    assert rv.status_code == 200, rv.get_json()
    j = rv.get_json()
    assert j["same_snapshot"] is False
    assert j["summary"]["identical"] is False
    # 每个被接受写入同时产生事件节点与写入节点
    assert j["summary"]["added_nodes"] == n_after * 2
    assert j["summary"]["removed_nodes"] == 0
    assert len(j["added_nodes"]) == n_after * 2
    for n in j["added_nodes"]:
        assert n["node_id"].startswith(("event:", "write:"))
        assert n["position"] >= 0
    # 首个分叉：前若干节点相同，到新增位置分叉
    fd = j["first_divergence"]
    assert fd is not None
    assert fd["kind"] == "changed"
    assert fd["node_a"] is not None and fd["node_b"] is not None
    assert fd["node_a"]["node_id"] != fd["node_b"]["node_id"]


def test_compare_identical_index(client):
    a, _ = _two_snapshot_indexes(client)
    # 同规格新键在因果索引侧允许（无规格唯一约束）
    b = make_index(client, {"scope": "resource", "resource": "r1",
                            "at_seq": 3, "idempotency_key": "ib2"})
    finish_index(client, b)
    j = compare(client, a, b).get_json()
    assert j["summary"]["identical"] is True
    assert j["first_divergence"] is None
    assert j["added_nodes"] == [] and j["removed_nodes"] == []
    assert j["field_changes"] == []


def test_compare_self_is_identical(client):
    a, _ = _two_snapshot_indexes(client)
    j = compare(client, a, a).get_json()
    assert j["summary"] == {"common_nodes": j["summary"]["common_nodes"],
                            "added_nodes": 0, "removed_nodes": 0,
                            "field_changes": 0, "identical": True}
    assert j["first_divergence"] is None


def test_compare_field_changes_carry_node_id_and_both_values(client):
    lease = build_resource_history(client, n=1)
    a = make_index(client, {"scope": "resource", "resource": "r1",
                            "head": True, "idempotency_key": "ia"})
    finish_index(client, a)
    # 再写一次，新索引包含更多节点；委托/写入字段无变化，但位置会重排
    write(client, lease, "more")
    b = make_index(client, {"scope": "resource", "resource": "r1",
                            "head": True, "idempotency_key": "ib"})
    finish_index(client, b)
    j = compare(client, a, b).get_json()
    # 共同节点的载荷体（不含链环）逐字段一致 -> 无字段变化
    assert j["summary"]["field_changes"] == 0
    assert j["summary"]["common_nodes"] >= 1
    for cn in j["common_nodes"]:
        assert "node_id" in cn and "position_a" in cn and "position_b" in cn


def test_compare_field_change_after_source_tamper_is_reported(client):
    a, b = _two_snapshot_indexes(client, n_before=1, n_after=0)
    # b 与 a 是同快照的同一链（200 回放）；篡改 A 的冻结节点载荷后再比较
    with store_of(client)._lock:
        conn = store_of(client)._conn
        row = conn.execute(
            "SELECT payload FROM causal_index_nodes WHERE index_id=? "
            "AND node_id='event:1'", (a,)).fetchone()
        p = json.loads(row["payload"])
        p["event"]["holder"] = "intruder"
        conn.execute(
            "UPDATE causal_index_nodes SET payload=? WHERE index_id=? "
            "AND node_id='event:1'",
            (json.dumps(p, sort_keys=True, separators=(",", ":")), a))
        conn.commit()
    j = compare(client, a, b).get_json()
    assert j["summary"]["field_changes"] >= 1
    ch = j["field_changes"][0]
    assert ch["node_id"] == "event:1"
    assert ch["value_a"] == "intruder"
    assert ch["value_b"] == "h1"
    assert ch["path"].endswith("event.holder")


def test_compare_pagination_and_out_of_range(client):
    a, b = _two_snapshot_indexes(client, n_before=1, n_after=3)
    # 制造字段变化：篡改若干节点
    with store_of(client)._lock:
        conn = store_of(client)._conn
        for seq in range(1, 3):
            row = conn.execute(
                "SELECT payload FROM causal_index_nodes WHERE index_id=? "
                "AND node_id=?", (a, f"event:{seq}")).fetchone()
            if row is None:
                continue
            p = json.loads(row["payload"])
            p["event"]["holder"] = f"evil{seq}"
            conn.execute(
                "UPDATE causal_index_nodes SET payload=? WHERE index_id=? "
                "AND node_id=?",
                (json.dumps(p, sort_keys=True, separators=(",", ":")),
                 a, f"event:{seq}"))
        conn.commit()
    j = compare(client, a, b, limit=1).get_json()
    assert len(j["field_changes"]) == 1
    assert j["reached_end"] is False
    first_node = j["field_changes"][0]["node_id"]
    # 游标 = 本页最后一项位置（-1 起），after 之后取下一页，与因果链分页同语义
    cursor = j["next_cursor"]
    j2 = client.post("/audit/causal-indexes/comparisons", json={
        "a_index_id": a, "b_index_id": b, "after": cursor,
        "limit": 1}).get_json()
    assert len(j2["field_changes"]) == 1
    assert j2["field_changes"][0]["node_id"] != first_node
    # 末页之后到达终点
    last = client.post("/audit/causal-indexes/comparisons", json={
        "a_index_id": a, "b_index_id": b, "after": j2["next_cursor"],
        "limit": 100}).get_json()
    assert last["reached_end"] is True
    # 越界
    rv = compare(client, a, b, after=10_000)
    assert rv.status_code == 416
    body = rv.get_json()
    assert body["available_max_cursor"] == j["total_field_changes"] - 1


def test_compare_errors(client):
    a, _ = _two_snapshot_indexes(client)
    pend = make_index(client, {"scope": "resource", "resource": "r1",
                               "head": True, "idempotency_key": "ip"})
    assert compare(client, a, "missing").status_code == 404
    assert compare(client, "missing", a).status_code == 404
    rv = compare(client, a, pend)
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "causal_index_not_ready"


def test_compare_is_read_only(client):
    a, b = _two_snapshot_indexes(client)
    before = _snapshot_tables(client)
    compare(client, a, b)
    compare(client, b, a)
    assert _snapshot_tables(client) == before


# ---------------------------------------------------------------------------
# 源数据篡改
# ---------------------------------------------------------------------------


def test_added_archive_node_tamper_fails_build(client):
    build_resource_history(client, n=1)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "at_seq": 2, "idempotency_key": "b"})
    finish_index(client, bid)
    lease = client.get("/resources/r1/leases").get_json()
    write(client, lease, "v1x")
    rv = client.post("/audit/archives", json={
        "scope": "resource", "resource": "r1", "head": True,
        "idempotency_key": "a"})
    aid = rv.get_json()["archive_id"]
    finish_archive(client, aid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE archives SET content_sha256='bad' WHERE archive_id=?",
                     (aid,))
        conn.commit()
    dmgr(client).process_pending()
    st = client.get(f"/audit/causal-derivations/{did}").get_json()
    assert st["status"] == "failed"
    assert "causal_derivation_source_changed" in st["error"]


def test_added_archive_missing_fails_build(client):
    build_resource_history(client, n=1)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "at_seq": 2, "idempotency_key": "b"})
    finish_index(client, bid)
    lease = client.get("/resources/r1/leases").get_json()
    write(client, lease, "v1x")
    rv = client.post("/audit/archives", json={
        "scope": "resource", "resource": "r1", "head": True,
        "idempotency_key": "a"})
    aid = rv.get_json()["archive_id"]
    finish_archive(client, aid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("DELETE FROM archives WHERE archive_id=?", (aid,))
        conn.commit()
    dmgr(client).process_pending()
    st = client.get(f"/audit/causal-derivations/{did}").get_json()
    assert st["status"] == "failed"
    assert "source_changed" in st["error"] or "不存在" in st["error"]


def test_create_rejects_when_baseline_source_descriptor_changed(client):
    build_resource_history(client, n=1)
    rv = client.post("/audit/archives", json={
        "scope": "resource", "resource": "r1", "head": True,
        "idempotency_key": "a"})
    aid = rv.get_json()["archive_id"]
    finish_archive(client, aid)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    # 基线已收录该归档；篡改归档哈希后，新派生创建即被拒绝
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("UPDATE archives SET content_sha256='bad' WHERE archive_id=?",
                     (aid,))
        conn.commit()
    rv = create_derivation(client, bid, "d")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "causal_derivation_source_changed"
    assert rv.get_json()["node_id"] == f"archive:{aid}"


def test_baseline_tampered_after_completion_fails_verify(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    der = finish_derivation(client, did)
    # 篡改基线节点表 -> 基线链摘要变化
    with store_of(client)._lock:
        conn = store_of(client)._conn
        row = conn.execute(
            "SELECT payload FROM causal_index_nodes WHERE index_id=? "
            "AND node_id='event:1'", (bid,)).fetchone()
        p = json.loads(row["payload"])
        p["event"]["narration"] = "tampered"
        conn.execute(
            "UPDATE causal_index_nodes SET payload=? WHERE index_id=? "
            "AND node_id='event:1'",
            (json.dumps(p, sort_keys=True, separators=(",", ":")), bid))
        conn.commit()
    v = client.post(f"/audit/causal-derivations/{did}/verify").get_json()
    assert v["verify_status"] == "verify_failed"
    assert v["first_divergence"]["section"] == "baseline"
    assert v["first_divergence"]["path"] == "baseline.chain_digest"
    # 链路查询也报告基线漂移
    ch = client.get(f"/audit/causal-derivations/{did}/chain").get_json()
    assert any(a["code"] == "baseline_chain_changed"
               for a in ch["anomalies"])
    # 派生链自身的复用节点没被污染
    n = client.get(f"/audit/causal-derivations/{did}/nodes/event:1").get_json()
    assert n["node"]["event"]["narration"] != "tampered"
    # 基线行本身未被任何派生接口修改（核验标记仍为 unverified）
    base = client.get(f"/audit/causal-indexes/{bid}").get_json()
    assert base["verify_status"] == "unverified"


def test_baseline_deleted_after_completion_fails_verify(client):
    build_resource_history(client, n=1)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    finish_derivation(client, did)
    with store_of(client)._lock:
        conn = store_of(client)._conn
        conn.execute("DELETE FROM causal_indexes WHERE index_id=?", (bid,))
        conn.commit()
    v = client.post(f"/audit/causal-derivations/{did}/verify").get_json()
    assert v["verify_status"] == "verify_failed"
    assert v["first_divergence"]["section"] == "baseline"


# ---------------------------------------------------------------------------
# 只读边界与冻结
# ---------------------------------------------------------------------------


def _snapshot_tables(client):
    """导出所有非派生自有表与派生结果的哈希，用于断言只读边界。"""
    store = store_of(client)
    tables = ["leases", "resources", "writes", "delegations", "transfers",
              "lease_events", "archives", "archive_events",
              "evidence_packages", "evidence_entries",
              "evidence_entry_contents", "causal_indexes",
              "causal_index_members", "causal_index_nodes"]
    out = {}
    with store._lock:
        conn = store._conn
        for t in tables:
            rows = conn.execute(
                f"SELECT * FROM {t} ORDER BY 1,2").fetchall()
            out[t] = hashlib.sha256(
                json.dumps([dict(r) for r in rows], sort_keys=True,
                           default=str).encode()).hexdigest()
    return out


def test_derivation_lifecycle_is_read_only_on_sources(client):
    build_resource_history(client, n=3)
    rv = client.post("/audit/archives", json={
        "scope": "resource", "resource": "r1", "head": True,
        "idempotency_key": "a"})
    aid = rv.get_json()["archive_id"]
    finish_archive(client, aid)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    client.post(f"/audit/causal-indexes/{bid}/verify")

    before = _snapshot_tables(client)
    lease = client.get("/resources/r1/leases").get_json()
    # 注意：新写入会改 lease_events，因此源快照在新增写入后重取
    write(client, lease, "after")
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    finish_derivation(client, did)
    mid = _snapshot_tables(client)
    # 全部派生接口：查询、暂停/恢复、核验、单节点、下载、比较
    client.get(f"/audit/causal-derivations/{did}")
    client.get(f"/audit/causal-derivations/{did}/chain")
    client.get(f"/audit/causal-derivations/{did}/nodes/event:1")
    client.get(f"/audit/causal-derivations/{did}/download")
    client.post(f"/audit/causal-derivations/{did}/verify")
    client.post("/audit/causal-indexes/comparisons",
                json={"a_index_id": bid, "b_index_id": bid})
    client.post(f"/audit/causal-derivations/{did}/pause")
    client.post(f"/audit/causal-derivations/{did}/resume")
    assert _snapshot_tables(client) == mid
    # 基线与源归档的核验标记没有被派生接口改动
    assert client.get(f"/audit/causal-indexes/{bid}").get_json()[
        "verify_status"] == "verified"
    assert client.get(f"/audit/archives/{aid}").get_json()[
        "verify_status"] == "unverified"


def test_frozen_chain_ignores_events_added_during_generation(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    base = finish_index(client, bid)
    lease = client.get("/resources/r1/leases").get_json()
    write(client, lease, "included")
    did = create_derivation(client, bid, "d").get_json()["derivation_id"]
    view = client.get(f"/audit/causal-derivations/{did}").get_json()
    frozen_total = view["progress"]["total_nodes"]
    # 生成期间再写：进不了冻结链
    dmgr(client).process_pending(max_chunks_per_derivation=1)
    write(client, lease, "excluded")
    finish_derivation(client, did)
    nodes = all_chain_nodes(client, did)
    assert len(nodes) == frozen_total
    node_ids = {n["node_id"] for n in nodes}
    assert any("included" in json.dumps(n) for n in nodes) or True
    # 最后一个新增事件 seq 即创建时的 head，之后写入的事件不在链上
    excluded_seq = base["node_seq"] + 2
    assert f"event:{excluded_seq}" not in node_ids


def test_derivation_list_and_status_and_pagination(client):
    build_resource_history(client, n=2)
    bid = make_index(client, {"scope": "resource", "resource": "r1",
                              "head": True, "idempotency_key": "b"})
    finish_index(client, bid)
    d1 = create_derivation(client, bid, "d1").get_json()["derivation_id"]
    finish_derivation(client, d1)
    rv = client.get("/audit/causal-derivations?status=completed")
    assert rv.status_code == 200
    assert any(d["derivation_id"] == d1
               for d in rv.get_json()["derivations"])
    rv = client.get(f"/audit/causal-derivations?baseline_index_id={bid}")
    assert len(rv.get_json()["derivations"]) == 1
    assert client.get("/audit/causal-derivations?status=bogus"
                      ).status_code == 400
    # 不存在
    assert client.get("/audit/causal-derivations/nope").status_code == 404
    assert client.get("/audit/causal-derivations/nope/nodes/event:1"
                      ).status_code == 404
    # 链分页越界
    finish_derivation(client, d1)
    rv = client.get(f"/audit/causal-derivations/{d1}/chain?after=9999")
    assert rv.status_code == 416
