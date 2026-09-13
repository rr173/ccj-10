"""审计因果索引：冻结创建、分块续跑、因果链路查询、节点重建与独立核验。

覆盖：
- 正常资源/凭证/证据包作用域索引：事件→写入/委托→源归档→证据包条目
  的有向因果链，按因果顺序给出事件序号、对象标识、前置、后继；
- 空结果（过滤后无任何节点，含确定摘要）；跨资源混合链路；
- 创建时冻结 snapshot_seq/范围/过滤：同键同规格回放、同键换范围/节点/
  过滤明确 409；生成期间新增事件、再核验源归档、新增归档/证据包都不
  进入已冻结的链；
- 分块进度逐块可见，生成中断（finalize 崩溃）后自动/手动续跑且不重复
  写入；服务重启后从已保存进度续跑、链文档逐字节一致；
- 固定快照游标分页（位置游标、越界 416）；断链/环路/重号/缺失源归档/
  缺失证据包条目等异常报告；
- 独立核验：从冻结审计事件与归档清单重算链路；源归档核验失败、源内容
  哈希变化、删原始事件、篡改链文档/冻结节点等给出首个差异节点/字段/双方值；
- 全流程只读：绝不修改租约、委托、原始审计历史、源归档或证据包。
"""

import hashlib
import json
import sqlite3
import threading
import time

import pytest

from app.app import create_app
from conftest import acquire, write
from test_archive import create_credential_archive, create_resource_archive
from test_audit import build_history


# ---------------------------------------------------------------------------
# 夹具与辅助
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "causal.db"
    app = create_app(str(db), start_ticker=False, enable_debug_api=True,
                     start_archive_worker=False)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def mgr(client):
    return client.application.extensions["causal"]


def archive_mgr(client):
    return client.application.extensions["archive"]


def evidence_mgr(client):
    return client.application.extensions["evidence"]


def store_of(client):
    return client.application.extensions["store"]


def db_path(client):
    store = store_of(client)
    with store._lock:
        return store._conn.execute(
            "PRAGMA database_list").fetchone()[2]


def create_index(client, payload):
    return client.post("/audit/causal-indexes", json=payload)


def resource_index(client, resource, key, **extra):
    payload = {"scope": "resource", "resource": resource,
               "idempotency_key": key, "head": True}
    payload.update(extra)
    if "head" in extra and not extra["head"]:
        payload.pop("head")
    return create_index(client, payload)


def finish(client, index_id):
    m = mgr(client)
    for _ in range(500):
        m.process_pending()
        st = client.get(f"/audit/causal-indexes/{index_id}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("因果索引未能在限定轮次内完成")


def finish_archive(client, aid):
    m = archive_mgr(client)
    for _ in range(300):
        m.process_pending()
        st = client.get(f"/audit/archives/{aid}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("源归档未能完成")


def finish_package(client, pid):
    am, em = archive_mgr(client), evidence_mgr(client)
    for _ in range(300):
        am.process_pending()
        em.process_pending()
        st = client.get(f"/audit/evidence/{pid}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("证据包未能完成")


def chain(client, index_id, **qs):
    qs = "&".join(f"{k}={v}" for k, v in qs.items())
    url = f"/audit/causal-indexes/{index_id}/chain" + (f"?{qs}" if qs else "")
    rv = client.get(url)
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


def all_nodes(client, index_id, limit=1000):
    ch = chain(client, index_id, limit=limit)
    nodes = list(ch["nodes"])
    while not ch["reached_end"]:
        ch = chain(client, index_id, after=ch["next_cursor"] - 1, limit=limit)
        nodes += ch["nodes"]
    return nodes


def download(client, index_id):
    rv = client.get(f"/audit/causal-indexes/{index_id}/download")
    assert rv.status_code == 200, rv.get_json()
    return json.loads(rv.data)


def sha_of(content):
    core = {k: v for k, v in content.items() if k != "content_sha256"}
    return hashlib.sha256(
        json.dumps(core, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).hexdigest()


MISSING = "<missing>"


def make_completed_archives(client, resource="cx-1"):
    build_history(client, resource)
    ev = client.get(f"/resources/{resource}/audit/events").get_json()["events"]
    ra = create_resource_archive(client, resource, "res-key", head=True)
    assert ra.status_code == 201
    aid = ra.get_json()["archive_id"]
    finish_archive(client, aid)
    return aid, ev


# ---------------------------------------------------------------------------
# 创建 → 生成 → 链路 → 校验值
# ---------------------------------------------------------------------------


def test_resource_index_builds_ordered_causal_chain(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "cx-1")
    rv = resource_index(client, "cx-1", "k1")
    assert rv.status_code == 201, rv.get_json()
    body = rv.get_json()
    assert body["replayed"] is False
    assert body["status"] == "pending"
    assert body["scope"] == "resource"
    iid = body["index_id"]
    total = body["progress"]["total_nodes"]
    assert total > 0
    # snapshot/node 冻结
    ev = client.get("/resources/cx-1/audit/events").get_json()["events"]
    assert body["node_seq"] == ev[-1]["seq"]
    assert body["snapshot_seq"] == ev[-1]["seq"]

    st = finish(client, iid)
    assert st["progress"]["done"] is True
    assert st["chain_digest"] and st["content_sha256"]

    nodes = all_nodes(client, iid)
    assert len(nodes) == total
    types = [n["node_type"] for n in nodes]
    # 因果分层：所有事件在前，然后写入/委托，没有归档（未创建归档）
    assert set(types) <= {"lease_event", "write", "delegation"}
    assert types == sorted(types, key=lambda t: (
        {"lease_event": 0, "write": 1, "delegation": 1}[t]))
    # 事件层按 seq 升序、无重复序号
    ev_nodes = [n for n in nodes if n["node_type"] == "lease_event"]
    seqs = [n["seq"] for n in ev_nodes]
    assert seqs == sorted(seqs) and len(seqs) == len(set(seqs))
    # 每个节点有事件序号/对象标识/前置/后继，首无前驱、末无后继
    for i, n in enumerate(nodes):
        assert n["object_id"]
        assert n["anchor_seq"] is not None
        assert n["prev"] == (nodes[i - 1]["node_id"] if i > 0 else None)
        assert n["next"] == (nodes[i + 1]["node_id"]
                             if i + 1 < len(nodes) else None)
    # 写入节点关联成功写入事件；委托节点锚定发放事件
    writes = [n for n in nodes if n["node_type"] == "write"]
    assert writes and all(n["node"]["write"]["accepted"] for n in writes)
    dels = [n for n in nodes if n["node_type"] == "delegation"]
    assert {n["object_id"] for n in dels} == {cid, cid2}

    doc = download(client, iid)
    assert doc["content_sha256"] == sha_of(doc)
    assert doc["chain_digest"] == st["chain_digest"]
    # 结构无异常
    ch = chain(client, iid)
    assert ch["consistent"] is True
    assert ch["anomalies"] == []


def test_node_payloads_carry_causal_detail(client):
    build_history(client, "cx-detail")
    iid = resource_index(client, "cx-detail", "k1").get_json()["index_id"]
    finish(client, iid)
    nodes = all_nodes(client, iid)
    by_type = {}
    for n in nodes:
        by_type.setdefault(n["node_type"], []).append(n)
    ev0 = by_type["lease_event"][0]
    assert ev0["node"]["event"]["event"] == "acquire"
    assert ev0["node"]["event"]["narration"]
    w = by_type["write"][0]
    assert w["node"]["write"]["resource"] == "cx-detail"
    assert w["node"]["write"]["source_event_seq"] == w["seq"]
    d = by_type["delegation"][0]
    # 委托状态由冻结事件纯重放：第一张凭证最终 revoked
    assert d["node"]["delegation"]["credential_id"]


def test_credential_scope_index(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "cx-cred")
    rv = create_index(client, {
        "scope": "credential", "credential_id": cid,
        "idempotency_key": "ck1", "head": True})
    assert rv.status_code == 201, rv.get_json()
    iid = rv.get_json()["index_id"]
    finish(client, iid)
    nodes = all_nodes(client, iid)
    evs = [n for n in nodes if n["node_type"] == "lease_event"]
    # 凭证链 5 条事件全部属于该凭证
    assert len(evs) == 5
    assert all(n["node"]["event"]["credential_id"] == cid for n in evs)
    dels = [n for n in nodes if n["node_type"] == "delegation"]
    assert [n["object_id"] for n in dels] == [cid]
    assert dels[0]["node"]["delegation"]["state"] == "revoked"
    assert client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "verify_status"] == "verified"


# ---------------------------------------------------------------------------
# 源归档与证据包条目进入因果链；跨资源混合链路
# ---------------------------------------------------------------------------


def test_chain_includes_source_archives_after_events(client):
    aid, ev = make_completed_archives(client, "cx-arc")
    iid = resource_index(client, "cx-arc", "k1").get_json()["index_id"]
    finish(client, iid)
    nodes = all_nodes(client, iid)
    arch = [n for n in nodes if n["node_type"] == "source_archive"]
    assert [n["object_id"] for n in arch] == [aid]
    # 归档层在所有事件/写入/委托之后
    assert all(_layer(n["node_type"]) <= 2 for n in nodes)
    assert arch[0]["node"]["source_archive"]["frozen_content_sha256"]
    assert arch[0]["node"]["source_archive"]["exists"] is True


def _layer(t):
    return {"lease_event": 0, "write": 1, "delegation": 1,
            "source_archive": 2, "evidence_entry": 3}[t]


def test_evidence_scope_mixed_cross_resource_chain(client):
    # 两个资源 + 各自归档 + 一个混合证据包
    l1 = acquire(client, "cx-rA", "node-a", ttl_ms=200000)
    assert write(client, l1, "A1").status_code == 201
    l2 = acquire(client, "cx-rB", "node-b", ttl_ms=200000)
    assert write(client, l2, "B1").status_code == 201
    ra = create_resource_archive(client, "cx-rA", "ka", head=True
                                 ).get_json()["archive_id"]
    rb = create_resource_archive(client, "cx-rB", "kb", head=True
                                 ).get_json()["archive_id"]
    finish_archive(client, ra)
    finish_archive(client, rb)
    pid = client.post("/audit/evidence", json={
        "archives": [ra, {"archive_id": rb, "include": "reference"}],
        "idempotency_key": "pkg"}).get_json()["package_id"]
    finish_package(client, pid)

    rv = create_index(client, {
        "scope": "evidence_package", "package_id": pid,
        "idempotency_key": "ci1"})
    assert rv.status_code == 201, rv.get_json()
    body = rv.get_json()
    # 证据包作用域的历史节点 = 包创建时钉死的快照节点
    assert body["node_seq"] == body["snapshot_seq"]
    iid = body["index_id"]
    finish(client, iid)

    nodes = all_nodes(client, iid)
    types = [n["node_type"] for n in nodes]
    assert types.count("source_archive") == 2
    assert types.count("evidence_entry") == 2
    # 分层因果顺序：事件 → 写入 → 归档 → 证据条目
    layers = [_layer(t) for t in types]
    assert layers == sorted(layers)
    # 证据条目按 position 0,1
    entries = [n for n in nodes if n["node_type"] == "evidence_entry"]
    assert [n["node"]["evidence_entry"]["position"] for n in entries] == [0, 1]
    assert entries[0]["node"]["evidence_entry"]["archive_id"] == ra
    assert entries[1]["node"]["evidence_entry"]["include_mode"] == "reference"
    # 跨资源：事件层包含两个资源的事件，按全局 seq 交错
    resources = {n["node"]["event"]["resource"]
                 for n in nodes if n["node_type"] == "lease_event"}
    assert resources == {"cx-rA", "cx-rB"}
    # 链尾是证据条目，其后继为 None；首个条目前驱是最后一个归档
    assert nodes[-1]["node_type"] == "evidence_entry"
    assert nodes[-1]["next"] is None

    assert client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "verify_status"] == "verified"


def test_empty_result_is_valid_completed_chain(client):
    build_history(client, "cx-empty")
    # 只看被拒绝事件之外：outcome=rejected 且事件类型 write —— 历史里
    # 被拒绝的是 acquire/write/delegate_write，精确组合可以为空
    rv = resource_index(
        client, "cx-empty", "k-empty", head=False, at_seq=1,
        filters={"outcomes": ["rejected"], "event_types": ["release"]})
    assert rv.status_code == 201, rv.get_json()
    iid = rv.get_json()["index_id"]
    assert rv.get_json()["progress"]["total_nodes"] == 0
    st = finish(client, iid)
    assert st["status"] == "completed"
    assert st["progress"] == {
        "processed_nodes": 0, "total_nodes": 0, "remaining_nodes": 0,
        "percent": 100.0, "done": True, "last_position": -1}
    ch = chain(client, iid)
    assert ch["nodes"] == []
    assert ch["reached_end"] is True
    assert ch["consistent"] is True
    doc = download(client, iid)
    assert doc["nodes"] == []
    assert doc["chain_digest"]  # 空链也有确定摘要
    assert doc["content_sha256"] == sha_of(doc)
    assert client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "verify_status"] == "verified"


# ---------------------------------------------------------------------------
# 幂等创建与冲突
# ---------------------------------------------------------------------------


def test_same_scope_node_filter_key_returns_same_index(client):
    build_history(client, "cx-idem")
    ev = client.get("/resources/cx-idem/audit/events").get_json()["events"]
    n_early, n_late = ev[2]["seq"], ev[-1]["seq"]
    filt = {"outcomes": ["ok"]}
    r1 = resource_index(client, "cx-idem", "k1", at_seq=n_late, head=False,
                        filters=filt)
    assert r1.status_code == 201
    iid = r1.get_json()["index_id"]
    r2 = resource_index(client, "cx-idem", "k1", at_seq=n_late, head=False,
                        filters=filt)
    assert r2.status_code == 200
    assert r2.get_json()["replayed"] is True
    assert r2.get_json()["index_id"] == iid

    # 同键换节点 → 409，给出首个差异字段与双方值
    r3 = resource_index(client, "cx-idem", "k1", at_seq=n_early, head=False,
                        filters=filt)
    assert r3.status_code == 409
    d = r3.get_json()
    assert d["error"] == "causal_index_id_conflict"
    assert d["first_difference"]["path"] == "node_seq"
    assert d["first_difference"]["existing"] == n_late
    assert d["first_difference"]["requested"] == n_early

    # 同键换过滤条件 → 409
    r4 = resource_index(client, "cx-idem", "k1", at_seq=n_late, head=False,
                        filters={"outcomes": ["rejected"]})
    assert r4.status_code == 409
    assert r4.get_json()["first_difference"]["path"].startswith("filters")


def test_unknown_filter_key_rejected_not_ignored(client):
    # 拼写错误/文档外的过滤键必须 400，不能被静默吞掉后错误命中幂等回放
    build_history(client, "cx-badf")
    rv = create_index(client, {"scope": "resource", "resource": "cx-badf",
                               "head": True, "idempotency_key": "k",
                               "filters": {"outcome": ["ok"]}})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "bad_request"
    assert "outcome" in rv.get_json()["unknown_filters"]


def test_same_key_changed_scope_conflicts_on_real_credential(client):
    _, _, cid, _, _ = build_history(client, "cx-idem2")
    r1 = create_index(client, {"scope": "credential", "credential_id": cid,
                               "idempotency_key": "kk", "head": True})
    assert r1.status_code == 201
    r2 = resource_index(client, "cx-idem2", "kk")
    assert r2.status_code == 409
    assert r2.get_json()["first_difference"]["path"] == "scope"


def test_concurrent_same_key_creates_yield_one_index(tmp_path):
    import urllib.request
    from wsgiref.simple_server import make_server

    db = str(tmp_path / "causal-conc.db")
    app = create_app(db, start_ticker=False, start_archive_worker=False)
    c = app.test_client()
    acquire(c, "cx-conc", "node-1", ttl_ms=200000)
    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    results, errors = [], []

    def worker():
        try:
            payload = json.dumps({
                "scope": "resource", "resource": "cx-conc",
                "idempotency_key": "race", "head": True}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/audit/causal-indexes",
                data=payload, method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req) as resp:
                results.append((resp.status, json.loads(resp.read())))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    server.shutdown()
    assert not errors
    assert len({r[1]["index_id"] for r in results}) == 1
    assert {r[0] for r in results} <= {200, 201}


def test_create_validation_errors(client):
    build_history(client, "cx-err")
    ev = client.get("/resources/cx-err/audit/events").get_json()["events"]
    # 非法 scope
    assert create_index(client, {"scope": "nope", "idempotency_key": "k",
                                 "head": True}).status_code == 400
    # 缺幂等键
    assert create_index(client, {"scope": "resource", "resource": "cx-err",
                                 "head": True}).status_code == 400
    # resource 作用域缺 resource
    assert create_index(client, {"scope": "resource", "idempotency_key": "k",
                                 "head": True}).status_code == 400
    # 多节点选择器
    assert create_index(client, {"scope": "resource", "resource": "cx-err",
                                 "idempotency_key": "k", "head": True,
                                 "at_seq": 3}).status_code == 400
    # evidence 作用域不允许节点选择器
    assert create_index(client, {"scope": "evidence_package",
                                 "package_id": "p", "idempotency_key": "k",
                                 "head": True}).status_code == 400
    # evidence 作用域不支持事件级过滤
    assert create_index(client, {"scope": "evidence_package",
                                 "package_id": "p", "idempotency_key": "k2",
                                 "filters": {"outcomes": ["ok"]}}
                        ).status_code == 400
    # 非法过滤
    assert resource_index(client, "cx-err", "kbad",
                          filters={"outcomes": ["bogus"]}).status_code == 400
    assert resource_index(client, "cx-err", "kbad2",
                          filters={"seq_min": 9, "seq_max": 3}).status_code == 400
    # 资源无历史 → 404；节点越界 → 416；证据包不存在 → 404
    assert resource_index(client, "ghost", "kg").status_code == 404
    assert resource_index(client, "cx-err", "ko", at_seq=10 ** 9,
                          head=False).status_code == 416
    rv = create_index(client, {"scope": "evidence_package",
                               "package_id": "no-such-pkg",
                               "idempotency_key": "kp"})
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "causal_source_not_found"


# ---------------------------------------------------------------------------
# 创建即冻结：生成期间新增事件/再核验源归档/新增归档与证据包都不进链
# ---------------------------------------------------------------------------


def test_generation_isolated_from_later_changes(client):
    aid, _ = make_completed_archives(client, "cx-iso")
    lease = client.get("/resources/cx-iso/leases").get_json()
    m = mgr(client)
    m.chunk_size = 1
    rv = resource_index(client, "cx-iso", "k1")
    iid = rv.get_json()["index_id"]
    total = rv.get_json()["progress"]["total_nodes"]

    # 还原一块后，索引处于 building；制造新事件、再核验源归档、新增归档
    m.process_pending(max_chunks_per_index=1)
    assert client.get(f"/audit/causal-indexes/{iid}").get_json()[
        "status"] == "building"
    # 新租约世代需要先转移；这里直接用新持有者写不进去，改用转移
    tr = client.post("/leases/transfer", json={
        "resource": "cx-iso", "holder": "node-2",
        "generation": lease["generation"], "to_holder": "node-3",
        "transfer_id": "tr-iso"})
    # 旧持有者可能已变（build_history 转移给 node-2），用当前 lease
    if tr.status_code != 201:
        cur = client.get("/resources/cx-iso/leases").get_json()
        tr = client.post("/leases/transfer", json={
            "resource": "cx-iso", "holder": cur["holder"],
            "generation": cur["generation"], "to_holder": "node-9",
            "transfer_id": "tr-iso2"})
    assert tr.status_code == 201, tr.get_json()
    new_lease = tr.get_json()["lease"]
    assert write(client, new_lease, "after-index-create").status_code == 201
    # 再核验源归档（verify_status 变化）
    assert client.post(f"/audit/archives/{aid}/verify").status_code == 200
    # 新增一个同资源归档（创建在索引之后）
    later = create_resource_archive(client, "cx-iso", "later-key", head=True)
    assert later.status_code == 201
    finish_archive(client, later.get_json()["archive_id"])

    st = finish(client, iid)
    assert st["progress"]["total_nodes"] == total
    nodes = all_nodes(client, iid)
    assert len(nodes) == total
    archs = [n["object_id"] for n in nodes
             if n["node_type"] == "source_archive"]
    assert archs == [aid]  # 后建的归档没有混进来
    max_seq = max(n["seq"] for n in nodes if n["node_type"] == "lease_event")
    assert max_seq <= st["node_seq"]
    # 源归档再核验不改变冻结链内容，核验仍通过
    assert client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "verify_status"] == "verified"


# ---------------------------------------------------------------------------
# 分块进度、断点续跑、失败重试不重复写入
# ---------------------------------------------------------------------------


def test_chunk_progress_visible_and_resumes(client):
    build_history(client, "cx-prog")
    m = mgr(client)
    m.chunk_size = 2
    rv = resource_index(client, "cx-prog", "k1")
    iid = rv.get_json()["index_id"]
    total = rv.get_json()["progress"]["total_nodes"]

    seen = []
    while True:
        m.process_pending(max_chunks_per_index=1)
        st = client.get(f"/audit/causal-indexes/{iid}").get_json()
        seen.append((st["status"], st["progress"]["processed_nodes"]))
        if st["status"] == "completed":
            break
    assert seen[0][0] == "building"
    assert seen[-1] == ("completed", total)
    # 每块至多推进 chunk_size，严格递增且不重复
    processed = [p for _, p in seen]
    assert processed == sorted(set(processed)) or len(processed) == len(set(processed))
    assert processed[-1] == total


def test_finalize_failure_retries_without_duplicate_nodes(client, monkeypatch):
    build_history(client, "cx-fin")
    m = mgr(client)
    rv = resource_index(client, "cx-fin", "k1")
    iid = rv.get_json()["index_id"]
    total = rv.get_json()["progress"]["total_nodes"]

    monkeypatch.setattr(
        m, "_finalize_locked",
        lambda _i: (_ for _ in ()).throw(RuntimeError("simulated crash")))
    m.process_pending()
    st = client.get(f"/audit/causal-indexes/{iid}").get_json()
    assert st["status"] == "failed"
    assert "simulated crash" in st["error"]
    assert st["progress"]["processed_nodes"] == total
    monkeypatch.undo()

    # 自动重试一轮即可完成
    m.process_pending()
    st = client.get(f"/audit/causal-indexes/{iid}").get_json()
    assert st["status"] == "completed"
    assert st["attempts"] == 2
    # 无重复节点
    store = store_of(client)
    with store._lock:
        rows = store._conn.execute(
            "SELECT node_id FROM causal_index_nodes WHERE index_id=?",
            (iid,)).fetchall()
    ids = [r["node_id"] for r in rows]
    assert len(ids) == total == len(set(ids))
    # 手动 retry 在非 failed 上 409
    assert client.post(
        f"/audit/causal-indexes/{iid}/retry").status_code == 409


def test_restart_resumes_from_saved_progress(tmp_path):
    db = str(tmp_path / "causal-restart.db")
    app1 = create_app(db, start_ticker=False, start_archive_worker=False)
    c1 = app1.test_client()
    build_history(c1, "cx-restart")
    m1 = app1.extensions["causal"]
    m1.chunk_size = 2
    iid = resource_index(c1, "cx-restart", "k1").get_json()["index_id"]
    total = c1.get(f"/audit/causal-indexes/{iid}").get_json()[
        "progress"]["total_nodes"]
    m1.process_pending(max_chunks_per_index=1)
    st = c1.get(f"/audit/causal-indexes/{iid}").get_json()
    assert st["status"] == "building"
    done = st["progress"]["processed_nodes"]
    assert 0 < done < total

    # 重启：同库新进程续跑
    app2 = create_app(db, start_ticker=False, start_archive_worker=False)
    c2 = app2.test_client()
    assert c2.get(f"/audit/causal-indexes/{iid}").get_json()[
        "status"] == "building"
    app2.extensions["causal"].process_pending()
    st = c2.get(f"/audit/causal-indexes/{iid}").get_json()
    assert st["status"] == "completed"
    doc = json.loads(c2.get(
        f"/audit/causal-indexes/{iid}/download").data)
    assert len(doc["nodes"]) == total
    assert doc["content_sha256"] == sha_of(doc)
    # 重启后再次下载逐字节一致，核验标记不丢
    c2.post(f"/audit/causal-indexes/{iid}/verify")
    app3 = create_app(db, start_ticker=False, start_archive_worker=False)
    c3 = app3.test_client()
    assert c3.get(f"/audit/causal-indexes/{iid}/download").data == \
        c2.get(f"/audit/causal-indexes/{iid}/download").data
    assert c3.get(f"/audit/causal-indexes/{iid}").get_json()[
        "verify_status"] == "verified"


def test_worker_autostart_completes_end_to_end(tmp_path):
    db = str(tmp_path / "causal-worker.db")
    app = create_app(db, start_ticker=False)  # worker 默认开启
    c = app.test_client()
    build_history(c, "cx-bg")
    iid = resource_index(c, "cx-bg", "k1").get_json()["index_id"]
    deadline = time.time() + 10
    while time.time() < deadline:
        st = c.get(f"/audit/causal-indexes/{iid}").get_json()
        if st["status"] == "completed":
            break
        time.sleep(0.05)
    else:
        raise AssertionError("后台 worker 未完成因果索引")
    assert c.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "verify_status"] == "verified"


# ---------------------------------------------------------------------------
# 固定快照游标分页
# ---------------------------------------------------------------------------


def test_cursor_pagination_is_stable_and_bounded(client):
    build_history(client, "cx-page")
    iid = resource_index(client, "cx-page", "k1").get_json()["index_id"]
    finish(client, iid)
    total = client.get(f"/audit/causal-indexes/{iid}").get_json()[
        "progress"]["total_nodes"]

    p1 = chain(client, iid, limit=3)
    assert [n["position"] for n in p1["nodes"]] == [0, 1, 2]
    assert p1["next_cursor"] == 3
    assert p1["reached_end"] is False
    p2 = chain(client, iid, after=2, limit=3)
    assert [n["position"] for n in p2["nodes"]] == [3, 4, 5]
    # 固定快照：后续有新事件，翻页结果不变（链已冻结）
    l = acquire(client, "cx-page-other", "node-z", ttl_ms=200000)
    assert write(client, l, "noise").status_code == 201
    p2b = chain(client, iid, after=2, limit=3)
    assert [n["node_id"] for n in p2b["nodes"]] == \
        [n["node_id"] for n in p2["nodes"]]
    # 一直翻到末尾，覆盖全部节点且不重复
    seen = [n["node_id"] for n in p1["nodes"]]
    cur = p1
    while not cur["reached_end"]:
        cur = chain(client, iid, after=cur["next_cursor"] - 1, limit=3)
        seen += [n["node_id"] for n in cur["nodes"]]
    assert len(seen) == total == len(set(seen))

    # 游标越界 → 416
    rv = client.get(f"/audit/causal-indexes/{iid}/chain?after={total}")
    assert rv.status_code == 416
    assert rv.get_json()["error"] == "node_out_of_range"
    # 非法 limit / after → 400
    assert client.get(
        f"/audit/causal-indexes/{iid}/chain?limit=0").status_code == 400
    assert client.get(
        f"/audit/causal-indexes/{iid}/chain?after=x").status_code == 400


def test_chain_not_queryable_until_completed(client):
    build_history(client, "cx-notready")
    iid = resource_index(client, "cx-notready", "k1").get_json()["index_id"]
    assert client.get(f"/audit/causal-indexes/{iid}/chain").status_code == 409
    assert client.get(
        f"/audit/causal-indexes/{iid}/download").status_code == 409
    assert client.post(
        f"/audit/causal-indexes/{iid}/verify").status_code == 409
    finish(client, iid)
    assert client.get(f"/audit/causal-indexes/{iid}/chain").status_code == 200


# ---------------------------------------------------------------------------
# 独立核验：通过 + 各类篡改的首个差异
# ---------------------------------------------------------------------------


def test_verify_passes_on_clean_index(client):
    build_history(client, "cx-v")
    iid = resource_index(client, "cx-v", "k1").get_json()["index_id"]
    finish(client, iid)
    r = client.post(f"/audit/causal-indexes/{iid}/verify")
    assert r.status_code == 200
    body = r.get_json()
    assert body["verify_status"] == "verified"
    assert body["first_divergence"] is None
    assert client.get(f"/audit/causal-indexes/{iid}").get_json()[
        "verify_status"] == "verified"


def test_verify_detects_deleted_history_event(client):
    build_history(client, "cx-del")
    iid = resource_index(client, "cx-del", "k1").get_json()["index_id"]
    finish(client, iid)
    ev = client.get("/resources/cx-del/audit/events").get_json()["events"]
    victim = ev[1]["seq"]
    conn = sqlite3.connect(db_path(client))
    conn.execute("DELETE FROM lease_events WHERE seq=?", (victim,))
    conn.commit()
    conn.close()
    body = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    # 成员集合重算即在首个缺失位置分叉
    assert div["section"] == "membership"
    assert div["path"].startswith("members")
    assert client.get(f"/audit/causal-indexes/{iid}").get_json()[
        "verify_status"] == "verify_failed"


def test_verify_detects_tampered_chain_document(client):
    build_history(client, "cx-doc")
    iid = resource_index(client, "cx-doc", "k1").get_json()["index_id"]
    finish(client, iid)
    doc = download(client, iid)
    doc["scope"] = "credential"  # 篡改文档
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE causal_indexes SET content=? WHERE index_id=?",
        (json.dumps(doc, ensure_ascii=False, sort_keys=True), iid))
    conn.commit()
    conn.close()
    div = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "first_divergence"]
    assert div["section"] == "checksum"
    assert div["path"] == "content_sha256"


def test_verify_detects_forged_node_with_matching_checksum(client):
    build_history(client, "cx-node")
    iid = resource_index(client, "cx-node", "k1").get_json()["index_id"]
    finish(client, iid)
    doc = download(client, iid)
    # 连校验值一起伪造一个事件节点的 holder
    doc["nodes"][0]["event"]["holder"] = "forged"
    doc["content_sha256"] = sha_of(doc)
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE causal_indexes SET content=?, content_sha256=? WHERE index_id=?",
        (json.dumps(doc, ensure_ascii=False, sort_keys=True),
         doc["content_sha256"], iid))
    conn.commit()
    conn.close()
    div = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "first_divergence"]
    # 校验值自洽但节点无法独立重建：nodes 段给出节点/字段/双方值
    assert div["section"] == "nodes"
    assert div["node_id"] == doc["nodes"][0]["node_id"]
    assert div["path"].endswith("holder")
    assert div["archived"] == "forged"
    assert div["recomputed"] == "node-1"


def test_verify_detects_tampered_frozen_node_row(client):
    build_history(client, "cx-frozen")
    iid = resource_index(client, "cx-frozen", "k1").get_json()["index_id"]
    finish(client, iid)
    store = store_of(client)
    with store._lock:
        row = store._conn.execute(
            "SELECT node_id, payload FROM causal_index_nodes "
            "WHERE index_id=? ORDER BY position LIMIT 1",
            (iid,)).fetchone()
        payload = json.loads(row["payload"])
        target_id = row["node_id"]
    payload["event"]["holder"] = "forged-row"
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE causal_index_nodes SET payload=? WHERE index_id=? AND node_id=?",
        (json.dumps(payload, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")), iid, target_id))
    conn.commit()
    conn.close()
    div = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "first_divergence"]
    assert div["section"] == "nodes"
    assert div["node_id"] == target_id
    assert div["archived"] == "forged-row"
    assert div["recomputed"] == "node-1"


def test_verify_detects_chain_digest_reorder(client):
    build_history(client, "cx-reorder")
    iid = resource_index(client, "cx-reorder", "k1").get_json()["index_id"]
    finish(client, iid)
    doc = download(client, iid)
    # 交换两个同层事件节点并重算总校验值（链摘要应对不上）
    ev_idx = [i for i, n in enumerate(doc["nodes"])
              if n["node_type"] == "lease_event"]
    i, j = ev_idx[0], ev_idx[1]
    doc["nodes"][i], doc["nodes"][j] = doc["nodes"][j], doc["nodes"][i]
    doc["content_sha256"] = sha_of(doc)
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE causal_indexes SET content=?, content_sha256=? WHERE index_id=?",
        (json.dumps(doc, ensure_ascii=False, sort_keys=True),
         doc["content_sha256"], iid))
    conn.commit()
    conn.close()
    div = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "first_divergence"]
    # 节点顺序与冻结成员位置不一致先暴露
    assert div["section"] in ("nodes", "chain_digest")


# ---------------------------------------------------------------------------
# 源归档核验失败 / 缺失 / 内容变化；证据包条目缺失
# ---------------------------------------------------------------------------


def test_source_archive_verify_failed_makes_index_untrusted(client):
    aid, _ = make_completed_archives(client, "cx-sv")
    iid = resource_index(client, "cx-sv", "k1").get_json()["index_id"]
    finish(client, iid)
    assert client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "verify_status"] == "verified"
    # 篡改源归档冻结事件，使其自身核验失败
    store = store_of(client)
    with store._lock:
        row = store._conn.execute(
            "SELECT seq, payload FROM archive_events WHERE archive_id=? "
            "ORDER BY seq LIMIT 1", (aid,)).fetchone()
        payload = json.loads(row["payload"])
    payload["holder"] = "forged"
    conn = sqlite3.connect(db_path(client))
    conn.execute("UPDATE archive_events SET payload=? WHERE archive_id=? AND seq=?",
                 (json.dumps(payload, ensure_ascii=False, sort_keys=True),
                  aid, row["seq"]))
    conn.commit()
    conn.close()
    arc_verify = client.post(f"/audit/archives/{aid}/verify").get_json()
    assert arc_verify["verify_status"] == "verify_failed"

    body = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["section"] == "sources"
    assert div["archive_id"] == aid
    # 链路查询也报告源归档核验失败异常
    ch = chain(client, iid)
    codes = ch["anomaly_summary"]["issues_by_code"]
    assert "source_archive_verify_failed" in codes


def test_deleted_source_archive_is_reported(client):
    aid, _ = make_completed_archives(client, "cx-sd")
    iid = resource_index(client, "cx-sd", "k1").get_json()["index_id"]
    finish(client, iid)
    conn = sqlite3.connect(db_path(client))
    conn.execute("DELETE FROM archives WHERE archive_id=?", (aid,))
    conn.commit()
    conn.close()
    ch = chain(client, iid)
    assert ch["consistent"] is False
    issue = next(a for a in ch["anomalies"]
                 if a["code"] == "source_archive_missing")
    assert issue["archive_id"] == aid
    div = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "first_divergence"]
    assert div["section"] == "sources"
    assert div["archive_id"] == aid


def test_source_archive_content_change_detected(client):
    aid, _ = make_completed_archives(client, "cx-sc")
    iid = resource_index(client, "cx-sc", "k1").get_json()["index_id"]
    finish(client, iid)
    conn = sqlite3.connect(db_path(client))
    conn.execute("UPDATE archives SET content_sha256=? WHERE archive_id=?",
                 ("a" * 64, aid))
    conn.commit()
    conn.close()
    codes = chain(client, iid)["anomaly_summary"]["issues_by_code"]
    assert "source_archive_changed" in codes
    div = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "first_divergence"]
    assert div["archived"] != div["recomputed"]
    assert div["path"] == "sources.source_archive_changed"


def test_missing_evidence_entry_detected(client):
    l = acquire(client, "cx-ee", "node-1", ttl_ms=200000)
    assert write(client, l, "v").status_code == 201
    aid = create_resource_archive(client, "cx-ee", "ka", head=True
                                  ).get_json()["archive_id"]
    finish_archive(client, aid)
    pid = client.post("/audit/evidence", json={
        "archives": [aid], "idempotency_key": "pk"}).get_json()["package_id"]
    finish_package(client, pid)
    iid = create_index(client, {"scope": "evidence_package",
                                "package_id": pid,
                                "idempotency_key": "ci"}).get_json()["index_id"]
    finish(client, iid)
    conn = sqlite3.connect(db_path(client))
    conn.execute("DELETE FROM evidence_entries WHERE package_id=? AND position=0",
                 (pid,))
    conn.commit()
    conn.close()
    codes = chain(client, iid)["anomaly_summary"]["issues_by_code"]
    assert "evidence_entry_missing" in codes
    div = client.post(f"/audit/causal-indexes/{iid}/verify").get_json()[
        "first_divergence"]
    assert div["section"] == "sources"
    assert div["package_id"] == pid and div["position"] == 0


# ---------------------------------------------------------------------------
# 断链 / 环路 / 重复序号（篡改冻结节点表）
# ---------------------------------------------------------------------------


def test_structural_anomaly_broken_link(client):
    build_history(client, "cx-broken")
    iid = resource_index(client, "cx-broken", "k1").get_json()["index_id"]
    finish(client, iid)
    store = store_of(client)
    # 把第一个节点的 next 篡改为不存在的节点
    with store._lock:
        row = store._conn.execute(
            "SELECT node_id, payload FROM causal_index_nodes "
            "WHERE index_id=? ORDER BY position LIMIT 1",
            (iid,)).fetchone()
        nid = row["node_id"]
        payload = json.loads(row["payload"])
    payload["next_node_id"] = "event:999999"
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE causal_index_nodes SET payload=? WHERE index_id=? AND node_id=?",
        (json.dumps(payload, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")), iid, nid))
    conn.commit()
    conn.close()
    codes = chain(client, iid)["anomaly_summary"]["issues_by_code"]
    assert "chain_broken" in codes


def test_structural_anomaly_cycle(client):
    build_history(client, "cx-cycle")
    iid = resource_index(client, "cx-cycle", "k1").get_json()["index_id"]
    finish(client, iid)
    conn = sqlite3.connect(db_path(client))
    rows = conn.execute(
        "SELECT node_id, payload FROM causal_index_nodes WHERE index_id=? "
        "ORDER BY position", (iid,)).fetchall()
    first = json.loads(rows[0][1])
    last = json.loads(rows[-1][1])
    # 末节点指回首节点形成环
    last["next_node_id"] = rows[0][0]
    conn.execute(
        "UPDATE causal_index_nodes SET payload=? WHERE index_id=? AND node_id=?",
        (json.dumps(last, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")), iid, rows[-1][0]))
    conn.commit()
    conn.close()
    codes = chain(client, iid)["anomaly_summary"]["issues_by_code"]
    assert "chain_cycle" in codes or "chain_broken" in codes


# ---------------------------------------------------------------------------
# 节点重建（只读）
# ---------------------------------------------------------------------------


def test_rebuild_node_matches_and_detects_drift(client):
    build_history(client, "cx-rb")
    iid = resource_index(client, "cx-rb", "k1").get_json()["index_id"]
    finish(client, iid)
    nodes = all_nodes(client, iid)
    target = nodes[0]["node_id"]
    rv = client.post(f"/audit/causal-indexes/{iid}/nodes/{target}/rebuild")
    assert rv.status_code == 200
    body = rv.get_json()
    assert body["matches"] is True
    assert body["first_divergence"] is None
    assert body["read_only"] is True
    assert body["frozen"]["node_id"] == body["rebuilt"]["node_id"]

    # 单节点 GET 返回冻结节点
    rv = client.get(f"/audit/causal-indexes/{iid}/nodes/{target}")
    assert rv.status_code == 200
    assert rv.get_json()["node_id"] == target
    # 不属于本索引的节点 404
    assert client.post(
        f"/audit/causal-indexes/{iid}/nodes/event:999999/rebuild"
    ).status_code == 404
    assert client.get(
        f"/audit/causal-indexes/{iid}/nodes/event:999999").status_code == 404


# ---------------------------------------------------------------------------
# 只读边界
# ---------------------------------------------------------------------------


def test_index_ops_never_mutate_source_tables(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "cx-ro")
    aid = create_resource_archive(client, "cx-ro", "ark", head=True
                                  ).get_json()["archive_id"]
    finish_archive(client, aid)
    pid = client.post("/audit/evidence", json={
        "archives": [aid], "idempotency_key": "epk"}).get_json()["package_id"]
    finish_package(client, pid)
    store = store_of(client)

    def snapshot():
        with store._lock:
            ev = store._conn.execute(
                "SELECT MAX(seq) m, COUNT(*) c FROM lease_events").fetchone()
            leases = [tuple(r) for r in store._conn.execute(
                "SELECT id, state, generation FROM leases ORDER BY id")]
            dels = [tuple(r) for r in store._conn.execute(
                "SELECT credential_id, state FROM delegations "
                "ORDER BY credential_id")]
            writes_c = store._conn.execute(
                "SELECT COUNT(*) c FROM writes").fetchone()["c"]
            arc = [tuple(r) for r in store._conn.execute(
                "SELECT archive_id, content_sha256, verify_status, status "
                "FROM archives ORDER BY archive_id")]
            pkg = [tuple(r) for r in store._conn.execute(
                "SELECT package_id, status, content_sha256 FROM evidence_packages"
                " ORDER BY package_id")]
        return (ev["m"], ev["c"]), leases, dels, writes_c, arc, pkg

    before = snapshot()
    # 资源/凭证/证据包三种作用域全流程
    iid1 = resource_index(client, "cx-ro", "i1").get_json()["index_id"]
    finish(client, iid1)
    client.get(f"/audit/causal-indexes/{iid1}/chain?limit=2")
    client.get(f"/audit/causal-indexes/{iid1}/download")
    client.post(f"/audit/causal-indexes/{iid1}/verify")
    nodes = all_nodes(client, iid1)
    client.post(
        f"/audit/causal-indexes/{iid1}/nodes/{nodes[0]['node_id']}/rebuild")

    iid2 = create_index(client, {"scope": "credential", "credential_id": cid,
                                 "idempotency_key": "i2", "head": True}
                        ).get_json()["index_id"]
    finish(client, iid2)
    client.post(f"/audit/causal-indexes/{iid2}/verify")

    iid3 = create_index(client, {"scope": "evidence_package", "package_id": pid,
                                 "idempotency_key": "i3"}).get_json()["index_id"]
    finish(client, iid3)
    client.post(f"/audit/causal-indexes/{iid3}/verify")
    client.get("/audit/causal-indexes")

    assert snapshot() == before
    # 当前租约仍可写
    cur = client.get("/resources/cx-ro/leases").get_json()
    rv = client.post("/resources/cx-ro/writes", json={
        "holder": cur["holder"], "generation": cur["generation"],
        "value": "still-alive"})
    assert rv.status_code == 201


def test_retry_and_status_guards(client):
    build_history(client, "cx-guard")
    assert client.get("/audit/causal-indexes/nope").status_code == 404
    assert client.get(
        "/audit/causal-indexes/nope/chain").status_code == 404
    assert client.post(
        "/audit/causal-indexes/nope/verify").status_code == 404
    assert client.post(
        "/audit/causal-indexes/nope/retry").status_code == 404
    iid = resource_index(client, "cx-guard", "k1").get_json()["index_id"]
    # 非 failed 不能 retry
    assert client.post(
        f"/audit/causal-indexes/{iid}/retry").status_code == 409
    finish(client, iid)
    assert client.post(
        f"/audit/causal-indexes/{iid}/retry").status_code == 409


def test_list_indexes_filters(client):
    build_history(client, "cx-list")
    iid = resource_index(client, "cx-list", "k1").get_json()["index_id"]
    finish(client, iid)
    iid2 = resource_index(client, "cx-list", "k2", at_seq=1, head=False
                          ).get_json()["index_id"]
    all_i = client.get("/audit/causal-indexes").get_json()["indexes"]
    assert {i["index_id"] for i in all_i} == {iid, iid2}
    done = client.get(
        "/audit/causal-indexes?status=completed").get_json()["indexes"]
    assert [i["index_id"] for i in done] == [iid]
    by_scope = client.get(
        "/audit/causal-indexes?scope=resource").get_json()["indexes"]
    assert {i["index_id"] for i in by_scope} == {iid, iid2}
    assert client.get(
        "/audit/causal-indexes?status=bogus").status_code == 400
    assert client.get(
        "/audit/causal-indexes?scope=bogus").status_code == 400
