"""可验证审计归档：幂等创建、快照隔离、进度查询、断点续跑、独立核验。

覆盖：
- 在指定稳定节点创建资源/凭证归档，内容固定事件范围、回放状态、
  诊断结果与内容校验值；
- 同对象+同节点+同幂等键重复创建得到同一份归档；同键不同节点 409；
- 归档生成期间的新写入不会混入归档（创建时钉死的事件上界）；
- 分块生成进度可查，重启/失败后从已保存进度续跑，重试不重复写入；
- 完成后可核验为 verified / verify_failed，失败给出首个差异位置；
- 归档、下载、核验绝不修改运行中的租约、委托与原始审计历史。
"""

import hashlib
import json
import sqlite3
import threading
import time

import pytest

from app.app import create_app
from conftest import acquire, write
from test_audit import build_history


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "archive.db"
    app = create_app(str(db), start_ticker=False, enable_debug_api=True,
                     start_archive_worker=False)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def mgr(client):
    return client.application.extensions["archive"]


def store_of(client):
    return client.application.extensions["store"]


def db_path(client):
    return store_of(client)._conn.execute(
        "PRAGMA database_list").fetchone()[2]


def create_resource_archive(client, resource, key, **node):
    payload = {"scope": "resource", "resource": resource,
               "idempotency_key": key}
    payload.update(node)
    return client.post("/audit/archives", json=payload)


def create_credential_archive(client, credential_id, key, **node):
    payload = {"scope": "credential", "credential_id": credential_id,
               "idempotency_key": key}
    payload.update(node)
    return client.post("/audit/archives", json=payload)


def finish(client, archive_id):
    """驱动后台生成直到完成，返回最终状态视图。"""
    m = mgr(client)
    for _ in range(500):
        m.process_pending()
        st = client.get(f"/audit/archives/{archive_id}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("归档未能在限定轮次内完成")


def download(client, archive_id):
    rv = client.get(f"/audit/archives/{archive_id}/download")
    assert rv.status_code == 200
    return json.loads(rv.data)


def sha_of(content):
    core = {k: v for k, v in content.items() if k != "content_sha256"}
    return hashlib.sha256(
        json.dumps(core, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).hexdigest()


def frozen_seqs(client, archive_id):
    store = store_of(client)
    with store._lock:
        rows = store._conn.execute(
            "SELECT seq FROM archive_events WHERE archive_id=? ORDER BY seq",
            (archive_id,)).fetchall()
    return [r["seq"] for r in rows]


# ---------------------------------------------------------------------------
# 创建 → 生成 → 下载 → 校验值
# ---------------------------------------------------------------------------

def test_create_complete_download_and_checksum(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "arc-1")
    ev = client.get("/resources/arc-1/audit/events").get_json()["events"]
    node_seq = ev[4]["seq"]  # 固定在第 5 条事件（委托冒用被拒）处

    rv = create_resource_archive(client, "arc-1", "k1", at_seq=node_seq)
    assert rv.status_code == 201, rv.get_json()
    body = rv.get_json()
    assert body["replayed"] is False
    assert body["status"] == "pending"
    assert body["node_seq"] == node_seq
    assert body["snapshot_seq"] == ev[-1]["seq"]
    assert body["progress"]["total_events"] == 5
    aid = body["archive_id"]

    st = finish(client, aid)
    assert st["progress"] == {
        "processed_events": 5, "total_events": 5,
        "remaining_events": 0, "percent": 100.0, "done": True,
    }
    assert st["content_sha256"]
    assert st["verify_status"] == "unverified"
    assert st["completed_at_ms"] is not None

    content = download(client, aid)
    assert content["kind"] == "lease_audit_archive"
    assert content["archive_id"] == aid
    assert content["scope"] == "resource"
    assert content["node_seq"] == node_seq
    assert content["node"]["seq"] == node_seq
    assert content["event_range"] == {
        "first_seq": ev[0]["seq"], "last_seq": node_seq, "count": 5}
    assert [e["seq"] for e in content["events"]] == \
        [e["seq"] for e in ev[:5]]
    # 回放状态固定在第 5 条事件时：值 v2、租约 node-1/gen1、凭证 active
    rs = content["replay_state"]
    assert rs["resource"]["value"] == "v2"
    assert rs["lease"]["holder"] == "node-1"
    assert rs["lease"]["active_at_node"] is True
    assert rs["delegations"][0]["state"] == "active"
    # 诊断结果与内容校验值
    assert content["diagnosis"]["summary"]["total_events"] == 5
    assert content["diagnosis"]["summary"]["consistent"] is True
    assert content["content_sha256"] == sha_of(content)
    # 下载响应头带校验值，且原文就是落库字节
    rv = client.get(f"/audit/archives/{aid}/download")
    assert rv.headers["X-Archive-SHA256"] == content["content_sha256"]
    assert json.loads(rv.data) == content


def test_create_by_head_and_wall_ms(client):
    lease = acquire(client, "arc-w", "node-1")
    assert write(client, lease, "w1").status_code == 201
    assert write(client, lease, "w2").status_code == 201
    ev = client.get("/resources/arc-w/audit/events").get_json()["events"]

    rv = create_resource_archive(client, "arc-w", "k1", head=True)
    assert rv.status_code == 201
    assert rv.get_json()["node_seq"] == ev[-1]["seq"]

    mid_wall = ev[1]["wall_ms"]
    rv = create_resource_archive(client, "arc-w", "k2", at_wall_ms=mid_wall)
    assert rv.status_code == 201
    assert rv.get_json()["node_seq"] == ev[1]["seq"]


def test_credential_archive_pins_chain_and_state(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "arc-cred")
    rv = create_credential_archive(client, cid, "ck1", head=True)
    assert rv.status_code == 201, rv.get_json()
    body = rv.get_json()
    assert body["resource"] == "arc-cred"
    assert body["credential_id"] == cid
    # 凭证链：发放/委托写/冒用被拒/撤销/迟到写被拒 = 5 条
    assert body["progress"]["total_events"] == 5
    aid = body["archive_id"]

    finish(client, aid)
    content = download(client, aid)
    assert content["scope"] == "credential"
    assert len(content["events"]) == 5
    assert all(e["credential_id"] == cid for e in content["events"])
    kinds = [e["event"] for e in content["events"]]
    assert kinds == ["delegate_grant", "delegate_write", "delegate_write",
                     "delegate_revoke", "delegate_write"]
    cred = content["replay_state"]["credential"]
    assert cred["credential_id"] == cid
    assert cred["state"] == "revoked"
    assert cred["writes_accepted"] == 1
    assert cred["writes_rejected"] == 2
    # 节点处的资源上下文（撤销后、转移前）
    assert content["replay_state"]["resource"]["value"] == "v2"
    assert content["replay_state"]["lease"]["holder"] == "node-1"
    assert content["content_sha256"] == sha_of(content)


# ---------------------------------------------------------------------------
# 幂等创建：同对象+同节点+同键 → 同一份；同键不同节点 → 409
# ---------------------------------------------------------------------------

def test_idempotent_create_returns_same_archive(client):
    build_history(client, "arc-2")
    ev = client.get("/resources/arc-2/audit/events").get_json()["events"]
    n5, n6 = ev[4]["seq"], ev[5]["seq"]

    r1 = create_resource_archive(client, "arc-2", "k1", at_seq=n5)
    assert r1.status_code == 201
    aid = r1.get_json()["archive_id"]

    # 同对象+同节点+同幂等键：返回同一份归档，绝不新建第二份
    r2 = create_resource_archive(client, "arc-2", "k1", at_seq=n5)
    assert r2.status_code == 200
    assert r2.get_json()["replayed"] is True
    assert r2.get_json()["archive_id"] == aid

    # 同键配不同节点：409 冲突，不会生成两份互相矛盾的归档
    r3 = create_resource_archive(client, "arc-2", "k1", at_seq=n6)
    assert r3.status_code == 409
    assert r3.get_json()["error"] == "archive_id_conflict"
    assert r3.get_json()["existing_node_seq"] == n5
    assert r3.get_json()["requested_node_seq"] == n6

    # 换幂等键同节点：允许存在第二份，但历史内容完全一致（不矛盾）
    r4 = create_resource_archive(client, "arc-2", "k2", at_seq=n5)
    assert r4.status_code == 201
    aid2 = r4.get_json()["archive_id"]
    assert aid2 != aid
    finish(client, aid)
    finish(client, aid2)
    c1, c2 = download(client, aid), download(client, aid2)
    assert c1["events"] == c2["events"]
    assert c1["replay_state"] == c2["replay_state"]
    assert c1["diagnosis"] == c2["diagnosis"]
    assert c1["node_seq"] == c2["node_seq"] == n5


def test_concurrent_creates_with_same_key_yield_one_archive(tmp_path):
    import urllib.request
    from wsgiref.simple_server import make_server

    db = str(tmp_path / "arc-conc.db")
    app = create_app(db, start_ticker=False, start_archive_worker=False)
    c = app.test_client()
    build_history(c, "arc-cc")
    ev = c.get("/resources/arc-cc/audit/events").get_json()["events"]
    node_seq = ev[-1]["seq"]

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    results, errors = [], []

    def worker():
        try:
            payload = json.dumps({
                "scope": "resource", "resource": "arc-cc",
                "idempotency_key": "race-key", "at_seq": node_seq,
            }).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/audit/archives", data=payload,
                method="POST", headers={"Content-Type": "application/json"})
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
    # 并发同键创建：全部指向同一份归档，状态码只有 201/200 两种
    assert {r[1]["archive_id"] for r in results}.__len__() == 1
    assert {r[0] for r in results} <= {200, 201}
    listed = c.get("/audit/archives?resource=arc-cc").get_json()["archives"]
    assert len(listed) == 1


# ---------------------------------------------------------------------------
# 快照隔离：生成期间的新写入进不了归档
# ---------------------------------------------------------------------------

def test_archive_isolated_from_writes_during_generation(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "arc-3")
    ev = client.get("/resources/arc-3/audit/events").get_json()["events"]
    node_seq = ev[4]["seq"]

    m = mgr(client)
    m.chunk_size = 2
    rv = create_resource_archive(client, "arc-3", "k1", at_seq=node_seq)
    aid = rv.get_json()["archive_id"]
    assert rv.get_json()["progress"]["total_events"] == 5

    # 冻结一块之后、归档完成之前，继续写入新事件
    m.process_pending(max_chunks_per_archive=1)
    st = client.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "building"
    assert st["progress"]["processed_events"] == 2
    assert write(client, new_lease, "post-create-1").status_code == 201
    assert write(client, new_lease, "post-create-2").status_code == 201

    st = finish(client, aid)
    # 事件范围在创建时钉死，不随新写入增长
    assert st["progress"]["total_events"] == 5
    content = download(client, aid)
    seqs = [e["seq"] for e in content["events"]]
    assert len(seqs) == 5
    assert max(seqs) <= node_seq
    assert content["replay_state"]["resource"]["value"] == "v2"
    # 新写入确实进了原始历史（13 条），但归档里一条都没有
    all_ev = client.get("/resources/arc-3/audit/events").get_json()["events"]
    assert len(all_ev) == 13
    assert frozen_seqs(client, aid) == seqs


# ---------------------------------------------------------------------------
# 进度：分块落库，逐块可见
# ---------------------------------------------------------------------------

def test_progress_is_saved_chunk_by_chunk(client):
    build_history(client, "arc-4")
    m = mgr(client)
    m.chunk_size = 3
    rv = create_resource_archive(client, "arc-4", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    assert rv.get_json()["progress"]["total_events"] == 11

    seen = []
    for _ in range(10):
        m.process_pending(max_chunks_per_archive=1)
        st = client.get(f"/audit/archives/{aid}").get_json()
        seen.append((st["status"], st["progress"]["processed_events"]))
        if st["status"] == "completed":
            break
    # 11 条事件按每块 3 条推进：3 → 6 → 9 → 11（完成）
    assert seen == [("building", 3), ("building", 6),
                    ("building", 9), ("completed", 11)]
    st = client.get(f"/audit/archives/{aid}").get_json()
    assert st["progress"]["done"] is True
    assert st["progress"]["percent"] == 100.0


# ---------------------------------------------------------------------------
# 重启续跑与失败重试：不丢进度、不重复写入
# ---------------------------------------------------------------------------

def test_restart_resumes_from_saved_progress(tmp_path):
    db = str(tmp_path / "arc-restart.db")
    app1 = create_app(db, start_ticker=False, start_archive_worker=False)
    c1 = app1.test_client()
    build_history(c1, "arc-r")
    m1 = app1.extensions["archive"]
    m1.chunk_size = 2
    rv = create_resource_archive(c1, "arc-r", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    total = rv.get_json()["progress"]["total_events"]

    m1.process_pending(max_chunks_per_archive=1)  # 冻结一块后"进程崩溃"
    st = c1.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "building"
    assert 0 < st["progress"]["processed_events"] < total

    # ---- 重启：同库新进程，从已保存的进度继续 ----
    app2 = create_app(db, start_ticker=False, start_archive_worker=False)
    c2 = app2.test_client()
    st = c2.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "building"  # 进度没丢
    app2.extensions["archive"].process_pending()
    st = c2.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "completed"

    # 冻结副本无重复、无缺口，恰好覆盖创建时钉死的事件范围
    seqs = []
    store2 = app2.extensions["store"]
    with store2._lock:
        seqs = [r["seq"] for r in store2._conn.execute(
            "SELECT seq FROM archive_events WHERE archive_id=? ORDER BY seq",
            (aid,)).fetchall()]
    assert len(seqs) == total
    assert len(set(seqs)) == total
    content = json.loads(c2.get(f"/audit/archives/{aid}/download").data)
    assert content["event_range"]["count"] == total
    assert content["content_sha256"] == sha_of(content)


def test_failed_finalize_retries_without_duplicate_writes(
        client, monkeypatch):
    build_history(client, "arc-f")
    m = mgr(client)
    rv = create_resource_archive(client, "arc-f", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    total = rv.get_json()["progress"]["total_events"]

    def boom(_archive_id):
        raise RuntimeError("simulated finalize crash")

    monkeypatch.setattr(m, "_finalize_locked", boom)
    m.process_pending()
    st = client.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "failed"
    assert "simulated finalize crash" in st["error"]
    # 已冻结的事件进度保留，重试从这里继续
    assert st["progress"]["processed_events"] == total
    monkeypatch.undo()

    # 手动复位重试
    rv = client.post(f"/audit/archives/{aid}/retry")
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "pending"
    m.process_pending()
    st = client.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "completed"

    # 重试没有重复写入任何事件
    assert frozen_seqs(client, aid) == sorted(set(frozen_seqs(client, aid)))
    assert len(frozen_seqs(client, aid)) == total


def test_failed_archive_is_auto_retried_on_next_pass(client, monkeypatch):
    build_history(client, "arc-f2")
    m = mgr(client)
    rv = create_resource_archive(client, "arc-f2", "k1", head=True)
    aid = rv.get_json()["archive_id"]

    monkeypatch.setattr(
        m, "_finalize_locked",
        lambda _aid: (_ for _ in ()).throw(RuntimeError("boom")))
    m.process_pending()
    assert client.get(f"/audit/archives/{aid}").get_json()["status"] == "failed"
    monkeypatch.undo()

    m.process_pending()  # 无需手动复位，下一轮处理自动重试
    st = client.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "completed"
    assert st["attempts"] == 2  # 首次失败 + 自动重试各计一次


# ---------------------------------------------------------------------------
# 独立核验：verified / verify_failed（首个差异位置）
# ---------------------------------------------------------------------------

def test_verify_marks_archive_verified(client):
    build_history(client, "arc-v")
    rv = create_resource_archive(client, "arc-v", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    finish(client, aid)

    body = client.post(f"/audit/archives/{aid}/verify").get_json()
    assert body["verify_status"] == "verified"
    assert body["first_divergence"] is None
    st = client.get(f"/audit/archives/{aid}").get_json()
    assert st["verify_status"] == "verified"
    assert st["verified_at_ms"] is not None


def test_verify_detects_deleted_history_event_with_first_divergence(client):
    build_history(client, "arc-t")
    ev = client.get("/resources/arc-t/audit/events").get_json()["events"]
    rv = create_resource_archive(client, "arc-t", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    finish(client, aid)
    assert client.post(f"/audit/archives/{aid}/verify").get_json()[
        "verify_status"] == "verified"

    # 删掉一条原始事件（模拟审计历史被删改）
    victim = ev[2]["seq"]
    conn = sqlite3.connect(db_path(client))
    conn.execute("DELETE FROM lease_events WHERE seq=?", (victim,))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/archives/{aid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["section"] == "events"
    assert div["seq"] == victim
    assert div["archived"] == victim
    # 首个差异位置持久化在归档上，可查
    st = client.get(f"/audit/archives/{aid}").get_json()
    assert st["verify_status"] == "verify_failed"
    assert st["verify_detail"]["seq"] == victim
    assert st["verify_detail"]["section"] == "events"


def test_verify_detects_tampered_archive_content(client):
    build_history(client, "arc-c")
    rv = create_resource_archive(client, "arc-c", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    finish(client, aid)

    # 篡改落库的归档文档（不同步改校验值）
    content = download(client, aid)
    content["replay_state"]["resource"]["value"] = "forged"
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE archives SET content=? WHERE archive_id=?",
        (json.dumps(content, ensure_ascii=False, sort_keys=True), aid))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/archives/{aid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    assert body["first_divergence"]["section"] == "checksum"


def test_verify_detects_forged_content_with_matching_checksum(client):
    build_history(client, "arc-c2")
    rv = create_resource_archive(client, "arc-c2", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    finish(client, aid)

    # 篡改文档并重算校验值（连校验值一起伪造）
    content = download(client, aid)
    content["replay_state"]["resource"]["value"] = "forged"
    forged_sha = sha_of(content)
    content["content_sha256"] = forged_sha
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE archives SET content=?, content_sha256=? WHERE archive_id=?",
        (json.dumps(content, ensure_ascii=False, sort_keys=True),
         forged_sha, aid))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/archives/{aid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    # 校验值自洽但派生内容对不上：回放状态无法由冻结事件重算得到
    assert div["section"] == "replay_state"
    assert div["path"] == "replay_state.resource.value"
    assert div["archived"] == "forged"
    assert div["recomputed"] == "v3"


def test_verify_detects_tampered_frozen_event(client):
    build_history(client, "arc-fe")
    rv = create_resource_archive(client, "arc-fe", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    finish(client, aid)

    # 篡改冻结副本里的一条事件
    payload = download(client, aid)["events"][0]
    payload["holder"] = "forged-holder"
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE archive_events SET payload=? WHERE archive_id=? AND seq=?",
        (json.dumps(payload, ensure_ascii=False, sort_keys=True),
         aid, payload["seq"]))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/archives/{aid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["section"] == "events"
    assert div["path"] == "events[0].holder"
    assert div["archived"] == "node-1"
    assert div["recomputed"] == "forged-holder"


# ---------------------------------------------------------------------------
# 只读边界：归档/下载/核验绝不修改运行中的租约、委托与原始历史
# ---------------------------------------------------------------------------

def test_archive_ops_never_mutate_leases_delegations_or_history(client):
    lease, new_lease, cid, cid2, _ = build_history(client, "arc-ro")
    store = store_of(client)

    def snapshot():
        with store._lock:
            ev = store._conn.execute(
                "SELECT MAX(seq) m, COUNT(*) c FROM lease_events").fetchone()
            leases = [tuple(r) for r in store._conn.execute(
                "SELECT id, state, generation FROM leases ORDER BY id")]
            dels = [tuple(r) for r in store._conn.execute(
                "SELECT credential_id, state, end_reason FROM delegations "
                "ORDER BY credential_id")]
            writes = store._conn.execute(
                "SELECT COUNT(*) c FROM writes").fetchone()["c"]
            res = store._conn.execute(
                "SELECT current_gen, last_passed_gen, value FROM resources "
                "WHERE resource='arc-ro'").fetchone()
        return (ev["m"], ev["c"]), leases, dels, writes, tuple(res)

    before = snapshot()
    # 资源归档全流程
    rv = create_resource_archive(client, "arc-ro", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    finish(client, aid)
    download(client, aid)
    client.post(f"/audit/archives/{aid}/verify")
    # 凭证归档全流程
    rv2 = create_credential_archive(client, cid, "k2", head=True)
    aid2 = rv2.get_json()["archive_id"]
    finish(client, aid2)
    download(client, aid2)
    client.post(f"/audit/archives/{aid2}/verify")
    # 列表与状态查询
    client.get("/audit/archives")
    client.get(f"/audit/archives/{aid}")

    assert snapshot() == before
    # 当前租约仍然可写：归档没有碰运行态
    assert write(client, new_lease, "still-alive").status_code == 201


# ---------------------------------------------------------------------------
# 显式错误
# ---------------------------------------------------------------------------

def test_create_errors_are_explicit(client):
    build_history(client, "arc-err")
    ev = client.get("/resources/arc-err/audit/events").get_json()["events"]
    hi = ev[-1]["seq"]

    # 节点选择器缺失 / 同时给多个
    assert create_resource_archive(client, "arc-err", "k1").status_code == 400
    rv = client.post("/audit/archives", json={
        "scope": "resource", "resource": "arc-err", "idempotency_key": "k1",
        "head": True, "at_seq": 1})
    assert rv.status_code == 400
    # 缺幂等键
    rv = client.post("/audit/archives", json={
        "scope": "resource", "resource": "arc-err", "head": True})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "bad_request"
    # 非法 scope
    rv = client.post("/audit/archives", json={
        "scope": "everything", "resource": "arc-err",
        "idempotency_key": "k1", "head": True})
    assert rv.status_code == 400
    # 资源无历史 → 404
    rv = create_resource_archive(client, "ghost", "k1", head=True)
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "history_not_found"
    # 凭证不存在 → 404
    rv = create_credential_archive(client, "nope", "k1", head=True)
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "credential_not_found"
    # 节点越界 → 416
    rv = create_resource_archive(client, "arc-err", "k2", at_seq=hi + 100)
    assert rv.status_code == 416
    assert rv.get_json()["error"] == "node_out_of_range"


def test_status_download_verify_retry_guards(client):
    build_history(client, "arc-g")
    # 不存在的归档：404
    assert client.get("/audit/archives/nope").status_code == 404
    assert client.get("/audit/archives/nope/download").status_code == 404
    assert client.post("/audit/archives/nope/verify").status_code == 404
    assert client.post("/audit/archives/nope/retry").status_code == 404

    rv = create_resource_archive(client, "arc-g", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    # 未完成：下载/核验 409，重试 409
    rv = client.get(f"/audit/archives/{aid}/download")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "archive_not_ready"
    assert client.post(f"/audit/archives/{aid}/verify").status_code == 409
    rv = client.post(f"/audit/archives/{aid}/retry")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "archive_bad_state"
    # 完成后：下载 200，重试仍是 409（非 failed 不需要重试）
    finish(client, aid)
    assert client.get(f"/audit/archives/{aid}/download").status_code == 200
    assert client.post(f"/audit/archives/{aid}/retry").status_code == 409


def test_list_archives_with_filters(client):
    build_history(client, "arc-l1")
    lease = acquire(client, "arc-l2", "node-1")
    assert write(client, lease, "x").status_code == 201
    a1 = create_resource_archive(
        client, "arc-l1", "k1", head=True).get_json()["archive_id"]
    finish(client, a1)
    a2 = create_resource_archive(
        client, "arc-l2", "k2", head=True).get_json()["archive_id"]

    all_a = client.get("/audit/archives").get_json()["archives"]
    assert {a["archive_id"] for a in all_a} == {a1, a2}
    by_res = client.get("/audit/archives?resource=arc-l1").get_json()
    assert [a["archive_id"] for a in by_res["archives"]] == [a1]
    completed = client.get("/audit/archives?status=completed").get_json()
    assert [a["archive_id"] for a in completed["archives"]] == [a1]
    pending = client.get("/audit/archives?status=pending").get_json()
    assert [a["archive_id"] for a in pending["archives"]] == [a2]
    assert client.get("/audit/archives?status=bogus").status_code == 400


# ---------------------------------------------------------------------------
# 后台 worker 端到端 & 重启后归档/核验结果一致
# ---------------------------------------------------------------------------

def test_background_worker_completes_archive_end_to_end(tmp_path):
    db = str(tmp_path / "arc-worker.db")
    app = create_app(db, start_ticker=False)  # 归档 worker 默认开启
    c = app.test_client()
    build_history(c, "arc-bg")
    rv = create_resource_archive(c, "arc-bg", "k1", head=True)
    assert rv.status_code == 201
    aid = rv.get_json()["archive_id"]

    deadline = time.time() + 10
    while time.time() < deadline:
        st = c.get(f"/audit/archives/{aid}").get_json()
        if st["status"] == "completed":
            break
        time.sleep(0.05)
    else:
        raise AssertionError("后台 worker 未在限定时间内完成归档")
    body = c.post(f"/audit/archives/{aid}/verify").get_json()
    assert body["verify_status"] == "verified"


def test_archive_and_verify_status_survive_restart(tmp_path):
    db = str(tmp_path / "arc-persist.db")
    app1 = create_app(db, start_ticker=False, start_archive_worker=False)
    c1 = app1.test_client()
    build_history(c1, "arc-p")
    rv = create_resource_archive(c1, "arc-p", "k1", head=True)
    aid = rv.get_json()["archive_id"]
    finish(c1, aid)
    d1 = c1.get(f"/audit/archives/{aid}/download").data
    assert c1.post(f"/audit/archives/{aid}/verify").get_json()[
        "verify_status"] == "verified"

    # ---- 重启：归档文档逐字节一致，核验标记不丢 ----
    app2 = create_app(db, start_ticker=False, start_archive_worker=False)
    c2 = app2.test_client()
    d2 = c2.get(f"/audit/archives/{aid}/download").data
    assert d1 == d2
    st = c2.get(f"/audit/archives/{aid}").get_json()
    assert st["status"] == "completed"
    assert st["verify_status"] == "verified"
    assert c2.post(f"/audit/archives/{aid}/verify").get_json()[
        "verify_status"] == "verified"
