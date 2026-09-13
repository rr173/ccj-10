"""审计证据包：冻结清单、分块续跑、幂等冲突、只读下载、独立核验。

覆盖：
- 资源归档与凭证归档混合组合的 创建-生成-下载-组合摘要-总校验值 闭环；
- 空组合、重复归档（含不同收录方式）边界；
- 同组归档+同顺序+同幂等键重复创建返回同一份；换归档/换顺序/换收录方式
  /换键 各自的明确冲突（409）；
- 生成期间源归档被再次核验、产生新归档都不改变已冻结的证据包内容；
- 分块进度逐块可见、生成中断（finalize 崩溃）后从已保存进度续跑、
  失败重试不重复写入、服务重启后续跑且文档逐字节一致；
- 独立核验：通过；源归档不存在、源内容哈希被改、下载后篡改文档/冻结
  载荷/组合顺序，均给出首个差异的归档标识、字段路径与双方值；
- 证据包全流程不修改租约、委托、原始审计历史与源归档。
"""

import hashlib
import json
import sqlite3
import time

from app.app import create_app
from conftest import acquire, write
from test_archive import create_credential_archive, create_resource_archive
from test_audit import build_history


# ---------------------------------------------------------------------------
# 夹具与辅助
# ---------------------------------------------------------------------------

def _client(tmp_path, *, worker=False, name="evidence.db"):
    app = create_app(str(tmp_path / name), start_ticker=False,
                     enable_debug_api=True, start_archive_worker=worker)
    app.config.update(TESTING=True)
    return app.test_client()


def mgr(client):
    return client.application.extensions["evidence"]


def store_of(client):
    return client.application.extensions["store"]


def db_path(client):
    store = store_of(client)
    with store._lock:
        return store._conn.execute(
            "PRAGMA database_list").fetchone()[2]


def _finish_archive(client, aid):
    m = client.application.extensions["archive"]
    for _ in range(200):
        m.process_pending()
        st = client.get(f"/audit/archives/{aid}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("源归档未能完成")


def make_archives(client, resource="ev-1"):
    """构造一个资源归档与一个凭证归档，返回 (resource_aid, credential_aid, ctx)。"""
    lease, new_lease, cid, cid2, _ = build_history(client, resource)
    rv = create_resource_archive(client, resource, "res-key", head=True)
    assert rv.status_code == 201, rv.get_json()
    res_aid = rv.get_json()["archive_id"]
    _finish_archive(client, res_aid)

    rv = create_credential_archive(client, cid, "cred-key", head=True)
    assert rv.status_code == 201, rv.get_json()
    cred_aid = rv.get_json()["archive_id"]
    _finish_archive(client, cred_aid)
    return res_aid, cred_aid, (lease, new_lease, cid, cid2)


def create_package(client, archives, key, **extra):
    payload = {"archives": archives, "idempotency_key": key}
    payload.update(extra)
    return client.post("/audit/evidence", json=payload)


def finish(client, package_id):
    """显式驱动后台生成直到完成，返回最终状态视图。"""
    m = mgr(client)
    for _ in range(500):
        m.process_pending()
        st = client.get(f"/audit/evidence/{package_id}").get_json()
        if st["status"] == "completed":
            return st
        assert st["status"] != "failed", st
    raise AssertionError("证据包未能在限定轮次内完成")


def download(client, package_id):
    rv = client.get(f"/audit/evidence/{package_id}/download")
    assert rv.status_code == 200, rv.get_json()
    return json.loads(rv.data)


def sha_of(content):
    core = {k: v for k, v in content.items() if k != "content_sha256"}
    return hashlib.sha256(
        json.dumps(core, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).hexdigest()


def chain_of(content):
    seed = hashlib.sha256(b"lease-audit-evidence-chain-v1").hexdigest()
    digest = seed
    for m in content["manifest"]:
        h = hashlib.sha256()
        h.update(digest.encode("ascii"))
        h.update(b"|")
        h.update(m["archive_id"].encode("utf-8"))
        h.update(b"|")
        h.update(m["frozen_sha256"].encode("ascii"))
        digest = h.hexdigest()
    return digest


def frozen_positions(client, package_id):
    store = store_of(client)
    with store._lock:
        rows = store._conn.execute(
            "SELECT position FROM evidence_entry_contents WHERE package_id=? "
            "ORDER BY position", (package_id,)).fetchall()
    return [r["position"] for r in rows]


# ---------------------------------------------------------------------------
# 创建 → 生成 → 下载 → 组合摘要 / 总校验值（资源+凭证混合）
# ---------------------------------------------------------------------------

def test_mixed_resource_and_credential_archives_full_cycle(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-mix")

    rv = create_package(client, [res_aid, cred_aid], "pkg-1",
                        metadata={"case": "mixed", "operator": "admin"})
    assert rv.status_code == 201, rv.get_json()
    body = rv.get_json()
    assert body["replayed"] is False
    assert body["status"] == "pending"
    assert body["progress"] == {
        "processed_entries": 0, "total_entries": 2,
        "remaining_entries": 2, "percent": 0.0, "done": False}
    pid = body["package_id"]
    assert body["manifest_fingerprint"]

    st = finish(client, pid)
    assert st["progress"]["done"] is True
    assert st["progress"]["percent"] == 100.0
    assert st["combination_digest"]
    assert st["content_sha256"]
    assert st["verify_status"] == "unverified"
    assert st["completed_at_ms"] is not None

    content = download(client, pid)
    assert content["kind"] == "lease_audit_evidence_package"
    assert content["package_id"] == pid
    assert content["idempotency_key"] == "pkg-1"
    assert content["metadata"] == {"case": "mixed", "operator": "admin"}
    assert content["snapshot_seq"] == body["snapshot_seq"]
    # 清单：顺序、归档标识、内容校验值、收录方式、稳定引用
    assert [m["position"] for m in content["manifest"]] == [0, 1]
    assert [m["archive_id"] for m in content["manifest"]] == [
        res_aid, cred_aid]
    assert all(m["include_mode"] == "content" for m in content["manifest"])
    assert all(m["source_sha256"] for m in content["manifest"])
    assert content["manifest"][0]["reference"]["scope"] == "resource"
    assert content["manifest"][1]["reference"]["scope"] == "credential"
    # 原文内嵌，可独立解析
    assert (content["sources"][0]["source_archive_content"]["scope"]
            == "resource")
    assert (content["sources"][1]["source_archive_content"]["scope"]
            == "credential")
    # 组合摘要与总校验值均可独立复算
    assert content["combination"] == {
        "algorithm": "sha256-chain-v1", "entries": 2,
        "ordered_archive_ids": [res_aid, cred_aid],
        "digest": content["combination"]["digest"]}
    assert content["combination"]["digest"] == chain_of(content)
    assert content["content_sha256"] == sha_of(content)
    # 下载响应头带总校验值，且原文逐字节稳定
    rv = client.get(f"/audit/evidence/{pid}/download")
    assert rv.headers["X-Evidence-SHA256"] == content["content_sha256"]
    assert json.loads(rv.data) == content

    # 独立核验通过
    result = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert result["verify_status"] == "verified"
    assert result["first_divergence"] is None
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["verify_status"] == "verified"
    assert st["verified_at_ms"] is not None


def test_reference_mode_embeds_only_stable_reference(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-ref")
    rv = create_package(
        client,
        [{"archive_id": res_aid, "include": "reference"}, cred_aid],
        "pkg-ref")
    pid = rv.get_json()["package_id"]
    finish(client, pid)
    content = download(client, pid)

    assert content["manifest"][0]["include_mode"] == "reference"
    assert content["manifest"][1]["include_mode"] == "content"
    ref_source = content["sources"][0]
    assert "source_archive_content" not in ref_source
    assert ref_source["source_sha256"] == content["manifest"][0]["source_sha256"]
    # 稳定引用足以定位源归档与其冻结节点
    ref = content["manifest"][0]["reference"]
    assert ref["archive_id"] == res_aid
    assert ref["location"] == f"/audit/archives/{res_aid}/download"
    assert ref["content_sha256"]
    # 第二份仍是原文
    assert content["sources"][1]["source_archive_content"]["archive_id"] == cred_aid
    assert client.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"


# ---------------------------------------------------------------------------
# 空组合与重复归档
# ---------------------------------------------------------------------------

def test_empty_combination_is_allowed_and_verifiable(client):
    rv = create_package(client, [], "empty-pkg", metadata={"note": "empty"})
    assert rv.status_code == 201, rv.get_json()
    pid = rv.get_json()["package_id"]
    assert rv.get_json()["progress"] == {
        "processed_entries": 0, "total_entries": 0,
        "remaining_entries": 0, "percent": 100.0, "done": True}

    st = finish(client, pid)
    assert st["status"] == "completed"
    content = download(client, pid)
    assert content["manifest"] == []
    assert content["sources"] == []
    assert content["combination"]["entries"] == 0
    assert content["combination"]["ordered_archive_ids"] == []
    # 空组合也有确定的组合摘要（链初值）与总校验值
    assert content["combination"]["digest"] == chain_of(content)
    assert content["content_sha256"] == sha_of(content)
    assert client.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"

    # 空组合同键重放
    rv2 = create_package(client, [], "empty-pkg")
    assert rv2.status_code == 200
    assert rv2.get_json()["package_id"] == pid
    # 同键但改成非空：冲突
    res_aid, _, _ = make_archives(client, "ev-empty-src")
    rv3 = create_package(client, [res_aid], "empty-pkg")
    assert rv3.status_code == 409
    assert rv3.get_json()["error"] == "evidence_id_conflict"
    diff = rv3.get_json()["first_difference"]
    assert diff["path"] == "archives[0]"


def test_duplicate_archives_allowed_with_positions(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-dup")
    # 同一归档在不同位置重复收录，且分别用不同收录方式
    rv = create_package(client, [
        res_aid,
        cred_aid,
        {"archive_id": res_aid, "include": "reference"},
        res_aid,
    ], "dup-pkg")
    assert rv.status_code == 201, rv.get_json()
    pid = rv.get_json()["package_id"]
    st = finish(client, pid)
    assert st["progress"]["total_entries"] == 4
    content = download(client, pid)
    assert [m["archive_id"] for m in content["manifest"]] == \
        [res_aid, cred_aid, res_aid, res_aid]
    assert [m["position"] for m in content["manifest"]] == [0, 1, 2, 3]
    assert content["combination"]["ordered_archive_ids"] == \
        [res_aid, cred_aid, res_aid, res_aid]
    assert content["combination"]["digest"] == chain_of(content)
    assert client.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"

    # 删掉一个重复条目（保持前 3 个位置的归档与收录方式一致）：
    # 首个差异落在清单长度上
    rv2 = create_package(client, [
        res_aid, cred_aid, {"archive_id": res_aid, "include": "reference"}],
        "dup-pkg")
    assert rv2.status_code == 409
    assert rv2.get_json()["first_difference"]["field"] == "length"


# ---------------------------------------------------------------------------
# 幂等与冲突
# ---------------------------------------------------------------------------

def test_same_archives_order_and_key_return_same_package(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-idem")
    r1 = create_package(client, [res_aid, cred_aid], "same-key")
    assert r1.status_code == 201
    pid = r1.get_json()["package_id"]
    finish(client, pid)

    # 完全相同的请求（含收录方式默认值）重放
    r2 = create_package(client, [
        {"archive_id": res_aid, "include": "content"}, cred_aid], "same-key")
    assert r2.status_code == 200
    assert r2.get_json()["replayed"] is True
    assert r2.get_json()["package_id"] == pid


def test_same_key_different_archive_reports_conflict_with_diff(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-c1")
    create_package(client, [res_aid, cred_aid], "k")
    # 换第二个归档
    rv = create_package(client, [res_aid, res_aid], "k")
    assert rv.status_code == 409
    body = rv.get_json()
    assert body["error"] == "evidence_id_conflict"
    assert body["package_id"]
    diff = body["first_difference"]
    assert diff["position"] == 1
    assert diff["path"] == "archives[1].archive_id"
    assert diff["existing"] == cred_aid
    assert diff["requested"] == res_aid


def test_same_key_different_order_reports_conflict(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-c2")
    create_package(client, [res_aid, cred_aid], "k")
    rv = create_package(client, [cred_aid, res_aid], "k")
    assert rv.status_code == 409
    diff = rv.get_json()["first_difference"]
    assert diff["path"] == "archives[0].archive_id"
    assert diff["existing"] == res_aid
    assert diff["requested"] == cred_aid


def test_same_key_different_include_mode_reports_conflict(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-c3")
    create_package(client, [res_aid, cred_aid], "k")
    rv = create_package(
        client, [{"archive_id": res_aid, "include": "reference"}, cred_aid],
        "k")
    assert rv.status_code == 409
    diff = rv.get_json()["first_difference"]
    assert diff["path"] == "archives[0].include"
    assert diff["existing"] == "content"
    assert diff["requested"] == "reference"


def test_same_manifest_different_key_is_manifest_conflict(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-c4")
    r1 = create_package(client, [res_aid, cred_aid], "key-A")
    assert r1.status_code == 201
    pid = r1.get_json()["package_id"]
    # 换键：不允许为同一套证据造第二份"原件"
    r2 = create_package(client, [res_aid, cred_aid], "key-B")
    assert r2.status_code == 409
    body = r2.get_json()
    assert body["error"] == "evidence_manifest_conflict"
    assert body["package_id"] == pid
    assert body["existing_idempotency_key"] == "key-A"


def test_concurrent_creates_with_same_key_yield_one_package(tmp_path):
    import threading
    import urllib.request
    from wsgiref.simple_server import make_server

    db = str(tmp_path / "ev-conc.db")
    app = create_app(db, start_ticker=False, start_archive_worker=False)
    c = app.test_client()
    res_aid, cred_aid, _ = make_archives(c, "ev-cc")

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    results, errors = [], []

    def worker():
        try:
            payload = json.dumps({
                "archives": [res_aid, cred_aid],
                "idempotency_key": "race-pkg-key",
            }).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/audit/evidence", data=payload,
                method="POST",
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
    assert {r[1]["package_id"] for r in results}.__len__() == 1
    assert {r[0] for r in results} <= {200, 201}
    listed = c.get("/audit/evidence").get_json()["packages"]
    assert [p["idempotency_key"] for p in listed].count("race-pkg-key") == 1


def test_order_matters_for_manifest_fingerprint(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-order")
    r1 = create_package(client, [res_aid, cred_aid], "ord-1")
    r2 = create_package(client, [cred_aid, res_aid], "ord-2")
    assert r1.status_code == 201 and r2.status_code == 201
    p1, p2 = r1.get_json()["package_id"], r2.get_json()["package_id"]
    assert p1 != p2
    finish(client, p1)
    finish(client, p2)
    c1, c2 = download(client, p1), download(client, p2)
    # 顺序不同 → 组合摘要不同；总校验值不同；每份源哈希仍一致
    assert c1["combination"]["digest"] != c2["combination"]["digest"]
    assert c1["content_sha256"] != c2["content_sha256"]
    assert [m["source_sha256"] for m in c1["manifest"]] == \
        [m["source_sha256"] for m in reversed(c2["manifest"])]


def test_create_validation_errors(client):
    res_aid, _, _ = make_archives(client, "ev-val")
    # archives 不是数组
    assert create_package(client, res_aid, "k").status_code == 400
    # 条目为空串/空对象
    assert create_package(client, [""], "k").status_code == 400
    assert create_package(client, [{}], "k").status_code == 400
    # 非法 include
    rv = create_package(client, [{"archive_id": res_aid, "include": "all"}],
                        "k")
    assert rv.status_code == 400
    # 缺幂等键 / 空白键
    rv = client.post("/audit/evidence", json={"archives": [res_aid]})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "bad_request"
    rv = create_package(client, [res_aid], "   ")
    assert rv.status_code == 400
    # 非法 metadata
    rv = create_package(client, [res_aid], "k", metadata=[1, 2])
    assert rv.status_code == 400


def test_create_rejects_missing_or_incomplete_source(client):
    res_aid, _, _ = make_archives(client, "ev-src")
    # 新建一个未完成的归档作为源
    rv = create_resource_archive(client, "ev-src", "unfinished", head=True)
    pending_aid = rv.get_json()["archive_id"]

    rv = create_package(client, ["no-such-archive"], "k")
    assert rv.status_code == 404
    assert rv.get_json()["error"] == "evidence_source_not_found"
    assert rv.get_json()["position"] == 0

    rv = create_package(client, [res_aid, pending_aid], "k")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "evidence_source_not_ready"
    assert rv.get_json()["position"] == 1


# ---------------------------------------------------------------------------
# 进度、分块、中断恢复、失败重试不重复写入
# ---------------------------------------------------------------------------

def test_chunk_progress_is_visible_and_resumes(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-chunk")
    # 再加两份归档，凑 4 个条目
    rv = create_resource_archive(client, "ev-chunk", "r2", head=True)
    a3 = rv.get_json()["archive_id"]
    _finish_archive(client, a3)
    rv = create_resource_archive(client, "ev-chunk", "r3", head=True)
    a4 = rv.get_json()["archive_id"]
    _finish_archive(client, a4)

    m = mgr(client)
    m.chunk_size = 2
    rv = create_package(client, [res_aid, cred_aid, a3, a4], "chunk-k")
    pid = rv.get_json()["package_id"]
    assert rv.get_json()["progress"]["total_entries"] == 4

    seen = []
    for _ in range(10):
        m.process_pending(max_chunks_per_package=1)
        st = client.get(f"/audit/evidence/{pid}").get_json()
        seen.append((st["status"], st["progress"]["processed_entries"]))
        if st["status"] == "completed":
            break
    # 每块 2 条：第一块后 building/2；第二块冻结完 4 条并在同轮 finalize
    assert seen == [("building", 2), ("completed", 4)]
    # 冻结内容无重复写入
    assert frozen_positions(client, pid) == [0, 1, 2, 3]


def test_failed_finalize_resumes_without_duplicate_writes(client, monkeypatch):
    res_aid, cred_aid, _ = make_archives(client, "ev-fail")
    rv = create_package(client, [res_aid, cred_aid], "fail-k")
    pid = rv.get_json()["package_id"]

    def boom(_package_id):
        raise RuntimeError("simulated evidence finalize crash")

    monkeypatch.setattr(mgr(client), "_finalize_locked", boom)
    mgr(client).process_pending()
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "failed"
    assert "simulated evidence finalize crash" in st["error"]
    # 条目进度已保留
    assert st["progress"]["processed_entries"] == 2
    monkeypatch.undo()

    # 自动重试（无需手动复位）：从已保存进度继续
    mgr(client).process_pending()
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "completed"
    assert st["attempts"] == 2
    assert frozen_positions(client, pid) == [0, 1]

    # 手动 retry 对已完成包是 409
    rv = client.post(f"/audit/evidence/{pid}/retry")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "evidence_bad_state"


def test_failed_package_manual_retry_keeps_progress(client, monkeypatch):
    res_aid, cred_aid, _ = make_archives(client, "ev-fail2")
    rv = create_package(client, [res_aid, cred_aid], "fail2-k")
    pid = rv.get_json()["package_id"]

    calls = {"n": 0}

    def flaky(_pid):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom once")

    # 冻结阶段就失败（第一次调用 _freeze_chunk_locked 即炸）
    monkeypatch.setattr(mgr(client), "_freeze_chunk_locked", flaky)
    mgr(client).process_pending()
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "failed"
    assert st["progress"]["processed_entries"] == 0
    monkeypatch.undo()

    rv = client.post(f"/audit/evidence/{pid}/retry")
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "pending"
    assert rv.get_json()["attempts"] == 0
    mgr(client).process_pending()
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "completed"
    assert frozen_positions(client, pid) == [0, 1]


def test_restart_resumes_from_saved_progress_and_bytes_match(tmp_path):
    db = str(tmp_path / "ev-restart.db")
    app1 = create_app(db, start_ticker=False, start_archive_worker=False)
    c1 = app1.test_client()
    res_aid, cred_aid, _ = make_archives(c1, "ev-r")
    m1 = app1.extensions["evidence"]
    m1.chunk_size = 1
    rv = create_package(c1, [res_aid, cred_aid, res_aid], "restart-k")
    pid = rv.get_json()["package_id"]
    total = rv.get_json()["progress"]["total_entries"]

    m1.process_pending(max_chunks_per_package=1)  # 冻结一个条目后"崩溃"
    st = c1.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "building"
    assert 0 < st["progress"]["processed_entries"] < total

    # ---- 重启：同库新进程，从已保存进度继续 ----
    app2 = create_app(db, start_ticker=False, start_archive_worker=False)
    c2 = app2.test_client()
    st = c2.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "building"
    app2.extensions["evidence"].process_pending()
    st = c2.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "completed"
    # 无重复、无缺口
    store2 = app2.extensions["store"]
    with store2._lock:
        positions = [r["position"] for r in store2._conn.execute(
            "SELECT position FROM evidence_entry_contents WHERE package_id=? "
            "ORDER BY position", (pid,)).fetchall()]
    assert positions == list(range(total))
    content = json.loads(
        c2.get(f"/audit/evidence/{pid}/download").data)
    assert content["combination"]["digest"] == chain_of(content)
    assert content["content_sha256"] == sha_of(content)
    # 核验标记与文档在再次重启后保持
    assert c2.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"
    app3 = create_app(db, start_ticker=False, start_archive_worker=False)
    c3 = app3.test_client()
    st = c3.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "completed"
    assert st["verify_status"] == "verified"
    d3 = c3.get(f"/audit/evidence/{pid}/download").data
    assert d3 == c2.get(f"/audit/evidence/{pid}/download").data


def test_background_worker_completes_package_end_to_end(tmp_path):
    c = _client(tmp_path, worker=True, name="ev-worker.db")
    res_aid, cred_aid, _ = make_archives(c, "ev-bg")
    rv = create_package(c, [res_aid, cred_aid], "bg-k")
    assert rv.status_code == 201
    pid = rv.get_json()["package_id"]
    deadline = time.time() + 10
    while time.time() < deadline:
        st = c.get(f"/audit/evidence/{pid}").get_json()
        if st["status"] == "completed":
            break
        time.sleep(0.05)
    else:
        raise AssertionError("后台 worker 未在限定时间内完成证据包")
    assert c.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"


# ---------------------------------------------------------------------------
# 冻结性：生成期间源归档被再核验/产生新归档都不改变证据包
# ---------------------------------------------------------------------------

def test_source_reverify_and_new_archives_do_not_change_package(client):
    res_aid, cred_aid, ctx = make_archives(client, "ev-freeze")
    lease, new_lease, cid, _ = ctx
    m = mgr(client)
    m.chunk_size = 1

    rv = create_package(client, [res_aid, cred_aid], "freeze-k")
    pid = rv.get_json()["package_id"]
    m.process_pending(max_chunks_per_package=1)  # 只冻结第一份
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "building"
    assert st["progress"]["processed_entries"] == 1

    # 生成期间：源归档被再次核验（verify 标记变化）
    assert client.post(f"/audit/archives/{res_aid}/verify").status_code == 200
    # 源资源上产生新的历史并再生成两份新归档（不同键）
    assert write(client, new_lease, "after-evidence-1").status_code == 201
    rv = create_resource_archive(client, "ev-freeze", "res-later", head=True)
    later_aid = rv.get_json()["archive_id"]
    _finish_archive(client, later_aid)
    rv = create_resource_archive(client, "ev-freeze", "res-later2", head=True)
    _finish_archive(client, rv.get_json()["archive_id"])

    st = finish(client, pid)
    content = download(client, pid)
    # 冻结的仍是创建时的两份归档与各自内容哈希，新归档没有混入
    assert [m["archive_id"] for m in content["manifest"]] == [
        res_aid, cred_aid]
    assert content["snapshot_seq"] == st["snapshot_seq"]
    assert max(m["reference"]["node_seq"] for m in content["manifest"]) < \
        client.get(f"/audit/archives/{later_aid}").get_json()["node_seq"]
    assert client.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"


def test_tampered_source_during_generation_fails_package(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-swap")
    m = mgr(client)
    m.chunk_size = 1
    rv = create_package(client, [res_aid, cred_aid], "swap-k")
    pid = rv.get_json()["package_id"]
    m.process_pending(max_chunks_per_package=1)  # 冻结第一份后中断

    # 源归档内容哈希被改动（第二份）：续跑必须失败，且不能静默收录
    conn = sqlite3.connect(db_path(client))
    row = conn.execute(
        "SELECT content FROM archives WHERE archive_id=?", (cred_aid,)
    ).fetchone()
    doc = json.loads(row[0])
    doc["node"]["holder"] = "forged"
    conn.execute(
        "UPDATE archives SET content=?, content_sha256=? WHERE archive_id=?",
        (json.dumps(doc, ensure_ascii=False, sort_keys=True),
         "deadbeef" * 8, cred_aid))
    conn.commit()
    conn.close()

    m.process_pending()
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["status"] == "failed"
    detail = st["error_detail"]
    assert detail["archive_id"] == cred_aid
    assert detail["position"] == 1
    assert detail["path"] == "sources[1].source_sha256"
    assert detail["recomputed"] == "deadbeef" * 8
    assert detail["archived"]
    # 已冻结的第一份进度保留
    assert st["progress"]["processed_entries"] == 1


# ---------------------------------------------------------------------------
# 独立核验：源归档自身核验失败（verify_failed）绝不能把证据包判为通过
# ---------------------------------------------------------------------------

def _fail_source_archive(client, aid, *, seq=None):
    """删改一条原始审计历史事件，让源归档的独立核验落到 verify_failed。"""
    conn = sqlite3.connect(db_path(client))
    if seq is None:
        row = conn.execute(
            "SELECT seq FROM lease_events ORDER BY seq ASC LIMIT 1").fetchone()
        seq = row[0]
    conn.execute(
        "UPDATE lease_events SET holder='forged-holder' WHERE seq=?", (seq,))
    conn.commit()
    conn.close()
    body = client.post(f"/audit/archives/{aid}/verify").get_json()
    assert body["verify_status"] == "verify_failed", body
    return body["first_divergence"]


def test_verify_fails_when_source_archive_is_verify_failed(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vsrcfail")
    rv = create_package(client, [res_aid, cred_aid], "vsrcfail-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)
    # 先证明确实曾经可以核验通过
    assert client.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"

    # 源归档（cred）自身独立核验失败：证据包核验必须失败
    src_div = _fail_source_archive(client, cred_aid)

    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["section"] == "sources"
    assert div["archive_id"] == cred_aid
    assert div["position"] == 1
    assert div["path"] == "sources[1].verify_status"
    assert div["archived"] == "verified"
    assert div["recomputed"] == "verify_failed"
    # 指出源归档自身的首个差异位置，便于定位不可信内容
    assert div["source_first_divergence"]["path"] == src_div["path"]
    # 失败结果持久化在证据包上（重启不丢）
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["verify_status"] == "verify_failed"
    assert st["verify_detail"]["archive_id"] == cred_aid
    assert st["verify_detail"]["source_first_divergence"]["path"] == \
        src_div["path"]


def test_verify_first_failed_source_is_reported_by_position(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vsrcorder")
    # 顺序 [res, cred]：让第 0 份（res）核验失败，首个差异必须落在 position 0，
    # 而不是后面的任何位置
    _fail_source_archive(client, res_aid)
    rv = create_package(client, [res_aid, cred_aid], "vsrcorder-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)
    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["position"] == 0
    assert div["archive_id"] == res_aid
    assert div["path"] == "sources[0].verify_status"


def test_verify_failed_source_blocks_reference_mode_too(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vsrcref")
    _fail_source_archive(client, res_aid)
    rv = create_package(
        client,
        [{"archive_id": res_aid, "include": "reference"}, cred_aid],
        "vsrcref-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)
    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["archive_id"] == res_aid
    assert div["position"] == 0
    assert div["path"] == "sources[0].verify_status"


# ---------------------------------------------------------------------------
# 独立核验：源归档丢失/被改、下载后篡改
# ---------------------------------------------------------------------------

def test_verify_detects_missing_source_archive(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vmiss")
    rv = create_package(client, [res_aid, cred_aid], "vmiss-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)
    assert client.post(f"/audit/evidence/{pid}/verify").get_json()[
        "verify_status"] == "verified"

    conn = sqlite3.connect(db_path(client))
    conn.execute("DELETE FROM archives WHERE archive_id=?", (cred_aid,))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["section"] == "sources"
    assert div["archive_id"] == cred_aid
    assert div["position"] == 1
    assert div["path"] == "sources[1].archive_id"
    assert div["recomputed"] == "<missing>"
    # 差异持久化在证据包上
    st = client.get(f"/audit/evidence/{pid}").get_json()
    assert st["verify_status"] == "verify_failed"
    assert st["verify_detail"]["archive_id"] == cred_aid


def test_verify_detects_changed_source_content_hash(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vchg")
    rv = create_package(client, [res_aid, cred_aid], "vchg-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)

    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE archives SET content_sha256=? WHERE archive_id=?",
        ("0" * 64, res_aid))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["section"] == "sources"
    assert div["archive_id"] == res_aid
    assert div["path"] == "sources[0].source_sha256"
    assert div["recomputed"] == "0" * 64
    assert len(div["archived"]) == 64 and div["archived"] != "0" * 64


def test_verify_detects_tampered_downloaded_document(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vdoc")
    rv = create_package(client, [res_aid, cred_aid], "vdoc-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)

    # 下载后篡改文档（不同步总校验值）
    content = download(client, pid)
    content["metadata"] = {"case": "tampered"}
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE evidence_packages SET content=? WHERE package_id=?",
        (json.dumps(content, ensure_ascii=False, sort_keys=True), pid))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    assert body["first_divergence"]["section"] == "checksum"
    assert body["first_divergence"]["path"] == "content_sha256"


def test_verify_detects_reordered_combination_with_matching_entry_hashes(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vord")
    rv = create_package(client, [res_aid, cred_aid], "vord-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)

    # 连总校验值一起伪造，仅交换组合顺序：文档内部可以做到自洽（链摘要
    # 按新顺序重算），但冻结载荷表仍是按原 position 存放的——组合顺序
    # 完整性核验必然抓到差异，且给出首个不同的归档标识与双方值
    content = download(client, pid)
    content["manifest"].reverse()
    content["sources"].reverse()
    for new_pos, m in enumerate(content["manifest"]):
        m["position"] = new_pos
    content["combination"]["ordered_archive_ids"] = \
        [m["archive_id"] for m in content["manifest"]]
    digest = hashlib.sha256(
        b"lease-audit-evidence-chain-v1").hexdigest()
    for m in content["manifest"]:
        h = hashlib.sha256()
        h.update(digest.encode()); h.update(b"|")
        h.update(m["archive_id"].encode()); h.update(b"|")
        h.update(m["frozen_sha256"].encode())
        digest = h.hexdigest()
    content["combination"]["digest"] = digest
    forged = sha_of(content)
    content["content_sha256"] = forged
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE evidence_packages SET content=?, content_sha256=?, "
        "combination_digest=? WHERE package_id=?",
        (json.dumps(content, ensure_ascii=False, sort_keys=True),
         forged, digest, pid))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    # 冻结载荷表仍按 position 0..N-1 存放原始顺序，文档被交换后在
    # sources[0] 处首次与冻结副本分叉：归档标识是交换后的 cred_aid
    assert div["section"] == "frozen_payload"
    assert div["path"].startswith("sources[0]")
    assert div["archive_id"] == cred_aid


def test_verify_detects_tampered_frozen_payload(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vfrozen")
    rv = create_package(client, [res_aid, cred_aid], "vfrozen-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)

    # 直接篡改冻结载荷副本（如把内嵌原文的 holder 改掉）
    store = store_of(client)
    with store._lock:
        row = store._conn.execute(
            "SELECT payload FROM evidence_entry_contents "
            "WHERE package_id=? AND position=0", (pid,)).fetchone()
    payload = json.loads(row["payload"])
    payload["source_archive_content"]["node"]["holder"] = "forged-node"
    conn = sqlite3.connect(db_path(client))
    conn.execute(
        "UPDATE evidence_entry_contents SET payload=? WHERE package_id=? "
        "AND position=0",
        (json.dumps(payload, ensure_ascii=False, sort_keys=True), pid))
    conn.commit()
    conn.close()

    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    assert div["section"] == "frozen_payload"
    assert div["archive_id"] == res_aid
    assert "source_archive_content" in div["path"]
    # 源资源归档的节点事件是转移后 node-2 的写入（head）
    assert div["archived"] == "node-2"
    assert div["recomputed"] == "forged-node"


def test_verify_detects_embedded_content_drift_from_source(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-vdrift")
    # 用 reference+content 混合，重点测 content 内嵌原文漂移
    rv = create_package(client, [res_aid, cred_aid], "vdrift-k")
    pid = rv.get_json()["package_id"]
    finish(client, pid)
    frozen_sha_res = download(client, pid)["manifest"][0]["source_sha256"]

    # 篡改源归档文档，并把源 content_sha256 重算成自洽值（绕过哈希层）：
    # 内嵌原文与源当前内容的逐字段比对必须报首个差异
    conn = sqlite3.connect(db_path(client))
    row = conn.execute(
        "SELECT content FROM archives WHERE archive_id=?", (res_aid,)
    ).fetchone()
    src = json.loads(row[0])
    src["replay_state"]["resource"]["value"] = "forged-value"
    src_text = json.dumps(src, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
    new_sha = hashlib.sha256(src_text.encode("utf-8")).hexdigest()
    src["content_sha256"] = new_sha
    conn.execute(
        "UPDATE archives SET content=?, content_sha256=? WHERE archive_id=?",
        (json.dumps(src, ensure_ascii=False, sort_keys=True),
         new_sha, res_aid))
    conn.commit()
    conn.close()
    assert new_sha != frozen_sha_res

    body = client.post(f"/audit/evidence/{pid}/verify").get_json()
    assert body["verify_status"] == "verify_failed"
    div = body["first_divergence"]
    # source_sha256 层先抓到（哈希确实变了），这也是首个差异
    assert div["path"] == "sources[0].source_sha256"
    assert div["archived"] == frozen_sha_res
    assert div["recomputed"] == new_sha


# ---------------------------------------------------------------------------
# 只读边界 & 显式错误
# ---------------------------------------------------------------------------

def test_evidence_ops_never_mutate_other_tables(client):
    res_aid, cred_aid, ctx = make_archives(client, "ev-ro")
    lease, new_lease, cid, _ = ctx
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
                "WHERE resource='ev-ro'").fetchone()
            arcs = [tuple(r) for r in store._conn.execute(
                "SELECT archive_id, status, content_sha256, verify_status "
                "FROM archives ORDER BY archive_id")]
            arc_events = store._conn.execute(
                "SELECT COUNT(*) c FROM archive_events").fetchone()["c"]
        return ((ev["m"], ev["c"]), leases, dels, writes, tuple(res),
                arcs, arc_events)

    before = snapshot()
    rv = create_package(client, [res_aid, cred_aid, res_aid], "ro-k",
                        metadata={"x": 1})
    pid = rv.get_json()["package_id"]
    finish(client, pid)
    client.get(f"/audit/evidence/{pid}")
    client.get(f"/audit/evidence/{pid}/download")
    client.post(f"/audit/evidence/{pid}/verify")
    client.get("/audit/evidence")
    client.get(f"/audit/evidence?archive_id={res_aid}")
    assert snapshot() == before
    # 当前租约照常可写：证据包没有碰运行态
    assert write(client, new_lease, "still-alive").status_code == 201


def test_status_download_verify_retry_guards(client):
    assert client.get("/audit/evidence/nope").status_code == 404
    assert client.get("/audit/evidence/nope/download").status_code == 404
    assert client.post("/audit/evidence/nope/verify").status_code == 404
    assert client.post("/audit/evidence/nope/retry").status_code == 404

    res_aid, _, _ = make_archives(client, "ev-guard")
    rv = create_package(client, [res_aid], "guard-k")
    pid = rv.get_json()["package_id"]
    # 未完成：下载/核验 409，重试 409
    rv = client.get(f"/audit/evidence/{pid}/download")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "evidence_not_ready"
    assert client.post(f"/audit/evidence/{pid}/verify").status_code == 409
    rv = client.post(f"/audit/evidence/{pid}/retry")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "evidence_bad_state"
    # 完成后下载/核验 200，重试仍 409
    finish(client, pid)
    assert client.get(f"/audit/evidence/{pid}/download").status_code == 200
    assert client.post(f"/audit/evidence/{pid}/verify").status_code == 200
    assert client.post(f"/audit/evidence/{pid}/retry").status_code == 409


def test_list_packages_filters(client):
    res_aid, cred_aid, _ = make_archives(client, "ev-list")
    p1 = create_package(client, [res_aid], "l1").get_json()["package_id"]
    finish(client, p1)
    p2 = create_package(client, [cred_aid], "l2").get_json()["package_id"]

    all_p = client.get("/audit/evidence").get_json()["packages"]
    assert {p["package_id"] for p in all_p} == {p1, p2}
    done = client.get("/audit/evidence?status=completed").get_json()["packages"]
    assert [p["package_id"] for p in done] == [p1]
    pending = client.get("/audit/evidence?status=pending").get_json()["packages"]
    assert [p["package_id"] for p in pending] == [p2]
    via_archive = client.get(
        f"/audit/evidence?archive_id={res_aid}").get_json()["packages"]
    assert [p["package_id"] for p in via_archive] == [p1]
    assert client.get("/audit/evidence?status=bogus").status_code == 400
