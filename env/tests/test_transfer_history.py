"""安全转移（原子交接 / 幂等 / 防重放 / 接收者资格）与完整租约历史。"""

from conftest import acquire, renew, write


def transfer(client, lease, to_holder="node-2", transfer_id=None, ttl_ms=None,
             holder=None, generation=None):
    payload = {
        "resource": lease["resource"],
        "holder": lease["holder"] if holder is None else holder,
        "generation": lease["generation"] if generation is None else generation,
        "to_holder": to_holder,
    }
    if transfer_id is not None:
        payload["transfer_id"] = transfer_id
    if ttl_ms is not None:
        payload["ttl_ms"] = ttl_ms
    return client.post("/leases/transfer", json=payload)


def history(client, resource):
    rv = client.get(f"/resources/{resource}/history")
    assert rv.status_code == 200
    return rv.get_json()["events"]


def test_transfer_hands_off_atomically(client):
    old = acquire(client, "cfg-T", "node-1")
    assert write(client, old, "before").status_code == 201

    rv = transfer(client, old, to_holder="node-2", transfer_id="t-1")
    assert rv.status_code == 201, rv.get_json()
    body = rv.get_json()
    assert body["replayed"] is False
    new = body["lease"]
    assert new["holder"] == "node-2"
    assert new["generation"] > old["generation"]
    assert body["from"]["generation"] == old["generation"]
    assert body["to"]["generation"] == new["generation"]

    # 旧持有者立刻失去写权限
    rv = write(client, old, "stale")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "generation_fence"

    # 新持有者拿到更大世代号，立刻可写
    rv = write(client, new, "after")
    assert rv.status_code == 201, rv.get_json()

    res = client.get("/resources/cfg-T").get_json()
    assert res["value"] == "after"
    assert res["last_passed_generation"] == new["generation"]

    # 当前租约已是新持有者
    cur = client.get("/resources/cfg-T/leases").get_json()
    assert cur["holder"] == "node-2"
    assert cur["generation"] == new["generation"]


def test_duplicate_transfer_submission_is_idempotent(client):
    old = acquire(client, "cfg-dup", "node-1")
    rv1 = transfer(client, old, to_holder="node-2", transfer_id="xfer-1")
    assert rv1.status_code == 201
    first = rv1.get_json()

    # 同一笔转移原样重提（网络重试）：返回首次结果，不得再次转移
    rv2 = transfer(client, old, to_holder="node-2", transfer_id="xfer-1")
    assert rv2.status_code == 200
    second = rv2.get_json()
    assert second["replayed"] is True
    assert second["to"]["lease_id"] == first["to"]["lease_id"]
    assert second["to"]["generation"] == first["to"]["generation"]

    # 世代号只 bump 了一次
    res = client.get("/resources/cfg-dup").get_json()
    assert res["current_generation"] == first["to"]["generation"]

    # 历史里只有一笔成功的 transfer
    events = history(client, "cfg-dup")
    ok = [e for e in events
          if e["event"] == "transfer" and e["outcome"] == "ok"]
    assert len(ok) == 1


def test_transfer_id_reused_with_different_params_conflicts(client):
    old = acquire(client, "cfg-idc", "node-1")
    rv = transfer(client, old, to_holder="node-2", transfer_id="xfer-9")
    assert rv.status_code == 201
    new_gen = rv.get_json()["to"]["generation"]

    # 同一 transfer_id 换个接收者：拒绝，不得产生任何状态变化
    rv = transfer(client, old, to_holder="node-3", transfer_id="xfer-9")
    assert rv.status_code == 409

    cur = client.get("/resources/cfg-idc/leases").get_json()
    assert cur["holder"] == "node-2"
    assert cur["generation"] == new_gen

    events = history(client, "cfg-idc")
    bad = [e for e in events
           if e["event"] == "transfer" and e["outcome"] == "rejected"]
    assert len(bad) == 1
    assert bad[0]["detail"] == "transfer_id_conflict"


def test_old_credentials_cannot_replay_after_transfer(client):
    old = acquire(client, "cfg-replay", "node-1")
    rv = transfer(client, old, to_holder="node-2", transfer_id="t-re")
    new = rv.get_json()["lease"]

    # 旧持有者用旧凭证再发起转移（换个 transfer_id，绕过幂等键）
    rv = transfer(client, old, to_holder="node-3", transfer_id="t-re-2")
    assert rv.status_code == 409

    # 旧凭证续约 / 释放 / 写入 全部被拒
    rv = client.post("/leases/renew", json={
        "resource": old["resource"], "holder": old["holder"],
        "generation": old["generation"],
    })
    assert rv.status_code == 409
    rv = client.post("/leases/release", json={
        "resource": old["resource"], "holder": old["holder"],
        "generation": old["generation"],
    })
    assert rv.status_code == 409
    assert write(client, old, "stale").status_code == 409

    # 新持有者不受影响
    assert write(client, new, "fresh").status_code == 201

    # 这些拒绝全部进了历史
    events = history(client, "cfg-replay")
    rejected = {(e["event"], e["outcome"]) for e in events}
    assert ("transfer", "rejected") in rejected
    assert ("renew", "rejected") in rejected
    assert ("release", "rejected") in rejected
    assert ("write", "rejected") in rejected


def test_ineligible_recipient_rejected_without_side_effects(client):
    old = acquire(client, "cfg-bad", "node-1")

    # 转给自己
    assert transfer(client, old, to_holder="node-1").status_code == 409
    # 接收者为空 / 缺失
    assert transfer(client, old, to_holder="").status_code == 409
    assert transfer(client, old, to_holder=None).status_code == 409

    # 原租约毫发无损：世代号没变，持有者还能写
    cur = client.get("/resources/cfg-bad/leases").get_json()
    assert cur["holder"] == "node-1"
    assert cur["generation"] == old["generation"]
    assert write(client, old, "still-mine").status_code == 201

    events = history(client, "cfg-bad")
    bad = [e for e in events if e["event"] == "transfer"]
    assert len(bad) == 3
    assert all(e["outcome"] == "rejected" for e in bad)
    assert all(e["detail"].startswith("ineligible_recipient") for e in bad)


def test_rejected_transfer_events_carry_lease_and_generation(client):
    old = acquire(client, "cfg-rej", "node-1")

    # 三种拒绝：转给自己 / 空接收者 / 世代号与生效租约不符
    assert transfer(client, old, to_holder="node-1").status_code == 409
    assert transfer(client, old, to_holder="").status_code == 409
    assert transfer(client, old, to_holder="node-2",
                    generation=old["generation"] + 1).status_code == 409

    events = history(client, "cfg-rej")
    bad = [e for e in events
           if e["event"] == "transfer" and e["outcome"] == "rejected"]
    assert len(bad) == 3
    # 每条拒绝事件都能关联到当时的租约与请求携带的世代号
    for e in bad:
        assert e["lease_id"] == old["lease_id"]
        assert isinstance(e["generation"], int)
    mismatch = [e for e in bad
                if e["detail"] == "holder_or_generation_mismatch"][0]
    assert mismatch["generation"] == old["generation"] + 1


def test_transfer_id_conflict_event_carries_current_lease(client):
    old = acquire(client, "cfg-idc2", "node-1")
    rv = transfer(client, old, to_holder="node-2", transfer_id="xfer-c")
    assert rv.status_code == 201
    new_lease_id = rv.get_json()["to"]["lease_id"]

    # 同一 transfer_id 换个接收者：拒绝
    rv = transfer(client, old, to_holder="node-3", transfer_id="xfer-c")
    assert rv.status_code == 409

    events = history(client, "cfg-idc2")
    bad = [e for e in events
           if e["event"] == "transfer" and e["outcome"] == "rejected"]
    assert len(bad) == 1
    assert bad[0]["detail"] == "transfer_id_conflict"
    # 当时生效的是首笔转移产生的新租约
    assert bad[0]["lease_id"] == new_lease_id
    assert bad[0]["generation"] == old["generation"]


def test_history_covers_all_ops_with_time_holder_lease_generation(client):
    lease = acquire(client, "cfg-hist", "node-1")
    renew(client, lease)
    write(client, lease, "v1")
    write(client, lease, "bad", holder="node-2")  # 非持有者，被拒
    rv = transfer(client, lease, to_holder="node-2", transfer_id="t-h")
    new = rv.get_json()["lease"]
    write(client, new, "v2")
    client.post("/leases/release", json={
        "resource": "cfg-hist", "holder": "node-2",
        "generation": new["generation"],
    })

    events = history(client, "cfg-hist")
    kinds = [(e["event"], e["outcome"]) for e in events]
    assert kinds == [
        ("acquire", "ok"),
        ("renew", "ok"),
        ("write", "ok"),
        ("write", "rejected"),
        ("transfer", "ok"),
        ("write", "ok"),
        ("release", "ok"),
    ]

    # 审计顺序：seq 严格递增
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs)

    # 每条都带时间、持有者、租约编号、世代号
    for e in events:
        assert e["wall_ms"] > 0
        assert e["logical"] >= 0
        assert e["holder"]
        assert e["lease_id"]
        assert isinstance(e["generation"], int)

    # 转移事件能看到新旧两侧
    t = [e for e in events if e["event"] == "transfer"][0]
    assert t["holder"] == "node-1"
    assert t["peer"] == "node-2"
    assert t["generation"] == lease["generation"]
    assert t["to_generation"] == new["generation"]
    assert t["to_lease_id"] == new["lease_id"]

    # 被拒的写带着拒绝原因
    w = [e for e in events
         if e["event"] == "write" and e["outcome"] == "rejected"][0]
    assert w["detail"] == "generation_fence"


def test_history_and_transfer_result_survive_restart(tmp_path):
    db = tmp_path / "transfer.db"
    from app.app import create_app

    app1 = create_app(str(db), start_ticker=False)
    c1 = app1.test_client()
    old = acquire(c1, "vol-T", "node-1")
    rv = transfer(c1, old, to_holder="node-2", transfer_id="t-restart")
    assert rv.status_code == 201
    new = rv.get_json()["lease"]
    assert write(c1, new, "v2").status_code == 201
    before = history(c1, "vol-T")

    # ---- 进程重启：重新建 app，复用同一个数据库文件 ----
    app2 = create_app(str(db), start_ticker=False)
    c2 = app2.test_client()

    # 历史与审计顺序完全一致
    assert history(c2, "vol-T") == before

    # 转移结果仍可幂等回放
    rv = transfer(c2, old, to_holder="node-2", transfer_id="t-restart")
    assert rv.status_code == 200
    assert rv.get_json()["to"]["lease_id"] == new["lease_id"]

    # 新持有者仍可写，旧持有者仍被栅栏挡住
    assert write(c2, new, "v3").status_code == 201
    assert write(c2, old, "stale").status_code == 409
