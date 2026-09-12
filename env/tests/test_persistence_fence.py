"""重启持久性 + 世代号栅栏：重启不丢租约，过期世代号写入必被拒。"""

from conftest import acquire, renew, wall_shift, write


def test_active_lease_and_generation_survive_restart(tmp_path):
    db = tmp_path / "persist.db"

    from app.app import create_app
    app1 = create_app(str(db), start_ticker=False)
    c1 = app1.test_client()
    rv = c1.post("/leases/acquire", json={
        "resource": "vol", "holder": "node-1", "ttl_ms": 2000,
    })
    lease = rv.get_json()["lease"]

    # 墙钟被拨快过，偏移也必须持久化，重启后不能"忘记"故障
    wall_shift(c1, 5_000)
    c1.post("/debug/tick", json={"steps": 1})  # 逻辑心跳仍在 -> 租约活着

    # ---- 进程重启：重新建 app，复用同一个数据库文件 ----
    app2 = create_app(str(db), start_ticker=False)
    c2 = app2.test_client()

    rv = c2.get("/debug/now")
    now = rv.get_json()
    assert now["logical"] == 1  # 逻辑钟持久化

    rv = c2.get("/resources/vol/leases")
    body = rv.get_json()
    assert body["state"] == "active"  # 生效中租约没丢
    assert body["generation"] == lease["generation"]
    assert body["lease_id"] == lease["lease_id"]

    # 原持有者带着原世代号仍可续约、写入
    rv = c2.post("/leases/renew", json={
        "resource": "vol", "holder": "node-1",
        "generation": lease["generation"],
    })
    assert rv.status_code == 200
    rv = c2.post("/resources/vol/writes", json={
        "holder": "node-1", "generation": lease["generation"],
        "value": "after-restart",
    })
    assert rv.status_code == 201


def test_after_handoff_stale_generation_write_is_rejected(tmp_path):
    db = tmp_path / "fence.db"
    from app.app import create_app

    app = create_app(str(db), start_ticker=False)
    c = app.test_client()

    old = acquire(c, "disk", "node-1")
    assert write(c, old, "v1").status_code == 201

    # node-1 自己释放
    rv = c.post("/leases/release", json={
        "resource": "disk", "holder": "node-1",
        "generation": old["generation"],
    })
    assert rv.status_code == 200

    # 下一任必须拿到更大的世代号
    new = acquire(c, "disk", "node-2")
    assert new["generation"] > old["generation"]
    assert write(c, new, "v2").status_code == 201

    # 旧持有者带着过期世代号（网络延迟到达的迟到写）—— 拒绝
    rv = write(c, old, "stale-v1")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "generation_fence"

    # 伪造更大但不属于自己的世代号 —— 同样拒绝
    rv = c.post("/resources/disk/writes", json={
        "holder": "node-1", "generation": new["generation"], "value": "hack",
    })
    assert rv.status_code == 409

    # 资源值没有被污染，审计里能看到是第 2 代放行的 v2
    rv = c.get("/resources/disk")
    res = rv.get_json()
    assert res["value"] == "v2"
    assert res["last_passed_generation"] == new["generation"]


def test_generation_keeps_monotonic_after_expiry_handoff(tmp_path):
    db = tmp_path / "mono.db"
    from app.app import create_app

    app = create_app(str(db), start_ticker=False)
    c = app.test_client()

    g1 = acquire(c, "r", "a")
    # 硬过期：墙钟推过 60s 硬上限，逻辑钟不动
    wall_shift(c, 61_000)
    g2 = acquire(c, "r", "b")
    assert g2["generation"] == g1["generation"] + 1

    wall_shift(c, 61_000)  # 第二代也硬过期
    g3 = acquire(c, "r", "c")
    assert g3["generation"] == g2["generation"] + 1

    rv = c.get("/resources/r")
    assert rv.get_json()["current_generation"] == g3["generation"]
