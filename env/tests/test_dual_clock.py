"""双时钟过期判定。

场景一：墙钟被拨快，越过软 TTL，但逻辑钟还在推进（持有者还在干活）
        —— 租约必须仍有效，写入继续放行。
场景二：墙钟正常（或被拨慢），但逻辑钟彻底卡死
        —— 不能靠逻辑钟续命到永远；硬墙钟上限一到必须结束。
场景三：墙钟过期且逻辑钟也沉默超过宽限 —— 正常过期，允许下一任获取。
"""

from conftest import acquire, renew, wall_shift, write


def test_wall_clock_jumped_forward_does_not_reclaim_working_lease(client):
    # TTL 2s，逻辑宽限 3 tick
    lease = acquire(client, "res", "node-1", ttl_ms=2000)

    # 有人把墙上时间往前拨了 10 秒（越过软 deadline，也越过正常 TTL），
    # 但没越过 60s 的硬上限
    wall_shift(client, 10_000)

    # 逻辑钟仍在推进：持有者一直在续约/干活
    client.post("/debug/tick", json={"steps": 2})
    renewed = renew(client, lease)
    assert renewed["generation"] == lease["generation"]

    # 租约依然生效，写入放行
    rv = write(client, lease, "still-mine")
    assert rv.status_code == 201, rv.get_json()
    assert rv.get_json()["accepted"] is True

    rv = client.get("/resources/res/leases")
    assert rv.get_json()["state"] == "active"


def test_stalled_logical_clock_still_expires_at_hard_wall_deadline(client):
    lease = acquire(client, "res2", "node-1", ttl_ms=2000)

    # 墙钟没动（甚至被拨慢），逻辑钟一次都不 tick —— 模拟逻辑时间卡死。
    # 直接把墙钟推过硬上限（60s）：租约必须死。
    wall_shift(client, 61_000)

    rv = client.get("/resources/res2/leases")
    body = rv.get_json()
    assert body["state"] == "expired"
    assert body["expire_reason"] == "hard_wall_deadline_reached"

    # 续约被拒（412），不能让同一代无限续命
    rv = client.post("/leases/renew", json={
        "resource": "res2", "holder": "node-1",
        "generation": lease["generation"],
    })
    assert rv.status_code == 412

    # 拿着旧世代号写入被拒
    rv = write(client, lease, "late")
    assert rv.status_code == 412

    # 下一任拿到的世代号必须更大
    new_lease = acquire(client, "res2", "node-2")
    assert new_lease["generation"] == lease["generation"] + 1


def test_normal_expiry_needs_both_clocks_silent(client):
    lease = acquire(client, "res3", "node-1", ttl_ms=2000)

    # 墙钟过了软 TTL，但逻辑钟仍在宽限内（落后 <= 3 tick）-> 还活着
    wall_shift(client, 3000)
    client.post("/debug/tick", json={"steps": 2})
    rv = write(client, lease, "grace-window")
    assert rv.status_code == 201

    # 逻辑钟继续推进超过宽限，且墙钟仍过期 -> 双沉默，租约结束
    client.post("/debug/tick", json={"steps": 5})
    rv = client.get("/resources/res3/leases")
    assert rv.get_json()["state"] == "expired"
    assert rv.get_json()["expire_reason"] == \
        "wall_ttl_passed_and_logical_stalled"

    rv = write(client, lease, "too-late")
    assert rv.status_code == 412

    new_lease = acquire(client, "res3", "node-2")
    assert new_lease["generation"] == lease["generation"] + 1
