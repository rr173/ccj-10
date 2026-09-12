"""基础租约语义：持有者才能写，世代号在审计中可查。"""

from conftest import acquire, renew, write


def test_only_holder_can_write_and_write_is_attributed_to_generation(client):
    lease = acquire(client, "cfg-A", "node-1")

    # 别人写：拒绝
    rv = write(client, lease, holder="node-2")
    assert rv.status_code == 409
    assert rv.get_json()["error"] == "generation_fence"

    # 持有者带正确世代号写：放行
    rv = write(client, lease, "hello")
    assert rv.status_code == 201, rv.get_json()
    result = rv.get_json()
    assert result["accepted"] is True
    assert result["generation"] == lease["generation"]
    write_id = result["write_id"]

    # 资源状态记住最后放行世代
    rv = client.get("/resources/cfg-A")
    assert rv.get_json()["last_passed_generation"] == lease["generation"]
    assert rv.get_json()["value"] == "hello"

    # 按写入 ID 反查：是哪一代租约、哪个持有者放行的
    rv = client.get(f"/writes/{write_id}")
    assert rv.status_code == 200
    assert rv.get_json()["generation"] == lease["generation"]
    assert rv.get_json()["lease_id"] == lease["lease_id"]
    assert rv.get_json()["holder"] == "node-1"

    # 列表里被拒的写入也留痕
    rv = client.get("/resources/cfg-A/writes")
    gens = {(w["generation"], w["accepted"]) for w in rv.get_json()["writes"]}
    assert (lease["generation"], True) in gens
    assert (lease["generation"], False) in gens


def test_same_holder_can_write_repeatedly_while_lease_valid(client):
    lease = acquire(client, "cfg-repeat", "node-1")

    # 租约没过期，同一持有者连续改动都应成功
    for i in range(3):
        rv = write(client, lease, f"v{i}")
        assert rv.status_code == 201, rv.get_json()
        assert rv.get_json()["accepted"] is True

    res = client.get("/resources/cfg-repeat").get_json()
    assert res["value"] == "v2"
    assert res["last_passed_generation"] == lease["generation"]

    # 三次写入全部留痕且都归属同一代租约
    writes = client.get("/resources/cfg-repeat/writes").get_json()["writes"]
    accepted = [w for w in writes if w["accepted"]]
    assert len(accepted) == 3
    assert {w["generation"] for w in accepted} == {lease["generation"]}


def test_same_holder_reacquire_returns_same_generation(client):
    lease = acquire(client, "cfg-B", "node-1")
    rv = client.post("/leases/acquire", json={
        "resource": "cfg-B", "holder": "node-1",
    })
    assert rv.status_code == 200
    assert rv.get_json()["acquired"] is False
    assert rv.get_json()["lease"]["generation"] == lease["generation"]

    # 别人获取则冲突
    rv = client.post("/leases/acquire", json={
        "resource": "cfg-B", "holder": "node-2",
    })
    assert rv.status_code == 409


def test_renew_keeps_generation_and_extends_soft_deadline(client):
    lease = acquire(client, "cfg-C", "node-1")
    renewed = renew(client, lease)
    assert renewed["generation"] == lease["generation"]
    assert renewed["renewed_count"] == 1
    assert renewed["wall_deadline_ms"] >= lease["wall_deadline_ms"]
