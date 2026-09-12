import pytest

from app.app import create_app


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "test.db"
    app = create_app(
        str(db),
        start_ticker=False,  # 测试里用 /debug/tick 确定性地驱动逻辑钟
        enable_debug_api=True,
        start_archive_worker=False,  # 归档生成由测试显式驱动，保证确定性
    )
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def acquire(client, resource, holder, ttl_ms=2000):
    rv = client.post("/leases/acquire", json={
        "resource": resource, "holder": holder, "ttl_ms": ttl_ms,
    })
    assert rv.status_code == 201, rv.get_json()
    return rv.get_json()["lease"]


def renew(client, lease):
    rv = client.post("/leases/renew", json={
        "resource": lease["resource"], "holder": lease["holder"],
        "generation": lease["generation"],
    })
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()["lease"]


def write(client, lease, value="v", *, holder=None, generation=None):
    return client.post(
        f"/resources/{lease['resource']}/writes",
        json={
            "holder": holder if holder is not None else lease["holder"],
            "generation": generation if generation is not None
            else lease["generation"],
            "value": value,
        },
    )


def wall_shift(client, delta_ms):
    return client.post("/debug/wall-shift", json={"delta_ms": delta_ms})
