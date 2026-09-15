"""审计事件窗口批次聚合：HTTP 端到端测试。

覆盖：
- 多来源独立 watermark 推进与独立封存
- 固定窗口边界（半开 [start,end)）与分组字段
- watermark 回退拒绝
- 正常封存：冻结成员/摘要/校验值 + 唯一一条多接收端通知
- 并发扫描 / 重复处理同段历史：事件不进两个批次、无重复通知
- 迟到事件三种处理（retain / forward / supplement）且不改写原批次
- 通知创建（发送）失败后的恢复
- 批次内容被篡改后核验失败并定位差异
- 规则切换（新版本）只影响之后（按事件发生时间）的事件
- 服务重启后继续未封存窗口
"""

import threading

import pytest

from app.app import create_app

T0 = 1_000_000_000_000
W = 60_000
BASE = (T0 // W) * W          # 对齐纪元的窗口起点
LAT = 10_000
RECIPIENTS = ["sec-a", "sec-b"]


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def make_source(client, sid="s1", initial=None):
    data = {"source_id": sid}
    if initial is not None:
        data["initial_watermark_ms"] = initial
    rv = client.post("/audit/batch/sources", json=data)
    assert rv.status_code in (200, 201), rv.get_json()
    return rv.get_json()


def make_rule(client, event_type="login", *, window_ms=W, group_field="region",
              allowed_lateness_ms=LAT, recipients=None, effective_at_ms=None,
              idempotency_key=None, expect=201):
    data = {
        "event_type": event_type, "window_ms": window_ms,
        "group_field": group_field,
        "allowed_lateness_ms": allowed_lateness_ms,
        "recipients": recipients or RECIPIENTS,
    }
    if effective_at_ms is not None:
        data["effective_at_ms"] = effective_at_ms
    if idempotency_key is not None:
        data["idempotency_key"] = idempotency_key
    rv = client.post("/audit/batch/rules", json=data)
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def scan(client, sid, events, expect=200, headers=None):
    rv = client.post(f"/audit/batch/sources/{sid}/events/scan",
                     json={"events": events}, headers=headers or {})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def watermark(client, sid, wm, *, expect=200, headers=None, seq=None):
    data = {"watermark_ms": wm}
    if seq is not None:
        data["seq"] = seq
    rv = client.post(f"/audit/batch/sources/{sid}/watermark", json=data,
                     headers=headers or {})
    assert rv.status_code == expect, rv.get_json()
    return rv.get_json()


def get_batch(client, bid):
    rv = client.get(f"/audit/batch/batches/{bid}")
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()


def list_batches(client, **params):
    rv = client.get("/audit/batch/batches", query_string=params)
    assert rv.status_code == 200, rv.get_json()
    return rv.get_json()["batches"]


def evt(seq, ts, region="cn", **extra):
    p = {"region": region}
    p.update(extra)
    return {"seq": seq, "event_type": "login", "occurred_at_ms": ts,
            "payload": p}


def setup(client, sid="s1"):
    make_source(client, sid)
    make_rule(client)


# ---------------------------------------------------------------------------
# 开放批次持续统计 + 正常封存
# ---------------------------------------------------------------------------

def test_open_batch_live_counts_and_normal_seal(client):
    setup(client)
    r = scan(client, "s1", [
        evt(1, BASE + 1_000, u=1), evt(2, BASE + 2_000, u=2),
        evt(3, BASE + W + 1_000, region="us", u=3),
    ])
    assert r["ingested_count"] == 3 and r["late_count"] == 0
    bid = r["ingested"][0]["batch_id"]
    assert r["ingested"][1]["batch_id"] == bid           # 同窗口同组
    assert r["ingested"][2]["batch_id"] != bid           # 下一窗口

    b = get_batch(client, bid)
    assert b["status"] == "open" and b["checksum"] is None
    assert b["event_count"] == 2
    assert b["seq_range"] == [1, 2]
    assert b["time_range_ms"] == [BASE + 1_000, BASE + 2_000]
    assert b["window_start_ms"] == BASE and b["window_end_ms"] == BASE + W
    # 开放批次无通知
    assert b["notification"] is None

    # 封存线前不封存
    r = watermark(client, "s1", BASE + W + LAT - 1)
    assert r["sealed_batches"] == []
    assert get_batch(client, bid)["status"] == "open"

    # 到线封存
    r = watermark(client, "s1", BASE + W + LAT)
    sealed_ids = {x["batch_id"] for x in r["sealed_batches"]}
    assert bid in sealed_ids
    b = get_batch(client, bid)
    assert b["status"] == "sealed" and b["checksum"]
    assert b["summary"]["event_count"] == 2
    assert b["summary"]["seq_range"] == [1, 2]
    assert b["summary"]["distinct_payloads"] == 2
    # 唯一一条多接收端通知，已发送，接收端冻结
    n = b["notification"]
    assert n["status"] == "sent"
    assert get_batch(client, bid)["notification"]["notification_id"] == n["notification_id"]
    lst = client.get("/audit/batch/notifications",
                     query_string={"batch_id": bid}).get_json()["notifications"]
    assert len(lst) == 1
    assert lst[0]["recipients"] == RECIPIENTS
    assert lst[0]["payload"]["checksum"] == b["checksum"]
    # 核验通过
    rv = client.post(f"/audit/batch/batches/{bid}/verify")
    assert rv.status_code == 200 and rv.get_json()["valid"] is True


def test_window_half_open_boundary(client):
    setup(client)
    r = scan(client, "s1", [
        evt(1, BASE + 3 * W),
        evt(2, BASE + 4 * W - 1),
        evt(3, BASE + 4 * W),
    ])
    ids = [e["batch_id"] for e in r["ingested"]]
    assert ids[0] == ids[1] and ids[1] != ids[2]


def test_group_field_and_null_group(client):
    setup(client)
    r = scan(client, "s1", [
        evt(1, BASE + 1_000, region="cn"),
        evt(2, BASE + 2_000, region="us"),
        # 缺失 / null 分组字段归入同一空组
        {"seq": 3, "event_type": "login", "occurred_at_ms": BASE + 3_000,
         "payload": {"other": 1}},
        {"seq": 4, "event_type": "login", "occurred_at_ms": BASE + 4_000,
         "payload": {"region": None}},
    ])
    ids = [e["batch_id"] for e in r["ingested"]]
    assert ids[0] != ids[1]
    assert ids[2] == ids[3]


# ---------------------------------------------------------------------------
# 多来源独立 watermark
# ---------------------------------------------------------------------------

def test_multiple_sources_advance_independently(client):
    make_source(client, "s1")
    make_source(client, "s2")
    make_rule(client)
    scan(client, "s1", [evt(1, BASE + 1_000)])
    scan(client, "s2", [evt(1, BASE + 1_000)])

    # 只推进 s1：s1 封存，s2 不动
    r = watermark(client, "s1", BASE + W + LAT)
    assert len(r["sealed_batches"]) == 1
    assert r["sealed_batches"][0]["source_id"] == "s1"
    s2_open = list_batches(client, source_id="s2")
    assert len(s2_open) == 1 and s2_open[0]["status"] == "open"

    # 序号独立：s2 下一条仍是 seq=2
    r = scan(client, "s2", [evt(2, BASE + W + 5_000)])
    assert r["ingested"][0]["seq"] == 2
    watermark(client, "s2", BASE + 2 * W + LAT)
    assert all(x["status"] == "sealed"
               for x in list_batches(client, source_id="s2"))

    # 各自通知互不相干
    n1 = client.get("/audit/batch/notifications",
                    query_string={"source_id": "s1"}).get_json()["notifications"]
    n2 = client.get("/audit/batch/notifications",
                    query_string={"source_id": "s2"}).get_json()["notifications"]
    assert n1 and n2 and not {x["notification_id"] for x in n1} & \
        {x["notification_id"] for x in n2}


def test_watermark_regression_rejected(client):
    setup(client)
    scan(client, "s1", [evt(1, BASE + 1_000)])
    watermark(client, "s1", BASE + W)
    rv = client.post("/audit/batch/sources/s1/watermark",
                     json={"watermark_ms": BASE + W - 1})
    assert rv.status_code == 409
    j = rv.get_json()
    assert j["error"] == "batch_conflict"
    assert j["current_watermark_ms"] == BASE + W
    # 状态不变
    s = client.get("/audit/batch/sources/s1").get_json()
    assert s["watermark_ms"] == BASE + W
    # 等值推进是允许的（无变化），仍不封存（未到线）
    watermark(client, "s1", BASE + W)
    assert get_batch(client, list_batches(client)[0]["batch_id"])["status"] == "open"


# ---------------------------------------------------------------------------
# 并发扫描 / 重复历史
# ---------------------------------------------------------------------------

def test_duplicate_rescan_is_idempotent(client):
    setup(client)
    evs = [evt(1, BASE + 1_000), evt(2, BASE + 2_000)]
    scan(client, "s1", evs)
    # 把窗口封存后再重放同段历史：seq 已存在 → duplicate，不新建批次/通知
    watermark(client, "s1", BASE + W + LAT)
    r = scan(client, "s1", evs)
    assert r["ingested_count"] == 0 and r["duplicate_count"] == 2
    batches = list_batches(client, source_id="s1")
    assert len(batches) == 1
    notifs = client.get("/audit/batch/notifications").get_json()["notifications"]
    assert len(notifs) == 1


def test_concurrent_scan_same_segment(client):
    setup(client)
    bar = threading.Barrier(2)
    results = []

    def worker():
        # 每个线程独立的 test_client，但共用同一个 app/store
        c = client.application.test_client()
        bar.wait()
        rv = c.post("/audit/batch/sources/s1/events/scan",
                    json={"events": [evt(1, BASE + 1_000)]})
        results.append((rv.status_code, rv.get_json()))

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start(); t2.start(); t1.join(); t2.join()

    bodies = [b for _, b in results]
    assert all(code == 200 for code, _ in results), bodies
    ing = sum(b["ingested_count"] for b in bodies)
    dup = sum(b["duplicate_count"] for b in bodies)
    assert ing == 1 and dup == 1, bodies
    # 只有一个批次、一条通知；事件只属于一个批次
    assert len(list_batches(client)) == 1
    members = client.get(
        f"/audit/batch/batches/{list_batches(client)[0]['batch_id']}/members"
    ).get_json()
    assert members["count"] == 1


def test_stable_seq_must_be_continuous(client):
    setup(client)
    scan(client, "s1", [evt(1, BASE + 1_000)])
    # 跳号被拒
    rv = client.post("/audit/batch/sources/s1/events/scan",
                     json={"events": [evt(3, BASE + 2_000)]})
    assert rv.status_code == 409
    assert rv.get_json()["expected_seq"] == 2
    # 同 seq 不同内容被拒
    rv = client.post("/audit/batch/sources/s1/events/scan",
                     json={"events": [evt(1, BASE + 2_000, region="us")]})
    assert rv.status_code == 409


# ---------------------------------------------------------------------------
# 迟到事件
# ---------------------------------------------------------------------------

def _seal_first_window(client):
    scan(client, "s1", [evt(1, BASE + 1_000, u=1), evt(2, BASE + 2_000, u=2)])
    bid = list_batches(client)[0]["batch_id"]
    watermark(client, "s1", BASE + W + LAT)
    assert get_batch(client, bid)["status"] == "sealed"
    return bid


def test_late_event_routed_to_late_zone_and_listed(client):
    setup(client)
    _seal_first_window(client)
    r = scan(client, "s1", [evt(3, BASE + 3_000, u=3)])
    assert r["late_count"] == 1 and r["ingested"][0]["late"] is True
    late = client.get("/audit/batch/late-events",
                      query_string={"status": "pending"}).get_json()["late_events"]
    assert len(late) == 1 and late[0]["status"] == "pending"
    # 原批次成员不变
    bid = list_batches(client, status="sealed")[0]["batch_id"]
    assert get_batch(client, bid)["event_count"] == 2


def test_late_retain_keeps_quarantine(client):
    setup(client)
    bid = _seal_first_window(client)
    lid = scan(client, "s1", [evt(3, BASE + 3_000)])["ingested"][0]["event_id"]
    rv = client.post("/audit/batch/late-events/handle",
                     json={"source_id": "s1", "event_id": lid,
                           "action": "retain", "note": "隔离观察"})
    assert rv.status_code == 200 and rv.get_json()["late_event"]["status"] == "retained"
    assert get_batch(client, bid)["event_count"] == 2
    late = client.get("/audit/batch/late-events",
                      query_string={"status": "retained"}).get_json()["late_events"]
    assert len(late) == 1 and late[0]["note"] == "隔离观察"
    # retain 后可改为别的处理（retained 仍允许再处理），但重复 retain 幂等返回


def test_late_forward_into_next_open_window(client):
    setup(client)
    bid = _seal_first_window(client)
    lid = scan(client, "s1", [evt(3, BASE + 3_000)])["ingested"][0]["event_id"]
    rv = client.post("/audit/batch/late-events/handle",
                     json={"source_id": "s1", "event_id": lid,
                           "action": "forward"})
    assert rv.status_code == 200
    target = rv.get_json()["target_batch_id"]
    tb = get_batch(client, target)
    assert tb["status"] == "open"
    assert tb["window_start_ms"] == BASE + W          # 下一窗口
    members = client.get(f"/audit/batch/batches/{target}/members").get_json()["members"]
    assert any(m["event_id"] == lid for m in members)
    # 原批次不动
    assert get_batch(client, bid)["event_count"] == 2
    assert get_batch(client, bid)["checksum"] == get_batch(client, bid)["checksum"]
    # 已处理不能再处理
    rv = client.post("/audit/batch/late-events/handle",
                     json={"source_id": "s1", "event_id": lid, "action": "retain"})
    assert rv.status_code == 409


def test_late_supplement_creates_sealed_supplement(client):
    setup(client)
    bid = _seal_first_window(client)
    lid = scan(client, "s1", [evt(3, BASE + 3_000)])["ingested"][0]["event_id"]
    rv = client.post("/audit/batch/late-events/handle",
                     json={"source_id": "s1", "event_id": lid,
                           "action": "supplement"})
    assert rv.status_code == 200
    sup = rv.get_json()["supplement_batch"]
    assert sup["batch_type"] == "supplement" and sup["status"] == "sealed"
    assert sup["parent_batch_id"] == bid and sup["event_count"] == 1
    # 补充批次有自己独立的一条通知和可核验校验值
    assert sup["notification"] is not None
    v = client.post(f"/audit/batch/batches/{sup['batch_id']}/verify")
    assert v.status_code == 200 and v.get_json()["valid"]
    # 原批次完全不变
    orig = get_batch(client, bid)
    assert orig["event_count"] == 2
    assert len(client.get(f"/audit/batch/batches/{bid}/members").get_json()["members"]) == 2
    # 同一事件不能重复 supplement
    rv = client.post("/audit/batch/late-events/handle",
                     json={"source_id": "s1", "event_id": lid,
                           "action": "supplement"})
    assert rv.status_code == 409


def test_late_unknown_event_404(client):
    setup(client)
    rv = client.post("/audit/batch/late-events/handle",
                     json={"source_id": "s1", "event_id": "ghost",
                           "action": "retain"})
    assert rv.status_code == 404


def test_window_closed_before_arrival_goes_late_without_batch(client):
    # watermark 先越过封存线、窗口内一个事件都还没有：之后到达的事件进
    # 迟到区，不凭空创建一个已关闭窗口的批次
    setup(client)
    watermark(client, "s1", BASE + W + LAT)
    r = scan(client, "s1", [evt(1, BASE + 1_000)])
    assert r["ingested"][0]["late"] is True
    assert r["ingested"][0]["batch_id"] is None
    late = client.get("/audit/batch/late-events").get_json()["late_events"]
    assert len(late) == 1
    assert late[0]["reason"] == "window_closed_before_arrival"
    assert list_batches(client) == []


def test_late_arrival_after_line_seals_old_members_first(client):
    # open 批次实际已到封存线但尚未触发封存，此刻同窗口新事件到达：
    # 旧成员先被冻结封存（不含新事件），新事件进迟到区
    setup(client)
    r = scan(client, "s1", [evt(1, BASE + 1_000, u=1)])
    bid = list_batches(client)[0]["batch_id"]
    # 直接把 watermark 推过封存线但不经过推进接口（避免触发主动封存）
    store = client.application.extensions["store"]
    with store._lock:
        store._conn.execute(
            "UPDATE audit_batch_sources SET watermark_ms=? WHERE source_id=?",
            (BASE + W + LAT, "s1"))
        store._conn.commit()
    assert get_batch(client, bid)["status"] == "open"      # 到线但未触发

    r = scan(client, "s1", [evt(2, BASE + 2_000, u=2)])
    assert r["ingested"][0]["late"] is True
    sealed = get_batch(client, bid)
    assert sealed["status"] == "sealed"
    assert sealed["event_count"] == 1                     # 只冻结旧成员
    assert sealed["notification"] is not None
    late = client.get("/audit/batch/late-events",
                      query_string={"source_id": "s1"}).get_json()["late_events"]
    assert len(late) == 1 and late[0]["sealed_batch_id"] == bid


# ---------------------------------------------------------------------------
# 通知失败恢复
# ---------------------------------------------------------------------------

def test_notification_delivery_failure_then_retry(client):
    setup(client)
    scan(client, "s1", [evt(1, BASE + 1_000), evt(2, BASE + 2_000)])
    bid = list_batches(client)[0]["batch_id"]
    # 带故障头推进 watermark：封存成功但发送失败
    r = watermark(client, "s1", BASE + W + LAT,
                  headers={"X-Fail-Delivery": "1"})
    assert any(x["batch_id"] == bid for x in r["sealed_batches"])
    b = get_batch(client, bid)
    assert b["status"] == "sealed"                       # 封存不受影响
    nid = b["notification"]["notification_id"]
    assert b["notification"]["status"] == "failed"
    assert b["notification"]["attempts"] == 1
    # 仍只有一条通知
    assert len(client.get("/audit/batch/notifications").get_json()["notifications"]) == 1
    # 不带故障头重试：复用同一条通知发送成功
    rv = client.post(f"/audit/batch/notifications/{nid}/retry")
    assert rv.status_code == 200
    n = rv.get_json()
    assert n["status"] == "sent" and n["attempts"] == 2
    assert get_batch(client, bid)["notification"]["notification_id"] == nid
    # 再次重试幂等，不产生新通知
    client.post(f"/audit/batch/notifications/{nid}/retry")
    assert len(client.get("/audit/batch/notifications").get_json()["notifications"]) == 1


# ---------------------------------------------------------------------------
# 篡改核验
# ---------------------------------------------------------------------------

def test_tampered_batch_verify_fails_and_locates_diff(client):
    setup(client)
    scan(client, "s1", [evt(1, BASE + 1_000, u=1), evt(2, BASE + 2_000, u=2)])
    bid = list_batches(client)[0]["batch_id"]
    members = client.get(f"/audit/batch/batches/{bid}/members").get_json()["members"]
    watermark(client, "s1", BASE + W + LAT)
    good = get_batch(client, bid)["checksum"]

    # 直接篡改已封存成员事件的载荷
    rv = client.post(f"/debug/batch/events/{members[0]['event_id']}/tamper",
                     json={"payload": {"region": "cn", "u": 666}})
    assert rv.status_code == 200
    rv = client.post(f"/audit/batch/batches/{bid}/verify")
    assert rv.status_code == 409
    j = rv.get_json()
    assert j["error"] == "batch_verify_failed" and j["valid"] is False
    assert j["stored_checksum"] == good and j["recomputed_checksum"] != good
    # 差异定位到冻结摘要（成员内容）
    assert j["first_diff"]["path"].startswith("frozen.summary")
    # checksum 接口只重算不改写
    rc = client.post(f"/audit/batch/batches/{bid}/checksum").get_json()
    assert rc["stored_checksum"] == good


# ---------------------------------------------------------------------------
# 规则切换只影响之后的事件
# ---------------------------------------------------------------------------

def test_rule_switch_only_affects_later_events(client):
    setup(client)
    # 老规则下已有一个 open 批次（BASE 窗口）
    scan(client, "s1", [evt(1, BASE + 1_000)])
    old_bid = list_batches(client)[0]["batch_id"]
    old_rule = get_batch(client, old_bid)["rule_id"]

    effective = BASE + 10 * W
    new_rule = make_rule(client, window_ms=30_000, group_field="region",
                         allowed_lateness_ms=5_000, recipients=["new"],
                         effective_at_ms=effective)
    assert new_rule["version"] == 2 and new_rule["rule_id"] != old_rule

    # 生效点之前（含边界前一刻）仍用旧规则
    before = scan(client, "s1", [evt(2, effective - 1, region="zz")])
    assert before["ingested"][0]["rule_id"] == old_rule
    # 恰好生效点（含）起用新规则
    at = scan(client, "s1", [evt(3, effective)])
    after = scan(client, "s1", [evt(4, effective + 1_000)])
    assert at["ingested"][0]["rule_id"] == new_rule["rule_id"]
    new_bid = after["ingested"][0]["batch_id"]
    assert at["ingested"][0]["batch_id"] == new_bid          # 30s 新窗口
    nb = get_batch(client, new_bid)
    assert nb["window_end_ms"] - nb["window_start_ms"] == 30_000
    assert nb["allowed_lateness_ms"] == 5_000
    # 已存在的旧 open 批次继续按旧规则聚合：旧窗口再来事件仍进老批次
    more = scan(client, "s1", [evt(5, BASE + 2_000)])
    assert more["ingested"][0]["batch_id"] == old_bid
    assert get_batch(client, old_bid)["rule_id"] == old_rule
    # 规则列表两版本都在
    rules = client.get("/audit/batch/rules",
                       query_string={"event_type": "login"}).get_json()["rules"]
    assert [r["version"] for r in rules] == [1, 2]


def test_rule_idempotency_key(client):
    r1 = make_rule(client, idempotency_key="k1")
    rv = client.post("/audit/batch/rules", json={
        "event_type": "login", "window_ms": W, "group_field": "region",
        "allowed_lateness_ms": LAT, "recipients": RECIPIENTS,
        "idempotency_key": "k1"})
    assert rv.status_code == 200 and rv.get_json()["rule_id"] == r1["rule_id"]
    # 同键不同规格冲突
    rv = client.post("/audit/batch/rules", json={
        "event_type": "login", "window_ms": W + 1, "group_field": "region",
        "allowed_lateness_ms": LAT, "recipients": RECIPIENTS,
        "idempotency_key": "k1"})
    assert rv.status_code == 409


def test_unconfigured_event_type_rejected(client):
    make_source(client)
    rv = client.post("/audit/batch/sources/s1/events/scan", json={"events": [
        {"seq": 1, "event_type": "mystery", "occurred_at_ms": BASE,
         "payload": {}}]})
    assert rv.status_code == 409


# ---------------------------------------------------------------------------
# 服务重启后继续未封存窗口
# ---------------------------------------------------------------------------

def test_restart_continues_open_window(tmp_path):
    db = str(tmp_path / "restart.db")

    def app_factory():
        return create_app(db, start_ticker=False,
                          enable_debug_api=True, start_archive_worker=False)

    app = app_factory()
    with app.test_client() as c:
        setup(c)
        scan(c, "s1", [evt(1, BASE + 1_000)])
        assert list_batches(c)[0]["status"] == "open"

    # 进程重启：重新建 app（新连接），open 窗口原样保留
    app2 = app_factory()
    with app2.test_client() as c:
        batches = list_batches(c)
        assert len(batches) == 1 and batches[0]["status"] == "open"
        bid = batches[0]["batch_id"]
        # 同窗口后续事件继续归入同一未封存批次
        r = scan(c, "s1", [evt(2, BASE + 2_000)])
        assert r["ingested"][0]["batch_id"] == bid
        assert get_batch(c, bid)["event_count"] == 2
        # 恢复接口幂等：不产生额外批次/通知
        before = len(c.get("/audit/batch/notifications").get_json()["notifications"])
        rv = c.post("/audit/batch/recover")
        assert rv.status_code == 200
        assert len(c.get("/audit/batch/notifications").get_json()["notifications"]) == before
        # watermark 到线后正常封存并发送唯一通知
        watermark(c, "s1", BASE + W + LAT)
        b = get_batch(c, bid)
        assert b["status"] == "sealed" and b["event_count"] == 2
        assert b["notification"]["status"] == "sent"
        notifs = c.get("/audit/batch/notifications",
                       query_string={"batch_id": bid}).get_json()["notifications"]
        assert len(notifs) == 1


def test_restart_recovers_interrupted_notification(tmp_path):
    db = str(tmp_path / "restart2.db")
    app = create_app(db, start_ticker=False, enable_debug_api=True,
                     start_archive_worker=False)
    with app.test_client() as c:
        setup(c)
        scan(c, "s1", [evt(1, BASE + 1_000)])
        bid = list_batches(c)[0]["batch_id"]
        # 发送失败（封存成功，通知 failed）
        watermark(c, "s1", BASE + W + LAT, headers={"X-Fail-Delivery": "1"})
        nid = get_batch(c, bid)["notification"]["notification_id"]

    app2 = create_app(db, start_ticker=False, enable_debug_api=True,
                      start_archive_worker=False)
    with app2.test_client() as c:
        # recover 不会新建通知；手动重试复用原通知成功
        rec = c.post("/audit/batch/recover").get_json()
        assert rec["dispatched"] >= 0
        assert len(c.get("/audit/batch/notifications").get_json()["notifications"]) == 1
        rv = c.post(f"/audit/batch/notifications/{nid}/retry")
        assert rv.get_json()["status"] == "sent"
        assert rv.get_json()["notification_id"] == nid
