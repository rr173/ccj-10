"""同键异内容必须显式冲突；隔离事件保留旧字段时 rename 可改到当前契约的新字段。

覆盖需求：
1. 同一幂等键只有请求内容完全一致才回放；契约登记/预演/生效/撤销/映射登记
   只要改了版本、范围、序号、事件类型或映射目标，必须明确返回冲突，
   不能沿用首次请求的结果。
2. 隔离事件保留的是旧字段时，rename 映射把旧字段改成当前契约要求的新字段
   （即使旧字段已不在当前契约中）；原始审计事件不改写；重试保留原投递身份
   与顺序，且不产生重复通知。
"""

import unittest

from tests.helpers import HttpTestCase


SPEC_V1 = {
    "type": "object", "unknown_policy": "strict",
    "properties": {
        "user_name": {"type": "string"},
        "action": {"type": "string", "enum": ["login", "logout"]},
    },
}

# v2：旧字段 user_name 被改名为 actor（当前契约中不再有 user_name）
SPEC_V2 = {
    "type": "object", "unknown_policy": "strict",
    "properties": {
        "actor": {"type": "string"},
        "action": {"type": "string", "enum": ["login", "logout"]},
    },
}


def _activate(c, sub, etype, version, seq):
    c.post(f"/subscriptions/{sub}/dry-runs",
           {"event_type": etype, "version": version,
            "from_seq": seq, "to_seq": seq})
    s, b = c.post(f"/subscriptions/{sub}/activations",
                  {"event_type": etype, "version": version,
                   "effective_seq": seq}, expect=200)
    return b


def _setup_rename_world(c, sub="sub-a"):
    """v1 治理 seq1；v2 在已是新格式的 seq2 上预演通过并生效；
    seq3 旧生产者仍发旧字段 user_name，被 v2 隔离。"""
    c.post(f"/subscriptions/{sub}", {})
    c.put("/contracts/e/versions/1.0.0", {"spec": SPEC_V1})
    c.put("/contracts/e/versions/2.0.0", {"spec": SPEC_V2})
    # seq1：旧格式，v1 生效并冻结
    c.post(f"/subscriptions/{sub}/events",
           {"seq": 1, "event_type": "e",
            "payload": {"user_name": "a", "action": "login"}})
    _activate(c, sub, "e", "1.0.0", 1)
    c.post(f"/subscriptions/{sub}/scan", {})
    # seq2：已是新格式，v2 在 seq2 预演通过、生效并冻结
    c.post(f"/subscriptions/{sub}/events",
           {"seq": 2, "event_type": "e",
            "payload": {"actor": "b", "action": "login"}})
    _activate(c, sub, "e", "2.0.0", 2)
    c.post(f"/subscriptions/{sub}/scan", {})
    # seq3：旧生产者仍发旧字段 user_name —— 在 v2 下未知字段 + 缺 actor，被隔离
    c.post(f"/subscriptions/{sub}/events",
           {"seq": 3, "event_type": "e",
            "payload": {"user_name": "c", "action": "login"}})
    scan = c.post(f"/subscriptions/{sub}/scan", {})[1]
    assert scan["head_blocked_seq"] == 3
    _, q = c.get(f"/subscriptions/{sub}/quarantine")
    item = next(i for i in q["items"] if i["seq"] == 3)
    assert item["expected_version"] == "2.0.0"
    return item["notification_id"]


class IdempotencyContentConflictTests(HttpTestCase):

    def _live(self, sub="sub-a"):
        self.c.post(f"/subscriptions/{sub}", {})
        self.c.put("/contracts/e/versions/1.0.0", {"spec": SPEC_V1})
        self.c.put("/contracts/e/versions/2.0.0", {"spec": SPEC_V2})
        self.c.post(f"/subscriptions/{sub}/events",
                    {"seq": 1, "event_type": "e",
                     "payload": {"user_name": "a", "action": "login"}})
        self.c.post(f"/subscriptions/{sub}/events",
                    {"seq": 2, "event_type": "e",
                     "payload": {"user_name": "b", "action": "login"}})

    # -- 契约登记：同键改版本/改契约内容都冲突 ------------------------------ #
    def test_register_same_key_changed_spec_conflicts(self):
        body1 = {"spec": SPEC_V1, "idempotency_key": "K1"}
        self.c.put("/contracts/e/versions/1.0.0", body1)
        tweaked = dict(SPEC_V1, unknown_policy="allow")
        s, b = self.c.put("/contracts/e/versions/1.0.0",
                          {"spec": tweaked, "idempotency_key": "K1"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        # 首次结果未被污染：契约仍是原 spec
        _, got = self.c.get("/contracts/e/versions/1.0.0")
        self.assertEqual(got["spec"].get("unknown_policy", "strict"), "strict")

    def test_register_same_key_changed_version_conflicts(self):
        self.c.put("/contracts/e/versions/1.0.0",
                   {"spec": SPEC_V1, "idempotency_key": "K1"})
        s, b = self.c.put("/contracts/e/versions/2.0.0",
                          {"spec": SPEC_V2, "idempotency_key": "K1"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        # 不能因为冲突把 2.0.0 登记进去
        _, vers = self.c.get("/contracts/e/versions")
        self.assertEqual(vers["versions"], ["1.0.0"])

    def test_register_same_key_identical_replays(self):
        body = {"spec": SPEC_V1, "idempotency_key": "K1"}
        r1 = self.c.put("/contracts/e/versions/1.0.0", body)[1]
        r2 = self.c.put("/contracts/e/versions/1.0.0", body)[1]
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["version"], r1["version"])

    # -- 预演：同键改范围/版本冲突 ------------------------------------------ #
    def test_dryrun_same_key_changed_range_conflicts(self):
        self._live()
        body = {"event_type": "e", "version": "1.0.0",
                "from_seq": 1, "to_seq": 1, "idempotency_key": "D1"}
        r1 = self.c.post("/subscriptions/sub-a/dry-runs", body)[1]
        s, b = self.c.post("/subscriptions/sub-a/dry-runs", {
            "event_type": "e", "version": "1.0.0",
            "from_seq": 1, "to_seq": 2, "idempotency_key": "D1"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        # 同键同内容仍回放首次的预演 id
        r3 = self.c.post("/subscriptions/sub-a/dry-runs", body)[1]
        self.assertTrue(r3["replayed"])
        self.assertEqual(r3["dry_run_id"], r1["dry_run_id"])

    def test_dryrun_same_key_changed_version_conflicts(self):
        self._live()
        body1 = {"event_type": "e", "version": "1.0.0",
                 "from_seq": 1, "to_seq": 1, "idempotency_key": "D2"}
        self.c.post("/subscriptions/sub-a/dry-runs", body1)
        s, b = self.c.post("/subscriptions/sub-a/dry-runs", {
            "event_type": "e", "version": "2.0.0",
            "from_seq": 1, "to_seq": 1, "idempotency_key": "D2"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")

    # -- 生效：同键改版本/生效序号冲突 -------------------------------------- #
    def test_activate_same_key_changed_version_conflicts(self):
        self._live()
        self.c.post("/subscriptions/sub-a/dry-runs",
                    {"event_type": "e", "version": "1.0.0",
                     "from_seq": 1, "to_seq": 2})
        self.c.post("/subscriptions/sub-a/dry-runs",
                    {"event_type": "e", "version": "2.0.0",
                     "from_seq": 1, "to_seq": 2})
        self.c.post("/subscriptions/sub-a/activations",
                    {"event_type": "e", "version": "1.0.0",
                     "effective_seq": 1, "idempotency_key": "A1"})
        s, b = self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "e", "version": "2.0.0",
            "effective_seq": 1, "idempotency_key": "A1"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        _, act = self.c.get("/subscriptions/sub-a/activations")
        self.assertEqual(act["activations"][0]["version"], "1.0.0")

    def test_activate_same_key_changed_effective_seq_conflicts(self):
        self._live()
        self.c.post("/subscriptions/sub-a/dry-runs",
                    {"event_type": "e", "version": "1.0.0",
                     "from_seq": 1, "to_seq": 2})
        # 首次在 seq1 生效；同键改到 seq2 必须冲突，不能回放 seq1 的结果
        self.c.post("/subscriptions/sub-a/activations",
                    {"event_type": "e", "version": "1.0.0",
                     "effective_seq": 1, "idempotency_key": "A2"})
        s, b = self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "e", "version": "1.0.0",
            "effective_seq": 2, "idempotency_key": "A2"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")

    # -- 撤销：同键改事件类型冲突 ------------------------------------------ #
    def test_revoke_same_key_changed_event_type_conflicts(self):
        self._live()
        self.c.put("/contracts/f/versions/1.0.0", {"spec": SPEC_V1})
        self.c.post("/subscriptions/sub-a/dry-runs",
                    {"event_type": "e", "version": "1.0.0",
                     "from_seq": 1, "to_seq": 2})
        self.c.post("/subscriptions/sub-a/dry-runs",
                    {"event_type": "f", "version": "1.0.0",
                     "from_seq": 1, "to_seq": 2})
        self.c.post("/subscriptions/sub-a/activations",
                    {"event_type": "e", "version": "1.0.0",
                     "effective_seq": 1})
        self.c.post("/subscriptions/sub-a/activations",
                    {"event_type": "f", "version": "1.0.0",
                     "effective_seq": 1})
        self.c.post("/subscriptions/sub-a/revocations",
                    {"event_type": "e", "idempotency_key": "R1"})
        s, b = self.c.post("/subscriptions/sub-a/revocations", {
            "event_type": "f", "idempotency_key": "R1"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        # f 仍然生效，未被同键异内容误撤销
        _, act = self.c.get("/subscriptions/sub-a/activations")
        active = {a["event_type"] for a in act["activations"]}
        self.assertEqual(active, {"f"})

    # -- 映射登记：同键改映射目标/操作冲突 ---------------------------------- #
    def test_mapping_same_key_changed_target_conflicts(self):
        self._live()
        self.c.post("/subscriptions/sub-a/dry-runs",
                    {"event_type": "e", "version": "1.0.0",
                     "from_seq": 1, "to_seq": 2})
        self.c.post("/subscriptions/sub-a/activations",
                    {"event_type": "e", "version": "1.0.0",
                     "effective_seq": 1})
        body1 = {"event_type": "e", "op": "default",
                 "dst_path": "user_name", "value": "bot",
                 "idempotency_key": "M1"}
        self.c.post("/subscriptions/sub-a/mappings", body1)
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "e", "op": "default",
            "dst_path": "action", "value": "login",
            "idempotency_key": "M1"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        _, lst = self.c.get("/subscriptions/sub-a/mappings")
        self.assertEqual(len(lst["mappings"]), 1)
        self.assertEqual(lst["mappings"][0]["dst_path"], "$.user_name")

    def test_mapping_same_key_changed_seq_conflicts(self):
        self._live()
        self.c.post("/subscriptions/sub-a/dry-runs",
                    {"event_type": "e", "version": "1.0.0",
                     "from_seq": 1, "to_seq": 2})
        self.c.post("/subscriptions/sub-a/activations",
                    {"event_type": "e", "version": "1.0.0",
                     "effective_seq": 1})
        body = {"event_type": "e", "seq": 1, "op": "default",
                "dst_path": "user_name", "value": "bot",
                "idempotency_key": "M2"}
        self.c.post("/subscriptions/sub-a/mappings", body)
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "e", "seq": 2, "op": "default",
            "dst_path": "user_name", "value": "bot",
            "idempotency_key": "M2"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")

    def test_fingerprint_conflict_survives_restart(self):
        # 指纹落库：重启后同键异内容（改版本）仍必须冲突，不能退化成回放
        self.c.put("/contracts/e/versions/1.0.0",
                   {"spec": SPEC_V1, "idempotency_key": "KP"})
        self.restart()
        s, b = self.c.put("/contracts/e/versions/2.0.0",
                          {"spec": SPEC_V2, "idempotency_key": "KP"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        _, vers = self.c.get("/contracts/e/versions")
        self.assertEqual(vers["versions"], ["1.0.0"])


class LegacyFieldRenameTests(HttpTestCase):

    def test_rename_legacy_field_not_in_current_contract_then_retry(self):
        blocked_id = _setup_rename_world(self.c)

        # user_name 已不在当前契约 v2 中；登记 rename user_name -> actor 必须允许：
        # 类型从激活历史中的旧版本 1.0.0 解析（string），与 actor 相同
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "e", "seq": 3, "op": "rename",
            "src_path": "user_name", "dst_path": "actor"})
        self.assertEqual(s, 200, b)
        self.assertTrue(b["registered"])

        r = self.c.post("/subscriptions/sub-a/quarantine/3/retry", {})[1]
        self.assertEqual(r["status"], "recovered")
        # 旧字段已改成当前契约要求的新字段
        self.assertEqual(r["frozen_payload"],
                         {"actor": "c", "action": "login"})
        # 原投递身份保持：复用同一条 notification
        self.assertEqual(r["notification_id"], blocked_id)

        # 原始审计事件绝不被改写
        _, q = self.c.get("/subscriptions/sub-a/quarantine")
        item = next(i for i in q["items"] if i["seq"] == 3)
        self.assertEqual(item["raw_event_summary"]["payload"],
                         {"user_name": "c", "action": "login"})
        self.assertEqual(item["notification_id"], blocked_id)

        # 通知表只有一条 seq3，身份不变；扫描已越过隔离点，顺序保持
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        seq3 = [x for x in n["notifications"] if x["seq"] == 3]
        self.assertEqual(len(seq3), 1)
        self.assertEqual(seq3[0]["notification_id"], blocked_id)
        seqs = [x["seq"] for x in n["notifications"]]
        self.assertEqual(seqs, [1, 2, 3])
        _, st = self.c.get("/subscriptions/sub-a/status")
        self.assertIsNone(st["head_blocked_seq"])
        self.assertEqual(st["scan_seq"], 3)

    def test_legacy_rename_inferred_from_raw_event_when_never_declared(self):
        # 旧字段在任何契约版本中都未声明过（旧生产者误送的额外字段），
        # 当前契约生效后它被 strict 隔离；登记 rename 时类型解析不到历史声明，
        # 退而按隔离原始事件中的 JSON 标量推断（string），仍允许改到新字段。
        c = self.c
        c.post("/subscriptions/si", {})
        # 只有一个契约版本（actor）；user_name 从未被任何版本声明过
        c.put("/contracts/x/versions/1.0.0", {"spec": {
            "type": "object", "unknown_policy": "strict",
            "properties": {"actor": {"type": "string"}}}})
        # seq1 是合法事件，契约在 seq1 生效并冻结
        c.post("/subscriptions/si/events",
               {"seq": 1, "event_type": "x", "payload": {"actor": "a"}})
        _activate(c, "si", "x", "1.0.0", 1)
        c.post("/subscriptions/si/scan", {})
        # seq2 旧生产者误送从未声明的 user_name -> strict 隔离
        c.post("/subscriptions/si/events",
               {"seq": 2, "event_type": "x",
                "payload": {"user_name": "c"}})
        scan = c.post("/subscriptions/si/scan", {})[1]
        self.assertEqual(scan["head_blocked_seq"], 2)
        _, q = c.get("/subscriptions/si/quarantine")
        blocked_id = q["items"][0]["notification_id"]
        s, b = c.post("/subscriptions/si/mappings", {
            "event_type": "x", "seq": 2, "op": "rename",
            "src_path": "user_name", "dst_path": "actor"})
        self.assertEqual(s, 200, b)
        r = c.post("/subscriptions/si/quarantine/2/retry", {})[1]
        self.assertEqual(r["status"], "recovered")
        self.assertEqual(r["notification_id"], blocked_id)
        self.assertEqual(r["frozen_payload"], {"actor": "c"})

    def test_retry_after_legacy_rename_is_idempotent_no_duplicate(self):
        blocked_id = _setup_rename_world(self.c)
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "e", "seq": 3, "op": "rename",
            "src_path": "user_name", "dst_path": "actor"})
        r0 = self.c.post("/subscriptions/sub-a/quarantine/3/retry", {})[1]
        self.assertEqual(r0["notification_id"], blocked_id)
        # 恢复后再次重试：幂等返回既有身份，不产生重复通知
        for i in range(3):
            r = self.c.post("/subscriptions/sub-a/quarantine/3/retry",
                            {"idempotency_key": f"RT{i}"})[1]
            self.assertTrue(r.get("replayed"))
            self.assertEqual(r["notification_id"], blocked_id)
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        seq3 = [x for x in n["notifications"] if x["seq"] == 3]
        self.assertEqual(len(seq3), 1)

    def test_legacy_rename_type_mismatch_still_rejected(self):
        # 旧字段在旧契约里是 int，新字段要求 string：借旧字段改名也不能改类型
        v1 = {"type": "object", "unknown_policy": "strict", "properties": {
            "uid": {"type": "int"}, "code": {"type": "string"}}}
        v2 = {"type": "object", "unknown_policy": "strict", "properties": {
            "who": {"type": "string"}, "code": {"type": "string"}}}
        self.c.post("/subscriptions/s", {})
        self.c.put("/contracts/t/versions/1.0.0", {"spec": v1})
        self.c.put("/contracts/t/versions/2.0.0", {"spec": v2})
        # seq1 旧格式，v1 生效冻结
        self.c.post("/subscriptions/s/events",
                    {"seq": 1, "event_type": "t",
                     "payload": {"uid": 1, "code": "x"}})
        _activate(self.c, "s", "t", "1.0.0", 1)
        self.c.post("/subscriptions/s/scan", {})
        # seq2 新格式，v2 生效冻结
        self.c.post("/subscriptions/s/events",
                    {"seq": 2, "event_type": "t",
                     "payload": {"who": "z", "code": "y"}})
        _activate(self.c, "s", "t", "2.0.0", 2)
        self.c.post("/subscriptions/s/scan", {})
        # seq3 旧生产者发 uid（int），v2 下隔离
        self.c.post("/subscriptions/s/events",
                    {"seq": 3, "event_type": "t",
                     "payload": {"uid": 7, "code": "z"}})
        self.c.post("/subscriptions/s/scan", {})
        s, b = self.c.post("/subscriptions/s/mappings", {
            "event_type": "t", "seq": 3, "op": "rename",
            "src_path": "uid", "dst_path": "who"}, expect=409)
        self.assertEqual(b["error"], "mapping_type_mismatch")
        self.assertEqual(b["detail"]["src_type"], "int")
        self.assertEqual(b["detail"]["dst_type"], "string")

    def test_legacy_rename_unknown_source_without_history_conflicts(self):
        # 旧字段在任何历史版本/隔离原始事件中都不存在时，不能凭空造字段
        _setup_rename_world(self.c, "sub-b")
        s, b = self.c.post("/subscriptions/sub-b/mappings", {
            "event_type": "e", "seq": 3, "op": "rename",
            "src_path": "ghost", "dst_path": "actor"}, expect=404)
        self.assertEqual(b["error"], "mapping_src_unknown")


if __name__ == "__main__":
    unittest.main()
