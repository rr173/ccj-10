"""映射规则登记校验、确定性修复重试、身份与顺序保持、重试不重复。"""

import unittest

from tests.helpers import HttpTestCase, SPEC_V1


# 与 SPEC_V1 类似；包含异类型叶子，便于演示 rename 的类型护栏
SPEC = {
    "type": "object", "unknown_policy": "strict",
    "properties": {
        "actor": {"type": "string", "required": False},
        "action": {"type": "string", "enum": ["login", "logout"]},
        "trace": {"type": "string", "required": False},
        "count": {"type": "int", "required": False},
        "debug": {"type": "string", "required": False, "ignorable": True},
    },
}


class MappingTests(HttpTestCase):

    def _strict_live(self, sub="sub-a"):
        self.c.post(f"/subscriptions/{sub}", {})
        self.register("audit.act", "1.0.0", SPEC)
        # 用 seq1 的合法事件完成预演 + 生效 + 扫描
        self.ingest(sub, 1, "audit.act", {"action": "login"})
        _, dr = self.dryrun(sub, "audit.act", "1.0.0", from_seq=1, to_seq=1)
        self.assertEqual(dr["status"], "passed")
        self.c.post(f"/subscriptions/{sub}/activations", {
            "event_type": "audit.act", "version": "1.0.0",
            "effective_seq": 1})
        self.c.post(f"/subscriptions/{sub}/scan", {})

    # -- 登记校验：三类允许 / 两类禁止 ------------------------------------ #
    def test_rename_only_between_known_leafs_same_type(self):
        self._strict_live()
        # trace -> actor，同为 string，允许
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "rename",
            "src_path": "trace", "dst_path": "actor"})
        self.assertEqual(s, 200)
        # 源未知
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "rename",
            "src_path": "ghost", "dst_path": "actor"}, expect=404)
        self.assertEqual(b["error"], "mapping_src_unknown")
        # 目标未知
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "rename",
            "src_path": "actor", "dst_path": "ghost"}, expect=404)
        self.assertEqual(b["error"], "mapping_dst_unknown")
        # 同一生效契约内异类型字段之间 rename 被禁止（不能借重命名改类型）
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "rename",
            "src_path": "action", "dst_path": "count"}, expect=409)
        self.assertEqual(b["error"], "mapping_type_mismatch")

    def test_default_must_match_type_or_enum(self):
        self._strict_live()
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "default",
            "dst_path": "actor", "value": "svc-bot"})
        self.assertEqual(s, 200)
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "default",
            "dst_path": "action", "value": "rm -rf"}, expect=409)
        self.assertEqual(b["error"], "mapping_value_type_mismatch")

    def test_drop_only_for_ignorable_field(self):
        self._strict_live()
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "drop",
            "src_path": "debug"})
        self.assertEqual(s, 200)
        s, b = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "drop",
            "src_path": "trace"}, expect=409)
        self.assertEqual(b["error"], "drop_not_allowed")

    def test_mapping_requires_active_contract(self):
        self.c.post("/subscriptions/sub-x", {})
        self.register("audit.act", "1.0.0", SPEC)
        s, b = self.c.post("/subscriptions/sub-x/mappings", {
            "event_type": "audit.act", "op": "drop",
            "src_path": "debug"}, expect=409)
        self.assertEqual(b["error"], "no_active_contract")

    def test_mapping_idempotent_conflict(self):
        self._strict_live()
        body = {"event_type": "audit.act", "op": "drop",
                "src_path": "debug", "idempotency_key": "D1"}
        r1 = self.c.post("/subscriptions/sub-a/mappings", body)[1]
        r2 = self.c.post("/subscriptions/sub-a/mappings", body)[1]
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["mapping_id"], r1["mapping_id"])
        # 同一规则无键重复登记也返回既有 id（不重复落库）
        r3 = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "drop", "src_path": "debug"})[1]
        self.assertTrue(r3.get("replayed"))
        _, lst = self.c.get("/subscriptions/sub-a/mappings")
        self.assertEqual(len(lst["mappings"]), 1)

    # -- 修复重试：rename + default + drop 组合 ---------------------------- #
    def test_rename_default_drop_then_retry_recovers(self):
        self._strict_live()
        # seq2 是真正的坏事件：
        #  - 必填 action 缺失，值被误放进已声明字段 trace -> rename trace -> action
        #  - 携带声明为 ignorable 的 debug 字段 -> drop 允许删除
        self.ingest("sub-a", 2, "audit.act",
                    {"trace": "login", "debug": "x"})
        scan = self.c.post("/subscriptions/sub-a/scan", {})[1]
        self.assertEqual(scan["head_blocked_seq"], 2)
        _, q = self.c.get("/subscriptions/sub-a/quarantine")
        blocked_id = q["items"][0]["notification_id"]
        failed_paths = {f["path"] for f in q["items"][0]["failed_fields"]}
        self.assertIn("$.action", failed_paths)

        # 登记确定性映射（绑定 seq=2）
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action"})
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "drop",
            "src_path": "debug"})

        r = self.c.post("/subscriptions/sub-a/quarantine/2/retry", {})[1]
        self.assertEqual(r["status"], "recovered")
        # 投递身份保持：仍是同一条 notification
        self.assertEqual(r["notification_id"], blocked_id)
        self.assertEqual(r["frozen_payload"], {"action": "login"})
        # 事件表中的原始事件未被映射改写（隔离查询保留原始摘要）
        _, q2 = self.c.get("/subscriptions/sub-a/quarantine")
        item = next(i for i in q2["items"] if i["seq"] == 2)
        self.assertEqual(item["status"], "recovered")
        self.assertEqual(item["raw_event_summary"]["payload"],
                         {"trace": "login", "debug": "x"})
        self.assertEqual(item["notification_id"], blocked_id)
        # 通知表没有产生第二条 seq2 通知
        _, n_after = self.c.get("/subscriptions/sub-a/notifications")
        seq2_rows = [x for x in n_after["notifications"] if x["seq"] == 2]
        self.assertEqual(len(seq2_rows), 1)
        self.assertEqual(seq2_rows[0]["notification_id"], blocked_id)

    def test_default_mapping_fills_missing_required(self):
        # 单独演示 default：action 缺失时补固定枚举值
        spec = {
            "type": "object", "unknown_policy": "strict",
            "properties": {
                "actor": {"type": "string"},
                "action": {"type": "string", "enum": ["login", "logout"]},
            },
        }
        self.c.post("/subscriptions/sd", {})
        self.register("e", "1.0.0", spec)
        self.ingest("sd", 1, "e", {"actor": "a", "action": "login"})
        self.dryrun("sd", "e", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sd/activations", {
            "event_type": "e", "version": "1.0.0", "effective_seq": 1})
        self.c.post("/subscriptions/sd/scan", {})
        self.ingest("sd", 2, "e", {"actor": "b"})
        self.c.post("/subscriptions/sd/scan", {})
        _, q = self.c.get("/subscriptions/sd/quarantine")
        self.assertEqual(q["head_blocked_seq"], 2)
        self.c.post("/subscriptions/sd/mappings", {
            "event_type": "e", "seq": 2, "op": "default",
            "dst_path": "action", "value": "login"})
        r = self.c.post("/subscriptions/sd/quarantine/2/retry", {})[1]
        self.assertEqual(r["frozen_payload"],
                         {"action": "login", "actor": "b"})

    def test_retry_without_fix_stays_quarantined(self):
        self._strict_live()
        self.ingest("sub-a", 2, "audit.act", {"trace": "login"})
        self.c.post("/subscriptions/sub-a/scan", {})
        s, b = self.c.post("/subscriptions/sub-a/quarantine/2/retry", {},
                           expect=422)
        self.assertEqual(b["error"], "retry_still_invalid")
        _, q = self.c.get("/subscriptions/sub-a/quarantine")
        self.assertEqual(q["items"][0]["status"], "blocked")
        self.assertEqual(q["items"][0]["retry_count"], 1)

    def test_replay_retry_is_idempotent_and_never_duplicates(self):
        # 与恢复用例同样的编排，但在独立 setUp 的干净实例中执行
        self._strict_live()
        self.ingest("sub-a", 2, "audit.act",
                    {"trace": "login", "debug": "x"})
        self.c.post("/subscriptions/sub-a/scan", {})
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action"})
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "drop",
            "src_path": "debug"})
        r0 = self.c.post("/subscriptions/sub-a/quarantine/2/retry", {})[1]
        nid = r0["notification_id"]
        # 恢复后再重试：返回既有结果，通知不重复
        r = self.c.post("/subscriptions/sub-a/quarantine/2/retry",
                        {"idempotency_key": "RT1"})[1]
        self.assertTrue(r.get("replayed"))
        self.assertEqual(r["notification_id"], nid)
        r2 = self.c.post("/subscriptions/sub-a/quarantine/2/retry",
                         {"idempotency_key": "RT1"})[1]
        self.assertTrue(r2.get("replayed"))
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        seq2 = [x for x in n["notifications"] if x["seq"] == 2]
        self.assertEqual(len(seq2), 1)
        self.assertEqual(seq2[0]["notification_id"], nid)

    def test_head_of_line_order_preserved_on_recovery(self):
        self._strict_live()
        # seq2、seq3 都缺 action（值错放进 trace）：泵停在 seq2
        self.ingest("sub-a", 2, "audit.act", {"trace": "login"})
        self.ingest("sub-a", 3, "audit.act", {"trace": "logout"})
        self.c.post("/subscriptions/sub-a/scan", {})
        # seq3 尚未进隔离（泵停在 seq2），对它重试返回 404
        s, b = self.c.post("/subscriptions/sub-a/quarantine/3/retry", {},
                           expect=404)
        self.assertEqual(b["error"], "quarantine_not_found")
        # 通用映射（seq=NULL）：trace->action 重命名 + 补固定 actor
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "rename",
            "src_path": "trace", "dst_path": "action"})
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "op": "default",
            "dst_path": "actor", "value": "bot"})
        # 恢复 seq2 后泵继续，seq3 在扫描时不带映射（映射仅用于重试），
        # 因此 seq3 进隔离，再重试恢复——顺序始终按 seq 推进
        self.c.post("/subscriptions/sub-a/quarantine/2/retry", {})
        _, q = self.c.get("/subscriptions/sub-a/quarantine")
        self.assertEqual(q["head_blocked_seq"], 3)
        self.c.post("/subscriptions/sub-a/quarantine/3/retry", {})
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        seqs = [x["seq"] for x in n["notifications"]]
        self.assertEqual(seqs, [1, 2, 3])
        ids = [x["notification_id"] for x in n["notifications"]]
        self.assertEqual(len(set(ids)), 3)
        _, st = self.c.get("/subscriptions/sub-a/status")
        self.assertIsNone(st["head_blocked_seq"])
        self.assertEqual(st["scan_seq"], 3)


if __name__ == "__main__":
    unittest.main()
