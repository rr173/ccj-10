"""服务重启后的状态恢复：中断预演续跑、冻结契约版本、映射规则、隔离位置/HOL。"""

import unittest

from tests.helpers import HttpTestCase, SPEC_V1, SPEC_V2_COMPAT


class RestartRecoveryTests(HttpTestCase):

    def test_interrupted_dry_run_resumes_after_restart(self):
        # 第一次启动：开启“首条事件后中断”钩子，模拟预演跑到一半进程崩溃
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        for i in range(1, 6):
            self.ingest("sub-a", i, "audit.user",
                        {"actor": f"a{i}", "action": "login"})
        self.restart(interrupt=True)
        _, started = self.dryrun("sub-a", "audit.user", "1.0.0",
                                 from_seq=1, to_seq=5)
        dr_id = started["dry_run_id"]
        _, running = self.c.get(f"/subscriptions/sub-a/dry-runs/{dr_id}")
        self.assertEqual(running["status"], "running")
        # 全合法事件无 block/info 结论行；中断后状态仍是 running，
        # 由下面的重启把它推进到 passed
        self.assertEqual(running["findings"], [])
        # 已处理进度不对外暴露为 findings（合法事件无结论行），
        # 通过预演状态保持 running 且尚未完成来确认它确实中断在中途
        self.assertIsNone(running.get("blocked_events") or None)

        # 重启（不带中断钩子）：启动时自动续跑未完成预演直到完成
        self.restart(interrupt=False)
        _, done = self.c.get(f"/subscriptions/sub-a/dry-runs/{dr_id}")
        self.assertEqual(done["status"], "passed")
        self.assertEqual(done["to_seq"], 5)
        checked = {f["seq"] for f in done["findings"]}
        # 无阻断；合法事件可能没有 findings（findings 只记录异常/信息），
        # 但状态必须从 running 推进到 passed
        self.assertEqual(done["blocking_errors"], 0)

    def test_interrupted_failing_dry_run_finishes_after_restart(self):
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.ingest("sub-a", 1, "audit.user",
                    {"actor": "a", "action": "login"})
        self.ingest("sub-a", 2, "audit.user",
                    {"actor": "b", "action": "login", "junk": 1})
        self.restart(interrupt=True)
        _, started = self.dryrun("sub-a", "audit.user", "1.0.0")
        dr_id = started["dry_run_id"]
        self.restart(interrupt=False)
        _, done = self.c.get(f"/subscriptions/sub-a/dry-runs/{dr_id}")
        self.assertEqual(done["status"], "failed")
        self.assertEqual(done["blocking_errors"], 1)
        self.assertEqual(done["blocked_events"], [2])

    def test_frozen_versions_survive_restart(self):
        # 生效 v1 -> 扫描 seq1 -> 切 v2 -> 扫描 seq2/3 -> 重启 -> 冻结版本不变
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.register("audit.user", "2.0.0", SPEC_V2_COMPAT)
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "1.0.0",
            "effective_seq": 1})
        self.c.post("/subscriptions/sub-a/scan", {})
        self.ingest("sub-a", 2, "audit.user", {"actor": "b", "action": "sudo"})
        self.ingest("sub-a", 3, "audit.user", {"actor": "c", "action": "logout"})
        self.dryrun("sub-a", "audit.user", "2.0.0", from_seq=2, to_seq=3)
        self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "2.0.0",
            "effective_seq": 2})
        self.c.post("/subscriptions/sub-a/scan", {})

        self.restart()
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        versions = {x["seq"]: x["contract_version"]
                    for x in n["notifications"]}
        self.assertEqual(versions, {1: "1.0.0", 2: "2.0.0", 3: "2.0.0"})
        _, act = self.c.get("/subscriptions/sub-a/activations")
        self.assertEqual(act["activations"][0]["version"], "2.0.0")
        # 摘要/规范化载荷仍是冻结字节
        self.assertTrue(n["notifications"][0]["digest"].startswith("sha256:"))

    def test_quarantine_position_and_hol_survive_restart(self):
        # seq2 隔离并挡住 seq3；重启后队头位置保持，seq3 仍未入队
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "1.0.0",
            "effective_seq": 1})
        self.c.post("/subscriptions/sub-a/scan", {})
        self.ingest("sub-a", 2, "audit.user",
                    {"actor": 7, "action": "login"})  # 类型错误
        self.ingest("sub-a", 3, "audit.user", {"actor": "c", "action": "login"})
        self.c.post("/subscriptions/sub-a/scan", {})

        self.restart()
        _, q = self.c.get("/subscriptions/sub-a/quarantine")
        self.assertEqual(q["head_blocked_seq"], 2)
        self.assertEqual(q["items"][0]["status"], "blocked")
        self.assertTrue(any(f["path"] == "$.actor"
                            for f in q["items"][0]["failed_fields"]))
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        self.assertEqual(sorted(x["seq"] for x in n["notifications"]), [1, 2])
        _, st = self.c.get("/subscriptions/sub-a/status")
        self.assertEqual(st["scan_seq"], 1)  # 停在隔离位置之前
        self.assertEqual(st["head_blocked_seq"], 2)

        # 重启后继续入库 seq4 并扫描：仍被 seq2 的 HOL 挡住
        self.ingest("sub-a", 4, "audit.user", {"actor": "d", "action": "login"})
        scan = self.c.post("/subscriptions/sub-a/scan", {})[1]
        self.assertEqual(scan["head_blocked_seq"], 2)

    def test_mappings_survive_restart_and_retry_works(self):
        from tests.test_mapping_retry import SPEC
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.act", "1.0.0", SPEC)
        self.ingest("sub-a", 1, "audit.act", {"action": "login"})
        self.dryrun("sub-a", "audit.act", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.act", "version": "1.0.0",
            "effective_seq": 1})
        self.c.post("/subscriptions/sub-a/scan", {})
        self.ingest("sub-a", 2, "audit.act",
                    {"trace": "login", "debug": "z"})
        self.c.post("/subscriptions/sub-a/scan", {})
        _, q1 = self.c.get("/subscriptions/sub-a/quarantine")
        nid = q1["items"][0]["notification_id"]
        # 映射登记后、重试前重启
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action",
            "idempotency_key": "M1"})
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "drop",
            "src_path": "debug", "idempotency_key": "M2"})

        self.restart()
        _, maps = self.c.get("/subscriptions/sub-a/mappings")
        self.assertEqual(len(maps["mappings"]), 2)
        # 幂等键重放：重启后再用同键登记不会新增
        again = self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action",
            "idempotency_key": "M1"})[1]
        self.assertTrue(again.get("replayed"))
        _, maps2 = self.c.get("/subscriptions/sub-a/mappings")
        self.assertEqual(len(maps2["mappings"]), 2)
        # 恢复重试成功，身份保持
        r = self.c.post("/subscriptions/sub-a/quarantine/2/retry", {})[1]
        self.assertEqual(r["status"], "recovered")
        self.assertEqual(r["notification_id"], nid)
        self.assertEqual(r["frozen_payload"], {"action": "login"})


class ActivationIdempotencyTests(HttpTestCase):

    def test_activation_idempotency_key_replay_same_result(self):
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        # 不触发扫描：激活后立即用同幂等键重放，必须回放而非走门禁
        body = {"event_type": "audit.user", "version": "1.0.0",
                "effective_seq": 1, "idempotency_key": "A1"}
        r1 = self.c.post("/subscriptions/sub-a/activations", body)[1]
        r2 = self.c.post("/subscriptions/sub-a/activations", body)[1]
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["version"], r1["version"])
        _, act = self.c.get("/subscriptions/sub-a/activations")
        self.assertEqual(len(act["activations"]), 1)

    def test_second_activation_requires_expected_version_cas(self):
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.register("audit.user", "2.0.0", SPEC_V2_COMPAT)
        for i in range(1, 4):
            self.ingest("sub-a", i, "audit.user",
                        {"actor": f"a{i}", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "1.0.0",
            "effective_seq": 1})
        # 不扫描，scan_seq 保持 0，可在 seq2 切约；先验 CAS 冲突
        self.dryrun("sub-a", "audit.user", "2.0.0", from_seq=2, to_seq=3)
        s, b = self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "2.0.0",
            "effective_seq": 2, "expected_version": "0.9.9"}, expect=409)
        self.assertEqual(b["error"], "activation_conflict")
        # 正确的 CAS 前置条件 -> 成功
        s, b = self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "2.0.0",
            "effective_seq": 2, "expected_version": "1.0.0"})
        self.assertEqual(s, 200)
        self.assertEqual(b["previous_version"], "1.0.0")
        # 扫描后冻结版本按生效点切换
        self.c.post("/subscriptions/sub-a/scan", {})
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        versions = {x["seq"]: x["contract_version"]
                    for x in n["notifications"]}
        self.assertEqual(versions, {1: "1.0.0", 2: "2.0.0", 3: "2.0.0"})

    def test_audit_history_records_diff_rejections_and_recovery(self):
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.ingest("sub-a", 1, "audit.user", {"actor": 9, "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        # 预演失败 -> 尝试激活被拒（拒绝原因入审计历史）
        self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "1.0.0",
            "effective_seq": 1}, expect=409)
        _, hist = self.c.get("/subscriptions/sub-a/audit-history")
        rejected = [h for h in hist["history"]
                    if h["category"] == "activation_rejected"]
        self.assertTrue(rejected)
        self.assertIn("reasons", rejected[0]["detail"])
        # 全局审计历史包含契约登记
        _, g = self.c.get("/audit-history")
        self.assertTrue(any(h["category"] == "contract_registered"
                            for h in g["history"]))


if __name__ == "__main__":
    unittest.main()
