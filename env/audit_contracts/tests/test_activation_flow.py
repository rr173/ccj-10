"""预演、生效门禁与序号边界的端到端场景。"""

import json
import threading
import unittest

from tests.helpers import Client, HttpTestCase, SPEC_V1, SPEC_V2_COMPAT, free_port
from app.service import Reject, Service


class FlowMixin:
    def bootstrap(self, spec=SPEC_V1):
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", spec)
        self.register("audit.user", "2.0.0", SPEC_V2_COMPAT)

    def activate_v1(self, sub="sub-a", etype="audit.user", version="1.0.0",
                    effective_seq=1, expect=200):
        return self.c.post(f"/subscriptions/{sub}/activations", {
            "event_type": etype, "version": version,
            "effective_seq": effective_seq}, expect)


class DryRunTests(FlowMixin, HttpTestCase):

    def test_dryrun_reports_each_bad_event_path_and_reason(self):
        self.bootstrap()
        # seq1 合法；seq2 未知字段（v1 strict 阻断）；seq3 action 枚举越界
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.ingest("sub-a", 2, "audit.user",
                    {"actor": "b", "action": "logout", "junk": 1})
        self.ingest("sub-a", 3, "audit.user", {"actor": "c", "action": "rm"})
        _, b = self.dryrun("sub-a", "audit.user", "1.0.0")
        self.assertEqual(b["status"], "failed")
        self.assertEqual(b["blocking_errors"], 2)
        self.assertEqual(b["blocked_events"], [2, 3])
        paths = {(f["seq"], f["path"]) for f in b["findings"]
                 if f["severity"] == "block"}
        self.assertIn((2, "$.junk"), paths)
        self.assertIn((3, "$.action"), paths)
        # 失败预演结论也进入审计历史
        _, hist = self.c.get("/subscriptions/sub-a/audit-history")
        cats = {h["category"] for h in hist["history"]}
        self.assertIn("dryrun_finished", cats)

    def test_dryrun_beyond_stable_rejected(self):
        self.bootstrap()
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        _, b = self.dryrun("sub-a", "audit.user", "1.0.0",
                           from_seq=1, to_seq=5, expect=422)
        self.assertEqual(b["error"], "dryrun_range_beyond_stable")

    def test_dryrun_on_partial_history(self):
        self.bootstrap()
        for i in range(1, 4):
            self.ingest("sub-a", i, "audit.user",
                        {"actor": f"a{i}", "action": "login"})
        _, b = self.dryrun("sub-a", "audit.user", "1.0.0",
                           from_seq=1, to_seq=2)
        self.assertEqual(b["status"], "passed")
        self.assertEqual(b["to_seq"], 2)

    def test_dryrun_strip_policy_records_info_not_block(self):
        self.bootstrap()
        self.ingest("sub-a", 1, "audit.user",
                    {"actor": "a", "action": "sudo", "extra": "x"})
        _, b = self.dryrun("sub-a", "audit.user", "2.0.0")
        self.assertEqual(b["status"], "passed")
        info = [f for f in b["findings"] if f["severity"] == "info"]
        self.assertTrue(any(f["path"] == "$.extra" for f in info))


class ActivationGateTests(FlowMixin, HttpTestCase):

    def test_cannot_activate_without_dryrun(self):
        self.bootstrap()
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        s, b = self.activate_v1(expect=409)
        self.assertEqual(b["error"], "activation_rejected")
        self.assertTrue(any("dry_run_missing" in r for r in b["detail"]["reasons"]))

    def test_cannot_activate_after_failed_dryrun(self):
        self.bootstrap()
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "bad": 1})
        _, dr = self.dryrun("sub-a", "audit.user", "1.0.0")
        self.assertEqual(dr["status"], "failed")
        s, b = self.activate_v1(expect=409)
        self.assertTrue(any("dry_run_failed" in r for r in b["detail"]["reasons"]))

    def test_effective_seq_beyond_stable_rejected(self):
        self.bootstrap()
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        s, b = self.activate_v1(effective_seq=2, expect=409)
        self.assertTrue(any("beyond_stable" in r for r in b["detail"]["reasons"]))

    def test_effective_seq_at_or_before_scan_rejected(self):
        self.bootstrap()
        for i in range(1, 4):
            self.ingest("sub-a", i, "audit.user",
                        {"actor": f"a{i}", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0")
        self.activate_v1(effective_seq=1)
        self.c.post("/subscriptions/sub-a/scan", {})
        # scan_seq 现在为 3；再次激活落在已扫描位置必须拒绝
        self.dryrun("sub-a", "audit.user", "2.0.0")
        s, b = self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "2.0.0",
            "effective_seq": 3}, expect=409)
        self.assertTrue(any("before_scan_position" in r
                            for r in b["detail"]["reasons"]))

    def test_dryrun_must_cover_effective_seq(self):
        self.bootstrap()
        for i in range(1, 4):
            self.ingest("sub-a", i, "audit.user",
                        {"actor": f"a{i}", "action": "login"})
        # 只预演 [1,1]，却想在 seq=3 生效
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        s, b = self.activate_v1(effective_seq=3, expect=409)
        self.assertTrue(any("not_covering_effective_seq" in r
                            for r in b["detail"]["reasons"]))

    def test_successful_activation_freeze_switch_at_effective_seq(self):
        self.bootstrap()
        # 先只入库 seq1：按 v1 冻结
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        self.activate_v1(effective_seq=1)
        self.c.post("/subscriptions/sub-a/scan", {})
        # 再入库 seq2（v2 才有的枚举 sudo）与 seq3，此时尚未换约
        self.ingest("sub-a", 2, "audit.user", {"actor": "b", "action": "sudo"})
        self.ingest("sub-a", 3, "audit.user", {"actor": "c", "action": "logout"})
        # seq2 起切换 v2：预演覆盖 [2,3]，生效点 2（>scan_seq=1, <=stable=3）
        self.dryrun("sub-a", "audit.user", "2.0.0", from_seq=2, to_seq=3)
        s, b = self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "audit.user", "version": "2.0.0",
            "effective_seq": 2})
        self.assertEqual(b["previous_version"], "1.0.0")
        self.c.post("/subscriptions/sub-a/scan", {})
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        versions = {x["seq"]: x["contract_version"]
                    for x in n["notifications"]}
        self.assertEqual(versions, {1: "1.0.0", 2: "2.0.0", 3: "2.0.0"})
        # 已排队的 seq1 冻结载荷不随后续换约改变
        self.assertEqual(n["notifications"][0]["frozen_payload"]["action"], "login")
        # 每条通知冻结了规范化载荷摘要与验证摘要
        for x in n["notifications"]:
            self.assertTrue(x["digest"].startswith("sha256:"))
            self.assertIn("valid", x["validation"])


class ValidationAtIngestTests(FlowMixin, HttpTestCase):

    def test_type_error_quarantines_and_blocks_head_of_line(self):
        self.bootstrap()
        self.c.post("/subscriptions/sub-b", {})
        self.ingest("sub-b", 1, "audit.user", {"actor": "a", "action": "login"})
        self.ingest("sub-b", 2, "audit.user", {"actor": 123, "action": "login"})
        self.ingest("sub-b", 3, "audit.user", {"actor": "c", "action": "login"})
        self.dryrun("sub-b", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sub-b/activations", {
            "event_type": "audit.user", "version": "1.0.0",
            "effective_seq": 1})
        scan = self.c.post("/subscriptions/sub-b/scan", {})[1]
        self.assertEqual(scan["head_blocked_seq"], 2)
        _, q = self.c.get("/subscriptions/sub-b/quarantine")
        self.assertEqual(q["head_blocked_seq"], 2)
        item = q["items"][0]
        self.assertTrue(any(f["path"] == "$.actor" and "string" in f["reason"]
                            for f in item["failed_fields"]))
        self.assertEqual(item["current_contract"]["version"], "1.0.0")
        # seq3 被头阻塞，尚未冻结/入队；seq2 有一条 blocked 状态的冻结行
        _, n = self.c.get("/subscriptions/sub-b/notifications")
        by_seq = {x["seq"]: x for x in n["notifications"]}
        self.assertEqual(sorted(by_seq), [1, 2])
        self.assertEqual(by_seq[1]["status"], "queued")
        self.assertEqual(by_seq[2]["status"], "blocked")

        # 管理员尝试在阻断点激活放宽的 v2：但 v2 对 seq2 的类型错误同样无法通过
        # 预演（类型错误无法靠 unknown_policy 放宽），门禁必须拒绝
        _, bad2 = self.dryrun("sub-b", "audit.user", "2.0.0",
                              from_seq=2, to_seq=2)
        self.assertEqual(bad2["status"], "failed")
        self.assertTrue(any(f["path"] == "$.actor" for f in bad2["findings"]))
        s, rej = self.c.post("/subscriptions/sub-b/activations", {
            "event_type": "audit.user", "version": "2.0.0",
            "effective_seq": 2}, expect=409)
        self.assertTrue(any("dry_run_failed" in r for r in rej["detail"]["reasons"]))
        # 不允许越过队头重试 seq3
        s, hol = self.c.post("/subscriptions/sub-b/quarantine/3/retry", {},
                             expect=404)
        self.assertEqual(hol["error"], "quarantine_not_found")
        # HOL 仍保持：seq2 仍是队头
        _, q2 = self.c.get("/subscriptions/sub-b/quarantine")
        self.assertEqual(q2["head_blocked_seq"], 2)

    def test_unknown_field_strict_blocks_strip_allows(self):
        # 第一段：strict v1 合法生效并扫描 seq1
        self.bootstrap()
        self.c.post("/subscriptions/sub-c", {})
        self.ingest("sub-c", 1, "audit.user",
                    {"actor": "a", "action": "login"})
        self.dryrun("sub-c", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sub-c/activations", {
            "event_type": "audit.user", "version": "1.0.0",
            "effective_seq": 1})
        self.c.post("/subscriptions/sub-c/scan", {})
        # 第二段：扫描位置之后出现携带未知字段的事件，strict v1 隔离并 HOL
        self.ingest("sub-c", 2, "audit.user",
                    {"actor": "b", "action": "login", "junk": True})
        self.c.post("/subscriptions/sub-c/scan", {})
        _, q = self.c.get("/subscriptions/sub-c/quarantine")
        self.assertEqual(q["head_blocked_seq"], 2)
        self.assertTrue(any(f["path"] == "$.junk"
                            for f in q["items"][0]["failed_fields"]))
        # 第三段：在阻断点激活 strip 的 v2（预演通过），重试后 junk 被规范化删除
        self.dryrun("sub-c", "audit.user", "2.0.0", from_seq=2, to_seq=2)
        self.c.post("/subscriptions/sub-c/activations", {
            "event_type": "audit.user", "version": "2.0.0",
            "effective_seq": 2})
        r = self.c.post("/subscriptions/sub-c/quarantine/2/retry", {})[1]
        self.assertEqual(r["status"], "recovered")
        _, n = self.c.get("/subscriptions/sub-c/notifications")
        by_seq = {x["seq"]: x for x in n["notifications"]}
        self.assertNotIn("junk", by_seq[2]["frozen_payload"])
        self.assertEqual(by_seq[2]["contract_version"], "2.0.0")
        self.assertEqual(by_seq[1]["contract_version"], "1.0.0")
        _, status = self.c.get("/subscriptions/sub-c/status")
        self.assertEqual(status["scan_seq"], 2)


class RevocationTests(FlowMixin, HttpTestCase):

    def test_revoke_then_events_unregulated(self):
        self.bootstrap()
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0")
        self.activate_v1(effective_seq=1)
        self.c.post("/subscriptions/sub-a/scan", {})
        self.c.post("/subscriptions/sub-a/revocations",
                    {"event_type": "audit.user"})
        # 撤销后入库一个 v1 下会非法的事件，扫描应直接入队、不隔离
        self.ingest("sub-a", 2, "audit.user", {"anything": 42})
        scan = self.c.post("/subscriptions/sub-a/scan", {})[1]
        self.assertIsNone(scan["head_blocked_seq"])
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        self.assertEqual([x["seq"] for x in n["notifications"]], [1, 2])
        self.assertIsNone(n["notifications"][1]["contract_version"])

    def test_revoke_without_activation_404(self):
        self.bootstrap()
        s, b = self.c.post("/subscriptions/sub-a/revocations",
                           {"event_type": "audit.user"}, expect=404)
        self.assertEqual(b["error"], "no_active_activation")

    def test_revoke_idempotent_replay(self):
        self.bootstrap()
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0")
        self.activate_v1(effective_seq=1)
        r1 = self.c.post("/subscriptions/sub-a/revocations",
                         {"event_type": "audit.user", "idempotency_key": "R1"})[1]
        r2 = self.c.post("/subscriptions/sub-a/revocations",
                         {"event_type": "audit.user", "idempotency_key": "R1"})[1]
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["version"], r1["version"])


class ConcurrentActivationTests(HttpTestCase):
    """跨连接并发激活：BEGIN IMMEDIATE + 部分唯一索引，只有一个版本成功。"""

    def test_concurrent_activate_only_one_wins(self):
        db = self.db_path

        def run(version, outcomes, idx):
            svc = Service(db)
            try:
                r = svc.activate("sub-a", "audit.user", version,
                                 effective_seq=1, expected_absent=True)
                outcomes[idx] = ("ok", r["version"])
            except Reject as e:
                outcomes[idx] = ("reject", e.reason)
            except Exception as e:  # pragma: no cover - 暴露并发期真实异常
                import traceback
                outcomes[idx] = ("error", traceback.format_exc())
            finally:
                svc.store.close()

        # 预置：用当前服务登记契约与历史、预演
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.register("audit.user", "2.0.0", SPEC_V2_COMPAT)
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        self.dryrun("sub-a", "audit.user", "1.0.0", from_seq=1, to_seq=1)
        self.dryrun("sub-a", "audit.user", "2.0.0", from_seq=1, to_seq=1)
        self.httpd.shutdown()
        self.httpd.server_close()
        self.svc.store.close()
        self._server_stopped = True

        outcomes: dict = {}
        threads = [
            threading.Thread(target=run, args=("1.0.0", outcomes, 0)),
            threading.Thread(target=run, args=("2.0.0", outcomes, 1)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        oks = [v for k, v in outcomes.items() if v[0] == "ok"]
        rejects = [v for k, v in outcomes.items() if v[0] == "reject"]
        self.assertEqual(len(oks), 1, outcomes)
        self.assertEqual(len(rejects), 1, outcomes)
        self.assertEqual(rejects[0][1], "activation_conflict")

        # 以新实例读取，确认只剩一个生效版本
        checker = Service(db)
        active = checker.active_activation("sub-a", "audit.user")
        self.assertEqual(active["version"], oks[0][1])
        checker.store.close()


if __name__ == "__main__":
    unittest.main()
