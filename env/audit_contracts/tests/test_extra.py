"""幂等键重放与补充契约校验场景。"""

import unittest

from tests.helpers import HttpTestCase, SPEC_V1, SPEC_V2_COMPAT


class IdempotencyEdgeTests(HttpTestCase):

    def test_dryrun_idempotency_key_replays_same_id(self):
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.ingest("sub-a", 1, "audit.user", {"actor": "a", "action": "login"})
        body = {"event_type": "audit.user", "version": "1.0.0",
                "from_seq": 1, "to_seq": 1, "idempotency_key": "DR1"}
        r1 = self.c.post("/subscriptions/sub-a/dry-runs", body)[1]
        r2 = self.c.post("/subscriptions/sub-a/dry-runs", body)[1]
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["dry_run_id"], r1["dry_run_id"])
        self.assertEqual(r2["status"], "passed")

    def test_retry_idempotency_key_first_call_then_replay(self):
        self.c.post("/subscriptions/sub-a", {})
        spec = {
            "type": "object", "unknown_policy": "strict",
            "properties": {
                "actor": {"type": "string", "required": False},
                "action": {"type": "string", "enum": ["login"]},
            },
        }
        self.register("e", "1.0.0", spec)
        self.ingest("sub-a", 1, "e", {"action": "login"})
        self.dryrun("sub-a", "e", "1.0.0", from_seq=1, to_seq=1)
        self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "e", "version": "1.0.0", "effective_seq": 1})
        self.c.post("/subscriptions/sub-a/scan", {})
        # seq2 缺 action；default 映射修复
        self.ingest("sub-a", 2, "e", {"actor": "b"})
        self.c.post("/subscriptions/sub-a/scan", {})
        self.c.post("/subscriptions/sub-a/mappings", {
            "event_type": "e", "seq": 2, "op": "default",
            "dst_path": "action", "value": "login"})
        body = {"idempotency_key": "TRY1"}
        r1 = self.c.post("/subscriptions/sub-a/quarantine/2/retry", body)[1]
        self.assertEqual(r1["status"], "recovered")
        r2 = self.c.post("/subscriptions/sub-a/quarantine/2/retry", body)[1]
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["notification_id"], r1["notification_id"])
        _, n = self.c.get("/subscriptions/sub-a/notifications")
        self.assertEqual(len([x for x in n["notifications"] if x["seq"] == 2]), 1)

    def test_event_seq_gap_and_conflict(self):
        self.c.post("/subscriptions/sub-a", {})
        self.ingest("sub-a", 1, "audit.user", {"x": 1})
        s, b = self.ingest("sub-a", 3, "audit.user", {"x": 2}, expect=409)
        self.assertEqual(b["error"], "event_seq_gap")
        s, b = self.ingest("sub-a", 1, "audit.user", {"x": 1}, expect=409)
        self.assertEqual(b["error"], "event_seq_conflict")

    def test_unknown_contract_and_event_type_404(self):
        self.c.post("/subscriptions/sub-a", {})
        s, b = self.c.post("/subscriptions/sub-a/activations", {
            "event_type": "nope", "version": "9.9.9",
            "effective_seq": 1}, expect=404)
        self.assertEqual(b["error"], "contract_not_found")
        s, b = self.dryrun("sub-a", "nope", "1.0.0", expect=404)
        self.assertEqual(b["error"], "contract_not_found")

    def test_diff_audit_written_when_sub_given(self):
        self.c.post("/subscriptions/sub-a", {})
        self.register("audit.user", "1.0.0", SPEC_V1)
        self.register("audit.user", "2.0.0", SPEC_V2_COMPAT)
        self.c.post("/contracts/audit.user/diff", {
            "old_version": "1.0.0", "new_version": "2.0.0",
            "sub_id": "sub-a"})
        _, hist = self.c.get("/subscriptions/sub-a/audit-history")
        self.assertTrue(any(h["category"] == "contract_diff"
                            for h in hist["history"]))

    def test_enum_and_nested_object_validation(self):
        spec = {
            "type": "object",
            "properties": {
                "ctx": {"type": "object", "properties": {
                    "level": {"type": "string", "enum": ["low", "high"]}}},
                "tags": {"type": "array", "required": False,
                         "items": {"type": "string"}},
            },
        }
        self.register("e", "1.0.0", spec)
        self.c.post("/subscriptions/s", {})
        self.ingest("s", 1, "e", {"ctx": {"level": "weird"},
                                  "tags": ["a", 2]})
        _, dr = self.dryrun("s", "e", "1.0.0", from_seq=1, to_seq=1)
        self.assertEqual(dr["status"], "failed")
        paths = {f["path"] for f in dr["findings"] if f["severity"] == "block"}
        self.assertIn("$.ctx.level", paths)
        self.assertIn("$.tags[1]", paths)

    def test_array_of_objects_nested_path(self):
        spec = {"type": "object", "properties": {
            "users": {"type": "array", "items": {
                "type": "object", "properties": {
                    "uid": {"type": "int"}}}}}}
        self.register("e", "1.0.0", spec)
        self.c.post("/subscriptions/s", {})
        self.ingest("s", 1, "e", {"users": [{"uid": 1}, {"uid": "x"}]})
        _, dr = self.dryrun("s", "e", "1.0.0", from_seq=1, to_seq=1)
        self.assertEqual(dr["status"], "failed")
        self.assertIn("$.users[1].uid",
                      {f["path"] for f in dr["findings"]})


if __name__ == "__main__":
    unittest.main()
