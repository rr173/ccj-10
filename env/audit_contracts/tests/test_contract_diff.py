"""契约登记幂等冲突、字段级差异与双向兼容性判定。"""

import unittest

from tests.helpers import HttpTestCase, SPEC_V1, SPEC_V2_BREAK, SPEC_V2_COMPAT


class ContractRegistrationTests(HttpTestCase):

    def test_register_and_get(self):
        s, b = self.register("audit.user", "1.0.0", SPEC_V1)
        self.assertTrue(b["registered"])
        s, b = self.c.get("/contracts/audit.user/versions/1.0.0")
        self.assertEqual(b["spec"]["type"], "object")
        s, b = self.c.get("/contracts/audit.user/versions")
        self.assertEqual(b["versions"], ["1.0.0"])

    def test_invalid_version(self):
        s, b = self.register("audit.user", "1.0", SPEC_V1, expect=400)
        self.assertEqual(s, 400)

    def test_invalid_spec_enum_type(self):
        bad = {"type": "object", "properties": {
            "x": {"type": "int", "enum": ["no"]}}}
        s, b = self.register("e", "1.0.0", bad, expect=400)
        self.assertIn("enum", str(b))

    def test_same_version_same_spec_idempotent(self):
        self.register("audit.user", "1.0.0", SPEC_V1)
        s, b = self.register("audit.user", "1.0.0", SPEC_V1)
        self.assertTrue(b.get("replayed"))

    def test_same_version_different_spec_conflict(self):
        self.register("audit.user", "1.0.0", SPEC_V1)
        tweaked = dict(SPEC_V1, unknown_policy="allow")
        s, b = self.register("audit.user", "1.0.0", tweaked, expect=409)
        self.assertEqual(b["error"], "contract_version_conflict")

    def test_idempotency_key_replays(self):
        _, b1 = self.register("e", "1.0.0", SPEC_V1, idempotency_key="K1")
        _, b2 = self.register("e", "1.0.0", SPEC_V1, idempotency_key="K1")
        self.assertTrue(b2["replayed"])
        self.assertEqual(b2["version"], b1["version"])


class DiffTests(HttpTestCase):

    def test_compatible_upgrade_is_backward_only(self):
        self.register("e", "1.0.0", SPEC_V1)
        self.register("e", "2.0.0", SPEC_V2_COMPAT)
        _, b = self.c.post("/contracts/e/diff",
                           {"old_version": "1.0.0", "new_version": "2.0.0"})
        self.assertTrue(b["backward_compatible"])
        self.assertFalse(b["forward_compatible"])
        self.assertEqual(b["verdict"], "backward_only")
        paths = {f["path"]: f for f in b["fields"]}
        self.assertEqual(paths["$.action"]["change"], "enum_changed")
        self.assertEqual(paths["$"]["change"], "unknown_policy_changed")
        self.assertEqual(paths["$.reason"]["change"], "field_added_optional")

    def test_breaking_change(self):
        self.register("e", "1.0.0", SPEC_V1)
        self.register("e", "2.0.0", SPEC_V2_BREAK)
        _, b = self.c.post("/contracts/e/diff",
                           {"old_version": "1.0.0", "new_version": "2.0.0"})
        self.assertTrue(b["breaking"])
        self.assertEqual(b["verdict"], "breaking")
        paths = {f["path"]: f for f in b["fields"]}
        self.assertFalse(paths["$.actor"]["backward_compatible"])
        self.assertEqual(paths["$.count"]["change"], "field_removed")
        self.assertFalse(paths["$.reason"]["forward_compatible"])
        self.assertGreaterEqual(b["counts"]["backward_incompatible"], 2)

    def test_optional_to_required_direction(self):
        self.register("e", "1.0.0", {"type": "object", "properties": {
            "x": {"type": "string", "required": False}}})
        self.register("e", "2.0.0", {"type": "object", "properties": {
            "x": {"type": "string", "required": True}}})
        _, b = self.c.post("/contracts/e/diff",
                           {"old_version": "1.0.0", "new_version": "2.0.0"})
        f = next(f for f in b["fields"] if f["path"] == "$.x")
        self.assertEqual(f["change"], "optional_to_required")
        self.assertFalse(f["backward_compatible"])
        self.assertTrue(f["forward_compatible"])

    def test_required_to_optional_direction(self):
        self.register("e", "1.0.0", {"type": "object", "properties": {
            "x": {"type": "string"}}})
        self.register("e", "2.0.0", {"type": "object", "properties": {
            "x": {"type": "string", "required": False}}})
        _, b = self.c.post("/contracts/e/diff",
                           {"old_version": "1.0.0", "new_version": "2.0.0"})
        f = next(f for f in b["fields"] if f["path"] == "$.x")
        self.assertTrue(f["backward_compatible"])
        self.assertFalse(f["forward_compatible"])

    def test_int_to_number_widening(self):
        self.register("e", "1.0.0", {"type": "object", "properties": {
            "n": {"type": "int"}}})
        self.register("e", "2.0.0", {"type": "object", "properties": {
            "n": {"type": "number"}}})
        _, b = self.c.post("/contracts/e/diff",
                           {"old_version": "1.0.0", "new_version": "2.0.0"})
        f = next(f for f in b["fields"] if f["path"] == "$.n")
        self.assertTrue(f["backward_compatible"])
        self.assertFalse(f["forward_compatible"])


if __name__ == "__main__":
    unittest.main()
