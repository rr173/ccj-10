"""每条冻结通知的可验证字段来源说明（provenance）。

覆盖场景：
- 直接取值 / 固定默认值（契约 default 与 default 映射）/ 旧字段重命名 /
  允许删除 / 未知字段剥离 / 验证失败进入隔离 / 映射恢复；
- 重复重试：只追加新尝试、同幂等键回放不再生成说明、顺序不变；
- 服务重启：说明与哈希链持久化；
- 说明记录被篡改：记录摘要 / 哈希链 / 绑定不一致一律返回完整性错误；
- HTTP 接口：来源说明、重试尝试列表、两次尝试逐字段比较。
"""

import json
import os
import sqlite3
import tempfile
import unittest

from tests.helpers import HttpTestCase, SPEC_V1


SPEC = {
    "type": "object", "unknown_policy": "strict",
    "properties": {
        "actor": {"type": "string", "required": False},
        "action": {"type": "string", "enum": ["login", "logout"]},
        "count": {"type": "int", "required": False},
        "debug": {"type": "string", "required": False, "ignorable": True},
    },
}

SPEC_STRIP = {
    "type": "object", "unknown_policy": "strip",
    "properties": {
        "actor": {"type": "string"},
        "action": {"type": "string", "enum": ["login", "logout"]},
        "region": {"type": "string", "required": False, "default": "cn"},
        "debug": {"type": "string", "required": False, "ignorable": True},
    },
}


def entries_by_path(body):
    entries = body["latest"]["entries"] if "latest" in body else body["entries"]
    return {e["path"]: e for e in entries}


class ProvenanceBase(HttpTestCase):

    def activate_contract(self, sub, etype, spec, version="1.0.0", seq=1):
        self.register(etype, version, spec)
        self.dryrun(sub, etype, version, from_seq=seq, to_seq=seq)
        s, b = self.c.post(f"/subscriptions/{sub}/activations", {
            "event_type": etype, "version": version,
            "effective_seq": seq})
        self.assertEqual(s, 200, b)

    def live(self, sub="sub-a", etype="audit.act", spec=SPEC):
        """seq1 合法事件完成 登记/预演/生效/扫描，返回 sub。"""
        self.c.post(f"/subscriptions/{sub}", {})
        self.ingest(sub, 1, etype, {"actor": "a", "action": "login"})
        self.activate_contract(sub, etype, spec)
        self.c.post(f"/subscriptions/{sub}/scan", {})
        return sub


# --------------------------------------------------------------------------- #
# 1) 直接取值 / 契约固定默认 / 未知字段剥离
# --------------------------------------------------------------------------- #
class DirectDefaultStripTests(ProvenanceBase):

    def test_direct_values_and_strip_and_contract_default(self):
        sub = self.live(spec=SPEC_STRIP)
        # junk 被 strip 剥离；region 缺失但契约带 default；debug 直接取值
        self.ingest(sub, 2, "audit.act",
                    {"actor": "b", "action": "logout",
                     "junk": 1, "debug": "z"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        s, p = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance")
        self.assertEqual(s, 200, p)
        self.assertTrue(p["integrity"]["trusted"])
        self.assertEqual(p["latest_attempt_no"], 1)
        e = entries_by_path(p)
        # 直接取值：路径=来源路径，无映射规则
        self.assertEqual(e["$.actor"]["origin"], "direct_value")
        self.assertEqual(e["$.actor"]["source_path"], "$.actor")
        self.assertEqual(e["$.actor"]["rule_id"], "source:direct")
        self.assertTrue(e["$.actor"]["validation"]["valid"])
        # 未知字段剥离：保留路径/类型/摘要与策略规则标识，但最终载荷无该字段
        self.assertEqual(e["$.junk"]["origin"], "unknown_stripped")
        self.assertEqual(e["$.junk"]["rule_id"], "policy:unknown_strip")
        self.assertEqual(e["$.junk"]["value_summary"]["type"], "int")
        self.assertTrue(e["$.junk"]["value_summary"]["digest"].startswith("sha256:"))
        # 契约固定默认值：source_path=null，值不入库只有摘要
        self.assertEqual(e["$.region"]["origin"], "contract_default")
        self.assertIsNone(e["$.region"]["source_path"])
        self.assertTrue(e["$.region"]["rule_id"].startswith("contract_default:"))
        # 冻结载荷确实补了默认值，但说明里不含原值
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        row2 = next(x for x in n["notifications"] if x["seq"] == 2)
        self.assertEqual(row2["frozen_payload"]["region"], "cn")
        self.assertNotIn("junk", row2["frozen_payload"])
        blob = json.dumps(p, ensure_ascii=False)
        self.assertNotIn('"junk_value"', blob)

    def test_unknown_allow_is_recorded_as_allowed(self):
        spec_allow = dict(SPEC_STRIP, unknown_policy="allow")
        sub = self.live(spec=spec_allow)
        self.ingest(sub, 2, "audit.act",
                    {"actor": "b", "action": "login", "extra": "kept"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        _, p = self.c.get(f"/subscriptions/{sub}/notifications/2/provenance")
        e = entries_by_path(p)
        self.assertEqual(e["$.extra"]["origin"], "unknown_allowed")
        self.assertEqual(e["$.extra"]["rule_id"], "policy:unknown_allow")


# --------------------------------------------------------------------------- #
# 2) 验证失败进入隔离：失败字段保留原因；说明绑定尝试 1
# --------------------------------------------------------------------------- #
class QuarantineProvenanceTests(ProvenanceBase):

    def test_validation_failure_fields_keep_reasons(self):
        sub = self.live()
        # actor 类型错误 + 必填 action 缺失
        self.ingest(sub, 2, "audit.act", {"actor": 7})
        scan = self.c.post(f"/subscriptions/{sub}/scan", {})[1]
        self.assertEqual(scan["head_blocked_seq"], 2)

        s, p = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance")
        self.assertEqual(s, 200)
        self.assertEqual(p["notification_status"], "blocked")
        self.assertEqual(p["latest"]["status"], "blocked")
        e = entries_by_path(p)
        self.assertEqual(e["$.actor"]["origin"], "validation_failed")
        self.assertFalse(e["$.actor"]["validation"]["valid"])
        self.assertIn("string", e["$.actor"]["validation"]["reason"])
        self.assertEqual(e["$.actor"]["value_type"], "int")  # 实际类型
        self.assertEqual(e["$.actor"]["declared_type"], "string")  # 声明类型
        self.assertEqual(e["$.action"]["origin"], "missing_required")
        self.assertFalse(e["$.action"]["validation"]["valid"])

        # 隔离列表内嵌来源摘要
        _, q = self.c.get(f"/subscriptions/{sub}/quarantine")
        item = next(i for i in q["items"] if i["seq"] == 2)
        self.assertEqual(item["provenance"]["attempt_count"], 1)
        self.assertEqual(item["provenance"]["latest_attempt_no"], 1)
        self.assertTrue(item["provenance"]["latest_record_digest"]
                        .startswith("sha256:"))

    def test_provenance_never_copies_raw_values(self):
        sub = self.live()
        secret = "super-secret-value-42"
        self.ingest(sub, 2, "audit.act",
                    {"actor": secret, "action": 9})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        _, p = self.c.get(f"/subscriptions/{sub}/notifications/2/provenance")
        blob = json.dumps(p, ensure_ascii=False)
        self.assertNotIn(secret, blob)
        # 但摘要可复算：对原值取 canonical sha256 应与条目摘要一致
        from app import contracts as C
        digest = C.digest(C.canonical_payload(secret))
        e = entries_by_path(p)
        self.assertEqual(e["$.actor"]["value_summary"]["digest"], digest)


# --------------------------------------------------------------------------- #
# 3) 映射恢复：旧字段重命名 / 固定默认映射 / 允许删除，逐字段比较
# --------------------------------------------------------------------------- #
class MappingRecoveryCompareTests(ProvenanceBase):

    def _block_seq2(self, payload):
        sub = self.live()
        self.ingest(sub, 2, "audit.act", payload)
        self.c.post(f"/subscriptions/{sub}/scan", {})
        return sub

    def test_rename_drop_default_recovery_and_field_level_compare(self):
        # 值误放进旧字段 trace（strict 未知）+ 带 ignorable 的 debug + 缺 action
        sub = self._block_seq2({"trace": "login", "debug": "x"})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action"})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "drop",
            "src_path": "debug"})
        r = self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {})[1]
        self.assertEqual(r["status"], "recovered")
        self.assertEqual(r["attempt_no"], 2)

        # 最新说明：重命名 / 删除都带规则标识，且不含原值
        _, p = self.c.get(f"/subscriptions/{sub}/notifications/2/provenance")
        self.assertEqual(p["latest_attempt_no"], 2)
        e = entries_by_path(p)
        self.assertEqual(e["$.action"]["origin"], "renamed")
        self.assertEqual(e["$.action"]["renamed_from"], "$.trace")
        self.assertEqual(e["$.action"]["source_path"], "$.trace")
        self.assertTrue(e["$.action"]["rule_id"].startswith("mapping:"))
        self.assertEqual(e["$.action"]["validation"], {"valid": True})
        self.assertEqual(e["$.debug"]["origin"], "dropped")
        self.assertTrue(e["$.debug"]["rule_id"].startswith("mapping:"))
        self.assertNotIn("value_summary", e["$.debug"])  # 删除不保留值摘要
        self.assertNotIn("login", json.dumps(p))

        # 两次尝试逐字段比较
        _, d = self.c.get(
            f"/subscriptions/{sub}/notifications/2/compare?from=1&to=2")
        self.assertEqual(d["counts"]["renamed"], 1)
        self.assertEqual(d["counts"]["removed"], 1)
        rn = d["renamed_fields"][0]
        self.assertEqual(rn["from_path"], "$.trace")
        self.assertEqual(rn["path"], "$.action")
        self.assertTrue(rn["rule_id"].startswith("mapping:"))
        self.assertFalse(rn["value_summary_changed"])  # 值未变，只改名
        self.assertEqual(d["removed_fields"][0]["path"], "$.debug")
        self.assertTrue(d["removed_fields"][0]["rule_id"].startswith("mapping:"))
        # 身份不变
        self.assertEqual(d["notification_id"], r["notification_id"])

    def test_fixed_default_mapping_is_distinct_from_contract_default(self):
        # 仅缺必填 action：用 default 映射补固定枚举值
        sub = self._block_seq2({"actor": "b"})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "default",
            "dst_path": "action", "value": "login"})
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {})
        _, p = self.c.get(f"/subscriptions/{sub}/notifications/2/provenance?attempt=2")
        e = entries_by_path(p)
        self.assertEqual(e["$.action"]["origin"], "fixed_default")
        self.assertTrue(e["$.action"]["rule_id"].startswith("mapping:"))
        self.assertIn("value_summary", e["$.action"])
        # 固定值本身不进说明
        self.assertNotIn("login", json.dumps(e["$.action"]))
        # 比较：attempt1 是 missing_required，attempt2 是 fixed_default -> changed
        _, d = self.c.get(
            f"/subscriptions/{sub}/notifications/2/compare?from=1&to=2")
        changed_paths = {f["path"]: f["changes"] for f in d["changed_fields"]}
        self.assertIn("$.action", changed_paths)
        self.assertIn("validation", changed_paths["$.action"])

    def test_failed_retry_appends_attempt_without_changing_order(self):
        sub = self._block_seq2({"trace": "login"})
        # 先做一次无修复的失败重试
        s, b = self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {},
                           expect=422)
        self.assertEqual(b["error"], "retry_still_invalid")
        self.assertEqual(b["detail"]["attempt_no"], 2)
        _, att = self.c.get(
            f"/subscriptions/{sub}/notifications/2/attempts")
        self.assertEqual([a["attempt_no"] for a in att["attempts"]], [1, 2])
        self.assertEqual(att["attempts"][1]["status"], "retry_failed")
        self.assertIn("$.action", att["attempts"][1]["failed_fields"])
        # 失败尝试也有自己的说明与哈希链锚点
        _, p2 = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance?attempt=2")
        self.assertEqual(p2["status"], "retry_failed")
        self.assertIsNotNone(p2["prev_record_digest"])
        # 注册映射后第三次尝试恢复
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action"})
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {})
        _, att2 = self.c.get(
            f"/subscriptions/{sub}/notifications/2/attempts")
        self.assertEqual(
            [(a["attempt_no"], a["status"]) for a in att2["attempts"]],
            [(1, "blocked"), (2, "retry_failed"), (3, "recovered")])
        # 通知顺序与身份未变
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        seqs = [x["seq"] for x in n["notifications"]]
        self.assertEqual(seqs, [1, 2])
        # 比较失败尝试 2 与恢复尝试 3
        _, d = self.c.get(
            f"/subscriptions/{sub}/notifications/2/compare?from=2&to=3")
        self.assertEqual(d["counts"]["renamed"], 1)


# --------------------------------------------------------------------------- #
# 4) 重复重试 / 幂等：只追加、回放不生成新说明、顺序不变
# --------------------------------------------------------------------------- #
class ReplayIdempotencyTests(ProvenanceBase):

    def test_repeated_retry_only_appends_new_attempt_records(self):
        sub = self.live()
        self.ingest(sub, 2, "audit.act", {"actor": "b"})  # 缺 action
        self.c.post(f"/subscriptions/{sub}/scan", {})
        # 连续两次无修复重试：各追加一条失败尝试
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {}, expect=422)
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {}, expect=422)
        _, att = self.c.get(
            f"/subscriptions/{sub}/notifications/2/attempts")
        self.assertEqual([a["attempt_no"] for a in att["attempts"]], [1, 2, 3])
        # 通知仍只有一条 seq2，且仍 blocked
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        self.assertEqual(len([x for x in n["notifications"] if x["seq"] == 2]), 1)

    def test_same_idempotency_key_replay_generates_no_new_explanation(self):
        sub = self.live()
        self.ingest(sub, 2, "audit.act", {"actor": "b"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "default",
            "dst_path": "action", "value": "login"})
        body = {"idempotency_key": "FIX-2"}
        r1 = self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", body)[1]
        self.assertEqual(r1["attempt_no"], 2)
        # 同键回放：返回首次结果，不追加尝试
        r2 = self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", body)[1]
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["attempt_no"], 2)
        r3 = self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", body)[1]
        self.assertTrue(r3["replayed"])
        _, att = self.c.get(
            f"/subscriptions/{sub}/notifications/2/attempts")
        self.assertEqual([a["attempt_no"] for a in att["attempts"]], [1, 2])
        # 只有恢复尝试记录了幂等键
        self.assertIsNone(att["attempts"][0]["idempotency_key"])
        self.assertEqual(att["attempts"][1]["idempotency_key"], "FIX-2")
        # 顺序不变
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        self.assertEqual([x["seq"] for x in n["notifications"]], [1, 2])

    def test_failed_retry_with_idem_key_replay_does_not_append(self):
        sub = self.live()
        self.ingest(sub, 2, "audit.act", {"actor": "b"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        body = {"idempotency_key": "FAIL-2"}
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", body,
                    expect=422)
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", body,
                    expect=422)
        _, att = self.c.get(
            f"/subscriptions/{sub}/notifications/2/attempts")
        self.assertEqual([a["attempt_no"] for a in att["attempts"]], [1, 2])
        self.assertEqual(att["attempts"][1]["idempotency_key"], "FAIL-2")


# --------------------------------------------------------------------------- #
# 5) 服务重启：说明、哈希链、尝试列表随 SQLite 持久化
# --------------------------------------------------------------------------- #
class ProvenanceRestartTests(ProvenanceBase):

    def test_explanations_and_chain_survive_restart(self):
        sub = self.live()
        self.ingest(sub, 2, "audit.act", {"trace": "login", "debug": "z"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action"})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "drop",
            "src_path": "debug"})
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {})
        before = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance")[1]

        self.restart()
        s, after = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance")
        self.assertEqual(s, 200)
        self.assertTrue(after["integrity"]["trusted"])
        self.assertEqual(after["attempt_count"], 2)
        self.assertEqual(
            [a[0] for a in [(x["attempt_no"], x["record_digest"])
                            for x in after["attempts"]]],
            [x["attempt_no"] for x in before["attempts"]])
        # 逐条摘要逐字节一致
        self.assertEqual(
            [x["record_digest"] for x in after["attempts"]],
            [x["record_digest"] for x in before["attempts"]])
        # 重启后比较仍可用
        _, d = self.c.get(
            f"/subscriptions/{sub}/notifications/2/compare?from=1&to=2")
        self.assertEqual(d["counts"]["renamed"], 1)


# --------------------------------------------------------------------------- #
# 6) 说明记录被篡改：读取必须返回明确完整性错误，绝不当作可信结果
# --------------------------------------------------------------------------- #
class ProvenanceTamperTests(ProvenanceBase):

    def _raw_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _recover_seq2(self, sub):
        self.ingest(sub, 2, "audit.act", {"trace": "login", "debug": "z"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "rename",
            "src_path": "trace", "dst_path": "action"})
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "drop",
            "src_path": "debug"})
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {})

    def test_tampered_entry_breaks_record_digest(self):
        sub = self.live()
        self._recover_seq2(sub)
        # 直接改库：篡改 attempt 2 条目的规则标识（伪装成另一条规则）
        conn = self._raw_conn()
        row = conn.execute(
            "SELECT entries_json FROM provenance_explanations "
            "WHERE sub_id=? AND attempt_no=2", (sub,)).fetchone()
        entries = json.loads(row["entries_json"])
        entries[0]["rule_id"] = "mapping:999"
        conn.execute(
            "UPDATE provenance_explanations SET entries_json=? "
            "WHERE sub_id=? AND attempt_no=2",
            (json.dumps(entries, ensure_ascii=False), sub))
        conn.commit()
        conn.close()

        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance", expect=422)
        self.assertEqual(b["error"], "provenance_integrity_error")
        checks = {c["check"] for c in b["detail"]["failed_checks"]}
        self.assertIn("record_digest", checks)
        # 三个只读端点都拒绝返回可信内容
        s2, b2 = self.c.get(
            f"/subscriptions/{sub}/notifications/2/attempts", expect=422)
        self.assertEqual(b2["error"], "provenance_integrity_error")
        s3, b3 = self.c.get(
            f"/subscriptions/{sub}/notifications/2/compare?from=1&to=2",
            expect=422)
        self.assertEqual(b3["error"], "provenance_integrity_error")

    def test_missing_explanation_is_integrity_error(self):
        sub = self.live()
        self._recover_seq2(sub)
        conn = self._raw_conn()
        conn.execute(
            "DELETE FROM provenance_explanations "
            "WHERE sub_id=? AND attempt_no=1", (sub,))
        conn.commit()
        conn.close()
        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance", expect=422)
        self.assertEqual(b["error"], "provenance_integrity_error")
        checks = {c["check"]: c for c in b["detail"]["failed_checks"]}
        self.assertIn("explanation_present", checks)
        self.assertIn("hash_chain", checks)  # 锚点也因此断裂

    def test_broken_attempt_sequence_is_integrity_error(self):
        sub = self.live()
        self._recover_seq2(sub)
        conn = self._raw_conn()
        conn.execute(
            "DELETE FROM delivery_attempts WHERE sub_id=? AND attempt_no=1",
            (sub,))
        conn.commit()
        conn.close()
        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance", expect=422)
        checks = {c["check"] for c in b["detail"]["failed_checks"]}
        self.assertIn("attempt_sequence", checks)
        self.assertIn("hash_chain", checks)

    def test_binding_digest_mismatch_is_integrity_error(self):
        sub = self.live()
        self._recover_seq2(sub)
        # 篡改说明绑定的载荷摘要
        conn = self._raw_conn()
        conn.execute(
            "UPDATE provenance_explanations SET payload_digest=? "
            "WHERE sub_id=? AND attempt_no=2",
            ("sha256:" + "0" * 64, sub))
        conn.commit()
        conn.close()
        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance", expect=422)
        checks = {c["check"] for c in b["detail"]["failed_checks"]}
        self.assertTrue(
            {"record_digest", "binding_payload_digest"} & checks)

    def test_origin_event_rebinding_is_detected(self):
        # 用后续事件的原始载荷替换事件表内容：原始事件摘要绑定必须失配
        sub = self.live()
        self._recover_seq2(sub)
        conn = self._raw_conn()
        conn.execute(
            "UPDATE events SET raw_payload=? WHERE sub_id=? AND seq=2",
            (json.dumps({"actor": "attacker", "action": "login"}), sub))
        conn.commit()
        conn.close()
        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance", expect=422)
        checks = {c["check"] for c in b["detail"]["failed_checks"]}
        self.assertIn("origin_event_digest", checks)


# --------------------------------------------------------------------------- #
# 7) 其它接口与边界
# --------------------------------------------------------------------------- #
class ProvenanceApiEdgeTests(ProvenanceBase):

    def test_no_notification_returns_404(self):
        self.c.post("/subscriptions/sub-a", {})
        s, b = self.c.get(
            "/subscriptions/sub-a/notifications/5/provenance", expect=404)
        self.assertEqual(b["error"], "notification_not_found")

    def test_attempt_out_of_range_404_and_bad_query_400(self):
        sub = self.live()
        self.ingest(sub, 2, "audit.act", {"actor": 7})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance?attempt=9",
            expect=404)
        self.assertEqual(b["error"], "attempt_not_found")
        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/compare?from=1",
            expect=200)
        # 缺省 to=最后一次尝试
        self.assertEqual(b["from_attempt"], 1)
        self.assertEqual(b["to_attempt"], 1)
        s, b = self.c.get(
            f"/subscriptions/{sub}/notifications/2/compare?from=x&to=2",
            expect=400)
        self.assertEqual(b["error"], "invalid_query_param")

    def test_explanation_immutable_after_later_recovery(self):
        # 首次冻结说明（attempt 1）在恢复后仍逐字节可读，不被后续规则修改
        sub = self.live()
        self.ingest(sub, 2, "audit.act", {"actor": "b"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        first = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance?attempt=1")[1]
        self.c.post(f"/subscriptions/{sub}/mappings", {
            "event_type": "audit.act", "seq": 2, "op": "default",
            "dst_path": "action", "value": "login"})
        self.c.post(f"/subscriptions/{sub}/quarantine/2/retry", {})
        again = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance?attempt=1")[1]
        self.assertEqual(
            [json.dumps(e, sort_keys=True) for e in first["entries"]],
            [json.dumps(e, sort_keys=True) for e in again["entries"]])
        self.assertEqual(first["record_digest"], again["record_digest"])
        self.assertEqual(first["status"], "blocked")
        self.assertIsNone(first["prev_record_digest"])  # 链头
        _, p = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance")
        self.assertIsNotNone(p["latest"]["prev_record_digest"])

    def test_ungoverned_after_revocation_has_passthrough_provenance(self):
        sub = self.live()
        # 撤销契约后入库 seq2，扫描时无约束原样冻结
        self.c.post(f"/subscriptions/{sub}/revocations",
                    {"event_type": "audit.act"})
        self.ingest(sub, 2, "audit.act", {"anything": 1, "actor": "z"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        _, p = self.c.get(
            f"/subscriptions/{sub}/notifications/2/provenance")
        origins = {e["path"]: e["origin"]
                   for e in p["latest"]["entries"]}
        self.assertEqual(origins["$.anything"], "ungoverned_passthrough")
        self.assertEqual(origins["$.actor"], "ungoverned_passthrough")
        self.assertTrue(p["integrity"]["trusted"])


if __name__ == "__main__":
    unittest.main()
