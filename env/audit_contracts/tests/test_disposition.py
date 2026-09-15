"""更正/撤回处置：按接收端独立决策、发送竞争、三关失败隔离、幂等冲突、
时间线查询、重启续跑、排队身份与顺序一致。"""

import json
import threading

from tests.helpers import HttpTestCase, SPEC_V1


def disposition(c, sub, seq, body, expect=200):
    return c.post(f"/subscriptions/{sub}/events/{seq}/dispositions", body, expect)


def claim(c, sub, seq, body=None, expect=200):
    return c.post(f"/subscriptions/{sub}/notifications/{seq}/claim", body or {}, expect)


def finish(c, kind, sub, ident, token, ack, expect=200):
    verb = "ack" if ack else "nack"
    path = (f"/subscriptions/{sub}/notifications/{ident}/{verb}" if kind == "original"
            else f"/subscriptions/{sub}/notices/{ident}/{verb}")
    return c.post(path, {"delivery_token": token}, expect)


class DispositionBase(HttpTestCase):
    SPEC = SPEC_V1
    ETYPE = "audit.user"

    def bootstrap(self, sub="sub-a", n=3, activate_at=1):
        self.c.post(f"/subscriptions/{sub}", {})
        self.register(self.ETYPE, "1.0.0", self.SPEC)
        for i in range(1, n + 1):
            self.ingest(sub, i, self.ETYPE,
                        {"actor": f"a{i}", "action": "login"})
        _, dr = self.dryrun(sub, self.ETYPE, "1.0.0",
                            from_seq=1, to_seq=n)
        self.assertEqual(dr["status"], "passed")
        self.c.post(f"/subscriptions/{sub}/activations",
                    {"event_type": self.ETYPE, "version": "1.0.0",
                     "effective_seq": activate_at})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        return sub

    def deliver(self, sub, seq):
        _, cl = claim(self.c, sub, seq)
        st, _ = finish(self.c, "original", sub, seq, cl["delivery_token"], True)
        self.assertEqual(st, 200)
        return cl["notification_id"]


class RetractQueuedTests(DispositionBase):
    def test_retract_before_send_atomically_cancels(self):
        sub = self.bootstrap(n=2)
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "误报事件",
                            "actor": "admin-1", "idempotency_key": "r1"})
        self.assertEqual(r["status"], "applied")
        t = r["targets"][0]
        self.assertEqual(t["state"], "cancelled")
        self.assertIsNone(t["result_notification_id"])

        # 原通知置 cancelled，没有产生任何后续通知
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        self.assertEqual(ev["original_notification"]["status"], "cancelled")
        self.assertEqual(ev["followup_notices"], [])
        # 排队位置保留（队列身份一致）
        self.assertEqual(ev["original_notification"]["queue_position"], 1)

        # cancelled 通知不可再领取发送（不会漏发更正后的东西，也不会重复发）
        claim(self.c, sub, 1, expect=409)

        # 后续通知仍可领取，顺序不受影响
        _, cl = claim(self.c, sub, 2)
        self.assertEqual(cl["queue_position"], 2)

    def test_retract_requires_reason(self):
        sub = self.bootstrap(n=1)
        st, body = disposition(self.c, sub, 1,
                               {"action": "retract", "reason": "   "}, expect=400)
        self.assertEqual(body["error"], "reason_required")

    def test_unknown_action_and_event(self):
        sub = self.bootstrap(n=1)
        st, body = disposition(self.c, sub, 1,
                               {"action": "freeze", "reason": "x"}, expect=400)
        self.assertEqual(body["error"], "invalid_disposition_action")
        disposition(self.c, sub, 99,
                    {"action": "retract", "reason": "x"}, expect=404)


class CorrectQueuedTests(DispositionBase):
    def test_correct_before_send_replaces_at_same_position_same_identity(self):
        sub = self.bootstrap(n=2)
        _, before = self.c.get(f"/subscriptions/{sub}/notifications")
        old = [n for n in before["notifications"] if n["seq"] == 1][0]

        _, r = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "actor 拼写错误",
            "corrected_payload": {"actor": "a1-fixed", "action": "login"},
            "idempotency_key": "c1"})
        self.assertEqual(r["status"], "applied")
        t = r["targets"][0]
        self.assertEqual(t["state"], "replaced")
        # 同一投递身份
        self.assertEqual(t["original_notification_id"],
                         t["result_notification_id"])
        self.assertEqual(t["result_notification_id"], old["notification_id"])

        _, after = self.c.get(f"/subscriptions/{sub}/notifications")
        new = [n for n in after["notifications"] if n["seq"] == 1][0]
        self.assertEqual(new["frozen_payload"]["actor"], "a1-fixed")
        self.assertEqual(new["queue_position"], old["queue_position"])  # 同一位置
        self.assertTrue(new["superseded"])
        # 仍是同一条通知，没有多出来
        self.assertEqual(len(after["notifications"]), 2)

        # 领取到的就是更正后的内容
        _, cl = claim(self.c, sub, 1)
        self.assertEqual(cl["notification_id"], old["notification_id"])
        self.assertEqual(cl["payload"]["actor"], "a1-fixed")

        # 修订留档可溯：revision 1 旧内容 + revision 2 更正内容（带签名）
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        revs = ev["original_notification"]["revisions"]
        self.assertEqual([x["revision_no"] for x in revs], [1, 2])
        self.assertIsNone(revs[0]["signature"])
        self.assertEqual(revs[1]["signature"]["alg"], "HMAC-SHA256")
        self.assertNotEqual(revs[0]["digest"], revs[1]["digest"])

    def test_correct_requires_payload_object(self):
        sub = self.bootstrap(n=1)
        st, body = disposition(self.c, sub, 1,
                               {"action": "correct", "reason": "x"}, expect=400)
        self.assertEqual(body["error"], "corrected_payload_required")

    def test_correct_validation_failure_leaves_original_untouched(self):
        sub = self.bootstrap(n=2)
        _, before = self.c.get(f"/subscriptions/{sub}/notifications")
        old_digest = [n for n in before["notifications"] if n["seq"] == 1][0]["digest"]

        # action 枚举越界 + actor 类型错误
        _, r = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "bad",
            "corrected_payload": {"actor": 123, "action": "delete"},
            "idempotency_key": "bad1"})
        self.assertEqual(r["status"], "failed")
        t = r["targets"][0]
        self.assertEqual(t["failure_stage"], "validation")
        self.assertEqual(t["failure_reason"], "correction_contract_validation_failed")
        paths = {d["path"] for d in t["fail_detail"]["errors"]}
        self.assertIn("$.actor", paths)
        self.assertIn("$.action", paths)

        _, after = self.c.get(f"/subscriptions/{sub}/notifications")
        n1 = [n for n in after["notifications"] if n["seq"] == 1][0]
        self.assertEqual(n1["digest"], old_digest)          # 原通知没被改
        self.assertEqual(n1["status"], "queued")            # 仍可发送
        _, cl = claim(self.c, sub, 1)
        self.assertEqual(cl["payload"]["actor"], "a1")

    def test_correct_without_active_contract_fails(self):
        # seq1 生效、扫描后撤销（撤销点 seq2）；seq2 在撤销后无治理入队，
        # 更正它没有"当前生效契约"可重新校验，必须拒绝且不改原通知
        sub = self.bootstrap(n=1)
        self.c.post(f"/subscriptions/{sub}/revocations",
                    {"event_type": self.ETYPE})
        self.ingest(sub, 2, self.ETYPE, {"actor": "b", "action": "login"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        before = [x for x in n["notifications"] if x["seq"] == 2][0]
        _, r = disposition(self.c, sub, 2, {
            "action": "correct", "reason": "x",
            "corrected_payload": {"actor": "z", "action": "login"}})
        self.assertEqual(r["targets"][0]["failure_reason"],
                         "correction_no_active_contract")
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        after = [x for x in n["notifications"] if x["seq"] == 2][0]
        self.assertEqual(after["digest"], before["digest"])

    def test_correct_normalizes_and_records_correction_provenance(self):
        # SPEC_V1: unknown_policy=strict at root, note ignorable, meta allow
        sub = self.bootstrap(n=1)
        _, r = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "补 note",
            "corrected_payload": {"actor": "a1", "action": "login",
                                  "note": "已复核",
                                  "meta": {"ip": "10.0.0.1", "zone": "x"}}})
        self.assertEqual(r["status"], "applied")
        _, p = self.c.get(f"/subscriptions/{sub}/notifications/1/provenance")
        origins = {e["origin"] for e in p["latest"]["entries"]}
        self.assertIn("correction_supplied", origins)
        self.assertIn("unknown_allowed", origins)  # meta.zone 随 allow 保留
        # 哈希链与绑定仍然完整
        self.assertTrue(p["integrity"]["trusted"])


class DeliveredAppendTests(DispositionBase):
    def test_delivered_retract_appends_linked_notice(self):
        sub = self.bootstrap(n=2)
        nid = self.deliver(sub, 1)
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "事后确认误报",
                            "idempotency_key": "dr1"})
        t = r["targets"][0]
        self.assertEqual(t["state"], "followup_queued")
        self.assertNotEqual(t["result_notification_id"], nid)  # 新身份
        notice_id = t["result_notification_id"]

        # 原通知保持 delivered，内容/摘要不变
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        self.assertEqual(ev["original_notification"]["status"], "delivered")
        self.assertEqual(ev["original_notification"]["notification_id"], nid)
        follow = ev["followup_notices"][0]
        self.assertEqual(follow["kind"], "retraction")
        self.assertGreater(follow["queue_position"],
                           ev["original_notification"]["queue_position"])

        # 后续通知的关联信封与签名可验证
        _, fc = self.c.post(f"/subscriptions/{sub}/notices/{notice_id}/claim", {})
        self.assertEqual(fc["envelope"]["kind"], "retraction")
        rel = fc["envelope"]["relation"]
        self.assertEqual(rel["original_notification_id"], nid)
        self.assertEqual(rel["disposition_id"], r["disposition_id"])
        self.assertEqual(rel["action"], "retract")
        _, ver = self.c.get(f"/subscriptions/{sub}/notices/{notice_id}/verify")
        self.assertTrue(ver["verified"])
        self.assertEqual(ver["relation"]["original_notification_id"], nid)
        finish(self.c, "notice", sub, notice_id, fc["delivery_token"], True)

        # 篡改信封后验签必须失败
        with self.svc.store.lock:
            conn = self.svc.store.conn
            row = conn.execute(
                "SELECT envelope_json FROM disposition_notices WHERE id=?",
                (notice_id,)).fetchone()
            env = json.loads(row["envelope_json"])
            env["reason"] = "tampered"
            conn.execute(
                "UPDATE disposition_notices SET envelope_json=? WHERE id=?",
                (json.dumps(env, ensure_ascii=False), notice_id))
            conn.commit()
        _, ver = self.c.get(f"/subscriptions/{sub}/notices/{notice_id}/verify")
        self.assertFalse(ver["verified"])

    def test_delivered_correct_appends_new_payload_notice(self):
        sub = self.bootstrap(n=1)
        self.deliver(sub, 1)
        _, r = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "更正",
            "corrected_payload": {"actor": "a1-new", "action": "login"}})
        self.assertEqual(r["targets"][0]["state"], "followup_queued")
        nid = r["targets"][0]["result_notification_id"]
        _, fc = self.c.post(f"/subscriptions/{sub}/notices/{nid}/claim", {})
        self.assertEqual(fc["kind"], "correction")
        self.assertEqual(fc["envelope"]["payload"]["actor"], "a1-new")
        self.assertEqual(fc["envelope"]["contract_version"], "1.0.0")
        self.assertTrue(
            all(e["origin"] == "correction_supplied"
                for e in fc["envelope"]["field_provenance"]))
        _, ver = self.c.get(f"/subscriptions/{sub}/notices/{nid}/verify")
        self.assertTrue(ver["verified"])

    def test_delivered_invalid_correct_changes_nothing(self):
        sub = self.bootstrap(n=1)
        old = self.deliver(sub, 1)
        _, r = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "x",
            "corrected_payload": {"actor": [], "action": "login"}})
        self.assertEqual(r["status"], "failed")
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        self.assertEqual(ev["original_notification"]["status"], "delivered")
        self.assertEqual(ev["followup_notices"], [])  # 没追加任何东西
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        self.assertEqual([x for x in n["notifications"] if x["seq"] == 1][0]
                         ["notification_id"], old)


class SendingRaceTests(DispositionBase):
    def _parked(self, seq, action="retract", **extra):
        _, cl = claim(self.c, "sub-a", seq)
        body = {"action": action, "reason": "竞争窗口"}
        body.update(extra)
        _, r = disposition(self.c, "sub-a", seq, body)
        self.assertEqual(r["targets"][0]["state"], "pending")
        return cl, r

    def test_ack_wins_pending_disposition_becomes_followup(self):
        self.bootstrap(n=1)
        cl, r = self._parked(1)
        st, _ = finish(self.c, "original", "sub-a", 1,
                       cl["delivery_token"], True)
        self.assertEqual(st, 200)
        _, got = self.c.get(f"/dispositions/{r['disposition_id']}")
        self.assertEqual(got["status"], "applied")
        self.assertEqual(got["targets"][0]["state"], "followup_queued")
        # 时间线体现先后：claim -> parked -> acked -> enqueued
        _, ev = self.c.get("/subscriptions/sub-a/events/1/dispositions")
        events = [t["event"] for t in ev["timeline"]]
        self.assertLess(events.index("disposition_parked_sending"),
                        events.index("notification_acked"))
        self.assertLess(events.index("notification_acked"),
                        events.index("followup_notice_enqueued"))

    def test_nack_wins_pending_retract_becomes_cancel(self):
        self.bootstrap(n=1)
        cl, r = self._parked(1)
        finish(self.c, "original", "sub-a", 1, cl["delivery_token"], False)
        _, got = self.c.get(f"/dispositions/{r['disposition_id']}")
        self.assertEqual(got["targets"][0]["state"], "cancelled")
        _, ev = self.c.get("/subscriptions/sub-a/events/1/dispositions")
        self.assertEqual(ev["original_notification"]["status"], "cancelled")
        self.assertEqual(ev["followup_notices"], [])

    def test_nack_wins_pending_correct_becomes_replace(self):
        self.bootstrap(n=1)
        cl, r = self._parked(
            1, action="correct",
            corrected_payload={"actor": "fixed", "action": "login"})
        finish(self.c, "original", "sub-a", 1, cl["delivery_token"], False)
        _, got = self.c.get(f"/dispositions/{r['disposition_id']}")
        self.assertEqual(got["targets"][0]["state"], "replaced")
        _, cl2 = claim(self.c, "sub-a", 1)
        self.assertEqual(cl2["payload"]["actor"], "fixed")

    def test_concurrent_disposition_and_ack_only_one_outcome(self):
        """并发：处置与 ack 同时提交，最终要么取消/替换要么追加，绝不两者都有。"""
        self.bootstrap(n=1)
        outcomes = []

        def do_disposition():
            try:
                _, r = disposition(self.c, "sub-a", 1,
                                   {"action": "retract", "reason": "并发"})
                outcomes.append(("disp", r["targets"][0]["state"]))
            except Exception as e:  # pragma: no cover
                outcomes.append(("disp_err", str(e)))

        _, cl = claim(self.c, "sub-a", 1)
        t = threading.Thread(target=do_disposition)
        t.start()
        # 与处置并发地确认送达
        finish(self.c, "original", "sub-a", 1, cl["delivery_token"], True)
        t.join(timeout=5)

        _, ev = self.c.get("/subscriptions/sub-a/events/1/dispositions")
        status = ev["original_notification"]["status"]
        notices = len(ev["followup_notices"])
        # delivered -> 必然且仅有一条追加；cancelled -> 必然没有追加
        if status == "delivered":
            self.assertEqual(notices, 1)
        else:
            self.assertEqual(status, "cancelled")
            self.assertEqual(notices, 0)

    def test_ack_requires_claim_token_duplicate_ack_idempotent(self):
        self.bootstrap(n=1)
        _, cl = claim(self.c, "sub-a", 1)
        st, body = finish(self.c, "original", "sub-a", 1, "tok_wrong", True,
                          expect=409)
        self.assertEqual(body["error"], "delivery_token_mismatch")
        finish(self.c, "original", "sub-a", 1, cl["delivery_token"], True)
        # 同令牌重复 ack：幂等
        st, _ = finish(self.c, "original", "sub-a", 1,
                       cl["delivery_token"], True)
        self.assertEqual(st, 200)
        # 旧令牌不能再 claim 走（delivered 终态不可领取）
        claim(self.c, "sub-a", 1, expect=409)

    def test_double_claim_rejected_force_reclaim_after_worker_death(self):
        self.bootstrap(n=1)
        _, cl1 = claim(self.c, "sub-a", 1)
        st, _ = claim(self.c, "sub-a", 1, expect=409)
        # 模拟前任发送端崩溃：强制接管，新令牌生效，旧令牌被废
        _, cl2 = claim(self.c, "sub-a", 1, {"force_reclaim": True})
        self.assertNotEqual(cl1["delivery_token"], cl2["delivery_token"])
        finish(self.c, "original", "sub-a", 1, cl1["delivery_token"], True,
               expect=409)
        finish(self.c, "original", "sub-a", 1, cl2["delivery_token"], True)


class QueueOrderTests(DispositionBase):
    def test_followups_ordered_after_original_and_each_other(self):
        sub = self.bootstrap(n=1)
        self.deliver(sub, 1)
        ids = []
        for i, action in enumerate(("retract", "correct", "retract")):
            body = {"action": action, "reason": f"r{i}"}
            if action == "correct":
                body["corrected_payload"] = {"actor": f"v{i}", "action": "login"}
            _, r = disposition(self.c, sub, 1, body)
            ids.append(r["targets"][0]["result_notification_id"])

        _, q = self.c.get(f"/subscriptions/{sub}/delivery-queue")
        kinds = [(x["kind"], x["status"], x["queue_position"]) for x in q["queue"]]
        self.assertEqual(kinds[0], ("original", "delivered", 1))
        self.assertEqual([k[0] for k in kinds[1:]],
                         ["retraction", "correction", "retraction"])
        positions = [k[2] for k in kinds]
        self.assertEqual(positions, sorted(positions))

        # 必须按位置顺序领取：不能跳过前一条
        st, _ = self.c.post(
            f"/subscriptions/{sub}/notices/{ids[2]}/claim", {}, expect=409)
        _, fc = self.c.post(f"/subscriptions/{sub}/notices/{ids[0]}/claim", {})
        self.assertEqual(fc["queue_position"], 2)

    def test_blocked_retract_clears_hol_keeping_later_positions(self):
        # 制造一个隔离队头：契约在 seq1 生效；seq2 非法（扫描期隔离），
        # seq3 合法但被头阻塞挡住
        sub = "sub-b"
        self.c.post(f"/subscriptions/{sub}", {})
        self.register(self.ETYPE, "1.0.0", self.SPEC)
        self.ingest(sub, 1, self.ETYPE, {"actor": "ok1", "action": "login"})
        self.dryrun(sub, self.ETYPE, "1.0.0", from_seq=1, to_seq=1)
        self.c.post(f"/subscriptions/{sub}/activations",
                    {"event_type": self.ETYPE, "version": "1.0.0",
                     "effective_seq": 1})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        self.ingest(sub, 2, self.ETYPE, {"actor": 1, "action": "login"})
        self.ingest(sub, 3, self.ETYPE, {"actor": "ok3", "action": "login"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        _, q = self.c.get(f"/subscriptions/{sub}/quarantine")
        self.assertEqual(q["head_blocked_seq"], 2)

        # 撤回被隔离（尚未发送）的队头：原子取消 + HOL 解除，seq3 续送入队
        _, r = disposition(self.c, sub, 2,
                           {"action": "retract", "reason": "错误事件"})
        self.assertEqual(r["targets"][0]["state"], "cancelled")
        _, n = self.c.get(f"/subscriptions/{sub}/notifications")
        by_seq = {x["seq"]: x for x in n["notifications"]}
        self.assertEqual(by_seq[2]["status"], "cancelled")
        self.assertEqual(by_seq[3]["status"], "queued")
        self.assertLess(by_seq[2]["queue_position"], by_seq[3]["queue_position"])

    def test_blocked_correct_replaces_and_unblocks(self):
        sub = "sub-c"
        self.c.post(f"/subscriptions/{sub}", {})
        self.register(self.ETYPE, "1.0.0", self.SPEC)
        self.ingest(sub, 1, self.ETYPE, {"actor": "ok", "action": "login"})
        self.dryrun(sub, self.ETYPE, "1.0.0", from_seq=1, to_seq=1)
        self.c.post(f"/subscriptions/{sub}/activations",
                    {"event_type": self.ETYPE, "version": "1.0.0",
                     "effective_seq": 1})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        self.ingest(sub, 2, self.ETYPE, {"actor": 9, "action": "login"})
        self.c.post(f"/subscriptions/{sub}/scan", {})
        _, r = disposition(self.c, sub, 2, {
            "action": "correct", "reason": "修",
            "corrected_payload": {"actor": "fixed", "action": "login"}})
        self.assertEqual(r["targets"][0]["state"], "replaced")
        _, cl = claim(self.c, sub, 2)
        self.assertEqual(cl["payload"]["actor"], "fixed")


class IdempotencyTests(DispositionBase):
    def test_same_request_replays_first_result(self):
        sub = self.bootstrap(n=1)
        body = {"action": "retract", "reason": "误报", "idempotency_key": "K1"}
        _, r1 = disposition(self.c, sub, 1, body)
        _, r2 = disposition(self.c, sub, 1, dict(body))
        self.assertEqual(r2["disposition_id"], r1["disposition_id"])
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["targets"][0]["state"], "cancelled")
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        # 只产生了一次处置
        self.assertEqual(len(ev["dispositions"]), 1)

    def test_changed_content_conflicts(self):
        sub = self.bootstrap(n=2)
        base = {"action": "retract", "reason": "原因A", "idempotency_key": "K2"}
        disposition(self.c, sub, 1, base)
        # 改处置方式
        st, b = disposition(
            self.c, sub, 1,
            {"action": "correct", "reason": "原因A",
             "corrected_payload": {"actor": "x", "action": "login"},
             "idempotency_key": "K2"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        # 改原因
        st, b = disposition(self.c, sub, 1,
                            {"action": "retract", "reason": "原因B",
                             "idempotency_key": "K2"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        # 改原事件
        st, b = disposition(self.c, sub, 2,
                            {"action": "retract", "reason": "原因A",
                             "idempotency_key": "K2"}, expect=409)
        self.assertEqual(b["error"], "idempotency_request_conflict")
        # 改更正内容
        st, b = disposition(
            self.c, sub, 1,
            {"action": "correct", "reason": "原因A",
             "corrected_payload": {"actor": "y", "action": "login"},
             "idempotency_key": "K2"}, expect=409)
        self.assertIn("first_request_fingerprint", b["detail"])
        self.assertIn("request_fingerprint", b["detail"])

    def test_inflight_disposition_blocks_second_without_key(self):
        sub = self.bootstrap(n=1)
        _, cl = claim(self.c, sub, 1)
        disposition(self.c, sub, 1, {"action": "retract", "reason": "a"})
        st, b = disposition(self.c, sub, 1,
                            {"action": "retract", "reason": "b"}, expect=409)
        self.assertEqual(b["error"], "disposition_already_pending")

    def test_failed_result_also_idempotent(self):
        # 更正校验失败的结果也被冻结：同键重放不重试、不新增留档
        sub = self.bootstrap(n=1)
        body = {"action": "correct", "reason": "x",
                "corrected_payload": {"actor": 1, "action": "login"},
                "idempotency_key": "FAIL"}
        _, r1 = disposition(self.c, sub, 1, body)
        self.assertEqual(r1["status"], "failed")
        _, r2 = disposition(self.c, sub, 1, body)
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["disposition_id"], r1["disposition_id"])
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        self.assertEqual(len(ev["dispositions"]), 1)


class SigningKeyRotationTests(DispositionBase):
    def test_rotation_keeps_old_signatures_valid_and_new_notice_uses_new_key(self):
        sub = self.bootstrap(n=1)
        self.deliver(sub, 1)
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "r"})
        old_id = r["targets"][0]["result_notification_id"]
        _, old = self.c.get(f"/subscriptions/{sub}/notices/{old_id}/verify")
        self.assertTrue(old["verified"])
        old_kid = old["kid"]

        st, rot = self.c.post("/signing/rotate", {})
        self.assertEqual(st, 200)
        self.assertNotEqual(rot["kid"], old_kid)

        # 旧密钥已轮换，但历史签名仍可验证
        _, old = self.c.get(f"/subscriptions/{sub}/notices/{old_id}/verify")
        self.assertTrue(old["verified"])
        self.assertEqual(old["kid"], old_kid)

        # 新追加的后续通知用新密钥签名
        _, r2 = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "r2",
            "corrected_payload": {"actor": "v2", "action": "login"}})
        new_id = r2["targets"][0]["result_notification_id"]
        _, new = self.c.get(f"/subscriptions/{sub}/notices/{new_id}/verify")
        self.assertTrue(new["verified"])
        self.assertEqual(new["kid"], rot["kid"])


class EventTypeGuardTests(DispositionBase):
    def test_event_without_frozen_notification_cannot_be_disposed(self):
        sub = self.bootstrap(n=1)
        # seq2 已入库但尚未扫描冻结（scan_seq=1）：还没有通知可处置，
        # 请求留档但该接收端结果为 precondition 失败，且没有任何状态变化
        self.ingest(sub, 2, self.ETYPE, {"actor": "a2", "action": "login"})
        _, body = disposition(self.c, sub, 2,
                              {"action": "retract", "reason": "x"})
        self.assertEqual(body["status"], "failed")
        t = body["targets"][0]
        self.assertEqual(t["failure_stage"], "precondition")
        self.assertEqual(t["failure_reason"], "notification_not_frozen")
        # 查询一个不存在处置的原事件：404
        self.c.get(f"/subscriptions/{sub}/events/9/dispositions", expect=404)
        # 原事件仍在；扫描冻结后可正常处置
        self.c.post(f"/subscriptions/{sub}/scan", {})
        _, r = disposition(self.c, sub, 2,
                           {"action": "retract", "reason": "x"})
        self.assertEqual(r["targets"][0]["state"], "cancelled")

    def test_multiple_replacements_keep_provenance_chain_intact(self):
        sub = self.bootstrap(n=1)
        for i, actor in enumerate(("v1", "v2", "v3"), start=1):
            _, r = disposition(self.c, sub, 1, {
                "action": "correct", "reason": f"r{i}",
                "corrected_payload": {"actor": actor, "action": "login"}})
            # 链式处置：上次更正后通知仍是 queued（未发送），可继续原位更正
            self.assertEqual(r["targets"][0]["state"], "replaced")
        _, p = self.c.get(f"/subscriptions/{sub}/notifications/1/provenance")
        self.assertTrue(p["integrity"]["trusted"])
        self.assertEqual(p["attempt_count"], 4)  # 初始 + 3 次更正
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        self.assertEqual(
            [x["revision_no"] for x in ev["original_notification"]["revisions"]],
            [1, 2, 3, 4])

    def test_event_type_mismatch_conflicts(self):
        sub = self.bootstrap(n=1)
        st, b = disposition(self.c, sub, 1,
                            {"action": "retract", "reason": "x",
                             "event_type": "audit.other"}, expect=409)
        self.assertEqual(b["error"], "event_type_mismatch")
        _, ok = disposition(self.c, sub, 1,
                            {"action": "retract", "reason": "x",
                             "event_type": self.ETYPE})
        self.assertEqual(ok["status"], "applied")


class SigningFailureTests(DispositionBase):
    def test_signing_failure_inflight_replace_changes_nothing(self):
        sub = self.bootstrap(n=1)
        _, before = self.c.get(f"/subscriptions/{sub}/notifications")
        old_digest = before["notifications"][0]["digest"]
        self.svc.store.signer.fail_next_signing()
        _, r = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "x",
            "corrected_payload": {"actor": "fixed", "action": "login"}})
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["targets"][0]["failure_stage"], "signing")
        _, after = self.c.get(f"/subscriptions/{sub}/notifications")
        self.assertEqual(after["notifications"][0]["digest"], old_digest)
        self.assertEqual(after["notifications"][0]["status"], "queued")
        # 失败后系统仍可用：之后的正常更正成功
        _, r2 = disposition(self.c, sub, 1, {
            "action": "correct", "reason": "x2",
            "corrected_payload": {"actor": "fixed2", "action": "login"}})
        self.assertEqual(r2["status"], "applied")

    def test_signing_failure_for_followup_leaves_delivery_intact(self):
        sub = self.bootstrap(n=1)
        self.deliver(sub, 1)
        self.svc.store.signer.fail_next_signing()
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "x"})
        self.assertEqual(r["targets"][0]["failure_stage"], "signing")
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        self.assertEqual(ev["original_notification"]["status"], "delivered")
        self.assertEqual(ev["followup_notices"], [])


class RestartRecoveryTests(DispositionBase):
    def test_pending_disposition_resolves_to_followup_after_restart_with_ack(self):
        sub = self.bootstrap(n=1)
        # 直接让处置挂起，重启前发送端先 ack（结果已落库），重启完成裁决
        _, cl = claim(self.c, sub, 1)
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "挂起",
                            "idempotency_key": "P1"})
        finish(self.c, "original", sub, 1, cl["delivery_token"], True)
        self.restart()
        _, got = self.c.get(f"/dispositions/{r['disposition_id']}")
        self.assertEqual(got["targets"][0]["state"], "followup_queued")
        notice_id = got["targets"][0]["result_notification_id"]
        # 后续通知排队身份在重启后保持，可继续领取并验签
        _, fc = self.c.post(f"/subscriptions/{sub}/notices/{notice_id}/claim",
                            {"force_reclaim": True})
        _, ver = self.c.get(f"/subscriptions/{sub}/notices/{notice_id}/verify")
        self.assertTrue(ver["verified"])

    def test_pending_disposition_waits_if_still_sending_after_restart(self):
        sub = self.bootstrap(n=1)
        _, cl = claim(self.c, sub, 1)
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "挂起"})
        self.restart()  # 没有发送结果：仍 sending，处置继续挂起
        _, got = self.c.get(f"/dispositions/{r['disposition_id']}")
        self.assertEqual(got["targets"][0]["state"], "pending")
        # 新任发送端强制接管后 nack -> 取消（稳定落到唯一结果）
        _, cl2 = claim(self.c, sub, 1, {"force_reclaim": True})
        finish(self.c, "original", sub, 1, cl2["delivery_token"], False)
        _, got = self.c.get(f"/dispositions/{r['disposition_id']}")
        self.assertEqual(got["targets"][0]["state"], "cancelled")

    def test_queued_followup_survives_restart_with_identity_and_order(self):
        sub = self.bootstrap(n=2)
        self.deliver(sub, 1)
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "r"})
        notice_id = r["targets"][0]["result_notification_id"]
        self.restart()
        _, q = self.c.get(f"/subscriptions/{sub}/delivery-queue")
        positions = {x["notification_id"]: x["queue_position"]
                     for x in q["queue"]}
        self.assertEqual(positions[notice_id], 3)  # 严格在原通知 1、2 之后
        # 原通知身份与位置也不变
        originals = [x for x in q["queue"] if x["kind"] == "original"]
        self.assertEqual([x["queue_position"] for x in originals], [1, 2])
        _, fc = self.c.post(f"/subscriptions/{sub}/notices/{notice_id}/claim",
                            {})
        self.assertEqual(fc["envelope"]["relation"]["original_seq"], 1)

    def test_first_followup_position_immediately_after_original(self):
        sub = self.bootstrap(n=1)
        self.deliver(sub, 1)
        _, r = disposition(self.c, sub, 1,
                           {"action": "retract", "reason": "r"})
        notice_id = r["targets"][0]["result_notification_id"]
        _, q = self.c.get(f"/subscriptions/{sub}/delivery-queue")
        positions = {x["notification_id"]: x["queue_position"]
                     for x in q["queue"]}
        self.assertEqual(positions[notice_id], 2)

    def test_replaced_notification_state_survives_restart(self):
        sub = self.bootstrap(n=1)
        disposition(self.c, sub, 1, {
            "action": "correct", "reason": "r",
            "corrected_payload": {"actor": "restart-fixed", "action": "login"}})
        self.restart()
        _, cl = claim(self.c, sub, 1)
        self.assertEqual(cl["payload"]["actor"], "restart-fixed")
        _, ev = self.c.get(f"/subscriptions/{sub}/events/1/dispositions")
        self.assertEqual(len(ev["original_notification"]["revisions"]), 2)
