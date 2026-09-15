"""核心服务：契约登记、差异、预演、生效门禁、扫描泵、冻结通知、
隔离/HOL、映射重试、撤销、幂等冲突与审计历史。重启后由 __init__ 恢复。"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from . import contracts as C
from . import provenance as P
from .contracts import ContractError, VersionError
from .provenance import ProvenanceIntegrityError
from .store import Store


class Reject(Exception):
    """业务拒绝：携带 HTTP 状态码与机器可读 reason。"""

    def __init__(self, status: int, reason: str, detail: Any = None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail or {}


def _fingerprint(parts: dict) -> str:
    """请求内容指纹：键排序的规范化 JSON 的 sha256。

    幂等键只在请求内容完全一致时回放；版本、范围、序号、事件类型、
    映射目标等任一变化都会得到不同指纹并显式报冲突。
    """
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _idem_cached(hit: Any) -> dict:
    """幂等记录统一形态：{"_response": <首次结果>, "_fingerprint": <首次指纹>}。"""
    if isinstance(hit, dict) and "_response" in hit:
        return hit
    # 兼容旧信封（曾直接把 {"response":...} 当作响应体存储）
    if isinstance(hit, dict) and "response" in hit:
        return {"_response": hit["response"],
                "_fingerprint": hit.get("fingerprint")}
    return {"_response": hit, "_fingerprint": None}


def _idem_replay(store: Store, scope: str, key: Optional[str],
                 fingerprint: str, operation: str) -> Optional[dict]:
    """命中幂等键时：内容一致回放首次结果；不一致显式冲突（绝不沿用旧结果）。

    返回 {"replayed": True, ...首次响应}；未命中返回 None。
    历史记录可能没有指纹（旧库迁移），缺失指纹时退化为回放。
    """
    if not key:
        return None
    hit = store.idem_get(scope, key)
    if hit is None:
        return None
    rec = _idem_cached(hit)
    if rec.get("_fingerprint") is not None and rec["_fingerprint"] != fingerprint:
        raise Reject(409, "idempotency_request_conflict", {
            "operation": operation,
            "idempotency_key": key,
            "reason": "同一幂等键绑定的请求内容与首次提交不一致，"
                      "不能沿用首次结果；请更换幂等键或保持请求内容一致",
            "first_request_fingerprint": rec["_fingerprint"],
            "request_fingerprint": fingerprint})
    return {"replayed": True, **rec["_response"]}


def _idem_replay_attempt(store: Store, scope: str, key: Optional[str],
                         fingerprint: str, operation: str) -> Optional[dict]:
    """重试专用回放：成功结果回放为响应；失败结果回放为同状态拒绝。

    失败的重试也会落尝试记录与来源说明，因此其结果必须被幂等记录冻结：
    同键再次调用直接重放同一次失败，绝不再生成一份说明。
    """
    if not key:
        return None
    hit = store.idem_get(scope, key)
    if hit is None:
        return None
    rec = _idem_cached(hit)
    if rec.get("_fingerprint") is not None and rec["_fingerprint"] != fingerprint:
        raise Reject(409, "idempotency_request_conflict", {
            "operation": operation,
            "idempotency_key": key,
            "reason": "同一幂等键绑定的请求内容与首次提交不一致，"
                      "不能沿用首次结果；请更换幂等键或保持请求内容一致",
            "first_request_fingerprint": rec["_fingerprint"],
            "request_fingerprint": fingerprint})
    resp = rec["_response"]
    if isinstance(resp, dict) and resp.get("_error"):
        detail = dict(resp.get("detail") or {})
        detail["replayed"] = True
        raise Reject(resp["status"], resp["reason"], detail)
    return {"replayed": True, **resp}


class Service:
    def __init__(self, db_path: str = ":memory:"):
        self.store = Store(db_path)
        # 测试钩子：预演在处理第一条事件后中止（模拟进程崩溃，验证重启续跑）
        self.dryrun_interrupt = False
        self._resume_on_startup()

    @staticmethod
    def _reject(status: int, reason: str, detail: Any = None):
        raise Reject(status, reason, detail)

    @staticmethod
    def _fingerprint(parts: dict) -> str:
        return _fingerprint(parts)

    @staticmethod
    def _idem_cached(hit: Any) -> dict:
        return _idem_cached(hit)

    # ------------------------------------------------------------------ #
    # 重启恢复：恢复中断的预演；其余状态（冻结版本/映射/隔离位置）均在表里
    # ------------------------------------------------------------------ #
    def _resume_on_startup(self) -> None:
        rows = self.store.query(
            "SELECT * FROM dry_runs WHERE status='running'"
        )
        for row in rows:
            try:
                self._resume_dry_run(row["id"])
            except Exception:  # pragma: no cover - 续跑失败保留 running，等下次重试
                pass
        # 续跑未终结的处置：发送中的保持挂起等 ack/nack；其余按当前状态裁决
        from . import disposition as D
        D.resume_on_startup(self)

    # ------------------------------------------------------------------ #
    # 处置（更正/撤回）与发送状态机：见 disposition.py
    # ------------------------------------------------------------------ #
    def create_disposition(self, **kw):
        from . import disposition as D
        return D.create_disposition(self, **kw)

    def get_disposition(self, disp_id: str) -> dict:
        from . import disposition as D
        return D.get_disposition(self, disp_id)

    def event_dispositions(self, sub_id: str, seq: int) -> dict:
        from . import disposition as D
        return D.event_dispositions(self, sub_id, seq)

    def delivery_queue(self, sub_id: str) -> dict:
        from . import disposition as D
        return D.delivery_queue(self, sub_id)

    def claim_notification(self, sub_id: str, seq: int,
                           force: bool = False) -> dict:
        from . import disposition as D
        return D.claim_notification(self, sub_id, seq, force)

    def ack_notification(self, sub_id: str, seq: int, token: str) -> dict:
        from . import disposition as D
        return D._finish_notification(self, sub_id, seq, token, True)

    def nack_notification(self, sub_id: str, seq: int, token: str) -> dict:
        from . import disposition as D
        return D._finish_notification(self, sub_id, seq, token, False)

    def claim_notice(self, sub_id: str, notice_id: str,
                     force: bool = False) -> dict:
        from . import disposition as D
        return D.claim_notice(self, sub_id, notice_id, force)

    def ack_notice(self, sub_id: str, notice_id: str, token: str) -> dict:
        from . import disposition as D
        return D._finish_notice(self, sub_id, notice_id, token, True)

    def nack_notice(self, sub_id: str, notice_id: str, token: str) -> dict:
        from . import disposition as D
        return D._finish_notice(self, sub_id, notice_id, token, False)

    def verify_notice_signature(self, sub_id: str, notice_id: str) -> dict:
        from . import disposition as D
        return D.verify_notice_signature(self, sub_id, notice_id)

    def rotate_signing_key(self, idem_key: Optional[str] = None) -> dict:
        """轮换当前签名密钥：旧密钥失活但保留验签能力，历史签名仍可验证。"""
        scope = "signing_rotation"
        fingerprint = _fingerprint({"op": "rotate_signing_key"})
        with self.store.lock:
            replayed = _idem_replay(self.store, scope, idem_key,
                                    fingerprint, "rotate_signing_key")
            if replayed is not None:
                return replayed
            self.store.begin()
            kid = self.store.signer.rotate_key()
            self.audit("signing_key_rotated", {"kid": kid})
            result = {"kid": kid, "rotated": True}
            if idem_key:
                self.store.idem_put(scope, idem_key, result, fingerprint)
            self.store.commit()
        return result

    # ------------------------------------------------------------------ #
    # 审计
    # ------------------------------------------------------------------ #
    def audit(self, category: str, detail: Any, sub_id: Optional[str] = None) -> None:
        self.store.conn.execute(
            "INSERT INTO audit_history(sub_id, at, category, detail_json) VALUES (?,?,?,?)",
            (sub_id, time.time(), category, json.dumps(detail, ensure_ascii=False)),
        )

    def audit_history(self, sub_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        if sub_id is None:
            rows = self.store.query(
                "SELECT * FROM audit_history ORDER BY id DESC LIMIT ?", (limit,))
        else:
            rows = self.store.query(
                "SELECT * FROM audit_history WHERE sub_id=? ORDER BY id DESC LIMIT ?",
                (sub_id, limit))
        return [{
            "id": r["id"], "sub_id": r["sub_id"], "at": r["at"],
            "category": r["category"], "detail": json.loads(r["detail_json"]),
        } for r in rows]

    # ------------------------------------------------------------------ #
    # 订阅与事件
    # ------------------------------------------------------------------ #
    def create_subscription(self, sub_id: str) -> dict:
        with self.store.lock:
            try:
                self.store.begin()
                row = self.store.conn.execute(
                    "SELECT id FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
                if row:
                    self.store.rollback()
                    raise Reject(409, "subscription_exists", {"sub_id": sub_id})
                self.store.conn.execute(
                    "INSERT INTO subscriptions(id, created_at) VALUES (?,?)",
                    (sub_id, time.time()))
                self.audit("subscription_created", {"sub_id": sub_id}, sub_id)
                self.store.commit()
            except Reject:
                raise
            except Exception as e:
                self.store.rollback()
                raise Reject(500, "internal_error", {"error": str(e)})
        return {"sub_id": sub_id}

    def ingest_event(self, sub_id: str, seq: int, event_type: str, payload: Any) -> dict:
        self._require_sub(sub_id)
        with self.store.lock:
            try:
                self.store.begin()
                dup = self.store.conn.execute(
                    "SELECT seq FROM events WHERE sub_id=? AND seq=?", (sub_id, seq)).fetchone()
                if dup:
                    self.store.rollback()
                    raise Reject(409, "event_seq_conflict", {"seq": seq})
                self.store.conn.execute(
                    "INSERT INTO events(sub_id, seq, event_type, raw_payload, ingested_at) "
                    "VALUES (?,?,?,?,?)",
                    (sub_id, seq, event_type,
                     json.dumps(payload, ensure_ascii=False), time.time()))
                # 单调推进稳定水位（测试/接入层负责无空洞提交）
                sub = self.store.conn.execute(
                    "SELECT stable_seq FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
                if seq == sub["stable_seq"] + 1:
                    self.store.conn.execute(
                        "UPDATE subscriptions SET stable_seq=? WHERE id=?", (seq, sub_id))
                elif seq > sub["stable_seq"] + 1:
                    self.store.rollback()
                    raise Reject(409, "event_seq_gap",
                                 {"seq": seq, "expected": sub["stable_seq"] + 1})
                self.audit("event_ingested",
                           {"seq": seq, "event_type": event_type}, sub_id)
                self.store.commit()
            except Reject:
                raise
            except Exception as e:
                self.store.rollback()
                raise Reject(500, "internal_error", {"error": str(e)})
        return {"sub_id": sub_id, "seq": seq, "accepted": True}

    def scan(self, sub_id: str) -> dict:
        """显式推进订阅扫描位置（操作员/投递循环驱动）。

        入库只推进稳定水位；扫描与入库解耦，从而在 scan_seq 与 stable_seq
        之间留出激活窗口。激活与重试成功后也会自动续扫。
        """
        self._require_sub(sub_id)
        with self.store.lock:
            before = self.store.query_one(
                "SELECT scan_seq, stable_seq FROM subscriptions WHERE id=?",
                (sub_id,))
            self._pump_locked(sub_id)
            after = self.store.query_one(
                "SELECT scan_seq, stable_seq FROM subscriptions WHERE id=?",
                (sub_id,))
        head = self.store.query_one(
            "SELECT seq FROM quarantines WHERE sub_id=? AND status='blocked' "
            "ORDER BY seq LIMIT 1", (sub_id,))
        return {"sub_id": sub_id,
                "scan_seq_before": before["scan_seq"],
                "scan_seq_after": after["scan_seq"],
                "stable_seq": after["stable_seq"],
                "head_blocked_seq": head["seq"] if head else None}

    def subscription_status(self, sub_id: str) -> dict:
        self._require_sub(sub_id)
        sub = self.store.query_one(
            "SELECT scan_seq, stable_seq FROM subscriptions WHERE id=?", (sub_id,))
        head = self.store.query_one(
            "SELECT seq FROM quarantines WHERE sub_id=? AND status='blocked' "
            "ORDER BY seq LIMIT 1", (sub_id,))
        return {"sub_id": sub_id, "scan_seq": sub["scan_seq"],
                "stable_seq": sub["stable_seq"],
                "head_blocked_seq": head["seq"] if head else None,
                "activations": self.active_activation(sub_id)}

    def _require_sub(self, sub_id: str) -> None:
        if not self.store.query_one("SELECT 1 FROM subscriptions WHERE id=?", (sub_id,)):
            raise Reject(404, "subscription_not_found", {"sub_id": sub_id})

    # ------------------------------------------------------------------ #
    # 契约登记
    # ------------------------------------------------------------------ #
    def register_contract(self, event_type: str, version: str,
                          spec: dict, idem_key: Optional[str] = None) -> dict:
        try:
            C.validate_version(version)
            C.validate_spec(spec)
        except (ContractError, VersionError) as e:
            raise Reject(400, "invalid_contract", {"message": str(e)})
        scope = f"contract:{event_type}"
        fingerprint = _fingerprint({
            "event_type": event_type, "version": version, "spec": spec})
        with self.store.lock:
            # 幂等回放/冲突优先：同键同内容回放；同键改版本/改 spec 一律显式冲突，
            # 绝不沿用首次结果（即使目标版本尚未登记，也不借首次键把它登记进去）
            replayed = _idem_replay(self.store, scope, idem_key,
                                    fingerprint, "register_contract")
            if replayed is not None:
                return replayed
            existing = self.store.query_one(
                "SELECT version FROM contracts WHERE event_type=? AND version=?",
                (event_type, version))
            if existing:
                row = self.store.query_one(
                    "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
                    (event_type, version))
                if json.loads(row["spec_json"]) != spec:
                    raise Reject(409, "contract_version_conflict",
                                 {"event_type": event_type, "version": version,
                                  "reason": "同版本号已登记不同契约"})
                result = {"event_type": event_type, "version": version, "replayed": True}
                if idem_key:
                    self.store.idem_put(scope, idem_key, result,
                                        fingerprint)
                return result
            self.store.begin()
            self.store.conn.execute(
                "INSERT INTO contracts(event_type, version, spec_json, created_at) "
                "VALUES (?,?,?,?)",
                (event_type, version, json.dumps(spec, ensure_ascii=False), time.time()))
            self.audit("contract_registered",
                       {"event_type": event_type, "version": version})
            result = {"event_type": event_type, "version": version, "registered": True}
            if idem_key:
                self.store.idem_put(scope, idem_key, result,
                                    fingerprint)
            self.store.commit()
        return result

    def get_contract(self, event_type: str, version: str) -> dict:
        row = self.store.query_one(
            "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
            (event_type, version))
        if not row:
            raise Reject(404, "contract_not_found",
                         {"event_type": event_type, "version": version})
        return {"event_type": event_type, "version": version, "spec": json.loads(row["spec_json"])}

    def list_contracts(self, event_type: str) -> dict:
        rows = self.store.query(
            "SELECT version FROM contracts WHERE event_type=? ORDER BY version", (event_type,))
        return {"event_type": event_type, "versions": [r["version"] for r in rows]}

    # ------------------------------------------------------------------ #
    # 差异
    # ------------------------------------------------------------------ #
    def diff(self, event_type: str, old_version: Optional[str],
             new_version: str, sub_id: Optional[str] = None) -> dict:
        new_row = self.store.query_one(
            "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
            (event_type, new_version))
        if not new_row:
            raise Reject(404, "contract_not_found", {"version": new_version})
        old_spec: Optional[dict] = None
        if old_version:
            old_row = self.store.query_one(
                "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
                (event_type, old_version))
            if not old_row:
                raise Reject(404, "contract_not_found", {"version": old_version})
            old_spec = json.loads(old_row["spec_json"])
        result = C.diff_contracts(old_spec, json.loads(new_row["spec_json"]))
        result.update({"event_type": event_type,
                       "old_version": old_version, "new_version": new_version})
        if sub_id:
            with self.store.lock:
                self.store.begin()
                self.audit("contract_diff", {
                    "event_type": event_type, "old_version": old_version,
                    "new_version": new_version, "verdict": result["verdict"],
                    "counts": result["counts"],
                }, sub_id)
                self.store.commit()
        return result

    # ------------------------------------------------------------------ #
    # 预演
    # ------------------------------------------------------------------ #
    def start_dry_run(self, sub_id: str, event_type: str, version: str,
                      from_seq: int = 1, to_seq: Optional[int] = None,
                      idem_key: Optional[str] = None) -> dict:
        self._require_sub(sub_id)
        scope = f"dryrun:{sub_id}"
        fingerprint = _fingerprint({
            "event_type": event_type, "version": version,
            "from_seq": from_seq,
            "to_seq": to_seq if to_seq is not None else "_stable_",
        })
        with self.store.lock:
            replayed = _idem_replay(self.store, scope, idem_key,
                                    fingerprint, "dry_run")
            if replayed is not None:
                dr_id = replayed["dry_run_id"]
                return {**self.get_dry_run(dr_id), "replayed": True}
        crow = self.store.query_one(
            "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
            (event_type, version))
        if not crow:
            raise Reject(404, "contract_not_found", {"version": version})
        sub = self.store.query_one(
            "SELECT stable_seq FROM subscriptions WHERE id=?", (sub_id,))
        stable = sub["stable_seq"]
        if to_seq is None:
            to_seq = stable
        if from_seq < 1 or to_seq < from_seq - 1:
            raise Reject(400, "invalid_range", {"from_seq": from_seq, "to_seq": to_seq})
        if to_seq > stable:
            raise Reject(
                422, "dryrun_range_beyond_stable",
                {"to_seq": to_seq, "stable_seq": stable,
                 "reason": "预演范围不能越过稳定历史：未来事件尚不可变，结论会失效"})
        with self.store.lock:
            self.store.begin()
            cur = self.store.conn.execute(
                "INSERT INTO dry_runs(sub_id, event_type, version, spec_json, "
                "from_seq, to_seq, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (sub_id, event_type, version, crow["spec_json"],
                 from_seq, to_seq, "running", time.time()))
            dr_id = cur.lastrowid
            self.audit("dryrun_started", {
                "dry_run_id": dr_id, "event_type": event_type, "version": version,
                "from_seq": from_seq, "to_seq": to_seq}, sub_id)
            if idem_key:
                self.store.idem_put(scope, idem_key,
                                    {"dry_run_id": dr_id},
                                    fingerprint)
            self.store.commit()
            self._run_dry_run_locked(dr_id)
        return self.get_dry_run(dr_id)

    def _run_dry_run_locked(self, dr_id: int) -> None:
        """逐条校验历史事件；处理进度随落库，重启后可续跑。

        合法事件写一条 severity=ok 的进度标记，使“处理到哪一条”不依赖
        是否产生 finding；block/info 是真正的预演结论。
        """
        dr = self.store.query_one("SELECT * FROM dry_runs WHERE id=?", (dr_id,))
        if dr["status"] != "running":
            return
        spec = json.loads(dr["spec_json"])
        done_seqs = {r["seq"] for r in self.store.query(
            "SELECT DISTINCT seq FROM dry_run_findings WHERE dry_run_id=?", (dr_id,))}
        events = self.store.query(
            "SELECT * FROM events WHERE sub_id=? AND event_type=? AND seq BETWEEN ? AND ? "
            "ORDER BY seq",
            (dr["sub_id"], dr["event_type"], dr["from_seq"], dr["to_seq"]))
        # 倒序处理，使崩溃钩子落在第一条（序号最小）事件之前，
        # 已落库的都是高序号结论，对“续跑”同样成立。
        events = list(reversed(events))
        interrupted = False
        first_unprocessed = True
        for ev in events:
            if ev["seq"] in done_seqs:
                first_unprocessed = False
                continue
            payload = json.loads(ev["raw_payload"])
            _, errors, infos = C.check_and_normalize(spec, payload)
            self.store.begin()
            if not errors and not infos:
                # 进度标记（不算结论）
                self.store.conn.execute(
                    "INSERT INTO dry_run_findings(dry_run_id, seq, severity, path, reason) "
                    "VALUES (?,?,?,?,?)",
                    (dr_id, ev["seq"], "ok", "$", "符合契约"))
            for e in errors:
                self.store.conn.execute(
                    "INSERT INTO dry_run_findings(dry_run_id, seq, severity, path, reason) "
                    "VALUES (?,?,?,?,?)",
                    (dr_id, ev["seq"], "block", e["path"], e["reason"]))
            for i in infos:
                self.store.conn.execute(
                    "INSERT INTO dry_run_findings(dry_run_id, seq, severity, path, reason) "
                    "VALUES (?,?,?,?,?)",
                    (dr_id, ev["seq"], "info", i["path"], i["reason"]))
            self.store.commit()
            if self.dryrun_interrupt and first_unprocessed:
                interrupted = True
                break
            first_unprocessed = False
        if interrupted:
            return
        self._finish_dry_run(dr_id)

    def _resume_dry_run(self, dr_id: int) -> None:
        with self.store.lock:
            self._run_dry_run_locked(dr_id)

    def _finish_dry_run(self, dr_id: int) -> None:
        with self.store.lock:
            self.store.begin()
            blocks = self.store.conn.execute(
                "SELECT COUNT(*) c FROM dry_run_findings WHERE dry_run_id=? AND severity='block'",
                (dr_id,)).fetchone()["c"]
            status = "passed" if blocks == 0 else "failed"
            self.store.conn.execute(
                "UPDATE dry_runs SET status=?, blocking_errors=?, finished_at=? WHERE id=?",
                (status, blocks, time.time(), dr_id))
            dr = self.store.conn.execute(
                "SELECT * FROM dry_runs WHERE id=?", (dr_id,)).fetchone()
            self.audit("dryrun_finished", {
                "dry_run_id": dr_id, "event_type": dr["event_type"],
                "version": dr["version"], "from_seq": dr["from_seq"],
                "to_seq": dr["to_seq"], "status": status,
                "blocking_errors": blocks}, dr["sub_id"])
            self.store.commit()

    def get_dry_run(self, dr_id: int) -> dict:
        dr = self.store.query_one("SELECT * FROM dry_runs WHERE id=?", (dr_id,))
        if not dr:
            raise Reject(404, "dryrun_not_found", {"dry_run_id": dr_id})
        findings = [dict(seq=r["seq"], severity=r["severity"],
                         path=r["path"], reason=r["reason"])
                    for r in self.store.query(
                        "SELECT * FROM dry_run_findings WHERE dry_run_id=? "
                        "AND severity IN ('block','info') ORDER BY seq, path",
                        (dr_id,))]
        blocked_events = sorted({f["seq"] for f in findings if f["severity"] == "block"})
        return {
            "dry_run_id": dr_id, "sub_id": dr["sub_id"],
            "event_type": dr["event_type"], "version": dr["version"],
            "from_seq": dr["from_seq"], "to_seq": dr["to_seq"],
            "status": dr["status"], "blocking_errors": dr["blocking_errors"],
            "blocked_events": blocked_events, "findings": findings,
        }

    # ------------------------------------------------------------------ #
    # 激活门禁
    # ------------------------------------------------------------------ #
    def activate(self, sub_id: str, event_type: str, version: str,
                 effective_seq: Optional[int] = None,
                 expected_version: Optional[str] = None,
                 expected_absent: bool = False,
                 idem_key: Optional[str] = None) -> dict:
        self._require_sub(sub_id)
        if not self.store.query_one(
                "SELECT 1 FROM contracts WHERE event_type=? AND version=?",
                (event_type, version)):
            raise Reject(404, "contract_not_found", {"version": version})

        sub = self.store.query_one(
            "SELECT scan_seq, stable_seq FROM subscriptions WHERE id=?", (sub_id,))
        scan_seq, stable_seq = sub["scan_seq"], sub["stable_seq"]
        if effective_seq is None:
            effective_seq = scan_seq + 1

        scope = f"activate:{sub_id}"
        fingerprint = _fingerprint({
            "event_type": event_type, "version": version,
            "effective_seq": effective_seq,
            "expected_version": expected_version,
            "expected_absent": expected_absent,
        })
        with self.store.lock:
            replayed = _idem_replay(self.store, scope, idem_key,
                                    fingerprint, "activate")
            if replayed is not None:
                return replayed

        checks: List[str] = []
        # 门禁 1：必须存在覆盖生效点、且无阻断错误的已完成预演
        gate = self.store.query_one(
            "SELECT * FROM dry_runs WHERE sub_id=? AND event_type=? AND version=? "
            "AND status='passed' AND from_seq<=? AND to_seq>=? "
            "ORDER BY id DESC LIMIT 1",
            (sub_id, event_type, version, effective_seq, effective_seq))
        if not gate:
            dr = self.store.query_one(
                "SELECT * FROM dry_runs WHERE sub_id=? AND event_type=? AND version=? "
                "ORDER BY id DESC LIMIT 1",
                (sub_id, event_type, version))
            if not dr:
                checks.append("尚未进行预演（dry_run_missing）：候选版本必须先在稳定历史上预演")
            elif dr["status"] != "passed":
                checks.append(
                    f"预演未通过（dry_run_failed, blocking_errors={dr['blocking_errors']}）："
                    f"仍有阻断错误的候选版本不能生效")
            else:
                checks.append(
                    f"预演范围 [{dr['from_seq']},{dr['to_seq']}] 未覆盖生效点 "
                    f"{effective_seq}（dry_run_not_covering_effective_seq）")
        # 门禁 2：生效序号不能越过稳定历史
        if effective_seq > stable_seq:
            checks.append(
                f"生效序号 {effective_seq} 越过稳定历史水位 {stable_seq}"
                f"（effective_seq_beyond_stable）：该位置的事件尚不可变，拒绝生效")
        # 门禁 3：生效序号不能早于（<=）订阅扫描位置
        if effective_seq <= scan_seq:
            checks.append(
                f"生效序号 {effective_seq} 不晚于订阅扫描位置 {scan_seq}"
                f"（effective_seq_before_scan_position）：这些事件已按旧契约冻结，"
                f"不能换约，拒绝生效")
        if checks:
            with self.store.lock:
                self.store.begin()
                self.audit("activation_rejected", {
                    "event_type": event_type, "version": version,
                    "effective_seq": effective_seq, "reasons": checks}, sub_id)
                self.store.commit()
            raise Reject(409, "activation_rejected", {"reasons": checks})

        scope = f"activate:{sub_id}"
        with self.store.lock:
            try:
                self.store.begin()
                # CAS：并发激活只允许一个版本成功
                cur = self.store.conn.execute(
                    "SELECT version FROM activations WHERE sub_id=? AND event_type=? AND active=1",
                    (sub_id, event_type)).fetchone()
                current_version = cur["version"] if cur else None
                if expected_version is not None and expected_version != current_version:
                    self.store.rollback()
                    raise Reject(409, "activation_conflict", {
                        "reason": "并发激活冲突：当前生效版本与 expected_version 不一致，"
                                  "只有一个版本能成功",
                        "current_version": current_version,
                        "expected_version": expected_version})
                if expected_absent and cur is not None:
                    self.store.rollback()
                    raise Reject(409, "activation_conflict", {
                        "reason": "并发激活冲突：expected_absent=true 但已存在生效版本，"
                                  "只有一个版本能成功",
                        "current_version": current_version})
                # 头阻塞：有隔离挡住的位置时，生效点不能落入被挡区域
                head = self.store.conn.execute(
                    "SELECT seq FROM quarantines WHERE sub_id=? AND status='blocked' "
                    "ORDER BY seq LIMIT 1", (sub_id,)).fetchone()
                if head and effective_seq > head["seq"]:
                    self.store.rollback()
                    raise Reject(409, "activation_blocked_by_quarantine", {
                        "blocked_seq": head["seq"], "effective_seq": effective_seq,
                        "reason": "隔离队列正挡住后续通知，无法在其后切换契约"})
                if cur:
                    self.store.conn.execute(
                        "UPDATE activations SET active=0 WHERE id=?",
                        (self._activation_id(sub_id, event_type),))
                self.store.conn.execute(
                    "INSERT INTO activations(sub_id, event_type, version, "
                    "effective_seq, active, created_at, idem_key) VALUES (?,?,?,?,1,?,?)",
                    (sub_id, event_type, version, effective_seq,
                     time.time(), idem_key))
                d = self.diff(event_type, current_version, version)
                self.audit("activated", {
                    "event_type": event_type, "version": version,
                    "previous_version": current_version,
                    "effective_seq": effective_seq,
                    "verdict": d["verdict"], "counts": d["counts"],
                    "field_changes": d["fields"]}, sub_id)
                result = {
                    "sub_id": sub_id, "event_type": event_type,
                    "version": version, "previous_version": current_version,
                    "effective_seq": effective_seq, "activated": True}
                if idem_key:
                    self.store.idem_put(scope, idem_key, result,
                                        fingerprint)
                self.store.commit()
            except Reject:
                raise
            except Exception as e:
                self.store.rollback()
                # SQLite 唯一索引竞争：并发激活的落败方
                raise Reject(409, "activation_conflict",
                             {"reason": "并发激活冲突，只有一个版本成功",
                              "error": str(e)})
            # 激活只登记生效点；不自动扫描。扫描由显式 /scan（投递循环）驱动，
            # 这样管理员可以在 scan_seq 与 stable_seq 之间连续登记多个生效点，
            # 且“生效序号早于扫描位置”的门禁保持确定语义。
        return result

    def _activation_id(self, sub_id: str, event_type: str) -> int:
        return self.store.query_one(
            "SELECT id FROM activations WHERE sub_id=? AND event_type=? AND active=1",
            (sub_id, event_type))["id"]

    def revoke(self, sub_id: str, event_type: str,
               idem_key: Optional[str] = None) -> dict:
        """撤销生效契约。撤销点之后（未扫描）的事件不再受该契约约束。"""
        self._require_sub(sub_id)
        scope = f"revoke:{sub_id}"
        fingerprint = _fingerprint({"event_type": event_type})
        with self.store.lock:
            replayed = _idem_replay(self.store, scope, idem_key,
                                    fingerprint, "revoke")
            if replayed is not None:
                return replayed
            self.store.begin()
            cur = self.store.conn.execute(
                "SELECT * FROM activations WHERE sub_id=? AND event_type=? AND active=1",
                (sub_id, event_type)).fetchone()
            if not cur:
                self.store.rollback()
                raise Reject(404, "no_active_activation", {"event_type": event_type})
            # 撤销点：下一个未扫描序号。撤销点之前已冻结的通知继续保留该版本，
            # 撤销点及之后的事件不再由该契约治理。
            scan_now = self.store.conn.execute(
                "SELECT scan_seq FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
            revoke_seq = scan_now["scan_seq"] + 1
            self.store.conn.execute(
                "UPDATE activations SET active=0, revoked_at=?, revoke_seq=? WHERE id=?",
                (time.time(), revoke_seq, cur["id"]))
            self.audit("activation_revoked", {
                "event_type": event_type, "version": cur["version"],
                "revoke_seq": revoke_seq}, sub_id)
            result = {"sub_id": sub_id, "event_type": event_type,
                      "version": cur["version"], "revoke_seq": revoke_seq,
                      "revoked": True}
            if idem_key:
                self.store.idem_put(scope, idem_key, result,
                                    fingerprint)
            self.store.commit()
        return result

    def _contract_at(self, sub_id: str, event_type: str, seq: int) -> Optional[dict]:
        """解析 seq 位置适用的契约版本。

        取 effective_seq<=seq 的最近一条激活历史行（包括换约/撤销后 active=0
        的行）：激活历史不可变，它解释了当时的入队决定。若该行被撤销且
        seq 已到达撤销点（revoke_seq<=seq），则该位置不再受任何契约治理，
        返回 None（撤销点之前的位置仍由其解释）。
        """
        row = self.store.query_one(
            "SELECT version, revoked_at, revoke_seq FROM activations "
            "WHERE sub_id=? AND event_type=? AND effective_seq<=? "
            "ORDER BY effective_seq DESC, id DESC LIMIT 1",
            (sub_id, event_type, seq))
        if not row:
            return None
        if row["revoke_seq"] is not None and row["revoke_seq"] <= seq:
            return None
        crow = self.store.query_one(
            "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
            (event_type, row["version"]))
        return {"version": row["version"], "spec": json.loads(crow["spec_json"]),
                "revoked": row["revoked_at"] is not None}

    def _resolve_legacy_leaf_type(self, sub_id: str, event_type: str,
                                  norm_path: str,
                                  seq: Optional[int]) -> Optional[str]:
        """解析已不在当前契约中的旧叶子字段类型（用于旧字段 rename）。

        隔离事件保留的是旧字段：它在隔离时冻结的旧契约版本里仍是声明叶子。
        解析顺序：
        1. 指定 seq 的隔离行冻结版本（隔离修复登记映射的典型路径）；
        2. 该订阅该事件类型激活历史中的所有版本（含已撤销/已换约）；
        3. 指定 seq 的隔离原始事件中按 JSON 标量推断（兜底，旧生产者误送字段）。
        """
        versions: List[str] = []
        if seq is not None:
            qrow = self.store.query_one(
                "SELECT expected_version FROM quarantines "
                "WHERE sub_id=? AND seq=? AND event_type=?",
                (sub_id, seq, event_type))
            if qrow and qrow["expected_version"]:
                versions.append(qrow["expected_version"])
        for r in self.store.query(
                "SELECT DISTINCT version FROM activations "
                "WHERE sub_id=? AND event_type=? ORDER BY id DESC",
                (sub_id, event_type)):
            if r["version"] not in versions:
                versions.append(r["version"])
        for ver in versions:
            crow = self.store.query_one(
                "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
                (event_type, ver))
            if not crow:
                continue
            leaf = C.flatten(json.loads(crow["spec_json"])).get(norm_path)
            if leaf and leaf["kind"] == "leaf":
                return leaf["type"]
        # 兜底：旧生产者可能误送一个任何契约都未声明过的字段，
        # 按隔离原始事件中的 JSON 标量类型推断（结构字段不允许作为 rename 源）。
        if seq is not None:
            ev = self.store.query_one(
                "SELECT raw_payload FROM events WHERE sub_id=? AND seq=?",
                (sub_id, seq))
            if ev:
                val = _get_path(json.loads(ev["raw_payload"]), norm_path, _MISSING)
                if val is not _MISSING:
                    inferred = _json_leaf_type(val)
                    if inferred is not None:
                        return inferred
        return None

    def active_activation(self, sub_id: str, event_type: Optional[str] = None) -> Any:
        if event_type is None:
            rows = self.store.query(
                "SELECT * FROM activations WHERE sub_id=? AND active=1", (sub_id,))
            return [{"event_type": r["event_type"], "version": r["version"],
                     "effective_seq": r["effective_seq"]} for r in rows]
        row = self.store.query_one(
            "SELECT * FROM activations WHERE sub_id=? AND event_type=? AND active=1",
            (sub_id, event_type))
        if not row:
            return None
        return {"event_type": event_type, "version": row["version"],
                "effective_seq": row["effective_seq"]}

    # ------------------------------------------------------------------ #
    # 扫描泵：冻结入队 / 验证失败隔离（HOL）
    # ------------------------------------------------------------------ #
    def _pump_locked(self, sub_id: str) -> None:
        """从 scan_seq+1 开始顺序处理，遇阻即停（头阻塞）。

        每个事件处理时冻结：契约版本、规范化载荷（canonical+digest）、验证摘要。
        """
        while True:
            sub = self.store.query_one(
                "SELECT scan_seq, stable_seq FROM subscriptions WHERE id=?", (sub_id,))
            nxt = sub["scan_seq"] + 1
            ev = self.store.query_one(
                "SELECT * FROM events WHERE sub_id=? AND seq=?", (sub_id, nxt))
            if not ev:
                return
            # 幂等护栏：重启后泵不应重复冻结（恢复路径除外，恢复走 UPDATE）
            if self.store.query_one(
                    "SELECT 1 FROM notifications WHERE sub_id=? AND seq=?",
                    (sub_id, nxt)):
                blocked = self.store.query_one(
                    "SELECT 1 FROM quarantines WHERE sub_id=? AND seq=? AND status='blocked'",
                    (sub_id, nxt))
                if blocked:
                    return  # 仍在隔离：保持 HOL
                self.store.begin()
                self.store.conn.execute(
                    "UPDATE subscriptions SET scan_seq=? WHERE id=?", (nxt, sub_id))
                self.store.commit()
                continue
            contract = self._contract_at(sub_id, ev["event_type"], nxt)
            raw = json.loads(ev["raw_payload"])
            if contract is None:
                revoked_here = self.store.query_one(
                    "SELECT 1 FROM activations WHERE sub_id=? AND event_type=? "
                    "AND effective_seq<=? AND revoke_seq IS NOT NULL "
                    "AND revoke_seq<=? ORDER BY id LIMIT 1",
                    (sub_id, ev["event_type"], nxt, nxt))
                if revoked_here:
                    # 契约在该位置已撤销：事件不再受契约约束，原样冻结并入队
                    self.store.begin()
                    entries = P.build_entries(None, raw, raw, [], [],
                                              ungoverned=True)
                    self._freeze_notification(
                        sub_id, ev, None, raw,
                        {"valid": True, "ungoverned": True,
                         "reason": "契约已撤销，事件不再受约束",
                         "errors": [], "infos": []},
                        "queued", source_payload=raw, entries=entries,
                        attempt_status="ungoverned", idem_key=None)
                    self.store.conn.execute(
                        "UPDATE subscriptions SET scan_seq=? WHERE id=?", (nxt, sub_id))
                    self.audit("notification_enqueued", {
                        "seq": nxt, "event_type": ev["event_type"],
                        "contract_version": None,
                        "reason": "契约撤销后无约束入队"}, sub_id)
                    self.store.commit()
                    continue
                # 从未生效过契约：不校验、不入队、不推进扫描位置。
                # 事件留在稳定历史中等待契约生效（预演正是针对它们）。
                return

            normalized, errors, infos = C.check_and_normalize(contract["spec"], raw)
            if errors:
                self.store.begin()
                entries = P.build_entries(
                    contract["spec"], raw, None, errors, infos)
                notif_id = self._freeze_notification(
                    sub_id, ev, contract["version"], raw,
                    {"valid": False, "errors": errors, "infos": infos},
                    "blocked", source_payload=raw, entries=entries,
                    attempt_status="blocked", idem_key=None)
                self.store.conn.execute(
                    "INSERT INTO quarantines(sub_id, seq, notification_id, event_type, "
                    "expected_version, raw_digest, errors_json, status, created_at) "
                    "VALUES (?,?,?,?,?,?,?,'blocked',?)",
                    (sub_id, nxt, notif_id, ev["event_type"], contract["version"],
                     C.digest(C.canonical_payload(raw)),
                     json.dumps(errors, ensure_ascii=False), time.time()))
                self.audit("event_quarantined", {
                    "seq": nxt, "event_type": ev["event_type"],
                    "contract_version": contract["version"],
                    "errors": errors}, sub_id)
                self.store.commit()
                return  # HOL：scan_seq 不推进，后续通知全部挡住

            self.store.begin()
            entries = P.build_entries(
                contract["spec"], raw, normalized, [], infos)
            self._freeze_notification(
                sub_id, ev, contract["version"], normalized,
                {"valid": True, "errors": [], "infos": infos}, "queued",
                source_payload=raw, entries=entries,
                attempt_status="queued", idem_key=None)
            self.store.conn.execute(
                "UPDATE subscriptions SET scan_seq=? WHERE id=?", (nxt, sub_id))
            self.audit("notification_enqueued", {
                "seq": nxt, "event_type": ev["event_type"],
                "contract_version": contract["version"],
                "digest": C.digest(C.canonical_payload(normalized))}, sub_id)
            self.store.commit()

    def _freeze_notification(self, sub_id: str, ev, version: Optional[str],
                             payload: Any, validation: dict, status: str,
                             source_payload: Any = None,
                             entries: Optional[List[dict]] = None,
                             attempt_status: Optional[str] = None,
                             idem_key: Optional[str] = None,
                             applied: Optional[List[dict]] = None) -> str:
        notif_id = f"ntf_{uuid.uuid4().hex}"
        frozen = C.canonical_payload(payload)
        origin_digest = C.digest(C.canonical_payload(
            source_payload if source_payload is not None else payload))
        # 排队位置：原通知与后续通知共享同一条单调队列（调用方须已 begin）
        pos_row = self.store.conn.execute(
            "SELECT next_queue_pos FROM subscriptions WHERE id=?",
            (sub_id,)).fetchone()
        queue_pos = pos_row["next_queue_pos"]
        self.store.conn.execute(
            "UPDATE subscriptions SET next_queue_pos=? WHERE id=?",
            (queue_pos + 1, sub_id))
        self.store.conn.execute(
            "INSERT INTO notifications(sub_id, seq, notification_id, event_type, "
            "contract_version, frozen_payload, digest, validation, status, created_at, "
            "queue_position) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (sub_id, ev["seq"], notif_id, ev["event_type"], version,
             frozen.decode("utf-8"), C.digest(frozen),
             json.dumps(validation, ensure_ascii=False), status, time.time(),
             queue_pos))
        # 首次修订留档（revision 1）：原位更正时通知行原地更新，历史在此可溯
        self.store.conn.execute(
            "INSERT INTO notification_revisions(sub_id, seq, notification_id, "
            "revision_no, contract_version, frozen_payload, digest, validation, "
            "signature_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sub_id, ev["seq"], notif_id, 1, version,
             frozen.decode("utf-8"), C.digest(frozen),
             json.dumps(validation, ensure_ascii=False), None, time.time()))
        # 首次冻结 = attempt_no 1：同时落尝试记录与来源说明（只追加、不可变）
        self._append_attempt_locked(
            sub_id, ev["seq"], notif_id, ev["event_type"], 1, "initial_freeze",
            attempt_status or status, version,
            origin_digest if status == "blocked" else C.digest(frozen),
            C.digest(frozen), entries or [], prev_digest=None,
            idem_key=idem_key, applied=applied or [])
        return notif_id

    def _append_attempt_locked(self, sub_id: str, seq: int, notif_id: str,
                               event_type: str, attempt_no: int, kind: str,
                               status: str, version: Optional[str],
                               payload_digest: str, frozen_digest: Optional[str],
                               entries: List[dict],
                               prev_digest: Optional[str],
                               idem_key: Optional[str] = None,
                               applied: Optional[List[dict]] = None) -> None:
        """原子追加一次尝试 + 一份来源说明（调用方须已 begin）。

        说明的 record_digest 覆盖全部绑定与条目，prev 锚定上一尝试，
        写入后任何后续契约/映射规则都不能再修改它。
        """
        origin_row = self.store.conn.execute(
            "SELECT raw_payload FROM events WHERE sub_id=? AND seq=?",
            (sub_id, seq)).fetchone()
        origin_event_digest = C.digest(
            C.canonical_payload(json.loads(origin_row["raw_payload"])))
        now = time.time()
        cur = self.store.conn.execute(
            "INSERT INTO delivery_attempts(sub_id, seq, notification_id, event_type, "
            "attempt_no, kind, status, contract_version, payload_digest, "
            "frozen_digest, applied_json, idem_key, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sub_id, seq, notif_id, event_type, attempt_no, kind, status,
             version, payload_digest, frozen_digest,
             json.dumps(applied or [], ensure_ascii=False), idem_key, now))
        record_digest = P.explanation_record_digest(
            sub_id=sub_id, seq=seq, attempt_no=attempt_no,
            notification_id=notif_id, contract_version=version,
            payload_digest=payload_digest,
            origin_event_digest=origin_event_digest, entries=entries)
        self.store.conn.execute(
            "INSERT INTO provenance_explanations(sub_id, seq, attempt_no, "
            "notification_id, contract_version, payload_digest, "
            "origin_event_digest, entries_json, record_digest, "
            "prev_record_digest, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (sub_id, seq, attempt_no, notif_id, version, payload_digest,
             origin_event_digest,
             json.dumps(entries, ensure_ascii=False), record_digest,
             prev_digest, now))

    def list_notifications(self, sub_id: str) -> dict:
        rows = self.store.query(
            "SELECT * FROM notifications WHERE sub_id=? ORDER BY seq", (sub_id,))
        return {"sub_id": sub_id, "notifications": [{
            "seq": r["seq"], "notification_id": r["notification_id"],
            "event_type": r["event_type"], "contract_version": r["contract_version"],
            "frozen_payload": json.loads(r["frozen_payload"]),
            "digest": r["digest"], "validation": json.loads(r["validation"]),
            "status": r["status"],
            "queue_position": r["queue_position"],
            "claimed_at": r["claimed_at"], "delivered_at": r["delivered_at"],
            "cancelled_at": r["cancelled_at"], "superseded": bool(r["superseded"]),
        } for r in rows]}

    # ------------------------------------------------------------------ #
    # 隔离查询
    # ------------------------------------------------------------------ #
    def list_quarantine(self, sub_id: str) -> dict:
        rows = self.store.query(
            "SELECT * FROM quarantines WHERE sub_id=? ORDER BY seq", (sub_id,))
        items = []
        for r in rows:
            ev = self.store.query_one(
                "SELECT raw_payload FROM events WHERE sub_id=? AND seq=?",
                (sub_id, r["seq"]))
            contract_now = self.active_activation(sub_id, r["event_type"])
            items.append({
                "seq": r["seq"], "notification_id": r["notification_id"],
                "event_type": r["event_type"],
                "expected_version": r["expected_version"],
                "status": r["status"], "retry_count": r["retry_count"],
                "raw_event_summary": {
                    "digest": r["raw_digest"],
                    "payload": json.loads(ev["raw_payload"]),
                },
                "failed_fields": json.loads(r["errors_json"]),
                "current_contract": contract_now,
                "provenance": self._provenance_summary(sub_id, r["seq"]),
                "created_at": r["created_at"],
                "recovered_at": r["recovered_at"],
            })
        head = next((i["seq"] for i in items if i["status"] == "blocked"), None)
        return {"sub_id": sub_id, "head_blocked_seq": head, "items": items}

    # ------------------------------------------------------------------ #
    # 来源说明查询 / 重试尝试列表 / 两次尝试比较（读取时强制完整性校验）
    # ------------------------------------------------------------------ #
    def _load_delivery(self, sub_id: str, seq: int):
        notif = self.store.query_one(
            "SELECT * FROM notifications WHERE sub_id=? AND seq=?",
            (sub_id, seq))
        if not notif:
            raise Reject(404, "notification_not_found",
                         {"sub_id": sub_id, "seq": seq,
                          "reason": "该序号尚未冻结任何通知（无来源说明）"})
        attempts = self.store.query(
            "SELECT * FROM delivery_attempts WHERE sub_id=? AND seq=? "
            "ORDER BY attempt_no", (sub_id, seq))
        explanations = self.store.query(
            "SELECT * FROM provenance_explanations WHERE sub_id=? AND seq=? "
            "ORDER BY attempt_no", (sub_id, seq))
        return notif, attempts, explanations

    def _verify_provenance_locked(self, sub_id: str, seq: int,
                                  notif, attempts, explanations) -> None:
        """重算哈希链与绑定；任何不一致都抛完整性错误，绝不返回可信内容。"""
        problems: List[dict] = []
        try:
            P.verify_chain(attempts, explanations)
        except ProvenanceIntegrityError as e:
            problems.extend(e.checks)
        # 原始审计事件摘要绑定
        ev = self.store.query_one(
            "SELECT raw_payload FROM events WHERE sub_id=? AND seq=?",
            (sub_id, seq))
        if ev and explanations:
            raw_digest = C.digest(
                C.canonical_payload(json.loads(ev["raw_payload"])))
            for exp in explanations:
                if exp["origin_event_digest"] != raw_digest:
                    problems.append({
                        "check": "origin_event_digest", "ok": False,
                        "attempt_no": exp["attempt_no"],
                        "stored": exp["origin_event_digest"],
                        "recomputed": raw_digest,
                        "reason": "来源说明绑定的原始事件摘要与审计事件不一致"})
        # 最新尝试的载荷摘要必须与冻结通知行一致
        if explanations:
            latest = explanations[-1]
            if latest["notification_id"] != notif["notification_id"]:
                problems.append({"check": "binding_notification_id", "ok": False,
                                 "reason": "来源说明绑定的投递身份与通知行不一致"})
            if notif["digest"] and notif["digest"] != latest["payload_digest"] \
                    and notif["status"] != "blocked":
                problems.append({
                    "check": "frozen_digest", "ok": False,
                    "attempt_no": latest["attempt_no"],
                    "notification_digest": notif["digest"],
                    "explanation_payload_digest": latest["payload_digest"],
                    "reason": "最新来源说明的载荷摘要与冻结通知不一致"})
        if problems:
            raise Reject(422, "provenance_integrity_error",
                         {"sub_id": sub_id, "seq": seq,
                          "reason": "来源说明未通过完整性校验，结果不可信",
                          "failed_checks": problems})

    def get_provenance(self, sub_id: str, seq: int,
                       attempt_no: Optional[int] = None) -> dict:
        self._require_sub(sub_id)
        notif, attempts, explanations = self._load_delivery(sub_id, seq)
        with self.store.lock:
            self._verify_provenance_locked(
                sub_id, seq, notif, attempts, explanations)
            if attempt_no is not None:
                rows = [a for a in attempts if a["attempt_no"] == attempt_no]
                if not rows:
                    raise Reject(404, "attempt_not_found",
                                 {"seq": seq, "attempt_no": attempt_no})
                exp = next(e for e in explanations
                           if e["attempt_no"] == attempt_no)
                return self._provenance_view(sub_id, seq, notif, rows[0], exp)
            latest_exp = explanations[-1]
            return {
                "sub_id": sub_id, "seq": seq,
                "notification_id": notif["notification_id"],
                "event_type": notif["event_type"],
                "notification_status": notif["status"],
                "latest_attempt_no": latest_exp["attempt_no"],
                "attempt_count": len(attempts),
                "integrity": {"trusted": True,
                              "checks": ["record_digest", "hash_chain",
                                         "bindings", "origin_event_digest",
                                         "frozen_digest"]},
                "latest": self._provenance_view(
                    sub_id, seq, notif, attempts[-1], latest_exp),
                "attempts": [
                    {"attempt_no": a["attempt_no"], "kind": a["kind"],
                     "status": a["status"],
                     "contract_version": a["contract_version"],
                     "payload_digest": a["payload_digest"],
                     "frozen_digest": a["frozen_digest"],
                     "record_digest": next(
                         e["record_digest"] for e in explanations
                         if e["attempt_no"] == a["attempt_no"])}
                    for a in attempts],
            }

    def _provenance_view(self, sub_id, seq, notif, att, exp) -> dict:
        entries = json.loads(exp["entries_json"])
        return {
            "sub_id": sub_id, "seq": seq,
            "attempt_no": att["attempt_no"], "kind": att["kind"],
            "status": att["status"],
            "notification_id": att["notification_id"],
            "event_type": att["event_type"],
            "contract_version": att["contract_version"],
            "payload_digest": att["payload_digest"],
            "frozen_digest": att["frozen_digest"],
            "origin_event_digest": exp["origin_event_digest"],
            "record_digest": exp["record_digest"],
            "prev_record_digest": exp["prev_record_digest"],
            "applied_mappings": json.loads(att["applied_json"]),
            "created_at": att["created_at"],
            "entries": entries,
            "integrity": {"trusted": True},
        }

    def list_retry_attempts(self, sub_id: str, seq: int) -> dict:
        self._require_sub(sub_id)
        notif, attempts, explanations = self._load_delivery(sub_id, seq)
        with self.store.lock:
            self._verify_provenance_locked(
                sub_id, seq, notif, attempts, explanations)
            exp_by_no = {e["attempt_no"]: e for e in explanations}
            items = []
            for a in attempts:
                exp = exp_by_no[a["attempt_no"]]
                entries = json.loads(exp["entries_json"])
                invalid = [e["path"] for e in entries
                           if e.get("validation", {}).get("valid") is False]
                items.append({
                    "attempt_no": a["attempt_no"], "kind": a["kind"],
                    "status": a["status"],
                    "contract_version": a["contract_version"],
                    "payload_digest": a["payload_digest"],
                    "frozen_digest": a["frozen_digest"],
                    "record_digest": exp["record_digest"],
                    "prev_record_digest": exp["prev_record_digest"],
                    "applied_mappings": json.loads(a["applied_json"]),
                    "idempotency_key": a["idem_key"],
                    "failed_fields": invalid,
                    "field_count": len(entries),
                    "created_at": a["created_at"]})
            return {"sub_id": sub_id, "seq": seq,
                    "notification_id": notif["notification_id"],
                    "notification_status": notif["status"],
                    "attempt_count": len(items),
                    "integrity": {"trusted": True},
                    "attempts": items}

    def compare_attempts(self, sub_id: str, seq: int,
                         from_attempt: Optional[int] = None,
                         to_attempt: Optional[int] = None) -> dict:
        self._require_sub(sub_id)
        notif, attempts, explanations = self._load_delivery(sub_id, seq)
        with self.store.lock:
            self._verify_provenance_locked(
                sub_id, seq, notif, attempts, explanations)
            available = [a["attempt_no"] for a in attempts]
            # 默认比较最后两次尝试（修复前 -> 修复后）
            if to_attempt is None:
                to_attempt = available[-1]
            if from_attempt is None:
                from_attempt = available[-2] if len(available) >= 2 \
                    else available[-1]
            exp_by_no = {e["attempt_no"]: e for e in explanations}
            if from_attempt not in exp_by_no or to_attempt not in exp_by_no:
                raise Reject(404, "attempt_not_found", {
                    "seq": seq, "from_attempt": from_attempt,
                    "to_attempt": to_attempt,
                    "available": available})
            ea = json.loads(exp_by_no[from_attempt]["entries_json"])
            eb = json.loads(exp_by_no[to_attempt]["entries_json"])
            diff = P.compare_explanations(ea, eb)
            return {
                "sub_id": sub_id, "seq": seq,
                "notification_id": notif["notification_id"],
                "from_attempt": from_attempt, "to_attempt": to_attempt,
                "from_record_digest": exp_by_no[from_attempt]["record_digest"],
                "to_record_digest": exp_by_no[to_attempt]["record_digest"],
                "from_contract_version":
                    exp_by_no[from_attempt]["contract_version"],
                "to_contract_version":
                    exp_by_no[to_attempt]["contract_version"],
                "integrity": {"trusted": True},
                **diff}

    def _provenance_summary(self, sub_id: str, seq: int) -> Optional[dict]:
        """隔离列表用的轻量来源摘要（完整校验在专门的 provenance 端点进行）。"""
        row = self.store.query_one(
            "SELECT COUNT(*) c, MAX(attempt_no) latest FROM delivery_attempts "
            "WHERE sub_id=? AND seq=?", (sub_id, seq))
        if not row or row["c"] == 0:
            return None
        last = self.store.query_one(
            "SELECT record_digest FROM provenance_explanations "
            "WHERE sub_id=? AND seq=? ORDER BY attempt_no DESC LIMIT 1",
            (sub_id, seq))
        return {"attempt_count": row["c"], "latest_attempt_no": row["latest"],
                "latest_record_digest": last["record_digest"] if last else None}

    def _next_attempt_no(self, sub_id: str, seq: int) -> int:
        row = self.store.query_one(
            "SELECT COALESCE(MAX(attempt_no),0) m FROM delivery_attempts "
            "WHERE sub_id=? AND seq=?", (sub_id, seq))
        return row["m"] + 1

    def _latest_record_digest(self, sub_id: str, seq: int) -> Optional[str]:
        row = self.store.query_one(
            "SELECT record_digest FROM provenance_explanations "
            "WHERE sub_id=? AND seq=? ORDER BY attempt_no DESC LIMIT 1",
            (sub_id, seq))
        return row["record_digest"] if row else None

    # ------------------------------------------------------------------ #
    # 映射规则
    # ------------------------------------------------------------------ #
    def register_mapping(self, sub_id: str, event_type: str, op: str,
                         src_path: Optional[str] = None,
                         dst_path: Optional[str] = None,
                         value: Any = None,
                         seq: Optional[int] = None,
                         idem_key: Optional[str] = None) -> dict:
        self._require_sub(sub_id)
        if op not in ("rename", "default", "drop"):
            raise Reject(400, "invalid_mapping_op", {"op": op})
        activation = self.active_activation(sub_id, event_type)
        if not activation:
            raise Reject(409, "no_active_contract",
                         {"reason": "映射必须针对一个生效契约版本登记"})
        version = activation["version"]
        spec_row = self.store.query_one(
            "SELECT spec_json FROM contracts WHERE event_type=? AND version=?",
            (event_type, version))
        spec = json.loads(spec_row["spec_json"])
        leaves = C.flatten(spec)

        # 登记时校验：只允许重命名 / 补固定默认值 / 删除明确允许忽略的字段
        if op == "rename":
            if not src_path or not dst_path:
                raise Reject(400, "mapping_need_paths", {"op": "rename"})
            norm_src = _norm_path(src_path)
            norm_dst = _norm_path(dst_path)
            d = leaves.get(norm_dst)
            if not d or d["kind"] != "leaf":
                raise Reject(404, "mapping_dst_unknown",
                             {"path": dst_path,
                              "reason": "目标字段必须是当前契约中的已知叶子字段"})
            # 源字段优先取当前契约；隔离事件保留的是旧字段时，允许源字段已不在
            # 当前契约中——从隔离时冻结的旧契约/该订阅激活过的历史版本解析类型。
            s = leaves.get(norm_src)
            if s is not None and s["kind"] != "leaf":
                raise Reject(409, "mapping_src_not_leaf",
                             {"path": src_path,
                              "reason": "重命名源必须是叶子字段，不能是结构节点"})
            if s is None:
                src_type = self._resolve_legacy_leaf_type(
                    sub_id, event_type, norm_src, seq)
                if src_type is None:
                    raise Reject(404, "mapping_src_unknown",
                                 {"path": src_path,
                                  "reason": "源字段既不在当前契约中，也无法从该订阅"
                                            "隔离事件保留的旧契约或历史版本中解析"})
            else:
                src_type = s["type"]
            if src_type != d["type"]:
                raise Reject(409, "mapping_type_mismatch",
                             {"src": src_path, "dst": dst_path,
                              "src_type": src_type, "dst_type": d["type"],
                              "reason": "重命名只能改字段名，不能改类型"})
        elif op == "default":
            if not dst_path:
                raise Reject(400, "mapping_need_dst", {"op": "default"})
            d = leaves.get(_norm_path(dst_path))
            if not d or d["kind"] != "leaf":
                raise Reject(404, "mapping_dst_unknown",
                             {"path": dst_path,
                              "reason": "默认值只能补到已知叶子字段"})
            if not C._value_matches_type(value, d["type"], d["enum"]):
                raise Reject(409, "mapping_value_type_mismatch",
                             {"path": dst_path, "value": value,
                              "type": d["type"], "enum": d["enum"]})
        else:  # drop
            if not src_path:
                raise Reject(400, "mapping_need_src", {"op": "drop"})
            s = leaves.get(_norm_path(src_path))
            if not s or s["kind"] != "leaf":
                raise Reject(404, "mapping_src_unknown",
                             {"path": src_path, "reason": "只能删除已知叶子字段"})
            if not s["ignorable"]:
                raise Reject(409, "drop_not_allowed",
                             {"path": src_path,
                              "reason": "映射只能删除明确标记 ignorable（允许忽略）的字段"})

        scope = f"mapping:{sub_id}"
        norm_src = _norm_path(src_path) if src_path else None
        norm_dst = _norm_path(dst_path) if dst_path else None
        fingerprint = _fingerprint({
            "event_type": event_type, "seq": seq, "op": op,
            "src_path": norm_src, "dst_path": norm_dst, "value": value})
        with self.store.lock:
            replayed = _idem_replay(self.store, scope, idem_key,
                                    fingerprint, "register_mapping")
            if replayed is not None:
                return replayed
            # 幂等冲突：同一 (事件类型,序号,op,src,dst) 已存在（路径先规范化）
            dup = self.store.query_one(
                "SELECT id FROM mappings WHERE sub_id=? AND event_type=? "
                "AND COALESCE(seq,-1)=COALESCE(?, -1) AND op=? "
                "AND COALESCE(src_path,'')=COALESCE(?, '') "
                "AND COALESCE(dst_path,'')=COALESCE(?, '')",
                (sub_id, event_type, seq, op, norm_src, norm_dst))
            if dup:
                result = {"mapping_id": dup["id"], "registered": False,
                          "replayed": True,
                          "reason": "相同映射规则已存在，幂等返回既有规则"}
                if idem_key:
                    self.store.idem_put(scope, idem_key, result,
                                        fingerprint)
                return result
            self.store.begin()
            cur = self.store.conn.execute(
                "INSERT INTO mappings(sub_id, event_type, seq, op, src_path, dst_path, "
                "value, contract_version, created_at, idem_key) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (sub_id, event_type, seq, op,
                 norm_src, norm_dst,
                 json.dumps(value, ensure_ascii=False) if value is not None else None,
                 version, time.time(), idem_key))
            mid = cur.lastrowid
            self.audit("mapping_registered", {
                "mapping_id": mid, "event_type": event_type, "seq": seq,
                "op": op, "src_path": src_path, "dst_path": dst_path,
                "value": value, "contract_version": version}, sub_id)
            result = {"mapping_id": mid, "registered": True}
            if idem_key:
                self.store.idem_put(scope, idem_key, result,
                                    fingerprint)
            self.store.commit()
        return result

    def list_mappings(self, sub_id: str, seq: Optional[int] = None) -> dict:
        if seq is None:
            rows = self.store.query(
                "SELECT * FROM mappings WHERE sub_id=? ORDER BY id", (sub_id,))
        else:
            rows = self.store.query(
                "SELECT * FROM mappings WHERE sub_id=? AND (seq=? OR seq IS NULL) ORDER BY id",
                (sub_id, seq))
        return {"sub_id": sub_id, "mappings": [{
            "id": r["id"], "event_type": r["event_type"], "seq": r["seq"],
            "op": r["op"], "src_path": r["src_path"], "dst_path": r["dst_path"],
            "value": json.loads(r["value"]) if r["value"] is not None else None,
            "contract_version": r["contract_version"],
        } for r in rows]}

    # ------------------------------------------------------------------ #
    # 隔离重试：映射重生成载荷；保留身份与顺序；不重复
    # ------------------------------------------------------------------ #
    def retry(self, sub_id: str, seq: int,
              idem_key: Optional[str] = None) -> dict:
        self._require_sub(sub_id)
        scope = f"retry:{sub_id}:{seq}"
        fingerprint = _fingerprint({"sub_id": sub_id, "seq": seq, "op": "retry"})
        with self.store.lock:
            replayed = _idem_replay_attempt(self.store, scope, idem_key,
                                            fingerprint, "retry")
            if replayed is not None:
                return replayed
            q = self.store.query_one(
                "SELECT * FROM quarantines WHERE sub_id=? AND seq=?", (sub_id, seq))
            if not q:
                raise Reject(404, "quarantine_not_found", {"seq": seq})
            # 顺序保证：必须是队头，前面不能还有 blocked
            head = self.store.query_one(
                "SELECT seq FROM quarantines WHERE sub_id=? AND status='blocked' "
                "ORDER BY seq LIMIT 1", (sub_id,))
            if head and head["seq"] < seq:
                raise Reject(409, "head_of_line_blocked", {
                    "seq": seq, "head_blocked_seq": head["seq"],
                    "reason": "必须保持投递顺序：前面仍有被隔离通知"})
            if q["status"] != "blocked":
                # 已恢复事件的重试是幂等的：返回既有结果，不生成重复通知
                result = {"seq": seq, "replayed": True, "status": q["status"],
                          "notification_id": q["notification_id"],
                          "reason": "该事件已恢复，重试不生成重复通知"}
                if idem_key:
                    self.store.idem_put(scope, idem_key, result,
                                        fingerprint)
                return result

            ev = self.store.query_one(
                "SELECT * FROM events WHERE sub_id=? AND seq=?", (sub_id, seq))
            original = json.loads(ev["raw_payload"])
            # 重试基准：该序号位置当前生效的契约（管理员可能登记映射修复，
            # 也可能在阻断点激活修复版契约）；expected_version 保留隔离时的冻结版本
            current = self._contract_at(sub_id, ev["event_type"], seq)
            if current is None:
                raise Reject(409, "no_governing_contract",
                             {"seq": seq, "reason": "该序号当前没有生效契约，无法重试验证"})
            version = current["version"]
            spec = current["spec"]

            rules = self.store.query(
                "SELECT * FROM mappings WHERE sub_id=? AND event_type=? "
                "AND contract_version=? AND (seq=? OR seq IS NULL) ORDER BY id",
                (sub_id, ev["event_type"], version, seq))

            # 映射只作用于派生载荷；原始审计事件绝不改写（从事件表重读一份作为输入）
            derived, effects, applied = P.apply_mappings_tracked(original, rules)

            normalized, errors, infos = C.check_and_normalize(spec, derived)
            attempt_no = self._next_attempt_no(sub_id, seq)
            prev_digest = self._latest_record_digest(sub_id, seq)
            origin_digest = C.digest(C.canonical_payload(original))
            derived_digest = C.digest(C.canonical_payload(derived))
            if errors:
                # 失败重试同样追加一份说明：逐字段记录失败原因与当时的规则，
                # 绝不覆盖首次隔离说明
                entries = P.build_entries(spec, derived, normalized,
                                          errors, infos, effects=effects)
                self.store.begin()
                self.store.conn.execute(
                    "UPDATE quarantines SET retry_count=retry_count+1 WHERE sub_id=? AND seq=?",
                    (sub_id, seq))
                self._append_attempt_locked(
                    sub_id, seq, q["notification_id"], ev["event_type"],
                    attempt_no, "retry", "retry_failed", version,
                    derived_digest, None, entries, prev_digest,
                    idem_key=idem_key, applied=applied)
                self.audit("retry_failed", {
                    "seq": seq, "attempt_no": attempt_no,
                    "expected_version": version,
                    "applied_mappings": applied, "errors": errors}, sub_id)
                # 失败结果也冻结幂等记录：同键回放重放同一次失败，
                # 绝不重复追加尝试/说明
                if idem_key:
                    self.store.idem_put(scope, idem_key, {
                        "_error": True, "status": 422,
                        "reason": "retry_still_invalid",
                        "detail": {"seq": seq, "attempt_no": attempt_no,
                                   "errors": errors,
                                   "applied_mappings": applied}},
                        fingerprint)
                self.store.commit()
                raise Reject(422, "retry_still_invalid",
                             {"seq": seq, "attempt_no": attempt_no,
                              "errors": errors,
                              "applied_mappings": applied})

            # 恢复成功：复用同一 notification_id（身份不变）、顺序由 pump 保持
            self.store.begin()
            entries = P.build_entries(spec, derived, normalized,
                                      [], infos, effects=effects)
            frozen = C.canonical_payload(normalized)
            self.store.conn.execute(
                "UPDATE notifications SET contract_version=?, frozen_payload=?, "
                "digest=?, validation=?, status='queued' WHERE sub_id=? AND seq=?",
                (version, frozen.decode("utf-8"), C.digest(frozen),
                 json.dumps({"valid": True, "recovered": True,
                             "frozen_at_failure_version": q["expected_version"],
                             "errors": [], "infos": infos}, ensure_ascii=False),
                 sub_id, seq))
            self.store.conn.execute(
                "UPDATE quarantines SET status='recovered', recovered_at=?, "
                "retry_count=retry_count+1 WHERE sub_id=? AND seq=?",
                (time.time(), sub_id, seq))
            self._append_attempt_locked(
                sub_id, seq, q["notification_id"], ev["event_type"],
                attempt_no, "retry", "recovered", version,
                C.digest(frozen), C.digest(frozen), entries, prev_digest,
                idem_key=idem_key, applied=applied)
            self.store.conn.execute(
                "UPDATE subscriptions SET scan_seq=? WHERE id=?", (seq, sub_id))
            self.audit("retry_recovered", {
                "seq": seq, "attempt_no": attempt_no,
                "notification_id": q["notification_id"],
                "contract_version": version, "applied_mappings": applied,
                "digest": C.digest(frozen)}, sub_id)
            self.store.commit()
            # 恢复队头后继续泵送后续被挡住的通知（保持顺序）。
            # 泵送产生的是后续 seq 的首次冻结，不会为本 seq 再生成说明。
            self._pump_locked(sub_id)

        result = {"seq": seq, "status": "recovered",
                  "notification_id": q["notification_id"],
                  "contract_version": version,
                  "attempt_no": attempt_no,
                  "frozen_payload": normalized,
                  "reason": "已保留原投递身份并恢复入队，未生成重复通知"}
        if idem_key:
            with self.store.lock:
                self.store.begin()
                self.store.idem_put(scope, idem_key, result,
                                    fingerprint)
                self.store.commit()
        return result


_MISSING = object()


def _json_leaf_type(val: Any) -> Optional[str]:
    """按 JSON 标量推断契约叶子类型；dict/list/None 不能作为 rename 源。"""
    if isinstance(val, bool):
        return "bool"
    if isinstance(val, int):
        return "int"
    if isinstance(val, float):
        return "number"
    if isinstance(val, str):
        return "string"
    if val is None:
        return "null"
    return None


def _norm_path(p: str) -> str:
    return p if p.startswith("$") else "$." + p.lstrip(".")


def _path_parts(path: str) -> List[str]:
    body = path[1:] if path.startswith("$") else path
    return [p for p in body.split(".") if p]


def _deepcopy(v: Any) -> Any:
    return json.loads(json.dumps(v, ensure_ascii=False))


def _get_path(obj: Any, path: str, default: Any = None) -> Any:
    cur = obj
    for part in _path_parts(path):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _set_path(obj: Any, path: str, value: Any) -> None:
    parts = _path_parts(path)
    cur = obj
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def _pop_path(obj: Any, path: str) -> Any:
    parts = _path_parts(path)
    cur = obj
    for part in parts[:-1]:
        cur = cur[part]
    return cur.pop(parts[-1])
