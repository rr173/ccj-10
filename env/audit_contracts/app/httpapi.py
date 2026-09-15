"""HTTP 接口（标准库 http.server）。

路由总览：
  POST   /subscriptions                                 建订阅
  GET    /subscriptions/{sub}/status                    扫描/稳定水位、生效版本
  POST   /subscriptions/{sub}/events                    事件入库（推进稳定水位）
  POST   /subscriptions/{sub}/scan                      显式推进扫描
  GET    /subscriptions/{sub}/notifications             冻结通知列表
  GET    /subscriptions/{sub}/notifications/{seq}/provenance
         单条通知/隔离事件的逐字段来源说明（?attempt=N 取某次尝试；
         读取时强制完整性校验，损坏返回 422 provenance_integrity_error）
  GET    /subscriptions/{sub}/notifications/{seq}/attempts
         重试尝试列表（只追加，含每次的规则/摘要/失败字段）
  GET    /subscriptions/{sub}/notifications/{seq}/compare?from=1&to=2
         两次尝试逐字段比较：新增/删除/改名/值摘要变化与对应规则

  发送状态机（投递循环驱动；claim 发放令牌，ack/nack 必须出示同一令牌）：
  POST   /subscriptions/{sub}/notifications/{seq}/claim   领取下一条待发原通知
  POST   /subscriptions/{sub}/notifications/{seq}/ack     确认送达 {delivery_token}
  POST   /subscriptions/{sub}/notifications/{seq}/nack    发送失败退回队列 {delivery_token}
  POST   /subscriptions/{sub}/notices/{notice_id}/claim   领取撤回/更正后续通知
  POST   /subscriptions/{sub}/notices/{notice_id}/ack     后续通知确认送达
  POST   /subscriptions/{sub}/notices/{notice_id}/nack    后续通知发送失败
  GET    /subscriptions/{sub}/notices/{notice_id}/verify  重算后续通知信封签名

  处置（管理员对已进入通知链路的事件更正/撤回）：
  POST   /subscriptions/{sub}/events/{seq}/dispositions
         {action: retract|correct, reason, corrected_payload?, event_type?, actor?}
  GET    /subscriptions/{sub}/events/{seq}/dispositions
         按原事件查看原通知状态、处置方式、关联通知、失败原因、完整时间线
  GET    /dispositions/{id}                               单次处置结果
  GET    /subscriptions/{sub}/delivery-queue              原通知+后续通知的统一有序队列

  POST   /signing/rotate                                  轮换当前签名密钥（旧签名仍可验）

  PUT    /contracts/{event_type}/versions/{version}     契约登记（幂等键可选）
  GET    /contracts/{event_type}/versions               版本列表
  GET    /contracts/{event_type}/versions/{version}     契约详情
  POST   /contracts/{event_type}/diff                   字段级差异与兼容性

  POST   /subscriptions/{sub}/dry-runs                  预演（指定版本与范围）
  GET    /subscriptions/{sub}/dry-runs/{id}             预演结果：逐条事件/路径/原因

  POST   /subscriptions/{sub}/activations               生效（门禁+并发互斥+幂等）
  GET    /subscriptions/{sub}/activations               当前生效版本
  POST   /subscriptions/{sub}/revocations                撤销生效

  GET    /subscriptions/{sub}/quarantine                隔离列表（原始摘要/失败字段/当前契约）
  POST   /subscriptions/{sub}/quarantine/{seq}/retry    映射重试（保留身份顺序）

  POST   /subscriptions/{sub}/mappings                  映射登记
  GET    /subscriptions/{sub}/mappings                  映射列表

  GET    /subscriptions/{sub}/audit-history             订阅审计历史
  GET    /audit-history                                 全局审计历史（契约登记等）

所有 POST/PUT 可在 JSON 体中带 "idempotency_key"。
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs as urllib_parse_qs

from .service import Reject, Service
from .contracts import ContractError, VersionError


def _require_token(body: dict) -> str:
    token = body.get("delivery_token")
    if not token:
        raise Reject(400, "missing_fields", {"required": ["delivery_token"]})
    return token


def _make_handler(svc: Service) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = "AuditContractGate/1.0"

        def log_message(self, *args):  # 静默常规访问日志
            pass

        # -- 基础 IO ------------------------------------------------------- #
        def _send(self, status: int, body: Any) -> None:
            data = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError
                return body
            except Exception:
                raise Reject(400, "invalid_json", {"reason": "请求体必须是 JSON 对象"})

        def _idempotency_key(self, body: dict) -> Optional[str]:
            return body.get("idempotency_key")

        # -- 路由 ---------------------------------------------------------- #
        def do_GET(self): self._route("GET")
        def do_POST(self): self._route("POST")
        def do_PUT(self): self._route("PUT")

        def _route(self, method: str) -> None:
            try:
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                query = urllib_parse_qs(parsed.query)
                body = self._read_json() if method in ("POST", "PUT") else {}
                handler, kwargs = _match(method, path)
                if handler is None:
                    raise Reject(404, "not_found", {"path": path, "method": method})
                self._send(200, handler(self, body, query=query, **kwargs))
            except Reject as e:
                self._send(e.status, {"error": e.reason, **({"detail": e.detail} if e.detail else {})})
            except (ContractError, VersionError) as e:
                self._send(400, {"error": "invalid_contract", "detail": {"message": str(e)}})
            except Exception as e:  # 兜底，避免连接挂死
                self._send(500, {"error": "internal_error", "detail": {"message": str(e)}})

        # -- 端点实现 ------------------------------------------------------ #
        # 订阅 / 事件
        def create_sub(self, body, sub, query=None):
            return svc.create_subscription(sub)

        def sub_status(self, body, sub, query=None):
            return svc.subscription_status(sub)

        def ingest(self, body, sub, query=None):
            if "seq" not in body or "event_type" not in body or "payload" not in body:
                raise Reject(400, "missing_fields",
                             {"required": ["seq", "event_type", "payload"]})
            return svc.ingest_event(sub, int(body["seq"]), body["event_type"],
                                    body["payload"])

        def scan(self, body, sub, query=None):
            return svc.scan(sub)

        def notifications(self, body, sub, query=None):
            return svc.list_notifications(sub)

        def provenance(self, body, sub, seq, query):
            attempt = query.get("attempt", [None])[0]
            try:
                no = int(attempt) if attempt is not None else None
            except ValueError:
                raise Reject(400, "invalid_query_param",
                             {"param": "attempt", "value": attempt})
            return svc.get_provenance(sub, int(seq), no)

        def attempts(self, body, sub, seq, query):
            return svc.list_retry_attempts(sub, int(seq))

        def compare(self, body, sub, seq, query):
            def qint(name):
                v = query.get(name, [None])[0]
                if v is None:
                    return None  # 缺省：比较最后两次尝试
                try:
                    return int(v)
                except ValueError:
                    raise Reject(400, "invalid_query_param",
                                 {"param": name, "value": v})
            return svc.compare_attempts(sub, int(seq), qint("from"), qint("to"))

        # 契约
        def put_contract(self, body, etype, version, query=None):
            if "spec" not in body:
                raise Reject(400, "missing_fields", {"required": ["spec"]})
            return svc.register_contract(etype, version, body["spec"],
                                         self._idempotency_key(body))

        def get_contract(self, body, etype, version, query=None):
            return svc.get_contract(etype, version)

        def list_contracts(self, body, etype, query=None):
            return svc.list_contracts(etype)

        def diff(self, body, etype, query=None):
            if "new_version" not in body:
                raise Reject(400, "missing_fields", {"required": ["new_version"]})
            sub = body.get("sub_id")
            return svc.diff(etype, body.get("old_version"),
                            body["new_version"], sub)

        # 预演
        def start_dryrun(self, body, sub, query=None):
            missing = [f for f in ("event_type", "version") if f not in body]
            if missing:
                raise Reject(400, "missing_fields", {"required": missing})
            return svc.start_dry_run(
                sub, body["event_type"], body["version"],
                int(body.get("from_seq", 1)),
                body.get("to_seq"), self._idempotency_key(body))

        def get_dryrun(self, body, sub, drid, query=None):
            return svc.get_dry_run(int(drid))

        # 生效 / 撤销
        def activate(self, body, sub, query=None):
            missing = [f for f in ("event_type", "version") if f not in body]
            if missing:
                raise Reject(400, "missing_fields", {"required": missing})
            return svc.activate(
                sub, body["event_type"], body["version"],
                body.get("effective_seq"), body.get("expected_version"),
                bool(body.get("expected_absent", False)),
                self._idempotency_key(body))

        def list_activations(self, body, sub, query=None):
            return {"sub_id": sub, "activations": svc.active_activation(sub)}

        def revoke(self, body, sub, query=None):
            if "event_type" not in body:
                raise Reject(400, "missing_fields", {"required": ["event_type"]})
            return svc.revoke(sub, body["event_type"], self._idempotency_key(body))

        # 隔离 / 重试 / 映射
        def quarantine(self, body, sub, query=None):
            return svc.list_quarantine(sub)

        def retry(self, body, sub, seq, query=None):
            return svc.retry(sub, int(seq), self._idempotency_key(body))

        def add_mapping(self, body, sub, query=None):
            for f in ("event_type", "op"):
                if f not in body:
                    raise Reject(400, "missing_fields", {"required": f})
            return svc.register_mapping(
                sub, body["event_type"], body["op"],
                body.get("src_path"), body.get("dst_path"),
                body.get("value"), body.get("seq"),
                self._idempotency_key(body))

        def list_mappings(self, body, sub, query=None):
            return svc.list_mappings(sub, body.get("seq"))

        # 审计
        def sub_audit(self, body, sub, query=None):
            return {"sub_id": sub, "history": svc.audit_history(sub)}

        def global_audit(self, body, query=None):
            return {"history": svc.audit_history(None)}

        # 发送状态机
        def claim(self, body, sub, seq, query=None):
            return svc.claim_notification(
                sub, int(seq), bool(body.get("force_reclaim", False)))

        def ack(self, body, sub, seq, query=None):
            return svc.ack_notification(sub, int(seq), _require_token(body))

        def nack(self, body, sub, seq, query=None):
            return svc.nack_notification(sub, int(seq), _require_token(body))

        def claim_notice(self, body, sub, nid, query=None):
            return svc.claim_notice(
                sub, nid, bool(body.get("force_reclaim", False)))

        def ack_notice(self, body, sub, nid, query=None):
            return svc.ack_notice(sub, nid, _require_token(body))

        def nack_notice(self, body, sub, nid, query=None):
            return svc.nack_notice(sub, nid, _require_token(body))

        def verify_notice(self, body, sub, nid, query=None):
            return svc.verify_notice_signature(sub, nid)

        # 处置
        def create_disposition(self, body, sub, seq, query=None):
            for f in ("action", "reason"):
                if f not in body:
                    raise Reject(400, "missing_fields",
                                 {"required": ["action", "reason"]})
            return svc.create_disposition(
                sub_id=sub, seq=int(seq), action=body["action"],
                reason=body["reason"],
                corrected_payload=body.get("corrected_payload"),
                event_type=body.get("event_type"),
                actor=body.get("actor"),
                idem_key=self._idempotency_key(body))

        def event_dispositions(self, body, sub, seq, query=None):
            return svc.event_dispositions(sub, int(seq))

        def get_disposition(self, body, did, query=None):
            return svc.get_disposition(did)

        def delivery_queue(self, body, sub, query=None):
            return svc.delivery_queue(sub)

        # 签名密钥轮换
        def rotate_signing(self, body, query=None):
            return svc.rotate_signing_key(self._idempotency_key(body))

    # ------------------------------------------------------------------ #
    # 路由表（method, regex）-> (handler, kwargs 名)
    # ------------------------------------------------------------------ #
    routes: List[Tuple[str, re.Pattern, str, List[str]]] = [
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)$"), "create_sub", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/status$"), "sub_status", ["sub"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/events$"), "ingest", ["sub"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/scan$"), "scan", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications$"), "notifications", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications/(?P<seq>\d+)/provenance$"), "provenance", ["sub", "seq"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications/(?P<seq>\d+)/attempts$"), "attempts", ["sub", "seq"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications/(?P<seq>\d+)/compare$"), "compare", ["sub", "seq"]),

        # 发送状态机
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications/(?P<seq>\d+)/claim$"),
         "claim", ["sub", "seq"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications/(?P<seq>\d+)/ack$"),
         "ack", ["sub", "seq"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications/(?P<seq>\d+)/nack$"),
         "nack", ["sub", "seq"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notices/(?P<nid>[^/]+)/claim$"),
         "claim_notice", ["sub", "nid"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notices/(?P<nid>[^/]+)/ack$"),
         "ack_notice", ["sub", "nid"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notices/(?P<nid>[^/]+)/nack$"),
         "nack_notice", ["sub", "nid"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notices/(?P<nid>[^/]+)/verify$"),
         "verify_notice", ["sub", "nid"]),

        # 处置
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/events/(?P<seq>\d+)/dispositions$"),
         "create_disposition", ["sub", "seq"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/events/(?P<seq>\d+)/dispositions$"),
         "event_dispositions", ["sub", "seq"]),
        ("GET",  re.compile(r"^/dispositions/(?P<did>[^/]+)$"),
         "get_disposition", ["did"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/delivery-queue$"),
         "delivery_queue", ["sub"]),

        ("POST", re.compile(r"^/signing/rotate$"),
         "rotate_signing", []),

        ("PUT",  re.compile(r"^/contracts/(?P<etype>[^/]+)/versions/(?P<version>[^/]+)$"),
         "put_contract", ["etype", "version"]),
        ("GET",  re.compile(r"^/contracts/(?P<etype>[^/]+)/versions/(?P<version>[^/]+)$"),
         "get_contract", ["etype", "version"]),
        ("GET",  re.compile(r"^/contracts/(?P<etype>[^/]+)/versions$"),
         "list_contracts", ["etype"]),
        ("POST", re.compile(r"^/contracts/(?P<etype>[^/]+)/diff$"), "diff", ["etype"]),

        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/dry-runs$"),
         "start_dryrun", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/dry-runs/(?P<drid>\d+)$"),
         "get_dryrun", ["sub", "drid"]),

        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/activations$"),
         "activate", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/activations$"),
         "list_activations", ["sub"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/revocations$"),
         "revoke", ["sub"]),

        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/quarantine$"),
         "quarantine", ["sub"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/quarantine/(?P<seq>\d+)/retry$"),
         "retry", ["sub", "seq"]),

        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/mappings$"),
         "add_mapping", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/mappings$"),
         "list_mappings", ["sub"]),

        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/audit-history$"),
         "sub_audit", ["sub"]),
        ("GET",  re.compile(r"^/audit-history$"), "global_audit", []),
    ]

    def _match(method, path):
        for m, rx, name, kw_names in routes:
            if m != method:
                continue
            mo = rx.match(path)
            if mo:
                return getattr(Handler, name), {k: mo.group(k) for k in kw_names}
        return None, {}

    return Handler


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8080) -> Tuple[ThreadingHTTPServer, Service]:
    svc = Service(db_path)
    httpd = ThreadingHTTPServer((host, port), _make_handler(svc))
    return httpd, svc
