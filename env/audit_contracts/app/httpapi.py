"""HTTP 接口（标准库 http.server）。

路由总览：
  POST   /subscriptions                                 建订阅
  GET    /subscriptions/{sub}/status                    扫描/稳定水位、生效版本
  POST   /subscriptions/{sub}/events                    事件入库（推进稳定水位）
  POST   /subscriptions/{sub}/scan                      显式推进扫描
  GET    /subscriptions/{sub}/notifications             冻结通知列表

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
from urllib.parse import urlparse

from .service import Reject, Service
from .contracts import ContractError, VersionError


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
                body = self._read_json() if method in ("POST", "PUT") else {}
                handler, kwargs = _match(method, path)
                if handler is None:
                    raise Reject(404, "not_found", {"path": path, "method": method})
                self._send(200, handler(self, body, **kwargs))
            except Reject as e:
                self._send(e.status, {"error": e.reason, **({"detail": e.detail} if e.detail else {})})
            except (ContractError, VersionError) as e:
                self._send(400, {"error": "invalid_contract", "detail": {"message": str(e)}})
            except Exception as e:  # 兜底，避免连接挂死
                self._send(500, {"error": "internal_error", "detail": {"message": str(e)}})

        # -- 端点实现 ------------------------------------------------------ #
        # 订阅 / 事件
        def create_sub(self, body, sub):
            return svc.create_subscription(sub)

        def sub_status(self, body, sub):
            return svc.subscription_status(sub)

        def ingest(self, body, sub):
            if "seq" not in body or "event_type" not in body or "payload" not in body:
                raise Reject(400, "missing_fields",
                             {"required": ["seq", "event_type", "payload"]})
            return svc.ingest_event(sub, int(body["seq"]), body["event_type"],
                                    body["payload"])

        def scan(self, body, sub):
            return svc.scan(sub)

        def notifications(self, body, sub):
            return svc.list_notifications(sub)

        # 契约
        def put_contract(self, body, etype, version):
            if "spec" not in body:
                raise Reject(400, "missing_fields", {"required": ["spec"]})
            return svc.register_contract(etype, version, body["spec"],
                                         self._idempotency_key(body))

        def get_contract(self, body, etype, version):
            return svc.get_contract(etype, version)

        def list_contracts(self, body, etype):
            return svc.list_contracts(etype)

        def diff(self, body, etype):
            if "new_version" not in body:
                raise Reject(400, "missing_fields", {"required": ["new_version"]})
            sub = body.get("sub_id")
            return svc.diff(etype, body.get("old_version"),
                            body["new_version"], sub)

        # 预演
        def start_dryrun(self, body, sub):
            missing = [f for f in ("event_type", "version") if f not in body]
            if missing:
                raise Reject(400, "missing_fields", {"required": missing})
            return svc.start_dry_run(
                sub, body["event_type"], body["version"],
                int(body.get("from_seq", 1)),
                body.get("to_seq"), self._idempotency_key(body))

        def get_dryrun(self, body, sub, drid):
            return svc.get_dry_run(int(drid))

        # 生效 / 撤销
        def activate(self, body, sub):
            missing = [f for f in ("event_type", "version") if f not in body]
            if missing:
                raise Reject(400, "missing_fields", {"required": missing})
            return svc.activate(
                sub, body["event_type"], body["version"],
                body.get("effective_seq"), body.get("expected_version"),
                bool(body.get("expected_absent", False)),
                self._idempotency_key(body))

        def list_activations(self, body, sub):
            return {"sub_id": sub, "activations": svc.active_activation(sub)}

        def revoke(self, body, sub):
            if "event_type" not in body:
                raise Reject(400, "missing_fields", {"required": ["event_type"]})
            return svc.revoke(sub, body["event_type"], self._idempotency_key(body))

        # 隔离 / 重试 / 映射
        def quarantine(self, body, sub):
            return svc.list_quarantine(sub)

        def retry(self, body, sub, seq):
            return svc.retry(sub, int(seq), self._idempotency_key(body))

        def add_mapping(self, body, sub):
            for f in ("event_type", "op"):
                if f not in body:
                    raise Reject(400, "missing_fields", {"required": f})
            return svc.register_mapping(
                sub, body["event_type"], body["op"],
                body.get("src_path"), body.get("dst_path"),
                body.get("value"), body.get("seq"),
                self._idempotency_key(body))

        def list_mappings(self, body, sub):
            return svc.list_mappings(sub, body.get("seq"))

        # 审计
        def sub_audit(self, body, sub):
            return {"sub_id": sub, "history": svc.audit_history(sub)}

        def global_audit(self, body):
            return {"history": svc.audit_history(None)}

    # ------------------------------------------------------------------ #
    # 路由表（method, regex）-> (handler, kwargs 名)
    # ------------------------------------------------------------------ #
    routes: List[Tuple[str, re.Pattern, str, List[str]]] = [
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)$"), "create_sub", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/status$"), "sub_status", ["sub"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/events$"), "ingest", ["sub"]),
        ("POST", re.compile(r"^/subscriptions/(?P<sub>[^/]+)/scan$"), "scan", ["sub"]),
        ("GET",  re.compile(r"^/subscriptions/(?P<sub>[^/]+)/notifications$"), "notifications", ["sub"]),

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
