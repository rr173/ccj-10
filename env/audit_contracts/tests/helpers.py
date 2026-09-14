"""测试辅助：临时文件 HTTP 服务、HTTP 客户端、示例契约。零第三方依赖。"""

import json
import os
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
import unittest
from typing import Optional

from app.httpapi import serve


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Client:
    def __init__(self, base: str):
        self.base = base

    def call(self, method: str, path: str, body: Optional[dict] = None,
             expect: Optional[int] = 200):
        data = json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.base + path,
            data=data if method != "GET" else None,
            method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                parsed = json.loads(resp.read().decode("utf-8"))
                status = resp.status
        except urllib.error.HTTPError as e:
            parsed = json.loads(e.read().decode("utf-8"))
            status = e.code
        if expect is not None:
            assert status == expect, f"{method} {path} -> {status}: {parsed}"
        return status, parsed

    def get(self, path, expect=200):
        return self.call("GET", path, None, expect)

    def post(self, path, body=None, expect=200):
        return self.call("POST", path, body, expect)

    def put(self, path, body=None, expect=200):
        return self.call("PUT", path, body, expect)


class HttpTestCase(unittest.TestCase):
    """每个用例一个临时数据库 + HTTP 服务；支持同库重启。"""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.db_path)
        self._start()

    def _start(self, interrupt: bool = False):
        self.httpd, self.svc = serve(self.db_path, port=free_port())
        self.svc.dryrun_interrupt = interrupt
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.c = Client(f"http://127.0.0.1:{self.httpd.server_address[1]}")

    def restart(self, interrupt: bool = False):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.svc.store.close()
        self.thread.join(timeout=2)
        time.sleep(0.05)
        self._start(interrupt)

    def tearDown(self):
        try:
            if not getattr(self, "_server_stopped", False):
                self.httpd.shutdown()
            self.httpd.server_close()
            self.svc.store.close()
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(self.db_path + suffix)
                except OSError:
                    pass

    def register(self, etype, version, spec, expect=200, **kw):
        return self.c.put(f"/contracts/{etype}/versions/{version}",
                          {"spec": spec, **kw}, expect)

    def ingest(self, sub, seq, etype, payload, expect=200):
        return self.c.post(f"/subscriptions/{sub}/events",
                           {"seq": seq, "event_type": etype, "payload": payload},
                           expect)

    def dryrun(self, sub, etype, version, from_seq=1, to_seq=None,
               expect=200, key=None):
        body = {"event_type": etype, "version": version,
                "from_seq": from_seq, "idempotency_key": key}
        if to_seq is not None:
            body["to_seq"] = to_seq
        return self.c.post(f"/subscriptions/{sub}/dry-runs", body, expect)


# --------------------------------------------------------------------------- #
# 示例契约
# --------------------------------------------------------------------------- #
SPEC_V1 = {
    "type": "object", "unknown_policy": "strict",
    "properties": {
        "actor": {"type": "string"},
        "action": {"type": "string", "enum": ["login", "logout"]},
        "count": {"type": "int", "required": False},
        "note": {"type": "string", "required": False, "ignorable": True},
        "meta": {"type": "object", "required": False, "unknown_policy": "allow",
                 "properties": {"ip": {"type": "string", "required": False}}},
    },
}

# 兼容升级：新增可选字段、放宽未知字段策略、扩大枚举
SPEC_V2_COMPAT = {
    "type": "object", "unknown_policy": "strip",
    "properties": {
        "actor": {"type": "string"},
        "action": {"type": "string", "enum": ["login", "logout", "sudo"]},
        "count": {"type": "int", "required": False},
        "reason": {"type": "string", "required": False},
        "note": {"type": "string", "required": False, "ignorable": True},
        "meta": {"type": "object", "required": False, "unknown_policy": "allow",
                 "properties": {"ip": {"type": "string", "required": False}}},
    },
}

# 破坏性变更：actor 类型不兼容、删除 count、枚举收窄、新增必填 reason
SPEC_V2_BREAK = {
    "type": "object", "unknown_policy": "strict",
    "properties": {
        "actor": {"type": "int"},
        "action": {"type": "string", "enum": ["login"]},
        "reason": {"type": "string"},
    },
}
