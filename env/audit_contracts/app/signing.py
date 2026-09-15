"""通知签名流程：HMAC-SHA256，密钥与 kid 持久化、支持轮换。

更正/撤回产生的每一条后续通知（以及对未发送通知的原位替换）都必须在
"当前生效签名密钥" 下对**规范化签名信封**签名；密钥缺失或规范化失败时
显式报错，调用方不得在签名缺失的情况下落库任何处置结果。

签名信封与业务载荷解耦：签名覆盖通知身份、类型、载荷摘要、原事件引用与
关联关系，使"这条通知确实针对那个原事件、载荷未被调换"可以被独立验证。

设计要点：
- 密钥只存服务端（SQLite），永不出现在响应中；
- 当前生效密钥始终是 enabled=1 且序号最大的那一把（轮换原子换旗）；
- 旧密钥保留用于验签，轮换后历史通知仍可验证；
- fail_next_signing 是测试钩子：让下一次签名返回失败，模拟密钥不可用/
  规范化异常，验证"签名失败不改变原通知、不产生任何处置结果"。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple


class SigningError(Exception):
    """签名流程失败（密钥不可用、信封规范化失败等）。"""


SCHEMA = """
CREATE TABLE IF NOT EXISTS signing_keys (
    kid        TEXT PRIMARY KEY,
    key_no     INTEGER NOT NULL UNIQUE,
    secret     TEXT NOT NULL,                 -- 仅服务端持有，绝不外发
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    rotated_at REAL
);
"""


class Signer:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(SCHEMA)
        self._fail_next: Optional[str] = None  # 测试钩子：下一次签名失败原因
        self._ensure_key()

    # -- 密钥管理 ----------------------------------------------------------- #
    def _ensure_key(self) -> None:
        row = self.conn.execute(
            "SELECT COUNT(*) c FROM signing_keys").fetchone()
        if row["c"] == 0:
            self.rotate_key()

    def rotate_key(self) -> str:
        """原子换发新当前密钥：旧密钥失活（保留可验签），新密钥生效。

        不自行管理事务：与所有其它写操作一样在调用方的写事务内执行，
        保证"换密钥"与处置落库要么一起提交要么一起回滚。
        """
        no_row = self.conn.execute(
            "SELECT COALESCE(MAX(key_no),0) m FROM signing_keys").fetchone()
        key_no = no_row["m"] + 1
        kid = f"key-{key_no:03d}"
        now = time.time()
        self.conn.execute(
            "UPDATE signing_keys SET enabled=0, rotated_at=? WHERE enabled=1",
            (now,))
        self.conn.execute(
            "INSERT INTO signing_keys(kid, key_no, secret, enabled, created_at) "
            "VALUES (?,?,?,1,?)",
            (kid, key_no, secrets.token_hex(32), now))
        return kid

    def current_kid(self) -> str:
        row = self.conn.execute(
            "SELECT kid FROM signing_keys WHERE enabled=1 ORDER BY key_no DESC LIMIT 1"
        ).fetchone()
        if not row:  # pragma: no cover - 构造时已保证存在
            raise SigningError("no_active_signing_key")
        return row["kid"]

    def _secret(self, kid: str) -> str:
        row = self.conn.execute(
            "SELECT secret FROM signing_keys WHERE kid=?", (kid,)).fetchone()
        if not row:
            raise SigningError(f"unknown_signing_key: {kid}")
        return row["secret"]

    # -- 测试钩子 ----------------------------------------------------------- #
    def fail_next_signing(self, reason: str = "signing_key_unavailable") -> None:
        self._fail_next = reason

    # -- 信封与签名 --------------------------------------------------------- #
    @staticmethod
    def canonical_envelope(envelope: Dict[str, Any]) -> bytes:
        """签名信封的规范化字节：键排序、无空白、Unicode 不转义。"""
        return json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")

    def build_envelope(self, *, kind: str, notification_id: str,
                       event_type: str, payload_digest: str,
                       sub_id: str, seq: int,
                       relation: Dict[str, Any]) -> Dict[str, Any]:
        """构造待签名信封。

        relation 固定携带关联信息：原通知身份、原事件坐标、处置类型、
        处置请求编号，使后续通知与原通知的关联不可被事后调换。
        """
        return {
            "kind": kind,                          # original / corrected / retraction / correction
            "notification_id": notification_id,
            "sub_id": sub_id,
            "seq": seq,
            "event_type": event_type,
            "payload_digest": payload_digest,
            "relation": relation,
        }

    def sign(self, envelope: Dict[str, Any]) -> Dict[str, str]:
        """对规范化信封用当前生效密钥签名，返回 {kid, alg, signature}。

        任一步骤失败都抛 SigningError，不返回半成品；调用方必须把它视为
        整个处置阶段失败，不得落库任何处置结果。
        """
        if self._fail_next is not None:
            reason, self._fail_next = self._fail_next, None
            raise SigningError(reason)
        try:
            kid = self.current_kid()
            secret = self._secret(kid)
            data = self.canonical_envelope(envelope)
        except SigningError:
            raise
        except Exception as e:  # pragma: no cover - 规范化异常兜底
            raise SigningError(f"envelope_canonicalization_failed: {e}")
        sig = hmac.new(secret.encode("ascii"), data, hashlib.sha256).hexdigest()
        return {"kid": kid, "alg": "HMAC-SHA256",
                "signature": "hmac-sha256:" + sig,
                "signed_at": time.time()}

    def verify(self, envelope: Dict[str, Any], signature_block: Dict[str, Any]
               ) -> Tuple[bool, List[str]]:
        """用签名块中 kid 对应的密钥重算签名（旧密钥已轮换也可验证）。"""
        problems: List[str] = []
        kid = signature_block.get("kid")
        sig = signature_block.get("signature", "")
        alg = signature_block.get("alg")
        if alg != "HMAC-SHA256":
            problems.append(f"unsupported_alg: {alg!r}")
        if not kid:
            problems.append("missing_kid")
            return False, problems
        try:
            secret = self._secret(kid)
        except SigningError as e:
            problems.append(str(e))
            return False, problems
        data = self.canonical_envelope(envelope)
        expect = "hmac-sha256:" + hmac.new(
            secret.encode("ascii"), data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig or ""):
            problems.append("signature_mismatch")
        return not problems, problems
