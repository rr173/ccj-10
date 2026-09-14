"""审计变更订阅与可靠通知（audit change subscription & reliable notification）。

在租约、审计事件、因果索引、归档、证据包与版本发布能力之上，管理员可以
为**资源**、**委托凭证**、**因果索引**或**发布版本**创建订阅：指定事件
范围（过滤条件）、起始历史序号与回调地址。系统保存订阅状态、过滤条件与
当前位置，按全局历史序号为每个订阅**严格顺序**地投递通知。

可靠性不变量
============
1. **稳定历史视图**：入队只从只增的 ``lease_events`` 历史读取（SELECT），
   绝不修改源审计历史、租约、委托、索引、归档、证据包或发布计划。订阅
   处理只写 ``audit_subscriptions`` / ``audit_subscription_deliveries``
   两张自有表。
2. **严格顺序、不跳号**：每个订阅的游标 ``position_seq`` 单调推进；
   队首存在 ``inflight`` / ``awaiting_confirm`` / ``dead_letter`` /
   ``pending（退避未到点）`` 的投递时，后面的事件一律不投递。匹配事件
   才生成通知（未匹配事件只推进游标，不产生投递记录）。
3. **一次确认**：同一事件对同一订阅只有一行投递记录
   （``(subscription_id, event_seq)`` 唯一 + INSERT OR IGNORE）。确认
   是条件 UPDATE（只有非终态行才会变成 confirmed），重复确认幂等回放
   但绝不推进两次。
4. **签名**：每次通知携带事件序号、对象标识、事件类型、内容摘要与订阅
   序号，载荷经规范化 JSON 后用订阅密钥做 HMAC-SHA256 签名；显式确认
   必须携带正确签名，签名错误的确认不能改变任何状态。
5. **失败重试与死信**：回调连接失败、超时或返回非成功状态都记录尝试
   次数、失败原因与下次重试时间，按指数退避重试；超过上限进入
   ``dead_letter`` 并挡住后续投递（不跳过）。管理员可以查看失败原因并
   重新放回队列（复位尝试次数，立即重试）。
6. **取消与迟到响应**：取消后不会再投递新通知；进行中回调的迟到响应被
   忽略（按订阅当前状态判定），回调方即便返回成功也不会再发后续通知。
7. **并发与重启**：认领是带唯一 ``dispatch_token`` 的条件 UPDATE，同一
   行投递不可能被两个投递器同时认领；服务重启把残留的 ``inflight`` /
   ``awaiting_confirm`` 行回收为 pending（不增加尝试次数），崩溃不会
   造成重复确认、乱序或丢失。

幂等创建
========
``idempotency_key`` 全局唯一：同键重复提交返回同一订阅（200 +
``replayed``）；同键换作用域/对象/过滤条件/回调地址/起始序号 → 409
``subscription_id_conflict``，响应给出首个差异字段与双方值。

重新开始
========
``restart-from`` 把游标重置到指定序号：已有投递记录全部保留作为历史，
未确认的旧行复位为 pending（不重置已确认行，已确认事件不会重复确认），
并立即重新扫描入队。已发生过版本切换（含存在预创建版本）的订阅为避免
跨版本重放一律 409 拒绝（版本不可变，需要新回调/过滤请创建下一版本）。

订阅版本切换
============
管理员可以为一个**活动**订阅预先创建下一版本（新回调地址、新事件过滤
条件、生效历史序号 ``effective_seq``，含），随后原子激活：

1. **原子切换**：激活在单个写事务内完成——旧版本置 ``superseded``、
   新版本置 ``active``、订阅的当前回调/过滤/密钥/版本号/游标整体切换。
   事务要么全成要么全不成，崩溃/中断后从已保存状态继续，不留半切换。
2. **进行中投递按旧版本收尾**：切换前已入队/认领中的投递行冻结了当时
   版本的回调地址、密钥、载荷与订阅序号，继续按旧版本签名与订阅序号
   投递和确认；迟到响应只匹配本行认领令牌，绝不被新版本改写。
3. **生效序号之后只进新版本**：旧版本扫描上界钉在 ``effective_seq-1``，
   新版本从 ``effective_seq`` 开始扫描。两个版本在投递表内按全局
   event_seq 共享同一条严格顺序队列，队首（最小 event_seq 非终态行）
   约束保证旧版本未确认通知与新版本通知**互不越过**；
   ``(subscription_id, event_seq)`` 唯一保证同一事件绝不重复，未匹配
   事件也各自推进版本游标，保证不丢事件。
4. **每个版本独立的订阅序号**：通知载荷带 ``version_no``，订阅序号在
   版本内从 1 连续编号并用该版本自己的密钥签名。
5. **幂等**：创建/激活/取消/死信重试都要幂等键。同一幂等键换回调地址、
   过滤条件、生效序号或目标订阅/版本 → 409 明确冲突（给出首个差异）；
   ``effective_seq`` 越过当前稳定历史上界 → 416 拒绝且原订阅不变。
6. **审计**：版本创建、激活、取消、重试与所有拒绝原因都只追加进该订阅
   自己的审计历史（``audit_subscription_events``），绝不改写租约、
   委托、``lease_events`` 原始审计事件或已有投递记录。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from .archive import ArchiveError, canonical_json
from .audit import AuditBadRequest, event_dict
from .causal import event_passes_filters, normalize_filters

# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class SubscriptionError(ArchiveError):
    code = "subscription_error"


class SubscriptionNotFound(SubscriptionError):
    code = "subscription_not_found"
    status = 404


class DeliveryNotFound(SubscriptionError):
    code = "delivery_not_found"
    status = 404


class SubscriptionIdConflict(SubscriptionError):
    """同一幂等键被作用域/对象/过滤/回调/起始序号不同的请求占用（409）。"""

    code = "subscription_id_conflict"
    status = 409


class SubscriptionBadState(SubscriptionError):
    """当前订阅状态不允许该操作（暂停/恢复/取消/重新开始的前提，409）。"""

    code = "subscription_bad_state"
    status = 409


class DeliveryBadState(SubscriptionError):
    """投递行当前状态不允许该操作（确认/重新放回的前提，409）。"""

    code = "delivery_bad_state"
    status = 409


class SubscriptionRangeError(SubscriptionError):
    """起始序号越过创建时刻的稳定视图上界（416）。"""

    code = "subscription_seq_out_of_range"
    status = 416


class InvalidSignature(SubscriptionError):
    """确认携带的签名与服务端重算值不一致（401），不改变任何状态。"""

    code = "invalid_signature"
    status = 401


class SubscriptionVersionNotFound(SubscriptionError):
    """订阅版本不存在（404）。"""

    code = "subscription_version_not_found"
    status = 404


class SubscriptionVersionConflict(SubscriptionError):
    """版本操作的幂等键被参数不同的请求占用（409）。"""

    code = "subscription_version_conflict"
    status = 409


class SubscriptionVersionBadState(SubscriptionError):
    """版本/订阅当前状态不允许该版本操作（409）。"""

    code = "subscription_version_bad_state"
    status = 409


class SubscriptionVersionRangeError(SubscriptionError):
    """生效序号越过当前稳定历史上界（416），原订阅不改变。"""

    code = "subscription_version_seq_out_of_range"
    status = 416


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SCOPE_RESOURCE = "resource"
SCOPE_CREDENTIAL = "credential"
SCOPE_CAUSAL_INDEX = "causal_index"
SCOPE_RELEASE = "release"
SCOPES = (SCOPE_RESOURCE, SCOPE_CREDENTIAL,
          SCOPE_CAUSAL_INDEX, SCOPE_RELEASE)

SUB_ACTIVE = "active"
SUB_PAUSED = "paused"
SUB_CANCELLED = "cancelled"
SUB_STATUSES = (SUB_ACTIVE, SUB_PAUSED, SUB_CANCELLED)

D_PENDING = "pending"
D_INFLIGHT = "inflight"
D_AWAITING = "awaiting_confirm"
D_CONFIRMED = "confirmed"
D_DEAD = "dead_letter"
D_DISCARDED = "discarded"
# 非终态：还需要（或可能需要）投递/确认
D_OPEN = (D_PENDING, D_INFLIGHT, D_AWAITING)
D_TERMINAL = (D_CONFIRMED, D_DEAD, D_DISCARDED)

# 订阅版本状态
V_PREPARED = "prepared"        # 预创建，等待激活
V_ACTIVE = "active"            # 当前生效版本
V_SUPERSEDED = "superseded"    # 已被下一版本替换，只做收尾投递
V_CANCELLED = "cancelled"      # 预创建版本被取消，永不生效
V_OPEN = (V_PREPARED, V_ACTIVE, V_SUPERSEDED)

# 版本操作幂等日志中的操作类型
OP_ACTIVATE = "activate"
OP_CANCEL = "cancel"
OP_RETRY_DEAD = "retry_dead_letters"

# 回调 2xx 中，只有 202 表示"先收下，稍后显式签名确认"
ACK_PENDING_STATUS = 202
# 回调 410 Gone：接收方永久拒收，直接死信，不再退避重试
PERMANENT_REJECT_STATUS = 410

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_BACKOFF_MS = 1_000
DEFAULT_MAX_BACKOFF_MS = 300_000
# inflight/awaiting 认领租约：超过此时长视为投递器崩溃，回收为 pending
DEFAULT_CLAIM_LEASE_MS = 60_000

SCAN_BATCH = 500

SIGNATURE_VERSION = "v1"
SIGNATURE_ALGORITHM = "HMAC-SHA256"

# 签名验证结果（与 key_rotation 模块共享取值；无轮换时确认恒为 ok）
V_OK = "ok"


def new_secret() -> str:
    """生成订阅签名密钥：32 字节随机值的十六进制表示。"""
    return secrets.token_hex(32)


def sign_payload(secret: str, payload: dict[str, Any]) -> str:
    """对规范化通知载荷做 HMAC-SHA256，返回十六进制签名。"""
    body = canonical_json(payload).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, payload: dict[str, Any],
                     signature: str | None) -> bool:
    if not isinstance(signature, str) or not signature:
        return False
    expected = sign_payload(secret, payload)
    return hmac.compare_digest(expected, signature.strip())


def backoff_delay_ms(attempts: int, *, base_ms: int,
                     max_ms: int) -> int:
    """指数退避：第 n 次失败后等待 base * 2^(n-1)，封顶 max。"""
    n = max(1, int(attempts))
    delay = int(base_ms) * (2 ** (n - 1))
    return min(delay, int(max_ms))


# ---------------------------------------------------------------------------
# 默认 HTTP 投递器（urllib，无第三方依赖）
# ---------------------------------------------------------------------------


class HttpDeliveryResult:
    def __init__(self, *, status: int | None = None,
                 ok: bool = False, ack_pending: bool = False,
                 permanent_reject: bool = False,
                 error: str | None = None):
        self.status = status
        self.ok = ok
        self.ack_pending = ack_pending
        self.permanent_reject = permanent_reject
        self.error = error


# 可注入的投递器：(callback_url, payload, signature) -> HttpDeliveryResult
DeliveryCallable = Callable[[str, dict[str, Any], str], HttpDeliveryResult]


def default_http_delivery(url: str, payload: dict[str, Any],
                          signature: str, *, timeout_s: float = 5.0
                          ) -> HttpDeliveryResult:
    """同步 POST JSON 通知。

    200/201/204 视为成功确认；202 视为待显式确认；410 永久拒收（直接
    死信）；其余 4xx/5xx 与连接失败/超时一样按退避重试。
    """
    body = canonical_json(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Subscription-Id": payload["subscription_id"],
            "X-Subscription-Seq": str(payload["subscription_seq"]),
            "X-Event-Seq": str(payload["event_seq"]),
            "X-Signature-Algorithm": SIGNATURE_ALGORITHM,
            "X-Signature": signature,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = int(resp.status)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        kind = ("timeout" if "timed out" in str(reason)
                else "connection_error")
        return HttpDeliveryResult(
            error=f"{kind}: {type(exc).__name__}: {reason}")
    if status == ACK_PENDING_STATUS:
        return HttpDeliveryResult(status=status, ack_pending=True)
    if status == PERMANENT_REJECT_STATUS:
        return HttpDeliveryResult(status=status, permanent_reject=True)
    if 200 <= status < 300:
        return HttpDeliveryResult(status=status, ok=True)
    return HttpDeliveryResult(status=status,
                              error=f"http_status_{status}")


# ---------------------------------------------------------------------------
# 通知摘要
# ---------------------------------------------------------------------------


def event_summary(ev_row) -> dict[str, Any]:
    """从历史事件行生成通知中的对象标识、事件类型与内容摘要。"""
    kind = ev_row["event"]
    detail = ev_row["detail"]
    return {
        "event_type": kind,
        "outcome": ev_row["outcome"],
        "holder": ev_row["holder"],
        "peer": ev_row["peer"],
        "resource": ev_row["resource"],
        "generation": ev_row["generation"],
        "credential_id": ev_row["credential_id"],
        "lease_id": ev_row["lease_id"],
        "detail": detail,
        "text": _summary_text(kind, ev_row["outcome"], ev_row["holder"],
                              ev_row["peer"], detail),
        "digest_sha256": hashlib.sha256(
            canonical_json({
                "seq": ev_row["seq"], "event": kind,
                "outcome": ev_row["outcome"],
                "holder": ev_row["holder"], "peer": ev_row["peer"],
                "resource": ev_row["resource"],
                "generation": ev_row["generation"],
                "credential_id": ev_row["credential_id"],
                "lease_id": ev_row["lease_id"], "detail": detail,
                "value": ev_row["value"] if "value" in ev_row.keys()
                else None,
            }).encode("utf-8")).hexdigest(),
    }


def _summary_text(kind: str, outcome: str, holder: str, peer,
                  detail: str | None) -> str:
    verdict = "成功" if outcome == "ok" else "被拒绝"
    who = f"（对方 {peer}）" if peer else ""
    return f"{holder} 的 {kind} 事件{verdict}{who}：{detail or '无补充信息'}"


# ---------------------------------------------------------------------------
# 订阅管理器
# ---------------------------------------------------------------------------


class SubscriptionManager:
    """订阅的创建、扫描入队、投递、确认、重试、死信管理与历史查询。

    拥有独立 SQLite 连接与进程锁（与 Store 的连接共享同一 WAL 数据库，
    只 SELECT 租约侧的表），因此回调等慢 IO 不会阻塞租约写入。回调执行
    在数据库事务之外；认领/记录结果都是短事务，且全部以
    ``dispatch_token`` / 订阅状态为条件，迟到响应不会改错状态。
    """

    def __init__(
        self,
        store: Any,
        *,
        deliver: DeliveryCallable | None = None,
        base_backoff_ms: int = DEFAULT_BASE_BACKOFF_MS,
        max_backoff_ms: int = DEFAULT_MAX_BACKOFF_MS,
        claim_lease_ms: int = DEFAULT_CLAIM_LEASE_MS,
        key_rotation: Any = None,
    ):
        self._store = store
        # 签名密钥轮换管理器（可选，正交于版本切换）。由 app 装配后通过
        # attach_key_rotation 注入；为 None 时签名/确认完全沿用版本冻结
        # 密钥（轮换特性引入前的历史行为）。
        self._key_rotation = key_rotation
        import sqlite3 as _sqlite3

        self._lock = threading.RLock()
        # autocommit 模式（isolation_level=None）：只读 SELECT 不会开启
        # 长事务，长连接不会停在旧 WAL 快照而看不到别的连接（写入事务在
        # Store 连接上提交）的新数据；所有写操作显式 BEGIN IMMEDIATE。
        self._conn = _sqlite3.connect(store_db_path(store),
                                      check_same_thread=False,
                                      isolation_level=None)
        self._conn.row_factory = _sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        # 表结构通常由 Store 初始化时创建；此处幂等兜底，保证订阅管理器
        # 独立连接场景也可用（IF NOT EXISTS 不影响既有表）
        self._ensure_schema()

        self.base_backoff_ms = int(base_backoff_ms)
        self.max_backoff_ms = int(max_backoff_ms)
        self.claim_lease_ms = int(claim_lease_ms)
        if deliver is None:
            self._deliver_cb = self._default_deliver
        else:
            self._deliver_cb = deliver
        # 构造即恢复：上一个进程崩溃时残留的 inflight/awaiting 行立即回收
        # （INSERT/UPDATE 幂等，与是否启动后台 worker 无关）
        self.recover_stale_claims(lease_ms=0)

    def _ensure_schema(self) -> None:
        """幂等创建订阅自有表（与 Store.SCHEMA 中定义保持一致）。"""
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_subscriptions (
                subscription_id   TEXT PRIMARY KEY,
                idempotency_key   TEXT NOT NULL,
                scope             TEXT NOT NULL,
                resource          TEXT NOT NULL DEFAULT '',
                credential_id     TEXT NOT NULL DEFAULT '',
                index_id          TEXT NOT NULL DEFAULT '',
                release_id        TEXT NOT NULL DEFAULT '',
                callback_url      TEXT NOT NULL,
                secret            TEXT NOT NULL,
                filters_json      TEXT NOT NULL,
                start_seq         INTEGER NOT NULL,
                position_seq      INTEGER NOT NULL,
                sub_seq           INTEGER NOT NULL DEFAULT 0,
                snapshot_seq      INTEGER NOT NULL,
                current_version   INTEGER NOT NULL DEFAULT 1,
                pending_version   INTEGER,
                status            TEXT NOT NULL DEFAULT 'active',
                blocked           INTEGER NOT NULL DEFAULT 0,
                max_attempts      INTEGER NOT NULL DEFAULT 5,
                ack_required      INTEGER NOT NULL DEFAULT 0,
                error             TEXT,
                created_at_ms     INTEGER NOT NULL,
                updated_at_ms     INTEGER NOT NULL,
                cancelled_at_ms   INTEGER
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_subscription_idem
                ON audit_subscriptions(idempotency_key);
            CREATE INDEX IF NOT EXISTS idx_subscription_status
                ON audit_subscriptions(status, position_seq);
            CREATE TABLE IF NOT EXISTS audit_subscription_deliveries (
                delivery_id        TEXT PRIMARY KEY,
                subscription_id    TEXT NOT NULL,
                event_seq          INTEGER NOT NULL,
                subscription_seq   INTEGER NOT NULL,
                version_no         INTEGER NOT NULL DEFAULT 1,
                status             TEXT NOT NULL DEFAULT 'pending',
                attempts           INTEGER NOT NULL DEFAULT 0,
                next_retry_at_ms   INTEGER NOT NULL DEFAULT 0,
                claimed_at_ms      INTEGER,
                dispatch_token     TEXT,
                last_error         TEXT,
                dead_letter_reason TEXT,
                payload_json       TEXT NOT NULL,
                signature          TEXT,
                confirmed_at_ms    INTEGER,
                created_at_ms      INTEGER NOT NULL,
                updated_at_ms      INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_sub_event
                ON audit_subscription_deliveries(subscription_id, event_seq);
            CREATE INDEX IF NOT EXISTS idx_delivery_due
                ON audit_subscription_deliveries(status, next_retry_at_ms);
            CREATE INDEX IF NOT EXISTS idx_delivery_sub_order
                ON audit_subscription_deliveries(subscription_id, event_seq);
            """)
        # 旧库增量列/索引（IF NOT EXISTS 不影响新库）
        cols = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(audit_subscription_deliveries)").fetchall()}
        if "version_no" not in cols:
            self._conn.execute(
                "ALTER TABLE audit_subscription_deliveries "
                "ADD COLUMN version_no INTEGER NOT NULL DEFAULT 1")
        # 签名密钥轮换特性增量列：投递行冻结的签名密钥代际。NULL（含轮换
        # 特性前的旧行）表示回退到版本冻结密钥。
        if "signing_key_id" not in cols:
            self._conn.execute(
                "ALTER TABLE audit_subscription_deliveries "
                "ADD COLUMN signing_key_id TEXT")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_delivery_version "
            "ON audit_subscription_deliveries(subscription_id, "
            "version_no, event_seq)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_delivery_signkey "
            "ON audit_subscription_deliveries(subscription_id, signing_key_id)")
        scolumns = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(audit_subscriptions)").fetchall()}
        if "current_version" not in scolumns:
            self._conn.execute(
                "ALTER TABLE audit_subscriptions "
                "ADD COLUMN current_version INTEGER NOT NULL DEFAULT 1")
        if "pending_version" not in scolumns:
            self._conn.execute(
                "ALTER TABLE audit_subscriptions ADD COLUMN "
                "pending_version INTEGER")
        # 增量列：版本被切换时钉死的扫描上界（下一版本 effective_seq-1）。
        # 旧库已有版本行该列为 NULL：superseded 旧版本退化用自身
        # effective_seq-1（等于其 start_seq-1，历史行为一致）。
        vcolumns = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(audit_subscription_versions)").fetchall()}
        if vcolumns and "scan_upper_seq" not in vcolumns:
            self._conn.execute(
                "ALTER TABLE audit_subscription_versions "
                "ADD COLUMN scan_upper_seq INTEGER")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_subscription_versions (
                version_id        TEXT PRIMARY KEY,
                subscription_id   TEXT NOT NULL,
                version_no        INTEGER NOT NULL,
                idempotency_key   TEXT NOT NULL,
                callback_url      TEXT NOT NULL,
                secret            TEXT NOT NULL,
                filters_json      TEXT NOT NULL,
                effective_seq     INTEGER NOT NULL,
                scan_upper_seq    INTEGER,
                status            TEXT NOT NULL DEFAULT 'prepared',
                position_seq      INTEGER NOT NULL,
                sub_seq           INTEGER NOT NULL DEFAULT 0,
                snapshot_seq      INTEGER NOT NULL,
                created_at_ms     INTEGER NOT NULL,
                updated_at_ms     INTEGER NOT NULL,
                activated_at_ms   INTEGER,
                cancelled_at_ms   INTEGER,
                reject_reason     TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_subversion_no
                ON audit_subscription_versions(subscription_id, version_no);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_subversion_idem
                ON audit_subscription_versions(idempotency_key);
            CREATE INDEX IF NOT EXISTS idx_subversion_status
                ON audit_subscription_versions(subscription_id, status);
            CREATE TABLE IF NOT EXISTS audit_subscription_events (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                subscription_id   TEXT NOT NULL,
                version_no        INTEGER,
                event             TEXT NOT NULL,
                outcome           TEXT NOT NULL,
                detail            TEXT,
                detail_json       TEXT,
                created_at_ms     INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subevent_sub
                ON audit_subscription_events(subscription_id, id);
            CREATE TABLE IF NOT EXISTS audit_subscription_idempotency (
                idempotency_key   TEXT PRIMARY KEY,
                subscription_id   TEXT NOT NULL,
                operation         TEXT NOT NULL,
                target            TEXT NOT NULL,
                result_json       TEXT NOT NULL,
                created_at_ms     INTEGER NOT NULL
            );
            """)
        # 为版本切换特性之前创建的订阅回填隐式版本 1（active）：
        # 冻结其创建时的回调/过滤/密钥/位置；旧投递行 version_no 默认 1。
        self._conn.execute(
            "INSERT OR IGNORE INTO audit_subscription_versions(version_id, "
            "subscription_id, version_no, idempotency_key, callback_url, "
            "secret, filters_json, effective_seq, status, position_seq, "
            "sub_seq, snapshot_seq, created_at_ms, updated_at_ms, "
            "activated_at_ms) SELECT 'v1:'||subscription_id, "
            "subscription_id, 1, 'implicit-v1:'||idempotency_key, "
            "callback_url, secret, filters_json, start_seq, 'active', "
            "position_seq, sub_seq, snapshot_seq, created_at_ms, "
            "updated_at_ms, created_at_ms FROM audit_subscriptions s "
            "WHERE NOT EXISTS (SELECT 1 FROM audit_subscription_versions v "
            "WHERE v.subscription_id=s.subscription_id AND v.version_no=1)")
        self._conn.commit()

    # ---- 时钟 / 默认投递 ------------------------------------------------
    def _now(self) -> int:
        return self._store.clock.wall_ms()

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        """显式写事务（autocommit 连接下用 BEGIN IMMEDIATE 立即拿写锁）。

        与 Store 连接共享同一 WAL 库：写事务串行化，busy_timeout 等待
        Store 写提交；异常回滚。调用方必须已持有 self._lock。
        """
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _default_deliver(self, url, payload, signature) -> HttpDeliveryResult:
        return default_http_delivery(url, payload, signature)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def attach_key_rotation(self, key_rotation: Any) -> None:
        """注入签名密钥轮换管理器（解决两个管理器相互引用的构造顺序）。"""
        self._key_rotation = key_rotation

    # ======================================================================
    # 创建（幂等 + 冲突显式化）
    # ======================================================================
    def create_subscription(
        self,
        *,
        scope: Any,
        resource: Any = None,
        credential_id: Any = None,
        index_id: Any = None,
        release_id: Any = None,
        callback_url: Any = None,
        start_seq: Any = 0,
        filters: Any = None,
        idempotency_key: Any = None,
        max_attempts: Any = None,
    ) -> tuple[dict[str, Any], bool]:
        if scope not in SCOPES:
            raise AuditBadRequest(
                "scope 只能取 resource / credential / causal_index / release",
                scope=scope)
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：同一幂等键重复提交只会得到同一订阅")
        if not isinstance(callback_url, str) or not callback_url.strip() \
                or not callback_url.strip().lower().startswith(
                    ("http://", "https://")):
            raise AuditBadRequest(
                "callback_url 必填且必须是 http(s) 地址")
        url = callback_url.strip()
        key = idempotency_key.strip()
        filt = normalize_filters(filters)
        start = _as_int(start_seq, "start_seq", default=0)
        if start < 0:
            raise AuditBadRequest("start_seq 不能为负数", start_seq=start)
        # max_attempts 省略时不在幂等规格中比较（与既有订阅保持一致）；
        # 只有显式给出时才作为创建规格的一部分
        attempts_given = max_attempts not in (None, "")
        attempts_val = _as_int(max_attempts, "max_attempts",
                               default=DEFAULT_MAX_ATTEMPTS)
        if attempts_val < 1:
            raise AuditBadRequest("max_attempts 必须 >= 1",
                                  max_attempts=attempts_val)

        store = self._store
        with store._lock:  # noqa: SLF001 - 钉死快照与目标存在性须与写入互斥
            sconn = store._conn  # noqa: SLF001
            row = sconn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = int(row["m"]) if row["m"] is not None else 0

            # 起始序号越过创建时刻的稳定视图上界：明确拒绝。
            # 创建期间落库的新事件 seq 必 >= 本快照，不会被错误塞入
            # "更早的起始快照"（游标从 start_seq 开始只向前扫描）。
            if start > max_seq:
                raise SubscriptionRangeError(
                    f"start_seq={start} 越过当前稳定视图上界 {max_seq}，"
                    "该历史位置尚不存在；请先用一次审计查询取得当前最大序号",
                    start_seq=start, available_max_seq=max_seq)

            target = self._validate_target_locked(sconn, scope, resource,
                                                  credential_id, index_id,
                                                  release_id)

        # 幂等键全局唯一：同键即回放或冲突。插入在订阅自有连接上进行，
        # 目标描述只参与规格比较，不影响租约侧任何数据。
        with self._lock:
            conn = self._conn
            conn.rollback()
            prev = conn.execute(
                "SELECT * FROM audit_subscriptions WHERE idempotency_key=?",
                (key,)).fetchone()
            spec = self._spec(scope, target, url, start, filt,
                              attempts_val if attempts_given else None)
            if prev is not None:
                diff = self._first_spec_diff(prev, spec)
                if diff is None:
                    view = self._view(prev)
                    conn.rollback()
                    return view, False
                raise SubscriptionIdConflict(
                    f"幂等键 {key} 已用于订阅 {prev['subscription_id']}，"
                    f"本次请求与首次创建不一致：首个差异位于 {diff['path']}",
                    subscription_id=prev["subscription_id"],
                    first_difference=diff)

            subscription_id = uuid.uuid4().hex
            now = self._now()
            secret = new_secret()
            try:
                with self._tx():
                    conn.execute(
                        "INSERT INTO audit_subscriptions(subscription_id, "
                        "idempotency_key, scope, resource, credential_id, "
                        "index_id, release_id, callback_url, secret, "
                        "filters_json, start_seq, position_seq, sub_seq, "
                        "snapshot_seq, current_version, pending_version, "
                        "status, max_attempts, ack_required, "
                        "created_at_ms, updated_at_ms) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (subscription_id, key, scope, target["resource"],
                         target["credential_id"], target["index_id"],
                         target["release_id"], url, secret,
                         canonical_json(filt), start, start, 0, max_seq,
                         1, None, SUB_ACTIVE, attempts_val, 0, now, now))
                    # 版本 1：创建即生效，冻结同样的回调/过滤/密钥
                    conn.execute(
                        "INSERT INTO audit_subscription_versions(version_id, "
                        "subscription_id, version_no, idempotency_key, "
                        "callback_url, secret, filters_json, effective_seq, "
                        "status, position_seq, sub_seq, snapshot_seq, "
                        "created_at_ms, updated_at_ms, activated_at_ms) "
                        "VALUES(?,?,1,?,?,?,?,?, 'active', ?,0,?,?,?,?)",
                        ("v1:" + subscription_id, subscription_id, key,
                         url, secret, canonical_json(filt), start,
                         start, max_seq, now, now, now))
            except sqlite3.IntegrityError:
                # 并发重复提交兜底
                prev = conn.execute(
                    "SELECT * FROM audit_subscriptions "
                    "WHERE idempotency_key=?", (key,)).fetchone()
                if prev is not None:
                    diff = self._first_spec_diff(prev, spec)
                    if diff is None:
                        view = self._view(prev)
                        conn.rollback()
                        return view, False
                    raise SubscriptionIdConflict(
                        f"幂等键 {key} 已用于参数不同的订阅",
                        subscription_id=prev["subscription_id"],
                        first_difference=diff)
                raise
            row = self._get_row(conn, subscription_id)
            view = self._view(row)
            conn.rollback()
            return view, True

    @staticmethod
    def _spec(scope, target, url, start, filt,
              max_attempts) -> dict[str, Any]:
        """冻结的创建规格（幂等比较用；密钥是服务端生成的，不参与比较）。

        max_attempts 为 None 表示请求未显式给出，不参与幂等比较（回放时
        沿用既有订阅的设置）。
        """
        return {
            "scope": scope,
            "resource": target["resource"],
            "credential_id": target["credential_id"],
            "index_id": target["index_id"],
            "release_id": target["release_id"],
            "callback_url": url,
            "start_seq": start,
            "filters": filt,
            "max_attempts": max_attempts,
        }

    @staticmethod
    def _first_spec_diff(prev, spec: dict) -> dict | None:
        """逐个比较创建规格，返回首个差异字段（确定性顺序）。"""
        fields = [
            ("scope", prev["scope"], spec["scope"]),
            ("resource", prev["resource"], spec["resource"]),
            ("credential_id", prev["credential_id"],
             spec["credential_id"]),
            ("index_id", prev["index_id"], spec["index_id"]),
            ("release_id", prev["release_id"], spec["release_id"]),
            ("callback_url", prev["callback_url"], spec["callback_url"]),
            ("start_seq", prev["start_seq"], spec["start_seq"]),
        ]
        if spec["max_attempts"] is not None:
            fields.append(("max_attempts", prev["max_attempts"],
                           spec["max_attempts"]))
        for path, old, new in fields:
            if old != new:
                return {"path": path, "existing": old, "requested": new}
        old_filters = json.loads(prev["filters_json"])
        if old_filters != spec["filters"]:
            return {"path": "filters", "existing": old_filters,
                    "requested": spec["filters"]}
        return None

    def _validate_target_locked(self, conn, scope, resource, credential_id,
                                index_id, release_id) -> dict[str, str]:
        """校验订阅目标存在，返回规范化的目标描述。只读。"""
        target = {"resource": "", "credential_id": "", "index_id": "",
                  "release_id": ""}
        if scope == SCOPE_RESOURCE:
            res = str(require_value(resource, "resource"))
            row = conn.execute(
                "SELECT 1 FROM lease_events WHERE resource=? LIMIT 1",
                (res,)).fetchone()
            if row is None and conn.execute(
                    "SELECT 1 FROM resources WHERE resource=?",
                    (res,)).fetchone() is None:
                raise SubscriptionNotFound(
                    f"资源 {res} 不存在且没有任何历史事件，无法订阅",
                    resource=res)
            target["resource"] = res
        elif scope == SCOPE_CREDENTIAL:
            cid = str(require_value(credential_id, "credential_id"))
            row = conn.execute(
                "SELECT 1 FROM delegations WHERE credential_id=?",
                (cid,)).fetchone()
            ev = conn.execute(
                "SELECT 1 FROM lease_events WHERE credential_id=? LIMIT 1",
                (cid,)).fetchone()
            if row is None and ev is None:
                raise SubscriptionNotFound(
                    f"委托凭证 {cid} 不存在（既无凭证记录也无历史事件）",
                    credential_id=cid)
            target["credential_id"] = cid
        elif scope == SCOPE_CAUSAL_INDEX:
            iid = str(require_value(index_id, "index_id"))
            row = conn.execute(
                "SELECT scope, resource, credential_id, package_id, status "
                "FROM causal_indexes WHERE index_id=?", (iid,)).fetchone()
            if row is None:
                raise SubscriptionNotFound(
                    f"因果索引 {iid} 不存在，无法订阅", index_id=iid)
            target["index_id"] = iid
            # 把索引目标描述一并钉住（仅作为信息，不改变订阅范围：
            # 范围始终是该索引冻结成员所锚定的审计事件集合）
            target["_index_scope"] = row["scope"]
            target["_index_status"] = row["status"]
        else:  # SCOPE_RELEASE
            rid = str(require_value(release_id, "release_id"))
            row = conn.execute(
                "SELECT index_id, version FROM index_releases "
                "WHERE release_id=?", (rid,)).fetchone()
            if row is None:
                raise SubscriptionNotFound(
                    f"发布版本计划 {rid} 不存在，无法订阅",
                    release_id=rid)
            target["release_id"] = rid
            target["index_id"] = row["index_id"]
        return target

    # ======================================================================
    # 扫描历史 → 入队（稳定历史视图、严格顺序、不重复）
    # ======================================================================
    def scan_and_enqueue(self, *, now_ms: int | None = None,
                         max_events: int = SCAN_BATCH) -> int:
        """扫描各 active 订阅各版本游标之后的历史事件，把匹配事件入队。

        事件来自只增的 ``lease_events``（与审计回放同一稳定历史）；订阅
        处理只 SELECT 租约侧表，绝不改写。

        版本切换后一个订阅同时存在两个需要扫描的版本，各自独立游标：

        - ``superseded`` 旧版本：扫描上界钉在新版本 ``effective_seq-1``，
          只负责把切换时还没检视完的边界前事件补齐入队；
        - ``active`` 当前版本：从自己的 ``effective_seq`` 扫到视图上界。

        每个版本独立事务：未匹配事件只推进该版本游标；匹配事件插入投递行
        （``(subscription_id, event_seq)`` 唯一 + INSERT OR IGNORE 兜底），
        版本内订阅序号在同一事务内单调递增。返回新入队的投递行数。
        """
        now = now_ms if now_ms is not None else self._now()
        # 全局稳定视图上界：在租约锁内取一次 MAX(seq)，与写入互斥
        with self._store._lock:  # noqa: SLF001
            sconn = self._store._conn  # noqa: SLF001
            max_row = sconn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = int(max_row["m"]) if max_row["m"] is not None else 0

        enqueued = 0
        with self._lock:
            conn = self._conn
            subs_rows = conn.execute(
                "SELECT subscription_id FROM audit_subscriptions "
                "WHERE status=?", (SUB_ACTIVE,)).fetchall()
            conn.rollback()
        for s in subs_rows:
            sid = s["subscription_id"]
            # 旧版本（superseded，版本号更小）排在前面补扫，再扫当前
            # active 版本；分窗口推进直到两个版本都追上各自上界。
            while True:
                progressed = False
                with self._lock:
                    versions = conn.execute(
                        "SELECT * FROM audit_subscription_versions "
                        "WHERE subscription_id=? AND status IN (?,?) "
                        "ORDER BY version_no ASC",
                        (sid, V_SUPERSEDED, V_ACTIVE)).fetchall()
                    # 已预创建但尚未激活的版本钉住边界：在激活完成之前，
                    # 当前 active 版本也不得扫过 effective_seq-1，否则边界
                    # 上的事件会被错误地按旧回调/旧过滤入旧版本队列
                    prepared = conn.execute(
                        "SELECT effective_seq FROM "
                        "audit_subscription_versions "
                        "WHERE subscription_id=? AND status=?",
                        (sid, V_PREPARED)).fetchall()
                    # 已预登记但尚未生效的签名密钥同样钉住边界：否则生效
                    # 序号之后的事件会在生效前就用旧密钥入队（投递行一旦
                    # 写入即冻结签名密钥代际，无法回头改判）。
                    if self._key_rotation is not None:
                        prepared_keys = conn.execute(
                            "SELECT effective_seq FROM "
                            "audit_subscription_signing_keys "
                            "WHERE subscription_id=? AND status=?",
                            (sid, "prepared")).fetchall()
                    else:
                        prepared_keys = []
                    conn.rollback()
                pending_caps = [int(r["effective_seq"]) - 1 for r in prepared]
                pending_caps += [int(r["effective_seq"]) - 1
                                 for r in prepared_keys]
                for v in versions:
                    upper = self._version_upper_seq(v, max_seq)
                    if v["status"] == V_ACTIVE and pending_caps:
                        upper = min(upper, *pending_caps)
                    if int(v["position_seq"]) <= upper:
                        n = self._enqueue_version(
                            sid, int(v["version_no"]), upper, now,
                            max_events=max_events)
                        enqueued += n
                        progressed = True
                if not progressed:
                    break
        return enqueued

    @staticmethod
    def _version_upper_seq(version_row, max_seq: int) -> int:
        """版本允许扫描到的全局序号上界（含）。

        superseded 旧版本钉死在切换时保存的 ``scan_upper_seq``（即新版本
        生效序号 - 1，边界前事件）；该列为 NULL 的历史版本退化用自身
        effective_seq-1；active 当前版本取稳定视图上界（若存在预创建版本，
        调用方还会进一步压到其 effective_seq-1）。
        """
        if version_row["status"] == V_SUPERSEDED:
            keys = version_row.keys()
            if "scan_upper_seq" in keys \
                    and version_row["scan_upper_seq"] is not None:
                return int(version_row["scan_upper_seq"])
            return int(version_row["effective_seq"]) - 1
        return max_seq

    def _enqueue_version(self, subscription_id: str, version_no: int,
                         seq_to: int, now: int, *, max_events: int) -> int:
        """把一个版本 [position_seq, seq_to] 区间内一个窗口的事件入队。"""
        with self._lock:
            conn = self._conn
            sub = self._get_row(conn, subscription_id)
            if sub is None or sub["status"] != SUB_ACTIVE:
                return 0
            v = self._get_version_row(conn, subscription_id, version_no)
            if v is None or v["status"] not in (V_ACTIVE, V_SUPERSEDED):
                return 0
            upper = self._version_upper_seq(v, seq_to)
            pos = int(v["position_seq"])
            if pos > upper:
                return 0
            filt = json.loads(v["filters_json"])
            rows = self._scope_event_rows(conn, sub, pos, upper,
                                          limit=max_events)
            window = min(upper, pos + max(1, max_events) - 1)
            is_active = v["status"] == V_ACTIVE
            with self._tx():
                if not rows:
                    # 本窗口没有属于该作用域的事件：游标越过整个窗口。
                    # 不能直接跳到上界——后续窗口里可能还有属于该作用域
                    # 的事件（其它资源的事件在全局序号上交错）。
                    conn.execute(
                        "UPDATE audit_subscription_versions "
                        "SET position_seq=?, updated_at_ms=? "
                        "WHERE version_id=?",
                        (window + 1, now, v["version_id"]))
                    if is_active:
                        conn.execute(
                            "UPDATE audit_subscriptions SET position_seq=?, "
                            "updated_at_ms=? WHERE subscription_id=? AND status=?",
                            (window + 1, now, subscription_id, SUB_ACTIVE))
                    return 0

                ver_seq = int(v["sub_seq"])
                inserted = 0
                for r in rows:
                    ev = event_dict(r)
                    if not event_passes_filters(ev, filt):
                        continue
                    payload = self._build_payload(sub, r, version_no)
                    # 版本内订阅序号在同一事务内预先占位：按事件 seq 升序
                    ver_seq += 1
                    payload["subscription_seq"] = ver_seq
                    # 签名密钥代际：生效序号（含）起的事件钉住新轮换密钥，
                    # 否则钉住 None（回退版本冻结密钥）。投递行一旦写入就
                    # 不再随后续轮换改变——旧通知永远按旧密钥签名/确认。
                    sign_key_id = None
                    if self._key_rotation is not None:
                        _, sign_key_id = \
                            self._key_rotation.signing_secret_for_delivery(
                                subscription_id, int(r["seq"]),
                                version_no=version_no, conn=conn)
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO audit_subscription_deliveries"
                        "(delivery_id, subscription_id, event_seq, "
                        "subscription_seq, version_no, status, attempts, "
                        "next_retry_at_ms, payload_json, signature, "
                        "signing_key_id, created_at_ms, updated_at_ms) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (uuid.uuid4().hex, subscription_id, r["seq"],
                         ver_seq, version_no, D_PENDING, 0, 0,
                         canonical_json(payload), None, sign_key_id, now, now))
                    if cur.rowcount:
                        inserted += 1
                    else:
                        # 并发扫描/激活补扫导致的重复行：以既有行已落库的
                        # 订阅序号为准（绝不复用同一序号给两个不同事件），
                        # 本次预占的序号让回
                        prev = conn.execute(
                            "SELECT subscription_seq FROM "
                            "audit_subscription_deliveries "
                            "WHERE subscription_id=? AND event_seq=?",
                            (subscription_id, r["seq"])).fetchone()
                        ver_seq = (int(prev["subscription_seq"])
                                   if prev is not None else ver_seq - 1)
                # 游标推进到本窗口末端（不是最后一条匹配事件：窗口内未匹配
                # 或不属于本作用域的序号同样已经检视，不能再回头生成投递）
                conn.execute(
                    "UPDATE audit_subscription_versions SET position_seq=?, "
                    "sub_seq=?, updated_at_ms=? WHERE version_id=?",
                    (window + 1, ver_seq, now, v["version_id"]))
                if is_active:
                    # 订阅主行镜像当前版本游标/序号，维持订阅视图语义
                    conn.execute(
                        "UPDATE audit_subscriptions SET position_seq=?, "
                        "sub_seq=?, updated_at_ms=? "
                        "WHERE subscription_id=? AND status=?",
                        (window + 1, ver_seq, now, subscription_id,
                         SUB_ACTIVE))
                return inserted

    def _scope_event_rows(self, conn, sub, seq_from: int, seq_to: int,
                          *, limit: int):
        """取全局序号区间 [seq_from, seq_to] 内属于本订阅目标的事件。

        窗口上界 min(seq_to, seq_from+limit-1) 按**全局**序号取，因此
        作用域事件即便在全局序列上稀疏交错，每个 seq 也都会被检视到，
        不会因 per-scope LIMIT 跳过事件。调用方按最后检视到的全局 seq
        推进游标。
        """
        window = min(seq_to, seq_from + max(1, limit) - 1)
        scope = sub["scope"]
        if scope == SCOPE_RESOURCE:
            return conn.execute(
                "SELECT * FROM lease_events WHERE resource=? AND seq>=? "
                "AND seq<=? ORDER BY seq ASC",
                (sub["resource"], seq_from, window)).fetchall()
        if scope == SCOPE_CREDENTIAL:
            return conn.execute(
                "SELECT * FROM lease_events WHERE credential_id=? AND seq>=? "
                "AND seq<=? ORDER BY seq ASC",
                (sub["credential_id"], seq_from, window)).fetchall()
        # causal_index / release：事件集合 = 该索引冻结成员中锚定的
        # lease_event 节点（release 锚定其发布的索引）。成员集合创建时
        # 冻结，因此"后来事件插到前面"在结构上不可能发生。
        index_id = sub["index_id"]
        return conn.execute(
            "SELECT e.* FROM causal_index_members m "
            "JOIN lease_events e ON e.seq=m.anchor_seq "
            "WHERE m.index_id=? AND m.node_type='lease_event' "
            "AND e.seq>=? AND e.seq<=? ORDER BY e.seq ASC",
            (index_id, seq_from, window)).fetchall()

    def _build_payload(self, sub, ev_row, version_no: int = 1) -> dict[str, Any]:
        summary = event_summary(ev_row)
        return {
            "schema_version": 1,
            "subscription_id": sub["subscription_id"],
            "version_no": int(version_no),
            "scope": sub["scope"],
            "object": self._object_ref(sub),
            "event_seq": int(ev_row["seq"]),
            "subscription_seq": 0,  # 由调用方在入队事务内赋值
            "event_type": summary["event_type"],
            "object_id": f"lease_event:{ev_row['seq']}",
            "summary": summary,
            "wall_ms": int(ev_row["wall_ms"]),
            "logical": int(ev_row["logical"]),
        }

    @staticmethod
    def _object_ref(sub) -> dict[str, str]:
        return {
            "scope": sub["scope"],
            "resource": sub["resource"],
            "credential_id": sub["credential_id"],
            "index_id": sub["index_id"],
            "release_id": sub["release_id"],
        }

    def _delivery_signing_secret(self, row) -> str:
        """投递行签名用的密钥明文（调用方已持锁）。

        优先投递行冻结的轮换签名密钥（``signing_key_id``）；该列为 NULL
        （轮换特性前的旧行/未轮换）时回退所属版本冻结的密钥。
        """
        version_secret = row["secret"]
        kr = self._key_rotation
        if kr is None:
            return version_secret
        keys = row.keys()
        sign_key_id = row["signing_key_id"] if "signing_key_id" in keys \
            else None
        if not sign_key_id:
            return version_secret
        secret = kr.secret_for_key_id(
            self._conn, row["subscription_id"], sign_key_id)
        return secret if secret is not None else version_secret

    # ======================================================================
    # 投递：认领（带令牌的条件 UPDATE）→ 锁外回调 → 条件记录结果
    # ======================================================================
    def process_due(self, *, now_ms: int | None = None,
                    max_deliveries: int | None = None) -> int:
        """回收崩溃认领行、认领所有到点且位于队首的待投递通知并执行回调。

        返回本轮处理的投递数。严格顺序由队首检查保证：每个订阅只取最早
        的一行非终态投递，只有它是 pending 且退避到点时才投递；它处于
        inflight / awaiting_confirm / dead_letter / 退避等待时，后续事件
        全部等待。
        """
        now = now_ms if now_ms is not None else self._now()
        self.recover_stale_claims(now_ms=now)

        # 到点判定 = updated_at_ms（失败时刻）+ backoff_ms：两者来自同一
        # 偏移墙钟，墙钟被正拨只会让重试更早到点，绝不会出现"退避永远不
        # 到点"；新认领/复位行 updated_at_ms=建行时刻且 backoff=0。
        # SQL: d.next_retry_at_ms 存退避时长，到点比较 updated_at_ms + 值。
        with self._lock:
            conn = self._conn
            # 每个订阅的队首行 = 最小 event_seq 的**非终态**投递：
            # 已确认/已弃置的行不再占队，而 dead_letter / inflight /
            # awaiting_confirm / 退避等待中的行必须挡住后续事件，绝不跳过。
            heads = conn.execute(
                "SELECT d.* FROM audit_subscription_deliveries d "
                "JOIN (SELECT subscription_id, MIN(event_seq) AS min_seq "
                "FROM audit_subscription_deliveries "
                "WHERE status IN (?,?,?,?) GROUP BY subscription_id) h "
                "ON h.subscription_id=d.subscription_id "
                "AND h.min_seq=d.event_seq "
                "JOIN audit_subscriptions s ON s.subscription_id=d.subscription_id "
                "WHERE d.status=? AND (d.updated_at_ms + d.next_retry_at_ms)<=? "
                "AND s.status=? ORDER BY d.event_seq ASC",
                (D_DEAD, D_INFLIGHT, D_AWAITING, D_PENDING,
                 D_PENDING, now, SUB_ACTIVE)).fetchall()
            conn.rollback()
        if max_deliveries is not None:
            heads = heads[:max_deliveries]

        n = 0
        for head in heads:
            if self._claim_and_deliver(head["delivery_id"], now):
                n += 1
        return n

    def recover_stale_claims(self, *, now_ms: int | None = None,
                             lease_ms: int | None = None) -> int:
        """把超时的 inflight/awaiting_confirm 行回收为 pending。

        投递器崩溃/重启时认领行会残留；超过认领租约（以认领时刻
        ``claimed_at_ms`` 计）即回收（不增加 ``attempts``，退避清零
        立即重试）。``lease_ms=0`` 表示无条件回收（启动恢复用）。
        """
        now = now_ms if now_ms is not None else self._now()
        lease = self.claim_lease_ms if lease_ms is None else lease_ms
        cutoff = 0 if lease == 0 else now - lease
        with self._lock:
            conn = self._conn
            # lease_ms=0（启动恢复）：无条件回收所有认领中状态的行；
            # 周期性回收：只回收认领时刻早于 cutoff 的行。
            # 认领 UPDATE 总会写入 claimed_at_ms，故正常投递中的行
            # （claimed_at_ms≈now）不会被误回收。回收即立即重试
            # （退避清零，attempts 不增加）。
            if lease == 0:
                where = "status IN (?,?)"
                params: tuple = (D_INFLIGHT, D_AWAITING)
            else:
                where = "status IN (?,?) AND claimed_at_ms<=?"
                params = (D_INFLIGHT, D_AWAITING, cutoff)
            with self._tx():
                cur = conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "dispatch_token=NULL, claimed_at_ms=NULL, "
                    "next_retry_at_ms=0, "
                    "last_error=COALESCE(last_error, "
                    "'stale_claim_reclaimed'), updated_at_ms=? WHERE "
                    + where,
                    (D_PENDING, now, *params))
                return cur.rowcount

    def _claim_and_deliver(self, delivery_id: str, now: int) -> bool:
        """认领一行 pending 投递，执行回调并按结果记录。返回是否处理过。

        回调地址与签名密钥取**投递行所属版本**冻结的值：切换前已入队/
        进行中的旧版本通知继续发往旧回调地址、用旧密钥签名；新版本通知
        才使用新地址/新密钥。
        """
        with self._lock:
            conn = self._conn
            row = conn.execute(
                "SELECT d.*, s.status AS sub_status, v.callback_url AS url, "
                "v.secret AS secret, s.max_attempts AS max_attempts "
                "FROM audit_subscription_deliveries d "
                "JOIN audit_subscriptions s "
                "ON s.subscription_id=d.subscription_id "
                "JOIN audit_subscription_versions v "
                "ON v.subscription_id=d.subscription_id "
                "AND v.version_no=d.version_no "
                "WHERE d.delivery_id=?", (delivery_id,)).fetchone()
            if row is None:
                return False
            # 取消后的迟到通知不能再发送
            if row["sub_status"] != SUB_ACTIVE:
                return False
            if row["status"] != D_PENDING:
                return False
            token = uuid.uuid4().hex
            with self._tx():
                cur = conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "dispatch_token=?, claimed_at_ms=?, attempts=attempts+1, "
                    "updated_at_ms=? WHERE delivery_id=? AND status=?",
                    (D_INFLIGHT, token, now, now, delivery_id, D_PENDING))
                if cur.rowcount != 1:
                    return False
                payload = json.loads(row["payload_json"])
                # 签名密钥优先级：投递行冻结的轮换签名密钥 → 所属版本冻结
                # 密钥（旧行/无轮换时）。生效前入队的旧通知在此仍用旧
                # 密钥签名，绝不被后续轮换改写。
                secret = self._delivery_signing_secret(row)
                signature = sign_payload(secret, payload)
                conn.execute(
                    "UPDATE audit_subscription_deliveries SET signature=? "
                    "WHERE delivery_id=?", (signature, delivery_id))
            url = row["url"]

        # 回调在数据库事务/锁之外执行，慢回调不阻塞租约与其它订阅
        try:
            result = self._deliver_cb(url, payload, signature)
        except Exception as exc:  # noqa: BLE001 - 回调器自身异常按失败处理
            result = HttpDeliveryResult(
                error=f"delivery_exception: {type(exc).__name__}: {exc}")
        self._record_result(delivery_id, token, result, now)
        return True

    def _record_result(self, delivery_id: str, token: str,
                       result: HttpDeliveryResult, now: int) -> None:
        """按回调结果更新投递行；只接受本次认领令牌的响应。"""
        with self._lock:
            conn = self._conn
            row = conn.execute(
                "SELECT d.*, s.status AS sub_status, "
                "s.max_attempts AS max_attempts FROM "
                "audit_subscription_deliveries d JOIN audit_subscriptions s "
                "ON s.subscription_id=d.subscription_id "
                "WHERE d.delivery_id=?", (delivery_id,)).fetchone()
            if row is None:
                return
            # 令牌不匹配（迟到的旧响应）或订阅已取消/暂停：忽略。
            # 取消后的迟到通知即便成功也不能推进队列。
            if row["dispatch_token"] != token:
                return
            if row["sub_status"] != SUB_ACTIVE:
                # 订阅已暂停/取消：迟到响应不改变语义终态。
                # - 取消：开放行已在取消事务置 discarded，这里不动；
                # - 暂停（投递期间被暂停）：保持 inflight 与认领令牌，
                #   恢复后由崩溃认领回收机制重新投递（不丢通知）。
                return
            attempts = int(row["attempts"])
            max_attempts = int(row["max_attempts"])
            error = result.error or f"http_status_{result.status}"
            with self._tx():
                if result.ok:
                    cur = conn.execute(
                        "UPDATE audit_subscription_deliveries SET status=?, "
                        "dispatch_token=NULL, confirmed_at_ms=?, "
                        "last_error=NULL, updated_at_ms=? "
                        "WHERE delivery_id=? AND status=?",
                        (D_CONFIRMED, now, now, delivery_id, D_INFLIGHT))
                    if cur.rowcount:
                        self._clear_blocked_locked(
                            conn, row["subscription_id"], now)
                elif result.ack_pending:
                    conn.execute(
                        "UPDATE audit_subscription_deliveries SET status=?, "
                        "updated_at_ms=? WHERE delivery_id=? AND status=?",
                        (D_AWAITING, now, delivery_id, D_INFLIGHT))
                    conn.execute(
                        "UPDATE audit_subscriptions SET ack_required=1 "
                        "WHERE subscription_id=?",
                        (row["subscription_id"],))
                elif result.permanent_reject or attempts >= max_attempts:
                    # 永久拒收或超过上限：进入死信并挡住后续事件
                    reason = ("permanent_reject_410"
                              if result.permanent_reject
                              else "max_attempts_exceeded")
                    conn.execute(
                        "UPDATE audit_subscription_deliveries SET status=?, "
                        "dispatch_token=NULL, dead_letter_reason=?, "
                        "last_error=?, updated_at_ms=? "
                        "WHERE delivery_id=? AND status=?",
                        (D_DEAD, reason, error, now, delivery_id,
                         D_INFLIGHT))
                    conn.execute(
                        "UPDATE audit_subscriptions SET blocked=1, "
                        "error=?, updated_at_ms=? WHERE subscription_id=?",
                        (f"delivery {delivery_id} 进入死信（{reason}）："
                         f"{error}", now, row["subscription_id"]))
                else:
                    # 失败退避：next_retry_at_ms 存退避时长，到点判定用
                    # updated_at_ms + next_retry_at_ms（同一偏移墙钟，
                    # 正拨不会让退避永远不到点）
                    delay = backoff_delay_ms(
                        attempts, base_ms=self.base_backoff_ms,
                        max_ms=self.max_backoff_ms)
                    conn.execute(
                        "UPDATE audit_subscription_deliveries SET status=?, "
                        "dispatch_token=NULL, next_retry_at_ms=?, "
                        "last_error=?, updated_at_ms=? "
                        "WHERE delivery_id=? AND status=?",
                        (D_PENDING, delay, error, now, delivery_id,
                         D_INFLIGHT))

    # ======================================================================
    # 显式签名确认
    # ======================================================================
    def confirm_delivery(self, subscription_id: str, event_seq: Any,
                         signature: Any) -> dict[str, Any]:
        """订阅回调方对 awaiting_confirm（或重发确认）的通知做显式确认。

        必须携带与通知载荷一致的 HMAC 签名。确认是条件 UPDATE：只有
        inflight/awaiting_confirm 的行才会变成 confirmed；对已确认行
        重复提交幂等回放（不改变任何状态、不重复推进）；签名错误一律
        401 且不写库。
        """
        seq = _as_int(event_seq, "event_seq")
        with self._lock:
            conn = self._conn
            # 刷新读视图：密钥轮换可能已在另一连接（KeyRotationManager）把
            # 投递行冻结密钥置为 retired，停在旧 WAL 快照会误判它仍有效。
            conn.rollback()
            sub = self._get_row(conn, subscription_id)
            if sub is None:
                raise SubscriptionNotFound(
                    f"订阅 {subscription_id} 不存在",
                    subscription_id=subscription_id)
            d = conn.execute(
                "SELECT * FROM audit_subscription_deliveries "
                "WHERE subscription_id=? AND event_seq=?",
                (subscription_id, seq)).fetchone()
            if d is None:
                raise DeliveryNotFound(
                    f"订阅 {subscription_id} 没有事件 seq={seq} 的投递记录",
                    subscription_id=subscription_id, event_seq=seq)

            payload = json.loads(d["payload_json"])
            # 密钥取投递行所属版本：旧版本通知必须仍能用旧版本密钥确认。
            # 若启用签名密钥轮换，则再叠加轮换语义：投递行冻结的轮换密钥
            # 优先；旧通知在旧密钥宽限期内仍可用旧密钥确认。
            kr = self._key_rotation
            if kr is not None:
                accepted, result_code, info = kr.verify_ack_signature(
                    subscription_id, d, payload, signature, conn=conn)
                if not accepted:
                    # 验证失败也只追加一条 failed 验证记录（不改投递状态、
                    # 不推进队列），随后 401。失败记录归属投递行本应使用的
                    # 密钥（expected_key_id），便于"按密钥查验证失败投递"。
                    fail_info = {
                        "used_key_id": info.get("expected_key_id") or "",
                        "expected_key_id": info.get("expected_key_id")}
                    now0 = self._now()
                    with self._tx():
                        kr.record_verification(
                            subscription_id, d, result_code, fail_info,
                            conn=conn, now=now0)
                    raise InvalidSignature(
                        "确认签名校验失败：签名与当前（或宽限期旧）密钥的 "
                        "HMAC-SHA256 均不一致，状态未改变",
                        subscription_id=subscription_id, event_seq=seq,
                        verification=result_code)
            else:
                vrow = self._get_version_row(conn, subscription_id,
                                             int(d["version_no"]))
                secret = vrow["secret"] if vrow is not None else sub["secret"]
                result_code = V_OK
                info = {"expected_key_id": None}
                if not verify_signature(secret, payload, signature):
                    raise InvalidSignature(
                        "确认签名校验失败：签名与通知载荷的 HMAC-SHA256 不一致，"
                        "状态未改变",
                        subscription_id=subscription_id, event_seq=seq)

            if d["status"] == D_CONFIRMED:
                # 重复确认：幂等回放，绝不推进两次。验证结论（若启用轮换）
                # 以唯一约束幂等落库，不重复计数。
                if kr is not None:
                    now0 = self._now()
                    with self._tx():
                        kr.record_verification(
                            subscription_id, d, result_code, info,
                            conn=conn, now=now0)
                return self._delivery_view(d, replayed=True)
            if d["status"] not in (D_INFLIGHT, D_AWAITING):
                raise DeliveryBadState(
                    f"投递当前状态为 {d['status']}，不能确认；只有待确认"
                    "的投递可以确认",
                    subscription_id=subscription_id, event_seq=seq,
                    status=d["status"])
            now = self._now()
            with self._tx():
                conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "dispatch_token=NULL, confirmed_at_ms=?, updated_at_ms=? "
                    "WHERE delivery_id=? AND status IN (?,?)",
                    (D_CONFIRMED, now, now, d["delivery_id"],
                     D_INFLIGHT, D_AWAITING))
                self._clear_blocked_locked(conn, subscription_id, now)
                if kr is not None:
                    # 验证记录与确认在同一事务：不重复确认（delivery 唯一
                    # 验证行 + 条件 UPDATE），也不跳过通知。
                    kr.record_verification(
                        subscription_id, d, result_code, info,
                        conn=conn, now=now)
            return self._delivery_view(
                self._get_delivery_row(conn, d["delivery_id"]))

    # ======================================================================
    # 暂停 / 恢复 / 取消
    # ======================================================================
    def pause(self, subscription_id: str) -> dict[str, Any]:
        with self._lock:
            conn = self._conn
            sub = self._require_sub(conn, subscription_id)
            if sub["status"] == SUB_CANCELLED:
                raise SubscriptionBadState(
                    f"订阅 {subscription_id} 已取消，不能暂停",
                    subscription_id=subscription_id, status=SUB_CANCELLED)
            if sub["status"] != SUB_PAUSED:
                with self._tx():
                    conn.execute(
                        "UPDATE audit_subscriptions SET status=?, "
                        "updated_at_ms=? WHERE subscription_id=?",
                        (SUB_PAUSED, self._now(), subscription_id))
            return self._view(
                self._get_row(conn, subscription_id))

    def resume(self, subscription_id: str) -> dict[str, Any]:
        with self._lock:
            conn = self._conn
            sub = self._require_sub(conn, subscription_id)
            if sub["status"] == SUB_CANCELLED:
                raise SubscriptionBadState(
                    f"订阅 {subscription_id} 已取消，不能恢复",
                    subscription_id=subscription_id, status=SUB_CANCELLED)
            if sub["status"] == SUB_PAUSED:
                # 暂停期间可能有回调中的行停在 inflight：恢复时回收为
                # pending（不增加尝试次数），确保队首能继续投递
                with self._tx():
                    conn.execute(
                        "UPDATE audit_subscriptions SET status=?, "
                        "updated_at_ms=? WHERE subscription_id=?",
                        (SUB_ACTIVE, self._now(), subscription_id))
                    conn.execute(
                        "UPDATE audit_subscription_deliveries SET status=?, "
                        "dispatch_token=NULL, claimed_at_ms=NULL, "
                        "next_retry_at_ms=0, updated_at_ms=? "
                        "WHERE subscription_id=? AND status IN (?,?)",
                        (D_PENDING, self._now(), subscription_id,
                         D_INFLIGHT, D_AWAITING))
            return self._view(
                self._get_row(conn, subscription_id))

    def cancel(self, subscription_id: str) -> dict[str, Any]:
        """取消订阅：未终态投递全部置 discarded（保留历史），此后不再投递。

        正在回调中的通知其迟到响应会被 _record_result 的订阅状态检查
        忽略（回收为 pending 后也不会被扫描，因为订阅已 cancelled）。
        预创建但未激活的版本一并置 cancelled（永不生效）。
        """
        now = self._now()
        with self._lock:
            conn = self._conn
            sub = self._require_sub(conn, subscription_id)
            if sub["status"] == SUB_CANCELLED:
                # 幂等回放
                return self._view(sub)
            with self._tx():
                conn.execute(
                    "UPDATE audit_subscriptions SET status=?, blocked=0, "
                    "cancelled_at_ms=?, pending_version=NULL, updated_at_ms=? "
                    "WHERE subscription_id=?",
                    (SUB_CANCELLED, now, now, subscription_id))
                conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "dispatch_token=NULL, updated_at_ms=? "
                    "WHERE subscription_id=? AND status IN (?,?,?)",
                    (D_DISCARDED, now, subscription_id, *D_OPEN))
                conn.execute(
                    "UPDATE audit_subscription_versions SET status=?, "
                    "cancelled_at_ms=COALESCE(cancelled_at_ms, ?), "
                    "updated_at_ms=? "
                    "WHERE subscription_id=? AND status IN (?,?,?)",
                    (V_CANCELLED, now, now, subscription_id,
                     V_PREPARED, V_ACTIVE, V_SUPERSEDED))
                # 预登记但未生效的签名密钥一并撤销（永不生效）；已生效/
                # 宽限/退役密钥保留状态作为历史（其投递已随取消弃置）。
                if self._key_rotation is not None:
                    conn.execute(
                        "UPDATE audit_subscription_signing_keys SET status=?, "
                        "revoked_at_ms=COALESCE(revoked_at_ms, ?), "
                        "updated_at_ms=? "
                        "WHERE subscription_id=? AND status='prepared'",
                        ("revoked", now, now, subscription_id))
                self._audit_locked(
                    conn, subscription_id, None,
                    "subscription_cancelled", "ok", now=now)
            return self._view(self._get_row(conn, subscription_id))

    # ======================================================================
    # 从指定序号重新开始（保留已有投递记录）
    # ======================================================================
    def restart_from(self, subscription_id: str,
                     from_seq: Any) -> dict[str, Any]:
        """把订阅游标重置到 from_seq 并重新扫描入队。

        - 只允许 active/paused 订阅（已取消 409）；from_seq 不能越过当前
          稳定视图上界（416）；
        - **已有投递记录全部保留**：已确认行不动（同一事件不会重复确认）；
          其余非终态/dead_letter 行复位为 pending、清空尝试与死信原因，
          严格顺序恢复投递；
        - 重置后立即扫描 [from_seq, MAX(seq)] 重新补齐缺失的投递行
          （INSERT OR IGNORE，已有的不重建、订阅序号不重用）。
        - 已发生过版本切换或存在预创建版本的订阅拒绝重新开始（409）：
          跨版本重放会违反"旧版本按旧序号、生效序号后只进新版本"的
          不可变边界，需要新回调/过滤请创建下一版本。
        """
        seq = _as_int(from_seq, "from_seq")
        if seq < 0:
            raise AuditBadRequest("from_seq 不能为负数", from_seq=seq)
        store = self._store
        with store._lock:  # noqa: SLF001
            sconn = store._conn  # noqa: SLF001
            max_row = sconn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = int(max_row["m"]) if max_row["m"] is not None else 0
        if seq > max_seq:
            raise SubscriptionRangeError(
                f"from_seq={seq} 越过当前稳定视图上界 {max_seq}",
                start_seq=seq, available_max_seq=max_seq)

        now = self._now()
        with self._lock:
            conn = self._conn
            sub = self._require_sub(conn, subscription_id)
            if sub["status"] == SUB_CANCELLED:
                raise SubscriptionBadState(
                    f"订阅 {subscription_id} 已取消，不能重新开始",
                    subscription_id=subscription_id,
                    status=SUB_CANCELLED)
            vcount = conn.execute(
                "SELECT COUNT(*) AS c FROM audit_subscription_versions "
                "WHERE subscription_id=?", (subscription_id,)).fetchone()["c"]
            if int(vcount) > 1:
                raise SubscriptionVersionBadState(
                    "订阅已创建过下一版本（含已激活/取消），版本边界不可变，"
                    "不能跨版本重新开始；请创建新的订阅版本",
                    subscription_id=subscription_id,
                    versions=int(vcount))
            old_status = sub["status"]
            with self._tx():
                # 未确认的旧投递（含死信/待确认/投递中/退避等待）复位重试；
                # 已确认与已弃置（更早一次取消前的记录，正常不会出现）不动。
                conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "attempts=0, next_retry_at_ms=0, dispatch_token=NULL, "
                    "claimed_at_ms=NULL, last_error=NULL, "
                    "dead_letter_reason=NULL, updated_at_ms=? "
                    "WHERE subscription_id=? AND status IN (?,?,?,?)",
                    (D_PENDING, now, subscription_id,
                     D_PENDING, D_INFLIGHT, D_AWAITING, D_DEAD))
                conn.execute(
                    "UPDATE audit_subscriptions SET position_seq=?, blocked=0, "
                    "error=NULL, status=?, updated_at_ms=? "
                    "WHERE subscription_id=?",
                    (seq, SUB_ACTIVE, now, subscription_id))
                # 只有版本 1 时才允许走到这里：同步其游标
                conn.execute(
                    "UPDATE audit_subscription_versions SET position_seq=?, "
                    "updated_at_ms=? WHERE subscription_id=? AND version_no=1",
                    (seq, now, subscription_id))

        # 以 active 身份补齐区间内缺失的投递行，然后恢复原状态
        self.scan_and_enqueue(now_ms=now)
        with self._lock:
            conn = self._conn
            max_row = conn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            current_max = int(max_row["m"]) if max_row["m"] is not None else 0
            # 重新开始区间内的事件全部补齐后，游标停在视图末端做尾部追平；
            # 区间内 (subscription_id, event_seq) 唯一行已存在，后续扫描靠
            # INSERT OR IGNORE 不重建，严格顺序由"只投队首非终态行"保证
            with self._tx():
                conn.execute(
                    "UPDATE audit_subscriptions SET position_seq=?, status=? "
                    "WHERE subscription_id=?",
                    (current_max + 1, old_status, subscription_id))
            return self._view(self._get_row(conn, subscription_id))

    # ======================================================================
    # 死信：查询 / 查看原因 / 重新放回队列
    # ======================================================================
    def list_dead_letters(self, *, subscription_id: Any = None,
                          version_no: Any = None,
                          limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        ver = _as_int(version_no, "version_no") if version_no not in (
            None, "") else None
        with self._lock:
            conn = self._conn
            where, args = ["status=?"], [D_DEAD]
            if subscription_id not in (None, ""):
                where.append("subscription_id=?")
                args.append(str(subscription_id))
            if ver is not None:
                where.append("version_no=?")
                args.append(ver)
            args.append(limit)
            rows = conn.execute(
                "SELECT * FROM audit_subscription_deliveries WHERE "
                + " AND ".join(where)
                + " ORDER BY event_seq ASC LIMIT ?", tuple(args)).fetchall()
            conn.rollback()
            return {"dead_letters": [self._delivery_view(r) for r in rows],
                    "limit": limit,
                    "version_no": ver}

    def requeue_dead_letter(self, subscription_id: str,
                            event_seq: Any | None = None,
                            delivery_id: str | None = None) -> dict[str, Any]:
        """把死信重新放回队列：复位尝试次数，立即重试，解除挡队。

        重新放回不改变严格顺序：该行仍是其订阅在该 event_seq 上的唯一
        投递，前面若还有其它未确认行，它仍会等前面完成后才投递。
        """
        now = self._now()
        with self._lock:
            conn = self._conn
            self._require_sub(conn, subscription_id)
            if delivery_id:
                d = conn.execute(
                    "SELECT * FROM audit_subscription_deliveries "
                    "WHERE delivery_id=? AND subscription_id=?",
                    (str(delivery_id), subscription_id)).fetchone()
            else:
                seq = _as_int(event_seq, "event_seq")
                d = conn.execute(
                    "SELECT * FROM audit_subscription_deliveries "
                    "WHERE subscription_id=? AND event_seq=?",
                    (subscription_id, seq)).fetchone()
            if d is None:
                raise DeliveryNotFound(
                    "指定的死信投递不存在",
                    subscription_id=subscription_id, event_seq=event_seq)
            if d["status"] != D_DEAD:
                raise DeliveryBadState(
                    f"投递当前状态为 {d['status']}，只有 dead_letter 可以"
                    "重新放回队列",
                    subscription_id=subscription_id,
                    event_seq=d["event_seq"], status=d["status"])
            with self._tx():
                conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "attempts=0, next_retry_at_ms=0, dispatch_token=NULL, "
                    "claimed_at_ms=NULL, last_error=NULL, "
                    "dead_letter_reason=NULL, updated_at_ms=? "
                    "WHERE delivery_id=? AND status=?",
                    (D_PENDING, now, d["delivery_id"], D_DEAD))
                self._clear_blocked_locked(conn, subscription_id, now)
            return self._delivery_view(
                self._get_delivery_row(conn, d["delivery_id"]))

    # ======================================================================
    # 手动重试单条投递（退避未到点也可立即重试）
    # ======================================================================
    def retry_delivery(self, subscription_id: str,
                       event_seq: Any) -> dict[str, Any]:
        now = self._now()
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_sub(conn, subscription_id)
            seq = _as_int(event_seq, "event_seq")
            d = conn.execute(
                "SELECT * FROM audit_subscription_deliveries "
                "WHERE subscription_id=? AND event_seq=?",
                (subscription_id, seq)).fetchone()
            if d is None:
                raise DeliveryNotFound(
                    f"订阅 {subscription_id} 没有事件 seq={seq} 的投递记录",
                    subscription_id=subscription_id, event_seq=seq)
            if d["status"] not in (D_PENDING, D_AWAITING):
                raise DeliveryBadState(
                    f"投递当前状态为 {d['status']}，只有退避等待/待确认的"
                    "投递可以手动重试",
                    subscription_id=subscription_id, event_seq=seq,
                    status=d["status"])
            with self._tx():
                conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "next_retry_at_ms=0, dispatch_token=NULL, "
                    "claimed_at_ms=NULL, updated_at_ms=? "
                    "WHERE delivery_id=?",
                    (D_PENDING, now, d["delivery_id"]))
            return self._delivery_view(
                self._get_delivery_row(conn, d["delivery_id"]))

    # ======================================================================
    # 订阅版本切换：预创建 / 激活（原子切换）/ 取消 / 查询 / 差异
    # ======================================================================
    def prepare_version(self, subscription_id: str, *,
                        callback_url: Any = None,
                        filters: Any = None,
                        effective_seq: Any = None,
                        idempotency_key: Any = None) -> tuple[dict, bool]:
        """为活动订阅预创建下一版本（不影响任何在途通知）。

        返回 (版本视图, 是否新建)。同一幂等键重复提交且规格一致 ->
        回放同一版本（200 语义）；换回调地址/过滤条件/生效序号/目标订阅
        -> 409（给出首个差异）；生效序号越过当前稳定历史上界 -> 416，
        且原订阅与任何已有版本都不改变。
        """
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：版本创建必须携带幂等键")
        if not isinstance(callback_url, str) or not callback_url.strip() \
                or not callback_url.strip().lower().startswith(
                    ("http://", "https://")):
            raise AuditBadRequest(
                "callback_url 必填且必须是 http(s) 地址")
        url = callback_url.strip()
        key = idempotency_key.strip()
        filt = normalize_filters(filters)
        eff = _as_int(effective_seq, "effective_seq")
        if eff is None:
            raise AuditBadRequest(
                "effective_seq 必填：新版本从哪个历史序号（含）起生效")
        if eff < 0:
            raise AuditBadRequest("effective_seq 不能为负数",
                                  effective_seq=eff)

        # 稳定历史上界（与租约写入互斥地读取）
        with self._store._lock:  # noqa: SLF001
            sconn = self._store._conn  # noqa: SLF001
            max_row = sconn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = int(max_row["m"]) if max_row["m"] is not None else 0

        now = self._now()
        with self._lock:
            conn = self._conn
            sub = self._get_row(conn, subscription_id)
            if sub is None:
                raise SubscriptionNotFound(
                    f"订阅 {subscription_id} 不存在，不能创建下一版本",
                    subscription_id=subscription_id)

            # 幂等先行：同键重放或冲突（先于状态/边界校验，保证重复提交
            # 在订阅已变化后仍能稳定回放首次结果）
            prev = conn.execute(
                "SELECT * FROM audit_subscription_versions "
                "WHERE idempotency_key=?", (key,)).fetchone()
            spec = self._version_spec(subscription_id, url, filt, eff)
            if prev is not None:
                diff = self._first_version_spec_diff(prev, spec)
                if diff is None:
                    return self._version_view(prev), False
                raise self._version_conflict(conn, key, diff,
                                             version_id=prev["version_id"])
            other = self._idempotency_row(conn, key)
            if other is not None:
                raise self._idempotency_taken(conn, key, other)

            def reject_prepare(reason: str, *, code_event: str = "version_rejected",
                               exc: SubscriptionError):
                with self._tx():
                    self._audit_locked(
                        conn, subscription_id, None, code_event, "rejected",
                        reason,
                        detail_obj={"callback_url": url,
                                    "filters": filt, "effective_seq": eff},
                        now=now)
                raise exc

            if sub["status"] != SUB_ACTIVE:
                reject_prepare(
                    f"订阅当前状态为 {sub['status']}，只有 active 订阅可以"
                    "预创建下一版本",
                    exc=SubscriptionVersionBadState(
                        "订阅不是 active，不能创建下一版本",
                        subscription_id=subscription_id,
                        status=sub["status"]))
            existing = conn.execute(
                "SELECT * FROM audit_subscription_versions "
                "WHERE subscription_id=? AND status=?",
                (subscription_id, V_PREPARED)).fetchone()
            if existing is not None:
                reject_prepare(
                    f"已存在待激活版本 v{existing['version_no']}，"
                    "请先激活或取消它",
                    exc=SubscriptionVersionBadState(
                        "同一订阅同时只能有一个待激活版本",
                        subscription_id=subscription_id,
                        pending_version=int(existing["version_no"])))

            # 生效序号越过稳定历史上界：拒绝且不改变任何状态
            if eff > max_seq:
                reject_prepare(
                    f"effective_seq={eff} 越过当前稳定历史上界 {max_seq}，"
                    "该历史位置尚不存在",
                    code_event="version_rejected",
                    exc=SubscriptionVersionRangeError(
                        f"effective_seq={eff} 越过当前稳定历史上界 "
                        f"{max_seq}，原订阅未改变",
                        effective_seq=eff, available_max_seq=max_seq))

            cur_no = int(sub["current_version"])
            current = self._get_version_row(conn, subscription_id, cur_no)
            # 生效序号不得早于当前版本已经检视过的位置：否则边界前事件
            # 已经按旧过滤条件跳过，无法在不重放的前提下交给新版本
            min_eff = int(current["position_seq"])
            if eff < min_eff:
                reject_prepare(
                    f"effective_seq={eff} 早于当前版本已检视位置 "
                    f"{min_eff}，边界前事件已按旧过滤条件处理",
                    exc=SubscriptionVersionBadState(
                        f"effective_seq 不能早于当前版本扫描位置 {min_eff}",
                        subscription_id=subscription_id,
                        effective_seq=eff,
                        min_effective_seq=min_eff))

            # 新版本号取该订阅历史上最大版本号 + 1：取消的版本号不复用，
            # 否则会与已取消版本行的 (subscription_id, version_no) 唯一
            # 约束冲突，也避免旧审计记录的版本号被重新解释。
            maxrow = conn.execute(
                "SELECT MAX(version_no) AS m FROM audit_subscription_versions "
                "WHERE subscription_id=?", (subscription_id,)).fetchone()
            next_no = int(maxrow["m"] or cur_no) + 1
            version_id = uuid.uuid4().hex
            secret = new_secret()
            try:
                with self._tx():
                    conn.execute(
                        "INSERT INTO audit_subscription_versions(version_id, "
                        "subscription_id, version_no, idempotency_key, "
                        "callback_url, secret, filters_json, effective_seq, "
                        "status, position_seq, sub_seq, snapshot_seq, "
                        "created_at_ms, updated_at_ms) "
                        "VALUES(?,?,?,?,?,?,?,?,'prepared',?,0,?,?,?)",
                        (version_id, subscription_id, next_no, key, url,
                         secret, canonical_json(filt), eff, eff, max_seq,
                         now, now))
                    conn.execute(
                        "UPDATE audit_subscriptions SET pending_version=?, "
                        "updated_at_ms=? WHERE subscription_id=?",
                        (next_no, now, subscription_id))
                    self._audit_locked(
                        conn, subscription_id, next_no,
                        "version_prepared", "ok",
                        f"预创建版本 v{next_no}：effective_seq={eff}",
                        detail_obj={"callback_url": url, "filters": filt,
                                "effective_seq": eff},
                        now=now)
            except sqlite3.IntegrityError:
                # 并发同键创建兜底
                prev = conn.execute(
                    "SELECT * FROM audit_subscription_versions "
                    "WHERE idempotency_key=?", (key,)).fetchone()
                if prev is not None:
                    diff = self._first_version_spec_diff(prev, spec)
                    if diff is None:
                        return self._version_view(prev), False
                    raise self._version_conflict(conn, key, diff,
                                                 version_id=prev["version_id"])
                raise
            return self._version_view(
                self._get_version_row(conn, subscription_id, next_no)), True

    def activate_version(self, subscription_id: str, version_no: Any,
                         *, idempotency_key: Any = None) -> tuple[dict, bool]:
        """原子激活预创建版本：单事务完成新旧版本与订阅主行的切换。

        - 切换前已入队/进行中的旧版本通知继续按旧版本回调地址、密钥与
          订阅序号处理（投递行已冻结版本号，认领时按版本取地址/密钥）；
        - 生效序号之后新匹配事件只能进入新版本；
        - 同键重放回首次结果；换操作/目标订阅/版本 -> 409；
        - 订阅已取消/暂停或版本不是 prepared（已激活/已取消）-> 409；
          所有拒绝都写入订阅审计历史。
        """
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：版本激活必须携带幂等键")
        key = idempotency_key.strip()
        no = _as_int(version_no, "version_no")
        now = self._now()
        with self._lock:
            conn = self._conn
            sub = self._get_row(conn, subscription_id)
            if sub is None:
                raise SubscriptionNotFound(
                    f"订阅 {subscription_id} 不存在",
                    subscription_id=subscription_id)

            prev_op = self._idempotency_row(conn, key)
            if prev_op is not None:
                self._check_idempotency_op(
                    conn, key, prev_op, OP_ACTIVATE, subscription_id,
                    str(no))
                result = json.loads(prev_op["result_json"])
                return result, False
            # 创建版本的幂等键不能挪用于激活操作
            vprev = conn.execute(
                "SELECT version_id FROM audit_subscription_versions "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if vprev is not None:
                raise self._idempotency_taken(
                    conn, key,
                    {"operation": "prepare_version",
                     "subscription_id": subscription_id,
                     "target": vprev["version_id"]})

            def reject_activate(reason: str, exc: SubscriptionError):
                with self._tx():
                    self._audit_locked(
                        conn, subscription_id, no,
                        "version_rejected", "rejected", reason,
                        detail_obj={"operation": OP_ACTIVATE}, now=now)
                raise exc

            if sub["status"] != SUB_ACTIVE:
                reject_activate(
                    f"订阅当前状态为 {sub['status']}，不能激活新版本",
                    SubscriptionVersionBadState(
                        "订阅不是 active，不能激活新版本",
                        subscription_id=subscription_id,
                        status=sub["status"]))

            v = self._get_version_row(conn, subscription_id, no)
            if v is None:
                # 找不到目标版本不审计（没有可归属的版本号），直接 404
                raise SubscriptionVersionNotFound(
                    f"订阅 {subscription_id} 不存在版本 v{no}",
                    subscription_id=subscription_id, version_no=no)
            if v["status"] == V_ACTIVE and int(sub["current_version"]) == no:
                # 当前生效版本不能"再激活"：明确 409（真正的幂等重放必须
                # 携带首次成功时使用的同一个幂等键，在前面回放分支处理），
                # 拒绝原因写入订阅审计历史
                reject_activate(
                    f"版本 v{no} 已经是当前生效版本，无需也不能再次激活",
                    SubscriptionVersionBadState(
                        "版本已经生效，不能重复激活",
                        subscription_id=subscription_id, version_no=no,
                        status=V_ACTIVE))
            if v["status"] != V_PREPARED:
                reject_activate(
                    f"版本 v{no} 状态为 {v['status']}，只有 prepared 版本"
                    "可以激活",
                    SubscriptionVersionBadState(
                        "版本当前状态不允许激活",
                        subscription_id=subscription_id, version_no=no,
                        status=v["status"]))
            if int(sub["pending_version"] or 0) != no:
                reject_activate(
                    f"订阅待激活版本为 v{sub['pending_version']}，"
                    f"与请求的 v{no} 不一致",
                    SubscriptionVersionBadState(
                        "请求激活的版本不是订阅的待激活版本",
                        subscription_id=subscription_id, version_no=no,
                        pending_version=int(sub["pending_version"] or 0)))

            cur_no = int(sub["current_version"])
            cur = self._get_version_row(conn, subscription_id, cur_no)
            # 原子切换：以下更新一次提交，要么全成要么全不成
            with self._tx():
                conn.execute(
                    "UPDATE audit_subscription_versions SET status=?, "
                    "scan_upper_seq=?, updated_at_ms=? WHERE version_id=? "
                    "AND status=?",
                    (V_SUPERSEDED, int(v["effective_seq"]) - 1, now,
                     cur["version_id"], V_ACTIVE))
                cur = conn.execute(
                    "UPDATE audit_subscription_versions SET status=?, "
                    "activated_at_ms=?, updated_at_ms=? WHERE version_id=? "
                    "AND status=?",
                    (V_ACTIVE, now, now, v["version_id"], V_PREPARED))
                if cur.rowcount != 1:
                    raise SubscriptionVersionBadState(
                        "版本在激活过程中状态已变化（并发激活）",
                        subscription_id=subscription_id, version_no=no)
                switched = conn.execute(
                    "UPDATE audit_subscriptions SET callback_url=?, "
                    "secret=?, filters_json=?, current_version=?, "
                    "pending_version=NULL, position_seq=?, sub_seq=?, "
                    "updated_at_ms=? WHERE subscription_id=? "
                    "AND current_version=? AND pending_version=?",
                    (v["callback_url"], v["secret"], v["filters_json"],
                     no, v["position_seq"], v["sub_seq"], now,
                     subscription_id, cur_no, no))
                if switched.rowcount != 1:
                    raise SubscriptionVersionBadState(
                        "订阅在切换过程中状态已变化（并发激活）",
                        subscription_id=subscription_id, version_no=no)
                self._audit_locked(
                    conn, subscription_id, no,
                    "version_activated", "ok",
                    f"版本 v{no} 原子激活：v{cur_no} 置 superseded，"
                    f"生效序号 {v['effective_seq']}（含）起按新版本投递",
                    detail_obj={"superseded_version": cur_no,
                            "effective_seq": int(v["effective_seq"]),
                            "callback_url": v["callback_url"],
                            "filters": json.loads(v["filters_json"])},
                    now=now)
                # 幂等成功记录与切换在同一事务。注意：视图（含投递统计
                # SELECT）必须在事务提交后构建——视图辅助内部会 rollback
                # 读事务快照，在写事务内调用会把整个切换回滚掉。
                result_view = self._version_view_from_row(
                    conn,
                    self._get_version_row(conn, subscription_id, no))
                conn.execute(
                    "INSERT INTO audit_subscription_idempotency"
                    "(idempotency_key, subscription_id, operation, target, "
                    "result_json, created_at_ms) VALUES(?,?,?,?,?,?)",
                    (key, subscription_id, OP_ACTIVATE, str(no),
                     canonical_json(result_view), now))
            return self.get_version(subscription_id, no), True

    def cancel_version(self, subscription_id: str, version_no: Any,
                       *, idempotency_key: Any = None) -> tuple[dict, bool]:
        """取消预创建版本（只有 prepared 可取消；永不生效，记录保留）。"""
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：版本取消必须携带幂等键")
        key = idempotency_key.strip()
        no = _as_int(version_no, "version_no")
        now = self._now()
        with self._lock:
            conn = self._conn
            sub = self._get_row(conn, subscription_id)
            if sub is None:
                raise SubscriptionNotFound(
                    f"订阅 {subscription_id} 不存在",
                    subscription_id=subscription_id)
            prev_op = self._idempotency_row(conn, key)
            if prev_op is not None:
                self._check_idempotency_op(
                    conn, key, prev_op, OP_CANCEL, subscription_id, str(no))
                return json.loads(prev_op["result_json"]), False
            vprev = conn.execute(
                "SELECT version_id FROM audit_subscription_versions "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if vprev is not None:
                raise self._idempotency_taken(
                    conn, key,
                    {"operation": "prepare_version",
                     "subscription_id": subscription_id,
                     "target": vprev["version_id"]})

            v = self._get_version_row(conn, subscription_id, no)
            if v is None:
                raise SubscriptionVersionNotFound(
                    f"订阅 {subscription_id} 不存在版本 v{no}",
                    subscription_id=subscription_id, version_no=no)
            if v["status"] in (V_CANCELLED,):
                # 无幂等记录的重复取消（如换了键）：明确状态冲突
                raise SubscriptionVersionBadState(
                    f"版本 v{no} 已取消",
                    subscription_id=subscription_id, version_no=no,
                    status=V_CANCELLED)
            if v["status"] != V_PREPARED:
                with self._tx():
                    self._audit_locked(
                        conn, subscription_id, no,
                        "version_rejected", "rejected",
                        f"取消被拒绝：版本 v{no} 状态为 {v['status']}",
                        detail_obj={"operation": OP_CANCEL}, now=now)
                raise SubscriptionVersionBadState(
                    "只有 prepared（待激活）版本可以取消",
                    subscription_id=subscription_id, version_no=no,
                    status=v["status"])
            with self._tx():
                cur = conn.execute(
                    "UPDATE audit_subscription_versions SET status=?, "
                    "cancelled_at_ms=?, updated_at_ms=? WHERE version_id=? "
                    "AND status=?",
                    (V_CANCELLED, now, now, v["version_id"], V_PREPARED))
                if cur.rowcount != 1:
                    raise SubscriptionVersionBadState(
                        "版本在取消过程中状态已变化",
                        subscription_id=subscription_id, version_no=no)
                conn.execute(
                    "UPDATE audit_subscriptions SET pending_version=NULL, "
                    "updated_at_ms=? WHERE subscription_id=? "
                    "AND pending_version=?",
                    (now, subscription_id, no))
                self._audit_locked(
                    conn, subscription_id, no,
                    "version_cancelled", "ok",
                    f"预创建版本 v{no} 已取消，永不生效", now=now)
                result_view = self._version_view_from_row(
                    conn,
                    self._get_version_row(conn, subscription_id, no))
                conn.execute(
                    "INSERT INTO audit_subscription_idempotency"
                    "(idempotency_key, subscription_id, operation, target, "
                    "result_json, created_at_ms) VALUES(?,?,?,?,?,?)",
                    (key, subscription_id, OP_CANCEL, str(no),
                     canonical_json(result_view), now))
            return self.get_version(subscription_id, no), True

    def retry_version_dead_letters(self, subscription_id: str,
                                   version_no: Any, *,
                                   idempotency_key: Any = None
                                   ) -> tuple[dict, bool]:
        """只重试某个版本的全部死信（复位尝试次数，立即重试）。

        幂等：同键重放回首次结果；换操作/目标订阅/版本 -> 409。重试只
        改该版本的死信行，严格顺序仍由共享队首约束保证（旧版本未确认
        通知与新版本通知不会互相越过）。
        """
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：版本死信重试必须携带幂等键")
        key = idempotency_key.strip()
        no = _as_int(version_no, "version_no")
        now = self._now()
        with self._lock:
            conn = self._conn
            sub = self._get_row(conn, subscription_id)
            if sub is None:
                raise SubscriptionNotFound(
                    f"订阅 {subscription_id} 不存在",
                    subscription_id=subscription_id)
            prev_op = self._idempotency_row(conn, key)
            if prev_op is not None:
                self._check_idempotency_op(
                    conn, key, prev_op, OP_RETRY_DEAD, subscription_id,
                    str(no))
                return json.loads(prev_op["result_json"]), False
            vprev = conn.execute(
                "SELECT version_id FROM audit_subscription_versions "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if vprev is not None:
                raise self._idempotency_taken(
                    conn, key,
                    {"operation": "prepare_version",
                     "subscription_id": subscription_id,
                     "target": vprev["version_id"]})

            v = self._get_version_row(conn, subscription_id, no)
            if v is None:
                raise SubscriptionVersionNotFound(
                    f"订阅 {subscription_id} 不存在版本 v{no}",
                    subscription_id=subscription_id, version_no=no)
            with self._tx():
                cur = conn.execute(
                    "UPDATE audit_subscription_deliveries SET status=?, "
                    "attempts=0, next_retry_at_ms=0, dispatch_token=NULL, "
                    "claimed_at_ms=NULL, last_error=NULL, "
                    "dead_letter_reason=NULL, updated_at_ms=? "
                    "WHERE subscription_id=? AND version_no=? AND status=?",
                    (D_PENDING, now, subscription_id, no, D_DEAD))
                requeued = cur.rowcount
                self._clear_blocked_locked(conn, subscription_id, now)
                self._audit_locked(
                    conn, subscription_id, no,
                    "version_retry", "ok",
                    f"重试版本 v{no} 的 {requeued} 条死信",
                    detail_obj={"requeued": requeued}, now=now)
                result = {
                    "subscription_id": subscription_id,
                    "version_no": no,
                    "requeued": requeued,
                }
                conn.execute(
                    "INSERT INTO audit_subscription_idempotency"
                    "(idempotency_key, subscription_id, operation, target, "
                    "result_json, created_at_ms) VALUES(?,?,?,?,?,?)",
                    (key, subscription_id, OP_RETRY_DEAD, str(no),
                     canonical_json(result), now))
            return result, True

    # ---- 版本查询 / 差异 / 订阅审计历史 --------------------------------
    def list_versions(self, subscription_id: str, *,
                      status: Any = None, limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        if status is not None and status not in (
                V_PREPARED, V_ACTIVE, V_SUPERSEDED, V_CANCELLED):
            raise AuditBadRequest("status 过滤值非法", status=status)
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_sub(conn, subscription_id)
            if status:
                rows = conn.execute(
                    "SELECT * FROM audit_subscription_versions "
                    "WHERE subscription_id=? AND status=? "
                    "ORDER BY version_no ASC LIMIT ?",
                    (subscription_id, status, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_subscription_versions "
                    "WHERE subscription_id=? ORDER BY version_no ASC LIMIT ?",
                    (subscription_id, limit)).fetchall()
            conn.rollback()
            return {"subscription_id": subscription_id,
                    "versions": [self._version_view(r) for r in rows],
                    "limit": limit}

    def get_version(self, subscription_id: str, version_no: Any) -> dict:
        no = _as_int(version_no, "version_no")
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_sub(conn, subscription_id)
            v = self._get_version_row(conn, subscription_id, no)
            conn.rollback()
            if v is None:
                raise SubscriptionVersionNotFound(
                    f"订阅 {subscription_id} 不存在版本 v{no}",
                    subscription_id=subscription_id, version_no=no)
            return self._version_view(v)

    def diff_version(self, subscription_id: str, version_no: Any,
                     *, base_version: Any = None) -> dict[str, Any]:
        """比较某版本与其基线版本（默认当前生效版本）的差异。"""
        no = _as_int(version_no, "version_no")
        with self._lock:
            conn = self._conn
            conn.rollback()
            sub = self._require_sub(conn, subscription_id)
            base_no = (int(sub["current_version"])
                       if base_version in (None, "")
                       else _as_int(base_version, "base_version"))
            v = self._get_version_row(conn, subscription_id, no)
            if v is None:
                raise SubscriptionVersionNotFound(
                    f"订阅 {subscription_id} 不存在版本 v{no}",
                    subscription_id=subscription_id, version_no=no)
            b = self._get_version_row(conn, subscription_id, base_no)
            if b is None:
                raise SubscriptionVersionNotFound(
                    f"订阅 {subscription_id} 不存在基线版本 v{base_no}",
                    subscription_id=subscription_id,
                    version_no=base_no)
            diffs = self._version_diff_fields(b, v)
            conn.rollback()
            return {
                "subscription_id": subscription_id,
                "base_version": base_no,
                "target_version": no,
                "identical": not diffs,
                "differences": diffs,
                "base": {"version_no": base_no,
                         "callback_url": b["callback_url"],
                         "filters": json.loads(b["filters_json"]),
                         "effective_seq": int(b["effective_seq"])},
                "target": {"version_no": no,
                           "callback_url": v["callback_url"],
                           "filters": json.loads(v["filters_json"]),
                           "effective_seq": int(v["effective_seq"])},
            }

    def list_audit_history(self, subscription_id: str, *,
                           after_id: Any = None, limit: Any = 100,
                           event: Any = None) -> dict[str, Any]:
        """分页读取该订阅自己的审计历史（只追加：版本创建/激活/拒绝/
        取消/重试），游标是自增 id，升序。"""
        limit = _bounded_limit(limit)
        after = _as_int(after_id, "after_id", default=0)
        if after < 0:
            raise AuditBadRequest("after_id 不能为负数", after_id=after)
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_sub(conn, subscription_id)
            where = ["subscription_id=?"]
            args: list[Any] = [subscription_id]
            if after:
                where.append("id>?")
                args.append(after)
            if event:
                where.append("event=?")
                args.append(str(event))
            rows = conn.execute(
                "SELECT * FROM audit_subscription_events WHERE "
                + " AND ".join(where)
                + " ORDER BY id ASC LIMIT ?", (*args, limit + 1)).fetchall()
            conn.rollback()
        page = rows[:limit]
        has_more = len(rows) > limit
        return {
            "subscription_id": subscription_id,
            "events": [self._audit_view(r) for r in page],
            "limit": limit,
            "next": page[-1]["id"] if has_more else None,
            "reached_end": not has_more,
        }

    # ---- 版本辅助 -------------------------------------------------------
    @staticmethod
    def _get_version_row(conn, subscription_id: str, version_no: int):
        return conn.execute(
            "SELECT * FROM audit_subscription_versions "
            "WHERE subscription_id=? AND version_no=?",
            (subscription_id, int(version_no))).fetchone()

    @staticmethod
    def _idempotency_row(conn, key: str):
        return conn.execute(
            "SELECT * FROM audit_subscription_idempotency "
            "WHERE idempotency_key=?", (key,)).fetchone()

    def _check_idempotency_op(self, conn, key: str, prev, operation: str,
                              subscription_id: str, target: str) -> None:
        """命中操作幂等日志：规格一致回放，否则明确 409（给双方值）。"""
        if (prev["operation"] == operation
                and prev["subscription_id"] == subscription_id
                and prev["target"] == target):
            return
        raise SubscriptionVersionConflict(
            f"幂等键 {key} 已用于订阅 {prev['subscription_id']} 的 "
            f"{prev['operation']} 操作（目标 {prev['target']}），"
            "本次请求与首次不一致",
            idempotency_key=key,
            first_difference={
                "path": "operation/target",
                "existing": {"operation": prev["operation"],
                             "subscription_id": prev["subscription_id"],
                             "target": prev["target"]},
                "requested": {"operation": operation,
                              "subscription_id": subscription_id,
                              "target": target}})

    @staticmethod
    def _idempotency_taken(conn, key: str, other) -> SubscriptionVersionConflict:
        """幂等键被另一类订阅操作占用（如创建键用于激活）。"""
        if isinstance(other, dict):
            op = other.get("operation")
            existing = other
        else:
            # sqlite3.Row（audit_subscription_idempotency 命中行）
            op = other["operation"]
            existing = {"operation": other["operation"],
                        "subscription_id": other["subscription_id"],
                        "target": other["target"]}
        return SubscriptionVersionConflict(
            f"幂等键 {key} 已用于订阅的 {op or '其它'} 操作，"
            "不能复用于本次请求",
            idempotency_key=key,
            first_difference={"path": "operation",
                              "existing": existing,
                              "requested": {}})

    @staticmethod
    def _version_conflict(conn, key: str, diff: dict, *,
                          version_id: str) -> SubscriptionVersionConflict:
        return SubscriptionVersionConflict(
            f"幂等键 {key} 已用于版本 {version_id}，本次请求与首次创建"
            f"不一致：首个差异位于 {diff['path']}",
            idempotency_key=key, version_id=version_id,
            first_difference=diff)

    @staticmethod
    def _version_spec(subscription_id: str, url: str, filt: dict,
                      eff: int) -> dict[str, Any]:
        return {"subscription_id": subscription_id, "callback_url": url,
                "filters": filt, "effective_seq": eff}

    @staticmethod
    def _first_version_spec_diff(prev, spec: dict) -> dict | None:
        """逐个比较版本创建规格，返回首个差异字段（确定性顺序）。"""
        fields = [
            ("subscription_id", prev["subscription_id"],
             spec["subscription_id"]),
            ("callback_url", prev["callback_url"], spec["callback_url"]),
            ("effective_seq", int(prev["effective_seq"]),
             spec["effective_seq"]),
        ]
        for path, old, new in fields:
            if old != new:
                return {"path": path, "existing": old, "requested": new}
        old_filters = json.loads(prev["filters_json"])
        if old_filters != spec["filters"]:
            return {"path": "filters", "existing": old_filters,
                    "requested": spec["filters"]}
        return None

    @staticmethod
    def _version_diff_fields(base, target) -> list[dict]:
        """返回两个版本之间全部规格差异（确定性顺序）。"""
        out: list[dict] = []
        for path, old, new in (
                ("callback_url", base["callback_url"],
                 target["callback_url"]),
                ("effective_seq", int(base["effective_seq"]),
                 int(target["effective_seq"]))):
            if old != new:
                out.append({"path": path, "existing": old,
                            "requested": new})
        bf = json.loads(base["filters_json"])
        tf = json.loads(target["filters_json"])
        if bf != tf:
            out.append({"path": "filters", "existing": bf,
                        "requested": tf})
        return out

    def _version_view(self, v) -> dict[str, Any]:
        """版本视图（自带取连接/锁，内部结束只读快照——禁止在写事务内调用）。"""
        with self._lock:
            conn = self._conn
            view = self._version_view_from_row(conn, v)
            conn.rollback()
        return view

    def _version_view_from_row(self, conn, v) -> dict[str, Any]:
        """在给定连接/事务上构建版本视图（不提交、不回滚，可在写事务内调用）。"""
        stats = conn.execute(
            "SELECT "
            "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS confirmed, "
            "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS dead, "
            "SUM(CASE WHEN status IN (?,?,?) THEN 1 ELSE 0 END) AS open, "
            "MAX(CASE WHEN status IN (?,?,?) THEN event_seq ELSE NULL END) "
            "AS max_open_seq "
            "FROM audit_subscription_deliveries "
            "WHERE subscription_id=? AND version_no=?",
            (D_CONFIRMED, D_DEAD, *D_OPEN, *D_OPEN,
             v["subscription_id"], v["version_no"])).fetchone()
        open_seq = stats["max_open_seq"]
        return {
            "version_id": v["version_id"],
            "subscription_id": v["subscription_id"],
            "version_no": int(v["version_no"]),
            "idempotency_key": v["idempotency_key"],
            "status": v["status"],
            "callback_url": v["callback_url"],
            "filters": json.loads(v["filters_json"]),
            "effective_seq": int(v["effective_seq"]),
            "position_seq": int(v["position_seq"]),
            "subscription_seq_next": int(v["sub_seq"]) + 1,
            "snapshot_seq": int(v["snapshot_seq"]),
            "deliveries": {
                "confirmed": int(stats["confirmed"] or 0),
                "dead_letter": int(stats["dead"] or 0),
                "in_flight_or_pending": int(stats["open"] or 0),
            },
            # superseded 旧版本是否还有未完成通知：清空后旧版本收尾结束
            "drained": int(stats["open"] or 0) == 0,
            "last_open_event_seq": (int(open_seq)
                                    if open_seq is not None else None),
            "reject_reason": v["reject_reason"],
            "created_at_ms": v["created_at_ms"],
            "updated_at_ms": v["updated_at_ms"],
            "activated_at_ms": v["activated_at_ms"],
            "cancelled_at_ms": v["cancelled_at_ms"],
        }

    @staticmethod
    def _audit_view(r) -> dict[str, Any]:
        return {
            "id": r["id"],
            "subscription_id": r["subscription_id"],
            "version_no": (int(r["version_no"])
                           if r["version_no"] is not None else None),
            "event": r["event"],
            "outcome": r["outcome"],
            "detail": r["detail"],
            "detail_json": (json.loads(r["detail_json"])
                            if r["detail_json"] else None),
            "created_at_ms": r["created_at_ms"],
        }

    def _audit_locked(self, conn, subscription_id: str,
                      version_no: int | None, event: str, outcome: str,
                      detail: str | None = None, *,
                      detail_obj: dict | None = None,
                      now: int | None = None) -> None:
        """在订阅自己的审计历史只追加一行（调用方已持锁/在事务内）。

        绝不写 lease_events、租约、委托或投递记录。
        """
        conn.execute(
            "INSERT INTO audit_subscription_events(subscription_id, "
            "version_no, event, outcome, detail, detail_json, created_at_ms) "
            "VALUES(?,?,?,?,?,?,?)",
            (subscription_id, version_no, event, outcome, detail,
             canonical_json(detail_obj) if detail_obj is not None else None,
             now if now is not None else self._now()))

    # ======================================================================
    # 查询：订阅 / 投递历史（分页）
    # ======================================================================
    def get_subscription(self, subscription_id: str) -> dict[str, Any]:
        with self._lock:
            conn = self._conn
            # 显式结束可能残留的只读事务，确保看到其它连接（写入事务）
            # 的最新已提交视图（WAL 下长读连接会停在旧快照）
            conn.rollback()
            row = self._require_sub(conn, subscription_id)
            view = self._view(row)
            conn.rollback()
            return view

    def list_subscriptions(self, *, scope: Any = None, status: Any = None,
                           limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        if scope is not None and scope not in SCOPES:
            raise AuditBadRequest("scope 取值非法", scope=scope)
        if status is not None and status not in SUB_STATUSES:
            raise AuditBadRequest(
                "status 只能取 active / paused / cancelled", status=status)
        where, args = [], []
        if scope:
            where.append("scope=?")
            args.append(scope)
        if status:
            where.append("status=?")
            args.append(status)
        sql = "SELECT * FROM audit_subscriptions"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at_ms ASC, subscription_id ASC LIMIT ?"
        with self._lock:
            conn = self._conn
            conn.rollback()  # 取最新已提交视图（勿停在旧 WAL 快照）
            rows = conn.execute(sql, (*args, limit)).fetchall()
            views = [self._view(r) for r in rows]
            conn.rollback()
            return {"subscriptions": views, "limit": limit}

    def list_deliveries(self, subscription_id: str, *,
                        after_seq: Any = None, status: Any = None,
                        version_no: Any = None,
                        limit: Any = 100) -> dict[str, Any]:
        """分页读取订阅投递历史（按 event_seq 升序，游标是 event_seq）。

        可传 ``version_no`` 只看某一版本（切换前后）的投递与失败记录。
        """
        limit = _bounded_limit(limit)
        after = _as_int(after_seq, "after", default=0)
        if after < 0:
            raise AuditBadRequest("after 不能为负数", after=after)
        ver = _as_int(version_no, "version_no") if version_no not in (
            None, "") else None
        if status is not None and status not in (
                D_PENDING, D_INFLIGHT, D_AWAITING, D_CONFIRMED, D_DEAD,
                D_DISCARDED):
            raise AuditBadRequest("status 过滤值非法", status=status)
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_sub(conn, subscription_id)
            where = ["subscription_id=?"]
            args: list[Any] = [subscription_id]
            if after:
                where.append("event_seq>?")
                args.append(after)
            if status:
                where.append("status=?")
                args.append(status)
            if ver is not None:
                where.append("version_no=?")
                args.append(ver)
            rows = conn.execute(
                "SELECT * FROM audit_subscription_deliveries WHERE "
                + " AND ".join(where)
                + " ORDER BY event_seq ASC LIMIT ?",
                (*args, limit + 1)).fetchall()
            conn.rollback()
        page = rows[:limit]
        has_more = len(rows) > limit
        return {
            "subscription_id": subscription_id,
            "version_no": ver,
            "deliveries": [self._delivery_view(r) for r in page],
            "limit": limit,
            "next": page[-1]["event_seq"] if has_more else None,
            "reached_end": not has_more,
        }

    def get_delivery(self, subscription_id: str,
                     event_seq: Any) -> dict[str, Any]:
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_sub(conn, subscription_id)
            seq = _as_int(event_seq, "event_seq")
            d = conn.execute(
                "SELECT * FROM audit_subscription_deliveries "
                "WHERE subscription_id=? AND event_seq=?",
                (subscription_id, seq)).fetchone()
            conn.rollback()
            if d is None:
                raise DeliveryNotFound(
                    f"订阅 {subscription_id} 没有事件 seq={seq} 的投递记录",
                    subscription_id=subscription_id, event_seq=seq)
            return self._delivery_view(d)

    # ---- 视图 -----------------------------------------------------------
    def _require_sub(self, conn, subscription_id: str):
        row = self._get_row(conn, subscription_id)
        if row is None:
            raise SubscriptionNotFound(
                f"订阅 {subscription_id} 不存在",
                subscription_id=subscription_id)
        return row

    @staticmethod
    def _get_row(conn, subscription_id: str):
        return conn.execute(
            "SELECT * FROM audit_subscriptions WHERE subscription_id=?",
            (subscription_id,)).fetchone()

    @staticmethod
    def _get_delivery_row(conn, delivery_id: str):
        return conn.execute(
            "SELECT * FROM audit_subscription_deliveries WHERE delivery_id=?",
            (delivery_id,)).fetchone()

    def _clear_blocked_locked(self, conn, subscription_id: str,
                              now: int) -> None:
        """该订阅已无 dead_letter 挡队时清除 blocked 标记与错误说明。"""
        dead = conn.execute(
            "SELECT COUNT(*) AS c FROM audit_subscription_deliveries "
            "WHERE subscription_id=? AND status=?",
            (subscription_id, D_DEAD)).fetchone()["c"]
        if not dead:
            conn.execute(
                "UPDATE audit_subscriptions SET blocked=0, error=NULL, "
                "updated_at_ms=? WHERE subscription_id=? AND blocked=1",
                (now, subscription_id))

    def _view(self, row) -> dict[str, Any]:
        with self._lock:
            conn = self._conn
            stats = conn.execute(
                "SELECT "
                "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS confirmed, "
                "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS dead, "
                "SUM(CASE WHEN status IN (?,?,?) THEN 1 ELSE 0 END) AS open, "
                "MAX(CASE WHEN status=? THEN event_seq ELSE NULL END) "
                "AS last_confirmed_seq "
                "FROM audit_subscription_deliveries WHERE subscription_id=?",
                (D_CONFIRMED, D_DEAD, *D_OPEN, D_CONFIRMED,
                 row["subscription_id"])).fetchone()
            versions = conn.execute(
                "SELECT * FROM audit_subscription_versions "
                "WHERE subscription_id=? ORDER BY version_no ASC",
                (row["subscription_id"],)).fetchall()
            conn.rollback()
        return {
            "subscription_id": row["subscription_id"],
            "idempotency_key": row["idempotency_key"],
            "scope": row["scope"],
            "object": self._object_ref(row),
            "callback_url": row["callback_url"],
            "filters": json.loads(row["filters_json"]),
            "start_seq": row["start_seq"],
            "position_seq": row["position_seq"],
            "next_event_seq": row["position_seq"],
            "delivered_seq": (int(stats["last_confirmed_seq"])
                              if stats["last_confirmed_seq"] is not None
                              else None),
            "subscription_seq_next": row["sub_seq"] + 1,
            "snapshot_seq": row["snapshot_seq"],
            "current_version": int(row["current_version"]),
            "pending_version": (int(row["pending_version"])
                                if row["pending_version"] is not None
                                else None),
            "versions": [self._version_view(v) for v in versions],
            "status": row["status"],
            "blocked": bool(row["blocked"]),
            "max_attempts": row["max_attempts"],
            "ack_required": bool(row["ack_required"]),
            "error": row["error"],
            "counters": {
                "confirmed": int(stats["confirmed"] or 0),
                "dead_letter": int(stats["dead"] or 0),
                "in_flight_or_pending": int(stats["open"] or 0),
            },
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
            "cancelled_at_ms": row["cancelled_at_ms"],
        }

    def _delivery_view(self, d, *, replayed: bool = False) -> dict[str, Any]:
        payload = json.loads(d["payload_json"])
        # next_retry_at_ms 存的是退避时长；退避中的 pending 行换算出
        # 绝对下次重试时刻，其余状态给 None
        next_abs = None
        if d["status"] == D_PENDING and (d["next_retry_at_ms"] or 0) > 0:
            next_abs = int(d["updated_at_ms"]) + int(d["next_retry_at_ms"])
        keys = d.keys()
        return {
            "delivery_id": d["delivery_id"],
            "subscription_id": d["subscription_id"],
            "event_seq": d["event_seq"],
            "subscription_seq": d["subscription_seq"],
            "version_no": (int(d["version_no"]) if "version_no" in keys
                           else int(payload.get("version_no", 1))),
            "signing_key_id": (d["signing_key_id"]
                               if "signing_key_id" in keys else None),
            "status": d["status"],
            "attempts": d["attempts"],
            "backoff_ms": d["next_retry_at_ms"] or None,
            "next_retry_at_ms": next_abs,
            "claimed_at_ms": d["claimed_at_ms"],
            "last_error": d["last_error"],
            "dead_letter_reason": d["dead_letter_reason"],
            "confirmed_at_ms": d["confirmed_at_ms"],
            "replayed": replayed,
            "notification": {
                "event_type": payload["event_type"],
                "object_id": payload["object_id"],
                "summary": payload["summary"],
                "wall_ms": payload["wall_ms"],
            },
            "signature": d["signature"],
            "created_at_ms": d["created_at_ms"],
            "updated_at_ms": d["updated_at_ms"],
        }


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def store_db_path(store: Any) -> str:
    """从 Store 连接反查数据库文件路径（独立连接复用同一 WAL 库）。"""
    row = store._conn.execute(  # noqa: SLF001
        "PRAGMA database_list").fetchone()  # noqa: SLF001
    return row[2]


def require_value(value: Any, name: str) -> str:
    if value in (None, ""):
        raise AuditBadRequest(f"缺少必填参数: {name}")
    return value


def _as_int(value, name: str, *, default=None):
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise AuditBadRequest(f"参数 {name} 必须是整数", **{name: value})


def _bounded_limit(value) -> int:
    limit = _as_int(value, "limit", default=100)
    if limit < 1:
        raise AuditBadRequest("limit 必须 >= 1", limit=limit)
    return min(limit, 1000)
