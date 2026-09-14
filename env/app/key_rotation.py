"""订阅通知签名密钥轮换与验证（signing-key rotation & verification）。

在审计变更订阅与可靠通知能力之上，管理员可以为一个**活动**订阅预登记
下一把签名密钥（指纹、生效历史序号、宽限期），随后原子生效：

1. **生效前的通知继续使用旧密钥**：预登记（prepared）期间当前生效密钥
   不变；生效序号之前已入队/认领中的投递行冻结了它的 ``signing_key_id``，
   继续按旧密钥签名，等待显式确认的旧通知仍按旧密钥完成确认。
2. **生效序号之后的新通知必须使用新密钥**：生效（activated）后，所有
   ``event_seq >= effective_seq`` 的新投递都以新密钥签名。
3. **宽限期（grace）**：宽限窗口内收到的、用**旧密钥**做的显式确认仍然
   接受（旧通知宽限确认）；窗口结束（并完成恢复收敛）后旧密钥确认一律
   拒绝。首次轮换被替换的是版本冻结密钥（没有自己的密钥行，窗口挂在
   key_no=1 的行上，宽限为 0 立即退役）。新密钥确认不受宽限期影响。
4. **幂等**：预登记/生效/撤销/重签都带幂等键。同一幂等键改变密钥指纹、
   生效序号、宽限期或目标订阅必须返回明确冲突（409，给出首个差异）；
   省略密钥材料由服务端生成密钥时，完全相同的幂等请求回放第一次的密钥
   记录（服务端只在确认是新请求时生成一次随机密钥）；生效序号越过稳定
   历史或早于已扫描位置时拒绝且不改变当前密钥。
5. **验证与重签**：管理员可按密钥与时间范围分页查询投递签名验证结果；
   只对验证失败的**指定密钥**投递执行重新签名（幂等）。重签不改写已有
   投递记录的任何字段（签名、updated_at_ms、状态、尝试次数全部保持
   原值）：新签名只追加进验证表自有行（resigned 记录的 new_signature），
   不重置确认、不产生重复投递、不改变严格顺序。
6. **可恢复**：重启或轮换中断后从已保存状态继续，不重复确认、不跳过
   通知。宽限到期（含首次轮换被替换的版本冻结密钥——它没有自己的密钥
   行，宽限窗口挂在 key_no=1 的轮换密钥上）在构造、确认路径与显式恢复
   时惰性收敛退役。所有轮换事件与拒绝原因只追加进订阅自己的审计历史
   （``audit_subscription_events``），绝不改写租约、委托、原始审计事件、
   版本行或已有投递记录（投递表只追加 signing_key_id 列；重签的新签名
   只写验证表自有行）。

密钥轮换与订阅版本切换是两条**正交**的能力：版本切换更换回调地址/过滤/
版本密钥并按版本分段，密钥轮换则在当前版本密钥之外叠加一层"签名密钥
代际"。投递行新增 ``signing_key_id`` 列：旧库/旧行该列为 NULL，验证与
签名一律回退到投递行所属版本冻结的密钥，行为与轮换特性引入前完全一致。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from .archive import ArchiveError, canonical_json
from .audit import AuditBadRequest
from .subscription import (
    D_AWAITING,
    D_CONFIRMED,
    D_DEAD,
    D_OPEN,
    SUB_ACTIVE,
    SubscriptionManager,
    SubscriptionNotFound,
    _as_int,
    _bounded_limit,
    new_secret,
    sign_payload,
    store_db_path,
    verify_signature,
)

# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class KeyRotationError(ArchiveError):
    code = "key_rotation_error"


class KeyRotationNotFound(KeyRotationError):
    """订阅或密钥轮换不存在（404）。"""

    code = "key_rotation_not_found"
    status = 404


class KeyRotationIdConflict(KeyRotationError):
    """密钥操作的幂等键被参数不同的请求占用（409）。"""

    code = "key_rotation_id_conflict"
    status = 409


class KeyRotationConflict(KeyRotationError):
    """幂等键被另一类订阅/轮换操作占用（409）。"""

    code = "key_rotation_conflict"
    status = 409


class KeyRotationBadState(KeyRotationError):
    """订阅/轮换当前状态不允许该操作（409）。"""

    code = "key_rotation_bad_state"
    status = 409


class KeyRotationRangeError(KeyRotationError):
    """生效序号越过当前稳定历史上界（416），当前密钥不改变。"""

    code = "key_rotation_seq_out_of_range"
    status = 416


class KeyVerificationNotFound(KeyRotationError):
    """指定密钥下没有该投递验证记录（404）。"""

    code = "key_verification_not_found"
    status = 404


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 轮换状态
K_PREPARED = "prepared"          # 预登记，等待生效
K_ACTIVE = "active"              # 已生效：新通知使用该密钥
K_GRACE = "grace"                # 生效且宽限未结束：旧密钥确认仍接受
K_RETIRED = "retired"            # 宽限结束：旧密钥彻底退役
K_REVOKED = "revoked"            # 预登记被撤销，永不生效

# 一次订阅至多有一个待生效（prepared）轮换
K_PENDING_STATUSES = (K_PREPARED,)

# 幂等日志中的操作类型
OP_KEY_PREPARE = "prepare_key"
OP_KEY_ACTIVATE = "activate_key"
OP_KEY_REVOKE = "revoke_key"
OP_KEY_RESIGN = "resign_delivery"

# 验证结果（只追加，不改投递状态）
V_OK = "ok"                       # 签名与当前应使用的密钥一致
V_FAILED = "failed"               # 签名与应使用的密钥不一致
V_OLD_KEY_GRACE = "old_key_grace"  # 宽限期内用旧密钥确认，接受
V_RESIGNED = "resigned"           # 管理员重签后重新验证通过

DEFAULT_GRACE_MS = 0


def secret_fingerprint(secret: str) -> str:
    """密钥指纹：对密钥本身做 SHA-256（密钥不明文出现在任何 API 响应）。"""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 密钥轮换管理器
# ---------------------------------------------------------------------------


class KeyRotationManager:
    """签名密钥的预登记、生效、撤销、宽限退役、验证查询与重签。

    与 :class:`SubscriptionManager` 共享同一 WAL 数据库（独立连接、独立
    进程锁；写事务 BEGIN IMMEDIATE 串行化）。对租约侧表只做 SELECT，
    投递/版本表通过订阅管理器的既有不变量访问，自有状态只写
    ``audit_subscription_signing_keys`` /
    ``audit_subscription_key_idempotency`` /
    ``audit_subscription_signature_verifications`` 三张表。
    """

    def __init__(self, store: Any, subscriptions: SubscriptionManager):
        self._store = store
        self._subs = subscriptions
        import sqlite3 as _sqlite3

        self._lock = threading.RLock()
        self._conn = _sqlite3.connect(store_db_path(store),
                                      check_same_thread=False,
                                      isolation_level=None)
        self._conn.row_factory = _sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._ensure_schema()
        # 构造即恢复：把崩溃中断在半切换状态的轮换收敛，并把已过宽限期
        # 的旧密钥置为 retired（不重复确认、不跳过通知）。
        self.recover_interruptions()

    # ---- 建表 / 时钟 / 事务 ---------------------------------------------
    def _ensure_schema(self) -> None:
        """幂等创建密钥轮换自有表，并为既有投递行补 signing_key_id 列。"""
        conn = self._conn
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_subscription_signing_keys (
                key_id            TEXT PRIMARY KEY,
                subscription_id   TEXT NOT NULL,
                key_no            INTEGER NOT NULL,
                idempotency_key   TEXT NOT NULL,
                secret            TEXT NOT NULL,
                fingerprint       TEXT NOT NULL,
                effective_seq     INTEGER NOT NULL,
                grace_ms          INTEGER NOT NULL DEFAULT 0,
                status            TEXT NOT NULL DEFAULT 'prepared',
                replaces_key_id   TEXT,
                snapshot_seq      INTEGER NOT NULL,
                activated_at_ms   INTEGER,
                grace_until_ms    INTEGER,
                retired_at_ms     INTEGER,
                revoked_at_ms     INTEGER,
                reject_reason     TEXT,
                version_key_grace_until_ms INTEGER,
                version_key_retired_at_ms  INTEGER,
                created_at_ms     INTEGER NOT NULL,
                updated_at_ms     INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_signkey_no
                ON audit_subscription_signing_keys(subscription_id, key_no);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_signkey_idem
                ON audit_subscription_signing_keys(idempotency_key);
            CREATE INDEX IF NOT EXISTS idx_signkey_status
                ON audit_subscription_signing_keys(subscription_id, status);
            CREATE TABLE IF NOT EXISTS audit_subscription_key_idempotency (
                idempotency_key   TEXT PRIMARY KEY,
                subscription_id   TEXT NOT NULL,
                operation         TEXT NOT NULL,
                target            TEXT NOT NULL,
                result_json       TEXT NOT NULL,
                created_at_ms     INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_subscription_signature_verifications (
                verification_id   TEXT PRIMARY KEY,
                subscription_id   TEXT NOT NULL,
                delivery_id       TEXT NOT NULL,
                event_seq         INTEGER NOT NULL,
                key_id            TEXT NOT NULL,
                expected_key_id   TEXT,
                result            TEXT NOT NULL,
                detail            TEXT,
                new_signature     TEXT,
                created_at_ms     INTEGER NOT NULL,
                dedupe_key        TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_sigver_dedupe
                ON audit_subscription_signature_verifications(dedupe_key);
            CREATE INDEX IF NOT EXISTS idx_sigver_key_time
                ON audit_subscription_signature_verifications(
                    subscription_id, key_id, created_at_ms, event_seq);
            """)
        # 既有投递行增量列：签名使用的签名密钥代际。NULL 表示轮换特性
        # 引入前的行，签名/验证回退到版本冻结密钥（历史行为不变）。
        dcols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(audit_subscription_deliveries)").fetchall()}
        if "signing_key_id" not in dcols:
            conn.execute(
                "ALTER TABLE audit_subscription_deliveries "
                "ADD COLUMN signing_key_id TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_delivery_signkey "
            "ON audit_subscription_deliveries(subscription_id, signing_key_id)")
        # 既有密钥行增量列：首次轮换时版本冻结密钥的宽限窗口与退役时刻。
        # 首次轮换把版本密钥替换为第一把轮换密钥；这两列只挂在 key_no=1
        # 的行上，到期由 recover_interruptions 置退役标记。
        kcols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(audit_subscription_signing_keys)").fetchall()}
        if "version_key_grace_until_ms" not in kcols:
            conn.execute(
                "ALTER TABLE audit_subscription_signing_keys "
                "ADD COLUMN version_key_grace_until_ms INTEGER")
        if "version_key_retired_at_ms" not in kcols:
            conn.execute(
                "ALTER TABLE audit_subscription_signing_keys "
                "ADD COLUMN version_key_retired_at_ms INTEGER")
        # 既有验证行增量列：重签产生的新签名只追加在自有验证表，绝不改写
        # 已有投递记录的任何字段。
        vcols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(audit_subscription_signature_verifications)"
        ).fetchall()}
        if "new_signature" not in vcols:
            conn.execute(
                "ALTER TABLE audit_subscription_signature_verifications "
                "ADD COLUMN new_signature TEXT")
        conn.commit()

    def _now(self) -> int:
        return self._store.clock.wall_ms()

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ======================================================================
    # 预登记
    # ======================================================================
    def prepare_key(self, subscription_id: str, *,
                    secret: Any = None,
                    fingerprint: Any = None,
                    effective_seq: Any = None,
                    grace_ms: Any = None,
                    idempotency_key: Any = None) -> tuple[dict[str, Any], bool]:
        """为活动订阅预登记下一把签名密钥。

        - 密钥来源：``secret`` 给定则用它（必须为非空十六进制/字符串），
          省略时由服务端生成 32 字节随机密钥（API 永不回传密钥明文，
          只回传 SHA-256 指纹）；可同时给 ``fingerprint`` 做一致性校验，
          指纹必须等于 ``sha256(secret)``，否则 400。服务端生成只发生在
          确认是新请求之后，因此省略密钥材料的完全相同幂等请求重放第一
          次的密钥记录，只有显式改变指纹/序号/宽限期/订阅才冲突；
        - ``effective_seq``（含）必填，不能越过当前稳定历史上界（416），
          也不能早于当前版本已扫描位置（409），拒绝时当前密钥不变；
        - 同一幂等键改变指纹/生效序号/宽限期/目标订阅 → 409 明确冲突。

        返回 (密钥视图, 是否新建)。
        """
        sid = str(require_value(subscription_id, "subscription_id"))
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：密钥预登记必须携带幂等键")
        key = idempotency_key.strip()
        eff = _as_int(effective_seq, "effective_seq")
        if eff is None:
            raise AuditBadRequest(
                "effective_seq 必填：新密钥从哪个历史序号（含）起生效")
        if eff < 0:
            raise AuditBadRequest("effective_seq 不能为负数",
                                  effective_seq=eff)
        grace = _as_int(grace_ms, "grace_ms", default=DEFAULT_GRACE_MS)
        if grace < 0:
            raise AuditBadRequest("grace_ms 不能为负数", grace_ms=grace)

        # 先解析调用方显式提供的密钥材料：只给 fingerprint 不给 secret 永远
        # 无法服务端签名（400）；给了 secret 则此刻算出指纹用于规格比较。
        # 省略 secret/fingerprint 时密钥由服务端生成——必须**延迟到幂等回放
        # 判定之后**，否则完全相同的幂等请求第二次会生成另一把随机密钥，
        # 指纹不一致而误报 409（应回放首次的密钥记录）。
        sec_in = secret.strip() if isinstance(
            secret, str) and secret.strip() else None
        fp_in = fingerprint.strip() if isinstance(
            fingerprint, str) and fingerprint.strip() else None
        if sec_in is None and fp_in is not None:
            raise AuditBadRequest(
                "只提供 fingerprint 而不提供 secret 时无法签名：通知"
                "签名必须由服务端持有密钥；请同时提供与 "
                "sha256(secret) 一致的 fingerprint，或省略二者由服务端"
                "生成密钥")
        provided_fp = secret_fingerprint(sec_in) if sec_in is not None else None
        if sec_in is not None and fp_in is not None and not hmac.compare_digest(
                provided_fp, fp_in):
            raise AuditBadRequest(
                "fingerprint 与提供的 secret 不一致：指纹必须是 "
                "sha256(secret) 的十六进制",
                provided_fingerprint=fp_in,
                actual_fingerprint=provided_fp)

        # 稳定历史上界（与租约写入互斥读取）
        with self._store._lock:  # noqa: SLF001
            sconn = self._store._conn  # noqa: SLF001
            max_row = sconn.execute(
                "SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = int(max_row["m"]) if max_row["m"] is not None else 0

        now = self._now()
        with self._lock:
            conn = self._conn
            conn.rollback()  # 取最新已提交视图（订阅/版本可能由其它连接写入）
            sub = self._require_subscription(conn, sid)

            # 幂等先行（先于状态/边界校验），保证订阅状态变化后同键仍稳定
            # 回放首次结果；也先于服务端密钥生成（见上）。
            prev = conn.execute(
                "SELECT * FROM audit_subscription_signing_keys "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if prev is not None:
                # 同键重放：调用方省略密钥材料时直接回放首次密钥记录；
                # 显式给了 secret 才比较指纹，指纹/生效序号/宽限期/订阅
                # 任一不同即 409 明确冲突。
                spec_fp = provided_fp if provided_fp is not None \
                    else prev["fingerprint"]
                spec = {"subscription_id": sid, "fingerprint": spec_fp,
                        "effective_seq": eff, "grace_ms": grace}
                diff = self._first_prepare_diff(prev, spec)
                if diff is None:
                    conn.rollback()
                    return self.get_key(sid, prev["key_id"]), False
                raise self._prepare_conflict(key, diff,
                                             key_id=prev["key_id"])
            other = conn.execute(
                "SELECT * FROM audit_subscription_key_idempotency "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if other is not None:
                raise self._idempotency_taken(key, other)
            # 订阅侧（版本/订阅创建等）已占用该键
            sub_other = conn.execute(
                "SELECT 1 FROM audit_subscription_idempotency "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if sub_other is not None:
                raise KeyRotationConflict(
                    f"幂等键 {key} 已用于订阅的其它操作，不能复用",
                    idempotency_key=key)
            sub_ver = conn.execute(
                "SELECT 1 FROM audit_subscription_versions "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if sub_ver is not None:
                raise KeyRotationConflict(
                    f"幂等键 {key} 已用于订阅版本创建，不能复用",
                    idempotency_key=key)

            # 确认是新请求后再生成服务端密钥（只会发生一次）
            if sec_in is None:
                secret_val = new_secret()
                fp = secret_fingerprint(secret_val)
            else:
                secret_val, fp = sec_in, provided_fp
            spec = {"subscription_id": sid, "fingerprint": fp,
                    "effective_seq": eff, "grace_ms": grace}

            def reject_prepare(reason: str, exc: KeyRotationError):
                with self._tx():
                    self._audit_locked(conn, sid, None, "key_rejected",
                                       "rejected", reason,
                                       detail_obj={"operation": OP_KEY_PREPARE,
                                                   "fingerprint": fp,
                                                   "effective_seq": eff,
                                                   "grace_ms": grace},
                                       now=now)
                raise exc

            if sub["status"] != SUB_ACTIVE:
                reject_prepare(
                    f"订阅当前状态为 {sub['status']}，只有 active 订阅可以"
                    "预登记下一签名密钥",
                    KeyRotationBadState(
                        "订阅不是 active，不能预登记签名密钥",
                        subscription_id=sid, status=sub["status"]))

            existing = conn.execute(
                "SELECT * FROM audit_subscription_signing_keys "
                "WHERE subscription_id=? AND status=?",
                (sid, K_PREPARED)).fetchone()
            if existing is not None:
                reject_prepare(
                    f"已存在待生效密钥 {existing['key_id']}（"
                    f"effective_seq={existing['effective_seq']}），"
                    "请先生效或撤销它",
                    KeyRotationBadState(
                        "同一订阅同时只能有一个待生效签名密钥",
                        subscription_id=sid,
                        pending_key_id=existing["key_id"]))

            # 生效序号越过稳定历史上界：拒绝且当前密钥不变
            if eff > max_seq:
                reject_prepare(
                    f"effective_seq={eff} 越过当前稳定历史上界 {max_seq}，"
                    "该历史位置尚不存在",
                    KeyRotationRangeError(
                        f"effective_seq={eff} 越过当前稳定历史上界 "
                        f"{max_seq}，当前密钥未改变",
                        effective_seq=eff, available_max_seq=max_seq))

            # 生效序号不得早于当前版本已扫描位置（边界前通知已用旧密钥
            # 入队/检视，不能回头改判密钥）
            cur_no = int(sub["current_version"])
            cur_ver = self._get_version_row(conn, sid, cur_no)
            min_eff = int(cur_ver["position_seq"]) if cur_ver is not None \
                else int(sub["position_seq"])
            if eff < min_eff:
                reject_prepare(
                    f"effective_seq={eff} 早于当前已扫描位置 {min_eff}，"
                    "边界前通知已按旧密钥处理",
                    KeyRotationBadState(
                        f"effective_seq 不能早于当前扫描位置 {min_eff}",
                        subscription_id=sid, effective_seq=eff,
                        min_effective_seq=min_eff))

            maxrow = conn.execute(
                "SELECT MAX(key_no) AS m FROM "
                "audit_subscription_signing_keys WHERE subscription_id=?",
                (sid,)).fetchone()
            next_no = int(maxrow["m"] or 0) + 1
            if next_no == 1:
                # 首次轮换：当前密钥来自当前生效版本（版本 1 或已切换版本）
                replaces = None
            else:
                cur_key = conn.execute(
                    "SELECT key_id FROM audit_subscription_signing_keys "
                    "WHERE subscription_id=? AND status IN (?,?) "
                    "ORDER BY key_no DESC LIMIT 1",
                    (sid, K_ACTIVE, K_GRACE)).fetchone()
                replaces = cur_key["key_id"] if cur_key is not None else None

            key_id = uuid.uuid4().hex
            try:
                with self._tx():
                    conn.execute(
                        "INSERT INTO audit_subscription_signing_keys"
                        "(key_id, subscription_id, key_no, idempotency_key, "
                        "secret, fingerprint, effective_seq, grace_ms, status, "
                        "replaces_key_id, snapshot_seq, created_at_ms, "
                        "updated_at_ms) VALUES(?,?,?,?,?,?,?,?,'prepared',"
                        "?,?,?,?)",
                        (key_id, sid, next_no, key, secret_val, fp, eff,
                         grace, replaces, max_seq, now, now))
                    self._audit_locked(
                        conn, sid, next_no, "key_prepared", "ok",
                        f"预登记签名密钥 #{next_no}：指纹 {fp[:12]}…，"
                        f"effective_seq={eff}，宽限 {grace}ms",
                        detail_obj={"fingerprint": fp, "effective_seq": eff,
                                    "grace_ms": grace,
                                    "replaces_key_id": replaces},
                        now=now)
            except sqlite3.IntegrityError:
                prev = conn.execute(
                    "SELECT * FROM audit_subscription_signing_keys "
                    "WHERE idempotency_key=?", (key,)).fetchone()
                if prev is not None:
                    diff = self._first_prepare_diff(prev, spec)
                    if diff is None:
                        conn.rollback()
                        return self.get_key(sid, prev["key_id"]), False
                    raise self._prepare_conflict(key, diff,
                                                 key_id=prev["key_id"])
                raise
            return self.get_key(sid, key_id), True

    # ======================================================================
    # 生效（原子切换）
    # ======================================================================
    def activate_key(self, subscription_id: str, key_id: str, *,
                     idempotency_key: Any = None) -> tuple[dict[str, Any], bool]:
        """原子生效预登记密钥：单事务切换订阅当前签名密钥并退役上一把。

        - 生效序号之后新匹配事件的投递必须用新密钥（入队时按
          ``event_seq >= effective_seq`` 选择签名密钥）；
        - 生效前已入队/认领中的投递行冻结旧 ``signing_key_id``，继续按
          旧密钥签名/确认；
        - 旧密钥进入 ``grace``（``grace_ms>0``，宽限到点后由
          :meth:`recover_interruptions`/查询惰性置 retired），宽限为 0
          时直接 retired；
        - 同键重放回首次结果；换操作/目标订阅/密钥 → 409。
        """
        sid = str(require_value(subscription_id, "subscription_id"))
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：密钥生效必须携带幂等键")
        key = idempotency_key.strip()
        now = self._now()
        with self._lock:
            conn = self._conn
            conn.rollback()
            sub = self._require_subscription(conn, sid)

            prev_op = conn.execute(
                "SELECT * FROM audit_subscription_key_idempotency "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if prev_op is not None:
                self._check_op(prev_op, OP_KEY_ACTIVATE, sid, key_id)
                view = json.loads(prev_op["result_json"])
                conn.rollback()
                return view, False
            self._reject_cross_namespace_key(conn, key, sid)

            krow = self._get_key_row_by_id(conn, sid, key_id)
            if krow is None:
                raise KeyRotationNotFound(
                    f"订阅 {sid} 不存在签名密钥 {key_id}",
                    subscription_id=sid, key_id=key_id)

            def reject_activate(reason: str, exc: KeyRotationError):
                with self._tx():
                    self._audit_locked(conn, sid, int(krow["key_no"]),
                                       "key_rejected", "rejected", reason,
                                       detail_obj={"operation": OP_KEY_ACTIVATE},
                                       now=now)
                raise exc

            if sub["status"] != SUB_ACTIVE:
                reject_activate(
                    f"订阅当前状态为 {sub['status']}，不能生效签名密钥",
                    KeyRotationBadState(
                        "订阅不是 active，不能生效签名密钥",
                        subscription_id=sid, status=sub["status"]))
            if krow["status"] in (K_ACTIVE, K_GRACE):
                reject_activate(
                    f"密钥 #{krow['key_no']} 已经生效"
                    f"（状态 {krow['status']}），不能重复生效",
                    KeyRotationBadState(
                        "密钥已经生效，不能重复生效",
                        subscription_id=sid, key_id=key_id,
                        status=krow["status"]))
            if krow["status"] in (K_RETIRED, K_REVOKED):
                reject_activate(
                    f"密钥 #{krow['key_no']} 状态为 {krow['status']}，"
                    "不能生效",
                    KeyRotationBadState(
                        "密钥当前状态不允许生效",
                        subscription_id=sid, key_id=key_id,
                        status=krow["status"]))
            if krow["status"] != K_PREPARED:
                reject_activate(
                    f"密钥状态为 {krow['status']}，只有 prepared 密钥可生效",
                    KeyRotationBadState(
                        "只有 prepared（预登记）密钥可以生效",
                        subscription_id=sid, key_id=key_id,
                        status=krow["status"]))

            eff = int(krow["effective_seq"])
            grace = int(krow["grace_ms"])
            replaces_id = krow["replaces_key_id"]
            # 找到当前真正生效的旧密钥（可能处于 active/grace）：
            # key_no 最大且状态非 prepared/revoked/retired 的那把
            old = conn.execute(
                "SELECT * FROM audit_subscription_signing_keys "
                "WHERE subscription_id=? AND status IN (?,?) "
                "ORDER BY key_no DESC LIMIT 1",
                (sid, K_ACTIVE, K_GRACE)).fetchone()

            with self._tx():
                # 旧密钥：宽限 > 0 进入 grace，否则直接退役
                if old is not None:
                    if grace > 0:
                        conn.execute(
                            "UPDATE audit_subscription_signing_keys "
                            "SET status=?, grace_until_ms=?, updated_at_ms=? "
                            "WHERE key_id=? AND status IN (?,?)",
                            (K_GRACE, now + grace, now, old["key_id"],
                             K_ACTIVE, K_GRACE))
                    else:
                        conn.execute(
                            "UPDATE audit_subscription_signing_keys "
                            "SET status=?, grace_until_ms=?, retired_at_ms=?, "
                            "updated_at_ms=? WHERE key_id=? AND status IN (?,?)",
                            (K_RETIRED, now, now, now, old["key_id"],
                             K_ACTIVE, K_GRACE))
                # 新密钥生效
                cur = conn.execute(
                    "UPDATE audit_subscription_signing_keys SET status=?, "
                    "activated_at_ms=?, grace_until_ms=?, updated_at_ms=? "
                    "WHERE key_id=? AND status=?",
                    (K_ACTIVE, now,
                     now + grace if grace > 0 else None, now,
                     key_id, K_PREPARED))
                if cur.rowcount != 1:
                    raise KeyRotationBadState(
                        "密钥在生效过程中状态已变化（并发生效）",
                        subscription_id=sid, key_id=key_id)
                # 首次轮换（key_no=1）：被替换的是版本冻结密钥，而版本密钥
                # 没有自己的密钥行。把它的宽限窗口/退役时刻挂在首把轮换密钥
                # 上：宽限 >0 时版本密钥在窗口内隐式 grace（旧通知仍可按它
                # 确认），宽限为 0 立即退役。没有这两列，宽限结束并完成恢复
                # 处理后旧版本密钥签名仍会被回退逻辑当作 ok 接受。
                if int(krow["key_no"]) == 1:
                    conn.execute(
                        "UPDATE audit_subscription_signing_keys SET "
                        "version_key_grace_until_ms=?, "
                        "version_key_retired_at_ms=? WHERE key_id=?",
                        (now + grace if grace > 0 else None,
                         now if grace == 0 else None, key_id))
                self._audit_locked(
                    conn, sid, int(krow["key_no"]), "key_activated", "ok",
                    f"签名密钥 #{krow['key_no']} 原子生效：历史序号 {eff}"
                    f"（含）起新通知使用新密钥；旧密钥"
                    + (f"进入 {grace}ms 宽限期" if old is not None and grace > 0
                       else "立即退役" if old is not None else "无（首把密钥）"),
                    detail_obj={"effective_seq": eff, "grace_ms": grace,
                                "replaces_key_id": replaces_id,
                                "old_key_id": old["key_id"]
                                if old is not None else None},
                    now=now)
                view = self._key_view_from_row(
                    conn, self._get_key_row_by_id(conn, sid, key_id))
                conn.execute(
                    "INSERT INTO audit_subscription_key_idempotency"
                    "(idempotency_key, subscription_id, operation, target, "
                    "result_json, created_at_ms) VALUES(?,?,?,?,?,?)",
                    (key, sid, OP_KEY_ACTIVATE, key_id,
                     canonical_json(view), now))
            return self.get_key(sid, key_id), True

    # ======================================================================
    # 撤销（只有 prepared 可撤销）
    # ======================================================================
    def revoke_key(self, subscription_id: str, key_id: str, *,
                   idempotency_key: Any = None) -> tuple[dict[str, Any], bool]:
        """撤销预登记密钥（永不生效，记录保留）。只有 prepared 可撤销。"""
        sid = str(require_value(subscription_id, "subscription_id"))
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：密钥撤销必须携带幂等键")
        key = idempotency_key.strip()
        now = self._now()
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_subscription(conn, sid)

            prev_op = conn.execute(
                "SELECT * FROM audit_subscription_key_idempotency "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if prev_op is not None:
                self._check_op(prev_op, OP_KEY_REVOKE, sid, key_id)
                view = json.loads(prev_op["result_json"])
                conn.rollback()
                return view, False
            self._reject_cross_namespace_key(conn, key, sid)

            krow = self._get_key_row_by_id(conn, sid, key_id)
            if krow is None:
                raise KeyRotationNotFound(
                    f"订阅 {sid} 不存在签名密钥 {key_id}",
                    subscription_id=sid, key_id=key_id)
            if krow["status"] == K_REVOKED:
                raise KeyRotationBadState(
                    f"密钥 #{krow['key_no']} 已撤销",
                    subscription_id=sid, key_id=key_id,
                    status=K_REVOKED)
            if krow["status"] != K_PREPARED:
                with self._tx():
                    self._audit_locked(conn, sid, int(krow["key_no"]),
                                       "key_rejected", "rejected",
                                       f"撤销被拒绝：密钥状态为 "
                                       f"{krow['status']}",
                                       detail_obj={"operation": OP_KEY_REVOKE},
                                       now=now)
                raise KeyRotationBadState(
                    "只有 prepared（预登记）密钥可以撤销",
                    subscription_id=sid, key_id=key_id,
                    status=krow["status"])
            with self._tx():
                cur = conn.execute(
                    "UPDATE audit_subscription_signing_keys SET status=?, "
                    "revoked_at_ms=?, updated_at_ms=? WHERE key_id=? "
                    "AND status=?",
                    (K_REVOKED, now, now, key_id, K_PREPARED))
                if cur.rowcount != 1:
                    raise KeyRotationBadState(
                        "密钥在撤销过程中状态已变化",
                        subscription_id=sid, key_id=key_id)
                self._audit_locked(
                    conn, sid, int(krow["key_no"]), "key_revoked", "ok",
                    f"预登记签名密钥 #{krow['key_no']} 已撤销，永不生效",
                    now=now)
                view = self._key_view_from_row(
                    conn, self._get_key_row_by_id(conn, sid, key_id))
                conn.execute(
                    "INSERT INTO audit_subscription_key_idempotency"
                    "(idempotency_key, subscription_id, operation, target, "
                    "result_json, created_at_ms) VALUES(?,?,?,?,?,?)",
                    (key, sid, OP_KEY_REVOKE, key_id,
                     canonical_json(view), now))
            return self.get_key(sid, key_id), True

    # ======================================================================
    # 中断恢复 / 宽限退役
    # ======================================================================
    def recover_interruptions(self, *, now_ms: int | None = None) -> dict:
        """从已保存状态恢复：宽限到期退役旧密钥。

        生效本身是单事务原子切换，不存在"半切换"；崩溃可能留下的待收敛
        状态有两种：宽限到期但还没置 retired 的轮换旧密钥，以及首次轮换时
        被替换的版本冻结密钥（宽限窗口挂在 key_no=1 的行上，没有自己的
        密钥行）。该方法幂等，构造时与每次扫描/查询前调用都安全；不触碰
        任何投递行，因此不会重复确认或跳过通知。
        """
        now = now_ms if now_ms is not None else self._now()
        retired = 0
        version_retired = 0
        with self._lock:
            conn = self._conn
            with self._tx():
                rows = conn.execute(
                    "SELECT * FROM audit_subscription_signing_keys "
                    "WHERE status=? AND grace_until_ms IS NOT NULL "
                    "AND grace_until_ms<=?",
                    (K_GRACE, now)).fetchall()
                for r in rows:
                    conn.execute(
                        "UPDATE audit_subscription_signing_keys SET status=?, "
                        "retired_at_ms=?, updated_at_ms=? WHERE key_id=? "
                        "AND status=?",
                        (K_RETIRED, now, now, r["key_id"], K_GRACE))
                    self._audit_locked(
                        conn, r["subscription_id"], int(r["key_no"]),
                        "key_retired", "ok",
                        f"签名密钥 #{r['key_no']} 宽限期结束，旧密钥退役",
                        detail_obj={"grace_until_ms": r["grace_until_ms"]},
                        now=now)
                    retired += 1
                # 首次轮换：被首把轮换密钥替换掉的版本冻结密钥宽限到期。
                # 版本密钥没有自己的行，退役标记挂在 key_no=1 的轮换密钥上；
                # 标记落下后旧版本密钥签名一律拒绝（不改变任何投递状态）。
                vrows = conn.execute(
                    "SELECT * FROM audit_subscription_signing_keys "
                    "WHERE version_key_grace_until_ms IS NOT NULL "
                    "AND version_key_retired_at_ms IS NULL "
                    "AND version_key_grace_until_ms<=? "
                    "AND status!=?",
                    (now, K_REVOKED)).fetchall()
                for r in vrows:
                    conn.execute(
                        "UPDATE audit_subscription_signing_keys SET "
                        "version_key_retired_at_ms=?, updated_at_ms=? "
                        "WHERE key_id=?",
                        (now, now, r["key_id"]))
                    self._audit_locked(
                        conn, r["subscription_id"], 1,
                        "key_retired", "ok",
                        "签名密钥 #1 宽限期结束，其替换掉的版本冻结密钥退役",
                        detail_obj={"version_key": True,
                                    "grace_until_ms":
                                    r["version_key_grace_until_ms"]},
                        now=now)
                    version_retired += 1
            conn.rollback()
        return {"retired": retired, "version_key_retired": version_retired,
                "now_ms": now}

    # ======================================================================
    # 签名密钥选择（供 SubscriptionManager 入队/签名/确认调用）
    # ======================================================================
    def signing_secret_for_delivery(self, subscription_id: str,
                                    event_seq: int,
                                    *, version_no: int | None = None,
                                    conn: Any = None) -> tuple[str | None,
                                                               str | None]:
        """返回某条**新投递**应当使用的 (密钥明文, key_id)。

        规则：取该订阅已生效（active/grace）且 ``effective_seq`` 不大于
        event_seq 的 key_no 最大的密钥；否则回退到版本冻结密钥
        （返回 key_id=None，历史行为）。只读，不自行提交/回滚传入连接。
        """
        own = conn if conn is not None else self._conn
        row = own.execute(
            "SELECT key_id, secret FROM audit_subscription_signing_keys "
            "WHERE subscription_id=? AND status IN (?,?) AND effective_seq<=? "
            "ORDER BY effective_seq DESC, key_no DESC LIMIT 1",
            (subscription_id, K_ACTIVE, K_GRACE, event_seq)).fetchone()
        if row is not None:
            return row["secret"], row["key_id"]
        # 回退：当前生效版本冻结的密钥
        if version_no is None:
            sub = own.execute(
                "SELECT current_version FROM audit_subscriptions "
                "WHERE subscription_id=?", (subscription_id,)).fetchone()
            if sub is None:
                return None, None
            version_no = int(sub["current_version"])
        vrow = own.execute(
            "SELECT secret FROM audit_subscription_versions "
            "WHERE subscription_id=? AND version_no=?",
            (subscription_id, int(version_no))).fetchone()
        if vrow is not None:
            return vrow["secret"], None
        return None, None

    def secret_for_key_id(self, conn, subscription_id: str,
                          key_id: str | None) -> str | None:
        """按 key_id 取密钥；key_id 为 None（旧行）回退 None（调用方自行
        回退版本密钥）。只读。"""
        if key_id is None:
            return None
        row = conn.execute(
            "SELECT secret FROM audit_subscription_signing_keys "
            "WHERE key_id=? AND subscription_id=?",
            (key_id, subscription_id)).fetchone()
        return row["secret"] if row is not None else None

    def old_grace_secret_for_delivery(self, conn, subscription_id: str,
                                      delivery_row) -> str | None:
        """若投递行使用的签名密钥当前处于宽限期，返回其密钥明文，否则 None。

        用于"等待确认的旧通知在宽限期内仍可按旧密钥完成确认"。投递行冻结
        的 ``signing_key_id`` 即它本应使用的密钥代际：该密钥在被下一把密钥
        替换后进入 grace，宽限期内旧通知仍可按它确认。``signing_key_id``
        为 NULL 的行（首把轮换密钥生效前已入队）由
        :meth:`version_key_grace_info` 单独处理版本冻结密钥的宽限。
        """
        keys = delivery_row.keys()
        sign_key_id = delivery_row["signing_key_id"] if "signing_key_id" \
            in keys else None
        if sign_key_id:
            row = conn.execute(
                "SELECT secret FROM audit_subscription_signing_keys "
                "WHERE key_id=? AND subscription_id=? AND status=?",
                (sign_key_id, subscription_id, K_GRACE)).fetchone()
            if row is not None:
                return row["secret"]
        return None

    def version_key_grace_info(self, conn, subscription_id: str):
        """返回首把轮换密钥对版本冻结密钥的宽限状态行（key_no=1）。

        首次轮换时被替换的版本冻结密钥没有自己的密钥行，其宽限窗口挂在
        key_no=1 的轮换密钥上。返回该行（含
        ``version_key_grace_until_ms`` / ``version_key_retired_at_ms``），
        没有首把轮换密钥时返回 None。
        """
        return conn.execute(
            "SELECT * FROM audit_subscription_signing_keys "
            "WHERE subscription_id=? AND key_no=1",
            (subscription_id,)).fetchone()

    # ======================================================================
    # 显式确认：在订阅管理器确认路径上叠加宽限旧密钥语义 + 验证落库
    # ======================================================================
    def verify_ack_signature(self, subscription_id: str, delivery_row,
                             payload: dict, signature: str | None,
                             *, conn: Any,
                             now_ms: int | None = None
                             ) -> tuple[bool, str, dict]:
        """判定显式确认签名是否可接受，并返回验证结论。

        ``conn`` 为订阅管理器的连接（同一 WAL 库）。返回
        ``(accepted, result_code, info)``：

        - 当前密钥（投递行冻结的签名密钥）签名正确 → ``ok``；
        - 当前密钥不对、但投递是旧通知且其旧密钥在宽限期 →
          ``old_key_grace``（接受）；
        - 都不对 → ``failed``（拒绝，不改变状态）。

        该方法只读密钥表；验证落库由 :meth:`record_verification` 完成。
        ``now_ms`` 缺省用管理器墙钟；订阅管理器在同一确认请求里会传入它
        已取的时刻，保证宽限判定与验证落库同一瞬间。
        """
        vnow = now_ms if now_ms is not None else self._now()
        d = delivery_row
        key_id = d["signing_key_id"] if (
            "signing_key_id" in d.keys()) else None

        def _key_status(kid: str | None) -> str | None:
            if not kid:
                return None
            r = conn.execute(
                "SELECT status FROM audit_subscription_signing_keys "
                "WHERE key_id=? AND subscription_id=?",
                (kid, subscription_id)).fetchone()
            return r["status"] if r is not None else None

        # ---- 版本冻结密钥行（signing_key_id IS NULL）----
        # 首次轮换前：版本密钥恒可用（ok）。首次轮换后：它是被首把轮换
        # 密钥替换掉的"旧密钥"，只在宽限窗口内可做 old_key_grace 确认；
        # 宽限为 0（立即退役）或窗口结束并完成恢复后，旧签名一律 failed，
        # 绝不回退成 ok，也不改变投递状态。
        if key_id is None:
            vno = int(d["version_no"]) if "version_no" in \
                d.keys() else int(payload.get("version_no", 1))
            vrow = conn.execute(
                "SELECT secret FROM audit_subscription_versions "
                "WHERE subscription_id=? AND version_no=?",
                (subscription_id, vno)).fetchone()
            version_secret = vrow["secret"] if vrow is not None else None
            first = self.version_key_grace_info(conn, subscription_id)
            if first is None or first["status"] == K_PREPARED:
                # 首次轮换尚未生效：版本密钥仍是当前密钥
                if version_secret is not None and verify_signature(
                        version_secret, payload, signature):
                    return True, V_OK, {"used_key_id": None,
                                        "expected_key_id": None}
                return False, V_FAILED, {"expected_key_id": None}
            retired_at = first["version_key_retired_at_ms"]
            grace_until = first["version_key_grace_until_ms"]
            in_grace = (retired_at is None and grace_until is not None
                        and vnow < int(grace_until))
            if in_grace and version_secret is not None and verify_signature(
                    version_secret, payload, signature):
                return True, V_OLD_KEY_GRACE, {"used_key_id": None,
                                              "expected_key_id": None}
            return False, V_FAILED, {"expected_key_id": None}

        # ---- 钉住轮换密钥的行 ----
        # 投递行冻结的当前应使用密钥：轮换密钥优先，密钥行缺失时回退版本
        # 冻结密钥。
        cur_secret = self.secret_for_key_id(conn, subscription_id, key_id)
        cur_status = _key_status(key_id)
        if cur_secret is None:
            vno = int(d["version_no"]) if "version_no" in \
                d.keys() else int(payload.get("version_no", 1))
            vrow = conn.execute(
                "SELECT secret FROM audit_subscription_versions "
                "WHERE subscription_id=? AND version_no=?",
                (subscription_id, vno)).fetchone()
            cur_secret = vrow["secret"] if vrow is not None else None
        # 冻结密钥已被替换进入宽限期：用它签名属于"旧通知宽限确认"
        if (cur_status == K_GRACE and cur_secret is not None
                and verify_signature(cur_secret, payload, signature)):
            return True, V_OLD_KEY_GRACE, {"used_key_id": key_id,
                                          "expected_key_id": key_id}
        # 密钥仍生效：轮换密钥必须处于 active（retired/revoked/prepared 都
        # 不是当前可用密钥）
        if (cur_status == K_ACTIVE and cur_secret is not None
                and verify_signature(cur_secret, payload, signature)):
            return True, V_OK, {"used_key_id": key_id,
                                "expected_key_id": key_id}
        # 宽限：冻结密钥之外、处于宽限期的更旧密钥（兼容历史行）
        old_secret = self.old_grace_secret_for_delivery(
            conn, subscription_id, d)
        if old_secret is not None and verify_signature(
                old_secret, payload, signature):
            keys = d.keys()
            old_key_id = d["signing_key_id"] if "signing_key_id" in keys \
                else None
            return True, V_OLD_KEY_GRACE, {
                "used_key_id": old_key_id,
                "expected_key_id": key_id}
        return False, V_FAILED, {"expected_key_id": key_id}

    def record_verification(self, subscription_id: str, delivery_row,
                            result: str, info: dict, *,
                            conn: Any, now: int | None = None) -> None:
        """把一次确认的签名验证结论追加进验证表（自有表）。

        同一投递可以留下多条轨迹（先 failed 后 ok/old_key_grace）；完全
        相同的 (投递, 结果, 使用密钥, 期望密钥) 通过 ``dedupe_key`` 唯一
        约束 + INSERT OR IGNORE 去重，因此重复的幂等确认不会重复计数。
        调用方通常在订阅管理器的写事务内。
        """
        ts = now if now is not None else self._now()
        used = info.get("used_key_id") or ""
        expected = info.get("expected_key_id") or ""
        dedupe = "|".join([delivery_row["delivery_id"], result,
                           used, expected])
        conn.execute(
            "INSERT OR IGNORE INTO "
            "audit_subscription_signature_verifications(verification_id, "
            "subscription_id, delivery_id, event_seq, key_id, "
            "expected_key_id, result, detail, created_at_ms, dedupe_key) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, subscription_id,
             delivery_row["delivery_id"], int(delivery_row["event_seq"]),
             used, info.get("expected_key_id"), result,
             canonical_json(info), ts, dedupe))

    # ======================================================================
    # 验证结果分页查询（按密钥 + 时间范围）
    # ======================================================================
    def list_verifications(self, subscription_id: str, *,
                           key_id: Any = None,
                           result: Any = None,
                           from_ms: Any = None,
                           to_ms: Any = None,
                           after_seq: Any = None,
                           limit: Any = 100) -> dict[str, Any]:
        """按密钥与时间范围分页查询投递签名验证结果（event_seq 升序游标）。

        - ``key_id`` 过滤"确认时实际使用的密钥"；``result`` 可限定
          ok/failed/old_key_grace/resigned；
        - ``from_ms/to_ms`` 对验证记录创建墙钟时间做闭区间过滤；
        - 不改变任何状态（纯只读）。
        """
        limit = _bounded_limit(limit)
        with self._lock:
            conn = self._conn
            # 验证记录由订阅管理器连接在确认事务中写入：本连接必须结束可能
            # 残留的只读快照，否则长读连接停在旧 WAL 视图看不到新记录。
            conn.rollback()
            self._require_subscription(conn, subscription_id)
            where = ["subscription_id=?"]
            args: list[Any] = [subscription_id]
            if key_id not in (None, ""):
                where.append("key_id=?")
                args.append(str(key_id))
            if result not in (None, ""):
                if result not in (V_OK, V_FAILED, V_OLD_KEY_GRACE, V_RESIGNED):
                    raise AuditBadRequest("result 过滤值非法", result=result)
                where.append("result=?")
                args.append(str(result))
            t0 = _as_int(from_ms, "from_ms")
            t1 = _as_int(to_ms, "to_ms")
            if t0 is not None:
                where.append("created_at_ms>=?")
                args.append(t0)
            if t1 is not None:
                where.append("created_at_ms<=?")
                args.append(t1)
            # 游标是"上一页最后一条验证记录"的 "<created_ms>:<rowid>"：
            # 同一事件可有多条验证轨迹（failed 后 ok/old_key_grace），不能
            # 仅用 event_seq 做游标，否则同 seq 记录会互相翻页。
            if after_seq not in (None, "", 0, "0"):
                cur = str(after_seq)
                if ":" not in cur:
                    raise AuditBadRequest(
                        "after 游标必须是上一页返回的 '<ms>:<rowid>'",
                        after=cur)
                cur_ms_s, _, cur_row_s = cur.partition(":")
                cur_ms = _as_int(cur_ms_s, "after")
                cur_row = _as_int(cur_row_s, "after")
                if cur_ms is None or cur_row is None:
                    raise AuditBadRequest("after 游标格式非法", after=cur)
                where.append(
                    "(created_at_ms>? OR (created_at_ms=? AND rowid>?))")
                args.extend([cur_ms, cur_ms, cur_row])
            rows = conn.execute(
                "SELECT *, rowid AS rid FROM "
                "audit_subscription_signature_verifications WHERE "
                + " AND ".join(where)
                + " ORDER BY created_at_ms ASC, rid ASC LIMIT ?",
                (*args, limit + 1)).fetchall()
            conn.rollback()
        page = rows[:limit]
        has_more = len(rows) > limit
        return {
            "subscription_id": subscription_id,
            "key_id": str(key_id) if key_id not in (None, "") else None,
            "verifications": [self._verification_view(r) for r in page],
            "limit": limit,
            "next": (f"{page[-1]['created_at_ms']}:{page[-1]['rid']}"
                     if has_more else None),
            "reached_end": not has_more,
        }

    # ======================================================================
    # 只对验证失败的指定密钥投递重新签名
    # ======================================================================
    def resign_failed_delivery(self, subscription_id: str, event_seq: Any,
                               *, key_id: Any = None,
                               idempotency_key: Any = None
                               ) -> tuple[dict[str, Any], bool]:
        """对一条验证失败的投递用**当前应使用的密钥**重新签名。

        - 只处理验证结果为 ``failed`` 的投递；指定 ``key_id`` 时还要求
          该验证记录确实属于这把密钥，否则 404/409；
        - 重签**完全不修改已有投递记录**（signature、updated_at_ms、状态、
          尝试次数等所有字段保持原值）：新签名只作为 ``resigned`` 验证记录
          的 ``new_signature`` 追加进验证表，验证查询即可看到；不重置确认、
          不重复确认、不产生重复投递、不改变严格顺序；
        - 同幂等键重放回首次结果（含首次算出的新签名）；换投递/密钥/订阅
          → 409。
        """
        sid = str(require_value(subscription_id, "subscription_id"))
        seq = _as_int(event_seq, "event_seq")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：重新签名必须携带幂等键")
        key = idempotency_key.strip()
        now = self._now()
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_subscription(conn, sid)

            prev_op = conn.execute(
                "SELECT * FROM audit_subscription_key_idempotency "
                "WHERE idempotency_key=?", (key,)).fetchone()
            if prev_op is not None:
                self._check_op(prev_op, OP_KEY_RESIGN, sid, str(seq))
                view = json.loads(prev_op["result_json"])
                conn.rollback()
                return view, False
            self._reject_cross_namespace_key(conn, key, sid)

            d = conn.execute(
                "SELECT * FROM audit_subscription_deliveries "
                "WHERE subscription_id=? AND event_seq=?",
                (sid, seq)).fetchone()
            if d is None:
                raise KeyVerificationNotFound(
                    f"订阅 {sid} 没有事件 seq={seq} 的投递记录",
                    subscription_id=sid, event_seq=seq)
            ver = conn.execute(
                "SELECT * FROM audit_subscription_signature_verifications "
                "WHERE delivery_id=? ORDER BY created_at_ms DESC, "
                "rowid DESC LIMIT 1", (d["delivery_id"],)).fetchone()
            if ver is None or ver["result"] != V_FAILED:
                # 投递存在但没有验证失败记录：操作前提不满足（409，而不是
                # 把投递当作不存在的 404）
                raise KeyRotationBadState(
                    f"投递 seq={seq} 没有验证失败记录，不能重签；重签只针对"
                    "签名验证失败的投递",
                    subscription_id=sid, event_seq=seq,
                    last_result=ver["result"] if ver is not None else None)
            if key_id not in (None, "") and ver["key_id"] != str(key_id):
                raise KeyVerificationNotFound(
                    f"投递 seq={seq} 的失败验证不属于密钥 {key_id}",
                    subscription_id=sid, event_seq=seq,
                    requested_key_id=str(key_id),
                    verification_key_id=ver["key_id"])

            payload = json.loads(d["payload_json"])
            # 当前应使用的密钥：优先该事件生效序号内的轮换密钥，否则版本
            # 冻结密钥（重签不改变签名密钥代际，只修正签名值）。
            secret, used_key_id = self.signing_secret_for_delivery(
                sid, seq, version_no=int(d["version_no"]), conn=conn)
            if secret is None:
                raise KeyRotationBadState(
                    "无法确定该投递的当前签名密钥",
                    subscription_id=sid, event_seq=seq)
            new_sig = sign_payload(secret, payload)
            with self._tx():
                # 绝不 UPDATE 投递行：已有投递记录的所有字段（signature、
                # updated_at_ms、状态、尝试次数、dispatch_token 等）保持
                # 原值。新签名只追加进验证表自有行，查询验证结果即可看到。
                conn.execute(
                    "INSERT OR IGNORE INTO "
                    "audit_subscription_signature_verifications"
                    "(verification_id, subscription_id, delivery_id, "
                    "event_seq, key_id, expected_key_id, result, detail, "
                    "new_signature, created_at_ms, dedupe_key) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (uuid.uuid4().hex, sid, d["delivery_id"], seq,
                     used_key_id or "", used_key_id, V_RESIGNED,
                     canonical_json({"resigned_from_key_id": ver["key_id"],
                                     "event_seq": seq}), new_sig, now,
                     "|".join([d["delivery_id"], V_RESIGNED,
                               used_key_id or "", used_key_id or ""])))
                self._audit_locked(
                    conn, sid, None, "key_resigned", "ok",
                    f"投递 seq={seq} 用密钥 {used_key_id or 'version-key'}"
                    " 重新签名（验证失败后重签，投递记录不改动）",
                    detail_obj={"event_seq": seq,
                                "resigned_from_key_id": ver["key_id"],
                                "used_key_id": used_key_id},
                    now=now)
                result = {"subscription_id": sid, "event_seq": seq,
                          "delivery_id": d["delivery_id"],
                          "key_id": used_key_id, "result": V_RESIGNED,
                          "signature": new_sig}
                conn.execute(
                    "INSERT INTO audit_subscription_key_idempotency"
                    "(idempotency_key, subscription_id, operation, target, "
                    "result_json, created_at_ms) VALUES(?,?,?,?,?,?)",
                    (key, sid, OP_KEY_RESIGN, str(seq),
                     canonical_json(result), now))
            return result, True

    # ======================================================================
    # 查询：密钥状态 / 轮换进度 / 受影响投递
    # ======================================================================
    def get_key(self, subscription_id: str, key_id: str) -> dict[str, Any]:
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_subscription(conn, subscription_id)
            row = self._get_key_row_by_id(conn, subscription_id, key_id)
            conn.rollback()
            if row is None:
                raise KeyRotationNotFound(
                    f"订阅 {subscription_id} 不存在签名密钥 {key_id}",
                    subscription_id=subscription_id, key_id=key_id)
            return self._key_view(conn, row)

    def list_keys(self, subscription_id: str, *, status: Any = None,
                  limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        if status is not None and status not in (
                K_PREPARED, K_ACTIVE, K_GRACE, K_RETIRED, K_REVOKED):
            raise AuditBadRequest("status 过滤值非法", status=status)
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_subscription(conn, subscription_id)
            if status:
                rows = conn.execute(
                    "SELECT * FROM audit_subscription_signing_keys "
                    "WHERE subscription_id=? AND status=? "
                    "ORDER BY key_no ASC LIMIT ?",
                    (subscription_id, status, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_subscription_signing_keys "
                    "WHERE subscription_id=? ORDER BY key_no ASC LIMIT ?",
                    (subscription_id, limit)).fetchall()
            views = [self._key_view(conn, r) for r in rows]
            conn.rollback()
        return {"subscription_id": subscription_id, "keys": views,
                "limit": limit}

    def rotation_progress(self, subscription_id: str,
                          key_id: str) -> dict[str, Any]:
        """查询某次轮换的进度与受影响投递记录（只读）。

        - 旧密钥：生效序号前已入队、仍未终态的投递数（等待旧密钥签名/
          确认的尾巴）；
        - 新密钥：生效序号起已入队/已确认/开放/死信的投递数；
        - ``drained``：旧密钥尾巴是否清空（轮换收尾完成）。
        """
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_subscription(conn, subscription_id)
            row = self._get_key_row_by_id(conn, subscription_id, key_id)
            if row is None:
                raise KeyRotationNotFound(
                    f"订阅 {subscription_id} 不存在签名密钥 {key_id}",
                    subscription_id=subscription_id, key_id=key_id)
            eff = int(row["effective_seq"])
            # 旧密钥尾巴：生效序号之前已入队、仍未终态的投递（钉住旧轮换
            # 密钥或回退版本密钥的行都算），它们必须按旧密钥完成投递/确认
            old_open = conn.execute(
                "SELECT COUNT(*) AS c, "
                "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS awaiting "
                "FROM audit_subscription_deliveries "
                "WHERE subscription_id=? AND event_seq<? "
                "AND status IN (?,?,?)",
                (D_AWAITING, subscription_id, eff, *D_OPEN)
            ).fetchone()
            old_open_grace = old_open["awaiting"]
            # 新密钥：生效序号（含）起的全部投递统计
            new_stats = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS confirmed, "
                "SUM(CASE WHEN status IN (?,?,?) THEN 1 ELSE 0 END) AS open, "
                "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS dead, "
                "SUM(CASE WHEN signing_key_id=? THEN 1 ELSE 0 END) AS stamped "
                "FROM audit_subscription_deliveries WHERE subscription_id=? "
                "AND event_seq>=?",
                (D_CONFIRMED, *D_OPEN, D_DEAD, key_id,
                 subscription_id, eff)).fetchone()
            view = self._key_view(conn, row)
            conn.rollback()
        view["progress"] = {
            "effective_seq": eff,
            "old_key_open_deliveries": int(old_open["c"] or 0),
            "old_key_awaiting_confirm": int(old_open_grace or 0),
            "new_key_deliveries": int(new_stats["total"] or 0),
            "new_key_confirmed": int(new_stats["confirmed"] or 0),
            "new_key_open": int(new_stats["open"] or 0),
            "new_key_dead_letter": int(new_stats["dead"] or 0),
            "new_key_stamped": int(new_stats["stamped"] or 0),
            # 轮换收尾完成 = 边界前没有任何开放的旧密钥投递
            "drained": int(old_open["c"] or 0) == 0,
        }
        return view

    def affected_deliveries(self, subscription_id: str, key_id: str, *,
                            after_seq: Any = None, limit: Any = 100,
                            status: Any = None) -> dict[str, Any]:
        """分页查询受某次轮换影响的投递（按 event_seq 升序）。

        包含：生效序号前尚未终态（仍按旧密钥收尾）的投递，以及生效序号
        起属于新密钥的投递。纯只读，不改任何记录。
        """
        limit = _bounded_limit(limit)
        after = _as_int(after_seq, "after", default=0)
        with self._lock:
            conn = self._conn
            conn.rollback()
            self._require_subscription(conn, subscription_id)
            row = self._get_key_row_by_id(conn, subscription_id, key_id)
            if row is None:
                raise KeyRotationNotFound(
                    f"订阅 {subscription_id} 不存在签名密钥 {key_id}",
                    subscription_id=subscription_id, key_id=key_id)
            eff = int(row["effective_seq"])
            where = ["subscription_id=?",
                     "(event_seq>=? OR (event_seq<? AND status IN (?,?,?)))"]
            args: list[Any] = [subscription_id, eff, eff, *D_OPEN]
            if status not in (None, ""):
                where.append("status=?")
                args.append(str(status))
            if after:
                where.append("event_seq>?")
                args.append(after)
            rows = conn.execute(
                "SELECT * FROM audit_subscription_deliveries WHERE "
                + " AND ".join(where)
                + " ORDER BY event_seq ASC LIMIT ?",
                (*args, limit + 1)).fetchall()
            conn.rollback()
        page = rows[:limit]
        has_more = len(rows) > limit
        out = []
        for d in page:
            item = {
                "delivery_id": d["delivery_id"], "event_seq": d["event_seq"],
                "subscription_seq": d["subscription_seq"],
                "version_no": int(d["version_no"]),
                "status": d["status"], "attempts": d["attempts"],
                "signing_key_id": d["signing_key_id"],
                "side": ("new_key" if int(d["event_seq"]) >= eff
                         else "old_key_tail"),
                "signature": d["signature"],
            }
            out.append(item)
        return {"subscription_id": subscription_id, "key_id": key_id,
                "effective_seq": eff, "deliveries": out, "limit": limit,
                "next": page[-1]["event_seq"] if has_more else None,
                "reached_end": not has_more}

    # ======================================================================
    # 幂等 / 冲突辅助
    # ======================================================================
    def _check_op(self, prev, operation: str, subscription_id: str,
                  target: str) -> None:
        if (prev["operation"] == operation
                and prev["subscription_id"] == subscription_id
                and prev["target"] == str(target)):
            return
        raise KeyRotationIdConflict(
            f"幂等键 {prev['idempotency_key']} 已用于订阅 "
            f"{prev['subscription_id']} 的 {prev['operation']} 操作"
            f"（目标 {prev['target']}），本次请求与首次不一致",
            idempotency_key=prev["idempotency_key"],
            first_difference={
                "path": "operation/target",
                "existing": {"operation": prev["operation"],
                             "subscription_id": prev["subscription_id"],
                             "target": prev["target"]},
                "requested": {"operation": operation,
                              "subscription_id": subscription_id,
                              "target": str(target)}})

    def _reject_cross_namespace_key(self, conn, key: str, sid: str) -> None:
        """幂等键跨命名空间复用（预登记键用于操作/订阅侧键）一律 409。"""
        prepare_row = conn.execute(
            "SELECT subscription_id FROM audit_subscription_signing_keys "
            "WHERE idempotency_key=?", (key,)).fetchone()
        if prepare_row is not None:
            raise KeyRotationConflict(
                f"幂等键 {key} 已用于密钥预登记操作，不能复用",
                idempotency_key=key,
                first_difference={"path": "operation",
                                  "existing": {"operation": OP_KEY_PREPARE,
                                               "subscription_id":
                                               prepare_row["subscription_id"]},
                                  "requested": {"subscription_id": sid}})
        sub_other = conn.execute(
            "SELECT operation, subscription_id, target FROM "
            "audit_subscription_idempotency WHERE idempotency_key=?",
            (key,)).fetchone()
        if sub_other is not None:
            raise KeyRotationConflict(
                f"幂等键 {key} 已用于订阅的 {sub_other['operation']} 操作，"
                "不能复用于密钥轮换",
                idempotency_key=key)
        sub_ver = conn.execute(
            "SELECT 1 FROM audit_subscription_versions "
            "WHERE idempotency_key=?", (key,)).fetchone()
        if sub_ver is not None:
            raise KeyRotationConflict(
                f"幂等键 {key} 已用于订阅版本创建，不能复用",
                idempotency_key=key)

    @staticmethod
    def _prepare_conflict(key: str, diff: dict, *,
                          key_id: str) -> KeyRotationIdConflict:
        return KeyRotationIdConflict(
            f"幂等键 {key} 已用于密钥 {key_id}，本次请求与首次预登记"
            f"不一致：首个差异位于 {diff['path']}",
            idempotency_key=key, key_id=key_id, first_difference=diff)

    @staticmethod
    def _idempotency_taken(key: str, other) -> KeyRotationConflict:
        return KeyRotationConflict(
            f"幂等键 {key} 已用于密钥轮换的 {other['operation']} 操作，"
            "不能复用于本次请求",
            idempotency_key=key,
            first_difference={"path": "operation",
                              "existing": {"operation": other["operation"],
                                           "subscription_id":
                                           other["subscription_id"],
                                           "target": other["target"]},
                              "requested": {}})

    @staticmethod
    def _first_prepare_diff(prev, spec: dict) -> dict | None:
        """逐个比较预登记规格，返回首个差异字段（确定性顺序）。"""
        fields = [
            ("subscription_id", prev["subscription_id"],
             spec["subscription_id"]),
            ("fingerprint", prev["fingerprint"], spec["fingerprint"]),
            ("effective_seq", int(prev["effective_seq"]),
             spec["effective_seq"]),
            ("grace_ms", int(prev["grace_ms"]), spec["grace_ms"]),
        ]
        for path, old, new in fields:
            if old != new:
                return {"path": path, "existing": old, "requested": new}
        return None

    # ======================================================================
    # 行 / 视图辅助
    # ======================================================================
    def _require_subscription(self, conn, subscription_id: str):
        row = conn.execute(
            "SELECT * FROM audit_subscriptions WHERE subscription_id=?",
            (subscription_id,)).fetchone()
        if row is None:
            raise SubscriptionNotFound(
                f"订阅 {subscription_id} 不存在",
                subscription_id=subscription_id)
        return row

    @staticmethod
    def _get_version_row(conn, subscription_id: str, version_no: int):
        return conn.execute(
            "SELECT * FROM audit_subscription_versions "
            "WHERE subscription_id=? AND version_no=?",
            (subscription_id, int(version_no))).fetchone()

    @staticmethod
    def _get_key_row_by_id(conn, subscription_id: str, key_id: str):
        """key_id 允许传 key_no（整数/整数字符串）或 key_id 哈希。"""
        if isinstance(key_id, int) or (
                isinstance(key_id, str) and key_id.isdigit()
                and len(key_id) <= 12):
            return conn.execute(
                "SELECT * FROM audit_subscription_signing_keys "
                "WHERE subscription_id=? AND key_no=?",
                (subscription_id, int(key_id))).fetchone()
        return conn.execute(
            "SELECT * FROM audit_subscription_signing_keys "
            "WHERE subscription_id=? AND key_id=?",
            (subscription_id, str(key_id))).fetchone()

    def _key_view(self, conn, k) -> dict[str, Any]:
        counts = conn.execute(
            "SELECT "
            "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS confirmed, "
            "SUM(CASE WHEN status IN (?,?,?) THEN 1 ELSE 0 END) AS open, "
            "SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS dead "
            "FROM audit_subscription_deliveries "
            "WHERE subscription_id=? AND signing_key_id=?",
            (D_CONFIRMED, *D_OPEN, D_DEAD,
             k["subscription_id"], k["key_id"])).fetchone()
        now = self._now()
        grace_active = (k["status"] == K_GRACE and k["grace_until_ms"]
                        is not None and now < int(k["grace_until_ms"]))
        # 首次轮换：被替换掉的版本冻结密钥的宽限窗口挂在 key_no=1 的行上
        vk_grace_until = k["version_key_grace_until_ms"] if (
            "version_key_grace_until_ms" in k.keys()) else None
        vk_retired = k["version_key_retired_at_ms"] if (
            "version_key_retired_at_ms" in k.keys()) else None
        version_key_grace_active = (
            int(k["key_no"]) == 1 and vk_retired is None
            and vk_grace_until is not None and now < int(vk_grace_until))
        return {
            "key_id": k["key_id"],
            "subscription_id": k["subscription_id"],
            "key_no": int(k["key_no"]),
            "idempotency_key": k["idempotency_key"],
            "fingerprint": k["fingerprint"],
            "effective_seq": int(k["effective_seq"]),
            "grace_ms": int(k["grace_ms"]),
            "status": k["status"],
            "replaces_key_id": k["replaces_key_id"],
            "snapshot_seq": int(k["snapshot_seq"]),
            "grace_until_ms": k["grace_until_ms"],
            "grace_active": grace_active,
            "version_key_grace_until_ms": vk_grace_until,
            "version_key_retired_at_ms": vk_retired,
            "version_key_grace_active": version_key_grace_active,
            "activated_at_ms": k["activated_at_ms"],
            "retired_at_ms": k["retired_at_ms"],
            "revoked_at_ms": k["revoked_at_ms"],
            "reject_reason": k["reject_reason"],
            "created_at_ms": k["created_at_ms"],
            "updated_at_ms": k["updated_at_ms"],
            "deliveries": {
                "confirmed": int(counts["confirmed"] or 0),
                "in_flight_or_pending": int(counts["open"] or 0),
                "dead_letter": int(counts["dead"] or 0),
            },
        }

    def _key_view_from_row(self, conn, k) -> dict[str, Any]:
        """写事务内构建视图（不回滚读快照）。"""
        return self._key_view(conn, k)

    @staticmethod
    def _verification_view(r) -> dict[str, Any]:
        return {
            "verification_id": r["verification_id"],
            "subscription_id": r["subscription_id"],
            "delivery_id": r["delivery_id"],
            "event_seq": int(r["event_seq"]),
            "key_id": r["key_id"],
            "expected_key_id": r["expected_key_id"],
            "result": r["result"],
            "detail": (json.loads(r["detail"]) if r["detail"] else None),
            # 重签产生的新签名只在这里可见；投递行自身的 signature 等全部
            # 字段保持原值，绝不被重签改写。
            "new_signature": r["new_signature"] if "new_signature" in r.keys()
            else None,
            "created_at_ms": r["created_at_ms"],
        }

    def _audit_locked(self, conn, subscription_id: str,
                      key_no: int | None, event: str, outcome: str,
                      detail: str | None = None, *,
                      detail_obj: dict | None = None,
                      now: int | None = None) -> None:
        """在订阅自己的审计历史只追加一行（绝不写 lease_events/租约/委托/
        版本行/投递记录）。复用订阅审计表，version_no 列置 NULL。"""
        conn.execute(
            "INSERT INTO audit_subscription_events(subscription_id, "
            "version_no, event, outcome, detail, detail_json, created_at_ms) "
            "VALUES(?,?,?,?,?,?,?)",
            (subscription_id, None, event, outcome, detail,
             canonical_json(detail_obj) if detail_obj is not None else None,
             now if now is not None else self._now()))


def require_value(value: Any, name: str) -> str:
    if value in (None, ""):
        raise AuditBadRequest(f"缺少必填参数: {name}")
    return value
