"""审计证据包（audit evidence package）。

在租约、审计回放与可验证归档能力之上，把多份**已完成**的资源归档/委托
凭证归档按管理员给定的组合顺序组合成一份只读证据包。

冻结语义（创建时一次性钉死）
============================
- **归档清单**：每份源归档的标识、0 起的组合顺序（position）与收录方式
  （``content`` 原文 / ``reference`` 稳定引用）在创建时写入
  ``evidence_entries``，之后只读；
- **每份归档的内容校验值**：清单里记录创建时源归档的 ``content_sha256``
  （``source_sha256``）。源归档之后即使被再次核验、或产生新的归档，
  证据包内容都不受影响；若源归档内容后来被改动，证据包核验会在
  ``sources[position]`` 处报首个差异（双方值都给出）；
- **组合顺序**：顺序是清单的一部分，也是清单指纹的一部分——换顺序就是
  另一份证据包，同键提交会明确冲突；
- **生成时元数据**：创建墙钟、逻辑钟读数、稳定视图上界 snapshot_seq、
  可选 ``metadata``（规范化后冻结）。

幂等与冲突
==========
- 同一组归档（含同一收录方式）+ 同一组合顺序 + 同一幂等键重复创建，
  只返回同一份证据包（HTTP 200 + ``replayed: true``）；
- 同键但清单不同（换归档/换顺序/换收录方式）→ 409 ``evidence_id_conflict``，
  响应给出首个不同的字段路径与双方值；
- 不同键但清单相同 → 409 ``evidence_manifest_conflict``，
  指向已存在的证据包——同一套证据不允许生成两份互相独立的"原件"。

可续跑的后台生成
================
- 按条目分块（``chunk_size`` 条/块）把源归档载荷冻结进
  ``evidence_entry_contents``，每块一个事务、进度落库
  （``processed_entries`` / ``last_frozen_position``）；
- 服务重启后从已保存进度自动续跑；失败重试经
  ``INSERT OR IGNORE`` + 仅对 ``pending`` 条目推进，**不会重复写入**；
- 生成时只读取 ``archives`` 源行，绝不修改源归档。

只读下载
========
``download`` 返回落库原文（字节稳定，响应头带 ``X-Evidence-SHA256``），
文档包含：可独立解析的证据包清单、每份归档的原文或稳定引用、顺序敏感的
组合摘要（combination_digest）与总校验值（content_sha256）。

独立核验（verified / verify_failed）
====================================
逐份检查：源归档是否存在、源归档内容哈希是否与冻结的 source_sha256 一致、
冻结载荷是否与源内容一致、组合顺序是否完整，并重算组合摘要与总校验值。
任一失败给出**首个差异**的归档标识（archive_id）、字段路径（path）
与双方值（archived / recomputed）。

只读边界：本模块只写 evidence_packages / evidence_entries /
evidence_entry_contents 三张自有表，绝不修改租约、委托、原始审计历史
或源归档（archives/archive_events 对本模块只读）。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from .archive import (
    ArchiveError,
    canonical_json,
    content_sha256,
    first_diff,
)
from .audit import AuditBadRequest

# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class EvidenceError(ArchiveError):
    code = "evidence_error"


class EvidenceNotFound(EvidenceError):
    code = "evidence_not_found"
    status = 404


class EvidenceNotReady(EvidenceError):
    code = "evidence_not_ready"
    status = 409


class EvidenceIdConflict(EvidenceError):
    """同一幂等键被清单不同的创建请求占用（409）。"""

    code = "evidence_id_conflict"
    status = 409


class EvidenceManifestConflict(EvidenceError):
    """同一份清单（归档集合+顺序+收录方式）已用别的幂等键创建过（409）。"""

    code = "evidence_manifest_conflict"
    status = 409


class EvidenceSourceNotFound(EvidenceError):
    """清单中的某份源归档不存在（404）。"""

    code = "evidence_source_not_found"
    status = 404


class EvidenceSourceNotReady(EvidenceError):
    """清单中的某份源归档尚未生成完成（409）。"""

    code = "evidence_source_not_ready"
    status = 409


class EvidenceBadState(EvidenceError):
    """当前状态不允许该操作（如对非 failed 的证据包发起重试，409）。"""

    code = "evidence_bad_state"
    status = 409


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

MODE_CONTENT = "content"        # 收录原文
MODE_REFERENCE = "reference"    # 只收录稳定引用
INCLUDE_MODES = (MODE_CONTENT, MODE_REFERENCE)

STATUS_PENDING = "pending"
STATUS_BUILDING = "building"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

VERIFY_UNVERIFIED = "unverified"
VERIFY_VERIFIED = "verified"
VERIFY_FAILED = "verify_failed"

MAX_ATTEMPTS = 5  # 后台自动重试上限；之后可用 retry 手动复位
CHAIN_V1 = "sha256-chain-v1"

_MISSING = "<missing>"


# ---------------------------------------------------------------------------
# 纯函数：清理解析 / 指纹 / 组合摘要
# ---------------------------------------------------------------------------


def parse_entries(raw: Any) -> list[dict[str, str]]:
    """把请求里的 archives 参数解析成 [{archive_id, include_mode}]。

    允许两种写法："归档id"（默认收录原文）或
    {"archive_id": "...", "include": "content|reference"}。
    重复归档**允许**出现（同一归档可以不同位置重复收录，也可以不同
    收录方式重复收录），这是必须覆盖的正常边界；空清单也是合法输入，
    代表一份"空组合"证据包。
    """
    if not isinstance(raw, list):
        raise AuditBadRequest(
            "archives 必须是数组：按组合顺序给出每份归档的 archive_id"
            "（可写 {archive_id, include:'content|reference'}）",
        )
    entries: list[dict[str, str]] = []
    for i, item in enumerate(raw):
        if isinstance(item, str):
            aid, mode = item, MODE_CONTENT
        elif isinstance(item, dict):
            aid = item.get("archive_id")
            mode = item.get("include", MODE_CONTENT)
        else:
            raise AuditBadRequest(
                f"archives[{i}] 必须是 archive_id 字符串或 "
                "{archive_id, include} 对象",
            )
        if not isinstance(aid, str) or not aid.strip():
            raise AuditBadRequest(
                f"archives[{i}].archive_id 缺失或不是非空字符串")
        if mode not in INCLUDE_MODES:
            raise AuditBadRequest(
                f"archives[{i}].include 只能取 content / reference",
                archive_id=aid, include=mode,
            )
        entries.append({"archive_id": aid.strip(), "include_mode": mode})
    return entries


def manifest_fingerprint(entries: list[dict[str, str]]) -> str:
    """对"有序归档清单（归档标识 + 收录方式）"计算指纹。

    只覆盖创建者可控的组合参数：同组归档、同顺序、同收录方式必得到同一
    指纹；换其中任何一个就是不同指纹。源归档的内容校验值不进指纹
    （源内容变化由核验环节发现，而不应该让同一份组合变成"另一个包"）。
    """
    spec = [{"position": i,
             "archive_id": e["archive_id"],
             "include_mode": e["include_mode"]}
            for i, e in enumerate(entries)]
    return hashlib.sha256(canonical_json(spec).encode("utf-8")).hexdigest()


def chain_next(digest: str, archive_id: str, frozen_sha256: str) -> str:
    """组合摘要链式推进一步（顺序敏感）。

    每一步都把"上一步摘要 + 该位置归档标识 + 该位置冻结载荷哈希"喂入
    SHA-256：调换顺序、换归档、改任一份的冻结内容都会改变最终摘要。
    """
    h = hashlib.sha256()
    h.update(digest.encode("ascii"))
    h.update(b"|")
    h.update(archive_id.encode("utf-8"))
    h.update(b"|")
    h.update(frozen_sha256.encode("ascii"))
    return h.hexdigest()


def frozen_payload_hash(archive_id: str, mode: str, source_sha256: str,
                        source_text: str | None) -> str:
    """单条收录载荷（content/reference）的 SHA-256。

    与冻结进 evidence_entry_contents 的规范化 JSON 严格一致，因此
    核验时可以独立复算；对同一份源归档、同一种收录方式永远得到同值。
    """
    payload = _build_frozen_payload(archive_id, mode, source_sha256,
                                    source_text)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _build_frozen_payload(archive_id: str, mode: str, source_sha256: str,
                          source_text: str | None) -> dict[str, Any]:
    """构造一份归档在证据包中的收录载荷。

    include=content：归档文档原文作为独立可解析 JSON 内嵌
    （source_archive_content），即使未来源行丢失，证据包仍可独立核验内容；
    include=reference：只给稳定引用（archive_id + 内容哈希 + 节点定位），
    核验时回到源归档取内容比对。
    """
    entry: dict[str, Any] = {
        "kind": "evidence_entry",
        "version": 1,
        "archive_id": archive_id,
        "include_mode": mode,
        "source_sha256": source_sha256,
    }
    if mode == MODE_CONTENT:
        # 原文内嵌：直接放源归档落库文档（本身就是独立可解析的 JSON 对象）
        entry["source_archive_content"] = (
            json.loads(source_text) if source_text is not None else None)
    return entry


def _reference_for(archive_row) -> dict[str, Any]:
    """源归档的稳定引用：不随运行态变化、足以唯一定位该归档及其冻结节点。"""
    return {
        "archive_id": archive_row["archive_id"],
        "scope": archive_row["scope"],
        "resource": archive_row["resource"],
        "credential_id": archive_row["credential_id"] or None,
        "node_seq": archive_row["node_seq"],
        "snapshot_seq": archive_row["snapshot_seq"],
        "content_sha256": archive_row["content_sha256"],
        "location": f"/audit/archives/{archive_row['archive_id']}/download",
    }


# ---------------------------------------------------------------------------
# 证据包管理器
# ---------------------------------------------------------------------------


class EvidencePackageManager:
    """证据包的创建、分块生成、查询、只读下载、独立核验与失败重试。"""

    def __init__(self, store: Any, *, chunk_size: int = 1):
        self._store = store
        self.chunk_size = max(1, int(chunk_size))

    # ---- 创建（幂等 + 冲突显式化） --------------------------------------
    def create_package(self, *, archives: Any, idempotency_key: Any,
                       metadata: Any = None) -> tuple[dict[str, Any], bool]:
        """创建证据包，返回 (证据包视图, 是否新建)。"""
        entries = parse_entries(archives)
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise AuditBadRequest(
                "idempotency_key 必填：同一组归档+同一组合顺序+同一幂等键"
                "重复创建只会得到同一份证据包")
        key = idempotency_key.strip()
        frozen_metadata = self._freeze_metadata(metadata)

        store = self._store
        with store._lock:  # noqa: SLF001 - 与存储/归档共用同一把进程锁
            conn = store._conn  # noqa: SLF001
            max_seq = self._max_event_seq(conn)

            # 先解析并校验每份源归档（必须存在且已完成），并把创建时的
            # 内容校验值钉进清单；顺序原样保留（含重复归档）
            source_rows = []
            for i, e in enumerate(entries):
                row = conn.execute(
                    "SELECT * FROM archives WHERE archive_id=?",
                    (e["archive_id"],),
                ).fetchone()
                if row is None:
                    raise EvidenceSourceNotFound(
                        f"清单第 {i} 份归档 {e['archive_id']} 不存在，"
                        "证据包创建被拒绝",
                        archive_id=e["archive_id"], position=i)
                if row["status"] != STATUS_COMPLETED:
                    raise EvidenceSourceNotReady(
                        f"清单第 {i} 份归档 {e['archive_id']} 尚未生成完成"
                        f"（当前状态 {row['status']}），不能组合进证据包",
                        archive_id=e["archive_id"], position=i,
                        status=row["status"])
                source_rows.append(row)

            fingerprint = manifest_fingerprint(entries)

            # 1) 幂等键先行：同键即回放或冲突
            prev_key = conn.execute(
                "SELECT * FROM evidence_packages WHERE idempotency_key=?",
                (key,),
            ).fetchone()
            if prev_key is not None:
                prev_entries = self._manifest_entries(conn,
                                                      prev_key["package_id"])
                diff = self._first_manifest_diff(entries, prev_entries)
                if diff is None:
                    return self._view(prev_key), False
                raise EvidenceIdConflict(
                    f"幂等键 {key} 已用于证据包 "
                    f"{prev_key['package_id']}，本次清单与首次创建不一致："
                    f"首个差异位于 {diff['path']}",
                    package_id=prev_key["package_id"],
                    existing_fingerprint=prev_key["manifest_fingerprint"],
                    requested_fingerprint=fingerprint,
                    first_difference=diff,
                )

            # 2) 清单指纹：同一套组合不允许用别的键再造一份
            prev_man = conn.execute(
                "SELECT * FROM evidence_packages WHERE manifest_fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if prev_man is not None:
                raise EvidenceManifestConflict(
                    "同一组归档、同一组合顺序与收录方式的证据包已经存在"
                    f"（{prev_man['package_id']}，幂等键 "
                    f"{prev_man['idempotency_key']}）；换归档、换顺序或换"
                    "收录方式才能创建新证据包，重复创建请使用原幂等键",
                    package_id=prev_man["package_id"],
                    existing_idempotency_key=prev_man["idempotency_key"],
                )

            package_id = uuid.uuid4().hex
            now = store.clock.wall_ms()
            logical = store.clock.logical()
            try:
                conn.execute(
                    "INSERT INTO evidence_packages(package_id, idempotency_key, "
                    "manifest_fingerprint, status, total_entries, "
                    "last_frozen_position, metadata_json, snapshot_seq, "
                    "created_logical, created_at_ms, updated_at_ms) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (package_id, key, fingerprint, STATUS_PENDING, len(entries),
                     -1, frozen_metadata, max_seq, logical, now, now),
                )
                for i, (e, row) in enumerate(zip(entries, source_rows)):
                    conn.execute(
                        "INSERT INTO evidence_entries(package_id, position, "
                        "archive_id, include_mode, source_sha256, status) "
                        "VALUES(?,?,?,?,?,?)",
                        (package_id, i, e["archive_id"], e["include_mode"],
                         row["content_sha256"], "pending"),
                    )
                conn.commit()
            except sqlite3.IntegrityError:
                # 唯一索引兜底（锁内不会走到，防御性保留）：键或清单指纹
                # 已存在时回放到既有证据包，绝不产生第二份
                conn.rollback()
                prev_key = conn.execute(
                    "SELECT * FROM evidence_packages WHERE idempotency_key=?",
                    (key,),
                ).fetchone()
                if prev_key is not None:
                    prev_entries = self._manifest_entries(
                        conn, prev_key["package_id"])
                    if self._first_manifest_diff(entries, prev_entries) is None:
                        return self._view(prev_key), False
                    raise EvidenceIdConflict(
                        f"幂等键 {key} 已用于证据包 "
                        f"{prev_key['package_id']}，本次清单与首次创建不一致",
                        package_id=prev_key["package_id"])
                prev_man = conn.execute(
                    "SELECT * FROM evidence_packages "
                    "WHERE manifest_fingerprint=?",
                    (fingerprint,),
                ).fetchone()
                if prev_man is not None:
                    raise EvidenceManifestConflict(
                        "同一组归档、同一组合顺序与收录方式的证据包已经存在"
                        f"（{prev_man['package_id']}）",
                        package_id=prev_man["package_id"],
                        existing_idempotency_key=prev_man["idempotency_key"])
                raise
            return self._view(self._get_row(conn, package_id)), True

    @staticmethod
    def _freeze_metadata(metadata: Any) -> str | None:
        if metadata is None:
            return None
        if not isinstance(metadata, dict):
            raise AuditBadRequest("metadata 必须是对象（JSON），将在创建时"
                                  "规范化冻结")
        # 规范化：键排序、紧凑分隔；值必须能被 JSON 表示
        try:
            return canonical_json(metadata)
        except (TypeError, ValueError) as exc:
            raise AuditBadRequest(f"metadata 无法序列化为 JSON：{exc}")

    @staticmethod
    def _max_event_seq(conn) -> int:
        row = conn.execute(
            "SELECT MAX(seq) AS m FROM lease_events").fetchone()
        return int(row["m"]) if row is not None and row["m"] is not None else 0

    @staticmethod
    def _manifest_entries(conn, package_id) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT position, archive_id, include_mode, source_sha256 "
            "FROM evidence_entries WHERE package_id=? ORDER BY position ASC",
            (package_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _first_manifest_diff(requested: list[dict[str, str]],
                             existing: list[dict[str, Any]]) -> dict | None:
        """比较两份有序清单，返回首个差异（位置/归档标识/收录方式）。

        requested 只有组合参数；existing 还带 source_sha256。这里只比较
        创建者可控的组合维度（长度、顺序、archive_id、include_mode），
        源哈希差异由核验环节负责。
        """
        n = min(len(requested), len(existing))
        for i in range(n):
            req, ex = requested[i], existing[i]
            if req["archive_id"] != ex["archive_id"]:
                return {"path": f"archives[{i}].archive_id", "position": i,
                        "field": "archive_id",
                        "archive_id": ex["archive_id"],
                        "requested": req["archive_id"],
                        "existing": ex["archive_id"]}
            if req["include_mode"] != ex["include_mode"]:
                return {"path": f"archives[{i}].include", "position": i,
                        "field": "include",
                        "archive_id": ex["archive_id"],
                        "requested": req["include_mode"],
                        "existing": ex["include_mode"]}
        if len(requested) != len(existing):
            i = n
            req_at = requested[i] if i < len(requested) else None
            ex_at = existing[i] if i < len(existing) else None
            return {"path": f"archives[{i}]", "position": i,
                    "field": "length",
                    "archive_id": (req_at or ex_at or {}).get("archive_id"),
                    "requested": (req_at if req_at is not None else _MISSING),
                    "existing": (ex_at if ex_at is not None else _MISSING),
                    "message": "清单长度不同：组合顺序不完整或多出归档"}
        return None

    # ---- 查询 -----------------------------------------------------------
    @staticmethod
    def _get_row(conn, package_id):
        return conn.execute(
            "SELECT * FROM evidence_packages WHERE package_id=?",
            (package_id,),
        ).fetchone()

    def get_package(self, package_id: str) -> dict[str, Any]:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, package_id)
            if row is None:
                raise EvidenceNotFound(
                    f"证据包 {package_id} 不存在", package_id=package_id)
            try:
                return self._view(row)
            finally:
                conn.rollback()

    def list_packages(self, *, status=None, archive_id=None,
                      limit: Any = 100) -> dict[str, Any]:
        limit = _bounded_limit(limit)
        if status is not None and status not in (
                STATUS_PENDING, STATUS_BUILDING, STATUS_COMPLETED,
                STATUS_FAILED):
            raise AuditBadRequest(
                "status 只能取 pending/building/completed/failed",
                status=status)
        where, args = [], []
        if status:
            where.append("p.status=?")
            args.append(status)
        if archive_id:
            where.append(
                "EXISTS (SELECT 1 FROM evidence_entries e WHERE "
                "e.package_id=p.package_id AND e.archive_id=?)")
            args.append(str(archive_id))
        sql = ("SELECT p.* FROM evidence_packages p")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY p.created_at_ms ASC, p.package_id ASC LIMIT ?"
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            rows = conn.execute(sql, (*args, limit)).fetchall()
            try:
                return {"packages": [self._view(r) for r in rows],
                        "limit": limit}
            finally:
                conn.rollback()

    def _view(self, row) -> dict[str, Any]:
        total, done = row["total_entries"], row["processed_entries"]
        return {
            "package_id": row["package_id"],
            "idempotency_key": row["idempotency_key"],
            "manifest_fingerprint": row["manifest_fingerprint"],
            "status": row["status"],
            "progress": {
                "processed_entries": done,
                "total_entries": total,
                "remaining_entries": max(total - done, 0),
                "percent": round(100.0 * done / total, 1) if total else 100.0,
                "done": done >= total,
            },
            "attempts": row["attempts"],
            "error": row["error"],
            "error_detail": (json.loads(row["error_detail"])
                             if row["error_detail"] else None),
            "snapshot_seq": row["snapshot_seq"],
            "content_sha256": row["content_sha256"],
            "combination_digest": row["combination_digest"],
            "verify_status": row["verify_status"],
            "verify_detail": (json.loads(row["verify_detail"])
                              if row["verify_detail"] else None),
            "verified_at_ms": row["verified_at_ms"],
            "created_at_ms": row["created_at_ms"],
            "updated_at_ms": row["updated_at_ms"],
            "completed_at_ms": row["completed_at_ms"],
            "download_url":
                f"/audit/evidence/{row['package_id']}/download",
        }

    # ---- 只读下载 -------------------------------------------------------
    def download(self, package_id: str) -> tuple[str, dict[str, Any]]:
        """返回 (证据包文档原文, 证据包视图)。文档即落库字节，重启不变。"""
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, package_id)
            if row is None:
                raise EvidenceNotFound(
                    f"证据包 {package_id} 不存在", package_id=package_id)
            if row["status"] != STATUS_COMPLETED:
                raise EvidenceNotReady(
                    f"证据包 {package_id} 尚未生成完成（当前状态 "
                    f"{row['status']}，进度 "
                    f"{row['processed_entries']}/{row['total_entries']}），"
                    "暂不能下载",
                    package_id=package_id, status=row["status"])
            try:
                return row["content"], self._view(row)
            finally:
                conn.rollback()

    # ---- 后台生成：按条目分块冻结 + 进度落库，可续跑 --------------------
    def process_pending(self, *, max_packages: int | None = None,
                        max_chunks_per_package: int | None = None) -> int:
        """推进待生成的证据包，返回本轮处理过的证据包数。

        pending/building 立即可取；failed 在自动重试上限内也会被续跑。
        每块（chunk_size 个条目）一个事务：崩溃/重启后从
        last_frozen_position 继续；INSERT OR IGNORE 保证不重复写入。
        """
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            rows = conn.execute(
                "SELECT package_id FROM evidence_packages WHERE status IN (?,?)"
                " OR (status=? AND attempts<?) "
                "ORDER BY created_at_ms ASC, package_id ASC",
                (STATUS_PENDING, STATUS_BUILDING, STATUS_FAILED,
                 MAX_ATTEMPTS),
            ).fetchall()
            conn.rollback()
        ids = [r["package_id"] for r in rows]
        if max_packages is not None:
            ids = ids[:max_packages]
        n = 0
        for package_id in ids:
            if self._process_one(package_id,
                                 max_chunks=max_chunks_per_package):
                n += 1
        return n

    def _process_one(self, package_id: str, *,
                     max_chunks: int | None) -> bool:
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, package_id)
            if row is None or row["status"] == STATUS_COMPLETED:
                return False
            try:
                if row["status"] in (STATUS_PENDING, STATUS_FAILED):
                    conn.execute(
                        "UPDATE evidence_packages SET status=?, "
                        "attempts=attempts+1, error=NULL, error_detail=NULL, "
                        "updated_at_ms=? WHERE package_id=?",
                        (STATUS_BUILDING, store.clock.wall_ms(), package_id))
                    conn.commit()
                chunks = 0
                while True:
                    row = self._get_row(conn, package_id)
                    if row["processed_entries"] >= row["total_entries"]:
                        break
                    if max_chunks is not None and chunks >= max_chunks:
                        return True  # 本轮先到这，下轮从已存进度继续
                    self._freeze_chunk_locked(row)
                    chunks += 1
                self._finalize_locked(package_id)
                return True
            except Exception as exc:  # noqa: BLE001 - 失败落库后可续跑
                detail = None
                if isinstance(exc, EvidenceError):
                    detail = json.dumps(exc.to_response(), ensure_ascii=False)
                conn.rollback()  # 回滚未提交的分块，进度停在上一个已提交块
                conn.execute(
                    "UPDATE evidence_packages SET status=?, error=?, "
                    "error_detail=?, updated_at_ms=? WHERE package_id=?",
                    (STATUS_FAILED, f"{type(exc).__name__}: {exc}",
                     detail, store.clock.wall_ms(), package_id),
                )
                conn.commit()
                return True

    def _freeze_chunk_locked(self, row) -> int:
        """冻结下一块（chunk_size 个条目），单事务提交。

        每个条目只在仍为 pending 时推进：重启续跑/失败重试会跳过已冻结
        位置，INSERT OR IGNORE 兜底，绝不重复写入。冻结时重新读取源归档：
        若源归档已不存在或内容哈希与创建时钉死的值不一致，本块失败落库
        （failed + 首个差异明细），证据包绝不会静默收录被掉包的内容。
        """
        conn = self._store._conn  # noqa: SLF001
        package_id = row["package_id"]
        positions = [r["position"] for r in conn.execute(
            "SELECT position FROM evidence_entries WHERE package_id=? "
            "AND status='pending' ORDER BY position ASC LIMIT ?",
            (package_id, self.chunk_size),
        ).fetchall()]
        if not positions:
            # 防御：计数与实际不符时直接收敛，避免空转
            conn.execute(
                "UPDATE evidence_packages SET processed_entries=total_entries, "
                "updated_at_ms=? WHERE package_id=?",
                (self._store.clock.wall_ms(), package_id))
            conn.commit()
            return 0

        for position in positions:
            entry = conn.execute(
                "SELECT * FROM evidence_entries WHERE package_id=? AND position=?",
                (package_id, position),
            ).fetchone()
            source = conn.execute(
                "SELECT * FROM archives WHERE archive_id=?",
                (entry["archive_id"],),
            ).fetchone()
            if source is None:
                raise EvidenceSourceNotFound(
                    f"生成第 {position} 份归档时发现源归档 "
                    f"{entry['archive_id']} 已不存在",
                    package_id=package_id, archive_id=entry["archive_id"],
                    position=position,
                    path=f"sources[{position}].archive_id")
            if source["status"] != STATUS_COMPLETED:
                raise EvidenceSourceNotReady(
                    f"源归档 {entry['archive_id']} 当前状态为 "
                    f"{source['status']}，不是完成态",
                    package_id=package_id, archive_id=entry["archive_id"],
                    position=position,
                    path=f"sources[{position}].status")
            if source["content_sha256"] != entry["source_sha256"]:
                # 创建后源归档内容哈希发生变化：冻结立即失败并报告双方值
                raise EvidenceError(
                    f"源归档 {entry['archive_id']} 的内容校验值与证据包"
                    "创建时冻结的值不一致，拒绝收录",
                    package_id=package_id,
                    archive_id=entry["archive_id"], position=position,
                    path=f"sources[{position}].source_sha256",
                    section="sources",
                    archived=entry["source_sha256"],
                    recomputed=source["content_sha256"],
                )
            payload = _build_frozen_payload(
                entry["archive_id"], entry["include_mode"],
                entry["source_sha256"], source["content"])
            payload_text = canonical_json(payload)
            frozen_sha = hashlib.sha256(
                payload_text.encode("utf-8")).hexdigest()
            # INSERT OR IGNORE：同一位置重试/续跑不会重复写入
            conn.execute(
                "INSERT OR IGNORE INTO evidence_entry_contents"
                "(package_id, position, payload) VALUES(?,?,?)",
                (package_id, position, payload_text))
            conn.execute(
                "UPDATE evidence_entries SET status='frozen', frozen_sha256=? "
                "WHERE package_id=? AND position=? AND status='pending'",
                (frozen_sha, package_id, position))

        last_pos = max(positions)
        conn.execute(
            "UPDATE evidence_packages SET processed_entries=processed_entries+?, "
            "last_frozen_position=?, updated_at_ms=? WHERE package_id=?",
            (len(positions), last_pos, self._store.clock.wall_ms(),
             package_id))
        conn.commit()
        return len(positions)

    def _finalize_locked(self, package_id: str) -> None:
        """全部条目冻结完毕后组装证据包文档、组合摘要与总校验值。

        内容完全由冻结输入与创建元数据决定（不再读可变运行态），因此
        失败重试生成的内容逐字节一致；对 evidence_packages 是单次
        UPDATE，不会重复写入。
        """
        conn = self._store._conn  # noqa: SLF001
        row = self._get_row(conn, package_id)
        manifest_rows = conn.execute(
            "SELECT * FROM evidence_entries WHERE package_id=? "
            "ORDER BY position ASC", (package_id,),
        ).fetchall()
        contents = {r["position"]: r for r in conn.execute(
            "SELECT * FROM evidence_entry_contents WHERE package_id=?",
            (package_id,),
        ).fetchall()}

        manifest, sources = [], []
        digest = _chain_seed()
        for m in manifest_rows:
            c = contents[m["position"]]
            payload = json.loads(c["payload"])
            source_row = conn.execute(
                "SELECT * FROM archives WHERE archive_id=?",
                (m["archive_id"],),
            ).fetchone()
            if source_row is None:
                # 防御：冻结时已确认源归档存在（锁内不可能在此期间消失），
                # 即便如此也绝不产出引用为空的证据包
                raise EvidenceSourceNotFound(
                    f"组装证据包时发现源归档 {m['archive_id']} 已不存在",
                    package_id=package_id, archive_id=m["archive_id"],
                    position=m["position"],
                    path=f"sources[{m['position']}].archive_id")
            digest = chain_next(digest, m["archive_id"], m["frozen_sha256"])
            manifest.append({
                "position": m["position"],
                "archive_id": m["archive_id"],
                "include_mode": m["include_mode"],
                "source_sha256": m["source_sha256"],
                "frozen_sha256": m["frozen_sha256"],
                "reference": (_reference_for(source_row)
                              if source_row is not None else None),
            })
            sources.append(payload)

        # 组合顺序完整性：位置必须是连续的 0..N-1
        expected = list(range(len(manifest_rows)))
        actual = [m["position"] for m in manifest_rows]
        if actual != expected:
            raise EvidenceError(
                "组合顺序不完整：冻结条目位置不是连续的 0..N-1",
                package_id=package_id, path="manifest.positions",
                archived=actual, recomputed=expected)

        core = {
            "kind": "lease_audit_evidence_package",
            "version": 1,
            "package_id": package_id,
            "idempotency_key": row["idempotency_key"],
            "manifest_fingerprint": row["manifest_fingerprint"],
            "snapshot_seq": row["snapshot_seq"],
            "created_at_ms": row["created_at_ms"],
            "created_logical": row["created_logical"],
            "metadata": (json.loads(row["metadata_json"])
                         if row["metadata_json"] else None),
            "manifest": manifest,
            "sources": sources,
            "combination": {
                "algorithm": CHAIN_V1,
                "entries": len(manifest),
                "ordered_archive_ids": [m["archive_id"] for m in manifest],
                "digest": digest,
            },
        }
        core["content_sha256"] = content_sha256(core)
        text = json.dumps(core, ensure_ascii=False, sort_keys=True)
        now = self._store.clock.wall_ms()
        conn.execute(
            "UPDATE evidence_packages SET status=?, content=?, content_sha256=?, "
            "combination_digest=?, processed_entries=total_entries, "
            "completed_at_ms=?, updated_at_ms=? WHERE package_id=?",
            (STATUS_COMPLETED, text, core["content_sha256"], digest, now, now,
             package_id))
        conn.commit()

    # ---- 独立核验 -------------------------------------------------------
    def verify(self, package_id: str) -> dict[str, Any]:
        """独立核验已完成的证据包并把结果标记在包上（重启不丢）。

        检查顺序（首个失败即返回首个差异）：
        1. 证据包文档与保存的总校验值一致（文档未被改动）；
        2. 组合摘要可由冻结条目按组合顺序独立重算得到；
        3. 清单/顺序/长度完整，且冻结载荷表与文档逐条一致；
        4. 逐份检查源归档：存在、源内容哈希 = 冻结的 source_sha256、
           冻结载荷与源内容一致、内嵌原文可独立通过内容哈希自洽校验。
        只写 evidence_packages 自有表，绝不触碰源归档/租约/委托/历史。
        """
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, package_id)
            if row is None:
                raise EvidenceNotFound(
                    f"证据包 {package_id} 不存在", package_id=package_id)
            if row["status"] != STATUS_COMPLETED:
                raise EvidenceNotReady(
                    f"证据包 {package_id} 尚未生成完成（当前状态 "
                    f"{row['status']}），不能核验",
                    package_id=package_id, status=row["status"])
            content = json.loads(row["content"])

            divergence = self._check_checksum(row, content)
            if divergence is None:
                divergence = self._check_combination(content)
            if divergence is None:
                divergence = self._check_manifest_and_frozen(conn, row,
                                                             content)
            if divergence is None:
                divergence = self._check_sources(conn, content)

            now = store.clock.wall_ms()
            if divergence is None:
                conn.execute(
                    "UPDATE evidence_packages SET verify_status=?, "
                    "verify_detail=NULL, verified_at_ms=?, updated_at_ms=? "
                    "WHERE package_id=?",
                    (VERIFY_VERIFIED, now, now, package_id))
                result = {
                    "package_id": package_id,
                    "verify_status": VERIFY_VERIFIED,
                    "first_divergence": None,
                    "message": "独立核验通过：总校验值、组合摘要、清单顺序"
                               "与逐份源归档（存在性/内容哈希/原文）全部一致",
                }
            else:
                detail = json.dumps(divergence, ensure_ascii=False)
                conn.execute(
                    "UPDATE evidence_packages SET verify_status=?, "
                    "verify_detail=?, verified_at_ms=?, updated_at_ms=? "
                    "WHERE package_id=?",
                    (VERIFY_FAILED, detail, now, now, package_id))
                result = {
                    "package_id": package_id,
                    "verify_status": VERIFY_FAILED,
                    "first_divergence": divergence,
                    "message": "核验失败：首个差异位于 "
                               f"{divergence.get('path')}（归档 "
                               f"{divergence.get('archive_id')}："
                               f"{divergence.get('message', '内容不一致')}）",
                }
            conn.commit()
            result["verified_at_ms"] = now
            result["content_sha256"] = row["content_sha256"]
            result["combination_digest"] = row["combination_digest"]
            return result

    @staticmethod
    def _check_checksum(row, content) -> dict | None:
        core = {k: v for k, v in content.items() if k != "content_sha256"}
        actual = content_sha256(core)
        if actual != content.get("content_sha256") or \
                actual != row["content_sha256"]:
            return {
                "section": "checksum",
                "path": "content_sha256",
                "archive_id": None,
                "expected": row["content_sha256"],
                "archived": content.get("content_sha256"),
                "recomputed": actual,
                "message": "证据包文档与保存的总校验值不符，文档可能被篡改",
            }
        return None

    @staticmethod
    def _check_combination(content) -> dict | None:
        combo = content.get("combination") or {}
        digest = _chain_seed()
        manifest = content.get("manifest") or []
        sources = content.get("sources") or []
        if len(manifest) != len(sources):
            i = min(len(manifest), len(sources))
            return {
                "section": "combination",
                "path": f"sources[{i}]",
                "archive_id": (manifest[i]["archive_id"]
                               if i < len(manifest) else None),
                "message": "组合顺序不完整：清单条目数与收录条目数不一致",
                "archived": len(manifest), "recomputed": len(sources),
            }
        for i, (m, payload) in enumerate(zip(manifest, sources)):
            frozen_sha = hashlib.sha256(
                canonical_json(payload).encode("utf-8")).hexdigest()
            if frozen_sha != m.get("frozen_sha256"):
                return {
                    "section": "combination",
                    "path": f"manifest[{i}].frozen_sha256",
                    "archive_id": m.get("archive_id"),
                    "archived": m.get("frozen_sha256"),
                    "recomputed": frozen_sha,
                    "message": "收录载荷哈希与清单记录不一致",
                }
            digest = chain_next(digest, m["archive_id"], frozen_sha)
        if digest != combo.get("digest"):
            return {
                "section": "combination",
                "path": "combination.digest",
                "archive_id": None,
                "archived": combo.get("digest"),
                "recomputed": digest,
                "message": "组合摘要无法按组合顺序独立重算得到：顺序或"
                           "某份归档内容可能被改动",
            }
        ids = combo.get("ordered_archive_ids")
        if ids != [m["archive_id"] for m in manifest]:
            return {
                "section": "combination",
                "path": "combination.ordered_archive_ids",
                "archive_id": None,
                "archived": ids,
                "recomputed": [m["archive_id"] for m in manifest],
                "message": "组合摘要记录的归档顺序与清单不一致",
            }
        return None

    def _check_manifest_and_frozen(self, conn, row, content) -> dict | None:
        package_id = row["package_id"]
        manifest = content.get("manifest")
        if not isinstance(manifest, list):
            return {"section": "manifest", "path": "manifest",
                    "archive_id": None,
                    "message": "证据包文档缺少可独立解析的清单 manifest"}
        # 顺序完整性：连续 0..N-1
        positions = [m.get("position") for m in manifest]
        if positions != list(range(len(manifest))):
            return {"section": "manifest", "path": "manifest.positions",
                    "archive_id": None, "archived": positions,
                    "recomputed": list(range(len(manifest))),
                    "message": "组合顺序不完整或被重排"}
        frozen_rows = conn.execute(
            "SELECT * FROM evidence_entry_contents WHERE package_id=? "
            "ORDER BY position ASC", (package_id,),
        ).fetchall()
        if len(frozen_rows) != len(manifest):
            i = min(len(frozen_rows), len(manifest))
            return {
                "section": "manifest",
                "path": f"manifest[{i}]",
                "archive_id": manifest[i]["archive_id"]
                if i < len(manifest) else None,
                "archived": len(manifest), "recomputed": len(frozen_rows),
                "message": "冻结条目数与清单不一致（有缺失或多余的归档）",
            }
        for i, (m, fr) in enumerate(zip(manifest, frozen_rows)):
            stored_payload = json.loads(fr["payload"])
            if m.get("position") != fr["position"]:
                return {"section": "manifest",
                        "path": f"manifest[{i}].position",
                        "archive_id": m.get("archive_id"),
                        "archived": m.get("position"),
                        "recomputed": fr["position"],
                        "message": "清单位置与冻结载荷位置不一致"}
            diff = first_diff(content["sources"][i], stored_payload,
                              f"sources[{i}]")
            if diff is not None:
                return {**diff, "section": "frozen_payload",
                        "archive_id": m.get("archive_id"),
                        "message": "文档收录条目与冻结载荷副本不一致"}
            if hashlib.sha256(
                    fr["payload"].encode("utf-8")).hexdigest() != \
                    m.get("frozen_sha256"):
                return {"section": "frozen_payload",
                        "path": f"manifest[{i}].frozen_sha256",
                        "archive_id": m.get("archive_id"),
                        "archived": m.get("frozen_sha256"),
                        "recomputed": hashlib.sha256(
                            fr["payload"].encode("utf-8")).hexdigest(),
                        "message": "冻结载荷哈希与清单记录不一致"}
        return None

    def _check_sources(self, conn, content) -> dict | None:
        """逐份检查源归档：存在性、内容哈希一致、原文/引用一致。"""
        for i, (m, payload) in enumerate(zip(content["manifest"],
                                             content["sources"])):
            aid = m["archive_id"]
            source = conn.execute(
                "SELECT * FROM archives WHERE archive_id=?", (aid,),
            ).fetchone()
            # 1) 源归档必须存在
            if source is None:
                return {
                    "section": "sources",
                    "path": f"sources[{i}].archive_id",
                    "position": i, "archive_id": aid,
                    "archived": aid, "recomputed": _MISSING,
                    "message": f"第 {i} 份源归档 {aid} 已不存在",
                }
            # 2) 源归档当前内容哈希必须与冻结时钉死的 source_sha256 一致
            if source["content_sha256"] != m["source_sha256"]:
                return {
                    "section": "sources",
                    "path": f"sources[{i}].source_sha256",
                    "position": i, "archive_id": aid,
                    "archived": m["source_sha256"],
                    "recomputed": source["content_sha256"],
                    "message": f"源归档 {aid} 的内容哈希与证据包冻结值不一致"
                               "（源归档可能被改动）",
                }
            # 3) 收录方式与载荷自洽
            if payload.get("include_mode") != m["include_mode"]:
                return {
                    "section": "sources",
                    "path": f"sources[{i}].include_mode",
                    "position": i, "archive_id": aid,
                    "archived": m["include_mode"],
                    "recomputed": payload.get("include_mode"),
                    "message": "收录方式在清单与载荷间不一致",
                }
            if payload.get("source_sha256") != m["source_sha256"]:
                return {
                    "section": "sources",
                    "path": f"sources[{i}].source_sha256",
                    "position": i, "archive_id": aid,
                    "archived": m["source_sha256"],
                    "recomputed": payload.get("source_sha256"),
                    "message": "载荷记录的源哈希与清单不一致",
                }
            if m["include_mode"] == MODE_CONTENT:
                divergence = self._check_embedded_source(i, aid, payload,
                                                         source)
                if divergence is not None:
                    return divergence
            else:
                divergence = self._check_reference(i, aid, m, source)
                if divergence is not None:
                    return divergence
        return None

    @staticmethod
    def _check_embedded_source(i, aid, payload, source) -> dict | None:
        """include=content：内嵌原文必须与源归档当前内容逐字段一致，
        且内嵌原文自身的 content_sha256 字段可独立复算通过。"""
        embedded = payload.get("source_archive_content")
        if embedded is None:
            return {"section": "sources",
                    "path": f"sources[{i}].source_archive_content",
                    "position": i, "archive_id": aid,
                    "archived": "<present>", "recomputed": _MISSING,
                    "message": "收录方式为 content 但缺少归档原文"}
        current = json.loads(source["content"])
        diff = first_diff(embedded, current,
                          f"sources[{i}].source_archive_content")
        if diff is not None:
            return {**diff, "section": "sources", "position": i,
                    "archive_id": aid,
                    "message": f"内嵌的源归档 {aid} 原文与源归档当前内容"
                               "首次出现差异"}
        # 内嵌文档自身的校验值必须自洽（独立解析者无需访问本服务即可验）
        core = {k: v for k, v in embedded.items() if k != "content_sha256"}
        recomputed = content_sha256(core)
        if recomputed != embedded.get("content_sha256"):
            return {"section": "sources",
                    "path": (f"sources[{i}].source_archive_content"
                             ".content_sha256"),
                    "position": i, "archive_id": aid,
                    "archived": embedded.get("content_sha256"),
                    "recomputed": recomputed,
                    "message": "内嵌归档原文的内容校验值无法独立复算"}
        return None

    @staticmethod
    def _check_reference(i, aid, manifest_entry, source) -> dict | None:
        """include=reference：清单中的稳定引用必须仍准确定位源归档。"""
        ref = manifest_entry.get("reference")
        if not isinstance(ref, dict):
            return {"section": "sources",
                    "path": f"manifest[{i}].reference",
                    "position": i, "archive_id": aid,
                    "archived": _MISSING, "recomputed": "<present>",
                    "message": "收录方式为 reference 但清单缺少稳定引用"}
        current_ref = _reference_for(source)
        diff = first_diff(ref, current_ref, f"manifest[{i}].reference")
        if diff is not None:
            return {**diff, "section": "sources", "position": i,
                    "archive_id": aid,
                    "message": f"源归档 {aid} 的稳定引用与当前定位信息"
                               "首次出现差异"}
        return None

    # ---- 失败重试（手动复位） -------------------------------------------
    def retry(self, package_id: str) -> dict[str, Any]:
        """把失败的证据包复位为 pending，由后台从已保存进度继续。"""
        store = self._store
        with store._lock:  # noqa: SLF001
            conn = store._conn  # noqa: SLF001
            row = self._get_row(conn, package_id)
            if row is None:
                raise EvidenceNotFound(
                    f"证据包 {package_id} 不存在", package_id=package_id)
            if row["status"] != STATUS_FAILED:
                raise EvidenceBadState(
                    f"证据包 {package_id} 当前状态为 {row['status']}，"
                    "只有 failed 的证据包需要重试",
                    package_id=package_id, status=row["status"])
            conn.execute(
                "UPDATE evidence_packages SET status=?, attempts=0, "
                "error=NULL, error_detail=NULL, updated_at_ms=? "
                "WHERE package_id=?",
                (STATUS_PENDING, store.clock.wall_ms(), package_id))
            conn.commit()
            return self._view(self._get_row(conn, package_id))


def _chain_seed() -> str:
    """组合摘要链的固定初值（空组合也有确定摘要）。"""
    return hashlib.sha256(b"lease-audit-evidence-chain-v1").hexdigest()


def _bounded_limit(value) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError):
        raise AuditBadRequest("limit 必须是整数", limit=value)
    if limit < 1:
        raise AuditBadRequest("limit 必须 >= 1", limit=limit)
    return min(limit, 1000)
