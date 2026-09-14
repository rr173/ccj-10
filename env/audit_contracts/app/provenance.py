"""冻结通知的逐字段来源说明（provenance）。

每份说明只记录**可验证的元数据**，绝不复制保存原始字段值：
- 字段路径、最终路径、原始来源路径；
- 值的 JSON 类型、规范化内容摘要（sha256，不含值本身）；
- 产生该字段的规则标识：直接取值 / 契约默认 / 固定默认映射 /
  旧字段重命名映射 / 允许删除映射 / 未知字段策略剥离 / 验证失败。

每次说明都绑定当时冻结的契约版本、载荷摘要与投递身份，并以
`record_digest`（本行内容自校验）+ `prev_record_digest`（哈希链锚定）
防篡改；查询时重算并校验，任何缺失、断链或摘要不一致都返回明确的
完整性错误，绝不把损坏结果当作可信说明。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from . import contracts as C

_MISSING = object()

# 来源类别（origin）
ORIGIN_DIRECT = "direct_value"              # 直接取自原始审计事件
ORIGIN_CONTRACT_DEFAULT = "contract_default"  # 契约 spec 中声明的 default
ORIGIN_FIXED_DEFAULT = "fixed_default"      # default 映射补入的固定值
ORIGIN_RENAMED = "renamed"                  # rename 映射：旧字段改名而来
ORIGIN_DROPPED = "dropped"                  # drop 映射允许删除
ORIGIN_STRIPPED = "unknown_stripped"        # unknown_policy=strip 剥离
ORIGIN_UNKNOWN_ALLOWED = "unknown_allowed"  # unknown_policy=allow 放行
ORIGIN_VALIDATION_FAILED = "validation_failed"  # 验证失败进入隔离
ORIGIN_MISSING_REQUIRED = "missing_required"    # 必填缺失（未恢复）
ORIGIN_UNGOVERNED = "ungoverned_passthrough"    # 契约撤销后无约束原样冻结


# --------------------------------------------------------------------------- #
# 内容摘要：只给类型 + sha256 + 大小，绝不含原始值
# --------------------------------------------------------------------------- #
def value_summary(value: Any) -> Dict[str, Any]:
    """对单个字段值做非可逆的内容摘要（不保存值本身）。"""
    canonical = C.canonical_payload(value)
    return {
        "type": _json_type(value),
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "canonical_bytes": len(canonical),
    }


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


# --------------------------------------------------------------------------- #
# 映射作用（带追踪）：派生载荷 + 每个路径上生效的映射规则
# --------------------------------------------------------------------------- #
def apply_mappings_tracked(derived: Any, rules: List[Any]) -> Tuple[Any, Dict[str, dict], List[dict]]:
    """把映射规则作用于派生计份（deepcopy 后的原始事件）。

    返回 (新派生, effects, applied)：
    - effects[最终路径] = {op, rule_id, mapping_id, value_summary?, src?}；
    - applied：按规则登记顺序的作用摘要（不含固定值本身，固定值摘要在条目里）。
    映射只作用于派生计份；调用方负责保证 events.raw_payload 永不改写。
    """
    out = json.loads(json.dumps(derived, ensure_ascii=False))
    effects: Dict[str, dict] = {}
    applied: List[dict] = []

    def norm(p: str) -> str:
        return p if p.startswith("$") else "$." + p.lstrip(".")

    def parts(path: str) -> List[str]:
        body = path[1:] if path.startswith("$") else path
        return [p for p in body.split(".") if p]

    def get(obj, path, default=_MISSING):
        cur = obj
        for part in parts(path):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def pop(obj, path):
        cur = obj
        ps = parts(path)
        for part in ps[:-1]:
            cur = cur[part]
        return cur.pop(ps[-1])

    def setv(obj, path, value):
        cur = obj
        ps = parts(path)
        for part in ps[:-1]:
            cur = cur.setdefault(part, {})
        cur[ps[-1]] = value

    for r in rules:
        rid = f"mapping:{r['id']}"
        brief = {"mapping_id": r["id"], "op": r["op"], "rule_id": rid}
        if r["op"] == "rename":
            src, dst = norm(r["src_path"]), norm(r["dst_path"])
            brief.update({"src_path": src, "dst_path": dst})
            present = get(out, src) is not _MISSING
            if present:
                val = pop(out, src)
                setv(out, dst, val)
                effects.pop(src, None)  # 源路径不再独立存在
                effects[dst] = {"op": "rename", "rule_id": rid,
                                "mapping_id": r["id"], "src": src, "applied": True}
            else:
                effects[src] = {"op": "rename", "rule_id": rid,
                                "mapping_id": r["id"], "src": src,
                                "dst": dst, "applied": False,
                                "reason": "源字段在该事件中不存在，规则未生效"}
        elif r["op"] == "default":
            dst = norm(r["dst_path"])
            fixed = json.loads(r["value"])
            brief.update({"dst_path": dst})
            if get(out, dst) is _MISSING:
                setv(out, dst, fixed)
                effects[dst] = {"op": "default", "rule_id": rid,
                                "mapping_id": r["id"], "applied": True,
                                "value_summary": value_summary(fixed)}
            else:
                effects[dst] = {"op": "default", "rule_id": rid,
                                "mapping_id": r["id"], "applied": False,
                                "reason": "目标字段已存在，固定默认值未写入"}
        elif r["op"] == "drop":
            src = norm(r["src_path"])
            brief.update({"src_path": src})
            if get(out, src) is not _MISSING:
                pop(out, src)
                effects[src] = {"op": "drop", "rule_id": rid,
                                "mapping_id": r["id"], "applied": True}
            else:
                effects[src] = {"op": "drop", "rule_id": rid,
                                "mapping_id": r["id"], "applied": False,
                                "reason": "字段在该事件中不存在，规则未生效"}
        applied.append(brief)
    return out, effects, applied


# --------------------------------------------------------------------------- #
# 逐字段来源条目
# --------------------------------------------------------------------------- #
def build_entries(spec: Optional[dict], source: Any, normalized: Any,
                  errors: List[dict], infos: List[dict],
                  effects: Optional[Dict[str, dict]] = None,
                  ungoverned: bool = False) -> List[dict]:
    """构建来源说明条目列表（按最终路径排序）。

    - spec=None 且 ungoverned=True：契约已撤销，原始事件原样冻结，逐字段记 passthrough；
    - 否则按契约树遍历：声明叶子（含契约默认/映射改名/映射默认/验证失败）、
      未知字段（strip 剥离 / allow 放行）、映射删除、必填缺失。
    """
    effects = effects or {}
    entries: List[dict] = []
    err_by_path = _index_reasons(errors)
    info_by_path = _index_reasons(infos)

    if ungoverned or spec is None:
        _walk_ungoverned(source, "$", entries)
        return _sorted_entries(entries)

    _walk_node(spec, source, normalized, "$", entries, effects,
               err_by_path, info_by_path)
    return _sorted_entries(entries)


def _walk_ungoverned(value: Any, path: str, entries: List[dict]) -> None:
    if isinstance(value, dict):
        for key in value:
            _walk_ungoverned(value[key], _join(path, key), entries)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _walk_ungoverned(item, f"{path}[{i}]", entries)
    else:
        entries.append(_entry(
            path=path, src_path=path, origin=ORIGIN_UNGOVERNED,
            value_type=_json_type(value), summary=value_summary(value),
            rule_id="governance:revoked",
            reason="契约在该序号已撤销，字段原样冻结，未做校验/规范化"))


def _walk_node(spec: dict, source: Any, normalized: Any, path: str,
               entries: List[dict], effects: Dict[str, dict],
               err_by_path: Dict[str, str], info_by_path: Dict[str, str]) -> None:
    t = spec["type"]

    if t == "object":
        if not isinstance(source, dict):
            # 结构类型不符：整个节点验证失败（无值进入最终载荷）
            entries.append(_failed(path, source, spec, err_by_path.get(path),
                                   summary_of=source))
            return
        props = spec.get("properties", {})
        policy = spec.get("unknown_policy", "strict")

        for key in sorted(source.keys()):
            child_path = _join(path, key)
            if key not in props:
                eff = effects.get(child_path)
                if eff and eff["op"] == "drop" and eff.get("applied"):
                    entries.append(_entry(
                        path=child_path, src_path=child_path, origin=ORIGIN_DROPPED,
                        value_type=_json_type(source[key]),
                        summary=value_summary(source[key]),
                        rule_id=eff["rule_id"], mapping_id=eff["mapping_id"],
                        reason="字段由允许删除（ignorable）映射规则删除"))
                    continue
                # 未知字段（注意：被 rename 映射改名的旧字段会落到 dst 处理，
                # 不会出现在这里，因为它已不在派生载荷的旧路径上）
                if policy == "strict":
                    entries.append(_entry(
                        path=child_path, src_path=child_path,
                        origin=ORIGIN_VALIDATION_FAILED,
                        value_type=_json_type(source[key]),
                        summary=value_summary(source[key]),
                        rule_id="policy:unknown_strict",
                        validation={"valid": False,
                                    "reason": err_by_path.get(child_path)
                                    or "未知字段（unknown_policy=strict）"}))
                elif policy == "strip":
                    entries.append(_entry(
                        path=child_path, src_path=child_path, origin=ORIGIN_STRIPPED,
                        value_type=_json_type(source[key]),
                        summary=value_summary(source[key]),
                        rule_id="policy:unknown_strip",
                        reason=info_by_path.get(child_path)
                        or "未知字段已按 strip 策略删除"))
                else:
                    entries.append(_entry(
                        path=child_path, src_path=child_path,
                        origin=ORIGIN_UNKNOWN_ALLOWED,
                        value_type=_json_type(source[key]),
                        summary=value_summary(source[key]),
                        rule_id="policy:unknown_allow",
                        reason=info_by_path.get(child_path)
                        or "未知字段按 allow 策略保留"))
                continue

            # 声明子字段：检查映射是否对它生效
            eff = effects.get(child_path)
            if eff and eff["op"] == "drop" and eff.get("applied"):
                entries.append(_entry(
                    path=child_path, src_path=child_path, origin=ORIGIN_DROPPED,
                    value_type=_json_type(source[key]),
                    summary=value_summary(source[key]),
                    rule_id=eff["rule_id"], mapping_id=eff["mapping_id"],
                    reason="声明字段由允许删除（ignorable）映射规则删除"))
                continue
            _walk_declared(props[key], source[key], child_path, entries,
                           effects, err_by_path, info_by_path, eff)

        # 声明但原始/派生载荷中缺失的字段（契约默认 / 必填缺失 / 映射补值）
        for name in sorted(props):
            child_path = _join(path, name)
            if name in source:
                continue
            _walk_missing(props[name], child_path, entries, effects,
                          err_by_path)
        return

    if t == "array":
        if not isinstance(source, list):
            entries.append(_failed(path, source, spec, err_by_path.get(path),
                                   summary_of=source))
            return
        for i, item in enumerate(source):
            _walk_node(spec["items"], item,
                       normalized[i] if isinstance(normalized, list)
                       and i < len(normalized) else None,
                       f"{path}[{i}]", entries, effects, err_by_path, info_by_path)
        return

    # 叶子
    eff = effects.get(path)
    if eff and eff["op"] == "rename" and eff.get("applied"):
        # 值来自被改名的旧字段
        reason = err_by_path.get(path)
        entries.append(_entry(
            path=path, src_path=eff["src"], origin=ORIGIN_RENAMED,
            value_type=t, summary=value_summary(source),
            rule_id=eff["rule_id"], mapping_id=eff["mapping_id"],
            renamed_from=eff["src"],
            validation=({"valid": not bool(reason), "reason": reason}
                        if reason else {"valid": True})))
        return
    if eff and eff["op"] == "default" and eff.get("applied"):
        # default 映射补入的固定值（叶子存在分支正常不会走到这里，
        # 因为补值后路径已在 source 中；保留以稳妥处理）
        entries.append(_entry(
            path=path, src_path=None, origin=ORIGIN_FIXED_DEFAULT,
            value_type=t, summary=eff.get("value_summary") or value_summary(source),
            rule_id=eff["rule_id"], mapping_id=eff["mapping_id"],
            validation={"valid": True}))
        return
    # 直接取值（可能验证失败）
    reason = err_by_path.get(path)
    entries.append(_entry(
        path=path, src_path=path,
        origin=ORIGIN_VALIDATION_FAILED if reason else ORIGIN_DIRECT,
        value_type=t if not reason else _json_type(source),
        summary=value_summary(source),
        rule_id="validation:type_or_enum" if reason else "source:direct",
        declared_type=t,
        validation=({"valid": False, "reason": reason}
                    if reason else {"valid": True})))


def _walk_declared(child_spec: dict, src_val: Any, path: str, entries: list,
                   effects: dict, err_by_path: dict, info_by_path: dict,
                   eff: Optional[dict]) -> None:
    """处理声明路径上、且值存在的字段（可能携带 rename/default 映射效果）。"""
    if eff and eff["op"] == "rename" and eff.get("applied") \
            and child_spec["type"] not in ("object", "array"):
        reason = err_by_path.get(path)
        entries.append(_entry(
            path=path, src_path=eff["src"], origin=ORIGIN_RENAMED,
            value_type=child_spec["type"], summary=value_summary(src_val),
            rule_id=eff["rule_id"], mapping_id=eff["mapping_id"],
            renamed_from=eff["src"],
            validation=({"valid": False, "reason": reason}
                        if reason else {"valid": True})))
        return
    _walk_node(child_spec, src_val, None, path, entries, effects,
               err_by_path, info_by_path)


def _walk_missing(child_spec: dict, path: str, entries: list,
                  effects: dict, err_by_path: dict) -> None:
    """处理声明缺失字段：映射删除 / 映射补固定值 / 契约默认 / 必填缺失。"""
    eff = effects.get(path)
    if eff and eff["op"] == "drop" and eff.get("applied"):
        # drop 映射已把该字段从派生载荷移除：此处无值可摘要，
        # 记录“删除”事实与规则标识（值摘要留空）。
        entries.append(_entry(
            path=path, src_path=path, origin=ORIGIN_DROPPED,
            value_type=child_spec["type"],
            rule_id=eff["rule_id"], mapping_id=eff["mapping_id"],
            reason="声明字段由允许删除（ignorable）映射规则删除"))
        return
    if eff and eff["op"] == "default" and eff.get("applied"):
        entries.append(_entry(
            path=path, src_path=None, origin=ORIGIN_FIXED_DEFAULT,
            value_type=child_spec["type"], summary=eff.get("value_summary"),
            rule_id=eff["rule_id"], mapping_id=eff["mapping_id"],
            validation={"valid": True}))
        return
    if "default" in child_spec:
        entries.append(_entry(
            path=path, src_path=None, origin=ORIGIN_CONTRACT_DEFAULT,
            value_type=child_spec["type"],
            summary=value_summary(child_spec["default"]),
            rule_id=f"contract_default:{child_spec['type']}",
            validation={"valid": True}))
        return
    if child_spec.get("required", True) and not child_spec.get("ignorable", False):
        entries.append(_entry(
            path=path, src_path=None, origin=ORIGIN_MISSING_REQUIRED,
            value_type=child_spec["type"],
            rule_id="validation:required",
            validation={"valid": False,
                        "reason": err_by_path.get(path) or "必填字段缺失"}))
    # 可选且无默认值：缺席合法，最终载荷中没有该字段，不产生条目。


def _failed(path: str, source: Any, spec: dict, reason: Optional[str],
            summary_of: Any = None) -> dict:
    return _entry(
        path=path, src_path=path, origin=ORIGIN_VALIDATION_FAILED,
        value_type=_json_type(source),
        summary=value_summary(summary_of if summary_of is not None else source),
        rule_id="validation:type_mismatch",
        declared_type=spec["type"],
        validation={"valid": False,
                    "reason": reason or f"期望 {spec['type']}，"
                    f"实际 {_json_type(source)}"})


def _entry(*, path: str, src_path: Optional[str], origin: str,
           value_type: Optional[str] = None, summary: Optional[dict] = None,
           rule_id: Optional[str] = None, mapping_id: Optional[int] = None,
           renamed_from: Optional[str] = None, declared_type: Optional[str] = None,
           validation: Optional[dict] = None, reason: Optional[str] = None) -> dict:
    e: Dict[str, Any] = {"path": path, "source_path": src_path, "origin": origin}
    if value_type is not None:
        e["value_type"] = value_type
    if declared_type is not None:
        e["declared_type"] = declared_type
    if summary is not None:
        e["value_summary"] = summary
    if rule_id is not None:
        e["rule_id"] = rule_id
    if mapping_id is not None:
        e["mapping_id"] = mapping_id
    if renamed_from is not None:
        e["renamed_from"] = renamed_from
    if validation is not None:
        e["validation"] = validation
    if reason is not None:
        e["reason"] = reason
    return e


def _index_reasons(items: List[dict]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items or []:
        # 同路径多条原因时保留第一条（确定顺序：errors/infos 已按遍历顺序生成）
        out.setdefault(it["path"], it["reason"])
    return out


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path != "$" else f"$.{key}"


def _sorted_entries(entries: List[dict]) -> List[dict]:
    return sorted(entries, key=lambda e: (e["path"], e["origin"],
                                          e.get("rule_id") or ""))


# --------------------------------------------------------------------------- #
# 说明记录摘要 + 哈希链
# --------------------------------------------------------------------------- #
def explanation_record_digest(*, sub_id: str, seq: int, attempt_no: int,
                              notification_id: str, contract_version: Optional[str],
                              payload_digest: str, origin_event_digest: str,
                              entries: List[dict]) -> str:
    """说明行内容的规范化 sha256：任何字段被篡改都会导致重算不一致。"""
    body = {
        "sub_id": sub_id, "seq": seq, "attempt_no": attempt_no,
        "notification_id": notification_id,
        "contract_version": contract_version,
        "payload_digest": payload_digest,
        "origin_event_digest": origin_event_digest,
        "entries": entries,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# --------------------------------------------------------------------------- #
# 完整性校验
# --------------------------------------------------------------------------- #
class ProvenanceIntegrityError(Exception):
    """来源说明记录缺失、顺序断裂、哈希链断裂或摘要不一致。"""

    def __init__(self, code: str, checks: List[dict]):
        super().__init__(code)
        self.code = code
        self.checks = checks


def verify_chain(attempts: List[Any], explanations: List[Any]) -> List[dict]:
    """按顺序重算每条说明的自校验摘要并检查哈希链。

    attempts / explanations 为 sqlite Row 列表（已按 attempt_no 排序）。
    返回每项检查结果；发现问题时抛 ProvenanceIntegrityError，
    调用方必须把它作为明确完整性错误返回，不得返回可信内容。
    """
    checks: List[dict] = []
    exp_by_attempt = {r["attempt_no"]: r for r in explanations}

    def fail(code: str, problems: List[dict]) -> None:
        checks.extend(problems)
        raise ProvenanceIntegrityError(code, checks)

    problems: List[dict] = []
    prev_digest: Optional[str] = None
    expected_no = 1
    for att in attempts:
        no = att["attempt_no"]
        if no != expected_no:
            problems.append({"check": "attempt_sequence", "ok": False,
                             "expected_attempt_no": expected_no,
                             "actual_attempt_no": no,
                             "reason": "尝试记录顺序断裂或缺失"})
        exp = exp_by_attempt.get(no)
        if exp is None:
            problems.append({"check": "explanation_present", "ok": False,
                             "attempt_no": no,
                             "reason": "该次尝试缺少来源说明记录"})
        else:
            entries = json.loads(exp["entries_json"])
            recomputed = explanation_record_digest(
                sub_id=exp["sub_id"], seq=exp["seq"], attempt_no=exp["attempt_no"],
                notification_id=exp["notification_id"],
                contract_version=exp["contract_version"],
                payload_digest=exp["payload_digest"],
                origin_event_digest=exp["origin_event_digest"],
                entries=entries)
            if recomputed != exp["record_digest"]:
                problems.append({"check": "record_digest", "ok": False,
                                 "attempt_no": no,
                                 "stored": exp["record_digest"],
                                 "recomputed": recomputed,
                                 "reason": "来源说明内容与记录摘要不一致（记录可能被篡改）"})
            if exp["prev_record_digest"] != prev_digest:
                problems.append({"check": "hash_chain", "ok": False,
                                 "attempt_no": no,
                                 "expected_prev": prev_digest,
                                 "actual_prev": exp["prev_record_digest"],
                                 "reason": "哈希链锚点与上一尝试不一致（顺序断裂或记录被篡改）"})
            # 绑定一致性：投递身份 / 契约版本 / 载荷摘要
            for field, att_val, exp_val in (
                    ("notification_id", att["notification_id"], exp["notification_id"]),
                    ("contract_version", att["contract_version"], exp["contract_version"]),
                    ("payload_digest", att["payload_digest"], exp["payload_digest"])):
                if att_val != exp_val:
                    problems.append({"check": f"binding_{field}", "ok": False,
                                     "attempt_no": no, "field": field,
                                     "attempt_value": att_val,
                                     "explanation_value": exp_val,
                                     "reason": "来源说明绑定与尝试记录不一致"})
            prev_digest = exp["record_digest"]
        expected_no = no + 1

    if len(exp_by_attempt) > len(attempts):
        orphans = sorted(set(exp_by_attempt) - {a["attempt_no"] for a in attempts})
        problems.append({"check": "explanation_orphans", "ok": False,
                         "attempt_nos": orphans,
                         "reason": "存在不属于任何尝试的来源说明记录"})
    if problems:
        fail("provenance_integrity_error", problems)
    return [{"check": "record_digest", "ok": True},
            {"check": "hash_chain", "ok": True},
            {"check": "bindings", "ok": True},
            {"check": "attempts_count", "ok": True, "attempts": len(attempts),
             "explanations": len(explanations)}]


def verify_event_binding(explanation: Any, raw_event_digest: str) -> None:
    """来源说明绑定的原始事件摘要必须与 events 表中该序号的原始事件一致。"""
    if explanation["origin_event_digest"] != raw_event_digest:
        raise ProvenanceIntegrityError("provenance_integrity_error", [{
            "check": "origin_event_digest", "ok": False,
            "attempt_no": explanation["attempt_no"],
            "stored": explanation["origin_event_digest"],
            "recomputed": raw_event_digest,
            "reason": "来源说明绑定的原始事件摘要与审计事件不一致（记录可能被篡改）"}])


def verify_notification_binding(notification: Any, explanation: Any) -> List[dict]:
    """最新说明绑定的冻结载荷摘要 / 投递身份必须与通知行一致（恢复成功时）。"""
    problems: List[dict] = []
    if notification["notification_id"] != explanation["notification_id"]:
        problems.append({"check": "binding_notification_id", "ok": False,
                         "reason": "来源说明绑定的投递身份与通知不一致"})
    if notification["status"] in ("queued", "delivered", "ungoverned") \
            and notification["digest"] != explanation["payload_digest"] \
            and notification["digest"] is not None:
        # 恢复成功的说明记录的是该次尝试的冻结载荷；通知行已为最新冻结时必须相等
        problems.append({"check": "frozen_digest", "ok": False,
                         "attempt_no": explanation["attempt_no"],
                         "notification_digest": notification["digest"],
                         "explanation_payload_digest": explanation["payload_digest"],
                         "reason": "最新来源说明的载荷摘要与冻结通知不一致"})
    return problems


# --------------------------------------------------------------------------- #
# 两次尝试逐字段比较
# --------------------------------------------------------------------------- #
_CHANGE_ORIGINS = {ORIGIN_DROPPED, ORIGIN_STRIPPED, ORIGIN_MISSING_REQUIRED,
                   ORIGIN_VALIDATION_FAILED}


def compare_explanations(entries_a: List[dict], entries_b: List[dict]) -> dict:
    """逐字段比较两次尝试的来源说明。

    返回 added / removed / renamed / changed / unchanged 五组字段差异，
    每项带两侧来源、规则标识与值摘要变化。重命名优先于 add/remove 配对。
    """
    a_by_path = {e["path"]: e for e in entries_a}
    b_by_path = {e["path"]: e for e in entries_b}

    # 1) 重命名配对：B 中 renamed 条目的源路径在 A 中存在，即视为改名
    #    （即使 A 在目标路径上还有一条 missing_required——这正是“值放错字段
    #    且目标必填缺失”的典型修复场景）。
    pairs: List[Tuple[str, str]] = []
    used_a: set = set()
    for pb, eb in sorted(b_by_path.items()):
        if eb.get("origin") == ORIGIN_RENAMED and eb.get("source_path") \
                and eb["source_path"] in a_by_path:
            pairs.append((eb["source_path"], pb))
            used_a.add(eb["source_path"])

    renamed_fields: List[dict] = []
    for pa, pb in pairs:
        ea, eb = a_by_path[pa], b_by_path[pb]
        renamed_fields.append({
            "path": pb, "from_path": pa,
            "change": "renamed",
            "before": _brief(ea), "after": _brief(eb),
            "rule_id": eb.get("rule_id"),
            "mapping_id": eb.get("mapping_id"),
            "value_summary_changed": _summ_changed(ea, eb),
        })

    added, removed, changed, unchanged = [], [], [], []
    paired_b = {pb for _, pb in pairs}

    for pb in sorted(b_by_path):
        if pb in paired_b:
            continue
        eb = b_by_path[pb]
        ea = a_by_path.get(pb)
        if ea is None:
            added.append({"path": pb, "change": "added",
                          "after": _brief(eb),
                          "rule_id": eb.get("rule_id"),
                          "reason": _add_reason(eb)})
            continue
        # 允许删除：字段在 B 中被 drop 映射移除，归入 removed 并带删除规则
        if eb.get("origin") == ORIGIN_DROPPED:
            removed.append({"path": pb, "change": "removed",
                            "before": _brief(ea), "after": _brief(eb),
                            "rule_id": eb.get("rule_id"),
                            "mapping_id": eb.get("mapping_id"),
                            "reason": "该字段在修复重试中由允许删除（ignorable）映射删除"})
            continue
        diff = _field_diff(ea, eb)
        (changed if diff else unchanged).append(diff or {
            "path": pb, "change": "unchanged",
            "before": _brief(ea), "after": _brief(eb)})

    for pa in sorted(a_by_path):
        if pa in used_a or pa in b_by_path:
            continue
        ea = a_by_path[pa]
        removed.append({"path": pa, "change": "removed",
                        "before": _brief(ea),
                        "rule_id": ea.get("rule_id"),
                        "reason": _remove_reason(ea)})

    return {
        "added_fields": added,
        "removed_fields": removed,
        "renamed_fields": renamed_fields,
        "changed_fields": changed,
        "unchanged_fields": unchanged,
        "counts": {"added": len(added), "removed": len(removed),
                   "renamed": len(renamed_fields), "changed": len(changed),
                   "unchanged": len(unchanged)},
    }


def _field_diff(ea: dict, eb: dict) -> Optional[dict]:
    changes: List[str] = []
    if ea.get("origin") != eb.get("origin"):
        changes.append("origin")
    if ea.get("rule_id") != eb.get("rule_id"):
        changes.append("rule")
    if ea.get("source_path") != eb.get("source_path"):
        changes.append("source_path")
    sa = (ea.get("value_summary") or {}).get("digest")
    sb = (eb.get("value_summary") or {}).get("digest")
    summ_changed = sa != sb
    if summ_changed:
        changes.append("value_summary")
    va = (ea.get("validation") or {}).get("valid")
    vb = (eb.get("validation") or {}).get("valid")
    if va != vb:
        changes.append("validation")
    if not changes:
        return None
    return {"path": eb["path"], "changes": changes,
            "before": _brief(ea), "after": _brief(eb),
            "rule_before": ea.get("rule_id"), "rule_after": eb.get("rule_id"),
            "value_summary_before": ea.get("value_summary"),
            "value_summary_after": eb.get("value_summary")}


def _brief(e: dict) -> dict:
    return {"path": e["path"], "source_path": e.get("source_path"),
            "origin": e["origin"], "rule_id": e.get("rule_id"),
            "mapping_id": e.get("mapping_id"),
            "value_type": e.get("value_type"),
            "value_summary": e.get("value_summary"),
            "validation": e.get("validation")}


def _summ_changed(ea: dict, eb: dict) -> bool:
    return (ea.get("value_summary") or {}).get("digest") != \
        (eb.get("value_summary") or {}).get("digest")


def _add_reason(eb: dict) -> str:
    if eb.get("origin") == ORIGIN_FIXED_DEFAULT:
        return "修复重试通过固定默认值映射补入该字段"
    if eb.get("origin") == ORIGIN_DIRECT:
        return "修复后该字段出现在最终载荷中"
    return eb.get("reason") or f"新增字段（来源：{eb.get('origin')}）"


def _remove_reason(ea: dict) -> str:
    if ea.get("origin") == ORIGIN_STRIPPED:
        return "该字段在新尝试中不再出现（未知字段剥离/载荷变化）"
    if ea.get("origin") == ORIGIN_DROPPED:
        return "该字段已在之前尝试中由允许删除映射移除"
    if ea.get("origin") == ORIGIN_VALIDATION_FAILED:
        return "验证失败字段在修复重试后不再出现"
    if ea.get("origin") == ORIGIN_MISSING_REQUIRED:
        return "缺失字段在修复重试中被补入"
    return ea.get("reason") or "该字段在新尝试中不再出现"
