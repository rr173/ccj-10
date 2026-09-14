"""载荷契约核心：Schema 定义、校验/规范化、冻结摘要、字段差异与双向兼容性判定。

契约是一棵字段树：
- object 节点用 properties 描述子字段；
- array 节点用 items 描述元素；
- 叶子节点声明 type（string/int/number/bool/null）、enum、required、ignorable。

根节点及每个 object 节点用 unknown_policy 声明未知字段策略：
- strict：出现未声明字段即错误（阻断）；
- strip ：未知字段规范化时删除（信息记录，不阻断）；
- allow ：未知字段保留。
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")

SCALAR_TYPES = {"string", "int", "number", "bool", "null"}
POLICIES = {"strict", "strip", "allow"}


class ContractError(ValueError):
    """契约 Schema 本身不合法（登记时返回 400）。"""


class VersionError(ValueError):
    """版本号格式不合法。"""


_UNSET = object()


def validate_version(v: str) -> None:
    if not isinstance(v, str) or not VERSION_RE.match(v or ""):
        raise VersionError(f"版本号必须是语义化版本 MAJOR.MINOR.PATCH，收到: {v!r}")


def version_tuple(v: str) -> Tuple[int, int, int]:
    return tuple(int(x) for x in v.split("."))  # type: ignore[return-value]


def validate_spec(spec: Any, path: str = "$") -> None:
    """递归检查管理员提交的契约 Schema 是否自洽。"""
    if not isinstance(spec, dict):
        raise ContractError(f"{path}: 字段定义必须是对象")
    t = spec.get("type")
    if t not in ("object", "array") and t not in SCALAR_TYPES:
        raise ContractError(f"{path}: type 必须是 object/array/{'/'.join(sorted(SCALAR_TYPES))}")
    if not isinstance(spec.get("required", True), bool):
        raise ContractError(f"{path}: required 必须是布尔值")
    if not isinstance(spec.get("ignorable", False), bool):
        raise ContractError(f"{path}: ignorable 必须是布尔值")
    if "enum" in spec:
        if t not in SCALAR_TYPES:
            raise ContractError(f"{path}: enum 只能用于标量字段")
        if not isinstance(spec["enum"], list) or not spec["enum"]:
            raise ContractError(f"{path}: enum 必须是非空数组")
        for ev in spec["enum"]:
            if type(ev) is not _json_scalar_type(t):
                raise ContractError(f"{path}: enum 值 {ev!r} 类型与 {t} 不一致")
    if "default" in spec and not _value_matches_type(spec["default"], t, spec.get("enum")):
        raise ContractError(f"{path}: default 值与字段类型/枚举不匹配")

    if t == "object":
        policy = spec.get("unknown_policy", "strict")
        if policy not in POLICIES:
            raise ContractError(f"{path}: unknown_policy 必须是 {sorted(POLICIES)}")
        props = spec.get("properties", {})
        if not isinstance(props, dict):
            raise ContractError(f"{path}: properties 必须是对象")
        for name, child in props.items():
            if not isinstance(name, str) or not NAME_RE.match(name):
                raise ContractError(f"{path}: 字段名 {name!r} 非法（^[A-Za-z_][A-Za-z0-9_-]{{0,63}}$）")
            validate_spec(child, f"{path}.{name}")
    elif t == "array":
        if "items" not in spec:
            raise ContractError(f"{path}: array 必须声明 items")
        validate_spec(spec["items"], f"{path}[]")


def _json_scalar_type(t: str) -> Any:
    return {
        "string": str,
        "int": int,
        "number": (int, float),
        "bool": bool,
        "null": type(None),
    }[t]


def _value_matches_type(v: Any, t: str, enum: Optional[list] = None) -> bool:
    if t == "string":
        ok = isinstance(v, str)
    elif t == "int":
        ok = isinstance(v, int) and not isinstance(v, bool)
    elif t == "number":
        ok = isinstance(v, (int, float)) and not isinstance(v, bool)
    elif t == "bool":
        ok = isinstance(v, bool)
    elif t == "null":
        ok = v is None
    else:
        ok = False
    if ok and enum is not None and v not in enum:
        return False
    return ok


# --------------------------------------------------------------------------- #
# 校验 + 规范化
# --------------------------------------------------------------------------- #

def check_and_normalize(
    spec: Dict[str, Any],
    payload: Any,
    path: str = "$",
    present: bool = True,
) -> Tuple[Any, List[Dict[str, str]], List[Dict[str, Any]]]:
    """返回 (规范化后的值, 阻断错误列表, 信息列表)。

    阻断错误：类型不符 / 必填缺失 / 枚举越界 / strict 未知字段。
    信息记录：strip 删除的未知字段、allow 放行的未知字段。
    """
    errors: List[Dict[str, str]] = []
    infos: List[Dict[str, Any]] = []

    if not present:
        if "default" in spec:
            return _deepcopy_json(spec["default"]), errors, infos
        # 可选/可忽略字段整体缺席即通过，不再检查子树内部的必填项
        if not spec.get("required", True) or spec.get("ignorable", False):
            return _UNSET, errors, infos
        errors.append({"path": path, "reason": "必填字段缺失"})
        return None, errors, infos

    t = spec["type"]

    if t == "object":
        if not isinstance(payload, dict):
            errors.append({"path": path, "reason": f"期望 object，实际 {_type_name(payload)}"})
            return None, errors, infos
        props = spec.get("properties", {})
        policy = spec.get("unknown_policy", "strict")
        out: Dict[str, Any] = {}
        for key in sorted(payload.keys()):
            child_path = f"{path}.{key}" if path != "$" else f"$.{key}"
            if key not in props:
                if policy == "strict":
                    errors.append({"path": child_path, "reason": "未知字段（unknown_policy=strict）"})
                elif policy == "strip":
                    infos.append({"path": child_path, "reason": "未知字段已按 strip 策略删除"})
                else:
                    infos.append({"path": child_path, "reason": "未知字段按 allow 策略保留"})
                    out[key] = payload[key]
                continue
            val, errs, inf = check_and_normalize(props[key], payload[key], child_path, True)
            errors.extend(errs)
            infos.extend(inf)
            if val is not _UNSET and not errs:
                out[key] = val
        for name, child in props.items():
            if name in payload:
                continue
            val, errs, inf = check_and_normalize(child, None, f"{path}.{name}", False)
            errors.extend(errs)
            infos.extend(inf)
            if val is not _UNSET:
                out[name] = val
        return out, errors, infos

    if t == "array":
        if not isinstance(payload, list):
            errors.append({"path": path, "reason": f"期望 array，实际 {_type_name(payload)}"})
            return None, errors, infos
        out_list: List[Any] = []
        for i, item in enumerate(payload):
            val, errs, inf = check_and_normalize(spec["items"], item, f"{path}[{i}]", True)
            errors.extend(errs)
            infos.extend(inf)
            if not errs:
                out_list.append(val)
        return out_list, errors, infos

    # 标量
    if not _value_matches_type(payload, t):
        errors.append({"path": path, "reason": f"期望 {t}，实际 {_type_name(payload)}"})
        return None, errors, infos
    if "enum" in spec and payload not in spec["enum"]:
        errors.append({
            "path": path,
            "reason": f"枚举值 {payload!r} 不在允许集合 {spec['enum']}",
        })
        return None, errors, infos
    return payload, errors, infos


def _type_name(v: Any) -> str:
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
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def _deepcopy_json(v: Any) -> Any:
    return json.loads(json.dumps(v))


def canonical_payload(normalized: Any) -> bytes:
    """规范化载荷的冻结字节：键排序、无空白、Unicode 不转义。"""
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# 拍平叶子路径 + 字段级差异与兼容性
# --------------------------------------------------------------------------- #

def flatten(spec: Dict[str, Any], path: str = "$") -> Dict[str, Dict[str, Any]]:
    """拍平为 {dotted.path: 叶子描述}。数组元素按 [] 占位符折叠。"""
    t = spec["type"]
    if t == "object":
        out: Dict[str, Dict[str, Any]] = {}
        policy = spec.get("unknown_policy", "strict")
        out[path] = {"kind": "object", "unknown_policy": policy}
        for name, child in sorted(spec.get("properties", {}).items()):
            child_path = f"{path}.{name}" if path != "$" else f"$.{name}"
            out.update(flatten(child, child_path))
        return out
    if t == "array":
        out = {path: {"kind": "array"}}
        out.update(flatten(spec["items"], path + "[]"))
        return out
    leaf = {
        "kind": "leaf",
        "type": t,
        "required": spec.get("required", True),
        "ignorable": spec.get("ignorable", False),
        "enum": spec.get("enum"),
        "has_default": "default" in spec,
    }
    return {path: leaf}


def _type_backward_ok(old: str, new: str) -> bool:
    """旧数据（按 old 写出）能否被按 new 读取：宽化。"""
    return old == new or (old == "int" and new == "number")


def _type_forward_ok(old: str, new: str) -> bool:
    """新数据（按 new 写出）能否被按 old 读取：窄化或等价。"""
    return old == new or (old == "number" and new == "int")


def diff_contracts(old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> Dict[str, Any]:
    """计算两个契约的字段级差异，并分别判断向后/向前兼容性。

    约定（schema-registry 语义）：
    - backward（向后兼容）：旧版本载荷能被新版本消费者接受；
    - forward （向前兼容）：新版本载荷能被旧版本消费者接受。
    """
    old_leaves = flatten(old) if old else {}
    new_leaves = flatten(new)
    fields: List[Dict[str, Any]] = []

    def add(path, change, backward, forward, detail):
        fields.append({
            "path": path,
            "change": change,
            "backward_compatible": bool(backward),
            "forward_compatible": bool(forward),
            "detail": detail,
        })

    for path in sorted(set(old_leaves) | set(new_leaves)):
        o = old_leaves.get(path)
        n = new_leaves.get(path)

        if o is None:
            # 新增路径
            if n["kind"] == "leaf":
                if not n["required"] or n["has_default"]:
                    add(path, "field_added_optional", True, True,
                        "新增可选/带默认值字段，双方都可接受")
                else:
                    add(path, "field_added_required", True, False,
                        "新增必填字段：旧载荷没有该字段，会被旧契约拒绝（向前不兼容）")
            else:
                add(path, "node_added", True, True, "新增结构节点")
            continue
        if n is None:
            # 删除路径：只有明确标记 ignorable 的字段删除才向后安全。
            # 仅 optional 不够——旧载荷仍可能携带该字段，新 strict 会拒绝。
            if o["kind"] == "leaf":
                if o["ignorable"]:
                    add(path, "field_removed_ignorable", True, True,
                        "删除明确允许忽略（ignorable）的字段")
                else:
                    add(path, "field_removed", False, True,
                        "删除字段：旧载荷可能仍带该字段，会被新契约 strict 拒绝（向后不兼容）")
            else:
                add(path, "node_removed", False, True, "删除结构节点")
            continue

        if o["kind"] == "object" and n["kind"] == "object":
            if o["unknown_policy"] != n["unknown_policy"]:
                # strict->strip 让新消费者更宽容（向后安全）；旧 strict 消费者会拒绝新放行字段（向前不安全）
                order = {"strict": 0, "strip": 1, "allow": 2}
                add(path, "unknown_policy_changed",
                    order[n["unknown_policy"]] >= order[o["unknown_policy"]],
                    order[n["unknown_policy"]] <= order[o["unknown_policy"]],
                    f"未知字段策略 {o['unknown_policy']} -> {n['unknown_policy']}")
            continue
        if o["kind"] != "leaf" or n["kind"] != "leaf":
            if o["kind"] != n["kind"]:
                add(path, "kind_changed", False, False,
                    f"结构形态 {o['kind']} -> {n['kind']}")
            continue

        # 叶子对叶子
        if o["type"] != n["type"]:
            add(path, "type_changed",
                _type_backward_ok(o["type"], n["type"]),
                _type_forward_ok(o["type"], n["type"]),
                f"字段类型 {o['type']} -> {n['type']}")
        if o["required"] != n["required"]:
            if o["required"] and not n["required"]:
                add(path, "required_to_optional", True, False,
                    "必填改可选：新载荷可能缺字段，旧契约拒绝（向前不兼容）")
            else:
                add(path, "optional_to_required", False, True,
                    "可选改必填：旧载荷可能缺字段，新契约拒绝（向后不兼容）")
        if o["enum"] != n["enum"]:
            old_set = set(o["enum"] or [])
            new_set = set(n["enum"] or [])
            if n["enum"] is None and o["enum"] is not None:
                add(path, "enum_dropped", True, False, "枚举约束取消：旧读者可能不认识新值")
            elif o["enum"] is None and n["enum"] is not None:
                add(path, "enum_introduced", False, True,
                    f"新增枚举约束，允许值 {sorted(new_set)}")
            else:
                added = sorted(new_set - old_set)
                removed = sorted(old_set - new_set)
                add(path, "enum_changed", not removed, not added,
                    f"新增枚举值 {added}；移除枚举值 {removed}"
                    + ("（移除旧值使旧载荷可能非法→向后不兼容）" if removed else "")
                    + ("（新增值旧读者不认识→向前不兼容）" if added else ""))
        if o["ignorable"] != n["ignorable"]:
            add(path, "ignorable_changed", True, True,
                f"可忽略标记 {o['ignorable']} -> {n['ignorable']}（不影响兼容性）")
        if o["has_default"] != n["has_default"]:
            add(path, "default_changed", True, True, "默认值声明变化（不影响兼容性）")

    backward = all(f["backward_compatible"] for f in fields)
    forward = all(f["forward_compatible"] for f in fields)
    if not fields:
        verdict = "compatible"
    elif backward and forward:
        verdict = "compatible"
    elif backward:
        verdict = "backward_only"
    elif forward:
        verdict = "forward_only"
    else:
        verdict = "breaking"
    counts = {"total": len(fields), "backward_incompatible": 0, "forward_incompatible": 0}
    for f in fields:
        if not f["backward_compatible"]:
            counts["backward_incompatible"] += 1
        if not f["forward_compatible"]:
            counts["forward_incompatible"] += 1
    return {
        "verdict": verdict,
        "backward_compatible": backward,
        "forward_compatible": forward,
        "breaking": not (backward and forward),
        "counts": counts,
        "fields": fields,
    }
