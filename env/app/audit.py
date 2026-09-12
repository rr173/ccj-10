"""租约审计回放与一致性诊断（只读）。

设计原则
========
1. **纯事件溯源**：某一历史节点的资源值、当前租约、委托状态、世代号全部
   由 ``lease_events`` 按 ``seq`` 升序重放得到，不读（也不信任）运行态表
   里"现在"的状态——运行态表只用于跨表勾稽。投影是纯折叠函数，对同一份
   历史，任何时刻、重启前后结果完全一致。

2. **只读**：本模块只有 SELECT。它与写入路径共用 Store 的进程锁与连接，
   但绝不调用 ``_reap_locked`` 等会落"过期/栅栏"事件的方法，也绝不 INSERT/
   UPDATE——诊断与回放不会改动正在运行的租约和委托。

3. **稳定视图**：每次审计读在锁内先取 ``MAX(seq)`` 作为快照上界
   （snapshot_seq），本次查询/分页/诊断看到的所有内容都不越过该上界；
   并发写入要么整体在快照之前、要么整体在之后，不会读到半套状态。
   客户端可回传 ``snapshot`` 固定翻页视图。

4. **显式错误**：历史不存在 → 404；节点序号不属于该资源或越过快照上界、
   翻页游标越界 → 416 并给出可用范围；过滤窗口为空 → 404 给出事件实际
   区间。绝不生成"看似正常、其实没查到"的空报告。

序号（seq）是全局 AUTOINCREMENT，因此：
- 1..MAX(seq) 之间缺号意味着事件被删/损坏（不同资源交错产生的缺口属正常，
  只有全局缺号才算审计问题）；
- seq 升序即审计顺序，分页顺序固定。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# 错误（映射为明确的 HTTP 状态码，而不是空结果）
# ---------------------------------------------------------------------------


class AuditError(Exception):
    code = "audit_error"
    status = 400

    def __init__(self, message: str, **extra: Any):
        super().__init__(message)
        self.extra = extra

    def to_response(self) -> dict[str, Any]:
        return {"error": self.code, "message": str(self), **self.extra}


class AuditBadRequest(AuditError):
    code = "bad_request"
    status = 400


class HistoryNotFound(AuditError):
    code = "history_not_found"
    status = 404


class CredentialNotFound(AuditError):
    code = "credential_not_found"
    status = 404


class NodeOutOfRange(AuditError):
    """历史节点/翻页游标越界（416 Requested Range Not Satisfiable）。"""

    code = "node_out_of_range"
    status = 416


class NoEventsInRange(AuditError):
    """资源存在，但给定时间/序号窗口内没有任何事件（404，显式而非空列表）。"""

    code = "no_events_in_range"
    status = 404


# ---------------------------------------------------------------------------
# 中文叙述：每一步说明接受与否、涉及谁、拒绝原因
# ---------------------------------------------------------------------------

REASON_CN = {
    "no_active_lease": "资源上没有生效中的租约",
    "generation_fence": "世代号栅栏拦截：不是当前生效世代",
    "holder_or_generation_mismatch": "持有者或世代号与当前生效租约不符",
    "resource_held_by_other": "资源正被其他持有者持有",
    "reused_existing": "复用同持有者当前租约",
    "delegation_revoked": "委托凭证已被授权者撤销",
    "delegation_expired": "委托凭证已过墙钟有效期",
    "delegation_not_active": "委托凭证已不处于生效状态",
    "collaborator_mismatch": "请求者不是凭证指定的协作者",
    "unknown_credential": "凭证不存在或不属于该资源",
    "source_lease_released": "授权租约已被释放，委托连带失效",
    "source_lease_transferred": "授权租约已被转移，委托连带失效",
    "source_lease_expired": "授权租约已过期，委托连带失效",
    "credential_id_conflict": "凭证号已被占用且参数不同",
    "ineligible_collaborator": "协作者不合格（空/不是字符串）",
    "ineligible_collaborator:self": "不能委托给当前持有者自己",
    "ineligible_recipient": "转移接收者不合格（空/不是字符串）",
    "ineligible_recipient:self": "不能转移给当前持有者自己",
    "transfer_id_conflict": "幂等键 transfer_id 已被参数不同的转移占用",
    "lease_ends_too_soon": "授权租约即将到硬墙钟上限，不足以发放委托",
    "missing_credential_id": "缺少必填参数 credential_id",
}


def reason_cn(detail: str | None) -> str:
    if not detail:
        return "未给出原因"
    if detail in REASON_CN:
        return REASON_CN[detail]
    if detail.startswith("already_"):
        return f"凭证已处于 {detail[len('already_'):]} 终态"
    if detail.startswith("write_id="):
        return detail
    return detail


def narrate(ev: dict[str, Any]) -> str:
    """为一条事件生成人类可读的操作说明。"""
    kind = ev["event"]
    ok = ev["outcome"] == "ok"
    actor = ev["holder"]
    peer = ev.get("peer")
    cid = ev.get("credential_id")
    gen = ev.get("generation")
    verdict = "被接受" if ok else "被拒绝"

    if kind == "acquire":
        if ok:
            if ev.get("detail") == "reused_existing":
                return (f"{actor} 请求获取租约：其本人已持有该资源，"
                        f"复用现有租约 {ev.get('lease_id')}（世代号 {gen}），未发放新世代")
            return (f"{actor} 获取资源租约成功，租约 {ev.get('lease_id')}，"
                    f"世代号 {gen}")
        who = f"，当时持有者为 {peer}" if peer else ""
        return f"{actor} 获取租约被拒绝（{reason_cn(ev.get('detail'))}{who}）"

    if kind == "renew":
        if ok:
            return (f"{actor} 续约成功（租约 {ev.get('lease_id')}，"
                    f"世代号 {gen} 不变，软 TTL 顺延）")
        return f"{actor} 的续约被拒绝：{reason_cn(ev.get('detail'))}"

    if kind == "release":
        if ok:
            return (f"{actor} 主动释放租约 {ev.get('lease_id')}"
                    f"（世代号 {gen}），释放后该世代不可再写")
        return f"{actor} 的释放请求被拒绝：{reason_cn(ev.get('detail'))}"

    if kind == "transfer":
        if ok:
            return (f"{actor} 把租约安全转移给 {peer} 被接受：旧租约 "
                    f"{ev.get('lease_id')}（世代号 {gen}）即刻失效，新租约 "
                    f"{ev.get('to_lease_id')} 世代号 {ev.get('to_generation')}，"
                    "旧持有者即刻失去写权限")
        who = f"，目标接收者 {peer}" if peer else ""
        return (f"{actor} 向{peer or '（空缺接收者）'}的转移被拒绝："
                f"{reason_cn(ev.get('detail'))}{who}")

    if kind == "write":
        if ok:
            return (f"{actor} 的直接写入{verdict}（{ev.get('detail')}），"
                    f"经世代号 {gen} 的租约 {ev.get('lease_id')} 放行，资源值已更新")
        return (f"{actor} 的直接写入被拒绝：{reason_cn(ev.get('detail'))}"
                f"（其声称世代号 {gen}）")

    if kind == "delegate_grant":
        if ok:
            return (f"{actor}（授权者）向协作者 {peer} 发放委托凭证 {cid} 被接受，"
                    f"凭证锚定租约 {ev.get('lease_id')} 的世代号 {gen}，只授予该资源的写权限")
        who = f"，目标协作者 {peer}" if peer else ""
        return f"{actor} 发放委托{who}被拒绝：{reason_cn(ev.get('detail'))}"

    if kind == "delegate_write":
        if ok:
            return (f"协作者 {actor} 凭委托凭证 {cid}（授权者 {peer}）的写入被接受，"
                    f"按锚定世代号 {gen} 通过同一道栅栏，资源值已更新")
        return (f"{actor} 持委托凭证 {cid} 的写入被拒绝："
                f"{reason_cn(ev.get('detail'))}（授权者 {peer}，锚定世代号 {gen}）")

    if kind == "delegate_revoke":
        if ok:
            return (f"授权者 {actor} 提前撤销协作者 {peer} 的委托凭证 {cid} "
                    "被接受，此后迟到写入必拒")
        return f"{actor} 撤销委托凭证 {cid} 被拒绝：{reason_cn(ev.get('detail'))}"

    if kind == "delegate_expire":
        return (f"委托凭证 {cid} 到达墙钟有效期（授权者 {actor}，协作者 {peer}），"
                "系统将其置为过期，此后写入必拒")

    if kind == "delegate_fence":
        return (f"授权租约结束（{reason_cn(ev.get('detail'))}），委托凭证 {cid} "
                f"（授权者 {actor}，协作者 {peer}）在同一事务被连带栅栏，此后写入必拒")

    return f"{actor} 的 {kind} 操作{verdict}" + (
        f"：{reason_cn(ev.get('detail'))}" if not ok else ""
    )


def event_dict(r: Any) -> dict[str, Any]:
    """SQLite 行 → 对外事件 JSON（含中文叙述与 accepted 布尔）。"""
    keys = r.keys()
    ev = {
        "seq": r["seq"],
        "resource": r["resource"],
        "event": r["event"],
        "outcome": r["outcome"],
        "accepted": r["outcome"] == "ok",
        "holder": r["holder"],
        "peer": r["peer"],
        "lease_id": r["lease_id"],
        "generation": r["generation"],
        "to_lease_id": r["to_lease_id"],
        "to_generation": r["to_generation"],
        "credential_id": r["credential_id"],
        "detail": r["detail"],
        "wall_ms": r["wall_ms"],
        "logical": r["logical"],
        "value": r["value"] if "value" in keys else None,
    }
    ev["narration"] = narrate(ev)
    return ev


# ---------------------------------------------------------------------------
# 事件溯源投影器：把事件流折叠成某节点的资源/租约/委托状态
# ---------------------------------------------------------------------------


@dataclass
class _Lease:
    lease_id: str
    holder: str
    generation: int
    granted_wall_ms: int
    state: str = "active"            # active / released / transferred / expired
    end_reason: str | None = None
    end_seq: int | None = None
    renewed_count: int = 0

    def view(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "holder": self.holder,
            "generation": self.generation,
            "state": self.state,
            "granted_wall_ms": self.granted_wall_ms,
            "renewed_count": self.renewed_count,
            "end_reason": self.end_reason,
            "end_seq": self.end_seq,
        }


@dataclass
class _Delegation:
    credential_id: str
    resource: str
    lease_id: str
    authorizer: str
    collaborator: str
    generation: int
    granted_wall_ms: int
    expires_wall_ms: int | None
    granted_seq: int
    state: str = "active"            # active / revoked / expired / fenced
    end_reason: str | None = None
    end_seq: int | None = None
    writes_accepted: int = 0
    writes_rejected: int = 0

    def view(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "resource": self.resource,
            "lease_id": self.lease_id,
            "authorizer": self.authorizer,
            "collaborator": self.collaborator,
            "generation": self.generation,
            "state": self.state,
            "granted_wall_ms": self.granted_wall_ms,
            "granted_seq": self.granted_seq,
            "expires_wall_ms": self.expires_wall_ms,
            "end_reason": self.end_reason,
            "end_seq": self.end_seq,
            "writes_accepted": self.writes_accepted,
            "writes_rejected": self.writes_rejected,
        }


@dataclass
class Projection:
    resource: str
    applied_seq: int | None = None
    current: _Lease | None = None
    leases: dict[str, _Lease] = field(default_factory=dict)
    delegations: dict[str, _Delegation] = field(default_factory=dict)
    value: str | None = None
    value_seq: int | None = None
    value_recorded: bool = False
    last_passed_generation: int | None = None
    value_generation: int | None = None
    value_wall_ms: int | None = None
    max_generation: int | None = None
    generations: list[int] = field(default_factory=list)
    writes_accepted: int = 0
    writes_rejected: int = 0
    ops_accepted: int = 0
    ops_rejected: int = 0
    prev_wall: int | None = None
    prev_logical: int | None = None
    seen_write_ids: set[int] = field(default_factory=set)
    issues: list[dict[str, Any]] = field(default_factory=list)

    def _issue(self, code: str, severity: str, ev: dict[str, Any] | None,
               message: str, *, credential_id: str | None = None) -> None:
        self.issues.append({
            "code": code,
            "severity": severity,
            "seq": ev["seq"] if ev else None,
            "credential_id": credential_id,
            "event": ev["event"] if ev else None,
            "message": message,
        })

    def signature(self) -> dict[str, Any]:
        """供节点比较用的扁平状态指纹：只含有业务含义的状态字段。"""
        sig: dict[str, Any] = {
            "resource.value": self.value,
            "resource.value_seq": self.value_seq,
            "resource.last_passed_generation": self.last_passed_generation,
            "resource.max_generation": self.max_generation,
            "lease.state": self.current.state if self.current else "none",
            "lease.holder": self.current.holder if self.current else None,
            "lease.generation": self.current.generation if self.current else None,
            "lease.lease_id": self.current.lease_id if self.current else None,
            "lease.renewed_count": (
                self.current.renewed_count if self.current else 0),
        }
        for cid, d in self.delegations.items():
            sig[f"delegation.{cid}.state"] = d.state
            sig[f"delegation.{cid}.generation"] = d.generation
            sig[f"delegation.{cid}.authorizer"] = d.authorizer
            sig[f"delegation.{cid}.collaborator"] = d.collaborator
        return sig

    def replay_view(self) -> dict[str, Any]:
        """节点回放对外视图：当时的资源值、当前租约、委托状态与世代号。"""
        return {
            "resource": {
                "name": self.resource,
                "value": self.value,
                "value_recorded": self.value_recorded,
                "value_source_seq": self.value_seq,
                "last_passed_generation": self.last_passed_generation,
                "updated_by_generation": self.value_generation,
                "updated_wall_ms": self.value_wall_ms,
                "current_generation": self.max_generation,
            },
            "lease": (
                None if self.current is None
                else {**self.current.view(),
                      "active_at_node": self.current.state == "active"}
            ),
            "generations": {
                "acquired": self.generations,
                "current": self.max_generation,
                "count": len(self.generations),
            },
            "delegations": [
                d.view()
                for d in sorted(self.delegations.values(),
                                key=lambda x: x.granted_seq)
            ],
            "counters": {
                "writes_accepted": self.writes_accepted,
                "writes_rejected": self.writes_rejected,
                "ops_accepted": self.ops_accepted,
                "ops_rejected": self.ops_rejected,
            },
        }


def _parse_expires(detail: str | None) -> int | None:
    if not detail:
        return None
    for part in detail.split(","):
        if part.startswith("expires_wall_ms="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _fold(st: Projection, events: list[dict[str, Any]], *,
          check_clocks: bool = True) -> Projection:
    """把事件逐条应用到已有投影上（增量折叠，事件须按 seq 升序）。"""

    def active_lease() -> _Lease | None:
        cur = st.current
        return cur if cur is not None and cur.state == "active" else None

    for ev in events:
        st.applied_seq = ev["seq"]
        kind, ok = ev["event"], ev["outcome"] == "ok"

        # ---- 时钟回归检查（wall 回拨合法但留痕，logical 不该回退） ----
        if check_clocks and st.prev_logical is not None:
            if ev["logical"] < st.prev_logical:
                st._issue(
                    "logical_clock_regressed", "error", ev,
                    f"逻辑钟从 {st.prev_logical} 回退到 {ev['logical']}，"
                    "逻辑钟只增不减，历史疑似被篡改",
                )
            if ev["wall_ms"] < st.prev_wall:
                st._issue(
                    "wall_clock_moved_backward", "info", ev,
                    f"墙钟读数从 {st.prev_wall} 回拨到 {ev['wall_ms']}"
                    "（可由运维/NTP/调试拨表造成，仅提示，非损坏）",
                )
        st.prev_wall, st.prev_logical = ev["wall_ms"], ev["logical"]

        st.ops_accepted += 1 if ok else 0
        st.ops_rejected += 0 if ok else 1
        if kind in ("write", "delegate_write"):
            if ok:
                st.writes_accepted += 1
            else:
                st.writes_rejected += 1

        lid = ev.get("lease_id")
        gen = ev.get("generation")
        cid = ev.get("credential_id")

        # 被接受的写入事件 detail 里带 write_id=N：同一资源内重复即"重号"
        if ok and kind in ("write", "delegate_write"):
            wid = _parse_write_id(ev.get("detail"))
            if wid is not None:
                if wid in st.seen_write_ids:
                    st._issue(
                        "write_id_duplicate", "error", ev,
                        f"write_id={wid} 在该资源历史中出现了两次（接受事件），"
                        "写入审计自相矛盾", credential_id=cid,
                    )
                st.seen_write_ids.add(wid)

        # ================= 租约类 =================
        if kind == "acquire":
            if ok and ev.get("detail") != "reused_existing":
                if gen is not None and (
                    st.max_generation is None or gen > st.max_generation
                ):
                    st.max_generation = gen
                    st.generations.append(gen)
                cur = active_lease()
                if cur is not None:
                    # 正常旧租约应以 release/transfer/expire 收尾；没有任何
                    # 收尾事件就被新一代顶替，属状态矛盾
                    st._issue(
                        "active_lease_superseded_without_handover",
                        "error", ev,
                        f"租约 {cur.lease_id}（世代 {cur.generation}，持有者 "
                        f"{cur.holder}）没有释放/转移事件，就被世代 {gen} 的"
                        "新获取顶替",
                    )
                    cur.state, cur.end_reason, cur.end_seq = (
                        "expired", "inferred_at_next_acquire", ev["seq"])
                lease = _Lease(
                    lease_id=lid, holder=ev["holder"], generation=gen,
                    granted_wall_ms=ev["wall_ms"],
                )
                st.leases[lid] = lease
                st.current = lease
            elif ok and ev.get("detail") == "reused_existing":
                cur = active_lease()
                if cur is None or cur.lease_id != lid or cur.holder != ev["holder"]:
                    st._issue(
                        "reused_acquire_without_matching_active_lease",
                        "error", ev,
                        "标记为复用的获取事件找不到持有者一致的生效租约",
                    )

        elif kind == "renew":
            if ok:
                cur = active_lease()
                if (cur is None or cur.lease_id != lid
                        or cur.holder != ev["holder"] or cur.generation != gen):
                    st._issue(
                        "renew_accepted_without_matching_active_lease",
                        "error", ev,
                        "续约被接受，但事件上的租约/持有者/世代号与投影中的"
                        "生效租约对不上",
                    )
                elif cur is not None:
                    cur.renewed_count += 1

        elif kind == "release":
            if ok:
                cur = active_lease()
                if cur is None or cur.lease_id != lid or cur.holder != ev["holder"]:
                    st._issue(
                        "release_accepted_without_matching_active_lease",
                        "error", ev,
                        "释放被接受，但投影中不存在匹配的生效租约",
                    )
                if cur is not None:
                    cur.state, cur.end_reason, cur.end_seq = (
                        "released", "released", ev["seq"])

        elif kind == "transfer":
            if ok:
                cur = active_lease()
                new_lid, new_gen = ev.get("to_lease_id"), ev.get("to_generation")
                if cur is None or cur.lease_id != lid:
                    st._issue(
                        "transfer_accepted_without_active_source_lease",
                        "error", ev, "转移被接受，但投影中源租约不是生效租约",
                    )
                if not new_lid or new_gen is None:
                    st._issue(
                        "transfer_missing_new_lease", "error", ev,
                        "成功的转移事件缺少新租约号或新世代号",
                    )
                elif gen is not None and new_gen <= gen:
                    st._issue(
                        "transfer_generation_not_advanced", "error", ev,
                        f"转移后世代号 {new_gen} 没有严格大于旧世代号 {gen}",
                    )
                if cur is not None:
                    cur.state, cur.end_reason, cur.end_seq = (
                        "transferred", "transferred", ev["seq"])
                if new_lid and new_gen is not None:
                    if (st.max_generation is None
                            or new_gen > st.max_generation):
                        st.max_generation = new_gen
                        st.generations.append(new_gen)
                    new_lease = _Lease(
                        lease_id=new_lid, holder=ev.get("peer") or "",
                        generation=new_gen, granted_wall_ms=ev["wall_ms"],
                    )
                    st.leases[new_lid] = new_lease
                    st.current = new_lease

        # ================= 写入 =================
        elif kind == "write":
            if ok:
                cur = active_lease()
                if (cur is None or cur.lease_id != lid
                        or cur.holder != ev["holder"] or cur.generation != gen):
                    st._issue(
                        "write_accepted_without_fence_match", "error", ev,
                        "写入被标记为接受，但持有者/租约/世代号与投影中的生效"
                        "租约不一致（栅栏被绕过的迹象）",
                    )
                if (st.last_passed_generation is not None
                        and gen is not None
                        and gen < st.last_passed_generation):
                    st._issue(
                        "accepted_write_generation_went_backwards", "error", ev,
                        f"放行世代号 {gen} 小于此前已放行的 "
                        f"{st.last_passed_generation}",
                    )
                st.value = ev.get("value")
                st.value_recorded = ev.get("value") is not None
                st.value_seq = ev["seq"]
                st.last_passed_generation = gen
                st.value_generation = gen
                st.value_wall_ms = ev["wall_ms"]

        elif kind == "delegate_write":
            d = st.delegations.get(cid) if cid else None
            if ok:
                cur = active_lease()
                bad = (
                    d is None or d.state != "active"
                    or d.collaborator != ev["holder"]
                    or cur is None
                    or cur.lease_id != d.lease_id
                    or cur.generation != d.generation
                )
                if bad:
                    st._issue(
                        "delegated_write_accepted_against_inactive_chain",
                        "error", ev,
                        "委托写入被接受，但凭证已失效/协作者不符/授权租约已不是"
                        "发放时那一代", credential_id=cid,
                    )
                if d is not None:
                    d.writes_accepted += 1
                if (st.last_passed_generation is not None
                        and gen is not None
                        and gen < st.last_passed_generation):
                    st._issue(
                        "accepted_write_generation_went_backwards", "error", ev,
                        f"委托放行世代号 {gen} 小于此前已放行的 "
                        f"{st.last_passed_generation}", credential_id=cid,
                    )
                st.value = ev.get("value")
                st.value_recorded = ev.get("value") is not None
                st.value_seq = ev["seq"]
                st.last_passed_generation = gen
                st.value_generation = gen
                st.value_wall_ms = ev["wall_ms"]
            elif d is not None:
                d.writes_rejected += 1

        # ================= 委托生命周期 =================
        elif kind == "delegate_grant":
            if ok:
                expires = _parse_expires(ev.get("detail"))
                if cid and cid in st.delegations:
                    st._issue(
                        "credential_granted_twice", "error", ev,
                        f"凭证 {cid} 已有发放事件，凭证号/状态出现重叠",
                        credential_id=cid,
                    )
                cur = active_lease()
                if cur is None or cur.lease_id != lid or cur.generation != gen:
                    st._issue(
                        "delegation_anchored_to_non_active_lease", "error", ev,
                        "发放被接受，但锚定租约不是投影中的生效租约",
                        credential_id=cid,
                    )
                if cid:
                    st.delegations[cid] = _Delegation(
                        credential_id=cid, resource=st.resource, lease_id=lid,
                        authorizer=ev["holder"], collaborator=ev.get("peer") or "",
                        generation=gen, granted_wall_ms=ev["wall_ms"],
                        expires_wall_ms=expires, granted_seq=ev["seq"],
                    )

        elif kind == "delegate_revoke":
            if ok:
                d = st.delegations.get(cid) if cid else None
                if d is None:
                    st._issue(
                        "revoke_without_grant", "error", ev,
                        f"撤销事件找不到凭证 {cid} 的发放事件",
                        credential_id=cid,
                    )
                elif d.state != "active":
                    st._issue(
                        "credential_terminated_twice", "error", ev,
                        f"凭证 {cid} 在已是 {d.state} 后又被撤销",
                        credential_id=cid,
                    )
                else:
                    d.state, d.end_reason, d.end_seq = (
                        "revoked", "revoked", ev["seq"])

        elif kind == "delegate_expire":
            if ok:
                d = st.delegations.get(cid) if cid else None
                if d is None:
                    st._issue(
                        "expire_without_grant", "error", ev,
                        f"过期事件找不到凭证 {cid} 的发放事件",
                        credential_id=cid,
                    )
                elif d.state != "active":
                    st._issue(
                        "credential_terminated_twice", "error", ev,
                        f"凭证 {cid} 在已是 {d.state} 后又被记过期",
                        credential_id=cid,
                    )
                else:
                    d.state, d.end_reason, d.end_seq = (
                        "expired", "delegation_expired", ev["seq"])

        elif kind == "delegate_fence":
            if ok:
                d = st.delegations.get(cid) if cid else None
                if d is None:
                    st._issue(
                        "fence_without_grant", "error", ev,
                        f"连带失效事件找不到凭证 {cid} 的发放事件",
                        credential_id=cid,
                    )
                elif d.state != "active":
                    st._issue(
                        "credential_terminated_twice", "error", ev,
                        f"凭证 {cid} 在已是 {d.state} 后又被连带栅栏",
                        credential_id=cid,
                    )
                else:
                    d.state, d.end_reason, d.end_seq = (
                        "fenced", ev.get("detail") or "source_lease_ended",
                        ev["seq"])

        elif kind not in ("acquire", "renew", "release", "transfer", "write"):
            st._issue(
                "unknown_event_type", "warning", ev,
                f"审计器不认识事件类型 {kind}，投影时已跳过",
                credential_id=cid,
            )

    st.issues.sort(key=lambda i: (i["seq"] is None, i["seq"] or 0, i["code"]))
    return st


def project(resource: str, events: list[dict[str, Any]], *,
            check_clocks: bool = True) -> Projection:
    """把单个资源的事件流（seq 升序）折叠为投影并做状态矛盾检查。"""
    return _fold(Projection(resource=resource), events,
                 check_clocks=check_clocks)


# ---------------------------------------------------------------------------
# 审计读取器：稳定视图 + 纯 SELECT
# ---------------------------------------------------------------------------


class AuditReader:
    def __init__(self, store: Any):
        self._store = store

    @contextmanager
    def _snapshot(self) -> Iterator[tuple[Any, int]]:
        """在与写入相同的进程锁内做纯只读查询，返回 (连接, 快照上界 seq)。

        不调用任何收割方法、不写任何表，退出时 rollback 结束只读事务。
        持锁期间并发写入被阻塞到快照之后，保证回放/翻页/诊断看到同一份历史。
        """
        store = self._store
        with store._lock:  # noqa: SLF001 - 审计与存储刻意共用同一把锁
            conn = store._conn  # noqa: SLF001
            row = conn.execute("SELECT MAX(seq) AS m FROM lease_events").fetchone()
            max_seq = int(row["m"]) if row is not None and row["m"] is not None else 0
            try:
                yield conn, max_seq
            finally:
                conn.rollback()

    # ---- 基础查询 -------------------------------------------------------
    @staticmethod
    def _bounds(conn, max_seq, resource: str) -> tuple[int, int | None, int | None]:
        row = conn.execute(
            "SELECT COUNT(*) AS c, MIN(seq) AS lo, MAX(seq) AS hi "
            "FROM lease_events WHERE resource=? AND seq<=?",
            (resource, max_seq),
        ).fetchone()
        return row["c"], row["lo"], row["hi"]

    @staticmethod
    def _resolve_snapshot(client_snapshot: Any, max_seq: int) -> int:
        if client_snapshot in (None, ""):
            return max_seq
        snap = _as_int(client_snapshot, "snapshot")
        if snap < 0:
            raise AuditBadRequest("snapshot 不能为负数", snapshot=snap)
        if snap > max_seq:
            raise NodeOutOfRange(
                f"请求的稳定视图上界 snapshot={snap} 超过当前最大序号 "
                f"{max_seq}，该视图尚不存在；请先用一次不带 snapshot 的查询",
                requested_snapshot=snap, available_max_seq=max_seq,
            )
        return snap

    def list_events(
        self,
        *,
        scope: str,
        resource: str | None = None,
        credential_id: str | None = None,
        after_seq: Any = None,
        limit: Any = 100,
        snapshot: Any = None,
        seq_min: Any = None,
        seq_max: Any = None,
        from_ms: Any = None,
        to_ms: Any = None,
        outcomes: list[str] | None = None,
        event_types: list[str] | None = None,
    ) -> dict[str, Any]:
        after = _as_int(after_seq, "after", default=0)
        if after < 0:
            raise AuditBadRequest("after 不能为负数", after=after)
        seq_lo = _as_int(seq_min, "seq_min", default=None)
        seq_hi = _as_int(seq_max, "seq_max", default=None)
        t_lo = _as_int(from_ms, "from_ms", default=None)
        t_hi = _as_int(to_ms, "to_ms", default=None)
        if seq_lo is not None and seq_hi is not None and seq_lo > seq_hi:
            raise AuditBadRequest("seq_min 不能大于 seq_max",
                                  seq_min=seq_lo, seq_max=seq_hi)
        if t_lo is not None and t_hi is not None and t_lo > t_hi:
            raise AuditBadRequest("from_ms 不能大于 to_ms",
                                  from_ms=t_lo, to_ms=t_hi)
        limit = _bounded_limit(limit)

        with self._snapshot() as (conn, max_seq):
            snap = self._resolve_snapshot(snapshot, max_seq)

            base_where = ["seq<=?"]
            base_args: list[Any] = [snap]
            if scope == "resource":
                base_where.append("resource=?")
                base_args.append(resource)
            elif scope == "credential":
                base_where.append("credential_id=?")
                base_args.append(credential_id)

            where = list(base_where)
            args: list[Any] = list(base_args)
            if seq_lo is not None:
                where.append("seq>=?")
                args.append(seq_lo)
            if seq_hi is not None:
                where.append("seq<=?")
                args.append(seq_hi)
            if t_lo is not None:
                where.append("wall_ms>=?")
                args.append(t_lo)
            if t_hi is not None:
                where.append("wall_ms<=?")
                args.append(t_hi)
            if outcomes:
                where.append(
                    "outcome IN (" + ",".join("?" for _ in outcomes) + ")")
                args.extend(outcomes)
            if event_types:
                where.append(
                    "event IN (" + ",".join("?" for _ in event_types) + ")")
                args.extend(event_types)

            # 过滤窗口内的总量（不含翻页游标）：首页零匹配必须报错而不是空页
            count_row = conn.execute(
                "SELECT COUNT(*) AS c FROM lease_events WHERE "
                + " AND ".join(where), tuple(args),
            ).fetchone()
            window_count = count_row["c"]

            page_where = list(where)
            page_args = list(args)
            if after:
                page_where.append("seq>?")
                page_args.append(after)

            sql = ("SELECT * FROM lease_events WHERE "
                   + " AND ".join(page_where) + " ORDER BY seq ASC LIMIT ?")
            rows = conn.execute(sql, (*page_args, limit + 1)).fetchall()
            events = [event_dict(r) for r in rows[:limit]]
            has_more = len(rows) > limit

            # ---- 显式错误：历史不存在 / 游标越界 / 窗口为空 ----------
            if scope == "resource":
                count, lo, hi = self._bounds(conn, snap, resource)
                if count == 0:
                    raise HistoryNotFound(
                        f"资源 {resource} 在稳定视图（snapshot<={snap}）内"
                        "没有任何历史事件", resource=resource,
                        snapshot_seq=snap,
                    )
                self._check_window_and_cursor(
                    conn, snap, after, seq_lo, seq_hi, t_lo, t_hi,
                    scope_lo=lo, scope_hi=hi,
                    scope_column="resource", scope_value=resource,
                )
            elif scope == "credential":
                crow = conn.execute(
                    "SELECT COUNT(*) AS c, MIN(seq) AS lo, MAX(seq) AS hi "
                    "FROM lease_events WHERE credential_id=? AND seq<=?",
                    (credential_id, snap),
                ).fetchone()
                exists = conn.execute(
                    "SELECT 1 FROM delegations WHERE credential_id=?",
                    (credential_id,),
                ).fetchone()
                if crow["c"] == 0 and exists is None:
                    raise CredentialNotFound(
                        f"委托凭证 {credential_id} 不存在（既无凭证记录也无"
                        "历史事件）", credential_id=credential_id,
                        snapshot_seq=snap,
                    )
                if crow["c"]:
                    self._check_window_and_cursor(
                        conn, snap, after, seq_lo, seq_hi, t_lo, t_hi,
                        scope_lo=crow["lo"], scope_hi=crow["hi"],
                        scope_column="credential_id",
                        scope_value=credential_id,
                    )
            else:
                if after > snap:
                    raise NodeOutOfRange(
                        f"翻页游标 after={after} 越过稳定视图上界 {snap}",
                        after=after, available_max_seq=snap,
                    )
            if window_count == 0 and not has_more and not events:
                filters_active = any(
                    [seq_lo, seq_hi, t_lo, t_hi, outcomes, event_types])
                if scope != "global" or filters_active:
                    # 作用域存在但过滤条件零匹配（或资源/凭证作用域窗口为空）：
                    # 显式报错，绝不用"看似正常"的空页掩盖
                    raise NoEventsInRange(
                        "给定过滤条件在稳定视图内匹配不到任何事件",
                        snapshot_seq=snap,
                    )
            # 游标合法但已到过滤集末尾：返回 200 空页 + reached_end，
            # 属标准分页；真正越界（越过作用域/视图末条）已在上面拦截。

            return {
                "scope": scope,
                "resource": resource,
                "credential_id": credential_id,
                "events": events,
                "limit": limit,
                "next": events[-1]["seq"] if has_more and events else None,
                "reached_end": not has_more,
                "view": {"snapshot_seq": snap, "latest_seq": max_seq,
                         "order": "seq ASC"},
            }

    def _check_window_and_cursor(
        self, conn, snap, after, seq_lo, seq_hi, t_lo, t_hi, *,
        scope_lo, scope_hi, scope_column, scope_value,
    ) -> None:
        if after > snap:
            raise NodeOutOfRange(
                f"翻页游标 after={after} 越过稳定视图上界 {snap}",
                after=after, available_max_seq=snap,
            )
        if after > scope_hi:
            raise NodeOutOfRange(
                f"翻页游标 after={after} 已越过该作用域最后一条事件 "
                f"seq={scope_hi}",
                after=after, available_min_seq=scope_lo,
                available_max_seq=scope_hi,
            )
        if seq_hi is not None and seq_hi < scope_lo:
            raise NoEventsInRange(
                f"seq_max={seq_hi} 早于该作用域首条事件 seq={scope_lo}",
                requested_seq_min=seq_lo, requested_seq_max=seq_hi,
                available_min_seq=scope_lo, available_max_seq=scope_hi,
            )
        if seq_lo is not None and seq_lo > scope_hi:
            raise NoEventsInRange(
                f"seq_min={seq_lo} 晚于该作用域末条事件 seq={scope_hi}",
                requested_seq_min=seq_lo, requested_seq_max=seq_hi,
                available_min_seq=scope_lo, available_max_seq=scope_hi,
            )
        # 时间窗口与事件实际区间是否相交
        row = conn.execute(
            f"SELECT MIN(wall_ms) AS lo, MAX(wall_ms) AS hi FROM lease_events "
            f"WHERE {scope_column}=? AND seq<=?",
            (scope_value, snap),
        ).fetchone()
        if row["lo"] is not None:
            if t_hi is not None and t_hi < row["lo"]:
                raise NoEventsInRange(
                    f"to_ms={t_hi} 早于最早事件时间 {row['lo']}",
                    requested_from_ms=t_lo, requested_to_ms=t_hi,
                    available_from_ms=row["lo"], available_to_ms=row["hi"],
                )
            if t_lo is not None and t_lo > row["hi"]:
                raise NoEventsInRange(
                    f"from_ms={t_lo} 晚于最晚事件时间 {row['hi']}",
                    requested_from_ms=t_lo, requested_to_ms=t_hi,
                    available_from_ms=row["lo"], available_to_ms=row["hi"],
                )

    # ---- 取事件流（投影用） ---------------------------------------------
    def _resource_events(self, conn, snap: int, resource: str,
                         seq_ceil: int | None = None) -> list[dict]:
        ceil = snap if seq_ceil is None else min(snap, seq_ceil)
        rows = conn.execute(
            "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
            "ORDER BY seq ASC",
            (resource, ceil),
        ).fetchall()
        return [event_dict(r) for r in rows]

    def _resolve_node(
        self, conn, snap: int, resource: str,
        *, seq: int | None, wall_ms: int | None, head: bool,
    ) -> dict:
        """把 at_seq/at_wall_ms/head 解析成该资源事件流上的一个确定节点。"""
        count, lo, hi = self._bounds(conn, snap, resource)
        if count == 0:
            raise HistoryNotFound(
                f"资源 {resource} 在稳定视图（snapshot<={snap}）内没有任何"
                "历史事件，无法回放", resource=resource, snapshot_seq=snap,
            )
        if head:
            row = conn.execute(
                "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
                "ORDER BY seq DESC LIMIT 1",
                (resource, snap),
            ).fetchone()
            return event_dict(row)
        if seq is not None:
            row = conn.execute(
                "SELECT * FROM lease_events WHERE seq=?", (seq,),
            ).fetchone()
            if seq > snap:
                raise NodeOutOfRange(
                    f"序号 {seq} 越过稳定视图上界 snapshot={snap}，"
                    "该节点在固定视图内尚不可见",
                    requested_seq=seq, resource=resource,
                    available_min_seq=lo, available_max_seq=hi,
                    snapshot_seq=snap,
                )
            if row is None:
                raise NodeOutOfRange(
                    f"序号 {seq} 在历史中不存在（全局缺号）",
                    requested_seq=seq, resource=resource,
                    available_min_seq=lo, available_max_seq=hi,
                )
            if row["resource"] != resource:
                raise NodeOutOfRange(
                    f"序号 {seq} 属于资源 {row['resource']}，不属于 {resource}",
                    requested_seq=seq, resource=resource,
                    belongs_to_resource=row["resource"],
                    available_min_seq=lo, available_max_seq=hi,
                    reason="seq_belongs_to_other_resource",
                )
            return event_dict(row)
        # wall_ms：取该时刻（含）之前的最后一条事件
        row = conn.execute(
            "SELECT * FROM lease_events WHERE resource=? AND seq<=? "
            "AND wall_ms<=? ORDER BY seq DESC LIMIT 1",
            (resource, snap, wall_ms),
        ).fetchone()
        if row is None:
            raise NodeOutOfRange(
                f"资源 {resource} 在 wall_ms<={wall_ms} 时还没有任何事件",
                requested_wall_ms=wall_ms, resource=resource,
                first_event_seq=lo,
                first_event_wall_ms=self._wall_of(conn, lo),
            )
        return event_dict(row)

    @staticmethod
    def _wall_of(conn, seq: int | None) -> int | None:
        if seq is None:
            return None
        row = conn.execute(
            "SELECT wall_ms FROM lease_events WHERE seq=?", (seq,),
        ).fetchone()
        return row["wall_ms"] if row else None

    # ---- 节点回放 -------------------------------------------------------
    def replay_resource(
        self, resource: str, *, at_seq=None, at_wall_ms=None,
        head: bool = False, snapshot=None,
    ) -> dict[str, Any]:
        seq = _as_int(at_seq, "at_seq", default=None)
        wall = _as_int(at_wall_ms, "at_wall_ms", default=None)
        _exactly_one_node(seq, wall, head)
        with self._snapshot() as (conn, max_seq):
            snap = self._resolve_snapshot(snapshot, max_seq)
            node = self._resolve_node(
                conn, snap, resource, seq=seq, wall_ms=wall, head=head)
            events = self._resource_events(conn, snap, resource, node["seq"])
            st = project(resource, events, check_clocks=True)
            return self._replay_payload(resource, node, st, snap, max_seq)

    def replay_credential(
        self, credential_id: str, *, at_seq=None, at_wall_ms=None,
        head: bool = False, snapshot=None,
    ) -> dict[str, Any]:
        seq = _as_int(at_seq, "at_seq", default=None)
        wall = _as_int(at_wall_ms, "at_wall_ms", default=None)
        _exactly_one_node(seq, wall, head)
        with self._snapshot() as (conn, max_seq):
            snap = self._resolve_snapshot(snapshot, max_seq)
            chain_rows = conn.execute(
                "SELECT * FROM lease_events WHERE credential_id=? AND seq<=? "
                "ORDER BY seq ASC",
                (credential_id, snap),
            ).fetchall()
            drow = conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (credential_id,),
            ).fetchone()
            if not chain_rows and drow is None:
                raise CredentialNotFound(
                    f"委托凭证 {credential_id} 不存在（既无凭证记录也无历史事件）",
                    credential_id=credential_id, snapshot_seq=snap,
                )
            chain = [event_dict(r) for r in chain_rows]

            if head:
                if not chain:
                    raise NodeOutOfRange(
                        f"凭证 {credential_id} 在稳定视图内没有任何事件，"
                        "无法定位节点", credential_id=credential_id,
                        snapshot_seq=snap,
                    )
                node = chain[-1]
            elif seq is not None:
                matches = [e for e in chain if e["seq"] == seq]
                if not matches:
                    self._raise_credential_seq_miss(conn, seq, snap,
                                                    credential_id)
                node = matches[0]
            else:
                before = [e for e in chain if e["wall_ms"] <= wall]
                if not before:
                    first = chain[0]
                    raise NodeOutOfRange(
                        f"凭证 {credential_id} 在 wall_ms<={wall} 时还没有"
                        f"任何事件（首次事件 seq={first['seq']}, "
                        f"wall_ms={first['wall_ms']}）",
                        requested_wall_ms=wall, credential_id=credential_id,
                        first_event_seq=first["seq"],
                        first_event_wall_ms=first["wall_ms"],
                    )
                node = before[-1]

            # 节点所在资源的完整回放，用于说明当时授权租约/资源值/世代号
            resource = node["resource"]
            resource_events = self._resource_events(
                conn, snap, resource, node["seq"])
            st = project(resource, resource_events, check_clocks=True)
            payload = self._replay_payload(
                resource, node, st, snap, max_seq,
                credential_id=credential_id,
            )
            d = st.delegations.get(credential_id)
            payload["credential"] = None if d is None else d.view()
            payload["credential_events"] = [
                e for e in resource_events
                if e["credential_id"] == credential_id
            ]
            if drow is not None and d is None:
                payload["credential_note"] = (
                    "凭证在运行态表中存在，但在该历史节点之前尚无发放事件")
            return payload

    def _raise_credential_seq_miss(self, conn, seq, snap, credential_id):
        if seq > snap:
            raise NodeOutOfRange(
                f"序号 {seq} 越过稳定视图上界 snapshot={snap}",
                requested_seq=seq, available_max_seq=snap,
                credential_id=credential_id,
            )
        grow = conn.execute(
            "SELECT * FROM lease_events WHERE seq=?", (seq,),
        ).fetchone()
        if grow is None:
            raise NodeOutOfRange(
                f"序号 {seq} 在历史中不存在（全局缺号）",
                requested_seq=seq, available_max_seq=snap,
                credential_id=credential_id,
            )
        raise NodeOutOfRange(
            f"序号 {seq}（资源 {grow['resource']}，事件 {grow['event']}）"
            f"不属于凭证 {credential_id} 的事件链",
            requested_seq=seq, credential_id=credential_id,
            belongs_to_resource=grow["resource"],
            reason="seq_not_part_of_credential_chain",
        )

    def _replay_payload(self, resource, node, st: Projection, snap, max_seq,
                        *, credential_id=None) -> dict[str, Any]:
        return {
            "resource": resource,
            "credential_id": credential_id,
            "node": {
                "seq": node["seq"],
                "event": node["event"],
                "outcome": node["outcome"],
                "accepted": node["accepted"],
                "holder": node["holder"],
                "peer": node["peer"],
                "wall_ms": node["wall_ms"],
                "logical": node["logical"],
                "narration": node["narration"],
            },
            "state_as_of_node": st.replay_view(),
            "view": {"snapshot_seq": snap, "latest_seq": max_seq},
            "read_only": True,
        }

    # ---- 两节点比较 -----------------------------------------------------
    def compare_nodes(
        self, resource: str, *,
        a_seq=None, a_wall_ms=None, a_head=False,
        b_seq=None, b_wall_ms=None, b_head=False,
        snapshot=None,
    ) -> dict[str, Any]:
        aseq = _as_int(a_seq, "a_seq", default=None)
        awall = _as_int(a_wall_ms, "a_wall_ms", default=None)
        bseq = _as_int(b_seq, "b_seq", default=None)
        bwall = _as_int(b_wall_ms, "b_wall_ms", default=None)
        _exactly_one_node(aseq, awall, a_head, side="a")
        _exactly_one_node(bseq, bwall, b_head, side="b")
        with self._snapshot() as (conn, max_seq):
            snap = self._resolve_snapshot(snapshot, max_seq)
            node_a = self._resolve_node(
                conn, snap, resource, seq=aseq, wall_ms=awall, head=a_head)
            node_b = self._resolve_node(
                conn, snap, resource, seq=bseq, wall_ms=bwall, head=b_head)
            if node_b["seq"] < node_a["seq"]:
                raise AuditBadRequest(
                    f"节点顺序颠倒：b(seq={node_b['seq']}) 早于 "
                    f"a(seq={node_a['seq']})，比较要求 a 在 b 之前",
                    a_seq=node_a["seq"], b_seq=node_b["seq"],
                )
            events_to_a = self._resource_events(
                conn, snap, resource, node_a["seq"])
            events_to_b = self._resource_events(
                conn, snap, resource, node_b["seq"])
            st_a = project(resource, events_to_a, check_clocks=True)
            st_b = project(resource, events_to_b, check_clocks=True)

            sig_a = st_a.signature()
            sig_b = st_b.signature()
            between = [e for e in events_to_b
                       if node_a["seq"] < e["seq"] <= node_b["seq"]]

            # 增量折叠 (a,b] 之间的事件，第一条让指纹偏离 a 的事件即首异事件
            first = None
            state_at_first = None
            cursor = Projection(resource=resource)
            _fold(cursor, events_to_a, check_clocks=False)
            for ev in between:
                _fold(cursor, [ev], check_clocks=False)
                sig = cursor.signature()
                changed = {
                    k: {"at_a": sig_a.get(k), "at_node": sig.get(k)}
                    for k in sorted(set(sig_a) | set(sig))
                    if sig_a.get(k) != sig.get(k)
                }
                if changed:
                    first, state_at_first = ({
                        "seq": ev["seq"],
                        "event": ev["event"],
                        "outcome": ev["outcome"],
                        "accepted": ev["accepted"],
                        "holder": ev["holder"],
                        "peer": ev["peer"],
                        "credential_id": ev["credential_id"],
                        "detail": ev["detail"],
                        "wall_ms": ev["wall_ms"],
                        "narration": ev["narration"],
                        "changed_fields": sorted(changed),
                    }, changed)
                    break

            final_changed = {
                k: {"at_a": sig_a.get(k), "at_b": sig_b.get(k)}
                for k in sorted(set(sig_a) | set(sig_b))
                if sig_a.get(k) != sig_b.get(k)
            }
            return {
                "resource": resource,
                "node_a": self._node_ref(node_a),
                "node_b": self._node_ref(node_b),
                "identical": not final_changed,
                "events_between": len(between),
                "rejected_events_between": [
                    {"seq": e["seq"], "event": e["event"], "holder": e["holder"],
                     "detail": e["detail"], "narration": e["narration"]}
                    for e in between if e["outcome"] != "ok"
                ],
                "first_divergence": first,
                "state_at_first_divergence": state_at_first,
                "changed_fields_at_b": final_changed,
                "view": {"snapshot_seq": snap, "latest_seq": max_seq},
                "read_only": True,
            }

    @staticmethod
    def _node_ref(node: dict) -> dict:
        return {
            "seq": node["seq"], "event": node["event"],
            "outcome": node["outcome"], "holder": node["holder"],
            "wall_ms": node["wall_ms"], "logical": node["logical"],
            "narration": node["narration"],
        }

    # ---- 一致性诊断 -----------------------------------------------------
    def diagnose_resource(self, resource: str, *, snapshot=None) -> dict[str, Any]:
        with self._snapshot() as (conn, max_seq):
            snap = self._resolve_snapshot(snapshot, max_seq)
            count, lo, hi = self._bounds(conn, snap, resource)
            if count == 0:
                exists = conn.execute(
                    "SELECT 1 FROM resources WHERE resource=?", (resource,),
                ).fetchone()
                if exists is None:
                    raise HistoryNotFound(
                        f"资源 {resource} 不存在且没有任何历史事件",
                        resource=resource, snapshot_seq=snap,
                    )
            events = self._resource_events(conn, snap, resource)
            st = project(resource, events, check_clocks=True)
            issues = list(st.issues)
            issues += self._cross_table_checks(conn, snap, events)
            issues.sort(key=lambda i: (i["seq"] is None, i["seq"] or 0,
                                       i["code"]))
            return self._diagnosis_payload(
                snap, max_seq, scope="resource", resource=resource,
                bounds=(lo, hi), events=events, issues=issues, projection=st,
            )

    def diagnose_credential(self, credential_id: str, *, snapshot=None) -> dict[str, Any]:
        with self._snapshot() as (conn, max_seq):
            snap = self._resolve_snapshot(snapshot, max_seq)
            rows = conn.execute(
                "SELECT * FROM lease_events WHERE credential_id=? AND seq<=? "
                "ORDER BY seq ASC",
                (credential_id, snap),
            ).fetchall()
            drow = conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (credential_id,),
            ).fetchone()
            if not rows and drow is None:
                raise CredentialNotFound(
                    f"委托凭证 {credential_id} 不存在，无法诊断",
                    credential_id=credential_id, snapshot_seq=snap,
                )
            chain = [event_dict(r) for r in rows]
            resources = sorted({e["resource"] for e in chain}) or (
                [drow["resource"]] if drow is not None else [])
            issues: list[dict] = []
            projection = None
            for res in resources:
                evs = self._resource_events(conn, snap, res)
                p = project(res, evs, check_clocks=True)
                if projection is None:
                    projection = p
                issues += [i for i in p.issues
                           if i.get("credential_id") == credential_id]
                issues += [
                    i for i in self._cross_table_checks(conn, snap, evs)
                    if i.get("credential_id") == credential_id
                ]
            if not rows and drow is not None:
                issues.append({
                    "code": "credential_without_any_event", "severity": "warning",
                    "seq": None, "credential_id": credential_id, "event": None,
                    "message": "运行态表存在该凭证，但稳定视图内没有任何审计事件",
                })
            if rows and drow is None:
                issues.append({
                    "code": "credential_row_missing", "severity": "error",
                    "seq": chain[0]["seq"], "credential_id": credential_id,
                    "event": chain[0]["event"],
                    "message": "历史中有该凭证的事件，但 delegations 表无对应记录",
                })
            issues += self._credential_chain_checks(chain)
            issues.sort(key=lambda i: (i["seq"] is None, i["seq"] or 0,
                                       i["code"]))
            cstate = None
            if projection is not None:
                d = projection.delegations.get(credential_id)
                cstate = d.view() if d is not None else None
            lo = chain[0]["seq"] if chain else None
            hi = chain[-1]["seq"] if chain else None
            return {
                "scope": "credential",
                "credential_id": credential_id,
                "resources": resources,
                "event_seq_range": [lo, hi],
                "events": chain,
                "projected_state": cstate,
                "issues": issues,
                "summary": self._summarize(issues, chain),
                "view": {"snapshot_seq": snap, "latest_seq": max_seq,
                         "order": "seq ASC"},
                "read_only": True,
            }

    def diagnose_global(self, *, snapshot=None) -> dict[str, Any]:
        with self._snapshot() as (conn, max_seq):
            snap = self._resolve_snapshot(snapshot, max_seq)
            rows = conn.execute(
                "SELECT * FROM lease_events WHERE seq<=? ORDER BY seq ASC",
                (snap,),
            ).fetchall()
            events = [event_dict(r) for r in rows]
            issues: list[dict] = self._global_seq_integrity(conn, snap)
            per_resource: dict[str, list[dict]] = {}
            for e in events:
                per_resource.setdefault(e["resource"], []).append(e)
            for res in sorted(per_resource):
                evs = per_resource[res]
                p = project(res, evs, check_clocks=True)
                issues += p.issues
                issues += self._cross_table_checks(conn, snap, evs)
            issues.sort(key=lambda i: (i["seq"] is None, i["seq"] or 0,
                                       i["code"]))
            return {
                "scope": "global",
                "resources": sorted(per_resource),
                "event_count": len(events),
                "issues": issues,
                "summary": self._summarize(issues, events),
                "view": {"snapshot_seq": snap, "latest_seq": max_seq,
                         "order": "seq ASC"},
                "read_only": True,
            }

    # ---- 诊断子检查 -----------------------------------------------------
    def _global_seq_integrity(self, conn, snap: int) -> list[dict]:
        """seq 是全局 AUTOINCREMENT：1..MAX 缺号 = 事件被删/损坏。

        按资源看出现"缺口"是正常的（其他资源的事件交错占用了序号），
        只有全局缺号才报。主键保证无重复，仍防御性核对一次。
        """
        rows = conn.execute(
            "SELECT seq FROM lease_events WHERE seq<=? ORDER BY seq ASC",
            (snap,),
        ).fetchall()
        present = {r["seq"] for r in rows}
        if not present:
            return []
        missing = [s for s in range(1, max(present) + 1) if s not in present]
        issues = []
        if missing:
            for s in missing[:200]:
                issues.append({
                    "code": "seq_missing", "severity": "error", "seq": s,
                    "credential_id": None, "event": None,
                    "message": f"全局审计序号 {s} 缺失：事件被删除、损坏或绕过审计写入",
                })
            if len(missing) > 200:
                issues.append({
                    "code": "seq_missing_truncated", "severity": "warning",
                    "seq": None, "credential_id": None, "event": None,
                    "message": f"缺失序号超过 200 个（共 {len(missing)} 个），报告已截断",
                })
        if len(present) != len(rows):
            issues.append({
                "code": "seq_duplicate", "severity": "error", "seq": None,
                "credential_id": None, "event": None,
                "message": "检测到重复的全局审计序号（主键约束下不应发生）",
            })
        return issues

    def _cross_table_checks(self, conn, snap: int,
                            events: list[dict]) -> list[dict]:
        """事件流与运行态审计表勾稽（只读核对）。"""
        issues: list[dict] = []
        if not events:
            return issues

        def add(code, severity, ev, message, *, cid=None):
            issues.append({
                "code": code, "severity": severity, "seq": ev["seq"],
                "credential_id": cid, "event": ev["event"], "message": message,
            })

        lease_cache: dict[str, Any] = {}

        def lease_row(lid):
            if lid not in lease_cache:
                lease_cache[lid] = conn.execute(
                    "SELECT * FROM leases WHERE id=?", (lid,),
                ).fetchone()
            return lease_cache[lid]

        for ev in events:
            kind, ok = ev["event"], ev["outcome"] == "ok"
            lid, cid = ev.get("lease_id"), ev.get("credential_id")
            if (ok and kind == "acquire"
                    and ev.get("detail") != "reused_existing"):
                if lid and lease_row(lid) is None:
                    add("accepted_event_missing_lease_row", "error", ev,
                        f"成功的获取事件引用租约 {lid}，但 leases 表无此记录")
            if ok and kind == "transfer":
                if ev.get("to_lease_id") and lease_row(ev["to_lease_id"]) is None:
                    add("accepted_transfer_missing_new_lease_row", "error", ev,
                        f"转移事件的新租约 {ev.get('to_lease_id')} 在 leases 表缺失")
                t = conn.execute(
                    "SELECT 1 FROM transfers WHERE resource=? AND new_lease_id=?",
                    (ev["resource"], ev.get("to_lease_id")),
                ).fetchone()
                if t is None:
                    add("accepted_transfer_missing_transfer_row", "warning", ev,
                        "成功的转移事件在 transfers 表找不到对应幂等记录")
            if ok and kind == "delegate_grant" and cid:
                d = conn.execute(
                    "SELECT 1 FROM delegations WHERE credential_id=?", (cid,),
                ).fetchone()
                if d is None:
                    add("accepted_grant_missing_delegation_row", "error", ev,
                        f"成功的发放事件引用凭证 {cid}，但 delegations 表无此记录",
                        cid=cid)
            if ok and kind in ("write", "delegate_write"):
                wid = _parse_write_id(ev.get("detail"))
                if wid is not None:
                    w = conn.execute(
                        "SELECT * FROM writes WHERE id=?", (wid,),
                    ).fetchone()
                    if w is None:
                        add("accepted_write_missing_write_row", "error", ev,
                            f"被接受的写入事件引用 write_id={wid}，writes 表无此记录",
                            cid=cid)
                    elif not w["accepted"]:
                        add("write_event_vs_audit_disagree", "error", ev,
                            f"事件称 write_id={wid} 被接受，但 writes 表记录为拒绝",
                            cid=cid)
        return issues

    def _credential_chain_checks(self, chain: list[dict]) -> list[dict]:
        issues: list[dict] = []
        if not chain:
            return issues
        cid = chain[0]["credential_id"]
        grants = [e for e in chain if e["event"] == "delegate_grant"
                  and e["outcome"] == "ok"]
        if len(grants) > 1:
            issues.append({
                "code": "credential_granted_multiple_times", "severity": "error",
                "seq": grants[1]["seq"], "credential_id": cid,
                "event": "delegate_grant",
                "message": f"凭证在 {len(grants)} 个事件中被成功发放，同一凭证号不应重复发放",
            })
        terminals = {"delegate_revoke", "delegate_expire", "delegate_fence"}
        if not grants and any(
                e["event"] in terminals and e["outcome"] == "ok"
                for e in chain):
            issues.append({
                "code": "credential_chain_without_grant", "severity": "error",
                "seq": chain[0]["seq"], "credential_id": cid,
                "event": chain[0]["event"],
                "message": "凭证链存在终态/使用事件，但没有成功的发放事件",
            })
        return issues

    @staticmethod
    def _summarize(issues: list[dict], events: list[dict]) -> dict[str, Any]:
        by_code: dict[str, int] = {}
        for i in issues:
            by_code[i["code"]] = by_code.get(i["code"], 0) + 1
        sev = {"error": 0, "warning": 0, "info": 0}
        for i in issues:
            sev[i["severity"]] = sev.get(i["severity"], 0) + 1
        return {
            "total_events": len(events),
            "total_issues": len(issues),
            "errors": sev["error"],
            "warnings": sev["warning"],
            "infos": sev["info"],
            "issues_by_code": dict(sorted(by_code.items())),
            "consistent": sev["error"] == 0,
        }

    def _diagnosis_payload(self, snap, max_seq, *, scope, resource,
                           bounds, events, issues, projection) -> dict[str, Any]:
        lo, hi = bounds
        return {
            "scope": scope,
            "resource": resource,
            "event_seq_range": [lo, hi],
            "current_projection": projection.replay_view(),
            "issues": issues,
            "summary": self._summarize(issues, events),
            "view": {"snapshot_seq": snap, "latest_seq": max_seq,
                     "order": "seq ASC"},
            "read_only": True,
        }


# ---------------------------------------------------------------------------
# 参数小工具
# ---------------------------------------------------------------------------


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


def _exactly_one_node(seq, wall, head, *, side="node"):
    given = [seq is not None, wall is not None, bool(head)]
    if sum(given) != 1:
        label = "节点 a" if side == "a" else ("节点 b" if side == "b" else "历史节点")
        raise AuditBadRequest(
            f"必须且只能用一种方式指定{label}：at_seq / at_wall_ms / head",
        )


def _parse_write_id(detail: str | None) -> int | None:
    if detail and detail.startswith("write_id="):
        try:
            return int(detail.split("=", 1)[1])
        except ValueError:
            return None
    return None
