"""HTTP 接口 + 后台逻辑钟 ticker。

租约语义速览：
  POST   /leases/acquire       获取（新世代号）
  POST   /leases/renew         续约（世代号不变，软 TTL 顺延）
  POST   /leases/release       释放
  POST   /leases/transfer      安全转移（原子交接：旧持有者即刻失效，
                               新持有者拿更大世代号；transfer_id 幂等）
  POST   /resources/<r>/writes 受租约保护的写入（栅栏校验点）；
                               请求体带 credential_id 即走限时委托路径
委托语义速览：
  POST   /leases/delegations    持有者向指定协作者发放针对某资源的短期凭证
  POST   /leases/delegations/revoke  授权者提前撤销
  GET    /delegations/<id>      按凭证号查授权者/协作者/有效期/世代号/状态
  GET    /resources/<r>/delegations  列某资源的全部委托
  GET    /resources/<r>/history?credential_id=<id>
                               按凭证号过滤：发放/每次使用结果/撤销/过期/失效
  GET    /resources/<r>        查资源当前世代/值
  GET    /resources/<r>/leases 查当前租约
  GET    /resources/<r>/writes 查某次/每次写入是哪一代租约放行的
  GET    /resources/<r>/history 完整租约历史（获取/续约/释放/转移/写入/委托，
                               含被拒绝的操作，按审计顺序排列）
  GET    /writes/<id>          按写入 ID 反查放行世代

审计回放与一致性诊断（全部只读，不会改动运行中的租约/委托）：
  GET    /audit/events                          全资源事件流（seq 升序、固定分页）
  GET    /resources/<r>/audit/events            某资源的完整事件流
  GET    /delegations/<id>/audit/events         某委托凭证的完整事件流
       过滤: ?from_ms&to_ms | ?seq_min&seq_max | ?outcome=ok,rejected
             | ?event=write,transfer | ?after=<seq>&limit | ?snapshot=<seq>
  GET    /resources/<r>/audit/replay            还原历史节点的资源值/当前租约/
                                                委托状态/世代号（?at_seq|at_wall_ms|head）
  GET    /delegations/<id>/audit/replay         按凭证回放其在某节点的状态
  GET    /resources/<r>/audit/compare           比较两节点（?a_at_seq&b_at_seq 等），
                                                指出第一次产生差异的事件
  GET    /resources/<r>/audit/diagnose          单资源一致性诊断（缺号/重号/乱序/矛盾）
  GET    /delegations/<id>/audit/diagnose       单凭证一致性诊断
  GET    /audit/diagnose                        全局诊断（含全局 seq 缺号检查）
可验证审计归档（只写归档自有表，绝不改动租约/委托/原始历史）：
  POST   /audit/archives                        在指定稳定节点创建只读归档
                                                {scope, resource?|credential_id?,
                                                 at_seq|at_wall_ms|head, idempotency_key}
                                                同对象+同节点+同键 → 同一份归档（200 回放）
  GET    /audit/archives                        列归档（?scope&resource&credential_id&status）
  GET    /audit/archives/<id>                   查生成进度/状态/校验值/核验标记
  GET    /audit/archives/<id>/download          下载冻结的归档文档（含内容校验值）
  POST   /audit/archives/<id>/verify            独立核验：标记 verified / verify_failed
                                                （失败给出首个差异位置）
  POST   /audit/archives/<id>/retry             失败的归档复位重试（从已存进度继续）
审计证据包（只写 evidence_* 自有表，绝不修改租约/委托/原始历史/源归档）：
  POST   /audit/evidence                        组合多份已完成归档为只读证据包
                                                {archives:[id|{archive_id,include}],
                                                 idempotency_key, metadata?}
                                                同归档+同顺序+同键 → 同一份（200 回放）；
                                                同键不同清单/不同键同清单 → 409
  GET    /audit/evidence                        列证据包（?status&archive_id&limit）
  GET    /audit/evidence/<id>                   查生成进度/状态/组合摘要/核验标记
  GET    /audit/evidence/<id>/download          下载证据包文档（清单+原文/引用+
                                                组合摘要+总校验值；未完成 409）
  POST   /audit/evidence/<id>/verify            独立核验：逐份检查源归档存在性/
                                                自身核验可信（verify_failed 的
                                                源归档直接判失败）/内容哈希/
                                                原文与组合顺序完整性，
                                                失败给出首个差异位置
  POST   /audit/evidence/<id>/retry             失败的证据包复位重试（从已存进度继续）
审计因果索引（只写 causal_index_* 自有表，绝不修改租约/委托/原始历史/
归档/证据包）：
  POST   /audit/causal-indexes                  创建因果索引
                                                {scope: resource|credential|
                                                 evidence_package,
                                                 resource?|credential_id?|package_id?,
                                                 at_seq?|at_wall_ms?|head?,
                                                 filters?, idempotency_key}
                                                同作用域+同快照节点+同过滤+同键
                                                → 同一份（200 回放）；同键换
                                                范围/节点/过滤 → 409
  GET    /audit/causal-indexes                  列索引（?scope&status&limit）
  GET    /audit/causal-indexes/<id>             查生成进度/状态/链摘要/核验标记
  GET    /audit/causal-indexes/<id>/chain       按因果顺序分页查询链路
                                                （?after=<position>&limit=，
                                                报告断链/环路/重号/缺源归档等）
  GET    /audit/causal-indexes/<id>/nodes/<node_id>
                                                查单个冻结节点
  POST   /audit/causal-indexes/<id>/nodes/<node_id>/rebuild
                                                从冻结事件/归档清单独立重建节点
                                                （只读）并与冻结节点比对
  GET    /audit/causal-indexes/<id>/download    下载冻结的链文档（含链摘要/
                                                总校验值；未完成 409）
  POST   /audit/causal-indexes/<id>/verify      独立核验：从冻结审计事件与
                                                归档清单重算整条链路，通过
                                                verified / 失败 verify_failed
                                                （给出首个差异节点/字段/双方值）
  POST   /audit/causal-indexes/<id>/retry       失败的索引复位重试（从已存进度继续）
因果索引增量派生（只写 causal_derivation_* 自有表，绝不修改原索引/租约/
委托/原始历史/源归档/证据包；派生链复用基线冻结节点，只重建新增节点）：
  POST   /audit/causal-derivations              以已完成索引为基线提交增量派生
                                                {baseline_index_id,
                                                 at_seq?|at_wall_ms?|head?
                                                 （缺省 head）,
                                                 filters?（缺省沿用基线）,
                                                 idempotency_key}
                                                同基线+同节点+同过滤+同键 →
                                                同一份（200 回放）；同键换
                                                基线/节点/过滤 409；同规格换键
                                                409；基线不存在 404 / 未完成 409
  GET    /audit/causal-derivations              列派生任务（?status&baseline_index_id）
  GET    /audit/causal-derivations/<id>         查进度/状态/基线快照与链摘要/
                                                复用·新增·移除节点计数
  GET    /audit/causal-derivations/<id>/chain   按因果顺序分页查询派生链
                                                （?after=<position>&limit=；
                                                节点带 origin=reused/added；
                                                报告结构异常/源漂移/基线漂移）
  GET    /audit/causal-derivations/<id>/nodes/<node_id>
                                                查单个冻结节点（含其基线位置）
  GET    /audit/causal-derivations/<id>/download 下载冻结的派生链文档
  POST   /audit/causal-derivations/<id>/verify  独立核验（总校验值/基线链摘要/
                                                源/成员集合/复用与新增载荷/链摘要）
  POST   /audit/causal-derivations/<id>/retry   failed 复位重试（进度保留）
  POST   /audit/causal-derivations/<id>/pause   暂停（worker 跳过；幂等）
  POST   /audit/causal-derivations/<id>/resume  暂停后恢复（回到待跑队列）
  POST   /audit/causal-indexes/comparisons      比较两份已完成索引（纯只读）：
                                                {a_index_id, b_index_id,
                                                 after?, limit?} → 共同节点、
                                                首个分叉、增删节点、逐字段变化
                                                （每项带节点标识与双方值）
索引版本发布管理（只写 index_releases 自有表，绝不修改原索引/派生任务/
租约/委托/审计历史/源归档/证据包）：
  POST   /audit/index-releases                  登记发布计划
                                                {version, index_id,
                                                 idempotency_key,
                                                 effective_at_ms,
                                                 compare_with_index_id?}
                                                相同版本号+幂等键回放同一计划
                                                （200）；同键换索引/生效时间/
                                                比较对象 409；版本号换键 409；
                                                生效时间已到则同步 active/failed
  GET    /audit/index-releases                  列发布计划（?status&version&index_id）
  GET    /audit/index-releases/<id>             查计划/登记冻结/发布冻结/失败原因
  POST   /audit/index-releases/<id>/cancel      取消仍 scheduled 的计划（幂等）
  POST   /audit/index-releases/<id>/retry       failed 计划重新发布
  GET    /audit/index-versions/<version>        版本别名稳定解析（冻结指针+live 诊断）
  GET    /audit/index-versions/<version>/chain  版本固化的因果链（篡改 409/删除 404）
  GET    /audit/index-versions/<version>/nodes/<node_id>
                                                版本固化的单个冻结节点
  GET    /audit/index-versions/<version>/download
                                                版本固化的链文档（字节稳定）
审计变更订阅与可靠通知（只写 audit_subscription* 自有表，绝不修改源审计
历史、租约、委托、因果索引、归档、证据包或发布计划；对它们只做 SELECT）：
  POST   /audit/subscriptions                   创建订阅
                                                {scope: resource|credential|
                                                 causal_index|release,
                                                 resource?|credential_id?|
                                                 index_id?|release_id?,
                                                 callback_url, start_seq?,
                                                 filters?, idempotency_key,
                                                 max_attempts?}
                                                同幂等键重复提交 → 同一订阅
                                                （200 回放）；换过滤/回调/
                                                起始序号 409；起始序号越过
                                                当前稳定视图上界 416
  GET    /audit/subscriptions                   列订阅（?scope=&status=）
  GET    /audit/subscriptions/<id>              查状态/位置/过滤/投递计数
  POST   /audit/subscriptions/<id>/pause        暂停（幂等）
  POST   /audit/subscriptions/<id>/resume       恢复（幂等）
  POST   /audit/subscriptions/<id>/cancel       取消（幂等；迟到通知被忽略）
  POST   /audit/subscriptions/<id>/restart-from {from_seq}
                                                从指定序号重新开始（保留
                                                全部历史投递记录）
  GET    /audit/subscriptions/<id>/deliveries    分页投递历史
                                                （?after=&status=
                                                 &version_no=&limit=）
  GET    /audit/subscriptions/<id>/deliveries/<event_seq>
                                                单条投递（尝试次数/退避/
                                                失败原因/死信原因/签名）
  POST   /audit/subscriptions/<id>/deliveries/<event_seq>/ack
                                                显式签名确认（回调 202 时；
                                                X-Signature 或 body.signature；
                                                重复确认不推进两次，
                                                坏签名 401 不改状态）
  POST   /audit/subscriptions/<id>/deliveries/<event_seq>/retry
                                                忽略退避立即重试一条投递
  GET    /audit/subscriptions/dead-letters      列死信（?subscription_id=
                                                &version_no=）
  POST   /audit/subscriptions/<id>/dead-letters/<event_seq>/requeue
                                                死信重新放回队列（清空
                                                尝试次数，立即重试）
  订阅版本切换（原子切换；旧版本在途通知按旧回调/密钥/订阅序号收尾，生效
  序号（含）后新匹配事件只进新版本；创建/激活/取消/重试各自幂等键，换规格
  409、生效序号越过稳定历史上界 416 且原订阅不变）：
  POST   /audit/subscriptions/<id>/versions      预创建下一版本
                                                {callback_url, filters?,
                                                 effective_seq,
                                                 idempotency_key}
  GET    /audit/subscriptions/<id>/versions      列版本（?status=&limit=）
  GET    /audit/subscriptions/<id>/versions/<v>  查版本状态/位置/投递计数
  GET    /audit/subscriptions/<id>/versions/<v>/diff
                                                与基线版本差异
                                                （?base_version=，默认当前）
  POST   /audit/subscriptions/<id>/versions/<v>/activate
                                                原子激活（{idempotency_key}）
  POST   /audit/subscriptions/<id>/versions/<v>/cancel
                                                取消预创建版本（幂等键）
  POST   /audit/subscriptions/<id>/versions/<v>/retry-dead-letters
                                                只重试该版本的死信（幂等键）
  通知签名密钥轮换与验证（预登记/生效/撤销/重签各自幂等键；生效前旧密钥、
  生效序号（含）后新密钥，旧通知宽限期内仍可旧密钥确认；换指纹/生效序号/
  宽限期/目标订阅 409，越过稳定历史 416 且当前密钥不变）：
  POST   /audit/subscriptions/<id>/signing-keys
                                                预登记下一把签名密钥
                                                {secret?, fingerprint?,
                                                 effective_seq, grace_ms,
                                                 idempotency_key}
  GET    /audit/subscriptions/<id>/signing-keys 列密钥（?status=&limit=）
  GET    /audit/subscriptions/<id>/signing-keys/<kid>
                                                查密钥状态/指纹/投递计数
  GET    /audit/subscriptions/<id>/signing-keys/<kid>/progress
                                                轮换进度与新旧密钥投递计数
  GET    /audit/subscriptions/<id>/signing-keys/<kid>/deliveries
                                                受影响投递分页（?after=&status=）
  POST   /audit/subscriptions/<id>/signing-keys/<kid>/activate
                                                原子生效（{idempotency_key}）
  POST   /audit/subscriptions/<id>/signing-keys/<kid>/revoke
                                                撤销预登记密钥（幂等键）
  GET    /audit/subscriptions/<id>/signature-verifications
                                                按密钥/时间范围分页验证结果
                                                （?key_id=&result=&from_ms=
                                                 &to_ms=&after=&limit=）
  POST   /audit/subscriptions/<id>/deliveries/<event_seq>/resign
                                                只重签验证失败的指定密钥投递
                                                {key_id?, idempotency_key}
  GET    /audit/subscriptions/<id>/history       该订阅自己的审计历史
                                                （只追加；?after_id=
                                                 &event=&limit=）
  POST   /audit/subscriptions/process           管理/演练：扫描入队+投递一轮
审计通知多端投递（只写 audit_fanout_* 自有表，绝不修改租约、委托、审计
历史、归档、证据包、因果索引、发布计划或订阅投递；一条通知同时投递给
多个独立接收端，创建时冻结送达策略快照——接收端集合、所需成功数、策略
版本——之后修改策略只影响新通知）：
  POST   /audit/fanout/policies         创建送达策略（每次创建产生新的递增
                                        版本）{mode: all|any|quorum,
                                        quorum_count?}
  GET    /audit/fanout/policies         列策略版本（version 升序）
  GET    /audit/fanout/policies/current 当前（最新）策略
  GET    /audit/fanout/policies/<version>
                                        指定版本策略
  POST   /audit/fanout/notifications    创建通知并冻结策略快照
                                        {payload, recipients:[{recipient_id,
                                        max_attempts?}], policy_version?}
  GET    /audit/fanout/notifications    列通知（?status=&limit=）
  GET    /audit/fanout/notifications/<id>
                                        送达状态：冻结快照、每个接收端尝试
                                        次数/最后结果/暂停标记、离完成还差
                                        多少、终态判定快照
  GET    /audit/fanout/notifications/<id>/attempts
                                        整条通知的尝试记录（全局顺序）
  GET    /audit/fanout/notifications/<id>/recipients/<rid>/attempts
                                        单接收端尝试记录（按第几次排序）
  POST   /audit/fanout/notifications/<id>/receipts
                                        成功回执 {recipient_id,
                                        idempotency_key, content?}
                                        同键同内容 → 200 回放首次结果；
                                        同键不同内容 → 409；通知已终态 →
                                        409（迟到回执不能翻案）
  POST   /audit/fanout/notifications/<id>/recipients/<rid>/failures
                                        失败重试 {detail?}：记一次失败尝试，
                                        达到该接收端自己的 max_attempts 进入
                                        终止态；策略不再可能满足时整条通知
                                        明确失败并冻结参与判定的接收端状态
  POST   /audit/fanout/notifications/<id>/recipients/<rid>/pause
                                        暂停接收端（幂等；不改状态/计数，
                                        暂停已成功接收端不改变完成结论）
  POST   /audit/fanout/notifications/<id>/recipients/<rid>/resume
                                        恢复接收端（幂等）
  投递席位（seats 替代 recipients：每个席位冻结有序候选——第 1 位主接收端、
  其余按顺序备用——与切换期限 switch_after_ms；主接收端期限内成功则席位
  立即成功且永不启用备用；期限到达或管理员手动放弃时按顺序启用下一位；
  同一席位无论切换多少次只贡献一次成功；候选全部失败/被放弃则席位终止，
  参与原送达策略可满足性判定；被替换接收端的迟到回执 409 明确拒绝；
  回执与超时/手动切换并发时先结算者赢，后到者 409 带胜负信息）：
  POST   /audit/fanout/notifications/process-deadlines
                                        管理/演练：结算全部到期的切换期限
  GET    /audit/fanout/notifications/<id>/seats
                                        全部席位：当前处理人/下一位备用/
                                        切换期限/最近切换原因
  GET    /audit/fanout/notifications/<id>/seats/<sid>
                                        单席位状态（含全部候选与期限）
  GET    /audit/fanout/notifications/<id>/seats/<sid>/history
                                        席位完整历史（启用/替换原因/回执
                                        受理与拒绝/失败/席位成败）
  POST   /audit/fanout/notifications/<id>/seats/<sid>/switch
                                        手动放弃当前接收端 {reason?,
                                        expected_recipient_id?,
                                        idempotency_key?}；同键重放 200，
                                        席位已成功/已终止 409（带胜负信息）
调试/演练故障用（生产可通过 ENABLE_DEBUG_API=0 关闭）：
  POST   /debug/tick           手动推进逻辑钟
  POST   /debug/wall-shift     拨墙钟（可正可负）
  GET    /debug/now            看两种时钟读数
"""

from __future__ import annotations

import os
import threading
import time

from flask import Flask, Response, jsonify, request

from .archive import (
    ArchiveBadState,
    ArchiveConflict,
    ArchiveError,
    ArchiveManager,
    ArchiveNotFound,
    ArchiveNotReady,
)
from .evidence import (
    EvidenceBadState,
    EvidenceError,
    EvidenceIdConflict,
    EvidenceManifestConflict,
    EvidenceNotFound,
    EvidenceNotReady,
    EvidencePackageManager,
    EvidenceSourceNotFound,
    EvidenceSourceNotReady,
)
from .causal import (
    CausalBadState,
    CausalIdConflict,
    CausalIndexManager,
    CausalNotFound,
    CausalNotReady,
    CausalSourceNotFound,
)
from .derivation import (
    DerivationBadState,
    DerivationBaselineNotFound,
    DerivationBaselineNotReady,
    DerivationIdConflict,
    DerivationManager,
    DerivationNotFound,
    DerivationNotReady,
    DerivationSourceChanged,
    DerivationSpecConflict,
)
from .release import (
    IndexReleaseManager,
    ReleaseBadState,
    ReleaseCancelled,
    ReleaseCompareTargetNotReady,
    ReleaseComparisonChanged,
    ReleaseFailed as ReleaseFailedPlan,
    ReleaseIdConflict,
    ReleaseIndexDeleted,
    ReleaseIndexNotCompleted,
    ReleaseIndexTampered,
    ReleaseNotFound,
    ReleaseNotReady,
    ReleaseVersionConflict,
)
from .subscription import (
    DeliveryBadState,
    DeliveryNotFound,
    InvalidSignature,
    SubscriptionBadState,
    SubscriptionIdConflict,
    SubscriptionManager,
    SubscriptionNotFound,
    SubscriptionRangeError,
    SubscriptionVersionBadState,
    SubscriptionVersionConflict,
    SubscriptionVersionNotFound,
    SubscriptionVersionRangeError,
)
from .key_rotation import (
    KeyRotationBadState,
    KeyRotationConflict,
    KeyRotationIdConflict,
    KeyRotationManager,
    KeyRotationNotFound,
    KeyRotationRangeError,
    KeyVerificationNotFound,
)
from .fanout import (
    FanoutError,
    FanoutManager,
)
from .batching import (
    BatchBadState,
    BatchConflict,
    BatchError,
    BatchManager,
    BatchNotFound,
    BatchRuleNotFound,
    BatchSourceNotFound,
    BatchVerifyFailed,
)
from .audit import (
    AuditBadRequest,
    AuditError,
    AuditReader,
    CredentialNotFound as AuditCredentialNotFound,
    HistoryNotFound,
    NoEventsInRange,
    NodeOutOfRange,
)
from .store import (
    Conflict,
    DelegationNotFound,
    DelegationRejected,
    GenerationTooSmall,
    LeaseGone,
    Store,
)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def create_app(
    db_path: str | None = None,
    *,
    start_ticker: bool = True,
    enable_debug_api: bool | None = None,
    start_archive_worker: bool = True,
) -> Flask:
    app = Flask(__name__)

    db_path = db_path or os.environ.get("DB_PATH", "/data/leases.db")
    store = Store(
        db_path,
        ttl_ms=_env_int("LEASE_TTL_MS", 15_000),
        max_ttl_ms=_env_int("LEASE_MAX_TTL_MS", 60_000),
        hard_ttl_ms=_env_int("LEASE_HARD_TTL_MS", 60_000),
        logical_grace=_env_int("LOGICAL_GRACE_TICKS", 3),
        delegation_ttl_ms=_env_int("DELEGATION_TTL_MS", 15_000),
        delegation_max_ttl_ms=_env_int("DELEGATION_MAX_TTL_MS", 60_000),
    )
    app.extensions["store"] = store
    # 审计回放/诊断读取器：与写入路径共用同一把进程锁，但只读不写
    audit = AuditReader(store)
    app.extensions["audit"] = audit
    # 可验证审计归档：只写 archives/archive_events 自有表
    archive = ArchiveManager(
        store, audit, chunk_size=_env_int("ARCHIVE_CHUNK_SIZE", 100))
    app.extensions["archive"] = archive
    # 审计证据包：组合多份已完成归档，只写 evidence_* 自有表
    evidence = EvidencePackageManager(
        store, chunk_size=_env_int("EVIDENCE_CHUNK_SIZE", 1))
    app.extensions["evidence"] = evidence
    # 审计因果索引：组织事件/写入/委托/源归档/证据包条目为有向因果链，
    # 只写 causal_index_* 自有表
    causal = CausalIndexManager(
        store, audit, chunk_size=_env_int("CAUSAL_CHUNK_SIZE", 100))
    app.extensions["causal"] = causal
    # 因果索引增量派生与索引差异比较：派生只写 causal_derivation_* 自有表，
    # 比较纯只读
    derivation = DerivationManager(
        store, audit, causal,
        chunk_size=_env_int("CAUSAL_DERIVATION_CHUNK_SIZE", 100))
    app.extensions["derivation"] = derivation
    # 索引版本发布管理：登记/发布冻结索引摘要、快照与可选比较结果，只写
    # index_releases 自有表，绝不修改原索引/派生/租约/委托/历史/归档/证据包
    releases = IndexReleaseManager(store, causal, derivation)
    app.extensions["releases"] = releases
    # 审计变更订阅与可靠通知：只写 audit_subscription* 自有表，绝不修改
    # 租约/委托/原始历史/归档/证据包/因果索引/发布计划（对它们只做 SELECT）
    subscriptions = SubscriptionManager(
        store,
        base_backoff_ms=_env_int("SUBSCRIPTION_BACKOFF_BASE_MS", 1_000),
        max_backoff_ms=_env_int("SUBSCRIPTION_BACKOFF_MAX_MS", 300_000),
        claim_lease_ms=_env_int("SUBSCRIPTION_CLAIM_LEASE_MS", 60_000),
    )
    app.extensions["subscriptions"] = subscriptions
    # 订阅通知签名密钥轮换与验证：只写 audit_subscription_signing_keys /
    # audit_subscription_key_idempotency /
    # audit_subscription_signature_verifications 自有表（投递表只追加
    # signing_key_id 列与重签 signature），绝不修改租约、委托、原始历史、
    # 版本行或已有投递状态。
    key_rotation = KeyRotationManager(store, subscriptions)
    subscriptions.attach_key_rotation(key_rotation)
    app.extensions["key_rotation"] = key_rotation
    # 审计通知多端投递：创建通知时冻结送达策略快照（接收端集合/所需成功
    # 数/策略版本），按冻结快照判定完成或明确失败；只写 audit_fanout_*
    # 自有表，绝不修改其他模块的表
    fanout = FanoutManager(store)
    app.extensions["fanout"] = fanout
    # 审计事件窗口批次聚合：按事件类型配置固定窗口/分组字段/允许迟到，
    # 每来源独立 watermark，封存冻结成员/摘要/校验值并只创建一条多接收端
    # 通知；只写 audit_batch_* 自有表
    batching = BatchManager(store)
    app.extensions["batching"] = batching
    if enable_debug_api is None:
        enable_debug_api = os.environ.get("ENABLE_DEBUG_API", "1") == "1"

    tick_interval = float(os.environ.get("LOGICAL_TICK_INTERVAL_S", "1"))
    stop_event = threading.Event()

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------
    def body() -> dict:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def require(data: dict, key: str):
        value = data.get(key)
        if value in (None, ""):
            raise Conflict(f"缺少必填参数: {key}")
        return value

    # ------------------------------------------------------------------
    # 租约
    # ------------------------------------------------------------------
    @app.post("/leases/acquire")
    def acquire():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        ttl_ms = data.get("ttl_ms")
        view, created = store.acquire(resource, holder, ttl_ms)
        return jsonify({"acquired": created, "lease": view}), 201 if created else 200

    @app.post("/leases/renew")
    def renew():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        return jsonify({"lease": store.renew(resource, holder, generation)})

    @app.post("/leases/release")
    def release():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        store.release(resource, holder, generation)
        return jsonify({"released": True, "resource": resource})

    @app.post("/leases/transfer")
    def transfer():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        # to_holder 的校验放在 store 层，不合格接收者也会记入历史
        result = store.transfer(
            resource, holder, generation,
            to_holder=data.get("to_holder"),
            transfer_id=data.get("transfer_id"),
            ttl_ms=data.get("ttl_ms"),
        )
        return jsonify(result), 200 if result["replayed"] else 201

    # ------------------------------------------------------------------
    # 限时委托
    # ------------------------------------------------------------------
    @app.post("/leases/delegations")
    def grant_delegation():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        # collaborator 的资格校验放在 store 层，不合格也会记入历史
        result = store.grant_delegation(
            resource, holder, generation,
            collaborator=data.get("collaborator"),
            ttl_ms=data.get("ttl_ms"),
            credential_id=data.get("credential_id"),
        )
        return jsonify({"delegation": result}), 201

    @app.post("/leases/delegations/revoke")
    def revoke_delegation():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        credential_id = require(data, "credential_id")
        result = store.revoke_delegation(
            resource, holder, generation, credential_id
        )
        return jsonify({"delegation": result, "revoked": True})

    # ------------------------------------------------------------------
    # 受保护写入
    # ------------------------------------------------------------------
    @app.post("/resources/<resource>/writes")
    def write(resource):
        data = body()
        holder = require(data, "holder")
        credential_id = data.get("credential_id")
        # 持有者直写必须出示世代号；委托写入世代号由凭证锚定，可省
        if credential_id:
            raw_gen = data.get("generation")
            generation = int(raw_gen) if raw_gen not in (None, "") else None
        else:
            generation = int(require(data, "generation"))
        value = data.get("value")
        result = store.write(
            resource, holder, generation, value,
            credential_id=credential_id,
        )
        return jsonify(result), 201

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    @app.get("/resources/<resource>")
    def get_resource(resource):
        res = store.get_resource(resource)
        if res is None:
            return jsonify({"error": "not_found", "resource": resource}), 404
        return jsonify(res)

    @app.get("/resources/<resource>/leases")
    def get_lease(resource):
        lease = store.get_lease(resource)
        if lease is None:
            return jsonify({"resource": resource, "state": "none"}), 404
        return jsonify(lease)

    @app.get("/resources/<resource>/writes")
    def list_writes(resource):
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify(
            {"resource": resource, "writes": store.list_writes(resource, limit)}
        )

    @app.get("/resources/<resource>/delegations")
    def list_delegations(resource):
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify(
            {"resource": resource,
             "delegations": store.list_delegations(resource, limit)}
        )

    @app.get("/resources/<resource>/history")
    def get_history(resource):
        limit = min(int(request.args.get("limit", 200)), 1000)
        # ?credential_id=<id>：只看这张凭证的授权者/协作者/有效期/世代号
        # 与每次使用结果
        credential_id = request.args.get("credential_id")
        return jsonify(
            {"resource": resource,
             "events": store.list_history(
                 resource, limit, credential_id=credential_id)}
        )

    @app.get("/delegations/<credential_id>")
    def get_delegation(credential_id):
        d = store.get_delegation(credential_id)
        if d is None:
            return jsonify(
                {"error": "not_found", "credential_id": credential_id}
            ), 404
        return jsonify(d)

    @app.get("/writes/<int:write_id>")
    def get_write(write_id):
        w = store.get_write(write_id)
        if w is None:
            return jsonify({"error": "not_found", "write_id": write_id}), 404
        return jsonify(w)

    # ------------------------------------------------------------------
    # 审计回放与一致性诊断（全部只读，绝不改动运行中的租约/委托）
    #
    # 稳定视图：每个响应带 view.snapshot_seq；翻页/多次查询回传
    # ?snapshot=<seq> 即固定在同一份历史上，并发写入不会让结果漂移。
    # 节点三选一：at_seq=<seq> | at_wall_ms=<t> | head（最新）。
    # ------------------------------------------------------------------
    def _common_event_args():
        args = request.args
        outcomes = [o for o in args.get("outcome", "").split(",") if o]
        bad = [o for o in outcomes if o not in ("ok", "rejected")]
        if bad:
            raise AuditBadRequest("outcome 只能取 ok / rejected",
                                  bad_outcomes=bad)
        event_types = [e for e in args.get("event", "").split(",") if e]
        return {
            "after_seq": args.get("after"),
            "limit": args.get("limit", 100),
            "snapshot": args.get("snapshot"),
            "seq_min": args.get("seq_min"),
            "seq_max": args.get("seq_max"),
            "from_ms": args.get("from_ms"),
            "to_ms": args.get("to_ms"),
            "outcomes": outcomes or None,
            "event_types": event_types or None,
        }

    def _node_args(prefix: str = ""):
        args = request.args
        return {
            f"{prefix}at_seq": args.get(f"{prefix}at_seq"),
            f"{prefix}at_wall_ms": args.get(f"{prefix}at_wall_ms"),
            f"{prefix}head": args.get(f"{prefix}head", "").lower()
            in ("1", "true", "yes"),
        }

    @app.get("/audit/events")
    def audit_global_events():
        # 全局事件流（所有资源交错），按全局 seq 升序固定排列
        return jsonify(audit.list_events(scope="global",
                                         **_common_event_args()))

    @app.get("/resources/<resource>/audit/events")
    def audit_resource_events(resource):
        return jsonify(audit.list_events(
            scope="resource", resource=resource, **_common_event_args()))

    @app.get("/delegations/<credential_id>/audit/events")
    def audit_credential_events(credential_id):
        return jsonify(audit.list_events(
            scope="credential", credential_id=credential_id,
            **_common_event_args()))

    @app.get("/resources/<resource>/audit/replay")
    def audit_resource_replay(resource):
        kw = _node_args()
        return jsonify(audit.replay_resource(
            resource,
            at_seq=kw["at_seq"], at_wall_ms=kw["at_wall_ms"],
            head=kw["head"], snapshot=request.args.get("snapshot"),
        ))

    @app.get("/delegations/<credential_id>/audit/replay")
    def audit_credential_replay(credential_id):
        kw = _node_args()
        return jsonify(audit.replay_credential(
            credential_id,
            at_seq=kw["at_seq"], at_wall_ms=kw["at_wall_ms"],
            head=kw["head"], snapshot=request.args.get("snapshot"),
        ))

    @app.get("/resources/<resource>/audit/compare")
    def audit_compare(resource):
        a = _node_args("a_")
        b = _node_args("b_")
        return jsonify(audit.compare_nodes(
            resource,
            a_seq=a["a_at_seq"], a_wall_ms=a["a_at_wall_ms"], a_head=a["a_head"],
            b_seq=b["b_at_seq"], b_wall_ms=b["b_at_wall_ms"], b_head=b["b_head"],
            snapshot=request.args.get("snapshot"),
        ))

    @app.get("/resources/<resource>/audit/diagnose")
    def audit_diagnose_resource(resource):
        return jsonify(
            audit.diagnose_resource(resource,
                                    snapshot=request.args.get("snapshot")))

    @app.get("/delegations/<credential_id>/audit/diagnose")
    def audit_diagnose_credential(credential_id):
        return jsonify(
            audit.diagnose_credential(credential_id,
                                      snapshot=request.args.get("snapshot")))

    @app.get("/audit/diagnose")
    def audit_diagnose_global():
        return jsonify(
            audit.diagnose_global(snapshot=request.args.get("snapshot")))

    # ------------------------------------------------------------------
    # 可验证审计归档
    #
    # 在指定稳定历史节点把某资源/某凭证的事件范围、回放状态、诊断结果与
    # 内容校验值冻结成只读归档。生成是后台分块进行的：进度落库，重启/
    # 失败后从已保存的进度继续，重试不会重复写入。归档、下载、核验只写
    # 归档自有表，绝不修改正在运行的租约、委托和原始审计历史。
    # ------------------------------------------------------------------
    @app.post("/audit/archives")
    def archive_create():
        data = body()
        view, created = archive.create_archive(
            scope=data.get("scope"),
            resource=data.get("resource"),
            credential_id=data.get("credential_id"),
            at_seq=data.get("at_seq"),
            at_wall_ms=data.get("at_wall_ms"),
            head=bool(data.get("head", False)),
            idempotency_key=data.get("idempotency_key"),
        )
        # 同对象+同节点+同幂等键重复创建：200 回放同一份归档
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/archives")
    def archive_list():
        return jsonify(archive.list_archives(
            scope=request.args.get("scope"),
            resource=request.args.get("resource"),
            credential_id=request.args.get("credential_id"),
            status=request.args.get("status"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/archives/<archive_id>")
    def archive_status(archive_id):
        return jsonify(archive.get_archive(archive_id))

    @app.get("/audit/archives/<archive_id>/download")
    def archive_download(archive_id):
        text, view = archive.download(archive_id)
        # 落库原文逐字节返回：下载者可用 content_sha256 独立复算
        return Response(
            text, mimetype="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="audit-archive-{archive_id}.json"',
                "X-Archive-SHA256": view["content_sha256"] or "",
            },
        )

    @app.post("/audit/archives/<archive_id>/verify")
    def archive_verify(archive_id):
        # 独立核验：通过标记 verified，失败标记 verify_failed 并给出
        # 首个差异位置；只写归档自有表
        return jsonify(archive.verify(archive_id))

    @app.post("/audit/archives/<archive_id>/retry")
    def archive_retry(archive_id):
        return jsonify(archive.retry(archive_id))

    # ------------------------------------------------------------------
    # 审计证据包
    #
    # 把多份已完成的资源/凭证归档按给定组合顺序冻结成一份只读证据包。
    # 创建时冻结清单、每份归档的内容校验值、组合顺序与生成时元数据；
    # 后台按条目分块生成，进度落库，重启/失败后从已保存进度继续，
    # 重试不重复写入。证据包操作只写 evidence_* 自有表，绝不修改租约、
    # 委托、原始审计历史与源归档。
    # ------------------------------------------------------------------
    @app.post("/audit/evidence")
    def evidence_create():
        data = body()
        view, created = evidence.create_package(
            archives=data.get("archives"),
            idempotency_key=data.get("idempotency_key"),
            metadata=data.get("metadata"),
        )
        # 同组归档+同顺序+同键重复创建：200 回放同一份证据包
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/evidence")
    def evidence_list():
        return jsonify(evidence.list_packages(
            status=request.args.get("status"),
            archive_id=request.args.get("archive_id"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/evidence/<package_id>")
    def evidence_status(package_id):
        return jsonify(evidence.get_package(package_id))

    @app.get("/audit/evidence/<package_id>/download")
    def evidence_download(package_id):
        text, view = evidence.download(package_id)
        # 落库原文逐字节返回：下载者可用 content_sha256 独立复算
        return Response(
            text, mimetype="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="audit-evidence-{package_id}.json"',
                "X-Evidence-SHA256": view["content_sha256"] or "",
            },
        )

    @app.post("/audit/evidence/<package_id>/verify")
    def evidence_verify(package_id):
        # 独立核验：逐份检查源归档存在性/自身核验可信/内容哈希/原文与
        # 组合顺序完整性，通过标记 verified，失败标记 verify_failed 并给出
        # 首个差异位置
        return jsonify(evidence.verify(package_id))

    @app.post("/audit/evidence/<package_id>/retry")
    def evidence_retry(package_id):
        return jsonify(evidence.retry(package_id))

    # ------------------------------------------------------------------
    # 审计因果索引
    #
    # 把作用域内的租约事件、写入、委托、源归档、证据包条目组织成可查询
    # 的有向因果链。创建时冻结 snapshot_seq、查询范围与过滤条件，成员集合
    # 同事务落库；后台分块还原节点，进度落库，重启/失败续跑，重试不重复
    # 写入。所有接口只写 causal_index_* 自有表，绝不修改租约、委托、原始
    # 审计历史、源归档或证据包。
    # ------------------------------------------------------------------
    @app.post("/audit/causal-indexes")
    def causal_create():
        data = body()
        view, created = causal.create_index(
            scope=data.get("scope"),
            resource=data.get("resource"),
            credential_id=data.get("credential_id"),
            package_id=data.get("package_id"),
            at_seq=data.get("at_seq"),
            at_wall_ms=data.get("at_wall_ms"),
            head=bool(data.get("head", False)),
            filters=data.get("filters"),
            idempotency_key=data.get("idempotency_key"),
        )
        # 同作用域+同快照节点+同范围+同过滤+同键：200 回放同一份索引
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/causal-indexes")
    def causal_list():
        return jsonify(causal.list_indexes(
            scope=request.args.get("scope"),
            status=request.args.get("status"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/causal-indexes/<index_id>")
    def causal_status(index_id):
        return jsonify(causal.get_index(index_id))

    @app.get("/audit/causal-indexes/<index_id>/chain")
    def causal_chain(index_id):
        return jsonify(causal.get_chain(
            index_id,
            after=request.args.get("after"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/causal-indexes/<index_id>/nodes/<node_id>")
    def causal_node(index_id, node_id):
        # 单节点查询：取冻结载荷（只读）
        return jsonify(causal.get_frozen_node(index_id, node_id))

    @app.post("/audit/causal-indexes/<index_id>/nodes/<node_id>/rebuild")
    def causal_node_rebuild(index_id, node_id):
        return jsonify(causal.rebuild_node(index_id, node_id))

    @app.get("/audit/causal-indexes/<index_id>/download")
    def causal_download(index_id):
        text, view = causal.download(index_id)
        return Response(
            text, mimetype="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="audit-causal-index-'
                    f'{index_id}.json"',
                "X-Causal-SHA256": view["content_sha256"] or "",
                "X-Causal-Chain-Digest": view["chain_digest"] or "",
            },
        )

    @app.post("/audit/causal-indexes/<index_id>/verify")
    def causal_verify(index_id):
        return jsonify(causal.verify(index_id))

    @app.post("/audit/causal-indexes/<index_id>/retry")
    def causal_retry(index_id):
        return jsonify(causal.retry(index_id))

    # ------------------------------------------------------------------
    # 因果索引增量派生
    #
    # 以一份已完成的因果索引为基线，在新冻结快照上增量派生新链。创建时
    # 冻结新的 snapshot_seq/范围/过滤，并原样保留基线快照信息与链摘要；
    # 复用节点的载荷复制自基线冻结副本（生成期间源数据再变化也污染不了
    # 派生链），只重建基线快照之后新增的事件/源归档/证据包条目节点。
    # 支持创建进度、暂停/恢复、失败重试与稳定查询；只写 causal_derivation_*
    # 自有表，绝不修改原索引、租约、委托、审计历史、源归档或证据包。
    # ------------------------------------------------------------------
    @app.post("/audit/causal-derivations")
    def derivation_create():
        data = body()
        view, created = derivation.create_derivation(
            baseline_index_id=data.get("baseline_index_id"),
            scope=data.get("scope"),
            resource=data.get("resource"),
            credential_id=data.get("credential_id"),
            package_id=data.get("package_id"),
            at_seq=data.get("at_seq"),
            at_wall_ms=data.get("at_wall_ms"),
            head=bool(data.get("head", False)),
            filters=data.get("filters"),
            idempotency_key=data.get("idempotency_key"),
        )
        # 同基线+同范围+同快照节点+同过滤+同键：200 回放同一个派生任务
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/causal-derivations")
    def derivation_list():
        return jsonify(derivation.list_derivations(
            status=request.args.get("status"),
            baseline_index_id=request.args.get("baseline_index_id"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/causal-derivations/<derivation_id>")
    def derivation_status(derivation_id):
        return jsonify(derivation.get_derivation(derivation_id))

    @app.get("/audit/causal-derivations/<derivation_id>/chain")
    def derivation_chain(derivation_id):
        return jsonify(derivation.get_chain(
            derivation_id,
            after=request.args.get("after"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/causal-derivations/<derivation_id>/nodes/<node_id>")
    def derivation_node(derivation_id, node_id):
        return jsonify(
            derivation.get_frozen_node(derivation_id, node_id))

    @app.get("/audit/causal-derivations/<derivation_id>/download")
    def derivation_download(derivation_id):
        text, view = derivation.download(derivation_id)
        return Response(
            text, mimetype="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="audit-causal-derivation-'
                    f'{derivation_id}.json"',
                "X-Derivation-SHA256": view["content_sha256"] or "",
                "X-Derivation-Chain-Digest": view["chain_digest"] or "",
            },
        )

    @app.post("/audit/causal-derivations/<derivation_id>/verify")
    def derivation_verify(derivation_id):
        return jsonify(derivation.verify(derivation_id))

    @app.post("/audit/causal-derivations/<derivation_id>/retry")
    def derivation_retry(derivation_id):
        # failed -> pending，从已保存进度继续
        return jsonify(derivation.retry(derivation_id))

    @app.post("/audit/causal-derivations/<derivation_id>/pause")
    def derivation_pause(derivation_id):
        return jsonify(derivation.pause(derivation_id))

    @app.post("/audit/causal-derivations/<derivation_id>/resume")
    def derivation_resume(derivation_id):
        return jsonify(derivation.resume(derivation_id))

    # ------------------------------------------------------------------
    # 已完成因果索引的差异比较（纯只读，不写任何表）：
    # 共同节点、首个分叉节点、增删节点与逐字段变化（节点标识+双方值）
    # ------------------------------------------------------------------
    @app.post("/audit/causal-indexes/comparisons")
    def causal_compare():
        data = body()
        return jsonify(derivation.compare_indexes(
            require(data, "a_index_id"),
            require(data, "b_index_id"),
            after=data.get("after"),
            limit=data.get("limit", 100),
        ))

    # ------------------------------------------------------------------
    # 索引版本发布管理
    #
    # 把一份已完成的因果索引登记为逻辑版本并提交带生效时间的发布计划。
    # 登记时冻结索引摘要/快照/可选比较结果，生效时再次冻结并复核（原索引
    # 被篡改/删除、比较对象未完成 -> 计划 failed 并保留原因）。支持延迟
    # 生效、取消、中断恢复（worker + 查询惰性扫描）与版本别名稳定查询。
    # 只写 index_releases 自有表，绝不修改原索引、派生任务、租约、委托、
    # 审计历史、源归档或证据包。
    # ------------------------------------------------------------------
    @app.post("/audit/index-releases")
    def release_register():
        data = body()
        view, created = releases.register_release(
            version=data.get("version"),
            index_id=data.get("index_id"),
            idempotency_key=data.get("idempotency_key"),
            effective_at_ms=data.get("effective_at_ms"),
            compare_with_index_id=data.get("compare_with_index_id"),
        )
        # 相同版本号+幂等键重复登记：200 回放同一计划（含其当前状态）
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/index-releases")
    def release_list():
        return jsonify(releases.list_releases(
            status=request.args.get("status"),
            version=request.args.get("version"),
            index_id=request.args.get("index_id"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/index-releases/<release_id>")
    def release_status(release_id):
        return jsonify(releases.get_release(release_id))

    @app.post("/audit/index-releases/<release_id>/cancel")
    def release_cancel(release_id):
        return jsonify(releases.cancel_release(release_id))

    @app.post("/audit/index-releases/<release_id>/retry")
    def release_retry(release_id):
        # failed -> 立即重新发布（生效时间不变；到点计划无需重试）
        return jsonify(releases.retry_release(release_id))

    @app.get("/audit/index-versions/<version>")
    def version_resolve(version):
        # 版本别名稳定查询：只解析冻结的索引指针（附原索引只读 live 诊断）
        return jsonify(releases.resolve_version(version))

    @app.get("/audit/index-versions/<version>/chain")
    def version_chain(version):
        # 服务前再次核对原索引链摘要，被篡改/删除 -> 409/404
        return jsonify(releases.version_chain(
            version,
            after=request.args.get("after"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/index-versions/<version>/nodes/<node_id>")
    def version_node(version, node_id):
        return jsonify(releases.version_node(version, node_id))

    @app.get("/audit/index-versions/<version>/download")
    def version_download(version):
        text, view = releases.version_download(version)
        return Response(
            text, mimetype="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="index-version-'
                    f'{version}.json"',
                "X-Index-Version": version,
                "X-Causal-SHA256": view["content_sha256"] or "",
                "X-Causal-Chain-Digest": view["chain_digest"] or "",
            },
        )

    # ------------------------------------------------------------------
    # 审计变更订阅与可靠通知
    #
    # 为资源、委托凭证、因果索引或发布版本创建订阅：创建时冻结事件范围
    # （filters）、起始历史序号与回调地址，按全局历史序号为每个订阅严格
    # 顺序投递；通知带事件序号/对象标识/事件类型/内容摘要/订阅序号与
    # HMAC-SHA256 签名。回调失败按指数退避重试，超过上限进入死信并挡住
    # 后续投递，可查看失败原因并重新放回队列。订阅流程只写
    # audit_subscription* 自有表，绝不修改源审计历史、租约、委托、索引、
    # 归档、证据包或发布计划。
    # ------------------------------------------------------------------
    @app.post("/audit/subscriptions")
    def subscription_create():
        data = body()
        view, created = subscriptions.create_subscription(
            scope=data.get("scope"),
            resource=data.get("resource"),
            credential_id=data.get("credential_id"),
            index_id=data.get("index_id"),
            release_id=data.get("release_id"),
            callback_url=data.get("callback_url"),
            start_seq=data.get("start_seq", 0),
            filters=data.get("filters"),
            idempotency_key=data.get("idempotency_key"),
            max_attempts=data.get("max_attempts"),
        )
        # 同一幂等键重复提交：200 回放同一订阅；换过滤/回调/起始序号 409
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/subscriptions")
    def subscription_list():
        return jsonify(subscriptions.list_subscriptions(
            scope=request.args.get("scope"),
            status=request.args.get("status"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/subscriptions/<subscription_id>")
    def subscription_status(subscription_id):
        return jsonify(subscriptions.get_subscription(subscription_id))

    @app.post("/audit/subscriptions/<subscription_id>/pause")
    def subscription_pause(subscription_id):
        return jsonify(subscriptions.pause(subscription_id))

    @app.post("/audit/subscriptions/<subscription_id>/resume")
    def subscription_resume(subscription_id):
        return jsonify(subscriptions.resume(subscription_id))

    @app.post("/audit/subscriptions/<subscription_id>/cancel")
    def subscription_cancel(subscription_id):
        return jsonify(subscriptions.cancel(subscription_id))

    @app.post("/audit/subscriptions/<subscription_id>/restart-from")
    def subscription_restart(subscription_id):
        data = body()
        return jsonify(subscriptions.restart_from(
            subscription_id, require(data, "from_seq")))

    @app.get("/audit/subscriptions/<subscription_id>/deliveries")
    def subscription_deliveries(subscription_id):
        # 分页读取投递历史（按事件序号升序；?after=&status=&version_no=&limit=）
        return jsonify(subscriptions.list_deliveries(
            subscription_id,
            after_seq=request.args.get("after"),
            status=request.args.get("status"),
            version_no=request.args.get("version_no"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/subscriptions/<subscription_id>/deliveries/<int:event_seq>")
    def subscription_delivery(subscription_id, event_seq):
        return jsonify(subscriptions.get_delivery(subscription_id, event_seq))

    @app.post("/audit/subscriptions/<subscription_id>/deliveries/<int:event_seq>/ack")
    def subscription_ack(subscription_id, event_seq):
        # 显式签名确认（回调返回 202 的场景）：
        # 签名取 X-Signature 头或请求体 signature 字段
        data = body()
        signature = request.headers.get("X-Signature") or data.get("signature")
        return jsonify(subscriptions.confirm_delivery(
            subscription_id, event_seq, signature))

    @app.post("/audit/subscriptions/<subscription_id>/deliveries/<int:event_seq>/retry")
    def subscription_delivery_retry(subscription_id, event_seq):
        # 手动重试：忽略退避等待，立即重新进入待投递队列
        return jsonify(
            subscriptions.retry_delivery(subscription_id, event_seq))

    @app.get("/audit/subscriptions/dead-letters")
    def subscription_dead_letters():
        return jsonify(subscriptions.list_dead_letters(
            subscription_id=request.args.get("subscription_id"),
            version_no=request.args.get("version_no"),
            limit=request.args.get("limit", 100),
        ))

    @app.post("/audit/subscriptions/<subscription_id>/dead-letters/<int:event_seq>/requeue")
    def subscription_dead_letter_requeue(subscription_id, event_seq):
        # 死信重新放回队列：清空尝试次数，立即重试（严格顺序仍受队首约束）
        return jsonify(subscriptions.requeue_dead_letter(
            subscription_id, event_seq=event_seq))

    # -- 订阅版本切换 -----------------------------------------------------
    @app.post("/audit/subscriptions/<subscription_id>/versions")
    def subscription_version_prepare(subscription_id):
        # 为活动订阅预创建下一版本：新回调地址、新过滤条件、生效历史序号
        # （含）。同键重放 200；换规格/目标订阅 409；生效序号越过稳定
        # 历史上界 416 且原订阅不变。
        data = body()
        view, created = subscriptions.prepare_version(
            subscription_id,
            callback_url=data.get("callback_url"),
            filters=data.get("filters"),
            effective_seq=data.get("effective_seq"),
            idempotency_key=data.get("idempotency_key"),
        )
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/subscriptions/<subscription_id>/versions")
    def subscription_version_list(subscription_id):
        # 版本状态分页（?status=prepared/active/superseded/cancelled）
        return jsonify(subscriptions.list_versions(
            subscription_id,
            status=request.args.get("status"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/subscriptions/<subscription_id>/versions/<int:version_no>")
    def subscription_version_get(subscription_id, version_no):
        return jsonify(subscriptions.get_version(
            subscription_id, version_no))

    @app.get("/audit/subscriptions/<subscription_id>/versions/<int:version_no>/diff")
    def subscription_version_diff(subscription_id, version_no):
        # 与基线版本（默认当前生效版本）的差异：回调/过滤/生效序号
        return jsonify(subscriptions.diff_version(
            subscription_id, version_no,
            base_version=request.args.get("base_version")))

    @app.post("/audit/subscriptions/<subscription_id>/versions/<int:version_no>/activate")
    def subscription_version_activate(subscription_id, version_no):
        # 原子切换（单事务）：旧版本 superseded、新版本 active、订阅主行
        # 整体切换；同键重放 200。
        data = body()
        view, created = subscriptions.activate_version(
            subscription_id, version_no,
            idempotency_key=data.get("idempotency_key"))
        return jsonify({**view, "replayed": not created}), \
            200 if created else 200

    @app.post("/audit/subscriptions/<subscription_id>/versions/<int:version_no>/cancel")
    def subscription_version_cancel(subscription_id, version_no):
        # 取消预创建版本（只有 prepared 可取消），永不生效
        data = body()
        view, created = subscriptions.cancel_version(
            subscription_id, version_no,
            idempotency_key=data.get("idempotency_key"))
        return jsonify({**view, "replayed": not created}), 200

    @app.post("/audit/subscriptions/<subscription_id>/versions/<int:version_no>/retry-dead-letters")
    def subscription_version_retry_dead(subscription_id, version_no):
        # 只重试某个版本的死信（复位尝试次数，立即重试，严格顺序不变）
        data = body()
        view, created = subscriptions.retry_version_dead_letters(
            subscription_id, version_no,
            idempotency_key=data.get("idempotency_key"))
        return jsonify({**view, "replayed": not created}), 200

    @app.get("/audit/subscriptions/<subscription_id>/history")
    def subscription_audit_history(subscription_id):
        # 该订阅自己的审计历史（只追加）：版本创建/激活/拒绝原因/取消/重试
        return jsonify(subscriptions.list_audit_history(
            subscription_id,
            after_id=request.args.get("after_id"),
            event=request.args.get("event"),
            limit=request.args.get("limit", 100),
        ))

    # -- 签名密钥轮换与验证 -----------------------------------------------
    @app.post("/audit/subscriptions/<subscription_id>/signing-keys")
    def signing_key_prepare(subscription_id):
        # 为活动订阅预登记下一把签名密钥：指纹/生效历史序号（含）/宽限期。
        # 同键重放 200；换指纹/生效序号/宽限期/目标订阅 409；生效序号越过
        # 稳定历史 416、早于已扫描位置 409，拒绝时当前密钥不变。
        data = body()
        view, created = key_rotation.prepare_key(
            subscription_id,
            secret=data.get("secret"),
            fingerprint=data.get("fingerprint"),
            effective_seq=data.get("effective_seq"),
            grace_ms=data.get("grace_ms", 0),
            idempotency_key=data.get("idempotency_key"),
        )
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/subscriptions/<subscription_id>/signing-keys")
    def signing_key_list(subscription_id):
        # 密钥状态（?status=prepared/active/grace/retired/revoked）
        return jsonify(key_rotation.list_keys(
            subscription_id,
            status=request.args.get("status"),
            limit=request.args.get("limit", 100),
        ))

    @app.get("/audit/subscriptions/<subscription_id>/signing-keys/<key_id>")
    def signing_key_get(subscription_id, key_id):
        # 单把密钥状态
        return jsonify(key_rotation.get_key(subscription_id, key_id))

    @app.get("/audit/subscriptions/<subscription_id>/signing-keys/<key_id>/progress")
    def signing_key_progress(subscription_id, key_id):
        # 轮换进度：旧密钥待收尾投递数、新密钥投递计数、受影响投递分页
        return jsonify(key_rotation.rotation_progress(subscription_id, key_id))

    @app.get("/audit/subscriptions/<subscription_id>/signing-keys/<key_id>/deliveries")
    def signing_key_affected(subscription_id, key_id):
        # 受轮换影响的投递（边界前未终态旧密钥尾巴 + 边界后新密钥投递）
        return jsonify(key_rotation.affected_deliveries(
            subscription_id, key_id,
            after_seq=request.args.get("after"),
            status=request.args.get("status"),
            limit=request.args.get("limit", 100),
        ))

    @app.post("/audit/subscriptions/<subscription_id>/signing-keys/<key_id>/activate")
    def signing_key_activate(subscription_id, key_id):
        # 原子生效：生效序号（含）起新通知必须用新密钥；旧密钥进入宽限/
        # 立即退役；生效前在途通知继续按旧密钥完成确认
        data = body()
        view, created = key_rotation.activate_key(
            subscription_id, key_id,
            idempotency_key=data.get("idempotency_key"))
        return jsonify({**view, "replayed": not created}), 200

    @app.post("/audit/subscriptions/<subscription_id>/signing-keys/<key_id>/revoke")
    def signing_key_revoke(subscription_id, key_id):
        # 撤销预登记密钥（只有 prepared 可撤销，永不生效，记录保留）
        data = body()
        view, created = key_rotation.revoke_key(
            subscription_id, key_id,
            idempotency_key=data.get("idempotency_key"))
        return jsonify({**view, "replayed": not created}), 200

    @app.get("/audit/subscriptions/<subscription_id>/signature-verifications")
    def signing_key_verifications(subscription_id):
        # 按密钥与时间范围分页查询投递签名验证结果
        # （?key_id=&result=ok/failed/old_key_grace/resigned&from_ms=&to_ms=）
        return jsonify(key_rotation.list_verifications(
            subscription_id,
            key_id=request.args.get("key_id"),
            result=request.args.get("result"),
            from_ms=request.args.get("from_ms"),
            to_ms=request.args.get("to_ms"),
            after_seq=request.args.get("after"),
            limit=request.args.get("limit", 100),
        ))

    @app.post("/audit/subscriptions/<subscription_id>/deliveries/<int:event_seq>/resign")
    def signing_key_resign(subscription_id, event_seq):
        # 只对验证失败的指定密钥投递重新签名（不重置状态/不重复确认）
        data = body()
        view, created = key_rotation.resign_failed_delivery(
            subscription_id, event_seq,
            key_id=data.get("key_id"),
            idempotency_key=data.get("idempotency_key"))
        return jsonify({**view, "replayed": not created}), 200

    @app.post("/audit/subscriptions/process")
    def subscription_process():
        # 管理/演练入口：先扫描入队再投递到点通知
        enqueued = subscriptions.scan_and_enqueue()
        delivered = subscriptions.process_due()
        return jsonify({"enqueued": enqueued, "delivered": delivered})

    # ------------------------------------------------------------------
    # 审计通知多端投递
    #
    # 一条通知同时投递给多个独立接收端，创建时冻结送达策略快照（接收端
    # 集合、所需成功数、策略版本），之后修改策略只影响新通知。完成判定
    # 只认冻结快照：all 全部成功 / any 任一成功 / quorum 达到指定人数；
    # 仍可能成功的接收端数低于所需成功数时整条通知明确失败并冻结参与
    # 判定的接收端状态。回执按 (通知, 接收端, 幂等键) 幂等，失败可按
    # 每个接收端自己的上限重试。只写 audit_fanout_* 自有表。
    # ------------------------------------------------------------------
    @app.post("/audit/fanout/policies")
    def fanout_policy_create():
        # 创建送达策略：每次创建产生新的递增版本（修改策略 = 新版本）
        data = body()
        view = fanout.create_policy(
            mode=data.get("mode"),
            quorum_count=data.get("quorum_count"),
        )
        return jsonify(view), 201

    @app.get("/audit/fanout/policies")
    def fanout_policy_list():
        return jsonify(fanout.list_policies(
            limit=request.args.get("limit", 100)))

    @app.get("/audit/fanout/policies/current")
    def fanout_policy_current():
        return jsonify(fanout.current_policy())

    @app.get("/audit/fanout/policies/<int:version>")
    def fanout_policy_get(version):
        return jsonify(fanout.get_policy(version))

    @app.post("/audit/fanout/notifications")
    def fanout_notification_create():
        # 创建通知并冻结策略快照：{payload, policy_version?（缺省当前策略）,
        # recipients:[{recipient_id, max_attempts?} | "<rid>"] 或
        # seats:[{seat_id?, switch_after_ms,
        #         candidates:[{recipient_id, max_attempts?} | "<rid>", ...]}]}
        # （二选一；席位冻结有序候选与切换期限）
        data = body()
        view = fanout.create_notification(
            payload=data.get("payload"),
            recipients=data.get("recipients"),
            seats=data.get("seats"),
            policy_version=data.get("policy_version"),
        )
        return jsonify(view), 201

    @app.get("/audit/fanout/notifications")
    def fanout_notification_list():
        return jsonify(fanout.list_notifications(
            status=request.args.get("status"),
            limit=request.args.get("limit", 100)))

    @app.get("/audit/fanout/notifications/<notification_id>")
    def fanout_notification_get(notification_id):
        # 送达状态：冻结快照、每个接收端尝试次数/最后结果/暂停标记、
        # 离完成还差多少、终态判定快照
        return jsonify(fanout.get_notification(notification_id))

    @app.get("/audit/fanout/notifications/<notification_id>/attempts")
    def fanout_attempts_all(notification_id):
        # 整条通知的尝试记录（全局顺序）
        return jsonify(fanout.list_attempts(
            notification_id, limit=request.args.get("limit", 1000)))

    @app.get("/audit/fanout/notifications/<notification_id>/recipients/<recipient_id>/attempts")
    def fanout_attempts_recipient(notification_id, recipient_id):
        # 单接收端尝试记录（按第几次尝试排序）
        return jsonify(fanout.list_attempts(
            notification_id, recipient_id,
            limit=request.args.get("limit", 1000)))

    @app.post("/audit/fanout/notifications/<notification_id>/receipts")
    def fanout_receipt(notification_id):
        # 成功回执 {recipient_id, idempotency_key, content?}：
        # 同键同内容 → 200 回放首次结果；同键不同内容 → 409；
        # 通知已终态 → 409（迟到回执不能翻案）
        data = body()
        view, created = fanout.submit_receipt(
            notification_id,
            recipient_id=data.get("recipient_id"),
            idempotency_key=data.get("idempotency_key"),
            content=data.get("content"),
        )
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.post("/audit/fanout/notifications/<notification_id>/recipients/<recipient_id>/failures")
    def fanout_failure(notification_id, recipient_id):
        # 失败重试 {detail?}：记一次失败尝试，达到该接收端自己的
        # max_attempts 进入终止态；策略不再可能满足时整条通知明确失败
        data = body()
        return jsonify(fanout.record_failure(
            notification_id, recipient_id, detail=data.get("detail")))

    @app.post("/audit/fanout/notifications/<notification_id>/recipients/<recipient_id>/pause")
    def fanout_pause(notification_id, recipient_id):
        # 暂停接收端（幂等）：拒收新回执/失败上报；不改状态与计数，
        # 暂停已成功的接收端改变不了既有完成结论
        return jsonify(fanout.pause_recipient(notification_id, recipient_id))

    @app.post("/audit/fanout/notifications/<notification_id>/recipients/<recipient_id>/resume")
    def fanout_resume(notification_id, recipient_id):
        # 恢复接收端（幂等）
        return jsonify(fanout.resume_recipient(notification_id, recipient_id))

    # -- 投递席位：有序备用接收端 + 切换期限 -------------------------------
    @app.post("/audit/fanout/notifications/process-deadlines")
    def fanout_process_deadlines():
        # 管理/演练入口：结算全部到期的切换期限（超时启用下一位备用）。
        # 后台 worker 与各席位接口的惰性结算走同一路径，结果一致
        return jsonify(fanout.process_due_seats())

    @app.get("/audit/fanout/notifications/<notification_id>/seats")
    def fanout_seat_list(notification_id):
        # 全部席位：当前由谁处理、下一位备用、切换期限、最近切换原因
        return jsonify(fanout.list_seats(notification_id))

    @app.get("/audit/fanout/notifications/<notification_id>/seats/<seat_id>")
    def fanout_seat_get(notification_id, seat_id):
        # 单席位状态：当前候选/下一位备用/期限/全部候选状态
        return jsonify(fanout.get_seat(notification_id, seat_id))

    @app.get("/audit/fanout/notifications/<notification_id>/seats/<seat_id>/history")
    def fanout_seat_history(notification_id, seat_id):
        # 席位完整历史：启用/替换（含原因）/回执受理与拒绝/失败/席位成败
        return jsonify(fanout.seat_history(
            notification_id, seat_id,
            limit=request.args.get("limit", 200)))

    @app.post("/audit/fanout/notifications/<notification_id>/seats/<seat_id>/switch")
    def fanout_seat_switch(notification_id, seat_id):
        # 手动放弃当前接收端，按顺序启用下一位备用：
        # {reason?, expected_recipient_id?, idempotency_key?}
        # 同幂等键重放 200；席位已成功/已终止/通知已终态 409（带胜负信息）；
        # expected_recipient_id 与当前接收端不符 409（他人已先切换）
        data = body()
        view, created = fanout.switch_seat(
            notification_id, seat_id,
            reason=data.get("reason"),
            expected_recipient_id=data.get("expected_recipient_id"),
            idempotency_key=data.get("idempotency_key"))
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    # ------------------------------------------------------------------
    # 审计事件窗口批次聚合
    #
    # 管理员按事件类型配置固定窗口时长/分组字段/允许迟到时长/通知接收端
    # （规则版本化，切换只影响之后创建的批次）。系统从每来源独立的稳定
    # 序号持续读取事件，同分组+同窗口+同规则版本归入同一批次；批次持续
    # 暴露事件数量、序号范围、时间范围与内容摘要。仅当
    # window_end + allowed_lateness <= source.watermark 时封存，封存冻结
    # 成员/摘要/sha256 并在同事务创建唯一一条多接收端通知。成员表全局
    # 唯一归属保证并发/重复扫描不会让事件进两个批次。迟到事件三选一
    # 处理且绝不改写原批次。只写 audit_batch_* 自有表。
    # ------------------------------------------------------------------
    def _fail_delivery() -> bool:
        # 演练故障：让本次触发的通知发送失败（封存仍成功，可事后重试）
        return request.headers.get("X-Fail-Delivery", "").lower() in (
            "1", "true", "yes")

    # -- 聚合规则 ---------------------------------------------------------
    @app.post("/audit/batch/rules")
    def batch_rule_create():
        data = body()
        view, created = batching.configure_rule(
            require(data, "event_type"),
            window_ms=require(data, "window_ms"),
            group_field=require(data, "group_field"),
            allowed_lateness_ms=require(data, "allowed_lateness_ms"),
            recipients=require(data, "recipients"),
            effective_at_ms=data.get("effective_at_ms"),
            idempotency_key=data.get("idempotency_key"),
        )
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/batch/rules")
    def batch_rule_list():
        return jsonify(batching.list_rules(request.args.get("event_type")))

    @app.get("/audit/batch/rules/<rule_id>")
    def batch_rule_get(rule_id):
        return jsonify(batching.get_rule(rule_id))

    # -- 来源与 watermark -------------------------------------------------
    @app.post("/audit/batch/sources")
    def batch_source_create():
        data = body()
        view, created = batching.create_source(
            require(data, "source_id"),
            initial_watermark_ms=data.get("initial_watermark_ms"),
        )
        return jsonify({**view, "replayed": not created}), \
            201 if created else 200

    @app.get("/audit/batch/sources")
    def batch_source_list():
        return jsonify(batching.list_sources())

    @app.get("/audit/batch/sources/<source_id>")
    def batch_source_get(source_id):
        return jsonify(batching.get_source(source_id))

    @app.post("/audit/batch/sources/<source_id>/watermark")
    def batch_watermark(source_id):
        # watermark 只进不退；回退 409 且不改变任何状态。推进后尝试封存
        data = body()
        return jsonify(batching.advance_watermark(
            source_id, require(data, "watermark_ms"),
            seq=data.get("seq"), fail_delivery=_fail_delivery()))

    # -- 事件读取与查询 ---------------------------------------------------
    @app.post("/audit/batch/sources/<source_id>/events/scan")
    def batch_events_scan(source_id):
        # 从稳定序号持续读取；重复扫描同段历史返回 duplicates 而不重复归批
        data = body()
        return jsonify(batching.ingest_events(
            source_id, require(data, "events"),
            fail_delivery=_fail_delivery()))

    @app.get("/audit/batch/sources/<source_id>/events")
    def batch_events_list(source_id):
        return jsonify(batching.list_events(
            source_id,
            from_seq=request.args.get("from_seq"),
            to_seq=request.args.get("to_seq"),
            limit=request.args.get("limit", 1000)))

    # -- 批次与成员 -------------------------------------------------------
    @app.get("/audit/batch/batches")
    def batch_list():
        return jsonify(batching.list_batches(
            source_id=request.args.get("source_id"),
            event_type=request.args.get("event_type"),
            group_key=request.args.get("group_key"),
            status=request.args.get("status"),
            batch_type=request.args.get("batch_type"),
            limit=request.args.get("limit", 200)))

    @app.get("/audit/batch/batches/<batch_id>")
    def batch_get(batch_id):
        return jsonify(batching.get_batch(batch_id))

    @app.get("/audit/batch/batches/<batch_id>/members")
    def batch_members(batch_id):
        return jsonify(batching.list_members(batch_id))

    @app.post("/audit/batch/batches/<batch_id>/verify")
    def batch_verify(batch_id):
        # 独立重算成员/摘要/校验值；被篡改返回 409 batch_verify_failed
        return jsonify(batching.verify_batch(batch_id))

    @app.post("/audit/batch/batches/<batch_id>/checksum")
    def batch_recompute(batch_id):
        # 只重算返回，不改写冻结值（open 批次也可查看当前值）
        return jsonify(batching.recompute_checksum(batch_id))

    # -- 迟到区 -----------------------------------------------------------
    @app.get("/audit/batch/late-events")
    def batch_late_list():
        return jsonify(batching.list_late_events(
            source_id=request.args.get("source_id"),
            status=request.args.get("status"),
            limit=request.args.get("limit", 200)))

    @app.post("/audit/batch/late-events/handle")
    def batch_late_handle():
        # retain 保留隔离 / forward 放入下一未封存窗口 / supplement
        # 只含迟到事件的补充批次（任何处理都不改写原批次）
        data = body()
        return jsonify(batching.handle_late_event(
            require(data, "source_id"), require(data, "event_id"),
            require(data, "action"), note=data.get("note"),
            fail_delivery=_fail_delivery()))

    # -- 关联通知 ---------------------------------------------------------
    @app.get("/audit/batch/notifications")
    def batch_notification_list():
        return jsonify(batching.list_notifications(
            status=request.args.get("status"),
            source_id=request.args.get("source_id"),
            batch_id=request.args.get("batch_id"),
            limit=request.args.get("limit", 200)))

    @app.get("/audit/batch/notifications/<notification_id>")
    def batch_notification_get(notification_id):
        return jsonify(batching.get_notification(notification_id))

    @app.post("/audit/batch/notifications/<notification_id>/retry")
    def batch_notification_retry(notification_id):
        # 通知发送失败恢复：复用同一条通知，绝不创建第二条
        return jsonify(batching.retry_notification(
            notification_id, fail_delivery=_fail_delivery()))

    @app.post("/audit/batch/process")
    def batch_process():
        # 管理/演练入口：封存所有来源到点批次并投递待发通知
        return jsonify(batching.process(fail_delivery=_fail_delivery()))

    @app.post("/audit/batch/recover")
    def batch_recover():
        # 服务重启/手工恢复：续跑未封存窗口、复位在途通知并重投
        return jsonify(batching.recover_interrupted())

    # -- 调试：直接篡改事件载荷以演示校验值可发现 -------------------------
    @app.post("/debug/batch/events/<event_id>/tamper")
    def debug_batch_tamper(event_id):
        data = body()
        return jsonify(batching.debug_tamper_event(
            event_id, data.get("payload", {"tampered": True})))

    # ------------------------------------------------------------------
    # 调试：手动驱动两种时钟，演练"拨表/逻辑卡死"故障
    # ------------------------------------------------------------------
    @app.post("/debug/tick")
    def debug_tick():
        steps = int(body().get("steps", 1))
        return jsonify({"logical": store.tick(steps)})

    @app.post("/debug/wall-shift")
    def debug_wall_shift():
        delta_ms = int(require(body(), "delta_ms"))
        return jsonify({"wall_ms": store.shift_wall(delta_ms)})

    @app.get("/debug/now")
    def debug_now():
        return jsonify(
            {
                "wall_ms": store.clock.wall_ms(),
                "logical": store.clock.logical(),
            }
        )

    @app.before_request
    def _guard_debug():
        if request.path.startswith("/debug") and not enable_debug_api:
            return jsonify({"error": "debug_api_disabled"}), 403
        return None

    # ------------------------------------------------------------------
    # 错误处理
    # ------------------------------------------------------------------
    @app.errorhandler(AuditBadRequest)
    @app.errorhandler(NoEventsInRange)
    @app.errorhandler(HistoryNotFound)
    @app.errorhandler(AuditCredentialNotFound)
    @app.errorhandler(NodeOutOfRange)
    def _audit_error(exc: AuditError):
        # 回放/诊断的参数与范围错误一律给出明确的结构化错误，
        # 绝不降级成 200 + 空报告
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(ArchiveNotFound)
    @app.errorhandler(ArchiveNotReady)
    @app.errorhandler(ArchiveConflict)
    @app.errorhandler(ArchiveBadState)
    def _archive_error(exc: ArchiveError):
        # 归档的显式错误：不存在 404 / 未完成 409 / 幂等键冲突 409 /
        # 状态不允许 409
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(EvidenceNotFound)
    @app.errorhandler(EvidenceSourceNotFound)
    @app.errorhandler(EvidenceNotReady)
    @app.errorhandler(EvidenceSourceNotReady)
    @app.errorhandler(EvidenceIdConflict)
    @app.errorhandler(EvidenceManifestConflict)
    @app.errorhandler(EvidenceBadState)
    def _evidence_error(exc: EvidenceError):
        # 证据包显式错误：不存在/源归档不存在 404、未完成/源归档未完成 409、
        # 幂等键/清单冲突 409、状态不允许 409
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(CausalNotFound)
    @app.errorhandler(CausalSourceNotFound)
    @app.errorhandler(CausalNotReady)
    @app.errorhandler(CausalIdConflict)
    @app.errorhandler(CausalBadState)
    def _causal_error(exc):
        # 因果索引显式错误：索引/证据包源不存在 404、未完成 409、
        # 同键换范围/节点/过滤冲突 409、状态不允许 409
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(DerivationNotFound)
    @app.errorhandler(DerivationBaselineNotFound)
    @app.errorhandler(DerivationNotReady)
    @app.errorhandler(DerivationBaselineNotReady)
    @app.errorhandler(DerivationIdConflict)
    @app.errorhandler(DerivationSpecConflict)
    @app.errorhandler(DerivationBadState)
    @app.errorhandler(DerivationSourceChanged)
    def _derivation_error(exc):
        # 增量派生显式错误：派生/基线不存在 404、未完成 409、幂等/规格冲突
        # 409、暂停/恢复/重试状态不允许 409、新增节点的源被篡改 409
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(ReleaseNotFound)
    @app.errorhandler(ReleaseNotReady)
    @app.errorhandler(ReleaseCancelled)
    @app.errorhandler(ReleaseFailedPlan)
    @app.errorhandler(ReleaseIdConflict)
    @app.errorhandler(ReleaseVersionConflict)
    @app.errorhandler(ReleaseBadState)
    @app.errorhandler(ReleaseIndexDeleted)
    @app.errorhandler(ReleaseIndexNotCompleted)
    @app.errorhandler(ReleaseIndexTampered)
    @app.errorhandler(ReleaseCompareTargetNotReady)
    @app.errorhandler(ReleaseComparisonChanged)
    def _release_error(exc):
        # 版本发布显式错误：计划/版本不存在 404、未生效/已取消/已失败 409、
        # 幂等键/版本号冲突 409、状态不允许 409、原索引删除/未完成/被篡改
        # 409、比较对象未完成/比较结果漂移 409
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(InvalidSignature)
    def _invalid_signature(exc):
        # 401：确认签名校验失败，不改变任何状态
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(SubscriptionNotFound)
    @app.errorhandler(DeliveryNotFound)
    @app.errorhandler(SubscriptionIdConflict)
    @app.errorhandler(SubscriptionBadState)
    @app.errorhandler(DeliveryBadState)
    @app.errorhandler(SubscriptionRangeError)
    @app.errorhandler(SubscriptionVersionNotFound)
    @app.errorhandler(SubscriptionVersionConflict)
    @app.errorhandler(SubscriptionVersionBadState)
    @app.errorhandler(SubscriptionVersionRangeError)
    def _subscription_error(exc):
        # 订阅显式错误：订阅/投递/版本不存在 404、幂等冲突/状态前提 409、
        # 起始/生效序号越过稳定视图上界 416
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(KeyRotationNotFound)
    @app.errorhandler(KeyVerificationNotFound)
    @app.errorhandler(KeyRotationIdConflict)
    @app.errorhandler(KeyRotationConflict)
    @app.errorhandler(KeyRotationBadState)
    @app.errorhandler(KeyRotationRangeError)
    def _key_rotation_error(exc):
        # 签名密钥轮换显式错误：密钥/验证不存在 404、幂等冲突/跨命名空间
        # 409、状态前提 409、生效序号越过稳定历史 416
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(FanoutError)
    def _fanout_error(exc):
        # 多端投递显式错误（基类注册，子类按 MRO 命中）：策略/通知/接收端
        # 不存在 404、无当前策略 409、幂等键冲突 409、通知已终态（迟到
        # 回执/迟到失败上报）409、接收端暂停/终止/已成功 409
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(BatchSourceNotFound)
    @app.errorhandler(BatchNotFound)
    @app.errorhandler(BatchRuleNotFound)
    @app.errorhandler(BatchBadState)
    @app.errorhandler(BatchConflict)
    @app.errorhandler(BatchVerifyFailed)
    def _batch_error(exc: BatchError):
        # 批次聚合显式错误：来源/批次不存在 404、无生效规则/状态前提 409、
        # watermark 回退/序号冲突/幂等冲突 409、篡改核验失败 409；
        # 其余参数错误（BatchError 基类）400
        return jsonify(exc.to_response()), exc.status

    @app.errorhandler(GenerationTooSmall)
    def _gen_conflict(exc):
        return jsonify({"error": "generation_fence", "message": str(exc)}), 409

    @app.errorhandler(DelegationRejected)
    def _delegation_rejected(exc):
        # 409：凭证已撤销/过期/随租约失效，或协作者不符
        return jsonify({"error": "delegation_rejected",
                        "message": str(exc)}), 409

    @app.errorhandler(DelegationNotFound)
    def _delegation_not_found(exc):
        return jsonify({"error": "not_found", "message": str(exc)}), 404

    @app.errorhandler(LeaseGone)
    def _gone(exc):
        # 412：前提（存在生效租约）不满足
        return jsonify({"error": "no_active_lease", "message": str(exc)}), 412

    @app.errorhandler(Conflict)
    def _conflict(exc):
        return jsonify({"error": "conflict", "message": str(exc)}), 409

    @app.errorhandler(404)
    def _not_found(exc):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(Exception)
    def _internal(exc):
        if isinstance(exc, (ValueError, TypeError)):
            return jsonify({"error": "bad_request", "message": str(exc)}), 400
        raise exc

    # ------------------------------------------------------------------
    # 后台逻辑钟：每秒 +1 并顺带收割双时钟一致认定过期的租约
    # ------------------------------------------------------------------
    def _run_ticker():
        while not stop_event.wait(tick_interval):
            try:
                store.tick(1)
            except Exception:  # noqa: BLE001 - 后台线程不能因单次异常退出
                app.logger.exception("逻辑钟 tick 失败")

    if start_ticker:
        t = threading.Thread(target=_run_ticker, name="logical-ticker", daemon=True)
        t.start()

    # ------------------------------------------------------------------
    # 后台归档/证据包生成：分块冻结、进度落库；启动即续跑未完成的任务，
    # 进程重启或上次后台失败都能从已保存的进度继续
    # ------------------------------------------------------------------
    archive_interval = float(os.environ.get("ARCHIVE_WORKER_INTERVAL_S", "0.2"))

    def _run_archive_worker():
        while not stop_event.wait(archive_interval):
            try:
                archive.process_pending()
            except Exception:  # noqa: BLE001 - 后台线程不能因单次异常退出
                app.logger.exception("归档后台处理失败")
            try:
                evidence.process_pending()
            except Exception:  # noqa: BLE001
                app.logger.exception("证据包后台处理失败")
            try:
                causal.process_pending()
            except Exception:  # noqa: BLE001
                app.logger.exception("因果索引后台处理失败")
            try:
                derivation.process_pending()
            except Exception:  # noqa: BLE001
                app.logger.exception("增量派生后台处理失败")
            try:
                releases.process_due()  # 到点发布计划（延迟生效）
            except Exception:  # noqa: BLE001
                app.logger.exception("索引版本发布后台处理失败")
            try:
                # 订阅：先把新历史事件入队，再投递到点通知
                # （回调在数据库事务之外执行，失败退避/死信均落库）
                key_rotation.recover_interruptions()  # 宽限到期退役旧密钥
                subscriptions.scan_and_enqueue()
                subscriptions.process_due()
            except Exception:  # noqa: BLE001
                app.logger.exception("审计订阅后台处理失败")
            try:
                # 投递席位：结算到期的切换期限，按顺序启用下一位备用
                fanout.process_due_seats()
            except Exception:  # noqa: BLE001
                app.logger.exception("席位切换期限后台结算失败")
            try:
                # 窗口批次：封存到点批次并发送发件箱待发通知
                batching.process()
            except Exception:  # noqa: BLE001
                app.logger.exception("窗口批次后台处理失败")

    if start_archive_worker:
        archive.process_pending()  # 启动即续跑重启前未完成的归档
        evidence.process_pending()  # 同步续跑未完成的证据包
        causal.process_pending()  # 同步续跑未完成的因果索引
        derivation.process_pending()  # 同步续跑未完成的增量派生
        releases.process_due()  # 中断恢复：错过生效时间的计划立即发布
        try:
            key_rotation.recover_interruptions()  # 重启即收敛宽限到期密钥
            subscriptions.scan_and_enqueue()
            subscriptions.process_due()
        except Exception:  # noqa: BLE001
            app.logger.exception("审计订阅启动恢复失败")
        try:
            fanout.process_due_seats()  # 重启即按原期限结算错过的切换
        except Exception:  # noqa: BLE001
            app.logger.exception("席位切换期限启动结算失败")
        try:
            # 重启后续跑：封存已到点的未封存窗口，重投中断的批次通知
            batching.recover_interrupted()
        except Exception:  # noqa: BLE001
            app.logger.exception("窗口批次启动恢复失败")
        t = threading.Thread(target=_run_archive_worker,
                             name="archive-worker", daemon=True)
        t.start()

    def _stop(*_):
        stop_event.set()

    import atexit

    atexit.register(_stop)
    return app
