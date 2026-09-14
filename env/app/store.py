"""SQLite 持久化层：租约、世代号、资源、写入审计、系统元数据。

所有会改变状态的操作都在一把进程内互斥锁 + 单连接事务中完成，
SQLite 开 WAL，保证重启后正在生效的租约和世代号都不丢。

租约过期判定（双时钟，两个条件同时满足才算活）：

1. wall_ms < hard_wall_deadline_ms
   —— 硬墙钟上限。发放后固定，续约不能越过。
      即使逻辑钟彻底卡死（永远不 tick），租约到时也必死，
      不会出现"租约永不结束"。

2. wall_ms < wall_deadline_ms 或 逻辑钟宽限仍有效
   —— 软墙钟 TTL。墙钟被拨快只会越过软 deadline；
      只要逻辑钟在 (logical_grace + 续约时刻的逻辑钟) 之内
      仍在推进，就证明持有者还在干活，不能误回收。
      逻辑钟宽限是否有效 = 当前逻辑钟 <= last_seen_logical + grace。
"""

from __future__ import annotations

import threading
import uuid
from typing import Any

from .clock import Clock

STATE_ACTIVE = "active"
STATE_EXPIRED = "expired"
STATE_RELEASED = "released"
STATE_TRANSFERRED = "transferred"   # 已转移：旧持有者即刻失去一切权限

# 委托终态
DEL_STATE_ACTIVE = "active"
DEL_STATE_REVOKED = "revoked"       # 授权者提前撤销
DEL_STATE_EXPIRED = "expired"       # 到达委托自身的墙钟到期
DEL_STATE_FENCED = "fenced"         # 原租约释放/转移/过期：委托连带失效

# 委托被栅栏掉的原因（delegations.end_reason，state=fenced 时）
FENCE_LEASE_RELEASED = "source_lease_released"
FENCE_LEASE_TRANSFERRED = "source_lease_transferred"
FENCE_LEASE_EXPIRED = "source_lease_expired"
# state=expired / revoked 时的 end_reason
END_DELEGATION_EXPIRED = "delegation_expired"
END_DELEGATION_REVOKED = "revoked"

# 委托写入被拒原因（同时写入 writes.reject_reason 与历史 detail）
REJECT_DELEGATION_REVOKED = "delegation_revoked"
REJECT_DELEGATION_EXPIRED = "delegation_expired"
REJECT_COLLABORATOR_MISMATCH = "collaborator_mismatch"
REJECT_UNKNOWN_CREDENTIAL = "unknown_credential"

# 过期原因（state=expired 时）
REASON_HARD_WALL = "hard_wall_deadline_reached"       # 逻辑钟卡死也救不了：到硬上限
REASON_SOFT_WALL_AND_LOGICAL_STALL = "wall_ttl_passed_and_logical_stalled"  # 双重沉默

MIN_TTL_MS = 50                 # 客户端可请求的最小 TTL，避免 0 导致立即死
DEFAULT_TTL_MS = 15_000
DEFAULT_MAX_TTL_MS = 60_000
DEFAULT_HARD_TTL_MS = 60_000    # 硬上限相对发放时刻；必须大于环境中最大时钟跳变
DEFAULT_LOGICAL_GRACE = 3       # 续约后逻辑钟最多容忍落后多少 tick
DEFAULT_DELEGATION_TTL_MS = 15_000
DEFAULT_DELEGATION_MAX_TTL_MS = 60_000


class Conflict(Exception):
    """世代号栅栏冲突或状态前提不满足（映射为 HTTP 409/412）。"""


class LeaseGone(Conflict):
    """资源上不存在可操作的生效租约（HTTP 412）。"""


class GenerationTooSmall(Conflict):
    """写入携带的世代号 <= 资源已放行的最大世代号（HTTP 409）。"""


class DelegationRejected(Conflict):
    """委托凭证写入被拒绝：已撤销/已过期/原租约已结束/协作者不符（HTTP 409）。"""


class DelegationNotFound(LookupError):
    """委托凭证不存在或不属于该资源（HTTP 404）。"""


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    id                     TEXT PRIMARY KEY,
    resource               TEXT NOT NULL,
    holder                 TEXT NOT NULL,
    generation             INTEGER NOT NULL,
    granted_wall_ms        INTEGER NOT NULL,
    wall_deadline_ms       INTEGER NOT NULL,
    hard_wall_deadline_ms  INTEGER NOT NULL,
    logical_grace          INTEGER NOT NULL,
    last_seen_logical      INTEGER NOT NULL,
    renewed_count          INTEGER NOT NULL DEFAULT 0,
    state                  TEXT NOT NULL DEFAULT 'active',
    expire_reason          TEXT,
    created_at_ms          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resources (
    resource        TEXT PRIMARY KEY,
    current_gen     INTEGER NOT NULL,           -- 单调递增，世代号源头
    last_passed_gen INTEGER NOT NULL DEFAULT 0, -- 已放行写入的最大世代号（栅栏）
    value           TEXT,
    updated_by_gen  INTEGER,
    updated_at_ms   INTEGER
);
CREATE TABLE IF NOT EXISTS writes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    resource           TEXT NOT NULL,
    generation         INTEGER NOT NULL,        -- 是哪一代租约放行的
    lease_id           TEXT NOT NULL,
    holder             TEXT NOT NULL,
    accepted           INTEGER NOT NULL,        -- 1 放行 / 0 拒绝
    reject_reason      TEXT,
    created_at_ms      INTEGER NOT NULL,
    credential_id      TEXT                     -- 仅委托写入：用的哪张凭证
);
CREATE INDEX IF NOT EXISTS idx_writes_resource ON writes(resource, id);
-- 限时委托：当前持有者（授权者）针对某个资源向指定协作者发放的短期凭证。
-- 委托只授予"写"这一个动作：不能续约、释放、转移或再次转委托（这些入口
-- 只认生效租约的 holder+generation，协作者天然进不来）。
-- 委托的世代号栅栏锚定在授权租约上：lease_id 一旦不再是当前生效租约
-- （释放/转移/过期），本委托即被连带置为 fenced，迟到写入必拒。
CREATE TABLE IF NOT EXISTS delegations (
    credential_id     TEXT PRIMARY KEY,
    resource          TEXT NOT NULL,
    lease_id          TEXT NOT NULL,           -- 发放时绑定的授权者租约
    authorizer        TEXT NOT NULL,           -- 授权者（= 租约持有者）
    collaborator      TEXT NOT NULL,           -- 被授权的协作者
    generation        INTEGER NOT NULL,        -- 发放时授权租约的世代号
    granted_wall_ms   INTEGER NOT NULL,
    expires_wall_ms   INTEGER NOT NULL,        -- 硬墙钟到期：只信墙钟，不可续
    state             TEXT NOT NULL DEFAULT 'active',
    end_reason        TEXT,                    -- revoked/expired/fenced 细分原因
    created_at_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delegations_lease ON delegations(lease_id);
CREATE INDEX IF NOT EXISTS idx_delegations_resource ON delegations(resource, credential_id);
-- 转移记录：transfer_id 是幂等键，重复提交同一笔转移直接回放首次结果
CREATE TABLE IF NOT EXISTS transfers (
    transfer_id     TEXT PRIMARY KEY,
    resource        TEXT NOT NULL,
    from_holder     TEXT NOT NULL,
    to_holder       TEXT NOT NULL,
    from_lease_id   TEXT NOT NULL,
    from_generation INTEGER NOT NULL,
    new_lease_id    TEXT NOT NULL,
    new_generation  INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL
);
-- 统一租约历史：每次获取/续约/释放/转移/写入（含被拒绝的）以及委托的
-- 发放/使用/撤销/过期/连带失效（含被拒绝的）都留一条，
-- seq 全局单调递增即审计顺序，落库后重启不丢。
-- lease_id 记录操作发生时生效的租约（被拒绝的操作也一样），
-- 仅当当时没有生效租约时才为 NULL；generation 是请求携带的世代号。
-- credential_id 非空即说明该事件属于某张委托凭证，可按凭证过滤出
-- 授权者/协作者/有效期/世代号与每次使用结果。
CREATE TABLE IF NOT EXISTS lease_events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    resource      TEXT NOT NULL,
    event         TEXT NOT NULL,        -- acquire/renew/release/transfer/write/
                                        -- delegate/delegate_write/delegate_revoke
    outcome       TEXT NOT NULL,        -- ok / rejected
    holder        TEXT NOT NULL,        -- 操作发起者
    peer          TEXT,                 -- 另一方：transfer 接收者 / delegate 协作者 / ...
    lease_id      TEXT,
    generation    INTEGER,
    to_lease_id   TEXT,                 -- 仅 transfer：产生的新租约
    to_generation INTEGER,
    credential_id TEXT,                 -- 委托事件：涉及的凭证
    detail        TEXT,                 -- 拒绝原因 / write_id 等补充
    value         TEXT,                 -- 仅被接受的写入事件：当时落下去的资源值（审计回放用）
    wall_ms       INTEGER NOT NULL,
    logical       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_resource ON lease_events(resource, seq);
-- idx_events_credential 与新列一起在 _migrate_columns 中创建，
-- 以兼容没有 credential_id 列的旧库
-- 可验证审计归档：把某个资源/委托凭证在某个稳定历史节点上的事件范围、
-- 回放状态、诊断结果与内容校验值冻结成一份只读归档。
-- 归档只写本表与 archive_events，绝不触碰租约/委托/原始审计历史。
-- (scope, resource, credential_id, idempotency_key) 唯一：同一对象、同一
-- 幂等键重复创建只会得到同一份归档；同键配不同节点在代码里判 409。
CREATE TABLE IF NOT EXISTS archives (
    archive_id        TEXT PRIMARY KEY,
    scope             TEXT NOT NULL,            -- resource / credential
    resource          TEXT NOT NULL,
    credential_id     TEXT NOT NULL DEFAULT '', -- 资源作用域为空串
    node_seq          INTEGER NOT NULL,         -- 固定的历史节点（事件上界）
    snapshot_seq      INTEGER NOT NULL,         -- 创建时的稳定视图上界
    idempotency_key   TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending',
                      -- pending / building / completed / failed
    total_events      INTEGER NOT NULL DEFAULT 0,
    processed_events  INTEGER NOT NULL DEFAULT 0,
    last_frozen_seq   INTEGER NOT NULL DEFAULT 0, -- 续跑游标：已冻结到哪个 seq
    attempts          INTEGER NOT NULL DEFAULT 0,
    error             TEXT,
    content           TEXT,                     -- 冻结的归档文档（JSON）
    content_sha256    TEXT,                     -- 内容校验值
    verify_status     TEXT NOT NULL DEFAULT 'unverified',
                      -- unverified / verified / verify_failed
    verify_detail     TEXT,                     -- JSON：核验失败的首个差异位置
    verified_at_ms    INTEGER,
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL,
    completed_at_ms   INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_archives_idem
    ON archives(scope, resource, credential_id, idempotency_key);
-- 归档冻结的事件副本：主键 (archive_id, seq) + INSERT OR IGNORE，
-- 后台失败重试/重启续跑都不会重复写入或写出矛盾内容
CREATE TABLE IF NOT EXISTS archive_events (
    archive_id TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    payload    TEXT NOT NULL,                   -- event_dict 的规范化 JSON
    PRIMARY KEY (archive_id, seq)
);
-- 审计证据包：把多份**已完成**的资源归档/委托凭证归档按给定组合顺序冻结成
-- 一份只读证据包。创建时即冻结清单（evidence_entries：顺序、每份归档的
-- 内容校验值、收录方式）与生成元数据；证据包操作只写本表与
-- evidence_entries / evidence_entry_contents，绝不修改租约、委托、原始
-- 审计历史，甚至不写源归档行（源归档对证据包只读）。
-- idempotency_key 全局唯一：同键不同清单 -> 409；
-- manifest_fingerprint 全局唯一：同清单（同归档、同顺序、同收录方式）不同
-- 键 -> 409。系统里绝不会出现两份互相矛盾或重复的证据包。
CREATE TABLE IF NOT EXISTS evidence_packages (
    package_id             TEXT PRIMARY KEY,
    idempotency_key        TEXT NOT NULL,
    manifest_fingerprint   TEXT NOT NULL,       -- 对有序归档清单（id+收录方式）的 SHA-256
    status                 TEXT NOT NULL DEFAULT 'pending',
                           -- pending / building / completed / failed
    total_entries          INTEGER NOT NULL DEFAULT 0,
    processed_entries      INTEGER NOT NULL DEFAULT 0,
    last_frozen_position   INTEGER NOT NULL DEFAULT -1, -- 续跑游标：已冻结到的清单位置
    attempts               INTEGER NOT NULL DEFAULT 0,
    error                  TEXT,
    error_detail           TEXT,                -- JSON：失败的首个归档标识/字段/双方值
    metadata_json          TEXT,                -- 创建时冻结的元数据（规范化 JSON）
    snapshot_seq           INTEGER NOT NULL,     -- 创建时的稳定视图上界
    created_logical        INTEGER NOT NULL,     -- 创建时逻辑钟读数（生成元数据）
    content                TEXT,                -- 冻结的证据包文档（JSON）
    content_sha256         TEXT,                -- 总校验值
    combination_digest     TEXT,                -- 组合摘要（顺序敏感的链式哈希）
    verify_status          TEXT NOT NULL DEFAULT 'unverified',
                           -- unverified / verified / verify_failed
    verify_detail          TEXT,                -- JSON：核验失败的首个差异位置
    verified_at_ms         INTEGER,
    created_at_ms          INTEGER NOT NULL,
    updated_at_ms          INTEGER NOT NULL,
    completed_at_ms        INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_idem
    ON evidence_packages(idempotency_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_manifest
    ON evidence_packages(manifest_fingerprint);
-- 冻结的清单：证据包创建时一次性写入（顺序 + 每份归档的内容校验值 + 收录
-- 方式），之后只读；源归档之后被再次核验或产生新归档都改不动它。
CREATE TABLE IF NOT EXISTS evidence_entries (
    package_id        TEXT NOT NULL,
    position          INTEGER NOT NULL,         -- 0 起的组合顺序
    archive_id        TEXT NOT NULL,
    include_mode      TEXT NOT NULL,            -- content（原文）/ reference（稳定引用）
    source_sha256     TEXT NOT NULL,            -- 创建时钉死的源归档内容校验值
    status            TEXT NOT NULL DEFAULT 'pending',  -- pending / frozen
    frozen_sha256     TEXT,                     -- 冻结载荷自身的 SHA-256
    PRIMARY KEY (package_id, position)
);
-- 分块冻结的归档载荷：主键 (package_id, position) + INSERT OR IGNORE，
-- 分块处理、服务重启续跑、失败重试都不会重复写入或写出矛盾内容。
CREATE TABLE IF NOT EXISTS evidence_entry_contents (
    package_id TEXT NOT NULL,
    position   INTEGER NOT NULL,
    payload    TEXT NOT NULL,                   -- 收录条目的规范化 JSON（原文或稳定引用）
    PRIMARY KEY (package_id, position)
);
-- 审计因果索引：把一次管理员任务作用域内的租约事件、写入、委托、源归档、
-- 证据包条目组织成一条有向因果链。创建时即冻结 snapshot_seq、查询范围
-- （scope/对象/历史节点）与过滤条件（filters_json），成员集合在同一事务
-- 写入 causal_index_members；之后新增事件、再核验源归档、新增归档/证据包
-- 都进不了已冻结的链。索引只写本表与 causal_index_members /
-- causal_index_nodes 三张自有表，绝不修改租约、委托、原始审计历史、
-- 源归档或证据包。idempotency_key 全局唯一：同键换范围/节点/过滤 → 409。
CREATE TABLE IF NOT EXISTS causal_indexes (
    index_id          TEXT PRIMARY KEY,
    idempotency_key   TEXT NOT NULL,
    scope             TEXT NOT NULL,           -- resource / credential / evidence_package
    resource          TEXT NOT NULL DEFAULT '',
    credential_id     TEXT NOT NULL DEFAULT '',
    package_id        TEXT NOT NULL DEFAULT '',
    node_seq          INTEGER NOT NULL,        -- 冻结的历史节点（证据包作用域=包快照节点）
    snapshot_seq      INTEGER NOT NULL,        -- 创建时的稳定视图上界
    filters_json      TEXT NOT NULL,           -- 创建时冻结的过滤条件（规范化 JSON）
    status            TEXT NOT NULL DEFAULT 'pending',
                        -- pending / building / completed / failed
    total_nodes       INTEGER NOT NULL DEFAULT 0,
    processed_nodes   INTEGER NOT NULL DEFAULT 0,
    last_position     INTEGER NOT NULL DEFAULT -1, -- 续跑游标：已还原到的成员位置
    attempts          INTEGER NOT NULL DEFAULT 0,
    error             TEXT,
    content           TEXT,                    -- 冻结的链文档（JSON）
    content_sha256    TEXT,                    -- 总校验值
    chain_digest      TEXT,                    -- 顺序敏感的链摘要
    verify_status     TEXT NOT NULL DEFAULT 'unverified',
                        -- unverified / verified / verify_failed
    verify_detail     TEXT,                    -- JSON：核验失败的首个差异位置
    verified_at_ms    INTEGER,
    created_logical   INTEGER NOT NULL DEFAULT 0,
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL,
    completed_at_ms   INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_causal_idem
    ON causal_indexes(idempotency_key);
-- 冻结的成员集合：创建时一次性写入（因果顺序 position、节点标识、类型、
-- 对象标识、锚点序号与不可变描述），之后只读；worker 按 position 分块
-- 还原节点载荷。主键 (index_id, position) 保证顺序唯一不重复。
CREATE TABLE IF NOT EXISTS causal_index_members (
    index_id        TEXT NOT NULL,
    position        INTEGER NOT NULL,          -- 0 起的因果顺序
    node_id         TEXT NOT NULL,             -- 稳定节点标识（event:<seq> 等）
    node_type       TEXT NOT NULL,             -- lease_event/write/delegation/...
    object_id       TEXT NOT NULL,             -- 序号 / write_id / 凭证号 / 归档号 ...
    anchor_seq      INTEGER NOT NULL,          -- 锚定的审计序号（同层排序用）
    descriptor_json TEXT NOT NULL,             -- 创建时冻结的不可变成员描述
    PRIMARY KEY (index_id, position)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_causal_member_node
    ON causal_index_members(index_id, node_id);
-- 分块还原的节点载荷：主键 (index_id, node_id) + INSERT OR IGNORE，
-- 服务重启续跑、失败重试都不会重复写入或写出矛盾内容。
CREATE TABLE IF NOT EXISTS causal_index_nodes (
    index_id      TEXT NOT NULL,
    node_id       TEXT NOT NULL,
    node_type     TEXT NOT NULL,
    position      INTEGER NOT NULL,            -- 冗余成员位置，便于按因果顺序取页
    payload_sha256 TEXT NOT NULL,
    payload       TEXT NOT NULL,               -- 节点载荷的规范化 JSON
    PRIMARY KEY (index_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_causal_nodes_position
    ON causal_index_nodes(index_id, position);
-- 因果索引增量派生：以一份**已完成**的因果索引为基线，在新的冻结快照上
-- 增量派生一条新链。创建时即冻结新的 snapshot_seq / 范围 / 过滤，并把
-- 基线的快照信息与链摘要原样保留（baseline_* 列）；基线或源数据之后发生
-- 任何变化都改不动已冻结的派生链。成员分两类：reused（基线中仍有效的
-- 节点，载荷从基线冻结副本复制，只重盖链环字段）与 added（基线快照之后
-- 才出现的事件/源归档/证据包条目，从冻结事件与归档清单重建）。
-- 派生只写本表与 causal_derivation_members / causal_derivation_nodes，
-- 绝不修改租约、委托、审计历史、源归档、证据包或基线索引。
-- idempotency_key 全局唯一：同基线+同范围+同过滤+同键只返回同一派生任务；
-- spec_fingerprint 全局唯一：同基线+同节点+同过滤换键也明确 409。
CREATE TABLE IF NOT EXISTS causal_derivations (
    derivation_id           TEXT PRIMARY KEY,
    idempotency_key         TEXT NOT NULL,
    spec_fingerprint        TEXT NOT NULL,    -- 基线+范围+节点+过滤的 SHA-256
    baseline_index_id       TEXT NOT NULL,    -- 基线索引（创建后只读引用）
    scope                   TEXT NOT NULL,    -- 继承自基线：resource/credential/evidence_package
    resource                TEXT NOT NULL DEFAULT '',
    credential_id           TEXT NOT NULL DEFAULT '',
    package_id              TEXT NOT NULL DEFAULT '',
    node_seq                INTEGER NOT NULL, -- 新链冻结的历史节点
    snapshot_seq            INTEGER NOT NULL, -- 创建时新冻结的稳定视图上界
    filters_json            TEXT NOT NULL,
    baseline_snapshot_seq   INTEGER NOT NULL, -- 创建时钉死的基线快照上界
    baseline_node_seq       INTEGER NOT NULL, -- 创建时钉死的基线历史节点
    baseline_total_nodes    INTEGER NOT NULL, -- 创建时钉死的基线节点总数
    baseline_chain_digest   TEXT,             -- 创建时钉死的基线链摘要
    baseline_content_sha256 TEXT,             -- 创建时钉死的基线文档总校验值
    status                  TEXT NOT NULL DEFAULT 'pending',
                            -- pending / building / paused / completed / failed
    total_nodes             INTEGER NOT NULL DEFAULT 0,
    processed_nodes         INTEGER NOT NULL DEFAULT 0,
    last_position           INTEGER NOT NULL DEFAULT -1, -- 续跑游标
    reused_nodes            INTEGER NOT NULL DEFAULT 0,
    added_nodes             INTEGER NOT NULL DEFAULT 0,
    removed_nodes           INTEGER NOT NULL DEFAULT 0,
    attempts                INTEGER NOT NULL DEFAULT 0,
    error                   TEXT,
    content                 TEXT,             -- 冻结的派生链文档（JSON）
    content_sha256          TEXT,
    chain_digest            TEXT,
    verify_status           TEXT NOT NULL DEFAULT 'unverified',
                            -- unverified / verified / verify_failed
    verify_detail           TEXT,
    verified_at_ms          INTEGER,
    created_logical         INTEGER NOT NULL DEFAULT 0,
    created_at_ms           INTEGER NOT NULL,
    updated_at_ms           INTEGER NOT NULL,
    completed_at_ms         INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_derivation_idem
    ON causal_derivations(idempotency_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_derivation_spec
    ON causal_derivations(spec_fingerprint);
-- 派生链的冻结成员集合：创建事务里一次性写入。origin 标 reused/added，
-- reused 成员另记录其在基线链上的 baseline_position；之后只读。
CREATE TABLE IF NOT EXISTS causal_derivation_members (
    derivation_id     TEXT NOT NULL,
    position          INTEGER NOT NULL,       -- 0 起的新链因果顺序
    node_id           TEXT NOT NULL,
    node_type         TEXT NOT NULL,
    object_id         TEXT NOT NULL,
    anchor_seq        INTEGER NOT NULL,
    origin            TEXT NOT NULL,          -- reused / added
    baseline_position INTEGER,                -- reused：基线链位置；added：NULL
    descriptor_json   TEXT NOT NULL,
    PRIMARY KEY (derivation_id, position)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_derivation_member_node
    ON causal_derivation_members(derivation_id, node_id);
-- 派生链的冻结节点载荷：reused 节点的载荷体逐字段复制自基线冻结副本，
-- added 节点由冻结事件/归档清单重建；主键 (derivation_id, node_id) +
-- INSERT OR IGNORE，中断续跑/失败重试不重复写入。
CREATE TABLE IF NOT EXISTS causal_derivation_nodes (
    derivation_id  TEXT NOT NULL,
    node_id        TEXT NOT NULL,
    node_type      TEXT NOT NULL,
    position       INTEGER NOT NULL,
    origin         TEXT NOT NULL,             -- reused / added
    payload_sha256 TEXT NOT NULL,
    payload        TEXT NOT NULL,
    PRIMARY KEY (derivation_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_derivation_nodes_position
    ON causal_derivation_nodes(derivation_id, position);
-- 索引版本发布计划：管理员把一份**已完成**的因果索引登记为逻辑版本（version
-- 是不可再分配的版本别名，全局唯一；idempotency_key 全局唯一），提交带生效
-- 时间的发布计划。登记时一次性冻结索引摘要、快照信息与可选的索引比较结果；
-- 生效（发布）时再次冻结并复核原索引链摘要与比较结果——原索引被篡改/删除、
-- 比较对象缺失/未完成/比较结果漂移都会让计划 failed 并留下可解释原因。
-- 生效后按版本别名查询只指向冻结的索引（服务时再次核对链摘要），旧版本仍
-- 可按原索引标识查询。发布管理只写本表，绝不修改原索引、派生任务、租约、
-- 委托、审计历史、源归档或证据包。
CREATE TABLE IF NOT EXISTS index_releases (
    release_id                  TEXT PRIMARY KEY,
    version                     TEXT NOT NULL,   -- 逻辑版本别名（一旦登记永不复用）
    idempotency_key             TEXT NOT NULL,
    index_id                    TEXT NOT NULL,   -- 被发布的已完成因果索引（只读引用）
    effective_at_ms             INTEGER NOT NULL,-- 计划生效墙钟时间（<=登记时刻即立即生效）
    status                      TEXT NOT NULL DEFAULT 'scheduled',
                                -- scheduled / active / cancelled / failed
    plan_fingerprint            TEXT NOT NULL,   -- version+索引+生效时间+比较对象规格指纹
    -- 登记时冻结
    frozen_index_summary_json   TEXT NOT NULL,   -- 索引摘要（作用域/对象/节点数/链摘要/校验值/核验标记）
    frozen_snapshot_json        TEXT NOT NULL,   -- 快照信息（snapshot_seq/node_seq/MAX(seq)）
    frozen_compare_json         TEXT,            -- 可选：与比较对象的完整比较结果（规范化 JSON）
    compare_with_index_id       TEXT NOT NULL DEFAULT '',
    compare_digest              TEXT,            -- 比较结果规范化摘要
    -- 生效（发布）时再次冻结
    activate_index_summary_json TEXT,
    activate_snapshot_json      TEXT,
    activate_compare_json       TEXT,
    activate_index_chain_digest TEXT,            -- 生效时重算的原索引链摘要（应与登记冻结值一致）
    attempts                    INTEGER NOT NULL DEFAULT 0,
    error                       TEXT,            -- 失败的人类可读原因
    error_code                  TEXT,            -- 失败错误码（release_index_tampered 等）
    error_detail_json           TEXT,            -- 失败的结构化解释（路径/双方值）
    created_logical             INTEGER NOT NULL DEFAULT 0,
    created_at_ms               INTEGER NOT NULL,
    updated_at_ms               INTEGER NOT NULL,
    activated_at_ms             INTEGER,
    cancelled_at_ms             INTEGER,
    failed_at_ms                INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_release_version
    ON index_releases(version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_release_idem
    ON index_releases(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_release_due
    ON index_releases(status, effective_at_ms);
-- 审计变更订阅：管理员针对资源、委托凭证、因果索引或发布版本登记一个
-- 回调地址、事件范围（filters_json，创建时冻结）、起始历史序号与密钥。
-- 订阅处理只写本表与 audit_subscription_deliveries 两张自有表，绝不修改
-- 租约、委托、原始审计历史、源归档、证据包、因果索引或发布计划。
-- position_seq 是"下一个要检视的全局历史序号"游标；sub_seq 是该订阅
-- 已入队（匹配过滤条件）的通知计数，即下一次通知使用的订阅序号。
-- status: active / paused / cancelled；blocked=1 表示存在 dead_letter
-- 投递挡住了严格序号队列，重新放回队列后清除。
CREATE TABLE IF NOT EXISTS audit_subscriptions (
    subscription_id   TEXT PRIMARY KEY,
    idempotency_key   TEXT NOT NULL,
    scope             TEXT NOT NULL,    -- resource / credential / causal_index / release
    resource          TEXT NOT NULL DEFAULT '',
    credential_id     TEXT NOT NULL DEFAULT '',
    index_id          TEXT NOT NULL DEFAULT '',
    release_id        TEXT NOT NULL DEFAULT '',
    callback_url      TEXT NOT NULL,
    secret            TEXT NOT NULL,                  -- HMAC-SHA256 签名密钥（只在服务端保存）
    filters_json      TEXT NOT NULL,                  -- 创建时冻结的规范化过滤条件
    start_seq         INTEGER NOT NULL,               -- 登记的起始历史序号（含）
    position_seq      INTEGER NOT NULL,               -- 扫描游标：下一个待检视 seq
    sub_seq           INTEGER NOT NULL DEFAULT 0,     -- 已入队通知数（订阅序号，版本1）
    snapshot_seq      INTEGER NOT NULL,               -- 创建时钉死的稳定视图上界
    current_version   INTEGER NOT NULL DEFAULT 1,     -- 当前生效版本号
    pending_version   INTEGER,                        -- 预创建待激活的版本号
    status            TEXT NOT NULL DEFAULT 'active',
    blocked           INTEGER NOT NULL DEFAULT 0,     -- 有 dead_letter 挡队
    max_attempts      INTEGER NOT NULL DEFAULT 5,
    ack_required      INTEGER NOT NULL DEFAULT 0,     -- 回调返回 202 时是否等待显式签名确认
    error             TEXT,
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL,
    cancelled_at_ms   INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscription_idem
    ON audit_subscriptions(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_subscription_status
    ON audit_subscriptions(status, position_seq);
-- 每个订阅的每条匹配事件至多一行投递记录：(subscription_id, event_seq)
-- 唯一 + INSERT OR IGNORE，并发入队/重新开始/服务重启都不会产生两条通知。
-- status: pending（待投递/退避等待）/ inflight（已认领，回调进行中）/
--         awaiting_confirm（回调 202，等待签名确认）/ confirmed（已确认）/
--         dead_letter（超过尝试上限或永久拒收）/ discarded（取消/重新开始弃置）。
-- attempts 记录已尝试次数；next_retry_at_ms 存退避**时长**，到点判定
-- 用 updated_at_ms + next_retry_at_ms（同一偏移墙钟，正拨不会让退避
-- 永远不到点），last_error 记录最近一次失败原因（HTTP 状态/超时/异常），
-- dead_letter 额外保留 dead_letter_reason。dispatch_token 是每次认领
-- 的唯一令牌，迟到的回调响应只能作用于本次认领。
CREATE TABLE IF NOT EXISTS audit_subscription_deliveries (
    delivery_id        TEXT PRIMARY KEY,
    subscription_id    TEXT NOT NULL,
    event_seq          INTEGER NOT NULL,
    subscription_seq   INTEGER NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    attempts           INTEGER NOT NULL DEFAULT 0,
    next_retry_at_ms   INTEGER NOT NULL DEFAULT 0,
    claimed_at_ms      INTEGER,
    dispatch_token     TEXT,
    last_error         TEXT,
    dead_letter_reason TEXT,
    payload_json       TEXT NOT NULL,         -- 冻结的通知载荷（规范化签名输入）
    signature          TEXT,                  -- 最近一次投递使用的签名
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
-- 订阅版本切换：管理员为活动订阅预创建带新回调地址、新事件过滤条件与
-- 生效历史序号（effective_seq，含）的下一版本。版本切换在一个事务内
-- 原子完成：旧版本（superseded）只继续处理切换前已入队/进行中的通知
-- （投递行冻结了当时的回调地址、密钥、过滤条件与订阅序号），生效序号
-- 之后新匹配的事件只能进入新版本（active）。同一订阅的两个版本在
-- 投递表内按**全局 event_seq** 共享同一条严格顺序队列，队首约束保证
-- 旧版本未确认通知与新版本通知互不越过、不重复、不丢失。
-- status: prepared（预创建待激活）/ active（当前生效版本）/
--         superseded（已被下一版本切换，只做收尾投递）/
--         cancelled（预创建版本被取消，永不生效）。
-- position_seq 是该版本自己的扫描游标；sub_seq 是该版本自己的订阅
-- 序号计数（每个版本从 1 重新连续编号，随版本字段签名）。
CREATE TABLE IF NOT EXISTS audit_subscription_versions (
    version_id        TEXT PRIMARY KEY,
    subscription_id   TEXT NOT NULL,
    version_no        INTEGER NOT NULL,
    idempotency_key   TEXT NOT NULL,
    callback_url      TEXT NOT NULL,
    secret            TEXT NOT NULL,
    filters_json      TEXT NOT NULL,
    effective_seq     INTEGER NOT NULL,
    scan_upper_seq    INTEGER,                      -- 被切换时钉死：下一版本 effective_seq-1
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
-- 订阅自己的审计历史（只追加，永不更新/删除）：版本的创建、激活、
-- 拒绝原因、取消与死信重试都在此留痕。只写订阅自有表，绝不改写租约、
-- 委托、lease_events 原始审计事件或已有投递记录。
CREATE TABLE IF NOT EXISTS audit_subscription_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id   TEXT NOT NULL,
    version_no        INTEGER,
    event             TEXT NOT NULL,   -- version_prepared/version_activated/
                                       -- version_rejected/version_cancelled/
                                       -- version_retry
    outcome           TEXT NOT NULL,   -- ok / rejected
    detail            TEXT,
    detail_json       TEXT,
    created_at_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subevent_sub
    ON audit_subscription_events(subscription_id, id);
-- 订阅版本管理操作（激活/取消/死信重试）的幂等日志：同一幂等键重复
-- 提交回放首次结果（result_json），同键换操作类型/目标订阅/版本或
-- 重试目标即 409 冲突。创建版本的幂等键由版本行自身的唯一索引承载。
CREATE TABLE IF NOT EXISTS audit_subscription_idempotency (
    idempotency_key   TEXT PRIMARY KEY,
    subscription_id   TEXT NOT NULL,
    operation         TEXT NOT NULL,   -- activate / cancel / retry_dead_letters
    target            TEXT NOT NULL,   -- 版本号/重试作用域（冻结的操作目标）
    result_json       TEXT NOT NULL,
    created_at_ms     INTEGER NOT NULL
);
-- 订阅通知签名密钥轮换：管理员为活动订阅预登记下一把签名密钥（指纹、
-- 生效历史序号 effective_seq、宽限期 grace_ms），随后原子生效。
-- 生效序号之前已入队/认领中的投递在投递表上钉死旧 signing_key_id，继续
-- 按旧密钥签名/确认；生效序号（含）起的新投递使用新密钥。旧密钥在宽限
-- 期内处于 grace（旧通知仍可用旧密钥完成确认），到点退役为 retired；
-- 预登记密钥可撤销（revoked，永不生效）。密钥轮换只写本表与
-- audit_subscription_key_idempotency /
-- audit_subscription_signature_verifications 三张自有表（投递表只追加
-- signing_key_id 列与重签时的 signature），绝不改写租约、委托、
-- lease_events 原始审计事件、版本行或已有投递状态。
CREATE TABLE IF NOT EXISTS audit_subscription_signing_keys (
    key_id            TEXT PRIMARY KEY,
    subscription_id   TEXT NOT NULL,
    key_no            INTEGER NOT NULL,
    idempotency_key   TEXT NOT NULL,
    secret            TEXT NOT NULL,               -- 签名密钥明文（只在服务端保存）
    fingerprint       TEXT NOT NULL,               -- sha256(secret) 十六进制
    effective_seq     INTEGER NOT NULL,            -- 该序号（含）起新通知用新密钥
    grace_ms          INTEGER NOT NULL DEFAULT 0,  -- 旧密钥宽限时长（墙钟毫秒）
    status            TEXT NOT NULL DEFAULT 'prepared',
    replaces_key_id   TEXT,
    snapshot_seq      INTEGER NOT NULL,
    activated_at_ms   INTEGER,
    grace_until_ms    INTEGER,
    retired_at_ms     INTEGER,
    revoked_at_ms     INTEGER,
    reject_reason     TEXT,
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_signkey_no
    ON audit_subscription_signing_keys(subscription_id, key_no);
CREATE UNIQUE INDEX IF NOT EXISTS idx_signkey_idem
    ON audit_subscription_signing_keys(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_signkey_status
    ON audit_subscription_signing_keys(subscription_id, status);
-- 密钥轮换操作（生效/撤销/重签）的幂等日志：同键重复提交回放首次结果，
-- 同键换操作类型/目标订阅/目标即 409 冲突。预登记键由密钥行唯一索引承载。
CREATE TABLE IF NOT EXISTS audit_subscription_key_idempotency (
    idempotency_key   TEXT PRIMARY KEY,
    subscription_id   TEXT NOT NULL,
    operation         TEXT NOT NULL,   -- activate_key / revoke_key / resign_delivery
    target            TEXT NOT NULL,   -- key_id 或 event_seq（冻结的操作目标）
    result_json       TEXT NOT NULL,
    created_at_ms     INTEGER NOT NULL
);
-- 投递签名验证结果（只追加）：显式确认时按当前密钥/宽限旧密钥验证的结论。
-- 同一投递可保留多条轨迹（先 failed 后 ok/old_key_grace）；dedupe_key
-- (delivery_id|result|used|expected) 唯一使完全相同的重复确认不重复计数。
-- 重签追加 result=resigned 的新行（失败与重签轨迹都保留，按 created_at
-- 排序）。
CREATE TABLE IF NOT EXISTS audit_subscription_signature_verifications (
    verification_id   TEXT PRIMARY KEY,
    subscription_id   TEXT NOT NULL,
    delivery_id       TEXT NOT NULL,
    event_seq         INTEGER NOT NULL,
    key_id            TEXT NOT NULL,         -- 确认时实际使用的密钥（'' 表示版本密钥）
    expected_key_id   TEXT,                  -- 投递行冻结的应使用密钥
    result            TEXT NOT NULL,         -- ok / failed / old_key_grace / resigned
    detail            TEXT,
    created_at_ms     INTEGER NOT NULL,
    dedupe_key        TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sigver_dedupe
    ON audit_subscription_signature_verifications(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_sigver_key_time
    ON audit_subscription_signature_verifications(
        subscription_id, key_id, created_at_ms, event_seq);
"""


class Store:
    def __init__(
        self,
        db_path: str,
        *,
        ttl_ms: int = DEFAULT_TTL_MS,
        max_ttl_ms: int = DEFAULT_MAX_TTL_MS,
        hard_ttl_ms: int = DEFAULT_HARD_TTL_MS,
        logical_grace: int = DEFAULT_LOGICAL_GRACE,
        delegation_ttl_ms: int = DEFAULT_DELEGATION_TTL_MS,
        delegation_max_ttl_ms: int = DEFAULT_DELEGATION_MAX_TTL_MS,
    ):
        self._lock = threading.RLock()
        # check_same_thread=False + 全局互斥锁保证多线程访问安全
        import sqlite3

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)
        self._migrate_columns()
        self._conn.commit()

        self.default_ttl_ms = ttl_ms
        self.max_ttl_ms = max_ttl_ms
        self.hard_ttl_ms = hard_ttl_ms
        self.logical_grace = logical_grace
        self.default_delegation_ttl_ms = delegation_ttl_ms
        self.delegation_max_ttl_ms = delegation_max_ttl_ms

        self.clock = Clock(lambda: self._get_meta("wall_offset_ms", 0))
        self.clock.set_logical(self._get_meta("logical_clock", 0))
        # 重启即按持久化状态收割：已到期的委托与已连带失效的委托在此收敛，
        # 之后任何写入都会在同一把锁里重新判定，不会放行迟到凭证。
        self._reap_locked()

    def _migrate_columns(self) -> None:
        """给早于委托特性的旧库补列（CREATE TABLE IF NOT EXISTS 不会改已有表）。"""
        def columns(table: str) -> set[str]:
            return {r["name"] for r in self._conn.execute(
                f"PRAGMA table_info({table})"
            ).fetchall()}

        if "credential_id" not in columns("writes"):
            self._conn.execute("ALTER TABLE writes ADD COLUMN credential_id TEXT")
        events_cols = columns("lease_events")
        if "credential_id" not in events_cols:
            self._conn.execute(
                "ALTER TABLE lease_events ADD COLUMN credential_id TEXT"
            )
        if "value" not in events_cols:
            self._conn.execute(
                "ALTER TABLE lease_events ADD COLUMN value TEXT"
            )
        # 新库旧库都走这里：列已存在时 IF NOT EXISTS 是空操作
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_credential "
            "ON lease_events(credential_id, seq)"
        )
        # 订阅版本切换特性的增量列（旧库兼容；表尚不存在时 PRAGMA 返回空集）
        sub_cols = columns("audit_subscriptions")
        if sub_cols and "current_version" not in sub_cols:
            self._conn.execute(
                "ALTER TABLE audit_subscriptions "
                "ADD COLUMN current_version INTEGER NOT NULL DEFAULT 1")
        if sub_cols and "pending_version" not in sub_cols:
            self._conn.execute(
                "ALTER TABLE audit_subscriptions ADD COLUMN pending_version INTEGER")
        delivery_cols = columns("audit_subscription_deliveries")
        if delivery_cols and "version_no" not in delivery_cols:
            self._conn.execute(
                "ALTER TABLE audit_subscription_deliveries "
                "ADD COLUMN version_no INTEGER NOT NULL DEFAULT 1")
        # 签名密钥轮换特性增量列：投递行冻结的签名密钥代际（NULL 回退版本
        # 冻结密钥，轮换特性前的旧行历史行为不变）。
        if delivery_cols and "signing_key_id" not in delivery_cols:
            self._conn.execute(
                "ALTER TABLE audit_subscription_deliveries "
                "ADD COLUMN signing_key_id TEXT")
        if delivery_cols:
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_delivery_version "
                "ON audit_subscription_deliveries(subscription_id, "
                "version_no, event_seq)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_delivery_signkey "
                "ON audit_subscription_deliveries(subscription_id, "
                "signing_key_id)")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- 元数据 ---------------------------------------------------------
    def _get_meta(self, key: str, default: int = 0) -> int:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def _set_meta(self, key: str, value: int) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---- 统一历史：与状态变更同事务写入，调用方负责 commit --------------
    def _record_event_locked(
        self,
        resource: str,
        event: str,
        outcome: str,
        holder: str,
        *,
        peer: str | None = None,
        lease_id: str | None = None,
        generation: int | None = None,
        to_lease_id: str | None = None,
        to_generation: int | None = None,
        credential_id: str | None = None,
        detail: str | None = None,
        value: str | None = None,
        now: int | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO lease_events(resource, event, outcome, holder, peer, "
            "lease_id, generation, to_lease_id, to_generation, credential_id, "
            "detail, value, wall_ms, logical) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                resource, event, outcome, holder, peer, lease_id, generation,
                to_lease_id, to_generation, credential_id, detail, value,
                now if now is not None else self.clock.wall_ms(),
                self.clock.logical(),
            ),
        )

    # ---- 逻辑钟推进（后台 ticker / 测试接口调用） -----------------------
    def tick(self, steps: int = 1) -> int:
        with self._lock:
            value = self.clock.advance_logical(steps)
            self._set_meta("logical_clock", value)
            self._conn.commit()
            self._reap_locked()
            return value

    # ---- 调试用：拨墙钟（不持久化偏移就无法在重启后复现故障） ----------
    def shift_wall(self, delta_ms: int) -> int:
        with self._lock:
            offset = self._get_meta("wall_offset_ms", 0) + int(delta_ms)
            self._set_meta("wall_offset_ms", offset)
            self._conn.commit()
            self._reap_locked()
            return self.clock.wall_ms()

    # ---- 过期判定 -------------------------------------------------------
    def _classify_locked(self, lease) -> dict[str, Any]:
        """返回 {state, expire_reason}。纯函数式读取，不写库。"""
        wall = self.clock.wall_ms()
        logical = self.clock.logical()
        if lease["state"] != STATE_ACTIVE:
            return {"state": lease["state"], "expire_reason": lease["expire_reason"]}

        if wall >= lease["hard_wall_deadline_ms"]:
            # 硬上限：逻辑钟再怎么跳也没用，保证租约必然结束
            return {"state": STATE_EXPIRED, "expire_reason": REASON_HARD_WALL}

        soft_ok = wall < lease["wall_deadline_ms"]
        logical_ok = logical <= lease["last_seen_logical"] + lease["logical_grace"]
        if not soft_ok and not logical_ok:
            # 墙钟说过期、逻辑钟也沉默：双时钟一致，才能回收
            return {
                "state": STATE_EXPIRED,
                "expire_reason": REASON_SOFT_WALL_AND_LOGICAL_STALL,
            }
        return {"state": STATE_ACTIVE, "expire_reason": None}

    def _get_active_locked(self, resource: str, for_update: bool = True):
        row = self._conn.execute(
            "SELECT * FROM leases WHERE resource=? AND state='active' "
            "ORDER BY generation DESC LIMIT 1",
            (resource,),
        ).fetchone()
        if row is None:
            return None
        status = self._classify_locked(row)
        if status["state"] != STATE_ACTIVE:
            self._expire_locked(row, status["expire_reason"])
            return None
        return row

    def _expire_locked(self, row, reason: str) -> None:
        """把租约置为过期；其名下生效委托在同一事务内连带栅栏，不单独提交，
        由调用方与其余状态变更一起 commit（要么全成要么全不成）。"""
        self._fence_delegations_locked(row["id"], FENCE_LEASE_EXPIRED)
        self._conn.execute(
            "UPDATE leases SET state=?, expire_reason=? WHERE id=?",
            (STATE_EXPIRED, reason, row["id"]),
        )

    def _fence_delegations_locked(self, lease_id: str, reason: str) -> None:
        """租约释放/转移/过期时，把它名下仍生效的委托连带置为 fenced。

        与租约状态变更在同一事务：外部绝不会观察到"租约已结束但委托还能写"，
        也不会观察到"委托已栅栏但租约还活着"。每个被栅栏的委托各落一条
        delegate_fence 历史事件，审计可按 credential_id 追到失效时刻与原因。
        """
        cur = self._conn.execute(
            "UPDATE delegations SET state=?, end_reason=? "
            "WHERE lease_id=? AND state=?",
            (DEL_STATE_FENCED, reason, lease_id, DEL_STATE_ACTIVE),
        )
        if cur.rowcount:
            now = self.clock.wall_ms()
            logical = self.clock.logical()
            self._conn.execute(
                "INSERT INTO lease_events(resource, event, outcome, holder, "
                "peer, lease_id, generation, credential_id, detail, "
                "wall_ms, logical) "
                "SELECT resource, 'delegate_fence', 'ok', authorizer, "
                "collaborator, lease_id, generation, credential_id, ?, ?, ? "
                "FROM delegations WHERE lease_id=? AND state=? AND end_reason=?",
                (reason, now, logical, lease_id, DEL_STATE_FENCED, reason),
            )

    def _reap_delegations_locked(self) -> int:
        """墙钟到期的委托收尾（委托只信墙钟，不可续约、不看逻辑钟）。"""
        now = self.clock.wall_ms()
        rows = self._conn.execute(
            "SELECT * FROM delegations WHERE state=? AND expires_wall_ms <= ?",
            (DEL_STATE_ACTIVE, now),
        ).fetchall()
        for d in rows:
            self._conn.execute(
                "UPDATE delegations SET state=?, end_reason=? "
                "WHERE credential_id=?",
                (DEL_STATE_EXPIRED, END_DELEGATION_EXPIRED, d["credential_id"]),
            )
            self._record_event_locked(
                d["resource"], "delegate_expire", "ok", d["authorizer"],
                peer=d["collaborator"], lease_id=d["lease_id"],
                generation=d["generation"], credential_id=d["credential_id"],
                detail=END_DELEGATION_EXPIRED, now=now,
            )
        return len(rows)

    def _reap_locked(self) -> int:
        """按双时钟规则收割过期租约、再按墙钟收割到期委托，返回收割的租约数。"""
        rows = self._conn.execute(
            "SELECT * FROM leases WHERE state='active'"
        ).fetchall()
        n = 0
        for row in rows:
            status = self._classify_locked(row)
            if status["state"] != STATE_ACTIVE:
                self._expire_locked(row, status["expire_reason"])
                n += 1
        nd = self._reap_delegations_locked()
        if n or nd:
            self._conn.commit()
        return n

    # ---- 获取租约 -------------------------------------------------------
    def acquire(
        self, resource: str, holder: str, ttl_ms: int | None
    ) -> tuple[dict[str, Any], bool]:
        """成功返回 (lease视图, True)；同一持有者复用当前租约返回 (视图, False)。"""
        with self._lock:
            self._reap_locked()
            existing = self._conn.execute(
                "SELECT * FROM leases WHERE resource=? AND state='active' "
                "ORDER BY generation DESC LIMIT 1",
                (resource,),
            ).fetchone()
            if existing is not None:
                if existing["holder"] == holder:
                    self._record_event_locked(
                        resource, "acquire", "ok", holder,
                        lease_id=existing["id"],
                        generation=existing["generation"],
                        detail="reused_existing",
                    )
                    self._conn.commit()
                    return self._lease_view_locked(existing), False
                self._record_event_locked(
                    resource, "acquire", "rejected", holder,
                    peer=existing["holder"], lease_id=existing["id"],
                    generation=existing["generation"],
                    detail="resource_held_by_other",
                )
                self._conn.commit()
                raise Conflict(f"资源 {resource} 已被 {existing['holder']} 持有")

            ttl = self._clamp_ttl(ttl_ms)
            now = self.clock.wall_ms()
            gen = self._next_generation_locked(resource)
            lease_id = str(uuid.uuid4())
            logical = self.clock.logical()
            self._conn.execute(
                "INSERT INTO leases(id, resource, holder, generation, "
                "granted_wall_ms, wall_deadline_ms, hard_wall_deadline_ms, "
                "logical_grace, last_seen_logical, created_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    lease_id, resource, holder, gen, now, now + ttl,
                    now + self.hard_ttl_ms, self.logical_grace, logical, now,
                ),
            )
            self._record_event_locked(
                resource, "acquire", "ok", holder,
                lease_id=lease_id, generation=gen, now=now,
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM leases WHERE id=?", (lease_id,)
            ).fetchone()
            return self._lease_view_locked(row), True

    def _clamp_ttl(self, ttl_ms: int | None) -> int:
        ttl = int(ttl_ms) if ttl_ms is not None else self.default_ttl_ms
        return max(MIN_TTL_MS, min(ttl, self.max_ttl_ms))

    def _next_generation_locked(self, resource: str) -> int:
        self._conn.execute(
            "INSERT INTO resources(resource, current_gen) VALUES(?, 1) "
            "ON CONFLICT(resource) DO UPDATE SET "
            "current_gen = resources.current_gen + 1",
            (resource,),
        )
        row = self._conn.execute(
            "SELECT current_gen FROM resources WHERE resource=?", (resource,)
        ).fetchone()
        return row["current_gen"]

    # ---- 续约 -----------------------------------------------------------
    def renew(self, resource: str, holder: str, generation: int) -> dict[str, Any]:
        with self._lock:
            self._reap_locked()
            row = self._get_active_locked(resource)
            if row is None:
                self._record_event_locked(
                    resource, "renew", "rejected", holder,
                    generation=generation, detail="no_active_lease",
                )
                self._conn.commit()
                raise LeaseGone(f"资源 {resource} 没有生效中的租约，续约被拒绝；"
                                "请重新获取并取得更大的世代号")
            if row["holder"] != holder or row["generation"] != generation:
                self._record_event_locked(
                    resource, "renew", "rejected", holder,
                    lease_id=row["id"], generation=generation,
                    detail="holder_or_generation_mismatch",
                )
                self._conn.commit()
                raise Conflict("持有者或世代号与当前生效租约不符")

            now = self.clock.wall_ms()
            # 软 deadline 顺延，但永远不能越过发放时定死的硬墙钟上限
            new_soft = min(
                now + self.default_ttl_ms, row["hard_wall_deadline_ms"] - 1
            )
            self._conn.execute(
                "UPDATE leases SET wall_deadline_ms=?, last_seen_logical=?, "
                "renewed_count=renewed_count+1 WHERE id=?",
                (new_soft, self.clock.logical(), row["id"]),
            )
            self._record_event_locked(
                resource, "renew", "ok", holder,
                lease_id=row["id"], generation=generation, now=now,
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM leases WHERE id=?", (row["id"],)
            ).fetchone()
            return self._lease_view_locked(row)

    # ---- 释放 -----------------------------------------------------------
    def release(self, resource: str, holder: str, generation: int) -> None:
        with self._lock:
            self._reap_locked()
            row = self._get_active_locked(resource)
            if row is None:
                self._record_event_locked(
                    resource, "release", "rejected", holder,
                    generation=generation, detail="no_active_lease",
                )
                self._conn.commit()
                raise LeaseGone(f"资源 {resource} 没有生效中的租约")
            if row["holder"] != holder or row["generation"] != generation:
                self._record_event_locked(
                    resource, "release", "rejected", holder,
                    lease_id=row["id"], generation=generation,
                    detail="holder_or_generation_mismatch",
                )
                self._conn.commit()
                raise Conflict("持有者或世代号与当前生效租约不符")
            self._fence_delegations_locked(row["id"], FENCE_LEASE_RELEASED)
            self._conn.execute(
                "UPDATE leases SET state=? WHERE id=?",
                (STATE_RELEASED, row["id"]),
            )
            self._record_event_locked(
                resource, "release", "ok", holder,
                lease_id=row["id"], generation=generation,
            )
            self._conn.commit()

    # ---- 安全转移 -------------------------------------------------------
    def transfer(
        self,
        resource: str,
        holder: str,
        generation: int,
        to_holder,
        transfer_id=None,
        ttl_ms: int | None = None,
    ) -> dict[str, Any]:
        """把生效中的租约原子地转给 to_holder。

        单事务内完成：旧租约置为 transferred（旧持有者即刻失去写权限）、
        资源世代号 +1、以更大世代号发放新租约（新持有者即刻可写）、
        落转移记录与历史事件。崩溃只会整体回滚，不留半完成状态。

        transfer_id 是幂等键：同一笔转移重复提交直接回放首次结果，
        不会再次转移；同一 transfer_id 配不同参数则拒绝。
        """
        with self._lock:
            self._reap_locked()
            now = self.clock.wall_ms()
            if transfer_id is not None:
                transfer_id = str(transfer_id)

            # 当时的生效租约（无则 None）：无论转移成败，历史事件都要能
            # 关联到它；下面的凭证校验也复用这一行，不再重复查询
            row = self._get_active_locked(resource)
            active_lease_id = row["id"] if row else None

            # 1) 幂等键先行：已执行过的转移，参数一致 -> 回放首次结果
            if transfer_id:
                prev = self._conn.execute(
                    "SELECT * FROM transfers WHERE transfer_id=?",
                    (transfer_id,),
                ).fetchone()
                if prev is not None:
                    same = (
                        prev["resource"] == resource
                        and prev["from_holder"] == holder
                        and prev["from_generation"] == generation
                        and prev["to_holder"] == to_holder
                    )
                    if not same:
                        self._record_event_locked(
                            resource, "transfer", "rejected", holder,
                            peer=to_holder if isinstance(to_holder, str)
                            else None,
                            lease_id=active_lease_id,
                            generation=generation,
                            detail="transfer_id_conflict", now=now,
                        )
                        self._conn.commit()
                        raise Conflict(
                            f"transfer_id {transfer_id} 已被一笔参数不同的"
                            "转移占用，本次请求被拒绝"
                        )
                    lease_row = self._conn.execute(
                        "SELECT * FROM leases WHERE id=?",
                        (prev["new_lease_id"],),
                    ).fetchone()
                    return self._transfer_view_locked(prev, lease_row,
                                                      replayed=True)

            # 2) 接收者资格：非空字符串、不能转给当前持有者自己
            if not isinstance(to_holder, str) or not to_holder.strip():
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    lease_id=active_lease_id,
                    generation=generation, detail="ineligible_recipient",
                    now=now,
                )
                self._conn.commit()
                raise Conflict("接收者不符合条件：to_holder 必须是非空字符串")
            if to_holder == holder:
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    peer=to_holder, lease_id=active_lease_id,
                    generation=generation,
                    detail="ineligible_recipient:self", now=now,
                )
                self._conn.commit()
                raise Conflict("接收者不符合条件：不能转移给当前持有者自己")

            # 3) 旧凭证校验：必须是当前生效租约的持有者与世代号
            if row is None:
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    peer=to_holder, generation=generation,
                    detail="no_active_lease", now=now,
                )
                self._conn.commit()
                raise LeaseGone(f"资源 {resource} 没有生效中的租约，转移被拒绝")
            if row["holder"] != holder or row["generation"] != generation:
                self._record_event_locked(
                    resource, "transfer", "rejected", holder,
                    peer=to_holder, lease_id=row["id"], generation=generation,
                    detail="holder_or_generation_mismatch", now=now,
                )
                self._conn.commit()
                raise Conflict("持有者或世代号与当前生效租约不符，转移被拒绝")

            # 4) 原子交接：以下全部写操作一次 commit，要么全成要么全不成
            transfer_id = transfer_id or str(uuid.uuid4())
            new_gen = self._next_generation_locked(resource)
            new_lease_id = str(uuid.uuid4())
            ttl = self._clamp_ttl(ttl_ms)
            logical = self.clock.logical()
            # 原租约名下委托连带失效：转移完成的同一刻，迟到委托写必被拒
            self._fence_delegations_locked(row["id"], FENCE_LEASE_TRANSFERRED)
            self._conn.execute(
                "UPDATE leases SET state=? WHERE id=?",
                (STATE_TRANSFERRED, row["id"]),
            )
            self._conn.execute(
                "INSERT INTO leases(id, resource, holder, generation, "
                "granted_wall_ms, wall_deadline_ms, hard_wall_deadline_ms, "
                "logical_grace, last_seen_logical, created_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    new_lease_id, resource, to_holder, new_gen, now,
                    now + ttl, now + self.hard_ttl_ms, self.logical_grace,
                    logical, now,
                ),
            )
            self._conn.execute(
                "INSERT INTO transfers(transfer_id, resource, from_holder, "
                "to_holder, from_lease_id, from_generation, new_lease_id, "
                "new_generation, created_at_ms) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    transfer_id, resource, holder, to_holder, row["id"],
                    row["generation"], new_lease_id, new_gen, now,
                ),
            )
            self._record_event_locked(
                resource, "transfer", "ok", holder,
                peer=to_holder, lease_id=row["id"],
                generation=row["generation"], to_lease_id=new_lease_id,
                to_generation=new_gen, now=now,
            )
            self._conn.commit()
            transfer_row = self._conn.execute(
                "SELECT * FROM transfers WHERE transfer_id=?", (transfer_id,)
            ).fetchone()
            lease_row = self._conn.execute(
                "SELECT * FROM leases WHERE id=?", (new_lease_id,)
            ).fetchone()
            return self._transfer_view_locked(transfer_row, lease_row,
                                              replayed=False)

    def _transfer_view_locked(self, t, lease_row, *, replayed: bool):
        lease_view = None
        if lease_row is not None:
            status = self._classify_locked(lease_row)
            lease_view = self._lease_view_locked(lease_row,
                                                 state=status["state"])
            if status["state"] != STATE_ACTIVE:
                lease_view["expire_reason"] = status["expire_reason"]
        return {
            "transfer_id": t["transfer_id"],
            "resource": t["resource"],
            "replayed": replayed,
            "from": {
                "holder": t["from_holder"],
                "lease_id": t["from_lease_id"],
                "generation": t["from_generation"],
            },
            "to": {
                "holder": t["to_holder"],
                "lease_id": t["new_lease_id"],
                "generation": t["new_generation"],
            },
            "lease": lease_view,
            "created_at_ms": t["created_at_ms"],
        }

    # ---- 限时委托：发放 -------------------------------------------------
    def grant_delegation(
        self,
        resource: str,
        holder: str,
        generation: int,
        collaborator: Any,
        ttl_ms: int | None = None,
        credential_id: str | None = None,
    ) -> dict[str, Any]:
        """当前持有者为指定协作者发放只针对该资源的短期委托凭证。

        委托锚定在发放时的生效租约（lease_id + generation）上：
        - 协作者可凭凭证连续写入，世代号沿用授权租约那一代；
        - 不能续约/释放/转移/再次转委托：这些入口只认生效租约的
          holder+generation，协作者天然无法通过；
        - 有效期只信墙钟且不可延长；租约释放/转移/过期时委托在同一事务
          连带失效，撤销与到期同样立即生效。
        """
        with self._lock:
            self._reap_locked()
            now = self.clock.wall_ms()
            row = self._get_active_locked(resource)

            def reject(detail: str, *, lease_row=row, gen=generation,
                       peer=None) -> None:
                self._record_event_locked(
                    resource, "delegate_grant", "rejected", holder,
                    peer=peer,
                    lease_id=lease_row["id"] if lease_row else None,
                    generation=gen, detail=detail, now=now,
                )
                self._conn.commit()

            # 客户端可自带幂等凭证号；撞号（任何参数不同）都拒绝
            if credential_id is not None:
                credential_id = str(credential_id)
                prev = self._conn.execute(
                    "SELECT * FROM delegations WHERE credential_id=?",
                    (credential_id,),
                ).fetchone()
                if prev is not None:
                    reject(
                        "credential_id_conflict",
                        lease_row=row, gen=generation,
                        peer=prev["collaborator"],
                    )
                    raise Conflict(
                        f"凭证号 {credential_id} 已存在，发放被拒绝"
                    )

            # 协作者资格：非空字符串，不能委托给自己
            if not isinstance(collaborator, str) or not collaborator.strip():
                reject("ineligible_collaborator")
                raise Conflict("协作者不符合条件：collaborator 必须是非空字符串")
            if collaborator == holder:
                reject("ineligible_collaborator:self", peer=collaborator)
                raise Conflict("协作者不符合条件：不能委托给当前持有者自己")

            # 必须是当前生效租约的持有者与世代号
            if row is None:
                reject("no_active_lease", lease_row=None)
                raise LeaseGone(
                    f"资源 {resource} 没有生效中的租约，委托发放被拒绝"
                )
            if row["holder"] != holder or row["generation"] != generation:
                reject("holder_or_generation_mismatch", peer=collaborator)
                raise Conflict(
                    "持有者或世代号与当前生效租约不符，委托发放被拒绝"
                )

            ttl = self._clamp_delegation_ttl(ttl_ms)
            # 委托不能活过授权租约的硬墙钟上限：上限前租约必结束，
            # 那时委托必被连带栅栏；剩余时间不足以容纳最小 TTL 则拒绝发放
            max_ms = row["hard_wall_deadline_ms"] - now
            if max_ms < MIN_TTL_MS:
                reject("lease_ends_too_soon", peer=collaborator)
                raise Conflict(
                    f"授权租约将在 {max_ms}ms 内到硬上限，不足以发放委托"
                )
            ttl = min(ttl, max_ms)

            credential_id = credential_id or uuid.uuid4().hex
            expires = now + ttl
            self._conn.execute(
                "INSERT INTO delegations(credential_id, resource, lease_id, "
                "authorizer, collaborator, generation, granted_wall_ms, "
                "expires_wall_ms, state, created_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    credential_id, resource, row["id"], holder, collaborator,
                    row["generation"], now, expires, DEL_STATE_ACTIVE, now,
                ),
            )
            self._record_event_locked(
                resource, "delegate_grant", "ok", holder,
                peer=collaborator, lease_id=row["id"],
                generation=row["generation"], credential_id=credential_id,
                detail=f"expires_wall_ms={expires}", now=now,
            )
            self._conn.commit()
            d = self._conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (credential_id,),
            ).fetchone()
            return self._delegation_view_locked(d)

    def _clamp_delegation_ttl(self, ttl_ms: int | None) -> int:
        ttl = (int(ttl_ms) if ttl_ms is not None
               else self.default_delegation_ttl_ms)
        return max(MIN_TTL_MS, min(ttl, self.delegation_max_ttl_ms))

    # ---- 限时委托：提前撤销 ---------------------------------------------
    def revoke_delegation(
        self,
        resource: str,
        holder: str,
        generation: int,
        credential_id: Any,
    ) -> dict[str, Any]:
        """授权者提前撤销委托。撤销与状态变更同事务落库并留历史，
        撤销返回后任何迟到的凭证写入必然被拒。"""
        with self._lock:
            self._reap_locked()
            now = self.clock.wall_ms()

            if credential_id in (None, ""):
                self._record_event_locked(
                    resource, "delegate_revoke", "rejected", holder,
                    generation=generation, detail="missing_credential_id",
                    now=now,
                )
                self._conn.commit()
                raise Conflict("缺少必填参数: credential_id")
            credential_id = str(credential_id)

            d = self._conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (credential_id,),
            ).fetchone()
            if d is None or d["resource"] != resource:
                # 无可归属凭证：不制造针对别的资源的事件
                raise DelegationNotFound(
                    f"委托凭证 {credential_id} 不存在或不属于资源 {resource}"
                )

            def reject(detail: str) -> None:
                self._record_event_locked(
                    resource, "delegate_revoke", "rejected", holder,
                    peer=d["collaborator"], lease_id=d["lease_id"],
                    generation=generation, credential_id=credential_id,
                    detail=detail, now=now,
                )
                self._conn.commit()

            if d["authorizer"] != holder or d["generation"] != generation:
                reject("holder_or_generation_mismatch")
                raise Conflict(
                    "只有发放该委托的授权者且出示其当时的世代号才能撤销"
                )
            if d["state"] != DEL_STATE_ACTIVE:
                reject(f"already_{d['state']}")
                raise Conflict(
                    f"委托凭证 {credential_id} 已处于 {d['state']} 状态，"
                    "无需也不能再次撤销"
                )

            self._conn.execute(
                "UPDATE delegations SET state=?, end_reason=? "
                "WHERE credential_id=?",
                (DEL_STATE_REVOKED, END_DELEGATION_REVOKED, credential_id),
            )
            self._record_event_locked(
                resource, "delegate_revoke", "ok", holder,
                peer=d["collaborator"], lease_id=d["lease_id"],
                generation=d["generation"], credential_id=credential_id,
                detail=END_DELEGATION_REVOKED, now=now,
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (credential_id,),
            ).fetchone()
            return self._delegation_view_locked(row)

    # ---- 受租约保护的写入（栅栏点） -------------------------------------
    def write(
        self,
        resource: str,
        holder: str,
        generation: int | None,
        value: str,
        *,
        credential_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            # 收割在锁内先跑：撤销已落库或委托已到期，本次调用必然看到，
            # 杜绝"既能写又已撤销/已过期"的中间态
            self._reap_locked()
            now = self.clock.wall_ms()
            if credential_id is not None:
                return self._write_with_delegation_locked(
                    resource, holder, credential_id, generation, value, now=now
                )

            row = self._get_active_locked(resource)

            def record(accepted: bool, reason: str | None) -> dict[str, Any]:
                cur = self._conn.execute(
                    "INSERT INTO writes(resource, generation, lease_id, "
                    "holder, accepted, reject_reason, created_at_ms, "
                    "credential_id) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        resource, generation, row["id"] if row else "",
                        holder, 1 if accepted else 0, reason, now, None,
                    ),
                )
                self._record_event_locked(
                    resource, "write", "ok" if accepted else "rejected",
                    holder, lease_id=row["id"] if row else None,
                    generation=generation,
                    detail=f"write_id={cur.lastrowid}" if accepted else reason,
                    value=value if accepted else None,
                    now=now,
                )
                self._conn.commit()
                return {
                    "write_id": cur.lastrowid, "resource": resource,
                    "holder": holder, "generation": generation,
                    "accepted": accepted, "reject_reason": reason,
                }

            if row is None:
                record(False, "no_active_lease")
                raise LeaseGone(f"资源 {resource} 没有生效中的租约")
            if row["holder"] != holder or row["generation"] != generation:
                record(False, "generation_fence")
                raise GenerationTooSmall(
                    f"世代号 {generation} 不是资源 {resource} 的当前世代 "
                    f"{row['generation']}（持有者 {row['holder']}），写入被拒绝"
                )

            res = self._conn.execute(
                "SELECT * FROM resources WHERE resource=?", (resource,)
            ).fetchone()
            # 栅栏不变量：当前世代号不落后于已放行号。
            # 同一租约可重复写入（generation == last_passed_gen 属正常），
            # 只有更旧的世代号才越界——而上面的生效租约校验已排除这种情况。
            assert generation >= res["last_passed_gen"]
            self._conn.execute(
                "UPDATE resources SET value=?, updated_by_gen=?, updated_at_ms=?, "
                "last_passed_gen=? WHERE resource=?",
                (value, generation, now, generation, resource),
            )
            out = record(True, None)
            out["value"] = value
            return out

    # ---- 凭委托凭证的写入（委托只授予写，且与授权租约共用世代栅栏） ------
    def _write_with_delegation_locked(
        self,
        resource: str,
        holder: str,
        credential_id: str,
        claimed_generation: int | None,
        value: str,
        *,
        now: int,
    ) -> dict[str, Any]:
        d = self._conn.execute(
            "SELECT * FROM delegations WHERE credential_id=?", (credential_id,)
        ).fetchone()
        # 伪造的凭证，或拿 A 资源的凭证写 B 资源：不存在可挂载的租约/世代，
        # writes 表里没有对应行，只在统一历史留一条拒绝事件
        if d is None or d["resource"] != resource:
            self._record_event_locked(
                resource, "delegate_write", "rejected", holder,
                generation=claimed_generation, credential_id=credential_id,
                detail=REJECT_UNKNOWN_CREDENTIAL, now=now,
            )
            self._conn.commit()
            raise DelegationNotFound(
                f"委托凭证 {credential_id} 不存在或不属于资源 {resource}，"
                "写入被拒绝"
            )

        # 取生效租约；若授权租约恰在此时被判定过期，这里会在同一事务里
        # 连带把该凭证置为 fenced（_expire_locked -> _fence_delegations_locked）
        row = self._get_active_locked(resource)
        d = self._conn.execute(
            "SELECT * FROM delegations WHERE credential_id=?", (credential_id,)
        ).fetchone()

        def record(accepted: bool, reason: str | None) -> dict[str, Any]:
            cur = self._conn.execute(
                "INSERT INTO writes(resource, generation, lease_id, holder, "
                "accepted, reject_reason, created_at_ms, credential_id) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    resource, d["generation"], d["lease_id"], holder,
                    1 if accepted else 0, reason, now, credential_id,
                ),
            )
            self._record_event_locked(
                resource, "delegate_write",
                "ok" if accepted else "rejected", holder,
                peer=d["authorizer"], lease_id=d["lease_id"],
                generation=d["generation"], credential_id=credential_id,
                detail=f"write_id={cur.lastrowid}" if accepted else reason,
                value=value if accepted else None,
                now=now,
            )
            self._conn.commit()
            return {
                "write_id": cur.lastrowid, "resource": resource,
                "holder": holder, "generation": d["generation"],
                "accepted": accepted, "reject_reason": reason,
                "credential_id": credential_id,
                "authorizer": d["authorizer"],
                "collaborator": d["collaborator"],
            }

        # 防御性到期（正常情况下锁内 _reap_locked 已先处理过）
        if d["state"] == DEL_STATE_ACTIVE and now >= d["expires_wall_ms"]:
            self._conn.execute(
                "UPDATE delegations SET state=?, end_reason=? "
                "WHERE credential_id=?",
                (DEL_STATE_EXPIRED, END_DELEGATION_EXPIRED, credential_id),
            )
            self._record_event_locked(
                resource, "delegate_expire", "ok", d["authorizer"],
                peer=d["collaborator"], lease_id=d["lease_id"],
                generation=d["generation"], credential_id=credential_id,
                detail=END_DELEGATION_EXPIRED, now=now,
            )
            d = self._conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (credential_id,),
            ).fetchone()

        # 1) 凭证必须仍生效：撤销/过期/原租约结束一律拒绝迟到写入
        if d["state"] != DEL_STATE_ACTIVE:
            reason = self._delegation_reject_reason_locked(d)
            record(False, reason)
            raise DelegationRejected(
                f"委托凭证 {credential_id} 已{self._delegation_state_cn(d)}"
                f"（{reason}），写入被拒绝"
            )

        # 2) 只有凭证指定的协作者本人能用
        if holder != d["collaborator"]:
            record(False, REJECT_COLLABORATOR_MISMATCH)
            raise DelegationRejected(
                f"凭证 {credential_id} 只授权给协作者 {d['collaborator']}，"
                f"{holder} 的写入被拒绝"
            )

        # 3) 客户端若带了世代号，必须与凭证锚定的那一代一致
        if (
            claimed_generation is not None
            and int(claimed_generation) != d["generation"]
        ):
            record(False, "generation_fence")
            raise DelegationRejected(
                f"凭证 {credential_id} 锚定世代 {d['generation']}，"
                f"请求携带 {claimed_generation}，写入被拒绝"
            )

        # 4) 栅栏核心：原租约必须仍是发放时那一代的生效租约。
        #    释放/转移/过期的同事务栅栏已覆盖所有正常路径，这里是最终防线。
        if (
            row is None
            or row["id"] != d["lease_id"]
            or row["generation"] != d["generation"]
        ):
            reason = self._fence_by_lease_state_locked(d)
            record(False, reason)
            raise DelegationRejected(
                f"授权租约已结束（{reason}），委托凭证 {credential_id} "
                "的迟到写入被拒绝"
            )

        res = self._conn.execute(
            "SELECT * FROM resources WHERE resource=?", (resource,)
        ).fetchone()
        # 与持有者直写共用同一道栅栏：委托世代不落后于已放行号
        assert d["generation"] >= res["last_passed_gen"]
        self._conn.execute(
            "UPDATE resources SET value=?, updated_by_gen=?, updated_at_ms=?, "
            "last_passed_gen=? WHERE resource=?",
            (value, d["generation"], now, d["generation"], resource),
        )
        out = record(True, None)
        out["value"] = value
        return out

    @staticmethod
    def _delegation_state_cn(d) -> str:
        return {
            DEL_STATE_REVOKED: "撤销",
            DEL_STATE_EXPIRED: "过期",
            DEL_STATE_FENCED: "随原租约结束而失效",
        }.get(d["state"], "失效")

    @staticmethod
    def _delegation_reject_reason_locked(d) -> str:
        if d["state"] == DEL_STATE_REVOKED:
            return REJECT_DELEGATION_REVOKED
        if d["state"] == DEL_STATE_EXPIRED:
            return REJECT_DELEGATION_EXPIRED
        if d["state"] == DEL_STATE_FENCED:
            return d["end_reason"] or FENCE_LEASE_EXPIRED
        return "delegation_not_active"

    def _fence_by_lease_state_locked(self, d) -> str:
        """最终防线：凭证仍 active 但绑定租约已不是当前生效租约。
        按租约终态补上 fenced 状态与历史事件，返回对应拒绝原因。"""
        lease = self._conn.execute(
            "SELECT * FROM leases WHERE id=?", (d["lease_id"],)
        ).fetchone()
        if lease is None or lease["state"] == STATE_EXPIRED:
            reason = FENCE_LEASE_EXPIRED
        elif lease["state"] == STATE_RELEASED:
            reason = FENCE_LEASE_RELEASED
        elif lease["state"] == STATE_TRANSFERRED:
            reason = FENCE_LEASE_TRANSFERRED
        else:
            reason = FENCE_LEASE_EXPIRED
        cur = self._conn.execute(
            "UPDATE delegations SET state=?, end_reason=? "
            "WHERE credential_id=? AND state=?",
            (DEL_STATE_FENCED, reason, d["credential_id"], DEL_STATE_ACTIVE),
        )
        if cur.rowcount:
            self._record_event_locked(
                d["resource"], "delegate_fence", "ok", d["authorizer"],
                peer=d["collaborator"], lease_id=d["lease_id"],
                generation=d["generation"], credential_id=d["credential_id"],
                detail=reason,
            )
        return reason

    # ---- 查询 -----------------------------------------------------------
    def get_lease(self, resource: str) -> dict[str, Any] | None:
        with self._lock:
            self._reap_locked()
            row = self._conn.execute(
                "SELECT * FROM leases WHERE resource=? "
                "ORDER BY generation DESC LIMIT 1", (resource,),
            ).fetchone()
            if row is None:
                return None
            status = self._classify_locked(row)
            if status["state"] == STATE_ACTIVE:
                return self._lease_view_locked(row)
            return {
                "resource": resource,
                "state": status["state"],
                "expire_reason": status["expire_reason"],
            }

    def get_resource(self, resource: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM resources WHERE resource=?", (resource,)
            ).fetchone()
            if row is None:
                return None
            return {
                "resource": resource,
                "current_generation": row["current_gen"],
                "last_passed_generation": row["last_passed_gen"],
                "value": row["value"],
                "updated_by_generation": row["updated_by_gen"],
                "updated_at_ms": row["updated_at_ms"],
            }

    def list_writes(self, resource: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM writes WHERE resource=? ORDER BY id DESC LIMIT ?",
                (resource, int(limit)),
            ).fetchall()
            return [
                {
                    "write_id": r["id"], "resource": r["resource"],
                    "generation": r["generation"], "lease_id": r["lease_id"],
                    "holder": r["holder"], "accepted": bool(r["accepted"]),
                    "reject_reason": r["reject_reason"],
                    "created_at_ms": r["created_at_ms"],
                    "credential_id": r["credential_id"],
                }
                for r in rows
            ]

    def get_write(self, write_id: int) -> dict[str, Any] | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM writes WHERE id=?", (int(write_id),)
            ).fetchone()
            if r is None:
                return None
            return {
                "write_id": r["id"], "resource": r["resource"],
                "generation": r["generation"], "lease_id": r["lease_id"],
                "holder": r["holder"], "accepted": bool(r["accepted"]),
                "reject_reason": r["reject_reason"],
                "created_at_ms": r["created_at_ms"],
                "credential_id": r["credential_id"],
            }

    def list_history(
        self,
        resource: str,
        limit: int = 200,
        credential_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """按资源返回统一租约历史，按审计顺序（seq）从旧到新排列。

        可传 credential_id 只看某张委托凭证的完整轨迹：发放、每次使用
        （含被拒绝）、撤销/过期/连带失效，以及它锚定的授权者与世代号。
        """
        with self._lock:
            if credential_id is not None:
                rows = self._conn.execute(
                    "SELECT * FROM lease_events WHERE resource=? "
                    "AND credential_id=? ORDER BY seq DESC LIMIT ?",
                    (resource, str(credential_id), int(limit)),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM lease_events WHERE resource=? "
                    "ORDER BY seq DESC LIMIT ?",
                    (resource, int(limit)),
                ).fetchall()
            return [
                {
                    "seq": r["seq"], "resource": r["resource"],
                    "event": r["event"], "outcome": r["outcome"],
                    "holder": r["holder"], "peer": r["peer"],
                    "lease_id": r["lease_id"], "generation": r["generation"],
                    "to_lease_id": r["to_lease_id"],
                    "to_generation": r["to_generation"],
                    "credential_id": r["credential_id"],
                    "detail": r["detail"],
                    "wall_ms": r["wall_ms"], "logical": r["logical"],
                }
                for r in reversed(rows)
            ]

    # ---- 委托查询 -------------------------------------------------------
    def get_delegation(self, credential_id: str) -> dict[str, Any] | None:
        """按凭证号查委托全文：授权者、协作者、有效期、锚定世代号与状态。"""
        with self._lock:
            # 顺带把已到期/租约已结束的状态收敛，查询即看到真实终态
            self._reap_locked()
            d = self._conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (str(credential_id),),
            ).fetchone()
            if d is None:
                return None
            d = self._refresh_delegation_locked(d)
            return self._delegation_view_locked(d)

    def list_delegations(
        self, resource: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        with self._lock:
            self._reap_locked()
            rows = self._conn.execute(
                "SELECT * FROM delegations WHERE resource=? "
                "ORDER BY granted_wall_ms DESC, credential_id DESC LIMIT ?",
                (resource, int(limit)),
            ).fetchall()
            return [
                self._delegation_view_locked(self._refresh_delegation_locked(d))
                for d in rows
            ]

    def _refresh_delegation_locked(self, d):
        """查询时的惰性收敛：已过墙钟 -> expired；仍 active 但绑定租约
        已非当前生效租约 -> 按租约终态补 fenced（与写入路径同一套规则）。"""
        if d["state"] != DEL_STATE_ACTIVE:
            return d
        now = self.clock.wall_ms()
        if now >= d["expires_wall_ms"]:
            self._conn.execute(
                "UPDATE delegations SET state=?, end_reason=? "
                "WHERE credential_id=?",
                (DEL_STATE_EXPIRED, END_DELEGATION_EXPIRED,
                 d["credential_id"]),
            )
            self._record_event_locked(
                d["resource"], "delegate_expire", "ok", d["authorizer"],
                peer=d["collaborator"], lease_id=d["lease_id"],
                generation=d["generation"], credential_id=d["credential_id"],
                detail=END_DELEGATION_EXPIRED, now=now,
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (d["credential_id"],),
            ).fetchone()
        lease = self._conn.execute(
            "SELECT * FROM leases WHERE id=?", (d["lease_id"],)
        ).fetchone()
        if lease is not None and lease["state"] == STATE_ACTIVE:
            status = self._classify_locked(lease)
            if status["state"] != STATE_ACTIVE:
                # _expire_locked 已在同一事务连带 fence 并落事件
                self._expire_locked(lease, status["expire_reason"])
                self._conn.commit()
                return self._conn.execute(
                    "SELECT * FROM delegations WHERE credential_id=?",
                    (d["credential_id"],),
                ).fetchone()
            return d
        if lease is None or lease["state"] != STATE_ACTIVE:
            self._fence_by_lease_state_locked(d)
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM delegations WHERE credential_id=?",
                (d["credential_id"],),
            ).fetchone()
        return d

    def _delegation_view_locked(self, d) -> dict[str, Any]:
        return {
            "credential_id": d["credential_id"],
            "resource": d["resource"],
            "authorizer": d["authorizer"],
            "collaborator": d["collaborator"],
            "lease_id": d["lease_id"],
            "generation": d["generation"],
            "state": d["state"],
            "end_reason": d["end_reason"],
            "granted_wall_ms": d["granted_wall_ms"],
            "expires_wall_ms": d["expires_wall_ms"],
            "ttl_ms": d["expires_wall_ms"] - d["granted_wall_ms"],
            "created_at_ms": d["created_at_ms"],
        }

    def _lease_view_locked(self, row, state: str = STATE_ACTIVE) -> dict[str, Any]:
        logical = self.clock.logical()
        return {
            "resource": row["resource"],
            "lease_id": row["id"],
            "holder": row["holder"],
            "generation": row["generation"],
            "state": state,
            "granted_wall_ms": row["granted_wall_ms"],
            "wall_deadline_ms": row["wall_deadline_ms"],
            "hard_wall_deadline_ms": row["hard_wall_deadline_ms"],
            "last_seen_logical": row["last_seen_logical"],
            "current_logical": logical,
            "logical_grace": row["logical_grace"],
            "logical_stall_after": row["last_seen_logical"] + row["logical_grace"],
            "renewed_count": row["renewed_count"],
        }
