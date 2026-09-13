# 双时钟栅栏租约服务（Fencing-Lease Service）

谁持有租约，谁才能对资源做改动。租约的过期判定**同时**参考墙上时间和逻辑时间，
任何一种时钟被操纵都不会导致错误回收或租约永生；每次租约交接发放严格递增的
**世代号（fencing token）**，过期世代号的写入一律拒绝，且所有写入可审计。

## 为什么要两个时钟

| 故障 | 只信墙上时间 | 只信逻辑时间 | 本服务 |
|---|---|---|---|
| 墙上时钟被 NTP/运维拨快 | 正在干活的租约被误回收 ❌ | 不受影响 | 越过软 TTL，但逻辑心跳在宽限内仍推进 → **不回收** ✅ |
| 逻辑时间卡死（ticker 挂起） | 不受影响 | 租约永不结束 ❌ | 发放时写死的**硬墙钟上限**一到 → **强制结束** ✅ |
| 双时钟都沉默 | 正常过期 | 正常过期 | 两者一致沉默超过宽限 → 过期 ✅ |

每代租约落库三个时间量：

- `wall_deadline_ms`：软墙钟期限（发放墙钟 + TTL），续约可顺延；
- `hard_wall_deadline_ms`：**硬墙钟上限**（发放墙钟 + `LEASE_HARD_TTL_MS`），
  发放后固定，续约不能越过。设置时必须大于环境中可能出现的最大时钟跳变；
- `last_seen_logical` + `logical_grace`：最近一次心跳时的逻辑钟读数与宽限 tick 数。

生效条件（两者必须同时成立）：

```
wall_ms < hard_wall_deadline_ms
且 (wall_ms < wall_deadline_ms 或 logical_now <= last_seen_logical + grace)
```

## 世代号栅栏（fencing）

- 每个资源维护持久化单调递增的 `current_gen`，每次获取（不是续约）+1；
- 写入必须出示 `holder + generation`，服务端校验它就是**当前生效那一代**；
- 旧持有者即使持有未过期的租约，释放或过期后也无法再写：
  下一任的世代号严格更大，迟到的旧号写入得到 `409 generation_fence`；
- 资源记录 `last_passed_generation`，并对每次写入（含被拒的）留审计：
  可通过 `GET /writes/<id>` 查出某次写入是**哪一代租约、哪个 lease_id、哪个持有者**放行的。

## 安全转移（transfer）

持有者可以把**仍有效**的租约直接转给指定接收者，无需先释放再重新获取：

```
POST /leases/transfer
{"resource":"r","holder":"node-a","generation":3,"to_holder":"node-b","transfer_id":"xfer-001"}
```

- **原子交接**：旧租约置为 `transferred`、世代号 +1、以更大世代号向接收者发放新租约，
  全部在同一个事务里完成——旧持有者即刻失去写权限，新持有者即刻可写，
  崩溃只会整体回滚，不会留下半完成状态；
- **幂等**：`transfer_id` 是幂等键。同一笔转移重复提交（网络重试）返回首次结果
  （HTTP 200 + `"replayed": true`），不会再次转移；同一 `transfer_id` 搭配不同参数
  （换接收者/换世代号）直接 409 拒绝；
- **防重放**：转移完成后，旧持有者的 `holder + generation` 对转移/续约/释放/写入
  一律被拒（409），并全部记入历史；
- **接收者资格**：`to_holder` 必须是非空字符串且不能是当前持有者自己，
  不合格时拒绝且不产生任何状态变化；
- 新租约按 `ttl_ms`（缺省用默认 TTL）重新计时，硬墙钟上限也从交接时刻重新起算。

## 限时委托（delegation）

持有者可以为**指定协作者**发放一张**只针对某个资源**的短期委托凭证，协作者凭凭证
可以连续写入，但仅此而已：

```
POST /leases/delegations
{"resource":"r","holder":"node-a","generation":3,"collaborator":"node-d","ttl_ms":5000}
```

协作者写入时带上 `credential_id`（世代号可省略，由凭证锚定）：

```
POST /resources/r/writes
{"holder":"node-d","credential_id":"ab12...","value":"..."}
```

语义：

- **只授写权**：协作者不能续约、释放、转移，也不能再转委托——这些入口只认生效租约的
  `holder + generation`，协作者的请求一律 409；凭证也**只对发放时指定的那一个资源有效**；
- **短期、只信墙钟、不可续**：委托到期由墙钟判定（`expires_wall_ms`，发放时固定），
  且永远短于授权租约的硬墙钟上限——租约可能因逻辑心跳在软 TTL 后继续存活，
  委托则没有这种续命，到期即死；
- **同一道世代号栅栏**：委托锚定发放时授权租约的 `lease_id + generation`，协作者的写入
  与持有者直写走完全相同的栅栏，`last_passed_generation` 照常推进；
- **提前撤销**：授权者（且只有授权者本人）可随时
  `POST /leases/delegations/revoke`；撤销与状态变更在同一事务落库，
  撤销返回后的任何迟到凭证写入必然被拒（`409 delegation_rejected`）；
- **随原租约连带失效**：授权租约被释放、安全转移或过期时，其名下所有生效委托在
  **同一事务**里被置为 `fenced`（原因分别是 `source_lease_released` /
  `source_lease_transferred` / `source_lease_expired`）。转移后的新持有者不受影响；
- **迟到写入必拒**：已撤销、已过期、已连带失效的凭证、非指定协作者冒用、
  凭证串资源、携带错误世代号，全部拒绝，且拒绝同样进入写入审计与统一历史。

凭证与历史查询：

| 接口 | 说明 |
|---|---|
| `GET /delegations/<credential_id>` | 按凭证号查授权者、协作者、有效期、锚定世代号、状态与终态原因 |
| `GET /resources/<r>/delegations` | 列某资源上的全部委托 |
| `GET /resources/<r>/history?credential_id=<id>` | 按凭证号过滤：发放、每次使用结果（含拒绝）、撤销、过期、连带失效 |

委托事件与租约事件同处一份历史、共享同一个全局审计序号（`seq`）：
`delegate_grant` / `delegate_write` / `delegate_revoke` / `delegate_expire` /
`delegate_fence`，成功为 `ok`，拒绝为 `rejected`（`detail` 给原因）。
重启后凭证状态、终态原因与审计顺序完全一致；进程启动时即按墙钟收割已到期凭证。

## 完整租约历史

`GET /resources/<r>/history` 按审计顺序（`seq` 全局单调递增，重启后延续）返回该资源的
每一次**获取、续约、释放、转移、写入、委托发放/使用/撤销/过期/连带失效**，
成功（`"outcome":"ok"`）与拒绝
（`"outcome":"rejected"`，`detail` 给出原因）都留痕。每条事件包含：

| 字段 | 含义 |
|---|---|
| `seq` | 全局单调递增序号，即审计顺序 |
| `event` / `outcome` | 操作类型（acquire/renew/release/transfer/write/delegate_grant/delegate_write/delegate_revoke/delegate_expire/delegate_fence）与结果（ok/rejected） |
| `holder` / `peer` | 操作发起者 / 另一方（转移接收者、委托协作者、获取冲突时的持有者） |
| `lease_id` / `generation` | 相关租约编号与世代号 |
| `to_lease_id` / `to_generation` | 仅转移事件：新租约编号与新世代号 |
| `credential_id` | 委托事件：涉及的委托凭证（可按它过滤历史） |
| `detail` | 拒绝原因（如 `generation_fence`、`ineligible_recipient`、`transfer_id_conflict`、`delegation_revoked`）或补充（如 `write_id=N`、`expires_wall_ms=...`） |
| `wall_ms` / `logical` | 事件发生时的墙钟与逻辑钟读数 |

## 审计回放与一致性诊断（只读）

管理员可以针对某个**资源**或某张**委托凭证**，按时间范围或历史序号查看完整事件流，
并在任意历史节点还原"当时的资源值、当前租约、委托状态与世代号"，还能比较两个节点、
对历史做一致性诊断。所有审计接口都是**只读**的：只执行 SELECT，绝不调用过期收割、
绝不改动正在运行的租约和委托（每个响应都带 `"read_only": true`）。

### 稳定视图（snapshot）与固定分页

- 每个审计响应都带 `view.snapshot_seq`（本次读看到的最大审计序号）与
  `view.latest_seq`（全局最新序号）；
- 回传 `?snapshot=<seq>` 即可把整组分页/回放/比较/诊断固定在**同一份历史**上：
  并发写入要么整体在快照之前、要么整体在之后，绝不会读到半套状态；
- 事件一律按全局 `seq` **升序**返回；分页用游标 `?after=<上一页最后一条 seq>&limit=`，
  顺序固定，响应里 `next` 是下一页游标，`reached_end` 表示到末尾；
- 历史是只增的 SQLite 记录，**服务重启后对同一份历史得到完全相同的结果**。

### 事件流接口

| 接口 | 作用域 |
|---|---|
| `GET /audit/events` | 全资源交错事件流（按全局 seq 升序） |
| `GET /resources/<r>/audit/events` | 某资源的完整事件流 |
| `GET /delegations/<credential_id>/audit/events` | 某委托凭证的完整轨迹 |

通用查询参数（可任意组合）：

| 参数 | 含义 |
|---|---|
| `from_ms` / `to_ms` | 墙钟时间范围（闭区间，按事件 `wall_ms` 过滤） |
| `seq_min` / `seq_max` | 历史序号范围 |
| `after` / `limit` | 分页游标与页大小（1–1000，默认 100） |
| `outcome=ok,rejected` | 只看被接受/被拒绝的操作 |
| `event=write,transfer,...` | 只看指定事件类型 |
| `snapshot` | 固定稳定视图上界 |

每条事件除原有字段外还带：

- `accepted`：布尔，操作是否被接受；
- `value`：被接受的写入事件当时落下去的资源值；
- `narration`：中文叙述，说明**这一步是什么操作、被接受还是被拒绝、涉及谁、
  拒绝原因是什么**（例如"协作者 node-y 持委托凭证 … 的写入被拒绝：
  请求者不是凭证指定的协作者（授权者 node-1，锚定世代号 1）"）。

### 历史节点回放

```
GET /resources/<r>/audit/replay?head=1
GET /resources/<r>/audit/replay?at_seq=12
GET /resources/<r>/audit/replay?at_wall_ms=1750000000000
GET /delegations/<credential_id>/audit/replay?head=1
```

节点三选一（必须且只能给一个）：`head`（视图内最新）、`at_seq`（精确序号）、
`at_wall_ms`（该时刻含之前最后一条事件）。响应包含：

- `node`：被还原到的那个事件（含中文叙述、接受与否、涉及谁）；
- `state_as_of_node.resource`：**当时的资源值**、值来源事件序号、
  已放行最大世代号、资源当前（当时）世代号；
- `state_as_of_node.lease`：**当时的当前租约**（持有者、世代号、active/released/
  transferred/expired、续约次数、如何收尾）；
- `state_as_of_node.generations`：到该节点为止发放过的全部世代号；
- `state_as_of_node.delegations`：**当时各委托凭证的状态**（active/revoked/
  expired/fenced、终态原因与终态事件序号、接受/拒绝写入次数）。

凭证回放额外返回 `credential`（该凭证在节点处的状态）与其完整事件链。

### 两节点比较：第一次产生差异的事件

```
GET /resources/<r>/audit/compare?a_at_seq=3&b_head=1
GET /resources/<r>/audit/compare?a_at_seq=2&b_at_seq=9
```

两端各支持 `a_/b_` 前缀 + `at_seq|at_wall_ms|head`，要求 a 不晚于 b。响应给出：

- `identical`：两节点业务状态是否完全一致；
- `first_divergence`：**(a,b] 之间第一条让状态偏离 a 的事件**（被拒绝的操作
  不改变状态，不会成为差异点）及其 `changed_fields`；
- `state_at_first_divergence`：首异事件发生后每个变化字段在 a 点与该点的值；
- `changed_fields_at_b`：到 b 点为止所有变化字段的前后值（资源值、当前租约
  持有者/世代号、各凭证状态等）；
- `rejected_events_between`：区间内被拒绝的操作与原因（它们不产生状态差异）。

### 一致性诊断

```
GET /resources/<r>/audit/diagnose          # 单资源
GET /delegations/<credential_id>/audit/diagnose   # 单凭证
GET /audit/diagnose                        # 全局
```

诊断由事件流纯重放 + 与运行态审计表勾稽得到，输出 `issues`（每条带 `severity`、
`seq`、`code`、中文 `message`）与 `summary`（按严重度与错误码计数，
`consistent` 为 true 表示无 error）。可识别的问题包括：

- **序号缺失**：`seq_missing`（全局 1..MAX 之间缺号，说明事件被删/损坏/绕过审计；
  不同资源交错占用序号造成的"缺口"属正常，不会误报）；
- **序号重复/重号**：`seq_duplicate`、`write_id_duplicate`；
- **乱序**：`logical_clock_regressed`（逻辑钟只增不减，回退即篡改痕迹；
  墙钟回拨 `wall_clock_moved_backward` 记为 info）；
- **状态互相矛盾**，例如：
  - 成功的获取/续约/释放/转移在投影中找不到匹配的生效租约
    （`*_without_matching_active_lease`、`active_lease_superseded_without_handover`）；
  - 成功写入的持有者/租约/世代号与生效租约对不上（栅栏被绕过的迹象）；
  - 转移后世代号没有严格增大、成功转移缺少新租约；
  - 委托凭证重复发放、无发放却有撤销/过期/栅栏、同一凭证被终止两次；
  - 委托写入在凭证已失效/协作者不符/授权租约已换代时仍被标记接受；
  - 事件与 `leases`/`writes`/`transfers`/`delegations` 表勾稽不符（跨表矛盾）。

### 显式错误（不生成误导性空报告）

| 场景 | 状态码 | error |
|---|---|---|
| 资源没有任何历史 / 凭证不存在 | 404 | `history_not_found` / `credential_not_found` |
| `at_seq` 不存在、属于别的资源、越过 `snapshot` 上界 | 416 | `node_out_of_range`（附 `available_min_seq/available_max_seq` 等可用范围） |
| `at_wall_ms` 早于首条事件、翻页游标越过末条事件、`snapshot` 超过最新序号 | 416 | `node_out_of_range` |
| 时间/序号/过滤窗口内没有事件 | 404 | `no_events_in_range`（附事件实际区间） |
| 节点选择器缺失/给了多个、参数非整数、`outcome/limit` 非法、a 晚于 b | 400 | `bad_request` |

## 可验证审计归档（verifiable archive）

审计回放是"随查随算"，归档则把某个**资源**或某张**委托凭证**在某个稳定历史
节点上的"当时状态"**冻结**成一份只读文档：事件范围、回放状态、诊断结果与内容
校验值在创建时钉死，之后无论租约怎么变化，归档都逐字节不变，可下载、可独立核验。

### 创建（幂等）

```
POST /audit/archives
{"scope":"resource","resource":"cfg-1","at_seq":12,"idempotency_key":"audit-2026-09"}
{"scope":"credential","credential_id":"ab12...","head":true,"idempotency_key":"k-2"}
```

- 节点选择器与回放一致：`at_seq` / `at_wall_ms` / `head` 三选一（必填）；
- `idempotency_key` **必填**。**同一对象 + 同一节点 + 同一幂等键**重复创建
  只会得到同一份归档（HTTP 200 + `"replayed": true`）；同一幂等键配不同节点
  直接 409（`archive_id_conflict`）——系统里绝不会出现两份互相矛盾的归档。
  换幂等键对同一节点再归档是允许的，且历史内容（事件/回放状态/诊断）必然一致；
- 创建即钉死两个上界：`node_seq`（归档的事件上界）与 `snapshot_seq`
  （创建时的稳定视图上界）。归档只含 `seq <= node_seq` 的作用域事件——
  **生成期间再有新的租约写入也进不了归档**，不会读到半套事件；
- 创建返回 201 与归档视图（含 `archive_id`、进度），生成由后台分块进行。

### 生成进度与断点续跑

- 后台 worker 按块（`ARCHIVE_CHUNK_SIZE`，默认 100 条）把事件冻结进
  `archive_events` 表，每块提交后进度落库
  （`GET /audit/archives/<id>` 可见 `processed_events / total_events / percent`）；
- **服务重启或后台失败**：`pending/building/failed` 的归档从已保存的
  `last_frozen_seq` 继续，启动即自动续跑；`archive_events` 主键
  `(archive_id, seq)` + `INSERT OR IGNORE` 保证**失败重试不会重复写入**；
- 自动重试有上限（5 次），`POST /audit/archives/<id>/retry` 可手动复位
  `failed` 归档（进度保留，只重置尝试计数）。

### 归档文档（下载）

`GET /audit/archives/<id>/download` 在完成后返回落库原文（字节稳定，
响应头带 `X-Archive-SHA256`）：

| 字段 | 含义 |
|---|---|
| `node_seq` / `snapshot_seq` / `node` | 冻结的历史节点与创建时稳定视图 |
| `event_range` / `events` | 事件范围（首末序号、条数）与全部事件原文 |
| `replay_state` | 该节点的回放状态：资源值、当前租约、世代号、各凭证状态（凭证归档另含 `credential` 视图） |
| `diagnosis` | 基于归档事件流的**纯重放诊断**（序号/时钟/状态矛盾），`basis=pure_replay_over_archived_events` |
| `content_sha256` | 内容校验值：对除本字段外的规范化 JSON（键排序）计算的 SHA-256，下载者可独立复算 |

### 独立核验（标记 verified / verify_failed）

`POST /audit/archives/<id>/verify` 对已完成的归档做三层独立核验，
并把结果标记在归档上（`verify_status`，重启不丢）：

1. 归档文档与保存的 `content_sha256` 一致（内容未被改动）；
2. 归档事件与**原始审计历史**同范围逐条逐字段一致（历史未被删改）；
3. 回放状态与诊断可由冻结事件**独立重算**得到（派生内容自洽）。

任一失败即标记 `verify_failed`，且 `verify_detail` / 响应的
`first_divergence` 给出**首个差异位置**（`section` / `path` / `seq` /
双方取值与中文说明），例如 `events[2]` 序号分叉、
`replay_state.resource.value` 被伪造。全部通过则标记 `verified`。

### 只读边界

归档的创建、生成、下载、核验只写 `archives` / `archive_events` 两张自有表，
**绝不修改正在运行的租约、委托和原始审计历史**（`lease_events` / `leases` /
`delegations` / `writes` 等一个字节都不动）；归档完成后当前租约照常可写。

| 场景 | 状态码 | error |
|---|---|---|
| 归档不存在 | 404 | `archive_not_found` |
| 未完成就下载/核验 | 409 | `archive_not_ready` |
| 同幂等键配不同节点 | 409 | `archive_id_conflict` |
| 对非 failed 归档发起重试 | 409 | `archive_bad_state` |
| 节点选择器缺失/多个、缺幂等键、非法 scope/status | 400 | `bad_request` |
| 资源无历史 / 凭证不存在 / 节点越界 | 404/416 | 与审计回放一致 |

## 审计证据包（audit evidence package）

管理员可以把多份**已完成**的资源归档或委托凭证归档（允许混合、允许重复、
也允许空组合）按给定的组合顺序组合成一份只读证据包。证据包在**创建时**
即冻结四样东西，之后任何操作都改不动它：

1. **归档清单**：每份源归档的标识、0 起的组合顺序、收录方式
   （`content` 收录原文 / `reference` 只收录稳定引用）；
2. **每份归档的内容校验值**：清单记录创建时源归档的 `content_sha256`
   （`source_sha256`）；
3. **组合顺序**：顺序是清单指纹的一部分，换顺序就是另一份证据包；
4. **生成时元数据**：创建墙钟、逻辑钟读数、稳定视图上界 `snapshot_seq`
   与可选 `metadata`（规范化 JSON 后冻结）。

### 创建（幂等 + 冲突显式化）

```
POST /audit/evidence
{"archives":["<archive_id>",
             {"archive_id":"<archive_id>", "include":"reference"}],
 "idempotency_key":"bundle-2026-Q3",
 "metadata":{"case":"incident-42", "operator":"admin"}}
```

- 清单条目可写裸字符串（默认 `include:"content"`）或对象；**同一组归档、
  同一组合顺序（含收录方式）、同一幂等键**重复创建只返回同一份证据包
  （HTTP 200 + `"replayed": true`）；
- **同键但换归档 / 换顺序 / 换收录方式** → 409 `evidence_id_conflict`，
  响应 `first_difference` 给出首个差异位置（如 `archives[1].archive_id`）、
  字段名与双方值；
- **不同键但清单完全相同** → 409 `evidence_manifest_conflict`，指向已存在
  的证据包与其幂等键——同一套证据不允许生成两份互相独立的"原件"；
- 源归档必须存在且已完成：不存在 → 404 `evidence_source_not_found`
  （附 `position`），未完成 → 409 `evidence_source_not_ready`；
- 创建返回 201 与证据包视图（含 `package_id`、进度、`manifest_fingerprint`），
  生成由后台按条目分块进行。

### 生成进度与断点续跑

- 后台 worker 按块（`EVIDENCE_CHUNK_SIZE`，默认每块 1 个条目）把源归档
  载荷冻结进 `evidence_entry_contents`，每块提交后进度落库
  （`GET /audit/evidence/<id>` 可见
  `processed_entries / total_entries / percent`）；
- **服务重启或后台失败**：`pending/building/failed` 的证据包从已保存的
  `last_frozen_position` 继续，启动即自动续跑；只对仍为 `pending` 的条目
  推进，冻结表主键 `(package_id, position)` + `INSERT OR IGNORE` 保证
  **失败重试不会重复写入**；
- 自动重试有上限（5 次），`POST /audit/evidence/<id>/retry` 可手动复位
  `failed` 证据包（进度保留，只重置尝试计数）；
- 冻结时会重新比对源归档当前内容哈希与创建时钉死的 `source_sha256`，
  不一致（源归档在生成期间被掉包）立即 `failed`，
  `error_detail` 给出归档标识、位置、字段路径与双方值，绝不静默收录。

### 冻结性

证据包一旦创建，**源归档被再次核验（verify 标记变化）或产生新的归档**
都不会改变证据包内容：清单、源哈希、内嵌原文在创建/冻结时就固定，
新归档不会混入，源归档节点之后的历史也进不来。证据包的全部操作只写
`evidence_packages` / `evidence_entries` / `evidence_entry_contents`
三张自有表，**绝不修改租约、委托、原始审计历史，甚至不写源归档行**
（`archives` / `archive_events` 对证据包只读）；证据包完成后当前租约
照常可写。

### 证据包文档（只读下载）

`GET /audit/evidence/<id>/download` 在完成后返回落库原文（字节稳定，
响应头带 `X-Evidence-SHA256`），文档包含：

| 字段 | 含义 |
|---|---|
| `manifest` | **可独立解析的清单**：每项含 `position`、`archive_id`、`include_mode`、创建时冻结的 `source_sha256`、冻结载荷哈希 `frozen_sha256` 与源归档的**稳定引用**（scope/resource/credential_id/node_seq/snapshot_seq/下载位置） |
| `sources[]` | 每份归档的收录载荷：`include:"content"` 内嵌**归档文档原文**（独立可解析 JSON，含其自身的校验值）；`include:"reference"` 只含归档标识与源哈希 |
| `combination.digest` | **组合摘要**：顺序敏感的链式哈希（`sha256-chain-v1`，从固定初值起，逐步混入 archive_id 与该位置冻结载荷哈希）；换顺序/换归档/改内容都会改变摘要，并附 `ordered_archive_ids` |
| `content_sha256` | **总校验值**：对除本字段外的规范化 JSON（键排序）计算的 SHA-256，下载者可独立复算 |
| `metadata` / `created_at_ms` / `created_logical` / `snapshot_seq` | 创建时冻结的生成元数据 |

### 独立核验（标记 verified / verify_failed）

`POST /audit/evidence/<id>/verify` 对已完成的证据包做独立核验，结果标记
在证据包上（`verify_status`，重启不丢）。核验**逐份**检查：

1. 证据包文档与保存的总校验值一致（文档未被改动）；
2. 组合摘要可由各收录载荷按组合顺序独立重算得到，且顺序与清单一致；
3. 清单完整：位置是连续的 0..N-1，文档条目与冻结载荷表逐条一致；
4. 每个位置的**源归档存在**、**源归档自身的独立核验未失败**
   （源归档处于 `verify_failed` 时其内容已不可信，证据包直接判失败）、
   源归档当前**内容哈希**与冻结的 `source_sha256` 一致、内嵌原文与源
   当前内容逐字段一致（reference 模式则核对稳定引用的定位信息）、内嵌
   原文自身的内容校验值可独立复算。

任一失败即标记 `verify_failed`，`verify_detail` / 响应的
`first_divergence` 给出**首个差异的归档标识**（`archive_id`）、
**字段路径**（如 `sources[1].source_sha256`）、位置与**双方值**
（`archived` / `recomputed`，缺失显示 `<missing>`），例如源归档被删除、
源归档自身核验失败（`sources[i].verify_status`，并附
`source_first_divergence` 指出该归档内的首个差异位置）、源内容哈希被改、
下载文档被篡改、冻结载荷被伪造、组合顺序被重排。
全部通过则标记 `verified`。

| 场景 | 状态码 | error |
|---|---|---|
| 证据包不存在 | 404 | `evidence_not_found` |
| 源归档不存在 / 未完成 | 404 / 409 | `evidence_source_not_found` / `evidence_source_not_ready` |
| 未完成就下载/核验 | 409 | `evidence_not_ready` |
| 同键不同清单（换归档/顺序/收录方式） | 409 | `evidence_id_conflict`（附首个差异） |
| 不同键但清单相同 | 409 | `evidence_manifest_conflict` |
| 对非 failed 证据包发起重试 | 409 | `evidence_bad_state` |
| archives 非数组、条目非法、缺幂等键、非法 include/metadata/status | 400 | `bad_request` |


## 持久性

SQLite（WAL 模式）存放在 `DB_PATH`（容器内 `/data/leases.db`），库中包含：
生效租约、每资源世代号、写入审计、**转移记录（幂等键）**、**限时委托凭证**、
**统一租约历史（含每条被接受写入当时的资源值，供事件溯源回放）**、
**审计归档与冻结事件副本（归档进度、内容校验值与核验标记）**、
**审计证据包与冻结清单/收录载荷（组合顺序、每份源归档内容哈希、
组合摘要、总校验值与核验标记）**、
逻辑钟读数和墙钟偏移。进程/容器重启后全部恢复，
正在生效的租约与委托不会丢失，历史与审计顺序保持一致，转移结果仍可幂等回放，
**审计回放、节点比较与一致性诊断对同一份历史给出逐字节一致的结果**；
启动时即按墙钟收割已到期的委托，并自动续跑未完成的归档与证据包生成。
旧版本数据库会在启动时自动补列迁移。
逻辑钟由后台 ticker 每秒 +1（每次推进都 fsync 落库）。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/leases/acquire` | `{resource, holder, ttl_ms?}` → 新世代号租约（201）；同持有者复用（200）；被占（409） |
| POST | `/leases/renew` | `{resource, holder, generation}` → 顺延软 TTL；租约已失效返回 412（须重新获取更大世代号） |
| POST | `/leases/release` | `{resource, holder, generation}` |
| POST | `/leases/transfer` | `{resource, holder, generation, to_holder, transfer_id?, ttl_ms?}` → 原子转移（201）；同 `transfer_id` 重提返回首次结果（200）；参数冲突/接收者不合格/旧凭证重放 409 |
| POST | `/leases/delegations` | `{resource, holder, generation, collaborator, ttl_ms?, credential_id?}` → 发放限时委托凭证（201）；非持有者/世代号不符/协作者不合格 409，无生效租约 412 |
| POST | `/leases/delegations/revoke` | `{resource, holder, generation, credential_id}` → 授权者提前撤销（200）；非授权者/已终态 409，凭证不存在 404 |
| POST | `/resources/<r>/writes` | `{holder, generation, value}` 持有者直写；或 `{holder, credential_id, value, generation?}` 凭委托写。世代号过期 409，无生效租约 412；委托已撤销/过期/连带失效/协作者不符 409，凭证不存在 404 |
| GET | `/resources/<r>` | 当前世代号、已放行最大世代号、当前值 |
| GET | `/resources/<r>/leases` | 当前租约全文（含三种期限与逻辑钟读数） |
| GET | `/resources/<r>/writes` | 该资源全部写入审计（含拒绝记录与委托凭证号） |
| GET | `/resources/<r>/delegations` | 该资源的全部委托凭证 |
| GET | `/resources/<r>/history` | **完整租约历史**：获取/续约/释放/转移/写入/委托，含被拒操作，按审计顺序；`?credential_id=<id>` 只看某张凭证的轨迹 |
| GET | `/delegations/<credential_id>` | **按凭证号查委托**：授权者、协作者、有效期、锚定世代号、状态/终态原因 |
| GET | `/writes/<id>` | **按写入 ID 反查：哪一代租约（或哪张委托凭证）放行** |
| GET | `/audit/events` | **全局审计事件流**（seq 升序、固定分页、稳定视图；支持时间/序号/类型/结果过滤） |
| GET | `/resources/<r>/audit/events` | 某资源的完整事件流（每条带 accepted、写入值与中文叙述） |
| GET | `/delegations/<id>/audit/events` | 某委托凭证的完整事件流 |
| GET | `/resources/<r>/audit/replay` | **历史节点回放**：`?head=1` / `?at_seq=` / `?at_wall_ms=` 三选一，还原当时资源值、当前租约、委托状态、世代号 |
| GET | `/delegations/<id>/audit/replay` | 凭证视角的节点回放（附当时资源/租约上下文） |
| GET | `/resources/<r>/audit/compare` | **比较两个历史节点**（`?a_at_seq=&b_at_seq=` 等），指出第一次产生差异的事件 |
| GET | `/resources/<r>/audit/diagnose` | 单资源一致性诊断：缺号/重号/乱序/状态矛盾/跨表勾稽 |
| GET | `/delegations/<id>/audit/diagnose` | 单凭证一致性诊断 |
| GET | `/audit/diagnose` | 全局一致性诊断（含全局 seq 缺号检查） |
| POST | `/audit/archives` | **创建只读审计归档**：`{scope, resource?/credential_id?, at_seq?/at_wall_ms?/head?, idempotency_key}`；同对象+同节点+同键返回同一份（200 回放），同键不同节点 409 |
| GET | `/audit/archives` | 列归档（`?scope=&resource=&credential_id=&status=&limit=`） |
| GET | `/audit/archives/<id>` | **查归档进度**：状态、已冻结/总事件数、内容校验值、核验标记 |
| GET | `/audit/archives/<id>/download` | **下载归档文档**（事件范围+回放状态+诊断+SHA-256 校验值；未完成 409） |
| POST | `/audit/archives/<id>/verify` | **独立核验**：通过标记 `verified`，失败标记 `verify_failed` 并给出首个差异位置 |
| POST | `/audit/archives/<id>/retry` | 手动复位 `failed` 归档，从已保存进度继续（非 failed 409） |
| POST | `/audit/evidence` | **创建审计证据包**：`{archives:[id|{archive_id,include}], idempotency_key, metadata?}`；同归档+同顺序+同键返回同一份（200 回放），同键不同清单/不同键同清单 409 |
| GET | `/audit/evidence` | 列证据包（`?status=&archive_id=&limit=`） |
| GET | `/audit/evidence/<id>` | **查证据包进度**：状态、已冻结/总条目数、组合摘要、总校验值、核验标记 |
| GET | `/audit/evidence/<id>/download` | **下载证据包文档**（清单+原文/稳定引用+组合摘要+总校验值；未完成 409） |
| POST | `/audit/evidence/<id>/verify` | **独立核验**：逐份检查源归档存在性/自身核验可信/内容哈希/原文与组合顺序完整性，失败给出首个差异的归档标识、字段路径与双方值 |
| POST | `/audit/evidence/<id>/retry` | 手动复位 `failed` 证据包，从已保存进度继续（非 failed 409） |
| POST | `/debug/tick` | 手动推进逻辑钟 `{steps?}` |
| POST | `/debug/wall-shift` | 演练拨表 `{delta_ms}`（偏移持久化） |
| GET | `/debug/now` | 两种时钟当前读数 |

生产环境关闭调试接口：`ENABLE_DEBUG_API=0`。

## Docker 部署

```bash
docker compose up -d --build
./demo.sh                 # 跑端到端演练
docker compose logs -f
```

数据在命名卷 `lease-data` 中；升级镜像重启容器不会丢租约。

不用 Docker 本地运行：

```bash
pip install -r requirements.txt
DB_PATH=./leases.db gunicorn -b 0.0.0.0:8080 --workers 1 --threads 8 wsgi:app
```

> 部署约束：必须单进程（gunicorn 1 worker）。状态变更由进程内互斥锁串行化，
> 水平扩展需把存储换成 etcd/Postgres 等，本实现定位为单节点强语义服务。

## 手动示例

```bash
# 获取
curl -s -X POST localhost:8080/leases/acquire -H 'Content-Type: application/json' \
  -d '{"resource":"config-x","holder":"node-a","ttl_ms":15000}'

# 写入（出示返回的 generation）
curl -s -X POST localhost:8080/resources/config-x/writes \
  -H 'Content-Type: application/json' \
  -d '{"holder":"node-a","generation":1,"value":"..."}'

# 续约（持有者应在 TTL 内循环调用；续约失败就重新 acquire，不能拿旧号写）
curl -s -X POST localhost:8080/leases/renew -H 'Content-Type: application/json' \
  -d '{"resource":"config-x","holder":"node-a","generation":1}'

# 查某次写入是哪代租约放行的
curl -s localhost:8080/writes/1
```

## 配置项（环境变量）

| 变量 | 默认 | 含义 |
|---|---|---|
| `DB_PATH` | `/data/leases.db` | SQLite 文件路径 |
| `LEASE_TTL_MS` | 15000 | 默认软 TTL，续约顺延的步长 |
| `LEASE_MAX_TTL_MS` | 60000 | 客户端可请求 TTL 的上限 |
| `LEASE_HARD_TTL_MS` | 60000 | 硬墙钟上限（相对发放时刻），逻辑钟卡死时的最终死亡线 |
| `LOGICAL_GRACE_TICKS` | 3 | 墙钟过期后，逻辑心跳允许落后的 tick 数 |
| `DELEGATION_TTL_MS` | 15000 | 委托凭证缺省有效期（委托只信墙钟、不可续约） |
| `DELEGATION_MAX_TTL_MS` | 60000 | 委托凭证可请求有效期的上限（且永远短于授权租约的硬上限） |
| `LOGICAL_TICK_INTERVAL_S` | 1 | 后台逻辑钟 tick 间隔 |
| `ARCHIVE_CHUNK_SIZE` | 100 | 归档后台生成时每块冻结的事件条数（每块提交一次、进度落库） |
| `ARCHIVE_WORKER_INTERVAL_S` | 0.2 | 后台归档 worker 的轮询间隔（秒；归档与证据包共用） |
| `EVIDENCE_CHUNK_SIZE` | 1 | 证据包后台生成时每块冻结的归档条目数（每块提交一次、进度落库） |
| `ENABLE_DEBUG_API` | 1 | 是否开放 `/debug/*` 故障演练接口 |

## 测试

```bash
pip install pytest flask
PYTHONPATH=. pytest tests/ -q
```

覆盖：基础持有/写入/审计、同持有者复用、续约、墙钟拨快 10s 不误回收、
逻辑钟卡死到硬上限强制过期、双沉默才过期、重启后租约/世代号/墙钟偏移恢复、
交接后旧世代号与伪造世代号写入被拒、世代号跨多次交接单调递增、
转移原子交接（旧持有者即刻失效、新持有者更大世代号即刻可写）、
重复提交幂等回放、transfer_id 换参数冲突、旧凭证重放全被拒、
不合格接收者零副作用、历史覆盖五种操作且成功/拒绝可区分、
重启后历史/审计顺序/转移结果一致；
限时委托发放与协作者连续写入、协作者不能续约/释放/转移/再转委托、
协作者冒用与凭证串资源拒绝、提前撤销后迟到写拒绝、墙钟到期拒绝、
原租约释放/转移/硬过期连带栅栏、按凭证号过滤完整生命周期、
重启后委托状态与审计顺序一致、旧库自动迁移、
发放/撤销与并发写入下不出现"既能写又已撤销"。
审计能力覆盖：事件流 seq 升序与固定游标分页、snapshot 在并发写入下稳定、
多线程真实 HTTP 并发读不出现越界/半套视图、
按序号/墙钟/最新节点回放资源值/当前租约/委托状态/世代号、
每步中文叙述（接受/拒绝/涉及谁/原因）、
两节点比较定位首异事件且拒绝事件不产生差异、同节点比较 identical、
缺号（删事件后全局诊断）、重号、逻辑钟回退、不可能的成功事件等状态矛盾、
凭证维度诊断、历史不存在 404/节点越界 416/过滤窗口空 404/参数错误 400、
审计只读不收割不改变运行态、重启后回放与诊断结果一致。
审计归档覆盖：资源/凭证归档的创建-生成-下载-校验值闭环、
同对象同节点同幂等键重复创建返回同一份（含 8 线程并发同键创建）、
同键不同节点 409、换键同节点内容一致、
生成期间新写入不混入归档（事件上界创建时钉死）、
分块进度逐块可见、重启后从已保存进度续跑、
finalize 失败重试不重复写入冻结事件、
核验通过与三类篡改（删原始事件/改归档文档/改冻结副本）的首个差异位置、
归档全流程不修改租约/委托/原始历史、重启后归档文档与核验标记逐字节一致。
审计证据包覆盖：资源+凭证归档混合组合的创建-分块生成-下载-组合摘要-
总校验值-核验闭环、reference/content 两种收录方式、
空组合（含确定摘要与校验值、空转非空冲突）、重复归档（不同位置/不同收录方式）、
同组归档同顺序同键重放、换归档/换顺序/换收录方式的同键冲突（首个差异路径与双方值）、
不同键同清单冲突、
生成期间源归档被再次核验与产生新归档均不改变冻结内容、生成期间源哈希被掉包即失败、
分块进度逐块可见、finalize/冻结阶段失败后自动与手动续跑且不重复写入、
服务重启后从已保存进度续跑且文档逐字节一致、
核验通过与六类失败（源归档删除、源内容哈希变化、下载文档篡改、
组合顺序重排、冻结载荷伪造、内嵌原文漂移）的首个差异归档标识/字段路径/双方值、
证据包全流程不修改租约/委托/原始历史/源归档、未完成/不存在/源未就绪等显式错误。
