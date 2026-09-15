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

## 审计因果索引（audit causal index）

在租约服务、审计回放、可验证归档与证据包能力之上，因果索引把一次管理员
任务作用范围内的**租约事件、写入、委托、源归档、证据包条目**组织成一条
可查询的**有向因果链**，并提供创建进度、链路查询、节点重建与独立完整性
核验。任何索引、查询或核验操作都只写 `causal_indexes` /
`causal_index_members` / `causal_index_nodes` 三张自有表，**绝不修改租约、
委托、原始审计历史、源归档或证据包**。

### 作用域与冻结

```
POST /audit/causal-indexes
{"scope":"resource","resource":"cfg-1","head":true,"idempotency_key":"ci-1"}
{"scope":"credential","credential_id":"ab12...","at_seq":40,"idempotency_key":"ci-2",
 "filters":{"outcomes":["ok"],"event_types":["write","delegate_write"],
            "from_ms":...,"to_ms":...,"seq_min":...,"seq_max":...}}
{"scope":"evidence_package","package_id":"<证据包id>","idempotency_key":"ci-3"}
```

- 三种作用域：`resource`（资源）、`credential`（委托凭证）、
  `evidence_package`（证据包，跨资源混合链路）；
- **创建时一次性冻结**三样东西：`snapshot_seq`（稳定视图上界）、查询范围
  （作用域 + 历史节点 `at_seq` / `at_wall_ms` / `head` 三选一，证据包
  作用域的历史节点就是包创建时钉死的快照）、过滤条件（规范化 JSON 落库）；
- 成员集合（节点标识、类型、对象标识、锚点序号、不可变描述）在创建事务里
  同批写入 `causal_index_members`，链包含哪些节点、按什么顺序排列在创建时
  就固定；**生成期间新增事件、再次核验源归档、新增归档或证据包都进不了
  已冻结的因果链**；
- 资源/凭证作用域只收录创建时**已完成**且冻结节点不晚于索引历史节点的源
  归档；证据包作用域收录包的全部条目、每份源归档及其覆盖的事件（去重），
  证据包不存在 → 404 `causal_source_not_found`。

幂等与冲突：**同作用域、同快照节点、同范围、同过滤、同幂等键**重复创建
只返回同一份索引（HTTP 200 + `"replayed": true`）；**同一幂等键换作用域/
换节点/换范围/换过滤** → 409 `causal_index_id_conflict`，响应
`first_difference` 给出首个差异字段（如 `node_seq` / `filters.outcomes`）
与双方值。

### 因果分层与节点

节点按因果分层排列（同层按锚点审计序号，节点顺序即因果顺序）：

| 层 | 节点类型 | node_id | 对象标识 / 锚点 |
|---|---|---|---|
| 0 | `lease_event` 租约事件 | `event:<seq>` | 全局审计序号 |
| 1 | `write` 接受的写入 | `write:<write_id>` | 对应成功写入事件序号 |
| 1 | `delegation` 委托凭证 | `delegation:<credential_id>` | 发放事件序号（状态由冻结事件纯重放） |
| 2 | `source_archive` 源归档 | `archive:<archive_id>` | 归档冻结节点 `node_seq` |
| 3 | `evidence_entry` 证据包条目 | `evidence:<package_id>:<position>` | 该条源归档的 `node_seq` |

事件层按**全局 seq** 交错，因此证据包作用域天然形成跨资源混合链路；每个
节点记录链上的 `prev` / `next` 节点标识（首节点无前驱、末节点无后继）。

### 生成进度与断点续跑

后台 worker 按块（`CAUSAL_CHUNK_SIZE`，默认 100 个成员/块）从冻结的审计
事件与归档清单还原节点载荷，每块一个事务、进度落库
（`processed_nodes` / `last_position`，`GET` 可见 `progress.percent`）。
服务重启或后台失败后从已保存位置继续；节点表主键
`(index_id, node_id)` + `INSERT OR IGNORE` 保证**失败重试不重复写入**。
自动重试上限 5 次，`POST /audit/causal-indexes/<id>/retry` 可手动复位
`failed` 索引（进度保留）。

### 链路查询、分页与异常报告

`GET /audit/causal-indexes/<id>/chain?after=<上一页最后position>&limit=`
按因果顺序返回每个节点的事件序号、对象标识、前置、后继与载荷；游标是
固定快照下的节点位置，分页结果不随后续写入漂移，游标越过末位 → 416
`node_out_of_range`。响应的 `anomalies` / `anomaly_summary` 报告：

- **断链** `chain_broken`：节点的 prev/next 与因果邻接不一致或指向缺失节点；
- **环路** `chain_cycle`：沿 next 指针重复访问到同一节点；
- **重复序号** `duplicate_seq`：多个事件节点引用同一审计 seq；
- **缺失/漂移源归档** `source_archive_missing` / `source_archive_changed`
  / `source_archive_verify_failed`：源归档被删除、内容哈希变化，或源归档
  自身独立核验已失败（其内容不可信）；
- **缺失/漂移证据包条目** `evidence_entry_missing` /
  `evidence_entry_changed`：证据包、条目或冻结载荷缺失，或归档标识/源哈希
  /冻结载荷哈希变化。

未完成的索引不能查询/下载/核验（409 `causal_index_not_ready`）。
单节点可用 `GET /audit/causal-indexes/<id>/nodes/<node_id>` 取冻结载荷；
`POST .../nodes/<node_id>/rebuild` **只读地**从冻结事件/归档清单独立重建
该节点并与冻结节点逐字段比对，返回 `matches` 与 `first_divergence`
（源事件被删导致无法重建时给出 `<missing>`，不写任何表）。

### 链文档、链摘要与独立核验

`GET /audit/causal-indexes/<id>/download` 返回落库链文档（字节稳定，
响应头带 `X-Causal-SHA256` 与 `X-Causal-Chain-Digest`）。`chain_digest`
是顺序敏感的链式哈希（`sha256-causal-chain-v1`，固定初值起逐步混入位置、
节点标识与节点载荷哈希）；`content_sha256` 是除本字段外规范化 JSON 的
总校验值。空结果（过滤后零节点）也是合法完成态，链为空且摘要确定。

`POST /audit/causal-indexes/<id>/verify` 重新从**冻结的审计事件与归档
清单**计算整条链路，按序核验：文档总校验值 → 源归档/证据包条目可用性
（存在、源归档自身核验未失败、内容哈希未变）→ 成员集合 → 每个事件/写入/
委托节点逐字段可独立重建（同时核对下载文档与冻结表）→ 链摘要。任一失败
标记 `verify_failed` 并在 `first_divergence` 给出**首个差异节点标识
（node_id）、字段路径（path，如 `nodes[0].event.holder`）与双方值
（archived / recomputed）**；全部通过标记 `verified`（重启不丢）。

| 场景 | 状态码 | error |
|---|---|---|
| 索引不存在 / 节点不在链中 | 404 | `causal_index_not_found` |
| 证据包作用域指向的证据包不存在 | 404 | `causal_source_not_found` |
| 未完成就查询/下载/核验/重建 | 409 | `causal_index_not_ready` |
| 同幂等键换作用域/节点/范围/过滤 | 409 | `causal_index_id_conflict`（附首个差异） |
| 对非 failed 索引起重试 | 409 | `causal_index_bad_state` |
| 分页游标越过链末 | 416 | `node_out_of_range` |
| 非法 scope/过滤/节点选择器、缺幂等键 | 400 | `bad_request` |

## 因果索引增量派生（incremental derivation）

管理员可指定一份**已完成**的因果索引作为基线，在新的冻结快照上提交增量派生
任务。创建时一次性冻结新的 `snapshot_seq`、范围与过滤条件，并把**基线的快照
信息**（`baseline.snapshot_seq` / `node_seq` / `total_nodes` /
`chain_digest` / `content_sha256`）原样保留进派生任务；基线或源数据在生成
期间发生任何变化都**不能改写已冻结的派生链**。派生只写
`causal_derivations` / `causal_derivation_members` /
`causal_derivation_nodes` 三张自有表，比较、派生、查询与重试都**绝不修改原
索引、租约、委托、审计历史、源归档或证据包**。

```
POST /audit/causal-derivations
{"baseline_index_id":"<已完成索引id>", "idempotency_key":"der-1"}   # 缺省 head
{"baseline_index_id":"...", "at_seq":120,
 "filters":{"outcomes":["ok"]}, "idempotency_key":"der-2"}
```

- 作用域与对象（resource / credential / evidence_package）**继承自基线**，
  显式给出但与基线不一致 → 400；派生历史节点不能早于基线节点（400）；
  证据包作用域不接受节点选择器与过滤；资源/凭证作用域的过滤缺省沿用基线；
  `filters` 只接受 `outcomes` / `event_types` / `from_ms` / `to_ms` /
  `seq_min` / `seq_max` 六个字段，出现文档外或拼写错误的字段名（如少个 s 的
  `outcome`）直接 400，绝不静默忽略——否则两份过滤条件不同的请求会被错误地
  规范化成同一规格并回放成同一个派生任务；
- 成员集合在创建事务里分类落库：`reused`（基线中仍有效的节点）、`added`
  （基线快照之后新增的事件/写入/源归档/证据包条目）、基线有而新范围不再包含
  的计入 `removed`（如过滤变窄）；
- 复用节点的**载荷体逐字节复制自基线冻结副本**，只重盖 position/prev/next
  链环字段——基线之后源数据再被改动也污染不了派生链；新增节点由冻结的审计
  事件与归档清单重建，生成时再次核对源完整性（源归档/证据包条目缺失或内容
  哈希与冻结描述不一致 → 任务失败并给出双方值，绝不静默收录被掉包内容）。

幂等与冲突：**同基线、同范围、同快照节点、同过滤、同幂等键**重复提交只返回
同一任务（200 + `replayed`）；同键换基线/快照节点/范围/过滤 → 409
`causal_derivation_id_conflict`（`first_difference` 给出首个差异字段与双方
值）；同基线+同节点+同过滤但换幂等键 → 409
`causal_derivation_spec_conflict`。基线不存在 → 404
`causal_derivation_baseline_not_found`；基线未完成 → 409
`causal_derivation_baseline_not_ready`。无新增内容是合法完成态
（`increment.added_nodes=0`、`has_changes=false`，节点全部 reused）。

### 生成进度、暂停/恢复与失败重试

后台 worker 按块（`CAUSAL_DERIVATION_CHUNK_SIZE`，默认 100）还原节点，每块
一个事务、进度落库；重启或失败从已保存位置继续，主键
`(derivation_id, node_id)` + `INSERT OR IGNORE` 保证**重试不重复写入**。

| 操作 | 说明 |
|---|---|
| `GET /audit/causal-derivations` | 列派生任务（`?status=&baseline_index_id=&limit=`） |
| `GET /audit/causal-derivations/<id>` | 进度/状态/基线快照/链摘要/`reused·added·removed` 计数 |
| `POST .../<id>/pause` | 暂停（pending/building → paused，worker 跳过；幂等） |
| `POST .../<id>/resume` | 暂停后恢复（paused → pending；已在队列则幂等回放） |
| `POST .../<id>/retry` | failed 复位为 pending（进度保留；非 failed → 409） |
| `GET .../<id>/chain` | 按因果顺序分页查询派生链（节点带 `origin=reused/added`；报告结构异常、源漂移与**基线链漂移**） |
| `GET .../<id>/nodes/<node_id>` | 单个冻结节点（含 `baseline_position`） |
| `GET .../<id>/download` | 下载冻结派生链文档（含基线/增量段与独立链摘要，未完成 409） |
| `POST .../<id>/verify` | 独立核验（见下） |

`POST .../<id>/verify` 按序核验：文档总校验值 → **基线仍存在/完成且基线链
摘要与创建时冻结值一致（基线被篡改在此明确报 `baseline.chain_digest`）** →
源归档/证据包条目可用且哈希未变 → 成员集合（含 reused/added 分类）可由冻结
事件/归档清单重算 → 复用节点载荷与基线冻结副本逐字段一致、新增节点可独立
重建 → 派生链摘要。任一失败标记 `verify_failed`，`first_divergence` 给出
section/path/node_id 与双方值。

## 已完成索引的差异比较（纯只读）

```
POST /audit/causal-indexes/comparisons
{"a_index_id":"<索引A>", "b_index_id":"<索引B>", "after?":-1, "limit?":100}
```

对任意两份**已完成**索引做无副作用比较（不写任何表）：

- `summary`：共同节点数、A→B 的新增/缺失节点数、逐字段变化数、`identical`；
- `first_divergence`：按因果位置逐位比对的首个分叉（`changed` 给出双方节点
  标识；一方链结束则为 `a_ends_b_extends` / `b_ends_a_extends`）；
- `common_nodes` / `added_nodes`（B 有 A 无）/ `removed_nodes`（A 有 B 无）：
  每项带 node_id / node_type / seq / 位置；
- `field_changes`：共同节点的载荷体（不含 position/prev/next 链环字段）逐项
  叶子差异，**每项都带节点标识、字段路径与双方值**（value_a/value_b），按
  A 侧因果顺序排序，支持与链查询同语义的位置游标分页（越界 416
  `node_out_of_range`）；
- `same_snapshot` 标明双方快照节点是否相同；不同快照/不同作用域也可比较，
  只是报告差异，不算错误。任一方索引不存在 → 404、未完成 → 409。

| 派生/比较场景 | 状态码 | error |
|---|---|---|
| 派生任务不存在 / 节点不在链中 | 404 | `causal_derivation_not_found` |
| 基线索引不存在 | 404 | `causal_derivation_baseline_not_found` |
| 基线未完成 / 派生未完成就查询·下载·核验 | 409 | `causal_derivation_baseline_not_ready` / `causal_derivation_not_ready` |
| 同幂等键换基线/节点/范围/过滤 | 409 | `causal_derivation_id_conflict` |
| 同规格换幂等键 | 409 | `causal_derivation_spec_conflict` |
| 暂停/恢复/重试的状态前提不满足 | 409 | `causal_derivation_bad_state` |
| 新增节点的源缺失或哈希漂移（源被篡改） | 409（任务 failed） | `causal_derivation_source_changed` |
| 链/字段变化分页游标越过末位 | 416 | `node_out_of_range` |
| 非法节点选择器/过滤、节点早于基线、缺幂等键 | 400 | `bad_request` |

## 索引版本发布管理（index version release）

管理员可以把一份**已完成**的因果索引登记为一个逻辑**版本**，提交带
**生效时间**的发布计划。系统在**登记**与**发布（生效）**两个时刻分别
冻结索引摘要、快照信息以及可选的比较结果；计划支持延迟生效、取消、
服务中断后的恢复与稳定查询。登记、发布、取消与查询只写
`index_releases` 一张自有表，**绝不修改原索引、派生任务、租约、委托、
审计历史、源归档或证据包**。

### 登记（幂等 + 冲突显式化）

```
POST /audit/index-releases
{"version":"2026.09", "index_id":"<已完成索引id>",
 "idempotency_key":"release-2026-09", "effective_at_ms":1789000000000,
 "compare_with_index_id":"<可选：另一份已完成索引>"}
```

- 必填：`version`（逻辑版本别名，一旦登记永不复用）、`index_id`
  （已完成的因果索引；不存在 404、未完成 409）、`idempotency_key`、
  `effective_at_ms`（生效墙钟时间，整数毫秒；取当前时刻或更早表示
  立即生效）。可选 `compare_with_index_id`：登记时对两份索引做**完整
  只读比较**并把比较结果冻结进计划（比较对象缺失 404、未完成 409）；
- **登记时一次性冻结**三样东西：
  1. **索引摘要**：索引标识、作用域、对象、历史节点 `node_seq`、
     稳定视图 `snapshot_seq`、节点总数、链摘要 `chain_digest`、
     文档总校验值与核验标记；
  2. **快照信息**：索引的 snapshot/node 序号与登记时刻全局 `latest_seq`；
  3. **可选比较结果**：完整比较报告（剥离分页元数据后规范化）及其
     `compare_digest`；
- 幂等与冲突：
  - **相同版本号 + 相同幂等键**（且索引、生效时间、比较对象、比较
    结果都一致）重复登记只返回同一计划（HTTP 200 + `"replayed":
    true`），计划当前状态（active/cancelled/failed）原样返回；计划
    已到生效时间时，回放会先完成发布再返回；
  - **同键换索引、换生效时间或换比较对象** → 409 `release_id_conflict`，
    `first_difference` 给出首个差异字段（`index_id` / `effective_at_ms`
    / `compare_with_index_id`）与双方值；比较对象相同但其比较结果在
    两次登记间发生变化 → 首个差异为 `compare_digest`；
  - **版本号已被别的幂等键占用** → 409 `release_version_conflict`
    （附既有计划与幂等键）。版本别名一旦登记即不可再分配，**计划被
    取消或失败后同名版本仍然冲突**——要换索引/换生效时间/换比较对象
    必须使用新版本号；
- `effective_at_ms` 已到（含过去）时登记事务内**立即发布**，响应同步
  为 `active` 或 `failed`；否则进入 `scheduled`。

### 延迟生效、取消与中断恢复

- 后台 worker（与归档/证据包/因果索引/增量派生同一轮询循环）扫描
  `effective_at_ms <= now` 的 `scheduled` 计划并发布；查询入口
  （版本解析、版本链路/下载、计划查询、登记回放、取消）在锁内还会
  **惰性扫描**，保证即使错过 worker 轮询也"到点必生效"；
- `POST /audit/index-releases/<id>/cancel` 只允许取消仍 `scheduled`
  的计划（重复取消幂等回放）；已生效不可取消（409
  `release_bad_state`），已失败请用 retry；
- 服务中断/进程重启：启动即扫描，**错过生效时间的计划在重启后立即
  发布**（墙钟偏移随数据库持久化，恢复时按恢复后的墙钟判定）；
- `POST /audit/index-releases/<id>/retry` 对 `failed` 计划立即重新
  复核发布（不改变生效时间与任何冻结规格；非 failed → 409）。

### 发布复核与失败（保留可解释原因）

计划发布在同一事务里再次冻结 `activate_index_summary` /
`activate_snapshot` / `activate_comparison` 与重算的原索引链摘要，
并按序复核；**任一不通过计划即置 `failed`**，保留 `error_code` 与
结构化 `error_detail`（字段路径、冻结值/当前值），绝不静默发布被
掉包的索引：

| 发布时发现 | error_code |
|---|---|
| 原索引已被删除 | `release_index_deleted` |
| 原索引不再是完成态 | `release_index_not_completed` |
| 原索引行内链摘要/总校验值/节点数/核验标记与登记冻结值不一致 | `release_index_tampered`（`path=index.chain_digest` 等） |
| 从冻结节点重算的链摘要与登记冻结值不一致（节点载荷被篡改，即使行摘要被一起伪造） | `release_index_tampered`（`path=index.chain_digest_recomputed`） |
| 比较对象被删除 / 未完成 | `release_compare_target_not_ready` |
| 比较结果与登记冻结结果不一致（首个叶子差异路径） | `release_comparison_changed` |

每个计划独立事务：单个计划失败不影响其它到点计划；计划视图始终带
`status`（scheduled/active/cancelled/failed）、`attempts`、
`error/error_code/error_detail` 与登记/生效/取消/失败四个时间戳。

### 生效后的稳定查询

| 接口 | 说明 |
|---|---|
| `GET /audit/index-versions/<version>` | **版本别名解析**：主体只来自发布行冻结字段（冻结索引指针、发布时快照、冻结比较结果），永远不随后续变化漂移；另附对原索引当前状态的只读 `live` 诊断（`intact`/`tampered`/`deleted`）与 `stable` 标记 |
| `GET /audit/index-versions/<version>/chain` | 版本固化的因果链（分页参数与原索引链查询一致）；服务前再次核对原索引当前链摘要 |
| `GET /audit/index-versions/<version>/nodes/<node_id>` | 版本固化的单个冻结节点 |
| `GET /audit/index-versions/<version>/download` | 版本固化的链文档（字节稳定，响应头 `X-Index-Version` / `X-Causal-SHA256` / `X-Causal-Chain-Digest`） |
| `GET /audit/index-releases` | 列发布计划（`?status=&version=&index_id=&limit=`） |
| `GET /audit/index-releases/<id>` | 计划进度/状态/登记冻结/发布冻结/失败原因 |

- **生效后按版本别名查询只能指向发布时冻结的索引**：原索引被篡改
  （重算链摘要不等于冻结值）→ 版本链/节点/下载一律 409
  `release_index_tampered`；原索引被删除 → 404
  `release_index_deleted`；绝不把被掉包的内容当作版本内容。
  版本解析接口本身仍可返回冻结指针，并把 `live.state` 标为
  `tampered`/`deleted`（冻结视图不依赖原索引是否还在）；
- **旧版本仍可按原索引标识查询**（`/audit/causal-indexes/<id>`），
  新版本发布、计划取消或失败都不影响既有索引；
- 未生效（409 `index_release_not_effective`）、已取消（409
  `index_release_cancelled`）、已失败（409 `index_release_failed`，
  附失败错误码）、版本/计划不存在（404 `index_release_not_found`）
  都给出显式错误，而不是空结果或漂移到别的索引。

| 发布场景 | 状态码 | error |
|---|---|---|
| 计划/版本不存在 | 404 | `index_release_not_found` |
| 发布对象/比较对象索引不存在 | 404 | `causal_index_not_found` |
| 发布对象/比较对象索引未完成 | 409 | `causal_index_not_ready` |
| 同幂等键换索引/生效时间/比较对象（含比较结果漂移） | 409 | `release_id_conflict` |
| 版本号被别的幂等键占用（含已取消/已失败） | 409 | `release_version_conflict` |
| 取消/重试状态前提不满足 | 409 | `release_bad_state` |
| 版本查询：计划未生效/已取消/已失败 | 409 | `index_release_not_effective` / `index_release_cancelled` / `index_release_failed` |
| 版本链/节点/下载：原索引被篡改 | 409 | `release_index_tampered` |
| 版本链/节点/下载：原索引被删除/节点缺失 | 404 | `release_index_deleted` |
| 缺 version/index_id/幂等键/生效时间、时间非整数 | 400 | `bad_request` |

## 审计变更订阅与可靠通知（audit subscription）

管理员可以为**资源**、**委托凭证**、**因果索引**或**发布版本**创建订阅：
指定事件范围（过滤条件）、起始历史序号与回调地址。系统保存订阅状态、
过滤条件与当前位置，按全局历史序号为每个订阅**严格顺序**投递通知。

### 创建（幂等 + 冲突显式化）

`POST /audit/subscriptions`，请求体：

```json
{
  "scope": "resource",
  "resource": "vol-7",
  "callback_url": "https://ops.example/hook",
  "start_seq": 0,
  "filters": {"event_types": ["write", "transfer"], "outcomes": ["ok"]},
  "idempotency_key": "sub-2026-09-13-1",
  "max_attempts": 5
}
```

- 作用域对象：`resource`（`resource`）、`credential`（`credential_id`）、
  `causal_index`（`index_id`，投递其冻结成员锚定的审计事件；冻结之后的
  新事件不进入订阅范围）、`release`（`release_id`，锚定发布计划指向的
  索引）；目标不存在 → 404。
- `start_seq` 含起始，**不能越过创建时刻的稳定视图上界**（否则 416
  `subscription_seq_out_of_range` 并返回 `available_max_seq`）；创建期间
  落库的新事件序号必大于快照，只会随后按顺序入队，不会被塞入更早快照。
- 同一 `idempotency_key` 重复提交只返回同一订阅（200 + `replayed`）；
  同键换作用域/对象、**过滤条件、回调地址或起始序号** → 409
  `subscription_id_conflict`，响应 `first_difference` 给出首个差异字段。
- 密钥由服务端生成（32 字节随机值），只保存在订阅表，不通过 API 返回。

### 严格顺序与一次确认

- 扫描只从只增的 `lease_events` 稳定历史读取（按全局 seq 分窗口，稀疏交错
  的作用域事件也不会被跳过），未匹配过滤条件的事件只推进游标、不产生投递；
- 每个事件对每个订阅只有一行投递记录
  （`(subscription_id, event_seq)` 唯一 + `INSERT OR IGNORE`）；
- 投递器只认领每个订阅**最小 event_seq 的非终态行**：前面有
  `inflight` / `awaiting_confirm` / `dead_letter` 或退避未到点的行时，
  后来事件绝不提前发送，不跳号、不乱序；
- 认领是带唯一 `dispatch_token` 的条件 UPDATE，回调在数据库事务之外
  执行；并发投递/并发确认不可能把同一行处理两次；
- 回调返回 2xx（200/201/204）即隐式确认；返回 **202** 表示"先收下，稍后
  显式确认"，投递停在 `awaiting_confirm`；对同一行重复确认是幂等回放，
  **不会推进两次**（`replayed: true`）。

### 通知载荷与签名

每次通知为 POST JSON，并附带签名头：

| 头 | 内容 |
|---|---|
| `X-Signature` | 通知体规范化 JSON（排序键、紧凑分隔）的 HMAC-SHA256（订阅密钥）十六进制 |
| `X-Signature-Algorithm` | `HMAC-SHA256` |
| `X-Subscription-Id` / `X-Subscription-Seq` / `X-Event-Seq` | 订阅号、订阅序号、历史序号 |

载荷含 `event_seq`（历史序号）、`subscription_seq`（该订阅第几条通知，
从 1 连续）、`event_type`、`object_id`（`lease_event:<seq>`）、`object`
（作用域与对象标识）与 `summary`（对象标识/事件类型/内容摘要：操作方、
对方、世代、凭证与 `digest_sha256`）。显式确认
（`POST .../deliveries/<event_seq>/ack`，签名取 `X-Signature` 头或
请求体 `signature`）必须使用通知载荷的正确签名；**签名错误返回 401
`invalid_signature`，不改变任何状态**。

### 失败重试与死信

- 连接失败、超时、非 2xx 响应都记录 `attempts`、`last_error` 与
  `next_retry_at_ms`；退避为 `base * 2^(n-1)`（默认 1s 起、5min 封顶，
  可用 `SUBSCRIPTION_BACKOFF_BASE_MS` / `SUBSCRIPTION_BACKOFF_MAX_MS`
  配置）；
- 410 Gone 视为永久拒收，直接死信；其余失败超过 `max_attempts` 进入
  `dead_letter` 并**挡住后续投递**（订阅 `blocked: true`，绝不跳过）；
- `GET /audit/subscriptions/dead-letters`（可按订阅 `subscription_id`
  与版本 `version_no` 过滤）查看失败原因；
  `POST /audit/subscriptions/<id>/dead-letters/<event_seq>/requeue`
  清空尝试次数、立即重新放回队列（严格顺序仍受队首约束）；
- `POST .../deliveries/<event_seq>/retry` 可忽略退避立即重试一条等待中的投递。

### 订阅版本切换

管理员可以为一个**活动**订阅预先创建带新回调地址、新事件过滤条件和
生效历史序号（`effective_seq`，含）的下一版本，再原子激活：

| 接口 | 语义 |
|---|---|
| `POST /audit/subscriptions/<id>/versions` | 预创建下一版本 `{callback_url, filters?, effective_seq, idempotency_key}`（201；同键 200 回放）；同键换回调/过滤/生效序号/目标订阅 409，生效序号越过当前稳定历史上界 416（**原订阅不变**），早于当前版本已检视位置 409，订阅非 active 或已有待激活版本 409 |
| `GET /audit/subscriptions/<id>/versions` | 列版本状态（`?status=prepared/active/superseded/cancelled&limit=`） |
| `GET /audit/subscriptions/<id>/versions/<v>` | 查版本：状态、回调、过滤、生效序号、版本游标/下一订阅序号、confirmed/dead/open 计数、`drained` |
| `GET /audit/subscriptions/<id>/versions/<v>/diff?base_version=` | 与基线版本（默认当前生效版本）的回调/过滤/生效序号差异 |
| `POST /audit/subscriptions/<id>/versions/<v>/activate` | **原子切换**（单事务）：旧版本 `superseded`、新版本 `active`、订阅主行回调/密钥/过滤/版本号/游标整体切换；同键 200 回放，换目标/操作 409，版本不存在 404，非 prepared/非待激活版本 409 |
| `POST /audit/subscriptions/<id>/versions/<v>/cancel` | 取消预创建版本（只有 prepared 可取消；幂等键，永不生效） |
| `POST /audit/subscriptions/<id>/versions/<v>/retry-dead-letters` | 只重试某版本的全部死信（幂等键；复位尝试次数立即重投，回放首次结果，换版本/订阅/操作 409） |
| `GET /audit/subscriptions/<id>/history` | 该订阅自己的审计历史（只追加；`?after_id=&event=&limit=`）：版本创建/激活/取消/重试与所有拒绝原因 |

切换语义与不变量：

- **原子**：激活在单个写事务内完成，进程在事务中途崩溃则整笔回滚，
  不留半切换；用同一幂等键重试即完成；
- **在途通知按旧版本收尾**：投递行冻结版本号，切换前已入队/认领中的
  通知继续发往旧回调地址、用旧密钥签名、沿用旧版本内的订阅序号；
  202 待显式确认的通知也只能用旧版本密钥确认（新密钥确认返回 401）；
  迟到响应只匹配本行认领令牌；
- **边界不重不漏不乱序**：旧版本扫描上界钉在 `effective_seq-1`
  （预创建后立即钉住，即便激活前持续扫描也不会越过边界），新版本从
  `effective_seq` 开始。两个版本在投递表内按全局 event_seq 共享同一条
  严格顺序队列——队首（最小 event_seq 非终态行）约束保证旧版本未确认
  通知与新版本通知**互不越过**；`(subscription_id, event_seq)` 唯一保证
  同一事件绝不重复；边界前被旧过滤跳过的事件不回头重放；
- **版本独立编号与密钥**：通知载荷带 `version_no`，订阅序号在版本内
  从 1 连续编号，用该版本自己的密钥 HMAC 签名；
- **重启续跑**：版本状态、边界（`scan_upper_seq`）、游标、认领行全部
  持久化；新进程构造即回收认领中状态行，superseded 版本继续补齐边界前
  事件并收尾，active 版本从边界继续；
- **只追加审计**：版本创建、激活、取消、重试与所有拒绝原因只写订阅
  自有表 `audit_subscription_events`，绝不改写租约、委托、
  `lease_events` 原始审计事件或已有投递记录。

### 通知签名密钥轮换与验证

管理员可以为一个**活动**订阅预登记下一把通知签名密钥（密钥指纹、生效
历史序号 `effective_seq`、宽限期 `grace_ms`），再原子生效。密钥轮换与
版本切换是两条**正交**能力：版本切换更换回调地址/过滤/版本密钥并按版本
分段，密钥轮换则在投递行上叠加一层"签名密钥代际"（`signing_key_id`）。

| 接口 | 语义 |
|---|---|
| `POST /audit/subscriptions/<id>/signing-keys` | 预登记下一把密钥 `{secret?, fingerprint?, effective_seq, grace_ms, idempotency_key}`（201；同键 200 回放）。`secret` 省略时服务端生成 32 字节随机密钥；`fingerprint` 为 `sha256(secret)`（给定时必须吻合）。同键换指纹/生效序号/宽限期/目标订阅 409（`first_difference` 给首个差异）；生效序号越过稳定历史上界 416（**当前密钥不变**）、早于当前已扫描位置或订阅非 active/已有待生效密钥 409 |
| `GET /audit/subscriptions/<id>/signing-keys` | 列密钥（`?status=prepared/active/grace/retired/revoked&limit=`），只返回指纹不返回明文 |
| `GET /audit/subscriptions/<id>/signing-keys/<key_id>` | 单把密钥状态（含指纹、生效序号、宽限到点、`grace_active` 与投递计数） |
| `GET .../signing-keys/<key_id>/progress` | 轮换进度：旧密钥未终态尾巴（含 awaiting 确认数）、新密钥投递 confirmed/open/dead/钉章计数、`drained` |
| `GET .../signing-keys/<key_id>/deliveries?after=&status=&limit=` | 分页查询受影响投递（`side=old_key_tail/new_key`，游标为 event_seq） |
| `POST .../signing-keys/<key_id>/activate` | **原子生效**（幂等键）：旧密钥进入 `grace`（宽限 >0）或立即 `retired`；同键回放，换目标/操作 409 |
| `POST .../signing-keys/<key_id>/revoke` | 撤销预登记密钥（只有 prepared 可撤销；幂等键，永不生效，记录保留） |
| `GET /audit/subscriptions/<id>/signature-verifications` | 按密钥与时间范围分页查验证结果（`?key_id=&result=ok/failed/old_key_grace/resigned&from_ms=&to_ms=&after=<ms>:<rowid>&limit=`） |
| `POST /audit/subscriptions/<id>/deliveries/<event_seq>/resign` | **只对验证失败的指定密钥投递**重新签名 `{key_id?, idempotency_key}`：**完全不修改已有投递记录**，新签名只追加为 `resigned` 验证记录的 `new_signature`，不改投递状态/尝试次数、不重复确认 |

语义与不变量：

- **生效前旧密钥、生效后新密钥**：预登记（prepared）即钉住扫描边界，
  生效序号之后的事件在生效前不会被错误地用旧密钥入队；每个投递行在入队
  事务内冻结 `signing_key_id`，生效序号（含）起的新通知必须用新密钥
  HMAC 签名，之前已入队/认领中的旧通知继续用旧密钥；
- **旧通知宽限确认**：等待显式确认（202）的旧通知在旧密钥宽限期内仍可
  按旧密钥完成确认，验证结果记为 `old_key_grace`；宽限到点旧密钥置
  `retired`（后台/查询/确认路径惰性收敛），此后旧密钥确认一律 401 且不
  改变状态。首次轮换时被替换的是版本冻结密钥（它没有自己的密钥行，宽限
  窗口挂在 key_no=1 的轮换密钥上，宽限为 0 立即退役），语义与后续轮换
  完全一致；
- **幂等与冲突**：预登记/生效/撤销/重签都带幂等键；同键改变密钥指纹、
  生效序号、宽限期或目标订阅返回 409 并给出首个差异字段；操作幂等键与
  预登记键、订阅版本命名空间互不可复用。**省略 `secret`/`fingerprint`
  由服务端生成密钥时，完全相同的幂等请求回放第一次的密钥记录（同一
  key_id/指纹），服务端不会在重放时重新生成密钥**；
- **验证与重签**：每次显式确认（成功/失败/宽限）只追加验证记录
  （`(delivery,result,used,expected)` 去重，重复确认不重复计数）；
  重签只针对最新验证为 `failed` 的投递（无失败记录 409、密钥不符 404），
  重签**不改写已有投递记录的任何字段**（`signature`、`updated_at_ms`、
  状态、尝试次数等全部保持原值），新签名只作为验证表 `resigned` 行的
  `new_signature` 保存并在验证查询中返回，严格顺序与确认状态不变；
- **重启续跑**：密钥状态、生效序号、宽限到点、投递行冻结的密钥代际全部
  持久化；新管理器构造即收敛到期宽限密钥，从已保存状态继续，不重复确认、
  不跳过通知；
- **只追加审计 / 只读边界**：`key_prepared`/`key_activated`/
  `key_revoked`/`key_retired`/`key_resigned` 与所有拒绝原因只追加进该订阅
  自己的审计历史（`version_no` 列为 NULL）；密钥轮换只写
  `audit_subscription_signing_keys` /
  `audit_subscription_key_idempotency` /
  `audit_subscription_signature_verifications` 三张自有表（投递表只追加
  `signing_key_id` 列，重签的新签名只写验证表，投递行任何字段都不改写），
  绝不改写租约、委托、`lease_events` 原始审计事件、版本行或已有投递状态。

### 暂停、恢复、取消与重新开始

| 接口 | 语义 |
|---|---|
| `POST /audit/subscriptions/<id>/pause` | 暂停扫描与新投递（幂等）；已取消的订阅 409 |
| `POST /audit/subscriptions/<id>/resume` | 恢复（幂等） |
| `POST /audit/subscriptions/<id>/cancel` | 取消（幂等）：未终态投递置 `discarded` 但保留历史，预创建版本与**预登记签名密钥一并取消/撤销（永不生效）**；取消后迟到的回调响应被令牌/状态检查忽略，**不会再发送任何通知** |
| `POST /audit/subscriptions/<id>/restart-from` `{"from_seq": N}` | 从指定序号重新开始：**已有投递记录全部保留**，已确认行不重置（同一事件不重复确认），其余非终态/死信行复位为 pending 并立即补齐区间；已取消 409、越界 416 |
| `GET /audit/subscriptions/<id>/deliveries?after=&status=&version_no=&limit=` | 分页读取投递历史（游标为 event_seq，升序；可按版本过滤切换前后的投递/失败记录） |
| `POST /audit/subscriptions/process` | 管理/演练入口：扫描入队 + 到点投递各跑一轮 |

### 并发、重启与只读边界

- 后台 worker 与归档/发布 worker 同一轮询循环：先扫描入队再投递；
  `inflight`/`awaiting_confirm` 的认领行带租约（默认 60s，
  `SUBSCRIPTION_CLAIM_LEASE_MS`），超时回收为 pending（不增加尝试次数）；
  **进程重启时无条件回收所有认领中状态的行**，随后从游标与退避时刻继续；
- 并发创建（同幂等键）由唯一索引收敛为一个订阅；并发投递由条件认领
  UPDATE 收敛为一次回调；并发确认由条件状态 UPDATE 收敛为一次确认；
- 订阅流程只写 `audit_subscriptions` /
  `audit_subscription_deliveries` 两张自有表，对租约、委托、原始审计
  历史、因果索引、归档、证据包与发布计划**只读 SELECT，绝不改写**。

## 审计通知多端投递（audit notification fan-out）

一条审计通知可以同时投递给多个**独立接收端**，何时算完成由通知创建时
**冻结的送达策略快照**决定：冻结内容包含接收端集合（含每个接收端自己的
`max_attempts`）、所需成功数与策略版本；之后修改策略（创建新版本）只影响
新通知，在途通知永远按自己的快照判定。

### 三种完成模式与明确失败

- `all`：冻结集合里的接收端全部成功才算完成；
- `any`：任一接收端成功即完成；
- `quorum`：成功数达到策略的 `quorum_count` 即完成。

每次状态变化后在锁内按冻结快照重估：仍可能成功的接收端数
（`总数 - 已终止数`）一旦低于所需成功数，策略**永远不可能满足**，整条
通知立即置为 `failed`，并把判定快照 `decision`（原因 + 参与判定的每个
接收端当时的状态/尝试次数/最后结果）冻结落库。判定是终态：迟到回执与
迟到失败上报一律 409 `fanout_notification_decided`，不能复活已失败的
通知，也不能改动已完成的通知。

### 接收端生命周期、暂停/恢复

`pending → succeeded`（成功回执）或 `pending → terminal_failed`
（失败重试达到该接收端自己的 `max_attempts`）。失败可以重试，每次失败
上报记一次尝试。管理员可暂停/恢复某个接收端（均幂等）：暂停只是拒收新
回执与失败上报（409 `fanout_recipient_paused`），不改状态、不减计数——
**暂停已成功的接收端改变不了既有完成结论**（成功计数读的是 `state`，
不是 `paused`），暂停也不会让策略变得不可满足（被暂停的接收端可以恢复）。

### 回执幂等

成功回执按 `(notification_id, recipient_id, idempotency_key)` 幂等：
相同回执重复到达只返回首次处理结果（200 回放，不重复计尝试，即使通知
此后已终态）；同一幂等键配不同内容返回 409 `fanout_receipt_conflict`
并给出首个差异位置；接收端已成功后又来新键回执，不重复计尝试，返回
等效成功结果（`already_succeeded`）。

### 送达状态与尝试记录

`GET /audit/fanout/notifications/<id>` 返回冻结快照、每个接收端的尝试
次数/最后结果/暂停标记、离完成还差多少（`progress.remaining_successes`）、
策略是否仍可能满足（`progress.satisfiable`）与终态判定快照；
`.../attempts` 与 `.../recipients/<rid>/attempts` 按顺序给出逐次尝试
记录。策略、快照、尝试顺序、幂等记录与最终判定全部落库，进程重启后
原样保留。

### 投递席位：有序备用接收端 + 切换期限

创建通知时可以用 `seats` 替代扁平的 `recipients`（二选一）。每个
**投递席位**在创建时冻结一份**有序候选列表**（第 1 位是主接收端，其余
按顺序为备用接收端，各自可带自己的 `max_attempts`）与**切换期限**
`switch_after_ms`（当前接收端的处理时长上限）：

```json
{"payload": {...},
 "seats": [{"seat_id": "s1", "switch_after_ms": 30000,
            "candidates": ["primary", {"recipient_id": "backup-1",
                                       "max_attempts": 2}, "backup-2"]}]}
```

- 席位先由主接收端处理；主接收端在期限内成功，席位**立即成功**，备用
  接收端永远不再启用（对已成功席位的切换请求一律 409
  `fanout_seat_succeeded`）。
- 期限到达（超时）或管理员手动放弃当前接收端时，系统按顺序启用下一位
  备用接收端，并以启用时刻重算 `deadline_at_ms = now +
  switch_after_ms`。同一席位无论切换多少次，最多只给整条通知贡献
  **一次**成功（完成判定读的是席位状态）。
- 被替换接收端之后到达的回执/失败上报一律 409
  `fanout_candidate_superseded` 明确拒绝并记入席位历史，绝不算到当前
  席位；响应带**胜负信息** `winner`（赢的是哪次成功回执，或哪次切换及
  其原因与接任者），调用方能据此判断输赢。
- 当前接收端的成功回执与超时/手动切换并发时，进程锁把两个请求串行化，
  **先结算者赢**：期限是硬边界（`deadline_at_ms <= now` 一律算超时
  赢），后到者收到带胜负信息的 409 冲突。
- 候选失败达到自己的 `max_attempts` 也会被替换（原因
  `candidate_failed`）并自动启用下一位。一个席位的所有候选都失败或
  被放弃后，席位进入终止态 `exhausted`，参与原送达策略是否还能满足的
  判定：仍可能成功的席位数（`席位总数 - 已终止数`）低于冻结的所需
  成功数时，整条通知明确失败，判定快照冻结每个席位与其候选当时的
  状态。

管理员视图与操作：`GET .../seats` / `GET .../seats/<sid>` 给出每个席位
当前由谁处理、下一位备用接收端、切换期限与剩余时间、最近一次切换原因；
`GET .../seats/<sid>/history` 给出完整历史（启用/替换及原因/回执受理与
拒绝/失败/席位成败）；`POST .../seats/<sid>/switch` 手动放弃当前接收端
（`{reason?, expected_recipient_id?, idempotency_key?}`，同幂等键重放
200，`expected_recipient_id` 与当前接收端不符时 409 防止并发误切）。
期限结算有三条结果一致的路径：后台 worker、`POST
/audit/fanout/notifications/process-deadlines` 显式触发、各席位相关
接口的惰性结算。期限以绝对墙钟落库，**服务重启后按原期限继续**，切换
历史原样保留。

## 持久性

SQLite（WAL 模式）存放在 `DB_PATH`（容器内 `/data/leases.db`），库中包含：
生效租约、每资源世代号、写入审计、**转移记录（幂等键）**、**限时委托凭证**、
**统一租约历史（含每条被接受写入当时的资源值，供事件溯源回放）**、
**审计归档与冻结事件副本（归档进度、内容校验值与核验标记）**、
**审计证据包与冻结清单/收录载荷（组合顺序、每份源归档内容哈希、
组合摘要、总校验值与核验标记）**、
**审计因果索引与冻结成员集合/节点载荷（snapshot_seq、范围与过滤、
因果链摘要、总校验值与核验标记）**、
**因果索引增量派生任务与冻结成员/节点（基线快照与链摘要、新 snapshot_seq、
范围与过滤、reused/added/removed 分类、派生链摘要、总校验值与核验标记；
比较请求不落库）**、
**索引版本发布计划（版本别名与幂等键、发布对象、生效时间、登记时冻结的
索引摘要/快照/可选比较结果、发布时再次冻结的摘要与重算链摘要、
scheduled/active/cancelled/failed 状态机与可解释失败原因）**、
**审计变更订阅、订阅版本与投递记录（各版本冻结的回调地址/过滤条件/
生效序号/扫描上界/HMAC 密钥、过滤条件、起始/当前序号、版本内订阅序号、
pending/inflight/awaiting_confirm/confirmed/dead_letter/discarded 状态机、
尝试次数与退避时刻、失败与死信原因、认领令牌、冻结通知载荷与签名、
版本操作幂等日志、订阅审计历史）**、
**审计通知多端投递（策略版本、通知冻结策略快照、接收端集合与状态、
逐次尝试记录、回执幂等记录与终态判定快照；投递席位的有序候选、
切换期限、切换原因与完整历史、手动切换幂等记录）**、
逻辑钟读数和墙钟偏移。进程/容器重启后全部恢复，
正在生效的租约与委托不会丢失，历史与审计顺序保持一致，转移结果仍可幂等回放，
**审计回放、节点比较与一致性诊断对同一份历史给出逐字节一致的结果**；
启动时即按墙钟收割已到期的委托，并自动续跑未完成的归档、证据包、因果索引与
增量派生生成（暂停中的派生任务不会被自动续跑），
**错过生效时间的版本发布计划在启动时立即发布（失败保留原因，可 retry）**，
**订阅在启动时回收崩溃残留的认领行并从已保存游标与退避时刻继续，
不丢事件、不重复确认**，
**投递席位在启动时即按原期限结算错过的切换，切换历史与回执幂等记录
原样保留**。
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
| POST | `/audit/causal-indexes` | **创建审计因果索引**：`{scope: resource\|credential\|evidence_package, resource?\|credential_id?\|package_id?, at_seq?\|at_wall_ms?\|head?, filters?, idempotency_key}`；同作用域+同快照节点+同过滤+同键返回同一份（200 回放），同键换范围/节点/过滤 409 |
| GET | `/audit/causal-indexes` | 列因果索引（`?scope=&status=&limit=`） |
| GET | `/audit/causal-indexes/<id>` | **查索引进度**：状态、已还原/总节点数、冻结范围与过滤、链摘要、总校验值、核验标记 |
| GET | `/audit/causal-indexes/<id>/chain` | **按因果顺序分页查询链路**（`?after=<position>&limit=`）：每节点事件序号/对象标识/前置/后继，报告断链/环路/重号/缺源归档/缺证据包条目 |
| GET | `/audit/causal-indexes/<id>/nodes/<node_id>` | 取单个冻结节点载荷（只读） |
| POST | `/audit/causal-indexes/<id>/nodes/<node_id>/rebuild` | **节点重建**：从冻结事件/归档清单独立重算单节点并与冻结节点比对（只读，不写任何表） |
| GET | `/audit/causal-indexes/<id>/download` | **下载链文档**（全部节点+链摘要+总校验值；未完成 409） |
| POST | `/audit/causal-indexes/<id>/verify` | **独立核验**：从冻结审计事件与归档清单重算链路，失败给出首个差异节点标识、字段路径与双方值 |
| POST | `/audit/causal-indexes/<id>/retry` | 手动复位 `failed` 索引，从已保存进度继续（非 failed 409） |
| POST | `/audit/causal-derivations` | **创建增量派生**：`{baseline_index_id, at_seq?/at_wall_ms?/head?（缺省 head）, filters?（缺省沿用基线）, idempotency_key}`；同基线+同节点+同过滤+同键回放同一任务（200），同键换基线/节点/过滤 409，同规格换键 409；基线不存在 404、未完成 409 |
| GET | `/audit/causal-derivations` | 列派生任务（`?status=&baseline_index_id=&limit=`） |
| GET | `/audit/causal-derivations/<id>` | **查派生进度**：状态、已还原/总节点、基线快照与链摘要、复用/新增/移除计数 |
| GET | `/audit/causal-derivations/<id>/chain` | 按因果顺序分页查询派生链（节点带 `origin=reused/added`；报告结构异常、源漂移与基线链漂移） |
| GET | `/audit/causal-derivations/<id>/nodes/<node_id>` | 取单个冻结节点（含其基线位置，只读） |
| GET | `/audit/causal-derivations/<id>/download` | 下载冻结派生链文档（基线/增量段+独立链摘要+总校验值；未完成 409） |
| POST | `/audit/causal-derivations/<id>/verify` | **独立核验**：总校验值/基线链摘要/源/成员集合/复用与新增载荷/派生链摘要 |
| POST | `/audit/causal-derivations/<id>/retry` | 手动复位 `failed` 派生任务，从已保存进度继续（非 failed 409） |
| POST | `/audit/causal-derivations/<id>/pause` | 暂停派生任务（worker 跳过；幂等） |
| POST | `/audit/causal-derivations/<id>/resume` | 暂停后恢复（paused → pending；非 paused 409） |
| POST | `/audit/causal-indexes/comparisons` | **比较两份已完成索引**（纯只读）：`{a_index_id, b_index_id, after?, limit?}` → 共同节点、首个分叉、增删节点、逐字段变化（每项带节点标识与双方值）；任一方不存在 404、未完成 409、游标越界 416 |
| POST | `/audit/index-releases` | **登记索引版本发布计划**：`{version, index_id, idempotency_key, effective_at_ms, compare_with_index_id?}`；相同版本号+幂等键返回同一计划（200 回放，已到点先发布），同键换索引/生效时间/比较对象 409、版本号被别的键占用 409；生效时间已到则同步 active/failed |
| GET | `/audit/index-releases` | 列发布计划（`?status=scheduled/active/cancelled/failed&version=&index_id=&limit=`） |
| GET | `/audit/index-releases/<id>` | 查计划：状态、登记时冻结的索引摘要/快照/比较结果、发布时再次冻结的内容、失败错误码与结构化原因 |
| POST | `/audit/index-releases/<id>/cancel` | 取消仍 scheduled 的计划（幂等）；已生效/已失败 409 |
| POST | `/audit/index-releases/<id>/retry` | failed 计划立即重新发布（生效时间与冻结规格不变；非 failed 409） |
| GET | `/audit/index-versions/<version>` | **版本别名稳定解析**：冻结索引指针/发布快照/冻结比较结果 + 原索引只读 `live` 诊断（intact/tampered/deleted）；未生效 409、已取消 409、已失败 409、不存在 404 |
| GET | `/audit/index-versions/<version>/chain` | 版本固化的因果链分页（服务前复核原索引链摘要：被篡改 409、被删除 404） |
| GET | `/audit/index-versions/<version>/nodes/<node_id>` | 版本固化的单个冻结节点（同样的篡改/删除闸门） |
| GET | `/audit/index-versions/<version>/download` | 版本固化的链文档（字节稳定，`X-Index-Version` / `X-Causal-SHA256` / `X-Causal-Chain-Digest`） |
| POST | `/audit/subscriptions` | **创建审计变更订阅**：`{scope: resource/credential/causal_index/release, resource?/credential_id?/index_id?/release_id?, callback_url, start_seq?, filters?, idempotency_key, max_attempts?}`；同幂等键返回同一订阅（200 回放），换过滤/回调/起始序号 409，起始序号越过稳定视图上界 416，目标不存在 404 |
| GET | `/audit/subscriptions` | 列订阅（`?scope=&status=active/paused/cancelled&limit=`） |
| GET | `/audit/subscriptions/<id>` | 查订阅：状态、过滤、起始/当前位置、已确认序号、退避/死信计数 |
| POST | `/audit/subscriptions/<id>/pause` / `/resume` / `/cancel` | 暂停 / 恢复 / 取消（均幂等；取消后迟到通知不再发送；已取消再暂停/恢复 409） |
| POST | `/audit/subscriptions/<id>/restart-from` | 从指定序号重新开始 `{from_seq}`：保留全部投递历史，已确认不重复确认，非终态/死信行复位重试（已取消 409、越界 416） |
| GET | `/audit/subscriptions/<id>/deliveries` | 分页投递历史（`?after=<event_seq>&status=&limit=`，按历史序号升序） |
| GET | `/audit/subscriptions/<id>/deliveries/<event_seq>` | 单条投递：状态、尝试次数、下次重试时间、失败/死信原因、通知摘要与签名 |
| POST | `/audit/subscriptions/<id>/deliveries/<event_seq>/ack` | 回调 202 后的显式签名确认（`X-Signature` 头或 `{signature}`；重复确认幂等不推进两次，坏签名 401 不改状态） |
| POST | `/audit/subscriptions/<id>/deliveries/<event_seq>/retry` | 忽略退避立即重试一条等待中的投递（非等待/待确认状态 409） |
| GET | `/audit/subscriptions/dead-letters` | 列死信（`?subscription_id=&version_no=&limit=`，含 `dead_letter_reason` 与 `last_error`） |
| POST | `/audit/subscriptions/<id>/dead-letters/<event_seq>/requeue` | 死信重新放回队列（清空尝试次数立即重试；非 dead_letter 409） |
| POST | `/audit/subscriptions/<id>/versions` | **预创建下一版本**：`{callback_url, filters?, effective_seq, idempotency_key}`；同键 200 回放，换回调/过滤/生效序号/目标订阅 409，越过稳定历史上界 416（原订阅不变） |
| GET | `/audit/subscriptions/<id>/versions` | 列版本（`?status=&limit=`） |
| GET | `/audit/subscriptions/<id>/versions/<v>` | 查版本状态/游标/投递计数 |
| GET | `/audit/subscriptions/<id>/versions/<v>/diff` | 与基线版本差异（`?base_version=`，默认当前版本） |
| POST | `/audit/subscriptions/<id>/versions/<v>/activate` | **原子激活**（`{idempotency_key}`；同键回放，非 prepared/非待激活 409） |
| POST | `/audit/subscriptions/<id>/versions/<v>/cancel` | 取消预创建版本（`{idempotency_key}`；只有 prepared 可取消） |
| POST | `/audit/subscriptions/<id>/versions/<v>/retry-dead-letters` | 只重试该版本死信（`{idempotency_key}`；回放首次结果，换目标 409） |
| GET | `/audit/subscriptions/<id>/history` | 订阅自己的审计历史（只追加；`?after_id=&event=&limit=`） |
| POST | `/audit/subscriptions/process` | 管理/演练：扫描入队 + 到点投递各跑一轮，返回 `{enqueued, delivered}` |
| POST | `/audit/fanout/policies` | **创建送达策略**（每次创建产生新的递增版本）：`{mode: all\|any\|quorum, quorum_count?}` |
| GET | `/audit/fanout/policies` | 列策略版本（version 升序）；`/audit/fanout/policies/current` 查当前版本，`/audit/fanout/policies/<version>` 查指定版本 |
| POST | `/audit/fanout/notifications` | **创建通知并冻结策略快照**：`{payload, policy_version?, recipients:[{recipient_id, max_attempts?}]}` 或 `{payload, policy_version?, seats:[{seat_id?, switch_after_ms, candidates:[...]}]}`（二选一）；冻结接收端集合/席位候选与期限/所需成功数/策略版本，之后改策略只影响新通知 |
| GET | `/audit/fanout/notifications` | 列通知（`?status=pending/completed/failed&limit=`，带进度摘要） |
| GET | `/audit/fanout/notifications/<id>` | **送达状态**：冻结快照、每个接收端尝试次数/最后结果/暂停标记（或每个席位当前处理人/备用/期限）、离完成还差多少、终态判定快照 |
| GET | `/audit/fanout/notifications/<id>/attempts` | 整条通知的尝试记录（全局顺序）；`.../recipients/<rid>/attempts` 查单接收端 |
| POST | `/audit/fanout/notifications/<id>/receipts` | **成功回执** `{recipient_id, idempotency_key, content?}`：同键同内容 200 回放首次结果，同键不同内容 409，通知已终态 409（迟到不能翻案），接收端暂停/终止 409；席位通知里被替换接收端的迟到回执 409 `fanout_candidate_superseded`（带胜负信息） |
| POST | `/audit/fanout/notifications/<id>/recipients/<rid>/failures` | **失败重试** `{detail?}`：记一次失败尝试，达到该接收端 `max_attempts` 进入终止态（席位候选则自动启用下一位备用）；策略不再可能满足时整条通知明确失败 |
| POST | `/audit/fanout/notifications/<id>/recipients/<rid>/pause` / `/resume` | 暂停/恢复接收端（均幂等；不改状态与计数，暂停已成功接收端不改变完成结论） |
| POST | `/audit/fanout/notifications/process-deadlines` | **结算全部到期的切换期限**（超时按顺序启用下一位备用；与后台 worker、接口惰性结算同一路径） |
| GET | `/audit/fanout/notifications/<id>/seats` | **全部席位状态**：当前处理人、下一位备用、切换期限与剩余时间、最近切换原因 |
| GET | `/audit/fanout/notifications/<id>/seats/<sid>` | 单席位状态（含全部候选的期限/状态/替换原因） |
| GET | `/audit/fanout/notifications/<id>/seats/<sid>/history` | **席位完整历史**：启用/替换（含原因）/回执受理与拒绝/失败/席位成败 |
| POST | `/audit/fanout/notifications/<id>/seats/<sid>/switch` | **手动放弃当前接收端** `{reason?, expected_recipient_id?, idempotency_key?}`：按顺序启用下一位备用；同键重放 200，席位已成功/已终止 409（带胜负信息），期望接收端不符 409 |
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
| `CAUSAL_CHUNK_SIZE` | 100 | 因果索引后台生成时每块还原的成员节点数（每块提交一次、进度落库） |
| `CAUSAL_DERIVATION_CHUNK_SIZE` | 100 | 增量派生后台生成时每块还原的成员节点数（复用节点复制基线载荷、新增节点从冻结源重建） |
| `SUBSCRIPTION_BACKOFF_BASE_MS` | 1000 | 回调失败指数退避的基础等待（第 n 次失败后 `base*2^(n-1)`） |
| `SUBSCRIPTION_BACKOFF_MAX_MS` | 300000 | 回调失败退避上限 |
| `SUBSCRIPTION_CLAIM_LEASE_MS` | 60000 | 投递认领租约：超过此时长的 inflight/awaiting 行视为投递器崩溃，回收重试（启动时无条件回收） |
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
审计因果索引覆盖：资源/凭证/证据包三种作用域的创建-分块生成-链路查询-
下载-链摘要-核验闭环，因果分层（事件→写入/委托→源归档→证据包条目）
与 prev/next 邻接、跨资源混合链路按全局 seq 交错、
空结果（过滤后零节点、确定摘要与校验值）、
同作用域+同节点+同过滤+同键重放（含 8 线程并发同键创建）、
同键换节点/换过滤/换作用域/证据包换包的显式冲突（首个差异字段与双方值）、
创建即冻结（生成期间新增事件、再核验源归档、新增归档均不进链）、
固定快照游标分页与越界 416、分块进度、finalize 失败后自动/手动续跑且
不重复写入节点、服务重启后续跑且链文档逐字节一致、
断链/环路/重号/缺失源归档/缺失证据包条目等异常报告、
节点重建一致/漂移/源已删、
核验通过与删原始事件/篡改链文档（含连校验值一起伪造）/篡改冻结节点表/
源归档核验失败/源归档删除或内容哈希变化/证据条目缺失等篡改的
首个差异节点标识/字段路径/双方值、
全流程不修改租约/委托/原始历史/源归档/证据包、未完成/不存在等显式错误。
增量派生与索引比较覆盖：复用基线节点（载荷逐字节复制、仅重盖链环）+
新增节点重建的正常派生、无新增内容全复用完成态、窄过滤移除基线节点、
证据包作用域约束、基线不存在 404/未完成 409/节点早于基线 400/缺幂等键 400、
同键回放与同键换基线/换快照/换过滤冲突、同规格换键冲突、
分块中断后服务重启从已保存进度续跑且不重复写入、下载文档逐字节稳定、
暂停（worker 跳过、幂等）/恢复/失败重试与非法状态转换、
新增节点的源归档或证据包条目缺失/哈希漂移即生成失败、修复后重试成功、
基线描述漂移创建即拒绝、基线在派生完成后被篡改/删除时核验失败在
baseline.chain_digest 且复用节点载荷不被污染、
索引比较的共同节点/首个分叉（changed 与一方链结束）/增删节点/逐字段变化
（节点标识+双方值）/自比较 identical/不同快照可比较/分页与越界 416/
未完成 409/不存在 404、派生与比较全流程只读（租约/委托/历史/源归档/证据包/
原索引的核验标记均不被修改）。
索引版本发布管理覆盖：立即发布与延迟发布（登记冻结索引摘要/快照/完整比较
结果、发布时二次冻结）、worker 与查询惰性扫描双路径到点生效、
错过生效时间的计划在服务重启（启动扫描）后立即发布、
相同版本号+幂等键回放同一计划（含到点回放先激活）、同键换索引/换生效时间/
换比较对象/比较结果漂移的显式 409（首个差异字段与双方值）、版本号换键
（含取消/失败后同名）409 且永不复用、多版本互不影响、
取消仅对 scheduled 生效且幂等/对 active·failed 409、
发布期间原索引被篡改（节点载荷→chain_digest_recomputed、行摘要→
chain_digest）/删除/非完成态、比较对象删除/未完成/比较结果变化均 failed
并保留 error_code 与结构化 error_detail、failed retry 仍失败、源修复后
retry 成功、worker 批量发布时单计划失败不影响其它、
版本别名稳定查询（冻结指针不漂移、live 诊断 intact/tampered/deleted、
生效后新增写入与新索引不改变版本内容与下载字节、被篡改 409/被删除 404）、
旧版本仍按原索引标识查询、计划/版本不存在与未生效/已取消/已失败的显式错误、
登记/发布/取消/重试/查询全流程不修改原索引（含核验标记）、派生任务、租约、
委托、审计历史、源归档或证据包（只写 index_releases）。
审计变更订阅与可靠通知覆盖：正常投递（事件序号/对象标识/事件类型/内容摘要/
订阅序号字段齐全、HMAC-SHA256 签名可由密钥复算、严格按历史序号投递）、
空结果（起始位置之后无作用域事件、过滤零匹配）、过滤（只有匹配事件入队、
订阅序号连续、未匹配事件只推进游标）、重复确认幂等不推进两次、坏签名确认
401 且状态不变、202 待确认 + 显式签名确认（X-Signature 头）、
多线程并发投递恰好一次、8 线程同幂等键并发创建只产生一个订阅、
多线程并发确认只确认一次、回调 5xx/超时的尝试次数与退避重试（拨表驱动）、
退避未到点不重发、队首失败挡住后来事件（不跳过、不乱序）、
超上限死信挡队/410 直接死信/死信列表与原因查看/重新放回后续传、
非死信重新放回 409、暂停后不投递与恢复后顺序续传、
取消幂等与取消后进行中回调的迟到成功被丢弃（discarded 不变 confirmed）、
服务重启后 inflight 回收（不增加尝试次数）/已确认与暂停位置持久化、
起始序号越界 416 与负数 400、目标不存在 404、
同幂等键回放与换过滤/回调/起始序号的显式 409（首个差异字段）、
创建期间新事件不混入更早快照、从指定序号重新开始保留全部历史投递记录且
已确认事件不重复确认、投递历史分页与状态过滤、
凭证/因果索引（冻结边界）/发布版本三种额外作用域、
稀疏交错事件分窗口扫描不跳事件、真实 HTTP 回调（本地服务器校验签名头）、
订阅全生命周期不改写租约/委托/历史/归档/证据包/因果索引/发布计划
（表内容逐行相等、全局诊断一致）。

订阅版本切换覆盖：正常预创建/查询/差异/原子激活（含三版本连续切换）、
预创建后边界立即钉住（active 不扫过 effective_seq-1）、切换前后事件按
版本路由（回调地址/密钥/版本内订阅序号分流、边界前事件不重放、队列共享
不重不乱不丢、回调顺序全局升序）、202 待确认在途通知切换后仍用旧密钥
确认（新密钥 401）、认领后回调进行中切换版本的迟到成功响应按认领令牌
确认旧行、创建/激活/取消/死信重试的同键回放与换回调/过滤/生效序号/目标
订阅/版本/操作类型的 409 冲突（首个差异字段）、生效序号越过稳定历史
上界 416 且原订阅不变（拒绝入审计历史）、早于已检视位置 409、8 线程同
幂等键并发激活恰好一次切换其余回放、按版本分页查看投递/死信与只重试某
版本死信（严格顺序不越过）、服务重启回收认领行后从已保存状态继续
（待确认恢复、切换后未收尾重启、预创建中重启后仍可激活）、取消订阅
连带取消所有版本、版本创建/激活/取消/重试与全部拒绝原因只追加进订阅
自己的审计历史（分页/事件过滤）、版本流程不改写租约/委托/
`lease_events`/已有投递记录、事务中途故障注入不留半切换。
