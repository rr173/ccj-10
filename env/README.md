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

## 持久性

SQLite（WAL 模式）存放在 `DB_PATH`（容器内 `/data/leases.db`），库中包含：
生效租约、每资源世代号、写入审计、**转移记录（幂等键）**、**限时委托凭证**、
**统一租约历史**、逻辑钟读数和墙钟偏移。进程/容器重启后全部恢复，
正在生效的租约与委托不会丢失，历史与审计顺序保持一致，转移结果仍可幂等回放；
启动时即按墙钟收割已到期的委托。旧版本数据库会在启动时自动补列迁移。
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
