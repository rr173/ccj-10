# 审计通知载荷契约注册与兼容性门禁

面向审计通知管道的**载荷契约（payload contract）生命周期服务**：管理员按事件类型登记
带语义化版本号的 JSON 载荷契约，系统在候选版本生效前做字段级双向兼容性判定、
稳定历史预演（dry-run）和序号边界门禁；每条通知在入队时冻结**契约版本 + 规范化
载荷（canonical JSON + sha256 摘要）+ 验证摘要**；验证失败的事件进入**订阅自己的
隔离队列**并产生**队头阻塞（head-of-line blocking）**，管理员可查看原始事件摘要、
登记只允许 **rename / 固定 default / 删除 ignorable 字段** 的确定性映射后重试，
重试保持同一投递身份与顺序、绝不产生重复通知。

零第三方依赖：Python 3.9+ 标准库（`http.server` + `sqlite3` + `threading`）。

## 运行

```bash
python3 -m app --db audit.db --host 127.0.0.1 --port 8080
# 端到端演示（需要服务已起）
bash demo.sh
# 测试
python3 -m unittest discover -s tests -t . -v
```

## 数据模型与不变式

| 概念 | 说明 |
|---|---|
| 稳定水位 `stable_seq` | 入库的连续不可变事件序号（无空洞，缺号报 `event_seq_gap`） |
| 扫描位置 `scan_seq` | 已冻结/已隔离的最后一个序号；与入库解耦，由 `POST /scan` 或恢复重试驱动 |
| 生效点 `effective_seq` | 新契约开始治理的序号，必须 `scan_seq < effective_seq ≤ stable_seq` |
| 激活历史 `activations` | 只追加（换约把旧行 `active=0`，撤销记 `revoke_seq`），用于解释每个冻结位置 |
| 部分唯一索引 | `ux_active_activation ... WHERE active=1` + `BEGIN IMMEDIATE`：并发激活只有一个版本成功 |
| 通知主键 | `(sub_id, seq)`：重试是 `UPDATE` 同一行、复用 `notification_id`，结构上不可能重复 |

冻结规则：生效点**之前**已排队的通知保留旧契约版本与旧规范化载荷；生效点**及之后**
扫描的新通知使用新契约。冻结后不再随后续换约改变。

## 契约 Schema

```jsonc
{
  "type": "object",                  // object | array | string | int | number | bool | null
  "unknown_policy": "strict",        // object 节点：strict(阻断) | strip(规范化删除,info) | allow
  "required": true,                  // 默认 true
  "ignorable": false,                // 允许被 drop 映射删除
  "default": "x",                    // 缺失时补默认值
  "enum": ["a", "b"],                // 仅标量，值类型必须与 type 一致
  "properties": { "field": { /* 递归 */ } },
  "items": { /* array 元素，递归 */ }
}
```

## 兼容性判定（schema-registry 语义）

- **backward（向后兼容）**：旧版本写的载荷，新版本消费者能接受；
- **forward（向前兼容）**：新版本写的载荷，旧版本消费者能接受。

逐字段判定，给出路径级结论与总判定 `compatible / backward_only / forward_only / breaking`，例如：

| 变更 | backward | forward |
|---|---|---|
| 新增可选 / 带默认值字段 | ✅ | ✅ |
| 新增必填字段 | ✅ | ❌ |
| 删除非 ignorable 字段 | ❌ | ✅ |
| 删除 ignorable 字段 | ✅ | ✅ |
| `int → number`（宽化） | ✅ | ❌ |
| 必填→可选 | ✅ | ❌；可选→必填 反之 |
| 枚举加值 | ✅ | ❌；枚举减值 ❌/✅ |
| 未知策略 strict→strip/allow | ✅ | ❌（放宽方向对称判定） |

## 生效门禁（任一不过即 409 `activation_rejected`，原因全部落审计历史）

1. 存在 **status=passed 且范围覆盖生效点** 的预演（未预演/未通过/范围不覆盖分别给明原因）；
2. `effective_seq ≤ stable_seq`（越过稳定历史 → `effective_seq_beyond_stable`）；
3. `effective_seq > scan_seq`（早于/等于订阅扫描位置 → `effective_seq_before_scan_position`）；
4. 生效点不能落在隔离队头之后（`activation_blocked_by_quarantine`）；
5. 并发互斥：`expected_version`/`expected_absent` CAS + 部分唯一索引，只有一个版本成功。

## 隔离、映射与重试

- 扫描时校验失败：冻结一条 `status=blocked` 的通知行（含验证摘要），写 `quarantines`，
  **scan_seq 不推进**，后续事件全部被挡住；
- `GET /subscriptions/{s}/quarantine` 返回：原始事件摘要（canonical sha256 + 原始载荷）、
  失败字段路径/原因、隔离时版本、当前生效契约、重试次数；
- 映射只允许三类且登记时按**当前生效契约**校验：
  - `rename`：两个已声明的同类型叶子字段之间改名（不能借改名改类型/造字段）；
  - `default`：给已声明叶子补固定值，值必须满足 type/enum；
  - `drop`：只能删除显式 `ignorable: true` 的字段；
- 映射作用于**派生计份**，`events.raw_payload` 永不改写；
- 重试按该序号当前生效契约重新验证；失败则 `retry_count+1` 并保持 HOL；
  成功则 UPDATE 同一通知行（身份不变）并继续泵送后续被挡通知；
- 已恢复事件再次重试：幂等返回既有结果，不新增通知。

## 幂等

所有写接口（契约登记、预演、生效、撤销、映射登记、重试）接受 `idempotency_key`；
同键重放返回首次结果（顶层平铺并带 `"replayed": true`）。无键重复提交也按业务
唯一性冲突处理（同版本同契约、相同映射规则、已恢复重试等）。

## 重启恢复（全部状态在 SQLite）

启动时自动续跑所有 `status=running` 的预演（逐条进度已落库，不重复计算）；
冻结契约版本、映射规则、隔离队头位置、扫描位置、激活历史均从表恢复。

## HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/subscriptions/{s}` | 建订阅 |
| GET | `/subscriptions/{s}/status` | scan/stable 水位、隔离队头、生效版本 |
| POST | `/subscriptions/{s}/events` | 事件入库 `{seq,event_type,payload}` |
| POST | `/subscriptions/{s}/scan` | 显式推进扫描 |
| GET | `/subscriptions/{s}/notifications` | 冻结通知（版本/规范化载荷/摘要/验证） |
| PUT | `/contracts/{t}/versions/{v}` | 登记契约 `{spec}` |
| GET | `/contracts/{t}/versions[/{v}]` | 版本列表 / 契约详情 |
| POST | `/contracts/{t}/diff` | `{old_version,new_version,sub_id?}` 字段级差异 |
| POST | `/subscriptions/{s}/dry-runs` | `{event_type,version,from_seq,to_seq?}` |
| GET | `/subscriptions/{s}/dry-runs/{id}` | 逐条事件/字段路径/原因 |
| POST | `/subscriptions/{s}/activations` | 生效（含 effective_seq/CAS/幂等键） |
| GET | `/subscriptions/{s}/activations` | 当前生效版本 |
| POST | `/subscriptions/{s}/revocations` | 撤销（记撤销点） |
| GET | `/subscriptions/{s}/quarantine` | 隔离列表 |
| POST | `/subscriptions/{s}/quarantine/{seq}/retry` | 映射重试 |
| POST/GET | `/subscriptions/{s}/mappings` | 映射登记 / 查询 |
| GET | `/subscriptions/{s}/audit-history`、`/audit-history` | 审计历史 |

错误统一为 `{"error": "<machine_reason>", "detail": {...}}`。
