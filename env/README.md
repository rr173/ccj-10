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

## 持久性

SQLite（WAL 模式）存放在 `DB_PATH`（容器内 `/data/leases.db`），库中包含：
生效租约、每资源世代号、写入审计、逻辑钟读数和墙钟偏移。进程/容器重启后全部恢复，
正在生效的租约不会丢失。逻辑钟由后台 ticker 每秒 +1（每次推进都 fsync 落库）。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/leases/acquire` | `{resource, holder, ttl_ms?}` → 新世代号租约（201）；同持有者复用（200）；被占（409） |
| POST | `/leases/renew` | `{resource, holder, generation}` → 顺延软 TTL；租约已失效返回 412（须重新获取更大世代号） |
| POST | `/leases/release` | `{resource, holder, generation}` |
| POST | `/resources/<r>/writes` | `{holder, generation, value}` → 受保护写入；世代号过期 409，无生效租约 412 |
| GET | `/resources/<r>` | 当前世代号、已放行最大世代号、当前值 |
| GET | `/resources/<r>/leases` | 当前租约全文（含三种期限与逻辑钟读数） |
| GET | `/resources/<r>/writes` | 该资源全部写入审计（含拒绝记录） |
| GET | `/writes/<id>` | **按写入 ID 反查：哪一代租约放行** |
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
| `LOGICAL_TICK_INTERVAL_S` | 1 | 后台逻辑钟 tick 间隔 |
| `ENABLE_DEBUG_API` | 1 | 是否开放 `/debug/*` 故障演练接口 |

## 测试

```bash
pip install pytest flask
PYTHONPATH=. pytest tests/ -q
```

覆盖：基础持有/写入/审计、同持有者复用、续约、墙钟拨快 10s 不误回收、
逻辑钟卡死到硬上限强制过期、双沉默才过期、重启后租约/世代号/墙钟偏移恢复、
交接后旧世代号与伪造世代号写入被拒、世代号跨多次交接单调递增。
