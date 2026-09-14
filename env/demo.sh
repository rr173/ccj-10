#!/usr/bin/env bash
# 端到端演练：获取租约 -> 双时钟抗拨表 -> 交接 -> 旧世代号被栅栏拒绝 -> 审计反查
#             -> 安全转移（幂等/防重放）-> 完整租约历史 -> 委托
#             -> 审计事件流/节点回放/两节点比较/一致性诊断（全部只读）
# 用法: ./demo.sh [BASE_URL]
set -euo pipefail

BASE="${1:-http://127.0.0.1:8080}"
R="demo-res-$(date +%s)"

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)"; }

echo "== 0. 当前两种时钟 =="
curl -s "$BASE/debug/now" | python3 -m json.tool

echo
echo "== 1. node-1 获取租约（TTL 2s） =="
LEASE=$(curl -s -X POST "$BASE/leases/acquire" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-1\",\"ttl_ms\":2000}")
echo "$LEASE" | python3 -m json.tool
GEN=$(echo "$LEASE" | j "['lease']['generation']")
LID=$(echo "$LEASE" | j "['lease']['lease_id']")

echo
echo "== 2. 有人把墙上时钟往前拨了 10 秒（越过软 TTL，但未过硬上限） =="
curl -s -X POST "$BASE/debug/wall-shift" -H 'Content-Type: application/json' \
  -d '{"delta_ms":10000}' >/dev/null

echo "   逻辑钟仍在推进（node-1 还在干活），续约两次："
for _ in 1 2; do
  curl -s -X POST "$BASE/debug/tick" -d '{}' >/dev/null
  curl -s -X POST "$BASE/leases/renew" -H 'Content-Type: application/json' \
    -d "{\"resource\":\"$R\",\"holder\":\"node-1\",\"generation\":$GEN}" \
    | j "['lease']['state']"
done

echo "   带世代号 $GEN 写入 —— 必须放行："
WID=$(curl -s -X POST "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"node-1\",\"generation\":$GEN,\"value\":\"v1\"}" | j "['write_id']")
echo "   write_id=$WID"

echo
echo "== 3. 反查写入 #$WID 是哪一代租约放行的 =="
curl -s "$BASE/writes/$WID" | python3 -m json.tool

echo
echo "== 4. node-1 主动释放，node-2 接手 =="
curl -s -X POST "$BASE/leases/release" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-1\",\"generation\":$GEN}" >/dev/null
GEN2=$(curl -s -X POST "$BASE/leases/acquire" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-2\",\"ttl_ms\":2000}" \
  | j "['lease']['generation']")
echo "   旧世代=$GEN  新世代=$GEN2 （必须严格增大）"

echo
echo "== 5. node-1 的迟到写入（拿着过期世代号 $GEN）—— 必须 409 拒绝 =="
curl -s -o /tmp/resp.json -w "   HTTP %{http_code}\n" -X POST \
  "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"node-1\",\"generation\":$GEN,\"value\":\"stale\"}"
cat /tmp/resp.json | python3 -m json.tool

echo
echo "== 6. node-2 用新世代写入 —— 放行 =="
curl -s -X POST "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"node-2\",\"generation\":$GEN2,\"value\":\"v2\"}" >/dev/null
curl -s "$BASE/resources/$R" | python3 -m json.tool

echo
echo "== 7. 完整写入审计（含被拒的那次，写着拒绝原因） =="
curl -s "$BASE/resources/$R/writes" | python3 -m json.tool

echo
echo "== 8. node-2 把租约安全转移给 node-3（原子交接，幂等键 xfer-\$R） =="
TR=$(curl -s -X POST "$BASE/leases/transfer" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-2\",\"generation\":$GEN2,\"to_holder\":\"node-3\",\"transfer_id\":\"xfer-$R\"}")
echo "$TR" | python3 -m json.tool
GEN3=$(echo "$TR" | j "['to']['generation']")
echo "   node-2 世代=$GEN2 -> node-3 世代=$GEN3 （严格增大）"

echo
echo "== 9. 同一笔转移原样重提（网络重试）—— 必须回放首次结果，不再次转移 =="
curl -s -o /tmp/tr2.json -w "   HTTP %{http_code}\n" -X POST \
  "$BASE/leases/transfer" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-2\",\"generation\":$GEN2,\"to_holder\":\"node-3\",\"transfer_id\":\"xfer-$R\"}"
python3 -c "import json;d=json.load(open('/tmp/tr2.json'));print('   replayed =',d['replayed'],' to.generation =',d['to']['generation'])"

echo
echo "== 10. node-2 旧凭证重放（转移/写入）—— 必须全部拒绝 =="
curl -s -o /dev/null -w "   旧凭证再转移: HTTP %{http_code}\n" -X POST \
  "$BASE/leases/transfer" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-2\",\"generation\":$GEN2,\"to_holder\":\"node-9\",\"transfer_id\":\"xfer2-$R\"}"
curl -s -o /dev/null -w "   旧世代号写入: HTTP %{http_code}\n" -X POST \
  "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"node-2\",\"generation\":$GEN2,\"value\":\"stale\"}"

echo
echo "== 11. node-3 用新世代 $GEN3 写入 —— 放行 =="
curl -s -X POST "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"node-3\",\"generation\":$GEN3,\"value\":\"v3\"}" >/dev/null
curl -s "$BASE/resources/$R" | python3 -m json.tool

echo
echo "== 12. 完整租约历史（获取/续约/释放/转移/写入，成功与拒绝都在） =="
curl -s "$BASE/resources/$R/history" | python3 -m json.tool

echo
echo "== 13. 限时委托：node-3 给协作者 worker-1 发放 5s 短期凭证 =="
GEN_CUR=$(curl -s "$BASE/resources/$R/leases" | j "['generation']")
DEL=$(curl -s -X POST "$BASE/leases/delegations" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-3\",\"generation\":$GEN_CUR,\"collaborator\":\"worker-1\",\"ttl_ms\":5000}")
echo "$DEL" | python3 -m json.tool
CID=$(echo "$DEL" | j "['delegation']['credential_id']")
echo "   credential_id=$CID（锚定世代 $GEN_CUR）"

echo
echo "== 14. 协作者凭凭证连续写入（不用持有租约，世代号可省略） =="
for v in d1 d2 d3; do
  curl -s -o /dev/null -w "   协作者写 $v: HTTP %{http_code}\n" -X POST \
    "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
    -d "{\"holder\":\"worker-1\",\"credential_id\":\"$CID\",\"value\":\"$v\"}"
done
echo "   别人冒用该凭证："
curl -s -o /dev/null -w "   HTTP %{http_code}\n" -X POST \
  "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"mallory\",\"credential_id\":\"$CID\",\"value\":\"hack\"}"
echo "   协作者试图续约（必须 409，委托只授写）："
curl -s -o /dev/null -w "   HTTP %{http_code}\n" -X POST "$BASE/leases/renew" \
  -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"worker-1\",\"generation\":$GEN_CUR}"

echo
echo "== 15. 授权者提前撤销凭证 =="
curl -s -X POST "$BASE/leases/delegations/revoke" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$R\",\"holder\":\"node-3\",\"generation\":$GEN_CUR,\"credential_id\":\"$CID\"}" \
  | j "['delegation']['state']"

echo
echo "== 16. 撤销后的迟到委托写入 —— 必须 409 delegation_rejected =="
curl -s -o /tmp/del.json -w "   HTTP %{http_code}\n" -X POST \
  "$BASE/resources/$R/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"worker-1\",\"credential_id\":\"$CID\",\"value\":\"late\"}"
cat /tmp/del.json | python3 -m json.tool

echo
echo "== 17. 按凭证号查委托与其完整历史（授权者/协作者/有效期/世代号/每次结果） =="
curl -s "$BASE/delegations/$CID" | python3 -m json.tool
curl -s "$BASE/resources/$R/history?credential_id=$CID" | python3 -m json.tool

echo
echo "== 18. 审计事件流（seq 升序、固定分页、每条带中文叙述） =="
PAGE=$(curl -s "$BASE/resources/$R/audit/events?limit=5")
echo "$PAGE" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for e in d['events']:
    print(f\"  seq={e['seq']:>3} {e['event']:<16} {e['outcome']:<9} {e['holder']:<9} -> {e.get('narration')}\")
print('  next =', d['next'], ' reached_end =', d['reached_end'],
      ' snapshot =', d['view']['snapshot_seq'])
"
SNAP=$(echo "$PAGE" | j "['view']['snapshot_seq']")
echo "   固定快照 snapshot=$SNAP 再查一次（并发写入不会改变结果）："
curl -s "$BASE/resources/$R/audit/events?snapshot=$SNAP&limit=1000" \
  | j "['view']['snapshot_seq']" | sed 's/^/   snapshot = /'

echo
echo "== 19. 历史节点回放：还原 v1 写入那一刻的资源值/租约/委托/世代号 =="
V1_SEQ=$(curl -s "$BASE/resources/$R/audit/events?event=write&limit=1000" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['events'][0]['seq'])")
echo "   v1 写入事件 seq=$V1_SEQ"
curl -s "$BASE/resources/$R/audit/replay?at_seq=$V1_SEQ" | python3 -c "
import sys,json
d=json.load(sys.stdin)
s=d['state_as_of_node']
print('   节点:', d['node']['narration'])
print('   当时资源值 =', s['resource']['value'],
      ' 当前世代号 =', s['resource']['current_generation'])
print('   当时租约持有者 =', s['lease']['holder'],
      ' 租约世代 =', s['lease']['generation'],
      ' 状态 =', s['lease']['state'])
print('   委托数量 =', len(s['delegations']), '（v1 时代还没有委托）')
"

echo
echo "== 20. 比较两个历史节点：第一次产生差异的事件 =="
HEAD_SEQ=$(curl -s "$BASE/resources/$R/audit/events?limit=1000" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['events'][-1]['seq'])")
curl -s "$BASE/resources/$R/audit/compare?a_at_seq=$V1_SEQ&b_at_seq=$HEAD_SEQ" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
f=d['first_divergence']
print('   identical =', d['identical'], ' 区间事件数 =', d['events_between'])
print('   首异事件 seq=%s %s/%s' % (f['seq'], f['event'], f['outcome']))
print('   ->', f['narration'])
print('   首异时变化字段:', ', '.join(f['changed_fields']))
"

echo
echo "== 21. 一致性诊断（资源 / 凭证 / 全局）—— 健康历史应 consistent=true =="
curl -s "$BASE/resources/$R/audit/diagnose" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('   资源诊断:', d['summary'])
"
curl -s "$BASE/delegations/$CID/audit/diagnose" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('   凭证诊断:', d['summary'], ' 投影状态 =', d['projected_state']['state'])
"
curl -s "$BASE/audit/diagnose" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('   全局诊断:', d['summary'], ' 资源 =', d['resources'])
"

echo
echo "== 22. 显式错误（不是空报告）：历史不存在 404 / 节点越界 416 / 窗口为空 404 =="
curl -s -o /tmp/e1.json -w "   不存在的资源历史: HTTP %{http_code}\n" \
  "$BASE/resources/no-such-resource/audit/events"
cat /tmp/e1.json | python3 -c "import sys,json;print('    ->',json.load(sys.stdin)['error'])"
curl -s -o /tmp/e2.json -w "   序号越界回放:     HTTP %{http_code}\n" \
  "$BASE/resources/$R/audit/replay?at_seq=99999999"
cat /tmp/e2.json | python3 -c "import sys,json;d=json.load(sys.stdin);print('    ->',d['error'],'可用范围:',d.get('available_min_seq'),'..',d.get('available_max_seq'))"
curl -s -o /tmp/e3.json -w "   空时间窗口:       HTTP %{http_code}\n" \
  "$BASE/resources/$R/audit/events?to_ms=1"
cat /tmp/e3.json | python3 -c "import sys,json;print('    ->',json.load(sys.stdin)['error'])"
echo
echo "演练完成。所有审计接口均为只读，未改动上面运行中的任何租约与委托。"

# ---------------------------------------------------------------------------
# 23. 审计变更订阅与可靠通知（失败 -> 退避重试 -> 死信 -> 重新放回）
# ---------------------------------------------------------------------------
echo
echo "== 23. 审计变更订阅 =="
SUB=$(curl -s -X POST "$BASE/audit/subscriptions" -H 'Content-Type: application/json' \
  -d "{\"scope\":\"resource\",\"resource\":\"$R\",\"callback_url\":\"http://127.0.0.1:9/never-listens\",\"start_seq\":0,\"idempotency_key\":\"demo-sub-$R\",\"max_attempts\":3}")
SID=$(echo "$SUB" | j "['subscription_id']")
echo "   订阅 $SID（回调指向不可达地址，演练失败重试）"
echo "   同幂等键重复提交 -> 同一订阅："
curl -s -X POST "$BASE/audit/subscriptions" -H 'Content-Type: application/json' \
  -d "{\"scope\":\"resource\",\"resource\":\"$R\",\"callback_url\":\"http://127.0.0.1:9/never-listens\",\"start_seq\":0,\"idempotency_key\":\"demo-sub-$R\"}" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('    subscription_id=%s replayed=%s' % (d['subscription_id'], d['replayed']))"
echo "   换回调地址用同键 -> 409 显式冲突："
curl -s -o /tmp/subconflict.json -w "    HTTP %{http_code}\n" -X POST \
  "$BASE/audit/subscriptions" -H 'Content-Type: application/json' \
  -d "{\"scope\":\"resource\",\"resource\":\"$R\",\"callback_url\":\"http://other/\",\"start_seq\":0,\"idempotency_key\":\"demo-sub-$R\"}"
python3 -c "import json;d=json.load(open('/tmp/subconflict.json'));print('    ->',d['error'],'首个差异:',d['first_difference']['path'])"

echo "   扫描入队 + 三轮投递（连接失败，尝试次数递增，第三轮达上限进死信）："
# 先扫描入队，再取队首事件序号；随后用手动重试接口忽略退避推进三轮，
# 避免拨墙钟影响前面演练产生的短 TTL 租约
curl -s -X POST "$BASE/audit/subscriptions/process" -d '{}' >/dev/null
FIRST_SEQ=$(curl -s "$BASE/audit/subscriptions/$SID/deliveries?limit=1" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['deliveries'][0]['event_seq'])")
# 首轮已在上面投递（attempts=1）；再推进两轮：重试 -> 投递 -> 重试 -> 投递
curl -s -X POST "$BASE/audit/subscriptions/$SID/deliveries/$FIRST_SEQ/retry" \
  -d '{}' >/dev/null
curl -s -X POST "$BASE/audit/subscriptions/process" -d '{}' >/dev/null
curl -s -X POST "$BASE/audit/subscriptions/$SID/deliveries/$FIRST_SEQ/retry" \
  -d '{}' >/dev/null
curl -s -X POST "$BASE/audit/subscriptions/process" -d '{}' >/dev/null
curl -s "$BASE/audit/subscriptions/$SID/deliveries/$FIRST_SEQ" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('    队首事件 seq=%s 状态=%s 尝试=%s 死信原因=%s' % (
    d['event_seq'], d['status'], d['attempts'], d['dead_letter_reason']))
n=d['notification']
print('    通知字段: event_type=%s object_id=%s 订阅序号=%s' % (
    n['event_type'], n['object_id'], d['subscription_seq']))
print('    内容摘要 digest=%s...' % n['summary']['digest_sha256'][:16])
print('    签名=%s...' % (d['signature'] or '')[:16])
print('    最近错误:', d['last_error'])
"
echo "   死信列表（含失败原因）："
curl -s "$BASE/audit/subscriptions/dead-letters?subscription_id=$SID" | python3 -c "
import sys,json
for d in json.load(sys.stdin)['dead_letters']:
    print('    seq=%s 原因=%s 最近错误=%s' % (d['event_seq'], d['dead_letter_reason'], d['last_error']))
"
echo "   死信挡住后续事件，订阅 blocked=true："
curl -s "$BASE/audit/subscriptions/$SID" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('    status=%s blocked=%s 计数=%s' % (d['status'], d['blocked'], d['counters']))
"
echo "   死信重新放回队列（清空尝试次数；回调仍不可达会再次失败）："
curl -s -X POST "$BASE/audit/subscriptions/$SID/dead-letters/$FIRST_SEQ/requeue" -d '{}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('    -> status=%s attempts=%s' % (d['status'],d['attempts']))"
echo "   暂停订阅 -> 处理一轮不投递；恢复："
curl -s -X POST "$BASE/audit/subscriptions/$SID/pause" -d '{}' \
  | python3 -c "import sys,json;print('    status =',json.load(sys.stdin)['status'])"
curl -s -X POST "$BASE/audit/subscriptions/process" -d '{}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('    暂停中处理一轮: enqueued=%s delivered=%s' % (d['enqueued'],d['delivered']))"
curl -s -X POST "$BASE/audit/subscriptions/$SID/resume" -d '{}' \
  | python3 -c "import sys,json;print('    status =',json.load(sys.stdin)['status'])"
echo "   取消订阅（迟到通知不再发送；投递历史保留）："
curl -s -X POST "$BASE/audit/subscriptions/$SID/cancel" -d '{}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('    status =',d['status'],' 投递计数 =',d['counters'])"
curl -s "$BASE/audit/subscriptions/$SID/deliveries?limit=1000" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('    投递历史保留 %d 行，状态分布:' % len(d['deliveries']))
from collections import Counter
print('   ', dict(Counter(x['status'] for x in d['deliveries'])))
"
echo "订阅流程只写自有表：源审计历史、租约、委托、索引、归档、证据包、发布计划均不被改写。"

# ---------------------------------------------------------------------------
# 24. 订阅版本切换（预创建 -> 差异 -> 原子激活 -> 边界路由 -> 审计历史）
# ---------------------------------------------------------------------------
echo
echo "== 24. 订阅版本切换 =="
# 用独立资源演示，避免与前面演练的短 TTL 租约互相干扰
VR="demo-ver-$RANDOM$RANDOM"
VGEN=$(curl -s -X POST "$BASE/leases/acquire" -H 'Content-Type: application/json' \
  -d "{\"resource\":\"$VR\",\"holder\":\"ver-1\",\"ttl_ms\":600000}" \
  | j "['lease']['generation']")
# 先写两条边界前事件（v1 范围）
curl -s -X POST "$BASE/resources/$VR/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"ver-1\",\"generation\":$VGEN,\"value\":\"before-1\"}" >/dev/null
curl -s -X POST "$BASE/resources/$VR/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"ver-1\",\"generation\":$VGEN,\"value\":\"before-2\"}" >/dev/null
VSUB=$(curl -s -X POST "$BASE/audit/subscriptions" -H 'Content-Type: application/json' \
  -d "{\"scope\":\"resource\",\"resource\":\"$VR\",\"callback_url\":\"http://127.0.0.1:9/v1\",\"start_seq\":0,\"idempotency_key\":\"demo-ver-$VR\"}")
VSID=$(echo "$VSUB" | j "['subscription_id']")
echo "   新订阅 $VSID（资源 $VR，v1 回调不可达）"
# 越过稳定历史上界的预创建 -> 416（必须在创建待激活版本之前演示）
echo "   生效序号越过稳定历史上界 -> 416 且原订阅不变："
curl -s -o /tmp/voor.json -w "    HTTP %{http_code} " -X POST \
  "$BASE/audit/subscriptions/$VSID/versions" -H 'Content-Type: application/json' \
  -d "{\"callback_url\":\"http://x/\",\"effective_seq\":999999999,\"idempotency_key\":\"demo-ver-oor-$VR\"}"
python3 -c "import json;d=json.load(open('/tmp/voor.json'));print(d['error'],'available_max_seq=%s' % d['available_max_seq'])"
# 生效序号取当前稳定历史上界（含）；预创建后边界立即钉住，下一条事件
# （下面切换后写入）即按新版本投递。后台 worker 持续扫描，故建订阅后
# 立即预创建。
EFF=$(curl -s "$BASE/audit/events?limit=1000" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['events'][-1]['seq'])")
echo "   预创建 v2（生效序号 $EFF，新回调地址，只要 write 事件），同键重放："
curl -s -X POST "$BASE/audit/subscriptions/$VSID/versions" -H 'Content-Type: application/json' \
  -d "{\"callback_url\":\"http://127.0.0.1:9/v2\",\"filters\":{\"event_types\":[\"write\"]},\"effective_seq\":$EFF,\"idempotency_key\":\"demo-ver-prep-$VR\"}" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('    v%s status=%s eff=%s' % (d['version_no'],d['status'],d['effective_seq']))"
curl -s -o /tmp/vreplay.json -w "    同键重放 HTTP %{http_code} replayed=" -X POST \
  "$BASE/audit/subscriptions/$VSID/versions" -H 'Content-Type: application/json' \
  -d "{\"callback_url\":\"http://127.0.0.1:9/v2\",\"filters\":{\"event_types\":[\"write\"]},\"effective_seq\":$EFF,\"idempotency_key\":\"demo-ver-prep-$VR\"}"
python3 -c "import json;print(json.load(open('/tmp/vreplay.json'))['replayed'])"
echo "   同键换回调 -> 409："
curl -s -o /tmp/vconf.json -w "    HTTP %{http_code} " -X POST \
  "$BASE/audit/subscriptions/$VSID/versions" -H 'Content-Type: application/json' \
  -d "{\"callback_url\":\"http://changed/\",\"effective_seq\":$EFF,\"idempotency_key\":\"demo-ver-prep-$VR\"}"
python3 -c "import json;d=json.load(open('/tmp/vconf.json'));print(d['error'],'首个差异:',d['first_difference']['path'])"
echo "   版本差异（相对当前 v1）："
curl -s "$BASE/audit/subscriptions/$VSID/versions/2/diff" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for x in d['differences']:
    print('    -',x['path'],':',x['existing'],'->',x['requested'])
"
echo "   原子激活（同键重放；换键重复激活 409）："
curl -s -X POST "$BASE/audit/subscriptions/$VSID/versions/2/activate" -H 'Content-Type: application/json' \
  -d '{"idempotency_key":"demo-ver-act-'$R'"}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('    -> v%s status=%s' % (d['version_no'],d['status']))"
curl -s -o /dev/null -w "    换键重复激活 -> HTTP %{http_code}\n" -X POST \
  "$BASE/audit/subscriptions/$VSID/versions/2/activate" -H 'Content-Type: application/json' \
  -d '{"idempotency_key":"demo-ver-act-other"}'
curl -s "$BASE/audit/subscriptions/$VSID" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('    当前版本=%s 回调=%s 版本状态=%s' % (d['current_version'],d['callback_url'],{v['version_no']:v['status'] for v in d['versions']}))
"
echo "   切换后写入两条新事件：只进入 v2（回调不可达会退避，但版本路由可见）："
curl -s -X POST "$BASE/resources/$VR/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"ver-1\",\"generation\":$VGEN,\"value\":\"after-1\"}" >/dev/null
curl -s -X POST "$BASE/resources/$VR/writes" -H 'Content-Type: application/json' \
  -d "{\"holder\":\"ver-1\",\"generation\":$VGEN,\"value\":\"after-2\"}" >/dev/null
curl -s -X POST "$BASE/audit/subscriptions/process" -d '{}' >/dev/null
curl -s "$BASE/audit/subscriptions/$VSID/deliveries?limit=10" | python3 -c "
import sys,json
for d in json.load(sys.stdin)['deliveries']:
    print('    event_seq=%s version=v%s 订阅序号=%s 状态=%s' % (d['event_seq'],d['version_no'],d['subscription_seq'],d['status']))
"
echo "   只重试某版本死信（空操作也幂等）："
curl -s -X POST "$BASE/audit/subscriptions/$VSID/versions/2/retry-dead-letters" -H 'Content-Type: application/json' \
  -d '{"idempotency_key":"demo-ver-retry"}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('    -> requeued=%s' % d['requeued'])"
echo "   订阅自己的审计历史（只追加：创建/拒绝原因/激活）："
curl -s "$BASE/audit/subscriptions/$VSID/history?limit=100" | python3 -c "
import sys,json
for e in json.load(sys.stdin)['events']:
    v = 'v%s' % e['version_no'] if e['version_no'] is not None else '-'
    print('    #%s %s %s/%s' % (e['id'], v, e['event'], e['outcome']))
"
curl -s -X POST "$BASE/audit/subscriptions/$VSID/cancel" -d '{}' >/dev/null
echo "版本切换只写订阅自有表：租约、委托、原始审计事件与已有投递记录均不被改写。"
