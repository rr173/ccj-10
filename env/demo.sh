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
