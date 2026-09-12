#!/usr/bin/env bash
# 端到端演练：获取租约 -> 双时钟抗拨表 -> 交接 -> 旧世代号被栅栏拒绝 -> 审计反查
#             -> 安全转移（幂等/防重放）-> 完整租约历史
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
