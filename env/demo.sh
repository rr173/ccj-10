#!/usr/bin/env bash
# 端到端演练：获取租约 -> 双时钟抗拨表 -> 交接 -> 旧世代号被栅栏拒绝 -> 审计反查
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
