#!/usr/bin/env bash
# 端到端演示：契约登记 -> 差异 -> 预演 -> 生效门禁 -> 切换冻结 ->
#             校验失败隔离/HOL -> 映射修复重试 -> 撤销。
set -u
cd "$(dirname "$0")"

DB=$(mktemp -u /tmp/audit_contracts.XXXXXX.db)
PORT=${PORT:-18080}
BASE="http://127.0.0.1:${PORT}"

python3 -m app --db "$DB" --port "$PORT" >/tmp/audit_demo_server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -f "$DB" "$DB-wal" "$DB-shm"' EXIT
sleep 1

J() { python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin),ensure_ascii=False))'; }
req() { # method path [json]
  local m=$1 p=$2 body=${3:-}
  if [ "$m" = GET ]; then
    curl -s -X GET "$BASE$p"
  else
    curl -s -X "$m" "$BASE$p" -H 'Content-Type: application/json' -d "$body"
  fi
  echo
}
show() { echo; echo "==== $* ===="; }

V1='{"type":"object","unknown_policy":"strict","properties":{
 "actor":{"type":"string"},
 "action":{"type":"string","enum":["login","logout"]},
 "note":{"type":"string","required":false,"ignorable":true}}}'
V2='{"type":"object","unknown_policy":"strip","properties":{
 "actor":{"type":"string"},
 "action":{"type":"string","enum":["login","logout","sudo"]},
 "reason":{"type":"string","required":false},
 "note":{"type":"string","required":false,"ignorable":true}}}'

show "1) 登记契约 v1 / v2"
req PUT /contracts/audit.user/versions/1.0.0 "{\"spec\":$V1}"
req PUT /contracts/audit.user/versions/2.0.0 "{\"spec\":$V2}"

show "2) 字段级差异与双向兼容性"
req POST /contracts/audit.user/diff '{"old_version":"1.0.0","new_version":"2.0.0"}' | J

show "3) 建订阅 + 入库三条稳定历史"
req POST /subscriptions/demo '{}'
req POST /subscriptions/demo/events '{"seq":1,"event_type":"audit.user","payload":{"actor":"a","action":"login"}}'
req POST /subscriptions/demo/events '{"seq":2,"event_type":"audit.user","payload":{"actor":"b","action":"sudo"}}'
req POST /subscriptions/demo/events '{"seq":3,"event_type":"audit.user","payload":{"actor":"c","action":"logout"}}'

show "4) v1 全量预演：seq2 枚举越界 -> failed（不能生效）"
req POST /subscriptions/demo/dry-runs '{"event_type":"audit.user","version":"1.0.0"}' | J
show "   强行激活 v1 被门禁拒绝"
req POST /subscriptions/demo/activations '{"event_type":"audit.user","version":"1.0.0","effective_seq":1}'

show "5) 只在 [1,1] 预演 v1 通过并生效；扫描后 seq1 按 v1 冻结"
req POST /subscriptions/demo/dry-runs '{"event_type":"audit.user","version":"1.0.0","from_seq":1,"to_seq":1}' | J
req POST /subscriptions/demo/activations '{"event_type":"audit.user","version":"1.0.0","effective_seq":1}'
req POST /subscriptions/demo/scan '{}'

show "6) 生效序号越界：seq=9 越过稳定水位(3) 被拒；seq=1 早于扫描位置 被拒"
req POST /subscriptions/demo/dry-runs '{"event_type":"audit.user","version":"2.0.0","from_seq":2,"to_seq":3}' >/dev/null
req POST /subscriptions/demo/activations '{"event_type":"audit.user","version":"2.0.0","effective_seq":9}'
req POST /subscriptions/demo/activations '{"event_type":"audit.user","version":"2.0.0","effective_seq":1}'

show "7) 在 seq=2 合法切换 v2；seq2 此前已按 v1 隔离，映射/重试或换约后重试放行"
req POST /subscriptions/demo/activations '{"event_type":"audit.user","version":"2.0.0","effective_seq":2}'
req POST /subscriptions/demo/quarantine/2/retry '{}' | J
show "   通知冻结版本严格按生效点：seq1=1.0.0，seq2/3=2.0.0，且各只有一条通知"
req GET /subscriptions/demo/notifications | J

show "8) 未知字段 strict 隔离 + HOL：新订阅演示 v1 strict 下 junk 被挡"
req POST /subscriptions/hol '{}' >/dev/null
req POST /subscriptions/hol/events '{"seq":1,"event_type":"audit.user","payload":{"actor":"a","action":"login"}}' >/dev/null
req POST /subscriptions/hol/dry-runs '{"event_type":"audit.user","version":"1.0.0","from_seq":1,"to_seq":1}' >/dev/null
req POST /subscriptions/hol/activations '{"event_type":"audit.user","version":"1.0.0","effective_seq":1}' >/dev/null
req POST /subscriptions/hol/scan '{}' >/dev/null
req POST /subscriptions/hol/events '{"seq":2,"event_type":"audit.user","payload":{"actor":"b","action":"login","junk":true}}' >/dev/null
req POST /subscriptions/hol/events '{"seq":3,"event_type":"audit.user","payload":{"actor":"c","action":"login"}}' >/dev/null
req POST /subscriptions/hol/scan '{}'
req GET /subscriptions/hol/quarantine | J

show "9) 在阻断点切到 strip 的 v2 并重试：junk 被规范化删除，身份不变"
req POST /subscriptions/hol/dry-runs '{"event_type":"audit.user","version":"2.0.0","from_seq":2,"to_seq":3}' >/dev/null
req POST /subscriptions/hol/activations '{"event_type":"audit.user","version":"2.0.0","effective_seq":2}'
req POST /subscriptions/hol/quarantine/2/retry '{}' | J
show "   再重试一次：幂等，不产生重复通知"
req POST /subscriptions/hol/quarantine/2/retry '{"idempotency_key":"R1"}' | J

show "10) 隔离查询（原始事件摘要/失败字段/当前契约/来源摘要）与最终通知顺序"
req GET /subscriptions/hol/quarantine | J
req GET /subscriptions/hol/notifications | J

show "11) 逐字段来源说明：seq2 隔离尝试(1) 与 strip 恢复尝试(2)，只记录路径/类型/摘要/规则"
req GET /subscriptions/hol/notifications/2/provenance | J
show "    重试尝试列表（只追加，含哈希链锚点）"
req GET /subscriptions/hol/notifications/2/attempts | J
show "    修复前->修复后逐字段比较：junk 被 strip 剥离、值摘要/规则对比"
req GET '/subscriptions/hol/notifications/2/compare?from=1&to=2' | J

show "12) 订阅审计历史（差异/拒绝/隔离/恢复全部可审计）"
req GET /subscriptions/demo/audit-history | J
echo
echo "演示完成。服务日志: /tmp/audit_demo_server.log"
