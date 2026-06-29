#!/usr/bin/env bash
# End-to-end functional test: a REAL okboy server + REAL HMAC knock + REAL
# nftables, all inside an isolated network namespace so it never touches the
# host / k8s firewall. Validates the full HTTP -> auth -> firewall -> db -> nft
# chain. Run on Linux as a user with passwordless sudo:
#
#   bash scripts/e2e-test.sh [path/to/okboy]
set -u
BIN="${1:-$HOME/nft-okboy-fleet/dist/okboy}"
NS=okboy_e2e
TABLE=okboy_e2e
WORK=/tmp/okboy-e2e
PASS=0
FAIL=0
chk() { if eval "$2"; then echo "  PASS: $1"; PASS=$((PASS + 1)); else echo "  FAIL: $1"; FAIL=$((FAIL + 1)); fi; }
nsx() { sudo ip netns exec "$NS" env PATH=/usr/sbin:/usr/bin:/bin "$@"; }

[ -x "$BIN" ] || { echo "binary not found/executable: $BIN"; exit 1; }
rm -rf "$WORK"; mkdir -p "$WORK/backups"
cat > "$WORK/config.yaml" <<EOF
listen_host: 127.0.0.1
listen_port: 5000
proto: tcp
rule_prefix: okboy
trusted_proxies: ["127.0.0.1", "::1"]
nft_table: $TABLE
nft_chain: input
nft_priority: -150
db_path: $WORK/okboy.db
backup_dir: $WORK/backups
EOF

# Fresh isolated netns (everything below runs inside it → zero host/k8s impact).
sudo ip netns del "$NS" 2>/dev/null || true
sudo ip netns add "$NS"
nsx ip link set lo up

# Seed (DB-only ops, run in the netns for total isolation).
ua=$(nsx "$BIN" -c "$WORK/config.yaml" user-add alice 2>&1)
SECRET=$(echo "$ua" | grep -oE '[0-9a-f]{64}' | head -1)
nsx "$BIN" -c "$WORK/config.yaml" group-add ssh 22 >/dev/null 2>&1
nsx "$BIN" -c "$WORK/config.yaml" user-join alice ssh >/dev/null 2>&1
[ -n "$SECRET" ] || { echo "FAIL: could not seed user/secret"; echo "$ua"; sudo ip netns del "$NS"; exit 1; }
echo "seeded: alice (secret ${SECRET:0:8}...), group ssh:22"

# Start the server in the netns.
nsx "$BIN" -c "$WORK/config.yaml" serve >"$WORK/serve.log" 2>&1 &
sleep 2

hdr() { local ts sig; ts=$(date +%s); sig=$(printf '%s' "alice:$ts" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}'); echo "HMAC-SHA256 alice:$ts:$sig"; }
knock() { nsx curl -s -X POST -H "Authorization: $(hdr)" -H "X-Real-IP: $1" http://127.0.0.1:5000/api/knock; }
nftdump() { nsx nft list table inet "$TABLE" 2>/dev/null; }

echo "== knock 1: 203.0.113.50 =="
R1=$(knock 203.0.113.50); echo "  resp: $R1"
chk "knock1 changed=true" 'echo "$R1" | grep -q "\"changed\": *true"'
N1=$(nftdump)
chk "nft rule: 203.0.113.50 dport 22 comment okboy:alice:ssh" 'echo "$N1" | grep -q "203.0.113.50" && echo "$N1" | grep -q "okboy:alice:ssh" && echo "$N1" | grep -q "dport 22"'

echo "== knock 2: 198.51.100.7 (IP change) =="
R2=$(knock 198.51.100.7); echo "  resp: $R2"
chk "knock2 references new IP" 'echo "$R2" | grep -q "198.51.100.7"'
N2=$(nftdump)
chk "nft now has 198.51.100.7" 'echo "$N2" | grep -q "198.51.100.7"'
chk "old IP 203.0.113.50 removed" '! echo "$N2" | grep -q "203.0.113.50"'

echo "== knock 3: same IP heartbeat =="
R3=$(knock 198.51.100.7); echo "  resp: $R3"
chk "heartbeat changed=false" 'echo "$R3" | grep -q "\"changed\": *false"'

echo "== bad signature -> 401 =="
CODE=$(nsx curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: HMAC-SHA256 alice:1:deadbeef" -H "X-Real-IP: 9.9.9.9" http://127.0.0.1:5000/api/knock)
chk "bad sig -> 401" '[ "$CODE" = "401" ]'

echo "== /health =="
H=$(nsx curl -s http://127.0.0.1:5000/health)
chk "health ok" 'echo "$H" | grep -q "\"ok\": *true"'

# Teardown.
sudo pkill -f "$BIN.*serve" 2>/dev/null || true
sleep 0.3
sudo ip netns del "$NS" 2>/dev/null || true
echo ""
echo "RESULT: $PASS passed, $FAIL failed"
sudo nft list tables 2>/dev/null | grep -q "$TABLE" && echo "WARN: host has $TABLE table" || echo "host firewall clean (netns isolated)"
[ "$FAIL" -eq 0 ]
