#!/usr/bin/env bash
# End-to-end fleet verification: a hub (firewall_backend: none) + a real knock +
# an edge agent, all inside a mount+net namespace with ufw ENABLED and a private
# /etc/ufw — so it exercises the REAL hub -> desired-state -> agent -> firewall
# path with ZERO host impact (the namespace is torn down on exit; the host's
# firewall config and network stack are never touched).
#
# The agent backend is selectable so the SAME hub is verified against both edge
# firewalls (the heterogeneous-fleet claim):
#   AGENT_BACKEND=ufw       (default) — verify via `ufw status`
#   AGENT_BACKEND=nftables            — verify via `nft list table inet okboy`
#
# Usage (Linux box with ufw + nft + unshare + passwordless sudo, no Go required):
#   scp okboy scripts/e2e-fleet.sh <box>:/tmp/
#   sudo AGENT_BACKEND=ufw      bash /tmp/e2e-fleet.sh
#   sudo AGENT_BACKEND=nftables bash /tmp/e2e-fleet.sh
set -uo pipefail

BIN="${BIN:-/tmp/okboy}"
AGENT_BACKEND="${AGENT_BACKEND:-ufw}"
WORK=/tmp/fleet-e2e

if [ "${IN_NS:-}" != "1" ]; then
	command -v unshare >/dev/null || { echo "unshare not found"; exit 1; }
	[ -x "$BIN" ] || { echo "okboy binary not executable: $BIN"; exit 1; }
	rm -rf "$WORK"; mkdir -p "$WORK"
	export IN_NS=1 BIN WORK AGENT_BACKEND
	exec unshare --mount --net --fork bash "$0" "$@"
fi

FAILS=0
ok()   { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS + 1)); }

# Backend-aware rule inspection (the agent's managed rules, whichever firewall).
dump_rules() {
	case "$AGENT_BACKEND" in
		ufw)      ufw status numbered ;;
		nftables) nft list table inet okboy 2>/dev/null ;;
	esac
}
has_ip()    { # has_ip <ip> : a managed 18080 rule for <ip> exists
	case "$AGENT_BACKEND" in
		ufw)      ufw status numbered | grep -qE "18080/tcp.* $1( |$)" ;;
		nftables) nft list table inet okboy 2>/dev/null | grep -qE "saddr $1 .*dport 18080" ;;
	esac
}
any_18080() {
	case "$AGENT_BACKEND" in
		ufw)      ufw status numbered | grep -q '18080/tcp' ;;
		nftables) nft list table inet okboy 2>/dev/null | grep -q 'dport 18080' ;;
	esac
}

echo "### e2e (agent backend: $AGENT_BACKEND) — inside mount+net namespace, host untouched ###"
ip link set lo up
cp -a /etc/ufw "$WORK/etc-ufw"
mount --bind "$WORK/etc-ufw" /etc/ufw
export LANG=C LC_ALL=C
ufw --force enable >/dev/null   # ufw stays enabled in-ns even for the nft run (harmless)

cat > "$WORK/hub.yaml" <<EOF
firewall_backend: none
rule_prefix: okboy
listen_host: 127.0.0.1
listen_port: 5000
db_path: $WORK/hub.db
trusted_proxies: ["127.0.0.1", "::1"]
EOF
cat > "$WORK/agent.yaml" <<EOF
firewall_backend: $AGENT_BACKEND
rule_prefix: okboy
EOF

"$BIN" -c "$WORK/hub.yaml" serve >"$WORK/hub.log" 2>&1 &
HUBPID=$!
for _ in $(seq 1 20); do curl -fsS http://127.0.0.1:5000/health >/dev/null 2>&1 && break; sleep 0.5; done
if curl -fsS http://127.0.0.1:5000/health >/dev/null 2>&1; then ok "hub serving"; else fail "hub did not start"; sed 's/^/    hub: /' "$WORK/hub.log"; fi

SECRET=$("$BIN" -c "$WORK/hub.yaml" user-add alice | grep -oE '[0-9a-f]{64}' | head -1)
"$BIN" -c "$WORK/hub.yaml" group-add web 8080 >/dev/null
"$BIN" -c "$WORK/hub.yaml" user-join alice web >/dev/null
TOKEN=$("$BIN" -c "$WORK/hub.yaml" node-add edge-1 | grep -oE '[0-9a-f]{64}' | head -1)
"$BIN" -c "$WORK/hub.yaml" group-target add web edge-1 18080 >/dev/null
[ -n "$SECRET" ] && ok "user + secret" || fail "no user secret"
[ -n "$TOKEN" ]  && ok "node + token"  || fail "no node token"

knock() {
	local ip="$1" ts sig
	ts=$(date +%s)
	sig=$(printf '%s' "alice:$ts" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
	curl -sS -X POST http://127.0.0.1:5000/api/knock \
		-H "Authorization: HMAC-SHA256 alice:$ts:$sig" -H "X-Real-IP: $ip" >/dev/null
}

knock 203.0.113.50
"$BIN" -c "$WORK/agent.yaml" agent --hub http://127.0.0.1:5000 --node edge-1 --token "$TOKEN" --interval 2 >"$WORK/agent.log" 2>&1 &
AGENTPID=$!
sleep 5

echo "=== managed rules after agent apply ($AGENT_BACKEND) ==="; dump_rules | sed 's/^/    /'
if has_ip 203.0.113.50; then ok "rule applied: 203.0.113.50 -> 18080"; else fail "rule not applied"; sed 's/^/    agent: /' "$WORK/agent.log"; fi

knock 203.0.113.99; sleep 5
if has_ip 203.0.113.99; then ok "rule moved to 203.0.113.99"; else fail "rule not updated"; fi
if dump_rules | grep -q '203\.0\.113\.50'; then fail "stale IP 203.0.113.50 present"; else ok "stale IP removed"; fi

"$BIN" -c "$WORK/hub.yaml" user-leave alice web >/dev/null; sleep 5
if any_18080; then fail "rule present after leave"; else ok "rule removed after leave"; fi

"$BIN" -c "$WORK/hub.yaml" user-join alice web >/dev/null
knock 203.0.113.77; sleep 5
has_ip 203.0.113.77 && echo "    (rule present before hub kill)"
kill "$HUBPID" 2>/dev/null; sleep 5
if has_ip 203.0.113.77; then ok "fail-safe: rule retained while hub down"; else fail "rule flushed on hub outage"; fi

kill "$AGENTPID" 2>/dev/null || true
echo
echo "### RESULT ($AGENT_BACKEND): $FAILS failure(s) ###"
[ "$FAILS" -eq 0 ] && echo "ALL_E2E_PASS" || echo "E2E_HAD_FAILURES"
exit "$FAILS"
