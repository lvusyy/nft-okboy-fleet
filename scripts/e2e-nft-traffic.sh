#!/usr/bin/env bash
# Traffic-level check of the nftables backend — what the other tests cannot see,
# since they only inspect rule listings. Two network namespaces joined by a veth
# pair: "okb-srv" runs nft-okboy and a TCP listener on a managed port; "okb-cli"
# connects from an allowlisted (10.99.0.2) and a non-allowlisted (10.99.0.3)
# address. Nothing outside the two namespaces is touched.
#
#   A. standalone server (firewall_backend: nftables)
#      - allowlisted client connects, the other is dropped; loopback unaffected
#      - an established session survives losing its allow rule; a new one does not
#      - another firewall dropping the port (as UFW's default deny would) blocks
#        the allowlisted client too, and the server reports it at startup
#   B. hub (firewall_backend: none) + agent (nftables)
#      - same allow/drop result on the agent's host
#      - deleting the node on the hub makes the agent drop its allow rules
#      - the guard outlives both the allow rules and the hub: after a flush while
#        the hub rejects the node, and after a restart with the hub down, the
#        port is closed again at once
#
# Usage (root; Linux with nft, iproute2, curl, openssl, python3):
#   sudo BIN=/tmp/nft-okboy bash scripts/e2e-nft-traffic.sh
set -uo pipefail

BIN="${BIN:-/tmp/nft-okboy}"
WORK="$(mktemp -d /tmp/okb-traffic.XXXXXX)"
SRV=okb-srv
CLI=okb-cli
PORT=18080
FAILS=0
ok()   { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS + 1)); }
S()    { ip netns exec "$SRV" "$@"; }
C()    { ip netns exec "$CLI" "$@"; }
# bg <cmd...>: start <cmd> in the server namespace in the background. `ip netns
# exec` execs the command, so $! is its real PID (a function would add a subshell).
bg()   { ip netns exec "$SRV" "$@" & PIDS+=($!); }

[ -x "$BIN" ] || { echo "nft-okboy binary not executable: $BIN"; exit 1; }
PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	ip netns del "$SRV" 2>/dev/null
	ip netns del "$CLI" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

ip netns add "$SRV" && ip netns add "$CLI" || exit 1
ip link add okb-vs type veth peer name okb-vc
ip link set okb-vs netns "$SRV" && ip link set okb-vc netns "$CLI"
S ip link set lo up && S ip addr add 10.99.0.1/24 dev okb-vs && S ip link set okb-vs up
C ip link set lo up && C ip addr add 10.99.0.2/24 dev okb-vc && C ip addr add 10.99.0.3/24 dev okb-vc && C ip link set okb-vc up

# An echo server on the managed port (so a probe can prove a round trip).
bg python3 -c '
import socket, threading
def echo(c):
    try:
        while True:
            d = c.recv(1024)
            if not d:
                break
            c.sendall(d)
    except Exception:
        pass
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", '"$PORT"')); s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
'

# probe <src>: can a NEW connection from <src> reach the port? (2 s timeout)
probe() {
	C python3 -c '
import socket, sys
s = socket.socket(); s.settimeout(2); s.bind((sys.argv[1], 0))
try:
    s.connect(("10.99.0.1", '"$PORT"')); print("open")
except Exception:
    print("blocked")
' "$1"
}
expect() { # expect <src> <open|blocked> <what>
	local got; got=$(probe "$1")
	if [ "$got" = "$2" ]; then ok "$3 ($1 → $got)"; else fail "$3 ($1 → $got, want $2)"; fi
}

cat > "$WORK/srv.yaml" <<EOF
firewall_backend: nftables
rule_prefix: nft-okboy
listen_host: 127.0.0.1
listen_port: 5000
db_path: $WORK/srv.db
trusted_proxies: ["127.0.0.1", "::1"]
EOF

SECRET=$(S "$BIN" -c "$WORK/srv.yaml" user-add alice | grep -oE '[0-9a-f]{64}' | head -1)
S "$BIN" -c "$WORK/srv.yaml" group-add web "$PORT" >/dev/null
S "$BIN" -c "$WORK/srv.yaml" user-join alice web >/dev/null

knock() { # knock <client ip>
	local ts sig
	ts=$(date +%s)
	sig=$(printf '%s' "alice:$ts" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
	S curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:5000/api/knock \
		-H "Authorization: HMAC-SHA256 alice:$ts:$sig" -H "X-Real-IP: $1"
}
serve() { # serve <config> <log>: start the server, wait for /health
	bg "$BIN" -c "$1" serve >"$2" 2>&1
	for _ in $(seq 1 40); do S curl -fsS http://127.0.0.1:5000/health >/dev/null 2>&1 && return 0; sleep 0.25; done
	echo "server did not start:"; sed 's/^/    /' "$2"; return 1
}

echo "### A. standalone server, nftables backend"
serve "$WORK/srv.yaml" "$WORK/srv.log" || exit 1
SRVPID=${PIDS[-1]}
expect 10.99.0.3 blocked "guard: managed port closed before anyone knocks"
[ "$(knock 10.99.0.2)" = 200 ] && ok "knock from 10.99.0.2" || fail "knock failed"
expect 10.99.0.2 open    "allowlisted client connects"
expect 10.99.0.3 blocked "non-allowlisted client is dropped"
S python3 -c 'import socket; socket.create_connection(("127.0.0.1", '"$PORT"'), 2)' 2>/dev/null \
	&& ok "loopback is not guarded" || fail "loopback was blocked"

# An established session outlives its allow rule; new attempts do not.
C python3 -c '
import socket, time
s = socket.create_connection(("10.99.0.1", '"$PORT"'), 2, source_address=("10.99.0.2", 0))
open("'"$WORK"'/est.ready", "w").close()
time.sleep(6)
s.settimeout(3)
try:
    s.sendall(b"ping"); print("alive" if s.recv(16) == b"ping" else "dead")
except Exception:
    print("dead")
' >"$WORK/est.out" &
EST=$!
for _ in $(seq 1 20); do [ -e "$WORK/est.ready" ] && break; sleep 0.2; done
[ "$(knock 10.99.0.9)" = 200 ] || fail "knock from a new IP failed" # alice moves: 10.99.0.2 loses its rule
expect 10.99.0.2 blocked "old IP: new connections dropped after the IP moved"
wait "$EST"
[ "$(cat "$WORK/est.out")" = alive ] && ok "old IP: established session survived" || fail "established session was cut"

# Another firewall that drops the port (like UFW's default deny) wins: an accept
# in nft-okboy's chain is not final. The server must say so at startup.
[ "$(knock 10.99.0.2)" = 200 ] || fail "knock back from 10.99.0.2 failed"
S nft add table inet hostfw
S nft add chain inet hostfw input '{ type filter hook input priority 0; policy accept; }'
S nft add rule inet hostfw input tcp dport "$PORT" drop
expect 10.99.0.2 blocked "another firewall's drop still wins over the allowlist"
kill "$SRVPID"; wait "$SRVPID" 2>/dev/null
serve "$WORK/srv.yaml" "$WORK/srv2.log" || exit 1
SRVPID=${PIDS[-1]}
grep -q "other firewalls also filter incoming traffic" "$WORK/srv2.log" \
	&& ok "startup warns about the other firewall" || { fail "no conflict warning"; sed 's/^/    /' "$WORK/srv2.log"; }
S nft delete table inet hostfw
expect 10.99.0.2 open "allowlisted again once the other firewall is gone"
kill "$SRVPID"; wait "$SRVPID" 2>/dev/null
S nft delete table inet nft_okboy

echo "### B. hub (backend none) + agent (nftables)"
sed -e 's/^firewall_backend: nftables/firewall_backend: none/' "$WORK/srv.yaml" >"$WORK/hub.yaml"
TOKEN=$(S "$BIN" -c "$WORK/hub.yaml" node-add edge | grep -oE '[0-9a-f]{64}' | head -1)
S "$BIN" -c "$WORK/hub.yaml" group-target add web edge "$PORT" >/dev/null
serve "$WORK/hub.yaml" "$WORK/hub.log" || exit 1
HUBPID=${PIDS[-1]}
cat > "$WORK/agent.yaml" <<EOF
firewall_backend: nftables
rule_prefix: nft-okboy
agent_allowed_ports: [$PORT]
EOF
agent() { # agent <log>: start the agent (guard state kept in $WORK)
	NFT_OKBOY_TOKEN="$TOKEN" bg "$BIN" -c "$WORK/agent.yaml" agent --hub http://127.0.0.1:5000 --node edge \
		--interval 1 --state "$WORK/agent-guard.json" >"$1" 2>&1
}
agent "$WORK/agent.log"
AGENTPID=${PIDS[-1]}
[ "$(knock 10.99.0.2)" = 200 ] || fail "knock via hub failed"
sleep 3
expect 10.99.0.2 open    "agent: allowlisted client connects"
expect 10.99.0.3 blocked "agent: non-allowlisted client is dropped"
S "$BIN" -c "$WORK/hub.yaml" node-del edge >/dev/null
sleep 3
expect 10.99.0.2 blocked "agent: node deleted on the hub → its allow rules are gone"
grep -q "rejected this node's token" "$WORK/agent.log" && ok "agent logged the revocation" || { fail "no revocation log"; sed 's/^/    /' "$WORK/agent.log"; }

# Fail closed, not open: the ruleset flushed (systemctl restart nftables) while
# the hub rejects the node, then a reboot-like restart with the hub down.
S nft delete table inet nft_okboy
sleep 3
expect 10.99.0.3 blocked "agent: guard back after a flush while the hub rejects the node"
kill "$AGENTPID" "$HUBPID"; wait "$AGENTPID" "$HUBPID" 2>/dev/null
S nft delete table inet nft_okboy
agent "$WORK/agent2.log"
sleep 2
expect 10.99.0.3 blocked "agent: restarted with the hub down → guard back before any answer"

echo
echo "### RESULT (nft traffic): $FAILS failure(s) ###"
[ "$FAILS" -eq 0 ] && echo "ALL_TRAFFIC_PASS" || echo "TRAFFIC_HAD_FAILURES"
exit "$FAILS"
