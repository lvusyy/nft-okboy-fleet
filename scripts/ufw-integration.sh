#!/usr/bin/env bash
# Real-ufw integration harness. Runs the okboy ufw integration test binary inside
# fresh mount + network namespaces with a PRIVATE, throwaway /etc/ufw and ufw
# ENABLED — so it exercises real `ufw` without touching the host:
#
#   - --net  : a fresh network namespace (only `lo`); `ufw enable`'s default-deny
#              and every rule live here, NOT in the host stack → host SSH is safe.
#   - --mount: a private mount namespace; we bind-mount a copy of /etc/ufw over
#              /etc/ufw so the host's ufw config (incl. the ENABLED flag) is never
#              modified. Both namespaces vanish when the test process exits.
#
# The test box needs ufw + iproute2 + passwordless sudo. No Go is required on the
# box — cross-compile the test binary elsewhere and copy it over:
#
#   # on a Go host (any OS):
#   GOOS=linux GOARCH=amd64 go test -tags integration -c -o okboy-ufwtest ./internal/firewall/
#   scp okboy-ufwtest <testbox>:/tmp/
#   # on the test box:
#   sudo bash scripts/ufw-integration.sh /tmp/okboy-ufwtest
set -euo pipefail

BIN="$(readlink -f "${1:?usage: ufw-integration.sh <test-binary>}")"
[ -x "$BIN" ] || { echo "test binary not executable: $BIN" >&2; exit 1; }
command -v ufw      >/dev/null || { echo "ufw not found"      >&2; exit 1; }
command -v unshare  >/dev/null || { echo "unshare not found"  >&2; exit 1; }

export BIN
export TMP="$(mktemp -d /tmp/ufw-it.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

# Inner script runs inside the new namespaces; it reads $BIN/$TMP from the
# (inherited) environment, so no fragile quote interpolation is needed.
unshare --mount --net --fork bash -c '
  set -e
  ip link set lo up
  cp -a /etc/ufw "$TMP/etc-ufw"
  mount --bind "$TMP/etc-ufw" /etc/ufw
  export LANG=C LC_ALL=C
  ufw --force enable >/dev/null
  "$BIN" -test.run TestUfwIntegration -test.v
'
