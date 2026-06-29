#!/bin/sh
# okboy installer — one command to get a working server.
#
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
#
# Re-run any time to refresh the binary (config + database are preserved).
# Day-2 upgrades are easier still:  sudo okboy upgrade
#
# Env knobs:  OKBOY_VERSION=v0.2.0  (pin a version)   NO_COLOR=1  (plain output)
set -eu

REPO="lvusyy/nft-okboy-fleet"
RAW="https://raw.githubusercontent.com/$REPO"
BIN_DIR="/opt/okboy";        BIN="$BIN_DIR/okboy"
CONF_DIR="/etc/okboy";       CONF="$CONF_DIR/config.yaml"
DATA_DIR="/var/lib/okboy"
UNIT="/etc/systemd/system/okboy.service"

# ---- pretty output (auto-disabled when not a TTY or NO_COLOR set) ----
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B='\033[1m'; CY='\033[1;36m'; GR='\033[1;32m'; YL='\033[1;33m'; RD='\033[1;31m'; X='\033[0m'
else
  B=''; CY=''; GR=''; YL=''; RD=''; X=''
fi
say()  { printf "${CY}::${X} %s\n" "$*"; }
ok()   { printf "${GR}✓${X} %s\n" "$*"; }
warn() { printf "${YL}!${X} %s\n" "$*" >&2; }
die()  { printf "${RD}✗ %s${X}\n" "$*" >&2; exit 1; }

# ---- preflight ----
[ "$(id -u)" = 0 ] || die "Please run as root (use sudo)."
[ "$(uname -s)" = "Linux" ] || die "okboy runs on Linux only."
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l)        ARCH=armv7 ;;
  armv6l)        ARCH=armv6 ;;
  i386|i686)     ARCH=386 ;;
  loongarch64)   ARCH=loong64 ;;
  ppc64le)       ARCH=ppc64le ;;
  riscv64)       ARCH=riscv64 ;;
  s390x)         ARCH=s390x ;;
  *) die "No prebuilt binary for $(uname -m). Build from source." ;;
esac
ASSET="okboy-linux-$ARCH"
for t in curl install sha256sum systemctl; do
  command -v "$t" >/dev/null 2>&1 || die "Required command not found: $t"
done
command -v nft >/dev/null 2>&1 || warn "nft (nftables) is not installed — install it before starting okboy."

# ---- resolve version (latest release, or OKBOY_VERSION) ----
VER="${OKBOY_VERSION:-}"
if [ -z "$VER" ]; then
  # Resolve the latest tag from the releases/latest redirect (not the GitHub API),
  # so it works through the SAME CN-friendly mirrors as the downloads — the API host
  # is often blocked on networks where the mirror still serves.
  say "Resolving latest release…"
  for pre in "" "https://ghfast.top/" "https://gh-proxy.com/"; do
    VER=$(curl -fsSL --connect-timeout 8 --max-time 25 -o /dev/null -w '%{url_effective}' \
          "${pre}https://github.com/$REPO/releases/latest" 2>/dev/null | sed -n 's#.*/tag/##p')
    [ -n "$VER" ] && break
  done
  [ -n "$VER" ] || die "Could not resolve the latest release. Set OKBOY_VERSION=vX.Y.Z and retry."
fi

# ---- download helper: try direct, then CN-friendly mirrors ----
# curl gets a connect timeout AND a stall guard (--speed-limit/--speed-time): the
# GitHub release CDN can connect then reset mid-transfer, which would hang a plain
# `curl` forever and never fail over to a mirror. Abort a transfer that drops below
# 1 KB/s for 20s so the next mirror is tried.
dl() { # dl <github-url> <out>
  for pre in "" "https://ghfast.top/" "https://gh-proxy.com/"; do
    if curl -fsSL --connect-timeout 8 --speed-limit 1024 --speed-time 20 --max-time 600 \
        "$pre$1" -o "$2" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say "Downloading okboy $VER ($ASSET)…"
dl "https://github.com/$REPO/releases/download/$VER/$ASSET" "$TMP/okboy" || die "Download failed."
if dl "https://github.com/$REPO/releases/download/$VER/SHA256SUMS" "$TMP/sums"; then
  exp=$(awk -v f="$ASSET" '$2==f {print $1}' "$TMP/sums")
  got=$(sha256sum "$TMP/okboy" | cut -d' ' -f1)
  [ -n "$exp" ] && [ "$exp" = "$got" ] || die "Checksum mismatch — aborting."
  ok "checksum verified"
else
  warn "No published SHA256SUMS; skipping verification."
fi

UPGRADE=0; [ -x "$BIN" ] && UPGRADE=1

# ---- install binary + data dir ----
install -d -m 755 "$BIN_DIR"
install -d -m 700 "$DATA_DIR"
install -m 755 "$TMP/okboy" "$BIN"
ok "binary → $BIN ($VER)"

# ---- config (written once; an existing config is never overwritten) ----
if [ ! -f "$CONF" ]; then
  install -d -m 700 "$CONF_DIR"
  dl "$RAW/$VER/config.example.yaml" "$TMP/conf" || die "Could not fetch the default config."
  install -m 600 "$TMP/conf" "$CONF"
  ok "config → $CONF (production-sane defaults)"
else
  ok "kept existing config: $CONF"
fi

# ---- systemd unit ----
if [ ! -f "$UNIT" ]; then
  dl "$RAW/$VER/deploy/okboy.service" "$TMP/unit" || die "Could not fetch the systemd unit."
  install -m 644 "$TMP/unit" "$UNIT"
  systemctl daemon-reload
  systemctl enable okboy >/dev/null 2>&1 || true
  ok "service installed and enabled at boot"
fi

# ---- bootstrap an admin (fresh install only) ----
SECRET=""
if [ "$UPGRADE" = 0 ]; then
  say "Creating the admin user…"
  out=$("$BIN" -c "$CONF" user-add admin --admin 2>&1) || true
  SECRET=$(printf '%s' "$out" | grep -oE '[0-9a-f]{64}' | head -n1) || true
fi

# ---- (re)start ----
systemctl restart okboy 2>/dev/null || true
sleep 1
if systemctl is-active --quiet okboy; then
  ok "okboy is running"
else
  warn "service is not active yet — check: journalctl -u okboy -e"
fi

# ---- summary (credentials LAST, highlighted) ----
echo
if [ "$UPGRADE" = 1 ]; then
  ok "Upgraded to $VER. Config and database were preserved."
  echo "  Manage:  okboy user-list   |   Upgrade later:  sudo okboy upgrade"
  exit 0
fi

printf "${B}════════════════════════════════════════════════════════════${X}\n"
ok "okboy $VER installed."
echo
echo "  Web console:  https://<your-domain>/   (set up nginx + TLS — see deploy/nginx-okboy.conf)"
echo "  Local check:  curl -s http://127.0.0.1:5000/health"
echo
if [ -n "$SECRET" ]; then
  printf "  ${YL}${B}Admin credentials (shown once — store them now):${X}\n"
  printf "    username:  ${B}admin${X}\n"
  printf "    secret:    ${B}%s${X}\n" "$SECRET"
else
  warn "Could not auto-create admin. Create one with: okboy user-add <name> --admin"
fi
printf "${B}════════════════════════════════════════════════════════════${X}\n"
echo
echo "  Next: open a port group and authorize the admin, e.g."
echo "    okboy group-add ssh 22"
echo "    okboy user-join admin ssh"
echo
echo "  Then open the Web console, enter username + secret, and Connect."
echo "  Upgrade any time:  sudo okboy upgrade"
