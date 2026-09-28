#!/bin/sh
# nft-okboy installer — one command to get a working server.
#
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
#
# Re-run any time to refresh the binary (config + database are preserved).
# Day-2 upgrades are easier still:  sudo nft-okboy upgrade
#
# Env knobs:  NFT_OKBOY_VERSION=v0.2.0  (pin a version)   NO_COLOR=1  (plain output)
#             NFT_OKBOY_SHA256=<hex>    (the binary's sha256 from the release page, when
#                                        GitHub cannot be reached to look it up; set
#                                        NFT_OKBOY_VERSION too, and on a fresh install
#                                        NFT_OKBOY_GH_MIRROR for the config and unit)
#             NFT_OKBOY_GH_MIRROR=<url> (https:// only; a mirror you trust as much as GitHub
#                                        itself — used for the version, checksums, config and
#                                        unit when GitHub is unreachable)
set -eu

REPO="lvusyy/nft-okboy-fleet"
RAW="https://raw.githubusercontent.com/$REPO"
BIN_DIR="/opt/nft-okboy";        BIN="$BIN_DIR/nft-okboy"
CONF_DIR="/etc/nft-okboy";       CONF="$CONF_DIR/config.yaml"
DATA_DIR="/var/lib/nft-okboy"
UNIT="/etc/systemd/system/nft-okboy.service"

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
[ "$(uname -s)" = "Linux" ] || die "nft-okboy runs on Linux only."
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
ASSET="nft-okboy-linux-$ARCH"
for t in curl install sha256sum systemctl; do
  command -v "$t" >/dev/null 2>&1 || die "Required command not found: $t"
done
command -v nft >/dev/null 2>&1 || warn "nft (nftables) is not installed — install it before starting nft-okboy."

# ---- a mirror you trust (optional) ----
# NFT_OKBOY_GH_MIRROR is a mirror you trust as much as GitHub itself: it may stand
# in for GitHub for everything, including the version, checksum, config and unit.
GH_MIRROR="${NFT_OKBOY_GH_MIRROR:-}"
case "$GH_MIRROR" in
  ""|https://*) ;;
  *) die "NFT_OKBOY_GH_MIRROR must be an https:// URL prefix, e.g. https://ghfast.top/" ;;
esac

# ---- download helpers ----
# dl: the release BINARY only — direct, then your mirror, then CN-friendly public
# mirrors. A mirror is just a transport here: the bytes must match the checksum
# taken from GitHub below.
# curl gets a connect timeout AND a stall guard (--speed-limit/--speed-time): the
# GitHub release CDN can connect then reset mid-transfer, which would hang a plain
# `curl` forever and never fail over to a mirror. Abort a transfer that drops below
# 1 KB/s for 20s so the next mirror is tried.
dl() { # dl <github-url> <out>
  for pre in "" ${GH_MIRROR:+"$GH_MIRROR"} "https://ghfast.top/" "https://gh-proxy.com/"; do
    if curl -fsSL --connect-timeout 8 --speed-limit 1024 --speed-time 20 --max-time 600 \
        "$pre$1" -o "$2" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}
# dl_gh: everything that decides WHAT gets installed, or runs as root without being
# covered by the binary's checksum (SHA256SUMS, config, systemd unit), comes from
# GitHub itself, else only from NFT_OKBOY_GH_MIRROR — never from the public mirrors,
# which could tamper with these as easily as with the binary. HTTPS only, redirects
# included.
dl_gh() { # dl_gh <github-url> <out>
  curl -fsSL --proto =https --proto-redir =https --connect-timeout 8 --max-time 60 "$1" -o "$2" 2>/dev/null && return 0
  [ -n "$GH_MIRROR" ] &&
    curl -fsSL --proto =https --proto-redir =https --connect-timeout 8 --max-time 60 "$GH_MIRROR$1" -o "$2" 2>/dev/null
}

# ---- resolve version (latest release, or NFT_OKBOY_VERSION) ----
# From GitHub's API, else its releases/latest redirect, else (only if set) your
# mirror: a public mirror could otherwise pick an OLD release, whose genuine
# checksum would then verify just fine.
latest_tag() {
  curl -fsSL --proto =https --connect-timeout 8 --max-time 25 -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null |
    tr ',' '\n' | sed -n 's/^[{[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
}
latest_tag_via() { # latest_tag_via <mirror-prefix or "">: from the releases/latest redirect
  curl -fsSL --proto =https --proto-redir =https --connect-timeout 8 --max-time 25 -o /dev/null \
      -w '%{url_effective}' "${1}https://github.com/$REPO/releases/latest" 2>/dev/null | sed -n 's#.*/tag/##p'
}
VER="${NFT_OKBOY_VERSION:-}"
if [ -z "$VER" ]; then
  say "Resolving latest release…"
  VER=$(latest_tag)
  [ -n "$VER" ] || VER=$(latest_tag_via "")
  [ -n "$VER" ] || [ -z "$GH_MIRROR" ] || VER=$(latest_tag_via "$GH_MIRROR")
  [ -n "$VER" ] || die "Could not resolve the latest release from GitHub. Set NFT_OKBOY_VERSION=vX.Y.Z and retry."
fi
# The tag goes into every URL below: accept only a plain release tag.
case "$VER" in
  v[0-9]*) ;;
  *) die "Unexpected release tag \"$VER\"." ;;
esac
case "$VER" in
  *[!A-Za-z0-9._-]*) die "Unexpected release tag \"$VER\"." ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---- trusted checksum (before downloading anything that will run as root) ----
# Order: NFT_OKBOY_SHA256 by hand, else the digest GitHub's release API reports for
# the asset, else the release's SHA256SUMS fetched from github.com. No checksum, no
# install — there is deliberately no "skip verification" path.
EXP=$(printf '%s' "${NFT_OKBOY_SHA256:-}" | tr 'A-F' 'a-f')
if [ -z "$EXP" ]; then
  # The API answers compact JSON; one field per line is enough to pair each asset
  # "name" with the "digest" that follows it in the same asset object.
  EXP=$(curl -fsSL --proto =https --connect-timeout 8 --max-time 25 -H 'Accept: application/vnd.github+json' \
          "https://api.github.com/repos/$REPO/releases/tags/$VER" 2>/dev/null |
        tr ',{}' '\n\n\n' |
        awk -v want="$ASSET" '
          { gsub(/^[ \t]+|[ \t]+$/, ""); gsub(/": +/, "\":") }
          $0 == "\"name\":\"" want "\"" { hit = 1; next }
          hit && /^"browser_download_url"/ { hit = 0 }
          hit && /^"digest":"sha256:/ { d = $0; sub(/^"digest":"sha256:/, "", d); sub(/"$/, "", d); print tolower(d); exit }') || EXP=""
fi
if [ -z "$EXP" ] && dl_gh "https://github.com/$REPO/releases/download/$VER/SHA256SUMS" "$TMP/sums"; then
  EXP=$(awk -v f="$ASSET" '{ sub(/^\*/, "", $2) } $2 == f { print tolower($1); exit }' "$TMP/sums")
fi
case "$EXP" in *[!0-9a-f]*) EXP="" ;; esac
[ ${#EXP} -eq 64 ] || die "Could not get a trusted checksum for $ASSET $VER from GitHub (is api.github.com / github.com reachable?). Retry, or set NFT_OKBOY_SHA256=<the sha256 shown for $ASSET on the release page>."

say "Downloading nft-okboy $VER ($ASSET)…"
dl "https://github.com/$REPO/releases/download/$VER/$ASSET" "$TMP/nft-okboy" || die "Download failed."
got=$(sha256sum "$TMP/nft-okboy" | cut -d' ' -f1)
[ "$got" = "$EXP" ] || die "Checksum mismatch: the download does not match the checksum GitHub publishes — aborting."
ok "checksum verified against GitHub"

UPGRADE=0; [ -x "$BIN" ] && UPGRADE=1

# ---- install binary + data dir ----
install -d -m 755 "$BIN_DIR"
install -d -m 700 "$DATA_DIR"
install -m 755 "$TMP/nft-okboy" "$BIN"
ok "binary → $BIN ($VER)"

# ---- command on PATH ----
# A link, not a copy: `nft-okboy upgrade` replaces the file the link points to.
# (RHEL-family sudo does not search /usr/local/bin: use a root shell there.)
LINK="/usr/local/bin/nft-okboy"
if [ -L "$LINK" ] || [ ! -e "$LINK" ]; then
  install -d -m 755 /usr/local/bin
  ln -sfn "$BIN" "$LINK"
  ok "command → $LINK"
else
  warn "$LINK exists and is not a link: left alone (run $BIN instead)."
fi

# ---- config (written once; an existing config is never overwritten) ----
if [ ! -f "$CONF" ]; then
  install -d -m 700 "$CONF_DIR"
  dl_gh "$RAW/$VER/config.example.yaml" "$TMP/conf" || die "Could not fetch the default config from GitHub (see NFT_OKBOY_GH_MIRROR)."
  install -m 600 "$TMP/conf" "$CONF"
  ok "config → $CONF (production-sane defaults)"
else
  ok "kept existing config: $CONF"
fi

# ---- systemd unit ----
if [ ! -f "$UNIT" ]; then
  dl_gh "$RAW/$VER/deploy/nft-okboy.service" "$TMP/unit" || die "Could not fetch the systemd unit from GitHub (see NFT_OKBOY_GH_MIRROR)."
  install -m 644 "$TMP/unit" "$UNIT"
  systemctl daemon-reload
  systemctl enable nft-okboy >/dev/null 2>&1 || true
  ok "service installed and enabled at boot"
fi

# ---- bootstrap an admin (fresh install only) ----
SECRET=""
if [ "$UPGRADE" = 0 ]; then
  say "Creating the admin user…"
  # Flag BEFORE the name: releases up to v0.3.0 stop flag parsing at the first
  # positional, so `user-add admin --admin` silently created a non-admin there.
  out=$("$BIN" -c "$CONF" user-add --admin admin 2>&1) || true
  SECRET=$(printf '%s' "$out" | grep -oE '[0-9a-f]{64}' | head -n1) || true
fi

# ---- (re)start ----
systemctl restart nft-okboy 2>/dev/null || true
sleep 1
if systemctl is-active --quiet nft-okboy; then
  ok "nft-okboy is running"
else
  warn "service is not active yet — check: journalctl -u nft-okboy -e"
fi

# ---- summary (credentials LAST, highlighted) ----
echo
if [ "$UPGRADE" = 1 ]; then
  ok "Upgraded to $VER. Config and database were preserved."
  echo "  Manage:  sudo nft-okboy user-list   |   Upgrade later:  sudo nft-okboy upgrade"
  exit 0
fi

printf "${B}════════════════════════════════════════════════════════════${X}\n"
ok "nft-okboy $VER installed."
echo
echo "  Web console:  https://<your-domain>/   (set up nginx + TLS — see deploy/nginx-nft-okboy.conf)"
echo "  Local check:  curl -s http://127.0.0.1:5000/health"
echo
if [ -n "$SECRET" ]; then
  printf "  ${YL}${B}Admin credentials (shown once — store them now):${X}\n"
  printf "    username:  ${B}admin${X}\n"
  printf "    secret:    ${B}%s${X}\n" "$SECRET"
else
  warn "Could not auto-create admin. Create one with: sudo nft-okboy user-add --admin <name>"
fi
printf "${B}════════════════════════════════════════════════════════════${X}\n"
echo
echo "  Next: open a port group and authorize the admin, e.g."
echo "    sudo nft-okboy group-add ssh 22"
echo "    sudo nft-okboy user-join admin ssh"
echo
echo "  Then open the Web console, enter username + secret, and Connect."
printf "  ${YL}With the nftables backend a group's port admits only IPs that knocked: once\n"
printf "  'ssh' exists, NEW SSH connections from elsewhere are dropped (this session stays).\n"
printf "  Keep it open: knock (Web console or knock.sh), then log in again from a SECOND\n"
printf "  SSH session, and close this one only once that works.${X}\n"
echo "  Upgrade any time:  sudo nft-okboy upgrade"
