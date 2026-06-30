# nft-okboy

[![CI](https://github.com/lvusyy/nft-okboy-fleet/actions/workflows/ci.yml/badge.svg)](https://github.com/lvusyy/nft-okboy-fleet/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lvusyy/nft-okboy-fleet?sort=semver)](https://github.com/lvusyy/nft-okboy-fleet/releases)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64%20%7C%20armv7%20%7C%20riscv64%20%7C%20ppc64le%20%7C%20s390x%20%7C%20loong64-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Dynamic firewall allowlist manager on nftables** — authorized clients
authenticate once and their (changing) IP is automatically opened in the
firewall, with clean, traceable, self-healing rules. A **single static Go
binary** with no runtime dependencies, running on everything from x86 servers to
Raspberry Pis, RISC-V and LoongArch boards.

English | [简体中文](README.md)

> Go + nftables rewrite of [ufw-okboy](https://github.com/lvusyy/UFW-OkBoy) —
> same battle-tested auth/security semantics, native nftables data plane, single
> static binary.

---

## The problem it solves

Sensitive ports (SSH, admin panels, databases, dashboards) should be reachable
only from trusted IPs. But people's IPs change constantly — home broadband, 4G,
travel, VPNs — and editing firewall rules by hand every time does not scale.

**nft-okboy automates it**: a user authenticates through a web page (or a tiny
script) and the server opens *exactly their current IP* to *exactly the ports
their group grants*. IP changed? The next 30-second heartbeat swaps the rule
seamlessly — no rule sprawl, a full audit trail, zero standing exposure.

## ✨ Capabilities

### 🔥 Firewall — native nftables
- **Per-(user, group, port) allow rules** in a dedicated `inet nft_okboy` table — one
  rule per grant, commented `nft-okboy:<user>:<group>` for full traceability.
- **Seamless IP switching** — the old IP is removed the instant a new one registers.
- **Atomic, idempotent reconcile** on every knock — the firewall is made to match
  the database *exactly* (add missing, drop stale / old-IP / disabled-group rules),
  so it self-heals from races, crashes, and concurrent membership changes.
- **Coexists with Kubernetes / host firewalls** — its own table, hook `input` at
  priority -150, **policy accept with accept-only rules**: it can only *widen*
  access for named IP/port pairs, never drops, and never flushes anyone else's rules.
- **Precise, injection-safe writes** — every change is a JSON transaction piped to
  `nft -j -f -` (no shell, no argv interpolation), deleted by stable rule handle.

### 🔐 Security
- **Stateless HMAC-SHA256 auth** — the secret never travels the wire; timestamped,
  replay-windowed, every failure recorded.
- **Admin TOTP step-up (RFC 6238)** on *every* admin write, with **atomic replay
  protection** (a used code cannot be reused) and re-enrollment that proves possession.
- **Per-IP abuse throttle** — too many failures from one IP → HTTP 429 (keyed on
  IP, not username, so an attacker cannot lock a legitimate user out).
- **Input allowlist (SR-1)** — usernames / group names confined to `[A-Za-z0-9_-]`
  (≤64 chars), closing the nft injection class at the door.
- **Anti-IP-spoofing (H-9)** — `X-Forwarded-For` trusted only from configured
  proxies, using the rightmost hop.
- **Force-offline / revoke** — close ports + clear state + rotate the secret, so a
  leaked credential dies instantly.

### 🧰 Operations
- **Single static binary** (`CGO_ENABLED=0`, pure-Go SQLite) — no Python, venv,
  gunicorn, or libc. Drop it on a host and run.
- **9 CPU architectures** — see [Platforms](#platforms).
- **Online backup + restore** — a consistent SQLite snapshot with a SHA-256 checksum.
- **Audit log + anomaly detection** — every admin action recorded; suspicious IP
  churn flagged as possible credential sharing.
- **Three control surfaces** — a built-in **web admin console**, a full **CLI**,
  and a REST **HTTP API** — pick whichever fits.
- **systemd-ready**, behind nginx with TLS termination.

### 🌐 Clients
- **Web UI** (embedded, single file) — log in once, auto-knocks every 30s, mobile-friendly.
- **Python / shell** knock clients — the wire protocol is identical to ufw-okboy's,
  so its `knock.py` / `knock.sh` work unchanged.

## Architecture

```
Client (browser / Python / shell)
    │  HTTPS + HMAC-SHA256 signature
    ▼
Nginx (TLS termination, passes X-Real-IP)
    │  HTTP 127.0.0.1:5000
    ▼
nft-okboy (Go: HTTP API + CLI + auth + throttle)
    │  nft -j -f -   (JSON transaction, no shell)
    ▼
nftables (dedicated `inet nft_okboy` table — accept-only, coexists with k8s/host)
    │
    ▼
SQLite (pure-Go modernc; users / groups / membership / audit)
```

## Platforms

Prebuilt static `linux` binaries are attached to every [release](https://github.com/lvusyy/nft-okboy-fleet/releases):

| Arch | Target | Typical hardware |
|------|--------|------------------|
| `amd64`   | x86-64       | servers, cloud |
| `arm64`   | aarch64      | AWS Graviton, Pi 4/5, most ARM cloud |
| `armv7`   | 32-bit ARM   | Pi 2/3, many SBCs |
| `armv6`   | 32-bit ARM   | Pi 1 / Zero |
| `386`     | 32-bit x86   | legacy / embedded |
| `riscv64` | RISC-V       | SiFive, VisionFive |
| `ppc64le` | POWER (LE)   | OpenPOWER servers |
| `s390x`   | IBM Z        | mainframe |
| `loong64` | LoongArch    | Loongson / 龙芯 |

> Because nft-okboy is pure Go (no cgo), cross-compiling to any of these is free
> (`make release-bins`). **MIPS** (`mips`/`mipsle`, common on older routers) is
> **not** available — the pure-Go SQLite driver (modernc) has no MIPS port.
> nftables is Linux-only, so there are no server builds for macOS/Windows (the
> *clients* remain cross-platform).

## Quick start

### Install (one command, recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

The script picks the right binary for your arch (sha256-verified) → writes
`/etc/nft-okboy/config.yaml` (production-sane defaults) → installs and enables the
systemd service → **creates an `admin` account and prints its one-time secret,
highlighted, at the end**. Re-run any time to refresh the binary (config and
database are preserved). Pin a version with `NFT_OKBOY_VERSION=vX.Y.Z`.

Open your first group, authorize the admin, then open the Web console and Connect:

```bash
nft-okboy group-add ssh 22       # manage port 22 as the "ssh" group
nft-okboy user-join admin ssh    # authorize admin for it
```

### Upgrade

```bash
sudo nft-okboy upgrade           # self-update (backup DB → verify → restart → rollback on failure)
sudo nft-okboy upgrade --check   # check only, do not install
```

### From source / manual

```bash
make static                                  # → dist/nft-okboy-linux-amd64 (CGO_ENABLED=0, static)
#   or: curl -fsSLO https://github.com/lvusyy/nft-okboy-fleet/releases/latest/download/nft-okboy-linux-amd64
cp config.example.yaml config.yaml
./nft-okboy gen-secret alice                     # generate a user secret
./nft-okboy -c config.yaml user-add alice        # create the user
./nft-okboy -c config.yaml group-add ssh 22      # create a group bound to port 22
./nft-okboy -c config.yaml user-join alice ssh   # grant alice the ssh group
sudo ./nft-okboy -c config.yaml serve            # serve (needs root or CAP_NET_ADMIN)
```

Then open `https://your-server/` → enter username + secret → **Connect**.

## HTTP API

All `/api/*` responses are `{"ok": ..., ...}`. Auth is the header
`Authorization: HMAC-SHA256 <user>:<ts>:<hexsig>`.

| Method & path | Purpose | Auth |
|---|---|---|
| `POST /api/knock` | register / refresh the caller's IP | user |
| `GET /api/status` | caller's current registration state | user |
| `GET /api/me/groups` | groups the caller belongs to | user |
| `PATCH /api/me/membership/{gid}` | self-enable/disable an authorized group | user |
| `GET /api/admin/users` · `POST` · `DELETE /{id}` | list / create / delete users | admin (+ step-up) |
| `POST /api/admin/users/{id}/admin` | promote / demote | admin + step-up |
| `GET/POST /api/admin/users/{id}/groups` | view / grant membership | admin (+ step-up) |
| `POST /api/admin/memberships/remove` | revoke membership | admin + step-up |
| `POST /api/admin/users/{id}/revoke` | force offline + rotate secret | admin + step-up |
| `GET /api/admin/groups` · `POST` · `DELETE /{id}` | list / create / delete groups | admin (+ step-up) |
| `GET /api/admin/audit` | recent admin actions | admin |
| `POST /api/admin/totp/{enroll,activate}` · `DELETE /api/admin/totp` | 2FA lifecycle | admin |
| `GET /health` | health/version probe | none |

## CLI

```
serve [--debug]                    start the API server
upgrade [--check]                  self-update to the latest release
gen-secret [user]                  generate a secret
user-add <name> [--admin]          create a user (prints the secret)
user-del / user-list
group-add <name> <port> [--proto tcp] / group-del / group-list
user-join <user> <group> / user-leave <user> <group>
admin-add <user>                   grant admin
revoke <user> [--no-rotate]        force offline + rotate secret
list                               list managed nftables rules
cleanup [--max-age <days>]         purge stale rules
backup [--dir <path>]              checksummed online backup
--version
```

## Configuration (excerpt)

```yaml
listen_host: 127.0.0.1
listen_port: 5000
trusted_proxies: ["127.0.0.1", "::1"]   # whose X-Real-IP/XFF to trust
throttle_max_failures: 10               # per-IP, 0 disables
require_admin_totp: false               # force admin 2FA
totp_replay_protection: true
nft_table: nft-okboy                        # dedicated inet table
nft_priority: -150                      # accept-only, coexists with k8s
db_path: /var/lib/nft-okboy/nft-okboy.db
# users:                                # optional first-run seed
#   admin: { secret: "<64 hex chars>" }
```

## Testing

```bash
make test          # unit: auth (RFC 6238 vectors), db primitives, firewall Mock reconcile — any platform
make integration   # real nftables in an isolated netns (Linux+root) — zero host/k8s impact
```

The firewall logic is split behind a `FirewallBackend` interface, so the core
reconcile/auth code is unit-tested with an in-memory `MockBackend` on any dev OS,
while `NftBackend` is exercised against **real** nftables inside an isolated
network namespace. `scripts/e2e-test.sh` runs the whole stack end to end (server
+ HMAC knock + real nft). CI runs all of this on every push; the project was also
reviewed with codex.

## Deploy

```bash
install -Dm755 dist/nft-okboy-linux-amd64 /opt/nft-okboy/nft-okboy
install -Dm600 config.yaml /etc/nft-okboy/config.yaml
install -Dm644 deploy/nft-okboy.service /etc/systemd/system/nft-okboy.service
systemctl enable --now nft-okboy
# nginx: deploy/nginx-nft-okboy.conf — MUST set proxy_set_header X-Real-IP $remote_addr
```

## Project layout

```
cmd/nft-okboy/            main: subcommand dispatch
internal/config/      YAML config loading
internal/db/          SQLite layer (schema + migrations + CRUD + atomic IP write + backup)
internal/auth/        HMAC verify + TOTP + per-IP throttle
internal/firewall/    FirewallBackend interface + nftables impl + Mock + Manager (reconcile)
internal/server/      stdlib net/http routes (mirror every endpoint)
internal/static/      go:embed single-file web UI
deploy/               systemd unit + nginx example
scripts/              end-to-end test
.github/workflows/    CI + tag-triggered multi-arch release
```

## License

MIT
