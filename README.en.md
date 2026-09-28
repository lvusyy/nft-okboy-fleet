# nft-okboy

[![CI](https://github.com/lvusyy/nft-okboy-fleet/actions/workflows/ci.yml/badge.svg)](https://github.com/lvusyy/nft-okboy-fleet/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lvusyy/nft-okboy-fleet?sort=semver)](https://github.com/lvusyy/nft-okboy-fleet/releases)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64%20%7C%20armv7%20%7C%20armv6%20%7C%20386%20%7C%20riscv64%20%7C%20ppc64le%20%7C%20s390x%20%7C%20loong64-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**A dynamic firewall allowlist on nftables**: an authorized user authenticates once, and their current (changing) IP is opened to the ports they are allowed to reach, with traceable, self-healing rules. Shipped as a single static Go binary that runs on everything from x86 servers to Raspberry Pis, RISC-V and LoongArch boards.

English | [简体中文](README.md)

> A Go + nftables rewrite of [UFW-OkBoy](https://github.com/lvusyy/UFW-OkBoy): it keeps UFW-OkBoy's authentication protocol and security semantics (existing clients work as they are), moves the data plane to nftables (ufw is also supported), and adds a fleet mode in which one hub manages many hosts.

---

## The problem it solves

Sensitive ports (SSH, admin panels, databases, dashboards) should be reachable only from trusted IPs, but people's IPs keep changing: home broadband, 4G, travel, VPNs. Editing firewall rules by hand every time does not work.

**nft-okboy automates it**: a user authenticates once in a web page (or with a small script), and the server opens **their current IP** to **the ports of their groups**. When the IP changes, the next knock (every 30 seconds in the Web UI) moves the rule to the new IP and removes the old one; users who stop knocking are dropped from the allowlist automatically. Administrative changes are audited.

## Capabilities

### Firewall

- **Allow rules per (user, group)** in a dedicated `inet nft_okboy` table. Every rule carries the comment `nft-okboy:<user>:<group>` (the prefix is set by `rule_prefix`), so each rule traces back to a person and a group.
- **Reconcile on every knock**: one pass over all of the user's rules adds what is missing and removes rules for old IPs, disabled groups and leftovers; once a new IP is registered, the old IP's rules are removed at once.
- **Actually restricts**: each managed port (a group's port) is closed to every source that is not allowlisted: new TCP connections are dropped (established sessions survive) and UDP datagrams are dropped; loopback is never filtered. Other ports are left alone. Ports that Docker (`-p`) or Kubernetes (NodePort) DNAT elsewhere never reach the `input` hook, so nft-okboy can neither guard nor allowlist them; do not make one a group port.
- **Coexists with other firewalls**: it owns one table, hooked at `input` with priority -150, and never changes anyone else's rules. But an accept in one nftables chain is **not final**: if another firewall on the host (ufw, firewalld, an nftables.conf) drops a managed port, allowlisted users stay blocked. Either open the port there (nft-okboy then does the restricting), or on a ufw host use `firewall_backend: ufw`. Other firewalls found are logged at startup.
- **Self-healing and expiry**: every 30 seconds the server re-asserts the firewall from the database (a flushed table is recreated, rules left behind by failed deletes are removed); every hour, users who have not knocked for `cleanup_max_age_days` (default 7) days leave the allowlist.
- **Injection-safe writes**: every change is a JSON transaction piped to `nft -j -f -` (no shell, no command-line interpolation), and rules are deleted precisely by handle.
- **Choice of backend**: `firewall_backend` is `nftables` (default), `ufw` (drives the host's ufw through the `ufw` command) or `none` (no local firewall, for a control-plane-only hub).

### Security

- **HMAC-SHA256 request signatures**: requests carry a signature, never the secret; the signature includes a timestamp and is valid only within `signature_ttl`; every authentication failure is recorded.
- **Admin TOTP step-up (RFC 6238)**: an admin who has enrolled TOTP must supply a current code with every admin write; a used code cannot be used again; re-enrolling first requires proving possession with a current code. With `require_admin_totp: true`, admins who have not enrolled cannot perform admin writes.
- **Throttling**: too many authentication failures from one IP get HTTP 429 (counted per IP, not per username, so an attacker cannot lock a legitimate user out); wrong TOTP codes are also capped per account.
- **Name allowlist**: user, group and node names must start with a letter or digit and contain only letters, digits, `_` and `-`, at most 64 characters, which rules out injection at the source.
- **Anti-IP-spoofing**: `X-Real-IP` (or, without it, the rightmost `X-Forwarded-For` entry) is trusted only when the direct peer is in `trusted_proxies`, and it must be a single IP; otherwise the knock is refused.
- **Force offline**: closes the ports, clears the state and rotates the secret, so a leaked secret stops working at once.

### Operations

- **Single static binary** (`CGO_ENABLED=0`, pure-Go SQLite): no Python, virtualenv or libc. At runtime it needs only the command of the chosen backend: `nft` for nftables, `ufw` for ufw, neither for `none`.
- **9 CPU architectures**: see [Platforms](#platforms).
- **Online backup**: `backup` writes a consistent snapshot plus a SHA-256 checksum file and rotates them by `backup_keep`; `upgrade` backs up the database first by default. There is no restore command; see [Upgrade](#upgrade) for the restore steps.
- **Audit and anomaly detection**: administrative changes made through the API or the CLI are written to the audit log; when a user changes IP many times within a short period, the knock response carries a warning (possible credential sharing).
- **Three ways to manage**: the built-in web console, the CLI and the HTTP API. Fleet nodes and targets can currently be managed with the CLI only.
- **Install and self-update**: the one-line installer and `upgrade` accept only checksums published on GitHub (the installer can additionally be pointed at a mirror you trust); systemd units and an nginx example are included.

### Clients

- **Web UI** (embedded single page): after login, the page knocks every 30 seconds; it works on phones. It can remember the credentials in the browser: encrypted (PBKDF2 + AES-GCM) when a PIN is set, otherwise in plaintext in localStorage.
- **Command-line clients**: the protocol is the same as UFW-OkBoy's, so its `knock.py` and `knock.sh` work as they are.

## Architecture

```text
Client (browser / knock.py / knock.sh)
    │  HTTPS, HMAC-SHA256 signature
    ▼
Nginx (TLS termination, sets X-Real-IP)
    │  HTTP 127.0.0.1:5000
    ▼
nft-okboy serve (HTTP API, Web UI, auth, throttling, maintenance) ──► SQLite (users, groups, membership, nodes, audit)
    │  nft -j -f -  (JSON transaction, no shell)
    ▼
nftables: dedicated inet nft_okboy table (allowlist accepts + guard on managed ports, coexists with host and k8s tables)
```

In fleet mode, the same `serve` also serves desired state to the agents on the nodes; see [Fleet mode](#fleet-mode-one-hub-many-hosts).

## Platforms

Every [release](https://github.com/lvusyy/nft-okboy-fleet/releases) ships prebuilt static `linux` binaries and `SHA256SUMS`:

| Arch | Target | Typical hardware |
|------|--------|------------------|
| `amd64`   | x86-64       | servers, cloud |
| `arm64`   | aarch64      | AWS Graviton, Raspberry Pi 4/5, most ARM cloud |
| `armv7`   | 32-bit ARM   | Raspberry Pi 2/3, many SBCs |
| `armv6`   | 32-bit ARM   | Raspberry Pi 1 / Zero |
| `386`     | 32-bit x86   | legacy or embedded |
| `riscv64` | RISC-V       | SiFive, VisionFive |
| `ppc64le` | POWER (LE)   | OpenPOWER servers |
| `s390x`   | IBM Z        | mainframe |
| `loong64` | LoongArch    | Loongson |

- The project is pure Go (no cgo): `make release-bins` cross-compiles all 9 binaries and `SHA256SUMS` on any development machine, without a C toolchain.
- `nft-okboy upgrade` supports 7 of the architectures, all but armv6 and armv7; those two 32-bit ARM targets are upgraded by re-running the installer, see [Upgrade](#upgrade).
- **MIPS is not supported** (`mips`/`mipsle`, common on older routers): the pure-Go SQLite driver (modernc) has no MIPS port.
- The server runs on Linux only (nftables and ufw are Linux firewalls); a binary built for another OS contains only an in-memory mock backend, for development and tests. Clients are not limited this way.

## Quick start

### Install (one command, recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

The installer needs root, systemd, `curl` and `sha256sum`, and checks that `nft` is present (the default nftables backend cannot start without it). It:

1. picks the binary for `uname -m`, resolves the latest release and gets the binary's sha256 from GitHub; without a trusted checksum, or when the download does not match it, it aborts;
2. installs the binary as `/opt/nft-okboy/nft-okboy`, links `/usr/local/bin/nft-okboy` to it, and creates the data directory `/var/lib/nft-okboy` (0700);
3. on a first install, writes `/etc/nft-okboy/config.yaml` (nftables backend, listening on `127.0.0.1:5000`), installs and enables `nft-okboy.service`, creates the admin user `admin` and prints its one-time secret, highlighted, at the end;
4. starts (or restarts) the service.

Re-running it only refreshes the binary; an existing config, database and systemd unit are kept. The installer reads these environment variables (for example `curl … | sudo env NFT_OKBOY_VERSION=v0.4.0 sh`):

| Variable | Effect |
|----------|--------|
| `NFT_OKBOY_VERSION=vX.Y.Z` | install this version instead of the latest release |
| `NFT_OKBOY_GH_MIRROR=https://…/` | a mirror prefix you trust as much as GitHub: when GitHub is unreachable, the version, `SHA256SUMS`, the config file and the systemd unit come from it; it is also used to download the binary |
| `NFT_OKBOY_SHA256=<hex>` | the binary's sha256 from the release page, given by hand instead of looking it up on GitHub. Unless `NFT_OKBOY_VERSION` is also set, the version is still resolved from GitHub; on a first install the config file and the systemd unit are still downloaded from GitHub (or `NFT_OKBOY_GH_MIRROR`) |
| `NO_COLOR=1` | plain output without colors |

When the binary cannot be downloaded from GitHub directly, the installer also tries `NFT_OKBOY_GH_MIRROR` and its built-in public mirrors in turn; a mirror only carries the bytes, which must match the checksum GitHub publishes. Note that fetching and running `install.sh` itself through a mirror means trusting that mirror completely. If GitHub is unreachable, that is how to do it, taking the script as well as the version and checksums from the same mirror:

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh \
  | sudo env NFT_OKBOY_GH_MIRROR=https://ghfast.top/ sh
```

The installer sets up a standalone server; do not run it on fleet edge nodes, see [Fleet mode](#fleet-mode-one-hub-many-hosts).

### First steps

The service listens only on `127.0.0.1:5000` (local check: `curl -s http://127.0.0.1:5000/health`). Put nginx in front of it for TLS termination; see [`deploy/nginx-nft-okboy.conf`](deploy/nginx-nft-okboy.conf), where `proxy_set_header X-Real-IP $remote_addr` is essential.

Create the first group and authorize the admin:

```bash
sudo nft-okboy group-add ssh 22       # manage port 22 as the "ssh" group
sudo nft-okboy user-join admin ssh    # authorize admin for it
```

Then open `https://<your-domain>/` in a browser, enter the username and the secret, and click **Connect**. The page computes signatures with the browser's Web Crypto and must be served over HTTPS.

> **Note**: with the nftables backend, at most 30 seconds after a group is created the running service closes its port to every source that has not knocked (established sessions survive). When you create the `ssh` group, keep your current SSH session: knock, confirm that a second SSH login works, and only then close the first session.

Management commands read and write the database directly (readable by root only), so run them with `sudo`. On RHEL-family distributions sudo does not search `/usr/local/bin` (its `secure_path` does not include it): use a root shell there, or the full path `/opt/nft-okboy/nft-okboy`.

### Upgrade

```bash
sudo nft-okboy upgrade           # upgrade to the latest release
sudo nft-okboy upgrade --check   # only check whether a newer release exists
```

`upgrade` gets the target version and its sha256 from GitHub, backs up the database first (a failed backup only prints a warning and the upgrade goes on), downloads the binary and verifies it (the download may go through built-in public mirrors; only GitHub's checksum is accepted), replaces the binary and keeps the old one as `<path>.bak`, then restarts the `nft-okboy` service. It switches back to the old binary when the new one does not run, or when the service does not come up after the restart; if `systemctl restart` itself fails (for example, the service is not managed by systemd) it only asks you to start it by hand and does not roll back. To be sure a usable backup exists, run `sudo nft-okboy backup` first and check that it succeeds.

- **No `nft-okboy` command**: earlier installers did not create the `/usr/local/bin/nft-okboy` link, and `upgrade` does not create it either. Use the full path, `sudo /opt/nft-okboy/nft-okboy upgrade`, or re-run the installer to add the link.
- **armv6/armv7**: the two 32-bit ARM variants cannot be told apart at runtime, so `upgrade` stops with an error. Re-run the one-line installer to upgrade (config and database are kept); for agent nodes, see the [deployment guide](docs/DEPLOYMENT.md).
- **Rollback covers the binary only**: a database migrated by the new version is not rolled back.
- **Restoring the database**: there is no `restore` command. Stop the service with `sudo systemctl stop nft-okboy`, replace the database file that `db_path` points to with a backup from `backup_dir` (default `/var/lib/nft-okboy/backups`), delete any leftover `-wal` and `-shm` files next to it, and start the service again. The `.sha256` file next to each backup can be used to verify it.
- Neither `upgrade` nor re-running the installer updates systemd units that are already installed. When a release changes a unit (see the [CHANGELOG](CHANGELOG.md)), install it again from `deploy/` and run `sudo systemctl daemon-reload`.

### Manual install

Building from source needs Go 1.22 or later. You can also download `nft-okboy-linux-<arch>` for your architecture from [Releases](https://github.com/lvusyy/nft-okboy-fleet/releases), verify it against `SHA256SUMS`, and use that file name below. Run these commands from the repository root:

```bash
make static                  # → dist/nft-okboy-linux-amd64 (other arches: make release-bins)
sudo install -Dm755 dist/nft-okboy-linux-amd64 /opt/nft-okboy/nft-okboy
sudo ln -sfn /opt/nft-okboy/nft-okboy /usr/local/bin/nft-okboy
sudo install -d -m 700 /etc/nft-okboy /var/lib/nft-okboy     # the unit's ReadWritePaths needs the data dir to exist
sudo install -m 600 config.example.yaml /etc/nft-okboy/config.yaml
sudo install -m 644 deploy/nft-okboy.service /etc/systemd/system/nft-okboy.service
sudo systemctl daemon-reload
sudo nft-okboy user-add --admin admin     # create the admin; the secret is shown only this once
sudo systemctl enable --now nft-okboy
```

Then set up nginx and create groups as in [First steps](#first-steps). `serve` needs root or `CAP_NET_ADMIN`.

## Fleet mode: one hub, many hosts

With many hosts, you can run one hub and a lightweight agent on every protected host:

- The **hub** is an ordinary `nft-okboy serve`. It holds the users, groups and nodes, and the mappings from groups to ports on nodes (targets); it is the only endpoint clients need to reach. With `firewall_backend: none` it is a pure control plane; with `nftables` or `ufw`, each group's own port also takes effect on the hub itself.
- The **agent** is `nft-okboy agent`. Every `--interval` seconds (15 by default) it pulls its node's desired state from the hub over HTTPS with the node token and brings the local firewall in line with it. It only makes outbound connections, listens on no port and has no database.
- A client **knocks on the hub once**; every node it is authorized on opens its new IP at the node's next pull.
- One hub can manage nftables nodes and ufw nodes at the same time.

```bash
# on the hub
sudo nft-okboy node-add edge-1                     # register the node; prints its token (shown only once)
sudo nft-okboy group-add web 8080                  # create a group: 8080 is the group's port on the hub itself
sudo nft-okboy group-target add web edge-1 18080   # on edge-1, the web group maps to 18080/tcp
sudo nft-okboy user-add alice                      # create the user; prints its secret once
sudo nft-okboy user-join alice web

# on edge-1: install the binary and deploy/nft-okboy-agent.service, write
# /etc/nft-okboy/agent.yaml (backend, agent_allowed_ports) and /etc/nft-okboy/agent.env (hub URL, node name, token)
sudo systemctl enable --now nft-okboy-agent
```

- **Do not run the one-line installer on edge nodes**: it installs and starts the standalone service, which would compete with the agent for the same `nft_okboy` table.
- **`agent_allowed_ports`**: the node opens, and closes, only the ports listed here, so even a compromised hub cannot make the node open SSH or any other port. An nftables node without it closes no port at all.
- **Observability**: `sudo nft-okboy node-list` (or the admin API `GET /api/admin/nodes`) shows whether each node is online (pulled within the last 60 seconds), the agent version and backend, and the number of rules the hub computes for the node.
- **Revocation**: `node-del` deletes the node and its targets; at its next pull the node's agent gets a 401, removes every allow rule and keeps the guard, so the managed ports close.
- **Self-upgrade**: with `nft-okboy-agent-upgrade.timer` enabled, the agent checks for a new release once a day (not on armv6/armv7).

The full steps (standalone, fleet, Kubernetes, migrating from the Python ufw-okboy, upgrades, verification) are in the **[deployment guide](docs/DEPLOYMENT.md)** (in Chinese).

## HTTP API

Every `/api/*` response is JSON: `{"ok": true, ...}` on success, `{"ok": false, "error": "..."}` on failure.

**User authentication**: the header `Authorization: HMAC-SHA256 <user>:<timestamp>:<signature>`. The timestamp is in Unix seconds; the signature is the lowercase hex HMAC-SHA256 of `<user>:<timestamp>`, keyed with the user's secret (the string itself); the server requires `|now − timestamp| ≤ signature_ttl` (300 seconds by default). The signature does not cover the method, the path or the body, and a captured header can be replayed within `signature_ttl`, so it must travel over HTTPS.

```bash
ts=$(date +%s)
sig=$(printf '%s' "alice:$ts" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
curl -X POST -H "Authorization: HMAC-SHA256 alice:$ts:$sig" https://example.com/api/knock
```

**Admin step-up**: for the endpoints marked "step-up" below, an admin who has enrolled TOTP must send the current 6-digit code in the `X-TOTP-Code` header or in the `totp_code` field of the JSON body (with `totp_replay_protection` on, each code works once); with `require_admin_totp: true`, admins who have not enrolled cannot call them.

**Throttling**: after `throttle_max_failures` authentication failures within `throttle_window` seconds, requests to `/api/*` from that IP get 429; wrong TOTP codes are also counted per account and get 429 after the same number.

**Node authentication**: `GET /api/v1/node/desired-state` takes `Authorization: Bearer <token printed by node-add>`.

| Method and path | Purpose | Auth |
|---|---|---|
| `POST /api/knock` | register or refresh the caller's IP | user |
| `GET /api/status` | the caller's state: current IP, last knock, enabled groups and more | user |
| `GET /api/me/groups` | the caller's groups and whether each is enabled | user |
| `PATCH /api/me/membership/{group_id}` | enable or disable one of the caller's groups, body `enabled` (boolean); non-admins can re-enable only groups they were authorized for | user |
| `PATCH /api/membership/{user_id}/{group_id}` | the same for a given user: no step-up for one's own membership; changing another user's needs an admin | user; for others: admin + step-up |
| `GET /api/v1/node/desired-state` | an agent pulls its node's allow rules (`rules`) and managed ports (`ports`); the `X-Nft-Okboy-Version` and `X-Nft-Okboy-Backend` headers report its version and backend | node token |
| `GET /api/admin/users` | list users (without secrets) | admin |
| `POST /api/admin/users` | create a user: `username`, optional `secret` and `is_admin`; returns the secret | admin + step-up |
| `DELETE /api/admin/users/{user_id}` | delete a user and clean up their rules | admin + step-up |
| `POST /api/admin/users/{user_id}/admin` | grant or remove admin: `is_admin` (default true) | admin + step-up |
| `GET /api/admin/users/{user_id}/groups` | every group with the user's membership state | admin |
| `POST /api/admin/users/{user_id}/groups` | grant a group: `group_id`, optional `enabled` (default true) | admin + step-up |
| `POST /api/admin/memberships/remove` | revoke a membership: `username`, `group_name` | admin + step-up |
| `POST /api/admin/users/{user_id}/revoke` | force offline: close the ports, clear the IP, and by default rotate and return a new secret (`rotate_secret: false` keeps it) | admin + step-up |
| `GET /api/admin/groups` | list groups | admin |
| `POST /api/admin/groups` | create a group: `name`, `port`, optional `proto` (default tcp); subject to `allowed_ports` | admin + step-up |
| `DELETE /api/admin/groups/{group_id}` | delete a group and clean up its rules | admin + step-up |
| `GET /api/admin/audit?limit=N` | recent audit entries; `limit` defaults to 100, range 1–1000 | admin |
| `GET /api/admin/nodes` | node list: online state, version, backend, rule count | admin |
| `POST /api/admin/totp/enroll` | generate a TOTP secret and otpauth URI; needs the current code when already enrolled | admin |
| `POST /api/admin/totp/activate` | confirm and enable TOTP with `totp_code` in the body | admin |
| `DELETE /api/admin/totp` | disable TOTP; needs `totp_code` in the body when enabled | admin |
| `GET /health` | health check with service name and version | none |
| `GET /`, `GET /static/…` | the embedded Web UI | none |

## CLI

```text
nft-okboy [-c <config>] <command> [args]    options may come before or after positional arguments

Service
  serve [--debug]                           start the HTTP server (standalone or hub); --debug adds source locations to the log
  agent --hub <url> [options]               run as a fleet agent; options below

Users and groups
  gen-secret [user]                         generate a random secret and print config snippets (creates no user; for the users: seed)
  user-add <user> [--admin]                 create a user; prints the secret, shown only once
  user-del <user>                           delete a user and clean up the local rules
  user-list                                 list users
  admin-add <user>                          grant admin
  group-add <group> <port> [--proto tcp|udp]
                                            create a group; a port/protocol pair belongs to one group only
  group-del <group>                         delete a group (and its targets) and clean up the local rules
  group-list                                list groups
  user-join <user> <group>                  authorize a user for a group
  user-leave <user> <group>                 revoke the authorization
  revoke <user> [--no-rotate]               force offline: close the ports, clear the IP, rotate the secret by default
  totp-uri <user>                           print the otpauth:// URI of the user's TOTP secret

Fleet (run on the hub)
  node-add <node>                           register a node; prints its token, shown only once
  node-list                                 list nodes: online, version, backend, rule count, last pull
  node-del <node>                           delete a node and its targets
  group-target add <group> <node> <port> [--proto tcp|udp]
                                            map a group to a port on a node; running it again for the same group and node changes it
  group-target list                         list all targets
  group-target del <group> <node>           delete a target (aliases: rm, remove)

Maintenance
  list                                      list the managed rules in the local firewall
  cleanup [--max-age <days>]                drop users who have not knocked for N days (default 7, independent of cleanup_max_age_days)
  backup [--dir <dir>]                      consistent database backup plus .sha256; to backup_dir by default, keeping the newest backup_keep
  upgrade [--check] [--version vX.Y.Z] [--no-restart] [--no-backup] [--service <unit>]
                                            self-update; --service defaults to nft-okboy, agent nodes use --service nft-okboy-agent --no-backup
  version (or -V, --version)                print the version

Agent options
  --hub <url>            hub URL; must be https, plain http only for a loopback address or with --allow-http
  --node <name>          node name, for logging only (the token decides which node this is)
  --token <token>        node token; defaults to the NFT_OKBOY_TOKEN environment variable (recommended: arguments are visible to every local user)
  --interval <seconds>   pull interval, default 15
  --ca <pem>             verify the hub with this certificate only (the hub's CA, or its self-signed certificate)
  --insecure             do not verify the hub certificate (not recommended); cannot be combined with --ca
  --allow-http           accept a plain-http hub on a non-loopback address; NFT_OKBOY_ALLOW_HTTP=1 does the same
  --allow-ports <list>   comma-separated ports, overriding agent_allowed_ports from the config
  --state <file>         where the last applied guard is kept, default /var/lib/nft-okboy/agent-guard.json; "" turns it off
```

Management commands open the database directly and need root (`sudo nft-okboy …`); see [Configuration](#configuration) for where the config file is looked up.

## Configuration

Without `-c`, nft-okboy uses the `config.yaml` next to its executable if there is one, else `/etc/nft-okboy/config.yaml`. Every option is described in [`config.example.yaml`](config.example.yaml); the most common ones:

```yaml
listen_host: 127.0.0.1                 # listen locally when nginx runs on the same host
listen_port: 5000
trusted_proxies: ["127.0.0.1", "::1"]  # X-Real-IP / X-Forwarded-For are trusted only from these addresses (exact IPs, no ranges)
signature_ttl: 300                     # allowed timestamp skew of a signature, seconds
throttle_max_failures: 10              # per-IP throttle, 0 disables it
require_admin_totp: false              # true: admins without TOTP cannot perform admin writes
totp_replay_protection: true           # each TOTP code works once
firewall_backend: nftables             # nftables | ufw | none (control-plane-only hub)
nft_table: nft_okboy                   # dedicated inet table
nft_priority: -150                     # input hook priority
nft_guard: true                        # close managed ports to non-allowlisted sources; false = accept-only, restricts nothing
cleanup_max_age_days: 7                # days without a knock before a user leaves the allowlist, 0 = never
db_path: /var/lib/nft-okboy/nft-okboy.db
# agent_allowed_ports: [18080]         # agents only: open and close only these ports
# users:                               # optional: imported once, only when the database is created; imported users are not admins
#   alice: { secret: "<64 hex chars from nft-okboy gen-secret>" }
```

An agent reads only the firewall-related keys: `firewall_backend`, `rule_prefix`, `nft_table`, `nft_chain`, `nft_priority`, `nft_guard` and `agent_allowed_ports`.

## Testing

```bash
make test          # unit tests (go test ./...), run on any OS
make vet           # go vet
make integration   # integration test against real nftables in an isolated network namespace (Linux, needs sudo)
```

All firewall operations sit behind the `FirewallBackend` interface, so the reconcile, HTTP handler and agent logic is unit-tested with the in-memory `MockBackend`; the nftables and ufw backends also have integration tests that run against the real firewalls. The scripts in `scripts/` all run inside network namespaces and leave the host's firewall untouched:

| Script | What it covers |
|--------|----------------|
| `scripts/ufw-integration.sh` | enables ufw in private mount + net namespaces and runs the ufw integration test |
| `scripts/e2e-fleet.sh` | hub (`none` backend) + agent (`AGENT_BACKEND=ufw` or `nftables`): rule delivery, IP change, leaving a group, `agent_allowed_ports` refusing other ports, rules kept while the hub is down, `node-list` |
| `scripts/e2e-nft-traffic.sh` | real connections between two network namespaces: allow and drop in both standalone and hub + agent setups, established sessions surviving, another firewall dropping the port, a deleted node, the guard coming back after a flushed ruleset or with the hub down |
| `scripts/e2e-test.sh` | standalone server end to end (HMAC knock + real nftables); run by hand, not in CI |

CI runs on pushes and pull requests to `main`/`master`: `go vet`, the unit tests, cross-compilation for all 9 architectures, the nftables integration test, `scripts/ufw-integration.sh`, `scripts/e2e-fleet.sh` (once with ufw, once with nftables) and `scripts/e2e-nft-traffic.sh`.

## Project layout

```text
cmd/nft-okboy/        main: global flags, subcommand dispatch
internal/cli/         the subcommands (serve, agent, upgrade, user/group/node management, ...)
internal/config/      YAML config loading and defaults
internal/db/          SQLite layer: schema and migrations, CRUD, nodes and desired state, backup
internal/auth/        HMAC verification, TOTP, per-IP throttling
internal/firewall/    backend interface and implementations (nftables, ufw, none, mock), reconcile, guard
internal/server/      HTTP routes (client, admin, node API) and periodic maintenance
internal/agent/       fleet agent: pull desired state, reconcile, guard
internal/hub/         package documentation only (the hub logic lives in internal/server and internal/db)
internal/static/      the single-file Web UI, embedded with go:embed
deploy/               installer, systemd units (service, agent, agent self-upgrade), nginx example
docs/                 deployment guide
scripts/              integration and end-to-end test scripts
.github/workflows/    CI and tag-triggered releases
```

## Security

Please do not report vulnerabilities in public issues; use GitHub private vulnerability reporting. Supported versions, how to report and known limitations are in [SECURITY.md](SECURITY.md).

## Changelog

Changes in each version are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
