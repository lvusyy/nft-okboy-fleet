# Changelog

All notable changes to nft-okboy-fleet are documented in this file, newest first. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Binaries and checksums for every version are on the [releases page](https://github.com/lvusyy/nft-okboy-fleet/releases).

## v0.4.1 (2026-09-29)

The ufw backend no longer rewrites the host's own rules and holds still while ufw is disabled; the documentation was checked against the code and completed ([#3](https://github.com/lvusyy/nft-okboy-fleet/pull/3), [#4](https://github.com/lvusyy/nft-okboy-fleet/pull/4)).

### Read before upgrading from v0.4.0

- On ufw hosts, earlier versions may already have rewritten rules of your own (see Security): such a rule now reads `ALLOW IN` with a managed comment (`<rule_prefix>:<user>:<group>`), even where it was a `DENY`, and nft-okboy treats it as its own. Look in `sudo ufw status numbered` for managed rules on sources and ports you had rules for, and add your rule again: ufw replaces the managed rule with it, and nft-okboy leaves it alone from then on.

### Security

- ufw backend: a rule of the host's own with the same source, port and protocol as a managed rule is left in charge, and no managed rule is added over it (logged once per source, port and protocol); where such a rule of `serve`'s own host denies or rejects, the knock says so in its response (an agent logs it on its node). ufw keeps one rule per such match, so adding the managed rule used to rewrite the host's: a `DENY` became a managed `ALLOW`, and an `ALLOW` could later be deleted along with the managed access. A host rule that also names a source port, a destination address or an interface, or has no protocol, is a different match to ufw and was never affected. A rule counts as nft-okboy's only when it is an allow rule with its comment prefix.

### Added

- `SECURITY.md`: supported versions, private vulnerability reporting and known limitations.
- This changelog. The release notes of each version are taken from its section here.

### Changed

- The installer links `/usr/local/bin/nft-okboy` to `/opt/nft-okboy/nft-okboy`, so `sudo nft-okboy …` works right after installing (an existing file at that path that is not a link is left alone), and its hints now read `sudo nft-okboy …`. Existing installs get the link by re-running the installer; `upgrade` does not create it. On RHEL-family systems sudo's `secure_path` does not include `/usr/local/bin`; use a root shell or the full path there.

### Fixed

- ufw backend, while ufw is disabled (it then lists no rules but keeps them): nft-okboy no longer takes the empty list for "no rules" and leaves ufw alone until it is enabled; then `serve` catches up within 30 seconds and agents in their next cycle. Until then, rules saved before ufw was disabled that went stale meanwhile (after an IP change or a revoke) are in force again once it is enabled. Knocks are still recorded (a hub's nodes need them), with a warning in the response. Before, removals found nothing to remove and reported success, and `serve` and the agents re-added their rules on every pass and logged it as a repair.
- A revoke or a user deletion, from the CLI or the admin API, removes all of the user's managed rules, at whatever address, not only those at the current one; a rule left at an earlier address stayed open until the next maintenance pass.
- Firewall changes that fail are reported: the CLI commands `user-del`, `user-join`, `user-leave`, `group-del` and `revoke` print a warning (and go ahead with the database change even when the firewall cannot be driven at all), and the API's revoke, user deletion, group deletion and membership removal (a user disabling one of their groups included) return one that points to the retry every 30 seconds, which the web console now shows in the admin view (the revoke warning used to suggest `cleanup`, which does not handle revoked users). The web console's status line no longer calls every knock warning an anomaly. `revoke` no longer claims the ports are closed: a rule of the host's own may still admit the address.
- ufw runs with `LANGUAGE=C` as well as `LANG=C LC_ALL=C`: ufw takes its language from `LANGUAGE` first, so on a host with, say, `LANGUAGE=zh_CN` and ufw translations installed its status line was translated and an active ufw was reported as inactive.
- Documentation corrected against the code and completed: both READMEs (the English one gains the fleet section), the deployment guide, the roadmap, the comments in `config.example.yaml` and the package documentation. Among other things:
  - complete CLI and HTTP API references, including the request signature, the agent options and the node API;
  - the runtime needs `nft` (or `ufw`); the default table is `nft_okboy`; a `config.yaml` next to the binary takes precedence over `/etc/nft-okboy/config.yaml`;
  - `proto` in the config file is not used; `allowed_ports` is enforced by the HTTP API only; the `users:` seed runs only when the database is created and never creates admins;
  - `upgrade` does not work on armv6/armv7 (re-run the installer); there is no restore command (the manual steps are documented);
  - manual installs must create `/var/lib/nft-okboy` before starting the service; a Kubernetes hub needs a reachable `listen_host` and its proxy in `trusted_proxies`;
  - migrating from the Python ufw-okboy is one-way (the two projects number their schema migrations differently), and the Python install should be at v2.2.2 or later first;
  - the testing section describes what CI actually runs.

## v0.4.0 (2026-09-28)

The nftables backend now actually enforces the allowlist, and this release hardens installation, upgrades, the agent and TOTP ([#1](https://github.com/lvusyy/nft-okboy-fleet/pull/1), [#2](https://github.com/lvusyy/nft-okboy-fleet/pull/2)).

### Read before upgrading from v0.3.x

- The nftables backend now **actually enforces** the allowlist. Before, it only added accept rules in its own chain, which restricted nothing (managed ports stayed open to everyone, or stayed blocked for everyone when another firewall dropped them).
- After the upgrade, every managed port is **closed to sources that have not knocked** (established sessions survive). Knock first for the access you rely on, SSH in particular, and confirm that a new SSH login works before closing your current session. `nft_guard: false` restores the old accept-only behaviour.
- nftables **agents guard only the ports listed in `agent_allowed_ports`**; without it they close nothing (and say so in the log).
- Ports that Docker (`-p`) or Kubernetes (NodePort) DNAT elsewhere never reach the input hook: nft-okboy can neither guard nor allowlist them.
- A plain-http hub on a non-loopback address now needs `--allow-http` (or `NFT_OKBOY_ALLOW_HTTP=1`).
- `nft-okboy upgrade` replaces only the binary. The systemd units changed in this release: the agent unit no longer passes the token on the command line and also starts on hosts without ufw, and the server unit may write `/etc/ufw` (needed with `firewall_backend: ufw`). To pick these up, install the units from `deploy/` again and run `systemctl daemon-reload`.

### Security

- `upgrade` verifies the binary only against checksums published on GitHub (the release API's asset digest, else `SHA256SUMS` from github.com), never against a mirror's; mirrors only carry the download. The installer does the same, except that when `NFT_OKBOY_GH_MIRROR` is set it may also take the version, `SHA256SUMS`, the config file and the systemd unit from that mirror. Without a trusted checksum both stop; there is no longer a path that skips verification.
- The installer resolves the latest version from GitHub (or `NFT_OKBOY_GH_MIRROR`), never from the built-in public mirrors, which could otherwise pick an older release, and accepts only plain release tags.
- Client IPs taken from proxy headers must be a single IP and are canonicalized; a trusted proxy that sends no usable header no longer gets its own address registered; knocks from loopback or unspecified addresses are refused. Agents drop malformed hub rules, and both backends check every rule again (ufw reads `any` and `0.0.0.0/0` as everyone).
- Agent: the token is read from `NFT_OKBOY_TOKEN`, and the shipped unit keeps it out of the process list; `--ca` pins the hub certificate; redirects are not followed.
- TOTP: wrong codes are counted on every TOTP endpoint and capped per account, from any IP (HTTP 429); a request without a code does not count.
- ufw changes are serialized within a process and across processes; before, a numbered delete could hit the wrong rule, even one of the host's own.
- The database and backups are owner-only (0600, new directories 0700), and nft-okboy refuses a database that other users can read when it cannot fix the permissions.
- The `users:` seed runs only when the database is created and skips secrets shorter than 32 characters, so a deleted user cannot come back with an old secret.

### Added

- The nftables guard (`nft_guard`, on by default): new TCP connections and all UDP datagrams to managed ports are dropped unless the source is allowlisted; loopback is exempt. The node desired state now also lists the node's managed `ports`.
- `serve` re-asserts its own firewall from the database every 30 seconds: a flushed table is recreated, and orphaned or duplicate rules are removed.
- `cleanup_max_age_days` (default 7): users who have not knocked for that many days leave the allowlist, checked hourly, on the hub and, through the desired state, on every node.
- Agent guard state file (`--state`, default `/var/lib/nft-okboy/agent-guard.json`): after a reboot or a flushed ruleset the guard is restored at once, before the hub is asked.
- When the hub rejects its token (node deleted or token replaced), the agent removes every allow rule and keeps the guard; network and server errors still leave the rules as they are.
- Startup notes about other firewalls on the input hook and about nat chains on the prerouting hook (Docker, kube-proxy).
- Installer variables `NFT_OKBOY_SHA256` and `NFT_OKBOY_GH_MIRROR`; agent options `--ca`, `--allow-http` (or `NFT_OKBOY_ALLOW_HTTP=1`) and `--state`.
- `scripts/e2e-nft-traffic.sh`: a real-traffic test between two network namespaces, run in CI.

### Fixed

- CLI options written after positional arguments were ignored: `user-add admin --admin` created a non-admin, and `--proto` was dropped the same way. The installer now runs `user-add --admin admin`, which works with older binaries too.
- Enabling one group no longer removes the local rules of the user's other groups.
- `group-add` and `group-target add` accept only `tcp` and `udp`, like the HTTP API.
- Web console: the TOTP prompt was missing when creating users or groups, changing memberships and re-enrolling TOTP; the secret and PIN fields are now cleared on unlock, lock and disconnect, which previously let the admin console be reopened without the PIN.

## v0.3.0 (2026-06-30)

First release of nft-okboy-fleet: the Go and nftables port of UFW-OkBoy, extended with a fleet mode.

### Added

- Standalone server (`serve`): an HMAC-SHA256 knock API compatible with UFW-OkBoy clients, an embedded web console, an admin API with TOTP step-up, per-IP throttling, an audit log, a management CLI and online backups.
- Firewall backends: `nftables` (a dedicated `inet` table), `ufw`, and `none` for a control-plane-only hub.
- Fleet mode: a node registry on the hub (`node-add`, `node-list`, `node-del`), per-node group targets (`group-target add|list|del`), and the node API `GET /api/v1/node/desired-state`, authenticated with per-node bearer tokens that the hub stores hashed. The `agent` subcommand pulls its node's desired state, reconciles the local firewall, and keeps its rules while the hub is unreachable. One knock on the hub reaches every node the user is authorized on.
- `agent_allowed_ports` and `--allow-ports`: an agent opens only the listed ports.
- Fleet view: agents report their version and backend; `node-list` and `GET /api/admin/nodes` show online state, version, backend and rule count.
- `upgrade` self-update (`--check`, `--version`, `--no-restart`, `--no-backup`, `--service`) and a daily agent self-upgrade timer.
- One-line installer; static binaries for 9 Linux architectures, with `SHA256SUMS`.
- Deployment guide (`docs/DEPLOYMENT.md`).
