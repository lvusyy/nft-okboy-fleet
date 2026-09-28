**nft-okboy-fleet** — a Go + nftables rewrite of [UFW-OkBoy](https://github.com/lvusyy/UFW-OkBoy): an HMAC-authenticated dynamic firewall (port-knock style) with a web console, TOTP step-up, and a single dependency-free static binary.

## v0.4.0 — read before upgrading from v0.3.x

The nftables backend now **actually enforces** the allowlist. Before, it only added accept rules in its own chain, which restricted nothing (managed ports stayed open to everyone, or stayed blocked for everyone when another firewall dropped them).

- After the upgrade, every managed port is **closed to sources that have not knocked** (established sessions survive). Knock first for the access you rely on — SSH in particular — and confirm a new SSH login works before closing your current session. `nft_guard: false` restores the old accept-only behaviour.
- nftables **agents guard only the ports listed in `agent_allowed_ports`**; without it they do not close anything (and say so in the log).
- Ports that Docker (`-p`) or Kubernetes (NodePort) DNAT elsewhere never reach the input hook: nft-okboy cannot guard or allowlist them.
- A plain-http hub on a non-loopback address now needs `--allow-http` (or `NFT_OKBOY_ALLOW_HTTP=1`).
- Security fixes: upgrades and the installer verify checksums published on GitHub only (never a mirror's); client IPs are validated; the agent token no longer appears in the process list; TOTP guesses are counted and capped per account; ufw deletes are serialized; database and backups are owner-only.

Details: [#1](https://github.com/lvusyy/nft-okboy-fleet/pull/1) · [#2](https://github.com/lvusyy/nft-okboy-fleet/pull/2)

## Install — one command

```sh
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

Already installed?  `sudo nft-okboy upgrade`

## Downloads

Static `CGO_ENABLED=0` binaries for 9 linux arches — pick `nft-okboy-linux-<arch>` (amd64 · arm64 · armv7 · armv6 · 386 · loong64 · ppc64le · riscv64 · s390x) and verify against `SHA256SUMS`.

## Docs

📖 [English README](https://github.com/lvusyy/nft-okboy-fleet/blob/master/README.en.md) · [中文文档](https://github.com/lvusyy/nft-okboy-fleet/blob/master/README.md)
