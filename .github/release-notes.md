**nft-okboy-fleet** — a Go + nftables rewrite of [UFW-OkBoy](https://github.com/lvusyy/UFW-OkBoy): an HMAC-authenticated dynamic firewall (port-knock style) with a web console, TOTP step-up, and a single dependency-free static binary.

## Install — one command

```sh
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

Already installed?  `sudo nft-okboy upgrade`

## Downloads

Static `CGO_ENABLED=0` binaries for 9 linux arches — pick `nft-okboy-linux-<arch>` (amd64 · arm64 · armv7 · armv6 · 386 · loong64 · ppc64le · riscv64 · s390x) and verify against `SHA256SUMS`.

## Docs

📖 [English README](https://github.com/lvusyy/nft-okboy-fleet/blob/master/README.en.md) · [中文文档](https://github.com/lvusyy/nft-okboy-fleet/blob/master/README.md)
