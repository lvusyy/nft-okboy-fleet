**nft-okboy-fleet** is a Go + nftables rewrite of [UFW-OkBoy](https://github.com/lvusyy/UFW-OkBoy): an HMAC-authenticated dynamic firewall allowlist with a web console and TOTP step-up for admins, in a standalone mode or a hub/agent fleet mode, shipped as one static binary.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

The installer sets up a standalone server. For fleet agents, follow the [deployment guide](https://github.com/lvusyy/nft-okboy-fleet/blob/master/docs/DEPLOYMENT.md) instead.

## Upgrade

```sh
sudo nft-okboy upgrade
```

Installers before the `/usr/local/bin/nft-okboy` link was added leave the command off the PATH: run `sudo /opt/nft-okboy/nft-okboy upgrade` there, or re-run the installer, which adds the link. On armv6/armv7, `upgrade` is not available: re-run the installer (agent nodes: replace the binary as described in the deployment guide).

## Downloads

Static binaries for 9 Linux architectures: `nft-okboy-linux-<arch>` with `<arch>` one of amd64, arm64, armv7, armv6, 386, riscv64, ppc64le, s390x, loong64. Verify them against `SHA256SUMS`, for example with `sha256sum --ignore-missing -c SHA256SUMS` in the download directory. At runtime nft-okboy needs `nft` (nftables backend) or `ufw` (ufw backend); a hub with `firewall_backend: none` needs neither.

## Docs

[README (English)](https://github.com/lvusyy/nft-okboy-fleet/blob/master/README.en.md) · [README（中文）](https://github.com/lvusyy/nft-okboy-fleet/blob/master/README.md) · [Deployment guide (Chinese)](https://github.com/lvusyy/nft-okboy-fleet/blob/master/docs/DEPLOYMENT.md) · [Changelog](https://github.com/lvusyy/nft-okboy-fleet/blob/master/CHANGELOG.md) · [Security policy](https://github.com/lvusyy/nft-okboy-fleet/blob/master/SECURITY.md)
