# 安全策略 / Security Policy

[English](#english) | 中文

## 支持的版本

安全修复只进最新的次版本。报告问题前请先确认在最新版本上仍能复现。

| 版本 | 安全修复 |
|------|----------|
| 0.4.x | ✅ |
| < 0.4 | ❌ 请升级（见 [CHANGELOG](CHANGELOG.md)） |

## 报告漏洞

**请不要在公开 issue 里报告漏洞。** 请通过 GitHub 私密漏洞报告提交：
[Security → Report a vulnerability](https://github.com/lvusyy/nft-okboy-fleet/security/advisories/new)

请尽量写明：

- 受影响的版本（`nft-okboy version`）和运行方式：standalone、hub 或 agent，防火墙后端（`nftables`、`ufw` 或 `none`），是否在 Nginx 等反向代理之后；
- 复现步骤；
- 影响：例如能让哪些来源被放行、能关闭哪些端口、能读到或改动什么。

确认后会在私密通告里跟进，修复随新版本发布，并在 CHANGELOG 里说明。

## 已知限制

以下是已公开的设计取舍，不按漏洞处理：

- 签名只覆盖「用户名 + 时间戳」，不含请求方法、路径和正文：截获的请求头在 `signature_ttl`（默认 300 秒）内可以重放到该用户能调用的任何接口，传输层依赖 HTTPS 保护。管理员的 TOTP 验证码在 `totp_replay_protection` 开启（默认）时只能用一次。
- nft-okboy 只在 `input` 路径上放行和拦截：被 Docker（`-p`）或 Kubernetes（NodePort）经 DNAT 转发的端口不经过 `input` 钩子，nft-okboy 既拦不住也放行不了。
- 被攻破的 hub 能改动的只有各节点 `agent_allowed_ports` 中列出的端口：对这些端口放行任意地址、撤掉放行，在 nftables 节点上还能撤掉或加上这些端口的防护（撤掉后，除非主机上另有防火墙，端口对所有来源开放）。没有配置 `agent_allowed_ports` 的节点上，它能在任意端口上放行任意地址。它碰不到节点主机自己的防火墙规则，但 hub 的数据库里有全部用户的密钥。
- ufw 后端：ufw 对来源、端口、协议完全相同的规则只保留一条。主机上已有这样一条自己的规则（无论放行还是拒绝）时，nft-okboy 不添加受管规则，由那条规则决定该来源能否访问：主机拒绝的端口，敲门也打不开。v0.4.0 及更早的版本会把这样的规则改写成受管的放行规则，升级前请看 CHANGELOG。注释以 `<rule_prefix>:` 开头的放行规则都算作 nft-okboy 的。
- 期望状态没有签名，agent 只凭 TLS 确认 hub：hub 使用自签证书时用 `--ca` 固定证书，不要用 `--insecure`。
- 节点 token 是长期有效的 bearer token，不会过期；hub 只保存它的 SHA-256。持有 token 的人能读取该节点的期望状态（用户名、当前 IP、端口）。更换方法：`node-del` 后用同名重新 `node-add`，重新添加该节点的 target（删除节点时会一并删除），再更新节点上的 `agent.env`。
- 数据库和备份中的用户 HMAC 密钥与 TOTP 种子是明文（服务端必须能直接使用它们），只靠文件权限保护（0600，属主 root）。
- Web UI 的「记住」功能把用户名和密钥保存在浏览器的 localStorage 中：设置了 PIN 时加密保存（PBKDF2 + AES-GCM），否则是明文。PIN 的错误次数限制只在页面内生效。
- 设置了 `NFT_OKBOY_GH_MIRROR` 时，安装脚本把该镜像视为与 GitHub 同等可信：版本号、校验和、配置文件和 systemd 单元都可能取自它。通过镜像下载并执行安装脚本本身，也等于信任该镜像。`nft-okboy upgrade` 只认 GitHub 公布的校验和。

---

## English

### Supported versions

Security fixes go into the latest minor release only. Please check that an issue still reproduces on the latest release before reporting it.

| Version | Security fixes |
|---------|----------------|
| 0.4.x | ✅ |
| < 0.4 | ❌ please upgrade (see [CHANGELOG](CHANGELOG.md)) |

### Reporting a vulnerability

**Please do not report vulnerabilities in public issues.** Use GitHub private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/lvusyy/nft-okboy-fleet/security/advisories/new)

Please include the affected version (`nft-okboy version`) and how it runs (standalone, hub or agent; the firewall backend: `nftables`, `ufw` or `none`; behind Nginx or another reverse proxy or not), steps to reproduce, and the impact (for example which sources end up allowed, which ports can be closed, or what can be read or changed). Reports are followed up in the private advisory; fixes ship in a release and are described in the CHANGELOG.

### Known limitations

These are documented design trade-offs, not treated as vulnerabilities:

- The signature covers only the username and the timestamp, not the method, the path or the body: a captured request header can be replayed within `signature_ttl` (300 seconds by default) against any endpoint that user may call; the transport relies on HTTPS. With `totp_replay_protection` on (the default), an admin's TOTP code works only once.
- nft-okboy allows and blocks on the `input` path only: ports that Docker (`-p`) or Kubernetes (NodePort) DNAT elsewhere never reach the `input` hook, so nft-okboy can neither guard nor allowlist them.
- A compromised hub can change only the ports listed in each node's `agent_allowed_ports`: open them to any address, remove the openings, and on nftables nodes remove or add the guard on them (without the guard, such a port is open to every source unless another firewall on the host blocks it). On a node without `agent_allowed_ports`, it can open any port to any address. It cannot touch the node host's own firewall rules, but the hub's database holds every user's secret.
- ufw backend: ufw keeps one rule per source, port and protocol. Where the host has such a rule of its own (allow or deny), nft-okboy adds no managed rule and that rule decides the source's access: a knock does not open a port the host denies. v0.4.0 and earlier rewrote such a rule into a managed allow rule; read the CHANGELOG before upgrading. Allow rules whose comment starts with `<rule_prefix>:` count as nft-okboy's.
- Desired state is not signed; agents rely on TLS alone to authenticate the hub: pin a self-signed hub certificate with `--ca`, and do not use `--insecure`.
- Node tokens are long-lived bearer tokens that do not expire; the hub stores only their SHA-256. Whoever holds a token can read that node's desired state (user names, current IPs, ports). To replace a token, run `node-del` and then `node-add` with the same name, add the node's targets again (deleting the node deletes them), and update `agent.env` on the node.
- User HMAC secrets and TOTP seeds are stored in plaintext in the database and in backups (the server must be able to use them directly); only file permissions protect them (0600, owned by root).
- The Web UI's "remember" option keeps the username and the secret in the browser's localStorage: encrypted (PBKDF2 + AES-GCM) when a PIN is set, in plaintext otherwise. The limit on wrong PINs is enforced only within the page.
- When `NFT_OKBOY_GH_MIRROR` is set, the installer trusts that mirror as much as GitHub: the version, the checksums, the config file and the systemd unit may come from it. Fetching and running the installer itself through a mirror also means trusting that mirror. `nft-okboy upgrade` accepts only checksums published on GitHub.
