# nft-okboy

[![CI](https://github.com/lvusyy/nft-okboy-fleet/actions/workflows/ci.yml/badge.svg)](https://github.com/lvusyy/nft-okboy-fleet/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lvusyy/nft-okboy-fleet?sort=semver)](https://github.com/lvusyy/nft-okboy-fleet/releases)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64%20%7C%20armv7%20%7C%20armv6%20%7C%20386%20%7C%20riscv64%20%7C%20ppc64le%20%7C%20s390x%20%7C%20loong64-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**基于 nftables 的动态防火墙白名单**：授权用户认证一次，他当前的（不断变化的）IP 就被放行到他有权访问的端口；规则可追溯、能自愈。以单个静态 Go 二进制交付，从 x86 服务器到树莓派、RISC-V 和龙芯设备都能运行。

[English](README.en.md) | 简体中文

> [UFW-OkBoy](https://github.com/lvusyy/UFW-OkBoy) 的 Go + nftables 重写：沿用其认证协议和安全语义（现有客户端可以直接使用），数据面改用 nftables（也支持 ufw），并新增由一个 hub 管理多台机器的 fleet 模式。

---

## 它解决什么问题

敏感端口（SSH、管理后台、数据库、监控面板）应该只对可信 IP 开放，但人的 IP 一直在变：家庭宽带、4G、出差、VPN。每次都手动改防火墙规则并不现实。

**nft-okboy 把这件事自动化**：用户在网页（或用一个小脚本）认证一次，服务器就把**他当前的 IP** 放行到**他所在组的端口**。IP 变了，下一次敲门（Web UI 每 30 秒一次）就把规则切换到新 IP，旧 IP 的规则随即删除；长期不敲门的用户会被自动移出白名单。管理变更都有审计记录。

## 能力一览

### 防火墙

- **按（用户，组）生成放行规则**：写在专用的 `inet nft_okboy` 表里，每条规则带注释 `nft-okboy:<用户>:<组>`（前缀可用 `rule_prefix` 修改），可以追溯到人和组。
- **敲门即对账**：一次处理该用户的全部规则，补上缺失的，删除旧 IP、已停用的组和残留的规则；新 IP 登记后，旧 IP 的规则立即删除。
- **真正拦截**：受管端口（各组的端口）对白名单以外的来源关闭：TCP 丢弃新连接（已建立的会话不受影响），UDP 丢弃所有数据报；本机回环不受限。其他端口原样不动。Docker（`-p`）、Kubernetes（NodePort）经 DNAT 转发的端口不经过 `input` 钩子，nft-okboy 既拦不住也放行不了，不要把这类端口设为组端口。
- **与其他防火墙共存**：独占一张表，挂在 `input` 钩子上、优先级 -150，不改动别人的规则。但 nftables 里一条链的放行**不是最终结论**：主机上另有防火墙（ufw、firewalld、nftables.conf）拦着受管端口时，白名单用户照样进不来。这时要么在那边放开该端口（由 nft-okboy 负责筛选），要么在 ufw 主机上改用 `firewall_backend: ufw`。启动日志会列出检测到的其他防火墙。
- **自愈与过期**：服务每 30 秒按数据库校正一次防火墙（表被清空会重建，删除失败遗留的规则会被清掉）；每小时把超过 `cleanup_max_age_days`（默认 7）天没敲门的用户移出白名单。
- **防注入写入**：每次变更都是经 `nft -j -f -` 提交的 JSON 事务（不经 shell、不拼接命令行参数），并按规则 handle 精确删除。
- **可选后端**：`firewall_backend` 可选 `nftables`（默认）、`ufw`（通过 `ufw` 命令管理主机的 ufw，不改写主机自己的规则），或 `none`（不管理本机防火墙，用于只做控制面的 hub）。

### 安全

- **HMAC-SHA256 请求签名**：请求只携带签名、不携带密钥；签名含时间戳，只在 `signature_ttl` 窗口内有效；每次认证失败都有记录。
- **管理员 TOTP 二次验证（RFC 6238）**：绑定了 TOTP 的管理员，每个管理写操作都要提供当前验证码；验证码用过即作废；重新绑定前须用当前验证码证明持有。设置 `require_admin_totp: true` 后，未绑定 TOTP 的管理员不能执行管理写操作。
- **限流**：同一 IP 认证失败过多时返回 HTTP 429（按 IP 而不是用户名计数，攻击者无法借此锁死正常用户）；TOTP 验证码错误另按账号封顶。
- **名称白名单**：用户名、组名和节点名必须以字母或数字开头，只含字母、数字、`_` 和 `-`，最长 64 个字符，从源头杜绝注入。
- **防 IP 伪造**：只有直连对端在 `trusted_proxies` 里时，才采信 `X-Real-IP`（没有时取 `X-Forwarded-For` 的最右一项），而且必须是单个 IP，否则拒绝敲门。
- **强制下线**：撤掉该用户在任何地址上的放行规则（fleet 节点在下一次成功拉取时跟上）、清除状态并轮换密钥，泄露的密钥立即失效。

### 运维

- **单个静态二进制**（`CGO_ENABLED=0`，纯 Go SQLite）：不需要 Python、虚拟环境或 libc。运行时只需要所选后端的命令：nftables 后端要有 `nft`，ufw 后端要有 `ufw`，`none` 两者都不需要。
- **9 种 CPU 架构**：见[平台](#平台)。
- **在线备份**：`backup` 生成一致性快照和 SHA-256 校验文件，按 `backup_keep` 轮转；`upgrade` 默认先备份数据库。没有恢复命令，恢复步骤见[升级](#升级)。
- **审计与异常检测**：经 API 或 CLI 的管理变更都写入审计日志；同一用户在短时间内频繁更换 IP 时，敲门响应中带有警告（可能是凭据被共享）。
- **三种管理方式**：内置 Web 管理台、CLI 和 HTTP API。fleet 的节点和 target 目前只能用 CLI 管理。
- **安装与自更新**：一键安装脚本和 `upgrade` 都只认 GitHub 公布的校验和（安装脚本另可指定一个你信任的镜像）；附带 systemd 单元和 nginx 配置示例。

### 客户端

- **Web UI**（内嵌单页）：登录后页面每 30 秒自动敲门一次，适配手机。可选择在浏览器中记住凭据：设置了 PIN 时加密保存（PBKDF2 + AES-GCM），否则明文保存在 localStorage。
- **命令行客户端**：协议与 UFW-OkBoy 相同，它的 `knock.py`、`knock.sh` 可以直接使用。

## 架构

```text
客户端（浏览器 / knock.py / knock.sh）
    │  HTTPS，HMAC-SHA256 签名
    ▼
Nginx（TLS 终止，设置 X-Real-IP）
    │  HTTP 127.0.0.1:5000
    ▼
nft-okboy serve（HTTP API、Web UI、鉴权、限流、定期维护） ──► SQLite（用户、组、成员、节点、审计）
    │  nft -j -f -（JSON 事务，不经 shell）
    ▼
nftables：专用 inet nft_okboy 表（白名单放行 + 受管端口防护，与主机和 k8s 的表共存）
```

fleet 模式下，同一个 `serve` 还为各节点的 agent 提供期望状态，见 [Fleet 模式](#fleet-模式一个-hub-管理多台机器)。

## 平台

每个 [release](https://github.com/lvusyy/nft-okboy-fleet/releases) 都附带预编译的静态 `linux` 二进制和 `SHA256SUMS`：

| 架构 | 目标 | 典型硬件 |
|------|------|---------|
| `amd64`   | x86-64       | 服务器、云主机 |
| `arm64`   | aarch64      | AWS Graviton、树莓派 4/5、多数 ARM 云主机 |
| `armv7`   | 32 位 ARM    | 树莓派 2/3、众多开发板 |
| `armv6`   | 32 位 ARM    | 树莓派 1 / Zero |
| `386`     | 32 位 x86    | 老旧或嵌入式设备 |
| `riscv64` | RISC-V       | SiFive、VisionFive |
| `ppc64le` | POWER（LE）  | OpenPOWER 服务器 |
| `s390x`   | IBM Z        | 大型机 |
| `loong64` | LoongArch    | 龙芯 |

- 项目是纯 Go（不用 cgo），`make release-bins` 在任意开发机上都能交叉编译出全部 9 个二进制和 `SHA256SUMS`，不需要 C 工具链。
- `nft-okboy upgrade` 支持除 armv6、armv7 以外的 7 种架构；这两种 32 位 ARM 通过重新运行安装脚本升级，见[升级](#升级)。
- **不支持 MIPS**（`mips`/`mipsle`，常见于老路由器）：纯 Go 的 SQLite 驱动（modernc）没有 MIPS 移植。
- 服务端只支持 Linux（nftables 和 ufw 都是 Linux 防火墙）；在其他系统上构建出的二进制只带内存中的模拟后端，仅供开发和测试。客户端不受此限制。

## 快速开始

### 一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

安装脚本需要 root、systemd、`curl` 和 `sha256sum`，并会检查 `nft` 是否存在（默认的 nftables 后端没有它无法启动）。它会：

1. 按 `uname -m` 选择架构，解析最新 release，从 GitHub 获取该二进制的 sha256；拿不到可信的校验和，或下载的文件对不上，就中止。
2. 把二进制装到 `/opt/nft-okboy/nft-okboy`，并把 `/usr/local/bin/nft-okboy` 链接过去；创建数据目录 `/var/lib/nft-okboy`（0700）。
3. 首次安装时写入 `/etc/nft-okboy/config.yaml`（默认 nftables 后端，监听 `127.0.0.1:5000`），安装并启用 `nft-okboy.service`，创建管理员 `admin`，并在最后高亮打印它的一次性密钥。
4. 启动（或重启）服务。

重复运行只刷新二进制，已有的配置、数据库和 systemd 单元都保留。安装脚本读取以下环境变量（例如 `curl … | sudo env NFT_OKBOY_VERSION=v0.4.1 sh`）：

| 变量 | 作用 |
|------|------|
| `NFT_OKBOY_VERSION=vX.Y.Z` | 安装指定版本，默认安装最新 release |
| `NFT_OKBOY_GH_MIRROR=https://…/` | 一个你像信任 GitHub 一样信任的镜像前缀：连不上 GitHub 时，版本号、`SHA256SUMS`、配置文件和 systemd 单元都改从它获取，下载二进制时也会用它 |
| `NFT_OKBOY_SHA256=<hex>` | 手动提供二进制的 sha256（取自 release 页面），代替向 GitHub 查询校验和。除非同时设置 `NFT_OKBOY_VERSION`，版本号仍要从 GitHub 解析；首次安装时配置文件和 systemd 单元仍从 GitHub（或 `NFT_OKBOY_GH_MIRROR`）下载 |
| `NO_COLOR=1` | 输出不带颜色 |

直连 GitHub 下载二进制失败时，脚本还会依次尝试 `NFT_OKBOY_GH_MIRROR` 和内置的公共镜像；镜像只负责传输，下载结果必须与 GitHub 公布的校验和一致。注意：通过镜像获取并执行 `install.sh` 本身，就等于完全信任该镜像。连不上 GitHub 时可以这样做，让脚本本身以及版本号、校验和都经同一个镜像获取：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh \
  | sudo env NFT_OKBOY_GH_MIRROR=https://ghfast.top/ sh
```

安装脚本装的是 standalone 服务，不要在 fleet 的边缘节点上运行它，见 [Fleet 模式](#fleet-模式一个-hub-管理多台机器)。

### 首次使用

服务只监听 `127.0.0.1:5000`（本机检查：`curl -s http://127.0.0.1:5000/health`）。用 nginx 做 TLS 终止并反向代理到这个端口，示例见 [`deploy/nginx-nft-okboy.conf`](deploy/nginx-nft-okboy.conf)，其中 `proxy_set_header X-Real-IP $remote_addr` 必不可少。

建第一个组并授权管理员：

```bash
sudo nft-okboy group-add ssh 22       # 把 22 端口纳管为 "ssh" 组
sudo nft-okboy user-join admin ssh    # 授权 admin 使用该组
```

然后在浏览器打开 `https://<你的域名>/`，输入用户名和密钥，点击 **Connect**。页面依赖浏览器的 Web Crypto 计算签名，必须经 HTTPS 访问。

> **注意**：使用 nftables 后端时，组一建好，运行中的服务最迟 30 秒内就会对未敲门的来源关闭该端口（已建立的会话不受影响）。建 `ssh` 组时保持当前 SSH 会话：敲门后另开一个 SSH 会话确认能登录，再断开原来的会话。

管理命令直接读写数据库（只有 root 可读写），所以要用 `sudo`。RHEL 系发行版的 sudo 不搜索 `/usr/local/bin`（`secure_path` 不含它），在那里请使用 root shell，或写完整路径 `/opt/nft-okboy/nft-okboy`。

### 升级

```bash
sudo nft-okboy upgrade           # 升级到最新 release
sudo nft-okboy upgrade --check   # 只检查是否有新版本
```

`upgrade` 从 GitHub 获取目标版本和它的 sha256，先备份数据库（备份失败只打印警告、继续升级），下载二进制并校验（下载可以经内置的公共镜像，校验和只认 GitHub 公布的），替换二进制并把旧文件保留为 `<原路径>.bak`，然后重启 `nft-okboy` 服务。新二进制无法运行，或服务重启后没有进入运行状态时，换回旧二进制；`systemctl restart` 本身失败（例如服务不由 systemd 管理）时只提示手动启动，不回滚。要确保有可用的备份，先执行 `sudo nft-okboy backup` 并确认成功。

- **没有 `nft-okboy` 命令**：较早的安装脚本不建立 `/usr/local/bin/nft-okboy` 链接，`upgrade` 也不会创建它。这时用完整路径 `sudo /opt/nft-okboy/nft-okboy upgrade`，或重新运行安装脚本补上链接。
- **armv6/armv7**：运行时无法区分这两种 32 位 ARM，`upgrade` 会报错退出。重新运行一键安装脚本即可升级（保留配置和数据库）；agent 节点的做法见[部署指引](docs/DEPLOYMENT.md)。
- **回滚只针对二进制**：新版本迁移过的数据库不会随之回退。
- **恢复数据库**：没有 `restore` 命令。先 `sudo systemctl stop nft-okboy`，用 `backup_dir`（默认 `/var/lib/nft-okboy/backups`）中的备份文件替换 `db_path` 指向的数据库文件，删除同目录下残留的 `-wal`、`-shm` 文件，再启动服务。每个备份旁边的 `.sha256` 文件可用于校验。
- `upgrade` 和重新运行安装脚本都不会更新已安装的 systemd 单元。新版本的单元有变化时（见 [CHANGELOG](CHANGELOG.md)），从 `deploy/` 重新安装并执行 `sudo systemctl daemon-reload`。

### 手动安装

从源码构建需要 Go 1.22 或更高版本。也可以从 [Releases](https://github.com/lvusyy/nft-okboy-fleet/releases) 下载对应架构的 `nft-okboy-linux-<arch>`，用 `SHA256SUMS` 校验后替换下面的文件名。以下命令在仓库根目录执行：

```bash
make static                  # → dist/nft-okboy-linux-amd64（其他架构用 make release-bins）
sudo install -Dm755 dist/nft-okboy-linux-amd64 /opt/nft-okboy/nft-okboy
sudo ln -sfn /opt/nft-okboy/nft-okboy /usr/local/bin/nft-okboy
sudo install -d -m 700 /etc/nft-okboy /var/lib/nft-okboy     # 单元的 ReadWritePaths 要求数据目录已存在
sudo install -m 600 config.example.yaml /etc/nft-okboy/config.yaml
sudo install -m 644 deploy/nft-okboy.service /etc/systemd/system/nft-okboy.service
sudo systemctl daemon-reload
sudo nft-okboy user-add --admin admin     # 建管理员，密钥只显示这一次
sudo systemctl enable --now nft-okboy
```

之后按[首次使用](#首次使用)配置 nginx 并建组。`serve` 需要 root 或 `CAP_NET_ADMIN`。

## Fleet 模式：一个 hub 管理多台机器

机器多了，可以只部署一个 hub，在每台受保护的机器上运行一个轻量 agent：

- **hub** 就是普通的 `nft-okboy serve`，保存用户、组、节点，以及组到节点端口的映射（target），是客户端唯一需要访问的入口。`firewall_backend: none` 时只做控制面；用 `nftables` 或 `ufw` 时，各组自己的端口也在 hub 本机生效。
- **agent** 即 `nft-okboy agent`，每隔 `--interval` 秒（默认 15 秒）用节点 token 经 HTTPS 向 hub 拉取本节点的期望状态，把本机防火墙调整到与之一致。它只发起出站连接，不监听端口，没有数据库。
- 客户端**只敲 hub 一次**，它被授权的每个节点都会在下一次拉取时放行它的新 IP。
- 一个 hub 可以同时管理 nftables 节点和 ufw 节点。

```bash
# hub 上
sudo nft-okboy node-add edge-1                     # 注册节点，打印 token（只显示一次）
sudo nft-okboy group-add web 8080                  # 建组：8080 是该组在 hub 本机的端口
sudo nft-okboy group-target add web edge-1 18080   # web 组在 edge-1 上对应 18080/tcp
sudo nft-okboy user-add alice                      # 建用户，打印只显示一次的密钥
sudo nft-okboy user-join alice web

# edge-1 上：安装二进制和 deploy/nft-okboy-agent.service，写好
# /etc/nft-okboy/agent.yaml（后端、agent_allowed_ports）和 /etc/nft-okboy/agent.env（hub 地址、节点名、token）
sudo systemctl enable --now nft-okboy-agent
```

- **不要在边缘节点上运行一键安装脚本**：它会安装并启动 standalone 服务，和 agent 争用同一张 `nft_okboy` 表。
- **`agent_allowed_ports`**：节点只放行、也只拦截这里列出的端口，即使 hub 被攻破，也无法让节点对外开放 SSH 等其他端口。nftables 节点不配置它时不拦截任何端口。
- **观测**：`sudo nft-okboy node-list`（或管理员 API `GET /api/admin/nodes`）显示各节点是否在线（60 秒内拉取过）、agent 版本、后端，以及 hub 为该节点计算的规则数。
- **撤销**：`node-del` 删除节点及其 target；该节点的 agent 下一次拉取收到 401 后删除全部放行规则并保留防护，受管端口随之关闭。
- **自升级**：启用 `nft-okboy-agent-upgrade.timer` 后，agent 每天检查一次新版本（armv6/armv7 不支持）。

完整步骤（standalone、fleet、Kubernetes、从 Python 版 ufw-okboy 迁移、升级、验证）见 **[部署指引](docs/DEPLOYMENT.md)**。

## HTTP API

所有 `/api/*` 响应都是 JSON：成功时 `{"ok": true, ...}`，失败时 `{"ok": false, "error": "..."}`。

**用户认证**：请求头 `Authorization: HMAC-SHA256 <用户名>:<时间戳>:<签名>`。时间戳是 Unix 秒；签名以用户密钥（字符串本身）为 key，对 `<用户名>:<时间戳>` 计算 HMAC-SHA256，取小写十六进制；服务器要求 `|当前时间 − 时间戳| ≤ signature_ttl`（默认 300 秒）。签名不涵盖请求方法、路径和正文，截获的请求头在 `signature_ttl` 内可以被重放，所以必须经 HTTPS 传输。

```bash
ts=$(date +%s)
sig=$(printf '%s' "alice:$ts" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
curl -X POST -H "Authorization: HMAC-SHA256 alice:$ts:$sig" https://example.com/api/knock
```

**管理员二次验证（step-up）**：下表标为「step-up」的接口，绑定了 TOTP 的管理员须在请求头 `X-TOTP-Code` 或 JSON 正文的 `totp_code` 字段中带上当前 6 位验证码（`totp_replay_protection` 开启时每个验证码只能用一次）；未绑定 TOTP 的管理员在 `require_admin_totp: true` 时不能调用这些接口。

**限流**：同一 IP 在 `throttle_window` 秒内认证失败达到 `throttle_max_failures` 次后，它的 `/api/*` 请求返回 429；TOTP 验证码错误还按账号计数，达到同样次数后返回 429。

**节点认证**：`GET /api/v1/node/desired-state` 使用 `Authorization: Bearer <node-add 打印的 token>`。

| 方法与路径 | 用途 | 鉴权 |
|---|---|---|
| `POST /api/knock` | 登记或刷新调用者的 IP | 用户 |
| `GET /api/status` | 调用者的状态：当前 IP、上次敲门时间、已启用的组等 | 用户 |
| `GET /api/me/groups` | 调用者所属的组及启用状态 | 用户 |
| `PATCH /api/me/membership/{group_id}` | 开关自己的某个组，正文 `enabled`（布尔）；非管理员只能重新开启曾被授权的组 | 用户 |
| `PATCH /api/membership/{user_id}/{group_id}` | 同上，但指定用户：改自己的无需 step-up，改别人的须是管理员 | 用户；改别人：管理员 + step-up |
| `GET /api/v1/node/desired-state` | agent 拉取本节点的放行规则（`rules`）和受管端口（`ports`）；可用 `X-Nft-Okboy-Version`、`X-Nft-Okboy-Backend` 请求头上报版本和后端 | 节点 token |
| `GET /api/admin/users` | 列出用户（不含密钥） | 管理员 |
| `POST /api/admin/users` | 创建用户：`username`，可选 `secret`、`is_admin`；返回密钥 | 管理员 + step-up |
| `DELETE /api/admin/users/{user_id}` | 删除用户并清理其规则 | 管理员 + step-up |
| `POST /api/admin/users/{user_id}/admin` | 设置或取消管理员：`is_admin`（默认 true） | 管理员 + step-up |
| `GET /api/admin/users/{user_id}/groups` | 所有组及该用户在各组中的成员状态 | 管理员 |
| `POST /api/admin/users/{user_id}/groups` | 授予组：`group_id`，可选 `enabled`（默认 true） | 管理员 + step-up |
| `POST /api/admin/memberships/remove` | 撤销成员资格：`username`、`group_name` | 管理员 + step-up |
| `POST /api/admin/users/{user_id}/revoke` | 强制下线：撤掉该用户的全部放行规则、清除 IP，默认轮换并返回新密钥（`rotate_secret: false` 不轮换） | 管理员 + step-up |
| `GET /api/admin/groups` | 列出组 | 管理员 |
| `POST /api/admin/groups` | 创建组：`name`、`port`，可选 `proto`（默认 tcp）；受 `allowed_ports` 限制 | 管理员 + step-up |
| `DELETE /api/admin/groups/{group_id}` | 删除组并清理规则 | 管理员 + step-up |
| `GET /api/admin/audit?limit=N` | 最近的审计记录，`limit` 默认 100，范围 1–1000 | 管理员 |
| `GET /api/admin/nodes` | 节点列表：是否在线、版本、后端、规则数 | 管理员 |
| `POST /api/admin/totp/enroll` | 生成 TOTP 密钥和 otpauth URI；已绑定时须带当前验证码 | 管理员 |
| `POST /api/admin/totp/activate` | 用正文中的 `totp_code` 确认并启用 TOTP | 管理员 |
| `DELETE /api/admin/totp` | 关闭 TOTP；已启用时须在正文中带 `totp_code` | 管理员 |
| `GET /health` | 健康检查，返回服务名和版本 | 无 |
| `GET /`、`GET /static/…` | 内嵌的 Web UI | 无 |

## CLI

```text
nft-okboy [-c <配置文件>] <命令> [参数]      选项可以写在位置参数之前或之后

服务
  serve [--debug]                           启动 HTTP 服务（standalone 或 hub）；--debug 让日志带上源码位置
  agent --hub <url> [选项]                  以 fleet agent 运行，选项见下

用户与组
  gen-secret [用户名]                       生成随机密钥并打印配置片段（不建用户，用于配置文件的 users: 导入）
  user-add <用户名> [--admin]               建用户，打印只显示一次的密钥
  user-del <用户名>                         删除用户并清理本机规则
  user-list                                 列出用户
  admin-add <用户名>                        授予管理员
  group-add <组名> <端口> [--proto tcp|udp] 建组；同一 端口/协议 只能属于一个组
  group-del <组名>                          删除组（连同它的 target）并清理本机规则
  group-list                                列出组
  user-join <用户名> <组名>                 授权用户使用组
  user-leave <用户名> <组名>                撤销授权
  revoke <用户名> [--no-rotate]             强制下线：撤掉该用户的全部放行规则、清除 IP，默认轮换密钥
  totp-uri <用户名>                         打印该用户 TOTP 密钥的 otpauth:// URI

Fleet（在 hub 上执行）
  node-add <节点名>                         注册节点，打印只显示一次的 token
  node-list                                 列出节点：是否在线、版本、后端、规则数、最后拉取时间
  node-del <节点名>                         删除节点及其 target
  group-target add <组名> <节点名> <端口> [--proto tcp|udp]
                                            把组映射到节点上的端口；对同一组和节点再次执行即修改
  group-target list                         列出全部 target
  group-target del <组名> <节点名>          删除 target（别名 rm、remove）

维护
  list                                      列出本机防火墙中的受管规则
  cleanup [--max-age <天数>]                把超过 N 天（默认 7，与 cleanup_max_age_days 无关）没敲门的用户移出白名单
  backup [--dir <目录>]                     一致性备份数据库并写 .sha256；默认写到 backup_dir，保留最新 backup_keep 份
  upgrade [--check] [--version vX.Y.Z] [--no-restart] [--no-backup] [--service <单元>]
                                            自更新；--service 默认 nft-okboy，agent 节点用 --service nft-okboy-agent --no-backup
  version（或 -V、--version）               打印版本

agent 选项
  --hub <url>            hub 地址；须为 https，明文 http 只允许回环地址或加 --allow-http
  --node <名称>          节点名，只用于日志（节点身份由 token 决定）
  --token <token>        节点 token；默认读取环境变量 NFT_OKBOY_TOKEN（推荐：命令行参数对本机所有用户可见）
  --interval <秒>        拉取间隔，默认 15
  --ca <pem>             只用这个证书（hub 的 CA，或自签证书本身）校验 hub
  --insecure             不校验 hub 证书（不推荐），与 --ca 互斥
  --allow-http           允许非回环地址的明文 http hub；也可设置 NFT_OKBOY_ALLOW_HTTP=1
  --allow-ports <列表>   逗号分隔的端口，覆盖配置中的 agent_allowed_ports
  --state <文件>         保存最近一次防护的文件，默认 /var/lib/nft-okboy/agent-guard.json；设为 "" 关闭
```

管理命令直接打开数据库，需要 root 权限（`sudo nft-okboy …`）；配置文件的查找顺序见[配置](#配置)。

## 配置

未指定 `-c` 时，依次使用可执行文件同目录下的 `config.yaml`（存在时）和 `/etc/nft-okboy/config.yaml`。全部选项及说明见 [`config.example.yaml`](config.example.yaml)，常用的有：

```yaml
listen_host: 127.0.0.1                 # nginx 在同一台机器上时只监听本机
listen_port: 5000
trusted_proxies: ["127.0.0.1", "::1"]  # 只采信来自这些地址（完整 IP，不支持网段）的 X-Real-IP / X-Forwarded-For
signature_ttl: 300                     # 签名时间戳允许的偏差，秒
throttle_max_failures: 10              # 按 IP 限流，0 关闭
require_admin_totp: false              # true：未绑定 TOTP 的管理员不能执行管理写操作
totp_replay_protection: true           # 每个 TOTP 验证码只能用一次
firewall_backend: nftables             # nftables | ufw | none（只做控制面的 hub）
nft_table: nft_okboy                   # 专用 inet 表
nft_priority: -150                     # input 钩子优先级
nft_guard: true                        # 受管端口对白名单以外关闭；false = 只放行，什么也拦不住
cleanup_max_age_days: 7                # 多少天没敲门就移出白名单，0 为不过期
db_path: /var/lib/nft-okboy/nft-okboy.db
# agent_allowed_ports: [18080]         # 仅 agent 使用：只放行、只拦截这些端口
# users:                               # 可选：只在新建数据库时导入一次，导入的用户不是管理员
#   alice: { secret: "<nft-okboy gen-secret 生成的 64 位十六进制>" }
```

agent 只读取其中与防火墙有关的项：`firewall_backend`、`rule_prefix`、`nft_table`、`nft_chain`、`nft_priority`、`nft_guard` 和 `agent_allowed_ports`。

## 测试

```bash
make test          # 单元测试（go test ./...），任意操作系统都能运行
make vet           # go vet
make integration   # 在隔离的网络命名空间里对真实 nftables 运行集成测试（Linux，需要 sudo）
```

防火墙操作都在 `FirewallBackend` 接口之后，对账、HTTP 处理和 agent 的逻辑用内存中的 `MockBackend` 做单元测试；nftables 和 ufw 后端另有在真实防火墙上运行的集成测试。`scripts/` 中的脚本都在网络命名空间里运行，不影响宿主机的防火墙：

| 脚本 | 内容 |
|------|------|
| `scripts/ufw-integration.sh` | 在私有的 mount + net 命名空间里启用 ufw，运行 ufw 集成测试 |
| `scripts/e2e-fleet.sh` | hub（`none` 后端）+ agent（`AGENT_BACKEND=ufw` 或 `nftables`）：规则下发、换 IP、退组、`agent_allowed_ports` 拒绝越界端口、hub 停机时保留规则、`node-list` |
| `scripts/e2e-nft-traffic.sh` | 两个网络命名空间之间的真实连接：standalone 与 hub + agent 两种部署下的放行和拦截、已建立会话不中断、其他防火墙拦截端口、节点被删除、规则集被清空或 hub 停机时的防护恢复 |
| `scripts/e2e-test.sh` | standalone 服务端到端（HMAC 敲门 + 真实 nftables）；手动运行，不在 CI 中 |

CI 在向 `main`/`master` 推送或发起 PR 时运行：`go vet`、单元测试、全部 9 种架构的交叉编译、nftables 集成测试、`scripts/ufw-integration.sh`、`scripts/e2e-fleet.sh`（ufw、nftables 各一次）和 `scripts/e2e-nft-traffic.sh`。

## 目录结构

```text
cmd/nft-okboy/        main：解析全局参数，分发子命令
internal/cli/         各子命令的实现（serve、agent、upgrade、用户/组/节点管理等）
internal/config/      YAML 配置加载与默认值
internal/db/          SQLite 层：schema 与迁移、增删改查、节点与期望状态、备份
internal/auth/        HMAC 验签、TOTP、按 IP 限流
internal/firewall/    后端接口与实现（nftables、ufw、none、Mock）、对账、防护
internal/server/      HTTP 路由（客户端、管理、节点 API）与定期维护
internal/agent/       fleet agent：拉取期望状态、对账、防护
internal/hub/         仅有包文档（hub 逻辑在 internal/server 和 internal/db）
internal/static/      用 go:embed 内嵌的单文件 Web UI
deploy/               安装脚本、systemd 单元（服务、agent、agent 自升级）、nginx 示例
docs/                 部署指引
scripts/              集成与端到端测试脚本
.github/workflows/    CI 与按标签发版
```

## 安全

请不要在公开 issue 中报告漏洞，请使用 GitHub 的私密漏洞报告。支持的版本、报告方式和已知限制见 [SECURITY.md](SECURITY.md)。

## 更新记录

各版本的变更见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

[MIT](LICENSE)
