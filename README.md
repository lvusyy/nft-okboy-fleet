# okboy

[![CI](https://github.com/lvusyy/nft-okboy/actions/workflows/ci.yml/badge.svg)](https://github.com/lvusyy/nft-okboy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lvusyy/nft-okboy?sort=semver)](https://github.com/lvusyy/nft-okboy/releases)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64%20%7C%20armv7%20%7C%20riscv64%20%7C%20ppc64le%20%7C%20s390x%20%7C%20loong64-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**基于 nftables 的动态防火墙白名单管理器** — 授权客户端认证一次，其（不断变化的）
IP 就被自动注册进防火墙；规则整洁、可追溯、能自愈。**单个静态 Go 二进制**、无运行
时依赖，从 x86 服务器到树莓派、路由器、RISC-V、龙芯都能跑。

[English](README.en.md) | 简体中文

> [ufw-okboy](https://github.com/lvusyy/UFW-OkBoy) 的 Go + nftables 重写：保留全部
> 久经考验的认证/安全语义，数据面换成 nftables 原生，交付物换成单个静态二进制。

---

## 它解决什么问题

敏感端口（SSH、管理后台、数据库、监控面板）应只对可信 IP 开放。但人的 IP 一直在变
——家宽、4G、出差、VPN——每次都手动改防火墙规则根本不现实。

**okboy 把这件事自动化**：用户在网页（或一个小脚本）里认证一次，服务器就把**他当前
的 IP** 精确放行到**他所在组授权的端口**。IP 变了？下一个 30 秒心跳无感切换规则——不
留规则垃圾、全程审计、零长期暴露面。

## ✨ 能力一览

### 🔥 防火墙 —— nftables 原生
- **按 (用户, 组, 端口) 的放行规则**，落在专用 `inet okboy` 表里——每个授权一条规则，
  注释 `okboy:<用户>:<组>`，完全可追溯。
- **IP 无缝切换**——新 IP 一注册，旧 IP 立刻移除。
- **每次 knock 原子幂等 reconcile**——把防火墙调整到与数据库**完全一致**（补缺、删除
  旧 IP/失效组/残留规则），从竞态、崩溃、并发变更中自愈。
- **与 Kubernetes / 主机防火墙共存**——独占表、`input` 钩子优先级 -150、**policy
  accept 且只加 accept 规则**：只能为指定 IP/端口**放行**，永不 drop、永不 flush 别人的规则。
- **精确、防注入写入**——每次变更都是 JSON 事务经 `nft -j -f -` 写入（无 shell、无 argv
  拼接），按稳定的规则 handle 删除。

### 🔐 安全
- **无状态 HMAC-SHA256 认证**——密钥不上线；带时间戳、有重放窗口、失败全部记录。
- **管理员 TOTP step-up（RFC 6238）**覆盖*每一个*管理写操作，**原子防重放**（用过的码
  不能再用）+ 再注册需证明持有。
- **按 IP 限流**——同一 IP 失败过多 → HTTP 429（按 IP 不按用户名，攻击者无法把正常用户锁死）。
- **输入白名单（SR-1）**——用户名/组名限定 `[A-Za-z0-9_-]`（≤64），从源头堵死 nft 注入。
- **防 IP 伪造（H-9）**——`X-Forwarded-For` 仅信任配置的代理、取最右 hop。
- **强制下线 / revoke**——关端口 + 清状态 + 轮换密钥，泄露的凭据即刻失效。

### 🧰 运维
- **单个静态二进制**（`CGO_ENABLED=0` + 纯 Go SQLite）——无 Python / venv / gunicorn / libc。
  丢上去就能跑。
- **9 种 CPU 架构**——见 [平台](#平台)。
- **在线备份 / 恢复**——一致的 SQLite 快照 + SHA-256 校验和。
- **审计日志 + 异常检测**——所有管理操作入审计；可疑 IP 频繁切换告警（疑似凭据共享）。
- **三种控制面**——内置 **Web 管理台**、完整 **CLI**、REST **HTTP API**，按需选用。
- **systemd 就绪**，配 nginx 做 TLS 终止。

### 🌐 客户端
- **Web UI**（内嵌单文件）——登录一次，每 30s 自动续期，适配手机。
- **Python / Shell** 续期客户端——协议与 ufw-okboy 完全一致，其 `knock.py` / `knock.sh` 直接可用。

## 架构

```
客户端（浏览器 / Python / Shell）
    │  HTTPS + HMAC-SHA256 签名
    ▼
Nginx（TLS 终止，传 X-Real-IP）
    │  HTTP 127.0.0.1:5000
    ▼
okboy（Go：HTTP API + CLI + 鉴权 + 限流）
    │  nft -j -f -   （JSON 事务，无 shell）
    ▼
nftables（专用 inet okboy 表 —— 仅 accept，与 k8s/host 共存）
    │
    ▼
SQLite（纯 Go modernc；用户 / 组 / 成员 / 审计）
```

## 平台

每个 [release](https://github.com/lvusyy/nft-okboy/releases) 都附预编译的静态 `linux` 二进制：

| 架构 | 目标 | 典型硬件 |
|------|------|---------|
| `amd64`   | x86-64       | 服务器、云 |
| `arm64`   | aarch64      | AWS Graviton、Pi 4/5、多数 ARM 云 |
| `armv7`   | 32 位 ARM    | Pi 2/3、众多 SBC |
| `armv6`   | 32 位 ARM    | Pi 1 / Zero |
| `386`     | 32 位 x86    | 老旧 / 嵌入式 |
| `riscv64` | RISC-V       | SiFive、VisionFive |
| `ppc64le` | POWER (LE)   | OpenPOWER 服务器 |
| `s390x`   | IBM Z        | 大型机 |
| `loong64` | LoongArch    | 龙芯 / Loongson |

> 因为 okboy 是纯 Go（无 cgo），交叉编译到以上任意架构都是零成本（`make release-bins`）。
> **MIPS**（`mips`/`mipsle`，部分老路由器）**不支持**——纯 Go 的 SQLite 驱动（modernc）
> 没有 MIPS 移植。nftables 仅限 Linux，故没有 macOS/Windows 的服务端构建（*客户端*仍跨平台）。

## 快速开始

### 一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy/main/deploy/install.sh | sudo sh
```

> 国内网络慢可走镜像（脚本下载二进制时也会自动镜像兜底）：
> `curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/nft-okboy/main/deploy/install.sh | sudo sh`

脚本自动：按架构下载二进制（sha256 校验）→ 写入 `/etc/okboy/config.yaml`（默认值即生产可用）→ 安装并启用 systemd 服务 → **创建 admin 并在结尾高亮打印一次性密钥**。重复运行即刷新二进制（配置/数据库保留）。

装完开第一个组并授权，然后浏览器打开 Web 管理台，输入用户名 + 密钥 → **Connect**：

```bash
okboy group-add ssh 22       # 把 22 端口纳管为 "ssh" 组
okboy user-join admin ssh    # 授权 admin 使用该组
```

### 升级

```bash
sudo okboy upgrade           # 自更新到最新 release（备份 DB → 校验 → 重启 → 失败回滚）
sudo okboy upgrade --check   # 只检查不安装
```

### 从源码 / 手动

```bash
make static                                  # → dist/nft-okboy-linux-amd64（CGO_ENABLED=0，静态）
#   或下载：curl -fsSLO https://github.com/lvusyy/nft-okboy/releases/latest/download/nft-okboy-linux-amd64
cp config.example.yaml config.yaml
./okboy gen-secret alice                     # 生成用户密钥
./okboy -c config.yaml user-add alice        # 建用户
./okboy -c config.yaml group-add ssh 22      # 建组（绑端口 22）
./okboy -c config.yaml user-join alice ssh   # 把 ssh 组授权给 alice
sudo ./okboy -c config.yaml serve            # 启动（需 root 或 CAP_NET_ADMIN）
```

然后浏览器打开 `https://你的服务器/` → 输入用户名 + 密钥 → **Connect**。

## 🌐 Fleet 模式：一个 hub 管多机

机器多了，不想每台装一整套？同一个 okboy 二进制还能跑**中心化 fleet**：

- 一个 **hub**（控制面，唯一公网入口）holds 全部用户 / 组 / 节点 / 期望状态；
- 每台机器一个轻量 **agent**——**纯出站拉取、无数据库、不监听任何公网端口**；
- 客户端**敲一次 hub**，授权的所有机器自动开口；
- 一个 hub 可同时管 **nftables 与 ufw** 异构边缘。

```bash
# ① hub 上：注册节点 + 配置目标 + 授权用户
okboy node-add edge-1                      # 打印一次性 token（配给该节点的 agent）
okboy group-add web 8080
okboy group-target add web edge-1 18080    # web 组在 edge-1 上映射到 18080
okboy user-join alice web

# ② 边缘节点上：填 /etc/okboy/agent.env(OKBOY_HUB/NODE/TOKEN) + agent.yaml，然后
systemctl enable --now okboy-agent

# ③ 客户端敲一次 hub —— 授权的所有节点自动放行（一次 knock 覆盖全队列）
```

- **🛡 安全护栏**：`agent_allowed_ports: [18080]` —— 节点只开白名单端口，**hub 被攻破也开不了 SSH**。
- **📊 观测**：`okboy node-list` 看各节点 online / version / backend / 规则数。
- **⬆ 自升级**：启用 `okboy-agent-upgrade.timer` 即可让 agent 每日自更新。

> 📖 完整步骤（standalone / fleet / Kubernetes / 从 ufw-okboy 迁移 / 验证）见
> **[部署指引 → docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**。

## HTTP API

所有 `/api/*` 响应均为 `{"ok": ..., ...}`。认证用请求头
`Authorization: HMAC-SHA256 <用户>:<时间戳>:<十六进制签名>`。

| 方法与路径 | 用途 | 鉴权 |
|---|---|---|
| `POST /api/knock` | 注册 / 刷新调用者 IP | 用户 |
| `GET /api/status` | 调用者当前注册状态 | 用户 |
| `GET /api/me/groups` | 调用者所属的组 | 用户 |
| `PATCH /api/me/membership/{gid}` | 自助开关已授权的组 | 用户 |
| `GET /api/admin/users` · `POST` · `DELETE /{id}` | 列出 / 创建 / 删除用户 | 管理员（+ step-up）|
| `POST /api/admin/users/{id}/admin` | 提权 / 降权 | 管理员 + step-up |
| `GET/POST /api/admin/users/{id}/groups` | 查看 / 授予成员 | 管理员（+ step-up）|
| `POST /api/admin/memberships/remove` | 撤销成员 | 管理员 + step-up |
| `POST /api/admin/users/{id}/revoke` | 强制下线 + 轮换密钥 | 管理员 + step-up |
| `GET /api/admin/groups` · `POST` · `DELETE /{id}` | 列出 / 创建 / 删除组 | 管理员（+ step-up）|
| `GET /api/admin/audit` | 近期管理操作 | 管理员 |
| `POST /api/admin/totp/{enroll,activate}` · `DELETE /api/admin/totp` | 2FA 生命周期 | 管理员 |
| `GET /health` | 健康/版本探针 | 无 |

## CLI

```
serve [--debug]                    启动 API 服务
upgrade [--check]                  自更新到最新 release
gen-secret [user]                  生成密钥
user-add <name> [--admin]          建用户（打印密钥）
user-del / user-list
group-add <name> <port> [--proto tcp] / group-del / group-list
user-join <user> <group> / user-leave <user> <group>
admin-add <user>                   授予管理员
revoke <user> [--no-rotate]        强制下线 + 轮换密钥
list                               列出受管 nftables 规则
cleanup [--max-age <days>]         清理过期规则
backup [--dir <path>]              校验和在线备份
--version
```

## 配置（节选）

```yaml
listen_host: 127.0.0.1
listen_port: 5000
trusted_proxies: ["127.0.0.1", "::1"]   # 信任谁的 X-Real-IP/XFF
throttle_max_failures: 10               # 按 IP，0 关闭
require_admin_totp: false               # 强制管理员 2FA
totp_replay_protection: true
nft_table: okboy                        # 专用 inet 表
nft_priority: -150                      # 仅 accept，与 k8s 共存
db_path: /var/lib/okboy/okboy.db
# users:                                # 可选首次种子
#   admin: { secret: "<64 位十六进制>" }
```

## 测试

```bash
make test          # 单元：auth(RFC 6238 向量)、db 原语、firewall Mock reconcile —— 任意平台
make integration   # 隔离 netns 内真实 nftables（Linux+root）—— 对 host/k8s 零影响
```

防火墙逻辑抽象在 `FirewallBackend` 接口之后，所以核心 reconcile/鉴权代码可在任意开发系统用
内存 `MockBackend` 单测；`NftBackend` 在隔离 network namespace 内对**真实** nftables 验证。
`scripts/e2e-test.sh` 端到端跑通整条链路（服务 + HMAC knock + 真实 nft）。CI 每次 push 全跑；
项目还经 codex 审查。

## 部署

```bash
install -Dm755 dist/nft-okboy-linux-amd64 /opt/okboy/okboy
install -Dm600 config.yaml /etc/okboy/config.yaml
install -Dm644 deploy/okboy.service /etc/systemd/system/okboy.service
systemctl enable --now okboy
# nginx：deploy/nginx-okboy.conf —— 务必 proxy_set_header X-Real-IP $remote_addr
```

## 目录结构

```
cmd/okboy/            main：子命令分发
internal/config/      YAML 配置加载
internal/db/          SQLite 层（schema + 迁移 + CRUD + 原子 IP 写 + 备份）
internal/auth/        HMAC 验签 + TOTP + 按 IP 限流
internal/firewall/    FirewallBackend 接口 + nftables 实现 + Mock + Manager(reconcile)
internal/server/      stdlib net/http 路由（mirror 全部端点）
internal/static/      go:embed 单文件 Web UI
deploy/               systemd unit + nginx 示例
scripts/              端到端测试
.github/workflows/    CI + 打标签自动多架构发版
```

## 许可证

MIT
