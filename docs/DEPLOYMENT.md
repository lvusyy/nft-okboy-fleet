# 部署指引（Deployment Guide）

nft-okboy 是**一个二进制**，可按需运行三种模式，并搭配三种防火墙后端：

| 模式 | 角色 | 后端 (`firewall_backend`) |
|------|------|---------------------------|
| `standalone` | 单机自治：本机即受保护机器 | `nftables`（默认）/ `ufw` |
| `hub` | 中心控制面：管用户/组/节点/期望状态 | `none`（纯控制面）/ `nftables`·`ufw`（兼自保护）|
| `agent` | 边缘节点：出站拉取期望状态、对账本机防火墙 | `nftables` / `ufw` |

> **agent 的安全模型**：纯出站连接 hub，**无数据库、不监听任何公网端口**。即便 hub 被攻破，
> agent 的本地 `agent_allowed_ports` 白名单也能拒绝越界端口（见下）。

> **nftables 后端怎么拦**：受管端口（服务端 = 各组的端口；agent = hub 下发的本节点目标端口中、列在
> `agent_allowed_ports` 里的那些）对白名单以外的来源关闭——TCP 丢弃新连接、已建立的会话不断，UDP 丢弃所有数据报，
> 本机回环不受限。其余端口 nft-okboy 不碰。主机上若还有别的防火墙（ufw、firewalld、nftables.conf）拦着受管端口，
> 白名单用户照样进不来：nftables 里一条链的放行不是最终结论。此时要么在那边放开该端口（由 nft-okboy 负责筛选），
> 要么在 ufw 主机上改用 `firewall_backend: ufw`。启动日志会列出检测到的其他防火墙。
>
> Docker（`-p`）或 Kubernetes（NodePort）经 DNAT 转发走的端口不经过 input 钩子，nft-okboy 既拦不住也放行不了，
> 别把这类端口配成组端口（或在转发路径上限制，例如 Docker 的 `DOCKER-USER` 链）。启动日志发现 nat 链时会提示。
>
> hub 兼做节点时（同一台机器上既跑 `serve` 又跑 `agent`），两者**不能共用同一张表**：各自按自己的期望状态对账，
> 会把对方的规则和防护当作多余的删掉。要么 hub 用 `firewall_backend: none`，要么给 agent 单独配 `nft_table`
> （ufw 后端则配不同的 `rule_prefix`）。
>
> **从 v0.3.x 升级**：旧版 nftables 后端只加放行规则、实际什么也拦不住（端口对所有人开放，或被主机防火墙全挡）。
> 升级后受管端口立即对白名单以外关闭。升级前先确认你依赖的访问（比如 SSH 所在的组端口）已经有人敲门；
> 已建立的会话不受影响。确需旧行为时设 `nft_guard: false`。

下面给出三种典型部署案例。

---

## 场景一：单机 standalone（最简，1~2 台）

适合"这台机器自己保护自己"。一条命令装好：

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

脚本：按架构下载静态二进制（以 GitHub 公布的 sha256 校验，拿不到或对不上就中止）→ 写 `/etc/nft-okboy/config.yaml` → 装并启用 systemd
→ 建 admin 并打印一次性密钥。然后：

```bash
nft-okboy group-add ssh 22         # 把 22 端口纳管为 "ssh" 组（此后只放行敲过门的 IP；敲门后另开一个 SSH 会话确认能连上，再断开当前会话）
nft-okboy user-join admin ssh      # 授权 admin
```

浏览器打开 `https://你的服务器/` → 输入用户名 + 密钥 → **Connect**。完整单机说明见 [README](../README.md)。

---

## 场景二：Fleet —— 1 个 hub + N 个 agent（推荐用于多机）

把"谁被允许"（hub 控制面）和"开防火墙口子"（agent 数据面）分开：**部署一次 hub + 每台机器一个轻量 agent**，
不再每台装一整套。客户端**敲一次 hub**，授权的所有机器自动开口。一个 hub 可同时管 **nftables 与 ufw** 异构边缘。

```
  Client ──knock(一次)──► HUB（控制面 · 唯一公网入口 · nginx TLS）
                          │  users/groups/nodes/期望状态
              出站 HTTPS  ▼  （agent 拨出，节点不监听公网）
            ┌─────────────┼─────────────┐
        ┌───┴───┐     ┌───┴───┐     ┌───┴───┐
        │agent  │     │agent  │     │agent  │
        │ufw    │     │nft    │     │nft    │
        └───────┘     └───────┘     └───────┘
        node-A         node-B         node-C
```

### 1) 部署 hub

```bash
# 装二进制
sudo install -Dm755 nft-okboy-linux-amd64 /opt/nft-okboy/nft-okboy
sudo install -Dm644 deploy/nft-okboy.service /etc/systemd/system/nft-okboy.service

# hub 配置 /etc/nft-okboy/config.yaml
sudo install -Dm600 /dev/stdin /etc/nft-okboy/config.yaml <<'YAML'
firewall_backend: none          # 纯控制面（hub 自己不开端口）；要兼自保护改 nftables/ufw
rule_prefix: nft-okboy
listen_host: 127.0.0.1          # 经 nginx 暴露，仅本机监听
listen_port: 5000
trusted_proxies: ["127.0.0.1", "::1"]
require_admin_totp: true        # 生产建议开启管理员 2FA
db_path: /var/lib/nft-okboy/nft-okboy.db
YAML

# nginx 做 TLS 终止（务必透传 X-Real-IP）：参考 deploy/nginx-nft-okboy.conf
sudo systemctl enable --now nft-okboy
nft-okboy user-add admin --admin    # 建管理员（打印一次性密钥）
```

> hub 是新的"皇冠明珠"：用单证书、单入口集中加固它，并开启 `require_admin_totp`。
>
> hub 改用 `nftables`/`ufw` 兼自保护时，**每个组自己的端口也在 hub 本机生效**：nftables 后端会把它对白名单以外
> 关闭。别让组端口与 hub 自己对外的端口（nginx 的 443/80、SSH）重合，否则没敲过门的人连 hub 都进不来、也就没法敲门。
> 纯控制面用 `none` 最省心。

### 2) 在 hub 上注册节点 + 配置目标 + 授权用户

```bash
nft-okboy node-add edge-1                       # 打印一次性 token（仅显示一次，配给该节点的 agent）
nft-okboy group-add web 8080                    # 定义一个组（legacy 本地端口，仅 standalone 用）
nft-okboy group-target add web edge-1 18080     # web 组在 edge-1 上映射到 18080/tcp
nft-okboy user-join alice web                   # 授权 alice 使用 web 组
```

- 一个 group 可有**多个** target（不同节点不同端口）：`group-target add web edge-2 9090` …
- `group-target list` 查看全部 节点→组→端口 映射。

### 3) 每个边缘节点部署 agent

```bash
sudo install -Dm755 nft-okboy-linux-amd64 /opt/nft-okboy/nft-okboy
sudo install -Dm644 deploy/nft-okboy-agent.service /etc/systemd/system/nft-okboy-agent.service

# agent 配置（只需后端 + 前缀 + 安全护栏；无需 DB）
sudo install -Dm644 /dev/stdin /etc/nft-okboy/agent.yaml <<'YAML'
firewall_backend: nftables      # 或 ufw（按节点防火墙选）
rule_prefix: nft-okboy
agent_allowed_ports: [18080]    # 安全护栏：本节点只允许开、也只会关这些端口（见下）
YAML

# hub 地址 / 节点名 / token（0600；token 经环境变量传给 agent，不进 unit、不入日志，也不出现在 ps 能看到的进程参数里）
sudo install -Dm600 /dev/stdin /etc/nft-okboy/agent.env <<'ENV'
NFT_OKBOY_HUB=https://hub.example.com/
NFT_OKBOY_NODE=edge-1
NFT_OKBOY_TOKEN=<上一步 node-add 打印的 token>
ENV

sudo systemctl enable --now nft-okboy-agent
```

> hub 用**自签证书**时，把 hub 的证书（或签发它的 CA）拷到节点，例如 `/etc/nft-okboy/hub.pem`，给 agent 加
> `--ca /etc/nft-okboy/hub.pem`（编辑 unit 的 `ExecStart`）。不要用 `--insecure`：它不校验证书，
> 同一网络路径上的任何人都能冒充 hub、偷走节点 token、给节点下发规则。
>
> agent 只接受 `https://` 的 hub（本机回环地址除外）；hub 在可信的内网（如集群内部 Service）且只能走明文 http 时，
> 需显式加 `--allow-http`（或在 agent.env 里写 `NFT_OKBOY_ALLOW_HTTP=1`，不用改 unit）。

### 4) 客户端 knock（一次覆盖全队列）

客户端（Web UI / `knock.py` / `knock.sh`）指向 **hub**，认证一次即可。hub 据此算出该用户授权的
所有 `(节点, 端口)`，各节点 agent 在下个心跳拉取并放行——**一次 knock 覆盖你授权的所有机器**。

### 🛡 安全护栏：`agent_allowed_ports`（强烈建议；nftables 节点必配）

agent 在本地过滤 hub 下发的期望状态，**只开白名单内端口**，丢弃其余并告警。这样即便 hub 被攻破，
也命令不动某节点去开 SSH 等敏感端口。

nftables 节点上它同时是**防护能关闭的端口范围**：hub 下发的本节点端口里，只有列在这里的才会对白名单以外关闭；
没配时 agent 不关任何端口（只放行、什么也拦不住）并在日志里告警。这样被攻破的 hub 也没法让全队列关掉 SSH。

agent 把最近一次生效的防护记在 `/var/lib/nft-okboy/agent-guard.json`（`--state` 可改，`""` 关闭）：
重启或规则集被清空后，即使暂时连不上 hub，也会立即恢复防护。

```yaml
# agent.yaml
agent_allowed_ports: [18080, 443]
```
```bash
# 或 CLI 覆盖：
NFT_OKBOY_TOKEN=... nft-okboy agent --hub ... --allow-ports 18080,443
```

### 📊 Fleet 观测

```bash
nft-okboy node-list        # 各节点：在线 / version / backend / 当前规则数 / 最后心跳
```
或管理员 API：`GET /api/admin/nodes` → 同样信息的 JSON。

### ⬆ Agent 自升级（可选，opt-in）

```bash
sudo install -Dm644 deploy/nft-okboy-agent-upgrade.service /etc/systemd/system/nft-okboy-agent-upgrade.service
sudo install -Dm644 deploy/nft-okboy-agent-upgrade.timer   /etc/systemd/system/nft-okboy-agent-upgrade.timer
sudo systemctl enable --now nft-okboy-agent-upgrade.timer   # 每日检查新 release，有则升级 agent 并重启
```
手动等价：`sudo nft-okboy upgrade --service nft-okboy-agent --no-backup`（无 DB 节点跳过备份）。

---

## 场景三：Kubernetes

把每个 pod 当作一个隔离环境：1 个 hub pod + 每个受保护节点一个 agent pod。

### 推荐：自带 nftables 的镜像

`Dockerfile`：

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY nft-okboy-linux-amd64 /usr/local/bin/nft-okboy
ENTRYPOINT ["/usr/local/bin/nft-okboy"]
```

hub（`Deployment` + `Service`）：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: nft-okboy-hub, namespace: nft-okboy }
spec:
  replicas: 1
  selector: { matchLabels: { app: nft-okboy-hub } }
  template:
    metadata: { labels: { app: nft-okboy-hub } }
    spec:
      containers:
      - name: hub
        image: registry.example.com/nft-okboy:latest
        args: ["-c","/etc/nft-okboy/config.yaml","serve"]
        ports: [{ containerPort: 5000 }]
        volumeMounts:
        - { name: config, mountPath: /etc/nft-okboy }
        - { name: data,   mountPath: /var/lib/nft-okboy }
      volumes:
      - name: config
        configMap: { name: nft-okboy-hub-config }     # 内含 config.yaml（firewall_backend: none）
      - { name: data, emptyDir: {} }              # 生产用 PVC 持久化 SQLite
---
apiVersion: v1
kind: Service
metadata: { name: nft-okboy-hub, namespace: nft-okboy }
spec:
  selector: { app: nft-okboy-hub }
  ports: [{ port: 5000, targetPort: 5000 }]
```

agent（每节点一个；需 `NET_ADMIN` 编程 pod netns 的 nftables）：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: nft-okboy-agent-edge1, namespace: nft-okboy }
spec:
  replicas: 1
  selector: { matchLabels: { app: nft-okboy-agent, node: edge1 } }
  template:
    metadata: { labels: { app: nft-okboy-agent, node: edge1 } }
    spec:
      containers:
      - name: agent
        image: registry.example.com/nft-okboy:latest
        # token 由下面的 NFT_OKBOY_TOKEN 环境变量提供，不放进 args（args 在节点上 ps 可见）；
        # hub 走集群内网的明文 http，所以要显式加 --allow-http。
        args: ["-c","/etc/nft-okboy/agent.yaml","agent",
               "--hub","http://nft-okboy-hub:5000","--node","edge1",
               "--allow-http","--allow-ports","18080"]
        env:
        - name: NFT_OKBOY_TOKEN
          valueFrom: { secretKeyRef: { name: nft-okboy-edge1-token, key: token } }
        securityContext:
          capabilities: { add: ["NET_ADMIN"] }    # 或 privileged: true
        volumeMounts: [{ name: config, mountPath: /etc/nft-okboy }]
      volumes:
      - name: config
        configMap: { name: nft-okboy-agent-config }   # agent.yaml: firewall_backend: nftables
```

token 用 Secret（`kubectl create secret generic nft-okboy-edge1-token --from-literal=token=<node-add 的 token>`）。
节点注册/目标配置在 hub 内执行：`kubectl exec deploy/nft-okboy-hub -- nft-okboy -c /etc/nft-okboy/config.yaml node-add edge1`。

### 无 registry / 离线集群：hostPath 注入静态二进制（已验证）

集群拉不到镜像时，可用缓存的 `alpine` + hostPath 把 nft-okboy 静态二进制（+ 节点 `nft` 及其依赖库的
自带-glibc bundle）挂进 pod。参考 `scripts/` 中的做法与 [部署测试报告](#)。nft-okboy 是 `CGO_ENABLED=0`
静态二进制，任意基础镜像可跑；只有 agent 的 `nft` 子进程需要 nftables。

---

## 从 Python ufw-okboy 迁移

Go 版与 Python 版的 SQLite schema **逐字符相同**，可原地接管：

```bash
sudo systemctl stop ufw-okboy            # 停 Python 服务
# Go config.yaml：
#   firewall_backend: ufw                # 用 ufw 后端
#   rule_prefix: ufw-okboy               # 对齐 Python 既有规则注释前缀（Python 默认 ufw-okboy）
#   db_path: /var/lib/ufw-okboy/ufw-okboy.db   # 指向既有 SQLite（init 会幂等跑 migrations）
sudo systemctl enable --now nft-okboy        # 起 Go 二进制；既有 ufw 规则被识别，零丢失
```

---

## 验证部署

```bash
nft-okboy node-list                          # 各节点应 online，backend/规则数正确
```

端到端自检（隔离沙箱，对宿主零影响，ufw 与 nftables 双后端）：

```bash
# 在装了 Go 的机器交叉编译测试二进制后，于一台有 ufw+nft+unshare 的 Linux 上：
sudo BIN=/path/nft-okboy AGENT_BACKEND=nftables bash scripts/e2e-fleet.sh
sudo BIN=/path/nft-okboy AGENT_BACKEND=ufw      bash scripts/e2e-fleet.sh
```

`scripts/e2e-fleet.sh` 在 netns + 私有 `/etc/ufw` 沙箱里跑通 `hub → agent → 真实防火墙`，覆盖
规则应用、IP 变更、退组移除、**故障安全**（hub 不可达保留规则）、**护栏**（拒绝白名单外端口）。
CI 每次 push 全跑（含真实 nft/ufw 集成 + e2e 双后端）。
