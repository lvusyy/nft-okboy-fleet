# 部署指引

nft-okboy 是一个二进制，用子命令扮演三种角色：

| 角色 | 子命令 | systemd 单元 | 防火墙后端（`firewall_backend`） |
|------|--------|--------------|----------------------------------|
| standalone | `serve` | `nft-okboy.service` | `nftables`（默认）或 `ufw` |
| hub | `serve` | `nft-okboy.service` | `none`（只做控制面），或 `nftables`、`ufw`（同时保护 hub 本机） |
| agent | `agent` | `nft-okboy-agent.service` | `nftables` 或 `ufw` |

hub 就是注册了节点的 `serve`：它照常处理敲门和管理请求，另外为每个节点计算期望状态。agent 只向 hub 发起出站连接，不监听端口，也没有数据库；它在本地只保存最近一次生效的防护（见下文 `agent_allowed_ports` 一节）。

下面先说明各种部署共用的要点，再给出三种典型部署：单机、fleet（1 个 hub + N 个 agent）和 Kubernetes。

## 通用要点

**命令与权限**。一键安装脚本把 `/usr/local/bin/nft-okboy` 链接到 `/opt/nft-okboy/nft-okboy`，手动安装时也照此建立链接（见下文）。较早的安装脚本不建这个链接，`upgrade` 也不会创建它：standalone 和 hub 上重新运行安装脚本即可补上，agent 节点上请手动建立链接或使用完整路径。管理命令直接读写数据库（只有 root 可读写），因此本文一律写作 `sudo nft-okboy …`。RHEL 系发行版的 sudo 不搜索 `/usr/local/bin`（`secure_path` 不含它），在那里请使用 root shell，或写完整路径 `/opt/nft-okboy/nft-okboy`。

**nftables 后端怎么拦**。受管端口对白名单以外的来源关闭：TCP 丢弃新连接（已建立的会话不断），UDP 丢弃所有数据报，本机回环不受限；其余端口 nft-okboy 不碰。受管端口在 `serve` 上是各组的端口，在 agent 上是 hub 下发的本节点 target 端口中、同时列在 `agent_allowed_ports` 里的那些。

**放行不是最终结论**。主机上若还有别的防火墙（ufw、firewalld、nftables.conf）拦着受管端口，白名单用户照样进不来。此时要么在那边放开该端口（由 nft-okboy 负责筛选），要么在 ufw 主机上改用 `firewall_backend: ufw`。启动日志会列出检测到的其他防火墙。

**ufw 后端的前提**。ufw 后端只添加放行规则，拦住其余来源靠的是 ufw 自己的默认策略。使用前确认 `sudo ufw status verbose` 显示已启用（`active`）且入站默认拒绝（`deny (incoming)`），受管端口上没有更宽的放行规则（例如对 `Anywhere` 的 `ALLOW`）；启用 ufw 之前先放行自己的管理通道（SSH）。ufw 未启用时 nft-okboy 只在日志里提示，不会替你启用。另外，ufw 对来源、端口、协议完全相同的规则只保留一条：主机上已有这样一条手工规则（无论放行还是拒绝）时，添加受管规则会把它改写成受管的放行规则，之后还可能随授权撤销被删除。不要让手工规则与受管规则重叠。

**DNAT 转发的端口管不到**。Docker（`-p`）或 Kubernetes（NodePort）经 DNAT 转发走的端口不经过 `input` 钩子，nft-okboy 既拦不住也放行不了。不要把这类端口配成组端口或 target 端口（可以在转发路径上限制，例如 Docker 的 `DOCKER-USER` 链）。启动日志发现 nat 链时会提示。

**同一台机器上的 `serve` 与 `agent`**。hub 兼做节点时，两者不能共用同一张表：各自按自己的期望状态对账，会把对方的规则和防护当作多余的删掉。要么 hub 用 `firewall_backend: none`，要么给 agent 单独配置 `nft_table`（ufw 后端则配置不同的 `rule_prefix`）。一键安装脚本安装并启动的正是 `serve`，所以不要在边缘节点上运行它。

---

## 场景一：单机 standalone

适合「这台机器自己保护自己」。一条命令安装：

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/nft-okboy-fleet/master/deploy/install.sh | sudo sh
```

安装脚本下载与架构匹配的静态二进制（以 GitHub 公布的 sha256 校验，拿不到或对不上就中止），写入 `/etc/nft-okboy/config.yaml`，安装并启用 systemd 服务，创建管理员 `admin` 并打印一次性密钥。它读取的环境变量和镜像相关说明见 [README](../README.md#一键安装推荐)。

然后用 nginx 做 TLS 终止（示例见 `deploy/nginx-nft-okboy.conf`，务必设置 `proxy_set_header X-Real-IP $remote_addr`），再建组并授权：

```bash
sudo nft-okboy group-add ssh 22       # 把 22 端口纳管为 "ssh" 组（此后只放行敲过门的 IP）
sudo nft-okboy user-join admin ssh    # 授权 admin 使用该组
```

建 `ssh` 组时保持当前 SSH 会话：敲门后另开一个 SSH 会话确认能登录，再断开原来的会话。浏览器打开 `https://<你的域名>/`，输入用户名和密钥，点击 **Connect**。更多说明见 [README](../README.md)。

---

## 场景二：Fleet（1 个 hub + N 个 agent）

把「谁被允许」（hub，控制面）和「开关防火墙端口」（agent，数据面）分开：部署一个 hub，每台机器只运行一个轻量 agent，不再每台装一整套。客户端只敲 hub 一次，它被授权的所有机器都会放行。一个 hub 可以同时管理 nftables 与 ufw 节点。

```text
  Client ──knock（一次）──► HUB（控制面 · 唯一对外入口 · nginx TLS）
                              │  用户 / 组 / 节点 / target → 每个节点的期望状态
                  agent 定期拉取（出站 HTTPS，节点不监听端口）
             ┌────────────────┼────────────────┐
         ┌───┴───┐        ┌───┴───┐        ┌───┴───┐
         │ agent │        │ agent │        │ agent │
         │  ufw  │        │  nft  │        │  nft  │
         └───────┘        └───────┘        └───────┘
          node-A           node-B           node-C
```

### 1) 部署 hub

下面是手动安装，二进制的获取方式见 [README](../README.md#手动安装)。也可以先用一键安装脚本安装，再把 `/etc/nft-okboy/config.yaml` 改成下面的内容并执行 `sudo systemctl restart nft-okboy`。

```bash
# 二进制、命令链接和 systemd 单元（在仓库根目录执行）
sudo install -Dm755 nft-okboy-linux-amd64 /opt/nft-okboy/nft-okboy
sudo ln -sfn /opt/nft-okboy/nft-okboy /usr/local/bin/nft-okboy
sudo install -Dm644 deploy/nft-okboy.service /etc/systemd/system/nft-okboy.service
# 单元的 ReadWritePaths 要求数据目录在服务启动前已经存在
sudo install -d -m 700 /etc/nft-okboy /var/lib/nft-okboy

# hub 配置
sudo install -m 600 /dev/stdin /etc/nft-okboy/config.yaml <<'YAML'
firewall_backend: none          # 只做控制面；要同时保护 hub 本机，改为 nftables 或 ufw
listen_host: 127.0.0.1          # 由同一台机器上的 nginx 对外提供服务
listen_port: 5000
trusted_proxies: ["127.0.0.1", "::1"]
require_admin_totp: true        # 管理员须先绑定 TOTP，才能经 Web 或 API 执行管理写操作（CLI 不受影响）
db_path: /var/lib/nft-okboy/nft-okboy.db
YAML

sudo systemctl daemon-reload
sudo nft-okboy user-add --admin admin    # 建管理员，打印一次性密钥
sudo systemctl enable --now nft-okboy
# nginx 做 TLS 终止，务必设置 proxy_set_header X-Real-IP $remote_addr：参考 deploy/nginx-nft-okboy.conf
```

> hub 保存着全部用户的密钥和所有节点的授权，是需要重点保护的机器：只开放一个 HTTPS 入口，并开启 `require_admin_totp`。
>
> hub 用 `nftables` 或 `ufw` 后端时，每个组自己的端口也在 hub 本机生效（见下一步），nftables 后端会把它对白名单以外关闭。不要让组端口与 hub 自己对外的端口（nginx 的 443/80、SSH）重合，否则没敲过门的人连 hub 都访问不了，也就无法敲门。只做控制面时用 `none` 最省心。

### 2) 在 hub 上注册节点、配置 target、授权用户

```bash
sudo nft-okboy node-add edge-1                     # 打印节点 token，只显示一次，配给该节点的 agent
sudo nft-okboy group-add web 8080                  # 建组；8080 是该组在 hub 本机的端口
sudo nft-okboy group-target add web edge-1 18080   # web 组在 edge-1 上对应 18080/tcp
sudo nft-okboy user-add alice                      # 建用户，打印只显示一次的密钥
sudo nft-okboy user-join alice web                 # 授权 alice 使用 web 组
```

组与 target 的关系：

- 每个组有自己的端口和协议（`group-add` 的 `--proto`，默认 tcp），同一个端口/协议只能属于一个组。hub 用 `nftables` 或 `ufw` 后端时，这个端口在 hub 本机生效：成员敲门后在 hub 上被放行，nftables 后端还会对其他来源关闭它。hub 用 `none` 时，这个端口在 hub 上不起作用，但仍被该组占用。
- target 把组映射到某个节点上的端口和协议。一个组可以有多个 target（每个节点一个）；对同一组和节点再次执行 `group-target add` 会改成新的端口。
- `sudo nft-okboy group-target list` 列出全部映射，`sudo nft-okboy group-target del web edge-1` 删除映射。
- 配置文件中的 `allowed_ports` 只约束经 HTTP API（包括 Web 管理台）建组，不约束 CLI 的 `group-add` 和 `group-target add`。

### 3) 在每个边缘节点部署 agent

不要在边缘节点上运行一键安装脚本（原因见[通用要点](#通用要点)），按下面的步骤手动安装：

```bash
# 下载与节点架构匹配的二进制并校验
# A 可取 amd64、arm64、armv7、armv6、386、riscv64、ppc64le、s390x、loong64
A=amd64
curl -fsSLO "https://github.com/lvusyy/nft-okboy-fleet/releases/latest/download/nft-okboy-linux-$A"
curl -fsSLO "https://github.com/lvusyy/nft-okboy-fleet/releases/latest/download/SHA256SUMS"
grep " nft-okboy-linux-$A\$" SHA256SUMS | sha256sum -c -
sudo install -Dm755 "nft-okboy-linux-$A" /opt/nft-okboy/nft-okboy
sudo ln -sfn /opt/nft-okboy/nft-okboy /usr/local/bin/nft-okboy
# systemd 单元取自仓库的 deploy/ 目录
sudo install -Dm644 deploy/nft-okboy-agent.service /etc/systemd/system/nft-okboy-agent.service

# agent 配置：只需后端和护栏，不需要数据库
sudo install -Dm644 /dev/stdin /etc/nft-okboy/agent.yaml <<'YAML'
firewall_backend: nftables      # 或 ufw，按节点的防火墙选择（ufw 的前提见下）
agent_allowed_ports: [18080]    # 本节点只放行、也只拦截这些端口（见下文）
YAML

# hub 地址、节点名和 token（0600）。token 经环境变量交给 agent，不写进 unit、不进日志，也不出现在进程参数里
sudo install -Dm600 /dev/stdin /etc/nft-okboy/agent.env <<'ENV'
NFT_OKBOY_HUB=https://hub.example.com/
NFT_OKBOY_NODE=edge-1
NFT_OKBOY_TOKEN=<上一步 node-add 打印的 token>
ENV

sudo systemctl daemon-reload
sudo systemctl enable --now nft-okboy-agent
```

- `NFT_OKBOY_NODE` 只用于日志，节点的身份由 token 决定。
- hub 使用自签证书时，把 hub 的证书（或签发它的 CA）复制到节点，例如 `/etc/nft-okboy/hub.pem`，并给 agent 加上 `--ca /etc/nft-okboy/hub.pem`（用 `sudo systemctl edit --full nft-okboy-agent` 修改 `ExecStart`）。不要用 `--insecure`：它不校验证书，同一网络路径上的任何人都能冒充 hub、偷走节点 token、给节点下发规则。
- agent 只接受 `https://` 的 hub（本机回环地址除外）。hub 位于可信的内网（例如集群内部的 Service）且只能走明文 http 时，需要显式加上 `--allow-http`，或在 `agent.env` 中写入 `NFT_OKBOY_ALLOW_HTTP=1`（不必修改 unit）。

### 4) 客户端敲门

客户端（Web UI、`knock.py` 或 `knock.sh`）指向 hub，认证一次即可。hub 更新该用户的当前 IP，并据此为每个节点重新计算期望状态；各节点的 agent 在下一次拉取时（默认间隔 15 秒）放行新 IP，删除旧 IP 的规则。一次敲门覆盖该用户被授权的所有机器。

### 护栏：`agent_allowed_ports`（强烈建议；nftables 节点必须配置）

agent 在本地过滤 hub 下发的期望状态，**只放行列表中的端口**（按端口号匹配，tcp 和 udp 都算），其余规则丢弃并在日志中告警。这样即使 hub 被攻破，也无法让节点开放 SSH 等未列出的端口。hub 下发的规则还必须是单个 IP、合法的端口和协议，否则同样会被丢弃。

在 nftables 节点上，它同时决定**防护能关闭哪些端口**：hub 为本节点报告的受管端口中，只有列在这里的才会对白名单以外关闭；没有配置时，agent 不关闭任何端口（只放行，什么也拦不住），并在日志中告警。这样被攻破的 hub 也无法让整个集群关掉 SSH。

agent 把最近一次生效的防护记录在 `/var/lib/nft-okboy/agent-guard.json`（可用 `--state` 修改，设为 `""` 关闭）：重启或规则集被清空后，即使暂时连不上 hub，也会先把防护恢复。

```yaml
# agent.yaml
agent_allowed_ports: [18080, 443]
```

也可以在 unit 的 `ExecStart` 中加上 `--allow-ports 18080,443`，它会覆盖配置文件中的值。

### 观测

```bash
sudo nft-okboy node-list
```

各列含义：`Online` 为 `yes` 表示 60 秒内拉取过；`Version`、`Backend` 是 agent 自己上报的版本和后端；`Rules` 是 hub 当前为该节点计算的放行规则数，agent 会丢弃 `agent_allowed_ports` 以外的规则，所以实际生效的可能更少；`Last Seen` 是最后一次拉取的时间。管理员 API `GET /api/admin/nodes` 以 JSON 返回同样的信息。Web 管理台目前不显示节点。

### 撤销节点与更换 token

- `sudo nft-okboy node-del edge-1` 删除节点及其 target。该节点的 agent 下一次拉取会收到 401：它删除全部放行规则、保留防护，受管端口随之关闭；之后它继续按间隔重试，直到被停止。
- 节点 token 不会过期，也没有单独的更换命令。更换方法：`node-del` 后用同名重新 `node-add`，重新添加该节点的 target（删除节点时已一并删除），把新 token 写进节点的 `/etc/nft-okboy/agent.env`，再执行 `sudo systemctl restart nft-okboy-agent`。

### agent 升级

amd64、arm64、386、riscv64、ppc64le、s390x、loong64 节点可以启用每日自升级：

```bash
sudo install -Dm644 deploy/nft-okboy-agent-upgrade.service /etc/systemd/system/nft-okboy-agent-upgrade.service
sudo install -Dm644 deploy/nft-okboy-agent-upgrade.timer   /etc/systemd/system/nft-okboy-agent-upgrade.timer
sudo systemctl daemon-reload
sudo systemctl enable --now nft-okboy-agent-upgrade.timer
```

timer 每天运行一次（随机延迟最多 1 小时），执行 `nft-okboy upgrade --no-backup --service nft-okboy-agent`：有新版本时下载、按 GitHub 公布的校验和校验、替换二进制并重启 agent，agent 没能正常运行就换回旧二进制。手动执行这条命令效果相同。

armv6/armv7 节点上 `upgrade` 不可用，不要启用这个 timer。升级时按第 3 步下载并校验新版本的二进制，用它覆盖 `/opt/nft-okboy/nft-okboy`，再执行 `sudo systemctl restart nft-okboy-agent`。

---

## 场景三：Kubernetes

1 个 hub Pod，加上每个受保护节点一个使用主机网络（`hostNetwork: true`）的 agent Pod。agent 只能改动它所在网络命名空间里的 nftables：不用主机网络的 Pod 只保护它自己。

### 推荐：自带 nftables 的镜像

`Dockerfile`：

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY nft-okboy-linux-amd64 /usr/local/bin/nft-okboy
ENTRYPOINT ["/usr/local/bin/nft-okboy"]
```

hub（`ConfigMap` + `Deployment` + `Service`）：

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: nft-okboy-hub-config, namespace: nft-okboy }
data:
  config.yaml: |
    firewall_backend: none            # 只做控制面
    listen_host: 0.0.0.0              # 默认的 127.0.0.1 从 Pod 外访问不到
    listen_port: 5000
    trusted_proxies: ["192.0.2.10"]   # Ingress 或反向代理连接 hub 时的源地址，逐个写完整 IP
    db_path: /var/lib/nft-okboy/nft-okboy.db
---
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
        configMap: { name: nft-okboy-hub-config }
      - { name: data, emptyDir: {} }              # 生产环境用 PVC 持久化 SQLite
---
apiVersion: v1
kind: Service
metadata: { name: nft-okboy-hub, namespace: nft-okboy }
spec:
  selector: { app: nft-okboy-hub }
  ports: [{ port: 5000, targetPort: 5000 }]
```

- `listen_host` 必须是从 Pod 外可达的地址（`0.0.0.0` 或 Pod 的地址），否则 Service 的流量进不来。
- hub 按 HTTP 连接的对端地址识别客户端：对端不在 `trusted_proxies` 中时，登记的就是对端地址本身。客户端经 Ingress 或反向代理访问时，对端是代理，所以要把代理连接 hub 时使用的源地址写进 `trusted_proxies`，并让代理设置 `X-Real-IP`（或追加 `X-Forwarded-For`）。`trusted_proxies` 按完整 IP 精确匹配、不支持网段，代理的 Pod 地址变化后要同步更新。
- agent 的拉取只凭 token 认证，不受 `trusted_proxies` 影响，集群内可以直接访问 Service。

agent（每个受保护节点一个，用 `nodeSelector` 固定到该节点，并各用自己的节点 token；`hostNetwork: true` 让它改动的是节点本身的防火墙，为此需要 `NET_ADMIN`）：

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: nft-okboy-agent-config, namespace: nft-okboy }
data:
  agent.yaml: |
    firewall_backend: nftables
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: nft-okboy-agent-edge1, namespace: nft-okboy }
spec:
  replicas: 1
  selector: { matchLabels: { app: nft-okboy-agent, node: edge1 } }
  template:
    metadata: { labels: { app: nft-okboy-agent, node: edge1 } }
    spec:
      hostNetwork: true                            # 规则作用于节点本身，而不是这个 Pod
      dnsPolicy: ClusterFirstWithHostNet           # 主机网络下仍能解析集群内的 Service 名
      nodeSelector: { kubernetes.io/hostname: edge1 }
      containers:
      - name: agent
        image: registry.example.com/nft-okboy:latest
        # token 由下面的 NFT_OKBOY_TOKEN 环境变量提供，不放进 args（args 在节点上用 ps 可以看到）；
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
        configMap: { name: nft-okboy-agent-config }
```

- 受保护的是节点上直接监听的端口（`hostNetwork` 的 Pod、节点上的服务）。经 kube-proxy 的 NodePort、LoadBalancer 转发的流量走 DNAT，不经过 `input` 钩子，nft-okboy 管不到。
- 只想保护某个 Pod 自己监听的端口时，把 agent 作为 sidecar 放进那个 Pod（同一个网络命名空间），不需要 `hostNetwork`。
- 防护状态文件默认在容器里，Pod 重建后丢失；agent 会在第一次拉取成功后恢复防护。需要重启后立即恢复时，把节点上的一个目录（hostPath）挂到 `/var/lib/nft-okboy`。

建管理员（`user-add --admin`）、注册节点和配置 target 都在 hub 容器里执行，token 保存在 Secret 中：

```bash
kubectl -n nft-okboy exec deploy/nft-okboy-hub -- nft-okboy -c /etc/nft-okboy/config.yaml node-add edge1
read -rsp 'node token: ' T && printf '%s' "$T" \
  | kubectl -n nft-okboy create secret generic nft-okboy-edge1-token --from-file=token=/dev/stdin; unset T
```

### 离线集群

nft-okboy 是静态二进制，可以放进任意基础镜像。hub（`firewall_backend: none`）不需要其他文件；agent 还需要容器里有可用的 `nft`（nftables 后端）或 `ufw`（ufw 后端）。拉不到镜像的集群，也可以用 hostPath 把二进制挂进使用现有镜像的容器。

---

## 从 Python ufw-okboy 迁移

Go 版沿用 Python 版 ufw-okboy 的数据库表（用户、组、成员、审计和日志），可以直接打开现有数据库，首次打开时补建 fleet 用的 `nodes` 和 `group_targets` 表。

- **先把 Python 版升级到 v2.2.2 或更高**：该版本的数据库迁移会作废早期安装脚本建出的示例用户 `alice` 的公开密钥，Go 版不做这一步。
- **接管后不能再交回 Python 版**：两边的数据库迁移编号含义不同（Python 版的 v5、v6 是作废示例密钥和 TOTP 待确认列，Go 版的 v5、v6 是 fleet 的节点表），Python 版打开 Go 版用过的数据库时会跳过自己的这两项迁移。要回到 Python 版，请恢复迁移前的备份。

1. 安装 nft-okboy（一键安装脚本或手动安装）。一键安装脚本会立即以默认配置启动服务，并在 `/var/lib/nft-okboy` 新建一个只有 `admin` 的数据库；改用现有数据库后，这个新库和它打印的 `admin` 密钥都不再使用，继续使用 Python 版中的账号即可。
2. 停用 Python 服务、备份数据库、修改配置，然后重启 nft-okboy：

```bash
sudo /opt/ufw-okboy/venv/bin/python /opt/ufw-okboy/server/app.py -c /opt/ufw-okboy/server/config.yaml backup   # 带校验和的一致性备份
sudo systemctl disable --now ufw-okboy ufw-okboy-cleanup.timer
# 编辑 /etc/nft-okboy/config.yaml：
#   firewall_backend: ufw
#   rule_prefix: ufw-okboy                        # 与 Python 版的规则注释前缀一致（Python 版默认 ufw-okboy）
#   db_path: /var/lib/ufw-okboy/ufw-okboy.db      # 直接使用现有数据库
sudo systemctl restart nft-okboy
```

- Python 版的清理定时器 `ufw-okboy-cleanup.timer` 随服务一起停用：nft-okboy 自己按 `cleanup_max_age_days` 每小时清理。
- 现有的 ufw 规则按注释前缀识别并接管。服务每 30 秒按数据库对齐一次，数据库中没有对应授权的受管规则会被删除；超过 `cleanup_max_age_days`（默认 7）天没敲门的用户会被移出白名单。

---

## 升级与回滚

- standalone 和 hub：`sudo nft-okboy upgrade`，流程和数据库恢复步骤见 [README](../README.md#升级)；armv6/armv7 上重新运行一键安装脚本。
- agent：见上文「agent 升级」。
- `upgrade` 默认先备份数据库，但备份失败只打印警告、继续升级；要确保有可用的备份，先手动执行 `sudo nft-okboy backup` 并确认成功。
- 自动换回旧二进制只在两种情况下发生：新二进制运行 `--version` 失败，或服务重启后没能进入运行状态。`systemctl restart` 本身失败（例如服务不由 systemd 管理）时只打印警告，不回滚。回滚也只换回二进制，新版本对数据库做的迁移不会撤销，需要时从备份手动恢复。
- `upgrade` 和重新运行安装脚本都不会更新已安装的 systemd 单元。新版本的单元有变化时（见 [CHANGELOG](../CHANGELOG.md)），从 `deploy/` 重新安装并执行 `sudo systemctl daemon-reload`。

### 从 v0.3.x 升级

旧版 nftables 后端只加放行规则，实际什么也拦不住（受管端口对所有人开放，或被主机防火墙全部挡住）。升级后，受管端口立即对白名单以外的来源关闭。升级前先确认你依赖的访问（例如 SSH 所在的组端口）已经敲过门；已建立的会话不受影响。确实需要旧行为时设置 `nft_guard: false`。

nftables 节点上的 agent 只对 `agent_allowed_ports` 中列出的端口加防护；非回环地址的明文 http hub 需要 `--allow-http`（或 `NFT_OKBOY_ALLOW_HTTP=1`）。完整说明见 [CHANGELOG](../CHANGELOG.md)。

---

## 验证部署

```bash
sudo nft-okboy node-list      # 在 hub 上：各节点应在线，版本、后端和规则数符合预期
```

在节点上直接查看防火墙：nftables 节点用 `sudo nft list table inet nft_okboy`（放行规则在链首，防护规则在链尾），ufw 节点用 `sudo ufw status`。不要在 agent 节点上运行 `nft-okboy list` 等管理命令，它们会在本机新建一个空的数据库文件。

端到端自检在网络命名空间里运行，不影响宿主机的防火墙。需要 root，以及 `unshare`、`ufw`、`nft`、`curl`、`openssl`；不需要 Go，把在别处构建好的二进制复制过来即可：

```bash
sudo BIN=/path/to/nft-okboy AGENT_BACKEND=nftables bash scripts/e2e-fleet.sh
sudo BIN=/path/to/nft-okboy AGENT_BACKEND=ufw      bash scripts/e2e-fleet.sh
sudo BIN=/path/to/nft-okboy bash scripts/e2e-nft-traffic.sh    # 另需 iproute2、python3
```

`scripts/e2e-fleet.sh` 在 mount + net 命名空间和私有的 `/etc/ufw` 里跑通 hub → agent → 真实防火墙：规则下发、IP 变更、退组后移除、护栏拒绝白名单外的端口、hub 不可达时保留规则。`scripts/e2e-nft-traffic.sh` 在两个网络命名空间之间做真实连接测试，覆盖 standalone 和 hub + agent 两种部署。CI 在每次向 `main`/`master` 推送或发起 PR 时运行这些脚本，另外还运行单元测试以及真实 nftables、ufw 的集成测试。
