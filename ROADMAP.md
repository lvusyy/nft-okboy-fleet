# 路线图

nft-okboy-fleet 把 [UFW-OkBoy](https://github.com/lvusyy/UFW-OkBoy) 的单机模型扩展为「一个中心控制面 + 多个轻量边缘 agent」。本文说明设计思路、已经实现的能力和计划中的工作；各版本的具体变更见 [CHANGELOG](CHANGELOG.md)，部署方法见[部署指引](docs/DEPLOYMENT.md)。

## 为什么需要 fleet 模式

UFW-OkBoy 和 standalone 模式的 nft-okboy 都是单机自治：每台受保护的机器各跑一套 nginx + API + 防火墙 + SQLite，并以 root 运行。N 台机器就是 N 套部署、N 个对外开放的 root 管理服务，攻击面和运维工作量都随机器数增长。

fleet 模式把「谁被允许访问」（控制面）和「开关防火墙端口」（数据面）拆开：控制面集中在一个 hub，数据面由各机器上的 agent 执行。先按用户和组算出期望规则、再把防火墙调整到与之一致的对账逻辑，本来就不关心规则从哪里来；agent 只是把规则的来源从本地数据库换成了 hub。

## 架构

```text
                     ┌─────────────────────────────────────────┐
  Client ──knock──►  │  HUB（控制面 · 唯一对外入口）             │
  （只敲一次）        │  用户 / 组 / 成员 / 鉴权 / TOTP           │
                     │  节点注册 + 每个节点的期望状态            │
                     │  Web 管理台 / 统一审计                    │
                     └──▲───────────────▲───────────────▲───────┘
                        │ 出站 HTTPS     │ 出站 HTTPS     │ 出站 HTTPS   ← agent 主动拉取
                   ┌────┴─────┐    ┌────┴─────┐    ┌────┴─────┐
                   │  agent   │    │  agent   │    │  agent   │
                   │ ufw 后端 │    │ nft 后端 │    │ ufw 后端 │
                   └──────────┘    └──────────┘    └──────────┘
             （节点：不监听端口，无数据库，只保存最近一次生效的防护）
```

- **hub** 是 `nft-okboy serve`：保存用户、组、成员、节点和 target（组到节点端口的映射），为每个节点计算期望状态，也是 Web 管理台和审计的唯一入口。
- **agent** 是 `nft-okboy agent`：定期拉取本节点的期望状态，对账本机防火墙。
- **敲门**：客户端只敲 hub，hub 更新该用户的当前 IP；每个授权节点在下一次拉取时放行新 IP。一次敲门覆盖所有授权机器。

## 设计原则

1. **向后兼容**：standalone 模式的行为不因 fleet 功能而改变；hub 就是多了节点数据的 standalone 服务。
2. **故障安全**：拉取失败时 agent 保持现有规则，既不清空，也不擅自放开；hub 明确拒绝节点 token（401）时，agent 撤掉全部放行规则、保留防护。
3. **纵深防御**：agent 本地的 `agent_allowed_ports` 决定它能放行和拦截哪些端口，被攻破的 hub 改变不了这个范围；hub 下发的规则只能是单个 IP。
4. **本地状态最少**：受管规则靠注释前缀自我描述；agent 没有数据库，只保存最近一次生效的防护，以便重启或规则集被清空后立即恢复。

## 已实现

| 能力 | 说明 |
|------|------|
| standalone 模式 | `serve`：nftables（带防护）或 ufw 后端；Web 管理台、CLI、HTTP API；管理员 TOTP；审计；在线备份 |
| 可插拔后端 | `nftables`、`ufw`，以及只做控制面的 `none`；一个 hub 可以同时管理 nftables 与 ufw 节点；ufw 后端不改写主机自己的规则 |
| hub 控制面 | 节点注册（`node-add`、`node-list`、`node-del`），组到节点端口的映射（`group-target`），按节点计算期望状态（`GET /api/v1/node/desired-state`） |
| 节点认证 | 每个节点一个长期有效的 bearer token，hub 只保存其 SHA-256；删除节点即撤销 |
| agent 拉取 | 出站 HTTPS，按固定间隔（默认 15 秒）全量拉取；可用 `--ca` 固定 hub 证书；不跟随重定向；非回环地址的明文 http 须显式允许 |
| 本地护栏 | `agent_allowed_ports` / `--allow-ports`；丢弃不是单个 IP、端口或协议不合法的规则 |
| 防护持久化 | 防护状态文件（`--state`）：重启或规则集被清空后，在向 hub 拉取之前先恢复防护 |
| 自愈与过期 | `serve` 每 30 秒按数据库校正本机防火墙；超过 `cleanup_max_age_days` 天没敲门的用户被移出白名单，并经期望状态同步到各节点 |
| fleet 观测 | `node-list` 和 `GET /api/admin/nodes`：在线状态、agent 版本与后端、期望规则数 |
| agent 自升级 | `nft-okboy-agent-upgrade.timer` 每天运行 `upgrade --no-backup --service nft-okboy-agent`（armv6/armv7 除外） |
| 从 Python 版迁移 | 直接使用 ufw-okboy 的数据库和 ufw 规则前缀；单向迁移，见[部署指引](docs/DEPLOYMENT.md#从-python-ufw-okboy-迁移) |
| 测试 | 单元测试；真实 nftables 与 ufw 的集成测试；hub + agent 双后端的端到端测试和真实流量测试，都在 CI 中运行 |

## 计划中

以下工作尚未实现，排列顺序不代表优先级：

- **期望状态签名**：hub 签名、agent 验签，使 agent 不只依靠 TLS 确认 hub。
- **节点双向 TLS（mTLS）**：用短期有效的一次性入网凭据换发节点证书，替代长期有效的 bearer token。
- **在 Web 管理台和 HTTP API 中管理节点与 target**，并在 Web 管理台显示 fleet 视图。目前只能用 CLI 管理，API 只有只读的节点列表。
- **更快的下发**：用长轮询等方式替代固定间隔的全量拉取。
- **`restore` 命令**：从 `backup` 生成的快照恢复数据库。目前需要停服务后手动替换数据库文件。
- **armv6/armv7 自升级**：`upgrade` 目前无法区分这两种 32 位 ARM，只能重新运行安装脚本或手动替换二进制。
- **hub 高可用（可选）**：多实例 hub 加外置数据库，只在规模或可用性要求需要时考虑。
