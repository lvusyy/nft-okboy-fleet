# nft-okboy-fleet — Roadmap & Architecture

> 多机（fleet）场景下的 OkBoy：从「单机自治」演进为「中心控制面 + 轻量边缘 Agent」。
> 本项目以 [nft-okboy](../nft-okboy) 的 Go 代码为种子（seed），原样复用其
> `FirewallBackend` / `reconcile` / HMAC+TOTP 认证 / SQLite+migration 等原语。

## 为什么有这个项目

`ufw-okboy` / `nft-okboy` 是**单机自治**工具：每台被保护机器跑一整套
`nginx + API + 防火墙 + SQLite`（root）。N 台 = N 套部署 = N 个面向公网的
root 管理服务 = N 个攻击面 + N 倍运维。

把**「谁被允许」（控制面）**和**「开防火墙口子」（数据面）**拆开，三重压力一起解决。
关键复用洞察：`reconcile_user_rules(user, ip, enabled_groups)` 已经把「期望状态」与
「防火墙执行」解耦——中心化只是把期望状态的来源从本地 SQLite 换成 hub。

## 锁定的决策

| 项 | 取值 |
|---|---|
| 主干代码基 | **Go**（种子自 nft-okboy）；ufw-okboy(Python) 在 C1 功能等价后冻结为 legacy |
| 队列规模 | **10–100 台，云 + 本地/NAT 混合** |
| 形态 | **一个二进制 `nft-okboy`，三模式 `standalone\|hub\|agent`**，config 驱动 |
| 后端 | **可插拔 `firewall.Backend`：nftables / ufw**（一个 hub 管异构队列） |

## 架构

```
                     ┌───────────────────────────────────────┐
  Client ──knock──►  │  HUB（控制面 · 唯一公网入口）           │
  （只敲一次）        │  users/groups/membership/auth/TOTP     │
                     │  node 注册 + 每节点「期望状态」计算      │
                     │  Web 管理台 / 统一审计                  │
                     └──▲──────────────▲──────────────▲───────┘
                        │ 出站 HTTPS    │ 出站 HTTPS    │   ← agent 主动拨出
                   ┌────┴────┐    ┌─────┴───┐    ┌──────┴──┐
                   │  agent  │    │  agent  │    │  agent  │
                   │ ufw后端 │    │ nft后端 │    │ ufw后端 │
                   └─────────┘    └─────────┘    └─────────┘
              （节点：无 nginx / 无证书 / 无 DB / 不监听任何公网端口）
```

- **控制面 = hub** = 现 server/db/auth 去掉本地防火墙调用 + node 注册 + 每节点期望状态 API。
- **数据面 = agent** = 现 `firewall` reconcile，期望状态改从 hub 拉。**无状态、无 DB**。
- **knock**：client 敲 hub 一次 → hub 算出该用户授权的 `(node, port)` → 写各节点期望状态 → agent 下次拉取开口。**一次 knock 覆盖全队列**。

## 贯穿性原则

1. **向后兼容神圣不可侵犯**：`standalone` 模式行为永不改变；hub/agent 是新增拓扑，不是替换。
2. **Agent 无状态**：managed 规则由防火墙里 `nft-okboy:user:group` 前缀自描述，拉到期望集做幂等 diff。
3. **故障安全**：hub 不可达时 agent 保留 last-known-good，**绝不 panic 关、绝不擅自开**。
4. **纵深防御**：agent 本地 `max_ports` 白名单，即便 hub 被攻破也开不了 SSH。

## 关键技术规格

| 项 | 选型 | 理由 |
|---|---|---|
| 传输 | agent→hub **HTTPS 长轮询** + 30s 周期全量兜底 | 出站、穿 NAT/代理、秒级实时；比 WebSocket 简单 |
| 节点身份 | 一次性 enrollment token（短 TTL）→ 换发 **per-node mTLS** | token 失窃窗口小，之后双向认证 |
| 期望状态 | hub **签名**下发，agent 验签 | 防 hub-MITM / 篡改 |
| 数据模型 | 新增 `nodes`；group target：本地端口 → `(node, port, proto)` | 其余表不动 |

## 里程碑

| # | 目标 | 收敛标准（可验证） | 依赖 |
|---|---|---|---|
| **C1** | 防火墙后端统一：新增 `firewall` 的 ufw 后端 | ufw 后端通过与 nft 等价的测试套件；一台 ufw-okboy(Python) 机器可用本二进制原地替换、状态无损 | — |
| **C2** | Hub 控制面：node 注册 / 期望状态 API | curl 经 mTLS 拉某节点期望状态内容正确；管理台能注册 node + 绑定 `(node,port)` target | C1 |
| **C3** | Edge Agent：出站 pull + reconcile + 故障安全 | 2 台机（1 ufw+1 nft），改 target 后 N 秒内正确开/关；断 hub 后规则不变 | C1, C2 |
| **C4** | knock fan-out + 客户端迁移 | 一个用户 knock 一次，授权的多节点端口 N 秒内全放行；审计集中 | C2, C3 |
| **C5** | 运维加固：fleet 仪表盘 / agent 自升级 / 签名 / max_ports | 自升级演练通过；篡改期望状态被拒；hub 故障恢复演练通过 | C3, C4 |
| **C6** | （可选）Hub 高可用 | 双实例 hub + DB 外置；仅当规模/可用性要求升级时启动 | C2 |

> **C2+C3 = 最小可用闭环。C1 可独立先交付（即合并 ufw-okboy 与 nft-okboy）。**

## 目录演进

```
cmd/nft-okboy/              统一入口（已有；加 --mode 分发）
internal/firewall/      backend.go(已有) + nft.go(已有) + mock.go(已有) + ufw.go(C1 新增)
internal/auth/          HMAC+TOTP（已有）+ node mTLS（C2 新增）
internal/db/            + nodes / group_targets（C2 新增）
internal/server/        现有 API（已有）+ node 期望状态 API（C2 新增）
internal/hub/           控制面（C2）
internal/agent/         边缘 enforcer（C3）
internal/static/        Web UI（已有）+ fleet 视图（C2/C5）
```

## 交付状态（2026-06-30）

C1–C4 **已完成并实体验证**，项目可交付：

| 里程碑 | 状态 | 验证 |
|---|---|---|
| C1 ufw 后端 | ✅ | 单元 5/5 + 真实 ufw 0.36 集成测试（netns 沙箱） |
| C2 Hub（nodes/group_targets/期望状态 API/CLI） | ✅ | `DesiredStateForNode` 单元测试；DB schema 兼容 Python |
| C3 Edge Agent（出站拉取/整节点 reconcile/故障安全） | ✅ | `Reconcile` 单元测试（MockBackend） |
| C4 fan-out（自动）+ `none` 纯 hub 后端 | ✅ | — |
| **端到端** | ✅ | `scripts/e2e-fleet.sh`：hub→agent→真实 **ufw 与 nftables** 双后端，应用/IP变更/移除/故障安全全过，host 零影响 |

剩余（C5 强化，非交付阻塞）：fleet 仪表盘、agent 自升级、期望状态签名、节点 `max_ports` 白名单。

## 部署 fleet

- **Hub**（控制面）：`nft-okboy -c hub.yaml serve`，`firewall_backend: none`（纯控制面）或 `nftables`（兼自保护）；前置 nginx TLS（复用 `deploy/`）。
- **Agent**（每边缘节点）：`deploy/nft-okboy-agent.service` + `/etc/nft-okboy/agent.env`（`NFT_OKBOY_HUB`/`NFT_OKBOY_NODE`/`NFT_OKBOY_TOKEN`）+ `agent.yaml`（`firewall_backend: ufw|nftables`）。节点**只出站、无 DB、不监听公网**。

```bash
# Hub 端：注册节点 + 配置目标 + 授权用户
nft-okboy -c hub.yaml node-add edge-1            # 打印一次性 token
nft-okboy -c hub.yaml group-add web 8080
nft-okboy -c hub.yaml group-target add web edge-1 18080
nft-okboy -c hub.yaml user-join alice web
# Edge 端：token 写入 /etc/nft-okboy/agent.env，起 agent
systemctl enable --now nft-okboy-agent
```
