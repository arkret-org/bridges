# arkret-applets

arkret 协议的桥接(bridge)applet 集合,与 `palpo-im` 的 `matrix-bridge-*` 一一对应,
把 **arkret 去中心化协作协议** 与各第三方 chat app 互联。Rust 实现,技术栈 salvo + diesel,
协议侧基于 [`arkret-rust-sdk`](../arkret-rust-sdk)。

## 结构

Cargo workspace,所有 crate 位于 `crates/`(文件夹名去掉 `arkret-bridge-` 前缀,
包名仍为 `arkret-bridge-*`)。例:`crates/discord/` ⇒ 包 `arkret-bridge-discord`。

共享层拆为两个 crate(均在 `crates/` 下,目录名与包名不同):

- `crates/runtime/` ⇒ 包 **`arkret-bridge-runtime`**:与聊天无关的**通用桥运行时**——arkret 接入
  (`CokretEdge`/`BridgeAppletHandler`)、DB 连接池、salvo web、队列/缓存、配置/日志,契约是
  泛型 trait `BridgeApp`(收发裸 `arkret::Event`)。非聊天集成(IoT/工单/CI)可直接实现它。
- `crates/messaging/` ⇒ 包 **`arkret-bridge-messaging`**:在 runtime 之上的**消息层**——频道/
  用户/消息映射表、`ck.message.create` 转换、actor/realm 反查解析、webhook 助手,契约是
  `MessageBridge`/`MessageContext`(14 个聊天桥都实现它,经 `run_message_bridge` 装配)。

共享层术语对照:

| 目录 | 包名 | 当前职责 | 历史/旧称 |
|---|---|---|---|
| `crates/runtime` | `arkret-bridge-runtime` | 通用桥运行时 | core/runtime |
| `crates/messaging` | `arkret-bridge-messaging` | 聊天消息契约层 | messaging |

| crate(包名) | 对端 app | 应用侧技术 | 端口 |
|---|---|---|---|
| `arkret-bridge-runtime`(`crates/runtime`) | — | 通用桥运行时(arkret 接入/DB/web/队列) | — |
| `arkret-bridge-messaging`(`crates/messaging`) | — | 消息层(映射/`ck.message.create`/webhook 助手) | — |
| `arkret-bridge-discord` | Discord | serenity gateway | 9101 |
| `arkret-bridge-telegram` | Telegram | teloxide | 9102 |
| `arkret-bridge-slack` | Slack | tungstenite socket mode | 9103 |
| `arkret-bridge-feishu` | 飞书 | reqwest | 9104 |
| `arkret-bridge-wechat` | 微信 | reqwest | 9105 |
| `arkret-bridge-dingtalk` | 钉钉 | reqwest | 9106 |
| `arkret-bridge-zulip` | Zulip | reqwest event queue long-polling | 9107 |
| `arkret-bridge-whatsapp` | WhatsApp | reqwest (Cloud API) | 9108 |
| `arkret-bridge-line` | LINE | reqwest | 9109 |
| `arkret-bridge-qq` | QQ | reqwest (OneBot/官方) | 9110 |
| `arkret-bridge-googlechat` | Google Chat | reqwest | 9111 |
| `arkret-bridge-imessage` | iMessage | reqwest (网关) | 9112 |
| `arkret-bridge-messenger` | Messenger | reqwest (Graph API) | 9113 |
| `arkret-bridge-teams` | MS Teams | reqwest (Bot Framework) | 9114 |

## 架构

每个桥都是一个 arkret **Applet**:

- **入站(arkret → app)**:arkret server 经 `POST /_cokret/edge/applet/transactions`
  推送事件 → runtime `BridgeAppletHandler` 入队 → `consume_inbound` 消费循环 →
  `MessageBridge::on_cokret_event` → 适配器 `send_to_app`。
- **出站(app → arkret)**:适配器收到 app 消息(gateway/长轮询/webhook)→
  `MessageContext::submit_app_message` → runtime 构造并签名带 `external_ref` 溯源的
  per-user Ghost Actor `ck.message.create` 事件 → `events_submit` 提交。Ghost DID 按
  `protocol/tenant/external_user_id` 生成并写入 `user_mappings`;proof 使用该 Ghost DID 的
  configured key fragment,避免写侧退回 bridge service actor。纯 HTTP 桥的入站经各自
  `MessageBridge::webhook_router` 挂到 web 服务,平台来源验签在 handler 解析 JSON 前完成。
  部分桥(WeChat / Feishu / DingTalk / iMessage / QQ / LINE 等)的入站还需要 body-bound
  验签材料(EncodingAESKey / Encrypt Key / 注入式 HMAC secret / signing secret);缺失时入站面
  **fail-closed**:WeChat 整类 POST 投递被拒(仅 GET 握手可用),Feishu 直接不挂载 webhook 路由,
  且声明 webhook 入站面的桥若 `webhook_router` 因此返回 `None` 会在**启动期 fail-fast**(不会降级为
  无入站面的“健康”进程)。配齐 access token 不等于入站可用,还须配齐这些 body 验签材料。
- **映射 / 解析**:频道↔realm、消息↔event、用户↔actor 持久化于 diesel(sqlite/postgres/mysql);
  反查驱动 applet `resolve_actor`/`resolve_realm`(ghost/portal 读侧解析)。用户↔actor 映射
  同时参与 app→arkret 写侧署名。
- **序号**:服务 actor 的事件 seq 经 DB 块预留持久化,重启后严格单调。
- **消息内容**:对齐 SDK 规范类型 `TextMessageContent`(`{body}`)/`MediaContent`
  (`{body,blob,mimetype,filename,size}`)。
- **媒体**:`MessageContext::{upload_blob,download_blob,submit_media_message}` + `Attachment`;
  discord/telegram 收发双向、whatsapp/line 入站已接,余者文本(通用能力就绪)。
- **防回声**:`on_cokret_event` 跳过本桥 `external_ref.source` 自发事件、由本桥
  service actor 署名的事件,以及已在消息映射表记录的 event,避免出站回环。

详见 [`_BRIDGE_CONTRACT.md`](_BRIDGE_CONTRACT.md)(适配器编写契约)。

## 构建

```bash
cargo check --workspace
cargo run -p arkret-bridge-discord -- --config config.yaml
```

每个 crate 默认 `sqlite` feature;`--features postgres` / `--features mysql` 切换后端。
配置文件使用 YAML。
所有桥都必须显式建立 app channel 到 Realm 的映射；没有 channel-realm mapping 的入站消息会直接失败,
不再回退到默认 Realm。
推荐在配置文件的 `mappings` 段声明静态映射；各桥 `config.sample.yaml` 均包含注释样例,启动时会自动 upsert。

三个信任面绑在**两个独立监听**上,默认即隔离,不再仅靠反代 path 规则:

- **公网 webhook 面**(`/webhooks/*`,Teams 另含 Bot Framework 的 `/api/messages`):
  绑 `webhook_bind:port`,默认 `webhook_bind=0.0.0.0`,必须可被对应平台回调可达。
- **内网 admin/edge 面**(受信协议面 `/_cokret/edge/applet/*` 与运维面 `/health`、
  `/metrics`):绑 `admin_bind:admin_port`,默认 `admin_bind=127.0.0.1`(仅回环),
  `admin_port` 省略时回落到 `port + 1000`。即使不配反向代理,协议面与运维面也默认不对
  公网开放。

`/_cokret/edge/applet/*` 配置 `trusted_server_did` 与 `trusted_verification_methods` 后会
校验 HTTP Message Signature、source/destination DID 与 event proof;生产仍建议在反代/网络层
进一步限制为仅可信 Arkret server 访问,并对 `/metrics` 做内网或认证访问控制。若需把 admin/edge
面也对外(如 arkret server 在另一网段),显式设置 `admin_bind` 即可,但应自行收敛网络层暴露面。

公网 webhook 面**默认启用每源 IP 速率限制**(`bridge.webhook_rate_limit`,默认
`enabled: true`、`max_requests: 600`、`window_secs: 60`,即每 IP 持续 10 rps),用于无反代
裸跑时的基本抗泛洪;阈值刻意宽松,正常单租户回调远达不到。注意:部分平台的**重投风暴**
(如 Meta 对 5xx 的批量重投)可能从少量回调 IP 集中打来,若观察到被限,应按平台回调 IP 段
放宽 `max_requests` 或置 `enabled: false` 改由反代限流。

**重放守卫与 vendor token 缓存均持久化于桥数据库**(`webhook_replay_guard` / `token_cache`
表):重启后 TTL 内的捕获报文无法重放,且同一桥的多副本共享同一守卫与同一 vendor access token
(WeChat 类"取新令旧失效"平台在多副本下因此可用)。水平扩展多副本时,各副本必须指向同一
`database.url`(共享 postgres/mysql;sqlite 仅适合单副本)。

## 容器发布

仓库提供一个统一的多阶段 `Dockerfile`,通过 `BRIDGE_BIN` 选择要打包的桥二进制。由于 workspace
依赖 sibling `arkret-rust-sdk`,Docker build context 必须是同时包含 `bridges/` 与
`arkret-rust-sdk/` 的父目录:

```bash
docker build -f bridges/Dockerfile \
  --build-arg BRIDGE_BIN=arkret-bridge-slack \
  -t arkret-bridge-slack:local .
```

tag 推送会触发 `.github/workflows/release.yml`,矩阵构建 14 个桥镜像并推送到 GHCR,同时生成
CycloneDX SBOM;tag 发布的镜像会通过 keyless cosign 签名。
