# arkret-bridge-slack

Rust 实现的 **arkret ⇄ Slack** 桥接。基于共享核心 [`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),
应用侧使用 Slack **Socket Mode**(WebSocket,[`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite))
接收事件,使用 **Web API**(`ctx.http` / reqwest)发送消息。

## 架构

- **入站(Slack → arkret)**:先 POST `apps.connections.open` 用 `app_token`(`xapp-`)
  换取一次性 wss URL → 连接 socket mode → 读循环解析 `message` 事件 →
  `MessageContext::submit_app_message` → 核心签名 `ak.message.create` 提交 arkret。
  socket mode 要求对每个带 `envelope_id` 的 envelope 回 ack。
- **出站(arkret → Slack)**:arkret server 经 applet 端点
  `POST /_arkret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST `https://slack.com/api/chat.postMessage`(`bot_token` `xoxb-`)。
- **映射**:channel↔realm、消息(ts)↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与 app.bot_token / app.app_token
cargo run -p arkret-bridge-slack -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.bot_token`:Slack Bot User OAuth Token(`xoxb-...`),供 Web API 鉴权。
- `app.app_token`:Slack App-Level Token(`xapp-...`),供 Socket Mode 建连。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 说明

- 需在 Slack 应用后台开启 Socket Mode,并订阅 `message.channels` 等事件。
- 入站只转发普通文本消息;含 `subtype` 或 `bot_id` 的消息(编辑、bot 回声等)被忽略以防回环。

### 信任边界(Socket Mode 不逐 envelope 验签)

与 webhook 桥(Feishu/WeChat/LINE 等逐请求做 HMAC/签名校验)不同,Slack Socket Mode
**不对每条 envelope 单独签名**,这是平台设计:每个入站 envelope 的真实性来自这条持久
WebSocket 连接本身——

- 连接由 `app_token`(`xapp-`,机密)经 `apps.connections.open` 换取一次性 wss URL 建立;
  握手即对端点鉴权,只有持有有效 `app_token` 才能拿到连接。
- 链路由 **TLS**(`wss://`)保护,提供机密性与完整性,第三方无法注入或篡改 envelope。

因此该桥的入站信任根是 **`app_token` + TLS 通道**,而非逐 envelope 的应用层签名。
请将 `app_token`/`bot_token` 当作机密妥善保管(勿入库、勿落日志);出站错误信息已经过
URL 脱敏。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
