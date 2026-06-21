# cokret-bridge-slack

Rust 实现的 **cokret ⇄ Slack** 桥接。基于共享核心 [`cokret-bridge-runtime`](../runtime) + [`cokret-bridge-messaging`](../messaging),
应用侧使用 Slack **Socket Mode**(WebSocket,[`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite))
接收事件,使用 **Web API**(`ctx.http` / reqwest)发送消息。

## 架构

- **入站(Slack → cokret)**:先 POST `apps.connections.open` 用 `app_token`(`xapp-`)
  换取一次性 wss URL → 连接 socket mode → 读循环解析 `message` 事件 →
  `MessageContext::submit_app_message` → 核心签名 `ck.message.create` 提交 cokret。
  socket mode 要求对每个带 `envelope_id` 的 envelope 回 ack。
- **出站(cokret → Slack)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST `https://slack.com/api/chat.postMessage`(`bot_token` `xoxb-`)。
- **映射**:channel↔realm、消息(ts)↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.bot_token / app.app_token
cargo run -p cokret-bridge-slack -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.bot_token`:Slack Bot User OAuth Token(`xoxb-...`),供 Web API 鉴权。
- `app.app_token`:Slack App-Level Token(`xapp-...`),供 Socket Mode 建连。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 说明

- 需在 Slack 应用后台开启 Socket Mode,并订阅 `message.channels` 等事件。
- 入站只转发普通文本消息;含 `subtype` 或 `bot_id` 的消息(编辑、bot 回声等)被忽略以防回环。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
