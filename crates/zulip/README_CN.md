# cokret-bridge-zulip

Rust 实现的 **cokret ⇄ Zulip** 桥接。基于共享核心 [`cokret-bridge-core`](../core),
应用侧使用 [`reqwest`](https://crates.io/crates/reqwest) 走 Zulip **event queue 长轮询**
REST 接口(并预留 [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) 以备后续 ws 推送)。

## 架构

- **入站(Zulip → cokret)**:`run` 先 `POST /api/v1/register` 建 event queue,再循环
  `GET /api/v1/events`(长轮询)拉取 `message` 事件 → `BridgeContext::submit_app_message`
  → 核心构造并签名 `ck.message.create` 事件 → `events_submit` 提交到 cokret。
- **出站(cokret → Zulip)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` `POST {site}/api/v1/messages`(HTTP basic auth:bot_email + api_key)发送。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.site / bot_email / api_key
cargo run -p cokret-bridge-zulip -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.site`:Zulip 站点基址,如 `https://your-org.zulipchat.com`(无尾斜杠)。
- `app.bot_email` / `app.api_key`:Zulip bot 凭据(用于 register/events/messages 的 basic auth)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 不确定点(TODO)

- event queue 失效(`BAD_EVENT_QUEUE_ID`)的自动重注册尚未实现,当前简化为继续轮询。
- `app_channel` 的频道键格式(stream_id vs `pm/<id>`)需与 core 的频道↔realm 映射约定对齐。
- stream 出站消息的 `topic` 当前用占位值 `cokret`。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
