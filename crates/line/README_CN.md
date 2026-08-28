# arkret-bridge-line

Rust 实现的 **arkret ⇄ LINE** 桥接。基于共享核心
[`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),应用侧仅使用
[`reqwest`](https://crates.io/crates/reqwest) 直连
[LINE Messaging API](https://developers.line.biz/en/reference/messaging-api/)。

## 架构

- **入站(LINE → arkret)**:Messaging API 通过 webhook(POST,`X-Line-Signature`
  HMAC-SHA256 签名)推送事件,由 `MessageBridge::webhook_router` 暴露的路由接收
  (用 `channel_secret` 校验签名、解析 `events[]`),经 `webhook::submit` →
  `MessageContext::submit_app_message` 构造并签名 `ak.message.create` 事件提交到 arkret;
  `run` 为保活循环。
- **出站(arkret → LINE)**:arkret server 经 applet 端点
  `POST /_arkret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http`(reqwest)以 Bearer `channel_access_token` POST
  `https://api.line.me/v2/bot/message/push`。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与
# app.channel_access_token / channel_secret
cargo run -p arkret-bridge-line -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_id、applet_id、access_token、签名种子)。
- `app.channel_access_token`:LINE 推送消息令牌(Bearer)。
- `app.channel_secret`:webhook 签名校验密钥(入站接入时使用)。
- `database.url`:`sqlite://...` / `postgres://...`(对应 feature)。

## 待完善(TODO)

- 出站 `to` 字段当前取 `app_channel`,应为推送目标 ID(userId / groupId / roomId);
  实际映射规则待定。
- push 接口成功响应 body 不含消息 id,目前以 `x-line-request-id` 头作追踪标识。
- 入站 webhook 接收(POST + X-Line-Signature 校验)已接入(`webhook_router`)。
- 入站媒体(image/video/audio/file)已接:从 `api-data.line.me/.../content` Bearer 下载 →
  `upload_blob` → `submit_media_message`。出站二进制(LINE push 需 `originalContentUrl` 托管 URL)
  暂未实现。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
