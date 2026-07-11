# arkret-bridge-whatsapp

Rust 实现的 **arkret ⇄ WhatsApp** 桥接。基于共享核心
[`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),应用侧仅使用
[`reqwest`](https://crates.io/crates/reqwest) 直连
[WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api)。

## 架构

- **入站(WhatsApp → arkret)**:Cloud API 通过 webhook(GET 校验 + POST 接收)推送消息,
  由 `MessageBridge::webhook_router` 暴露的路由处理(GET 校验 `verify_token`、POST 解析
  前校验 `X-Hub-Signature-256` 后解析 `entry[].changes[].value.messages[]`),经 `webhook::submit` → `MessageContext::submit_app_message`
  构造并签名 `ak.message.create` 事件提交到 arkret;`run` 为保活循环。
- **出站(arkret → WhatsApp)**:arkret server 经 applet 端点
  `POST /_arkret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http`(reqwest)以 Bearer `access_token` POST
  `https://graph.facebook.com/v20.0/{phone_number_id}/messages`。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与
# app.phone_number_id / access_token / verify_token / app_secret
cargo run -p arkret-bridge-whatsapp -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_id、applet_id、access_token、签名种子)。
- `app.phone_number_id`:发送方电话号码 ID(出站 URL 路径段)。
- `app.access_token`:Cloud API 令牌(Bearer)。
- `app.verify_token`:webhook 校验回显令牌(入站接入时使用)。
- `app.app_secret`:Meta App Secret,必填;POST 投递用 `X-Hub-Signature-256` 校验。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待完善(TODO)

- 出站 `to` 字段当前取 `app_channel`,应为收件人 WhatsApp 号码(E.164,不含 `+`);
  实际映射规则待定。
- Graph API 版本 `v20.0` 写死,后续可随官方版本升级。
- 入站 webhook 验证(GET hub.challenge)与接收(POST 消息体)已接入(`webhook_router`)。
- 入站媒体(image/document/video/audio/sticker)已接:经 `graph.facebook.com/{media-id}`
  解析 URL → Bearer 下载 → `upload_blob` → `submit_media_message`。出站二进制(需先上传 media)
  暂未实现。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
