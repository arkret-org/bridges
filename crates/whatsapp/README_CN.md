# cokret-bridge-whatsapp

Rust 实现的 **cokret ⇄ WhatsApp** 桥接。基于共享核心
[`cokret-bridge-core`](../core),应用侧仅使用
[`reqwest`](https://crates.io/crates/reqwest) 直连
[WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api)。

## 架构

- **入站(WhatsApp → cokret)**:Cloud API 通过 webhook(GET 校验 + POST 接收)推送消息。
  当前 core 尚未向适配器暴露额外的入站 webhook 路由,故 `run` 先以保活循环占位;
  待 core 暴露后,在校验 `verify_token`、解析 `entry[].changes[].value.messages[]` 后调
  `BridgeContext::submit_app_message` 构造并签名 `ck.message.create` 事件提交到 cokret。
- **出站(cokret → WhatsApp)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http`(reqwest)以 Bearer `access_token` POST
  `https://graph.facebook.com/v20.0/{phone_number_id}/messages`。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与
# app.phone_number_id / access_token / verify_token
cargo run -p cokret-bridge-whatsapp -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.phone_number_id`:发送方电话号码 ID(出站 URL 路径段)。
- `app.access_token`:Cloud API 令牌(Bearer)。
- `app.verify_token`:webhook 校验回显令牌(入站接入时使用)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待完善(TODO)

- 出站 `to` 字段当前取 `app_channel`,应为收件人 WhatsApp 号码(E.164,不含 `+`);
  实际映射规则待定。
- Graph API 版本 `v20.0` 写死,后续可随官方版本升级。
- 入站 webhook 验证(GET hub.challenge)与接收(POST 消息体)待 core 暴露额外路由后补全。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
