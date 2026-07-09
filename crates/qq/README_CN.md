# arkret-bridge-qq

Rust 实现的 **arkret ⇄ QQ** 桥接。基于共享核心 [`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),
应用侧仅用 [`reqwest`](https://crates.io/crates/reqwest),不引入专有 SDK。对接 **OneBot**
HTTP API(go-cqhttp / NapCat / Lagrange 等)或 **QQ 官方机器人**。

## 架构

- **入站(QQ → arkret)**:QQ 侧消息经 OneBot webhook 上报到达,由
  `MessageBridge::webhook_router` 暴露的路由先校验 `X-Signature`,再经 `webhook::submit` →
  `MessageContext::submit_app_message` 构造并签名 `ck.message.create` 事件 →
  `events_submit` 提交到 arkret;`run` 为保活循环。
- **出站(arkret → QQ)**:arkret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST OneBot `send_msg`(或官方 `/channels/{id}/messages`)发到 QQ。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与 app.onebot_url / access_token / signing_secret
cargo run -p arkret-bridge-qq -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.onebot_url`:OneBot 实现的 HTTP API 基址。
- `app.access_token`:OneBot access_token(可选)。
- `app.signing_secret`:OneBot `X-Signature` HMAC secret,必填。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待办

- webhook/官方上报入站已接入(`webhook_router`);OneBot 反向 ws 模式可作后续可选增强。
- `send_to_app` 的 endpoint 与 `message_type` 按实际部署确认(群聊/私聊/频道)。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
