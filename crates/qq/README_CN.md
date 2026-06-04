# cokret-bridge-qq

Rust 实现的 **cokret ⇄ QQ** 桥接。基于共享核心 [`cokret-bridge-core`](../core),
应用侧仅用 [`reqwest`](https://crates.io/crates/reqwest),不引入专有 SDK。对接 **OneBot**
HTTP API(go-cqhttp / NapCat / Lagrange 等)或 **QQ 官方机器人**。

## 架构

- **入站(QQ → cokret)**:QQ 侧消息经 OneBot 上报或官方 webhook 到达 →
  `BridgeContext::submit_app_message` → 核心构造并签名 `ck.message.create` 事件 →
  `events_submit` 提交到 cokret。当前 `run` 为保活循环占位,ws/webhook 上报接入
  待 core 暴露额外注入路由。
- **出站(cokret → QQ)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST OneBot `send_msg`(或官方 `/channels/{id}/messages`)发到 QQ。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.onebot_url / access_token
cargo run -p cokret-bridge-qq -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.onebot_url`:OneBot 实现的 HTTP API 基址。
- `app.access_token`:OneBot access_token(可选)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待办

- `run` 接入真实 OneBot ws/官方 webhook 上报(依赖 core 暴露 webhook 注入路由)。
- `send_to_app` 的 endpoint 与 `message_type` 按实际部署确认(群聊/私聊/频道)。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
