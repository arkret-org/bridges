# cokret-bridge-imessage

Rust 实现的 **cokret ⇄ iMessage** 桥接。基于共享核心
[`cokret-bridge-runtime`](../runtime) + [`cokret-bridge-messaging`](../messaging),应用侧仅用
[`reqwest`](https://crates.io/crates/reqwest),不引入专有 SDK。经 **BlueBubbles /
AirMessage** 之类的 HTTP 网关与 iMessage 收发。

## 架构

- **入站(iMessage → cokret)**:网关 webhook 回调推送的新消息由
  `MessageBridge::webhook_router` 暴露的路由接收(可选 `webhook_secret`/`x-webhook-secret`
  头校验),经 `webhook::submit` → `MessageContext::submit_app_message` 构造并签名
  `ck.message.create` 事件 → `events_submit` 提交到 cokret;`run` 为保活循环。
- **出站(cokret → iMessage)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST 网关发送接口(示例为 BlueBubbles `/api/v1/message/text`)。
- **映射**:chat guid↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.gateway_url / password
cargo run -p cokret-bridge-imessage -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.gateway_url`:BlueBubbles / AirMessage 网关基址。
- `app.password`:网关访问口令(BlueBubbles 作 `?guid=` 查询参数)。
- `app.webhook_secret`:可选,入站 `/webhooks/imessage` 的共享密钥(请求须带
  `x-webhook-secret` 头);留空则不校验。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待办

- `send_to_app` 的 endpoint 与字段按实际网关(BlueBubbles / AirMessage)确认。
- 入站网关 webhook 回调已接入(`webhook_router`,支持可选 `webhook_secret`)。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
