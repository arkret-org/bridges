# arkret-bridge-imessage

Rust 实现的 **arkret ⇄ iMessage** 桥接。基于共享核心
[`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),应用侧仅用
[`reqwest`](https://crates.io/crates/reqwest),不引入专有 SDK。经 **BlueBubbles /
AirMessage** 之类的 HTTP 网关与 iMessage 收发。

## 架构

- **入站(iMessage → arkret)**:网关 webhook 回调推送的新消息由
  `MessageBridge::webhook_router` 暴露的路由接收(必填 `webhook_secret`,请求须携带
  `x-arkret-timestamp` 与 `x-arkret-signature-256` body HMAC),经 `webhook::submit` →
  `MessageContext::submit_app_message` 构造并签名 `ak.message.create` 事件 → `events_submit`
  提交到 arkret;`run` 为保活循环。
- **出站(arkret → iMessage)**:arkret server 经 applet 端点
  `POST /_arkret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST 网关发送接口(示例为 BlueBubbles `/api/v1/message/text`)。
- **映射**:chat guid↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与 app.gateway_url / password / webhook_secret
cargo run -p arkret-bridge-imessage -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.gateway_url`:BlueBubbles / AirMessage 网关基址。
- `app.password`:网关访问口令(BlueBubbles 作 `?guid=` 查询参数)。
- `app.webhook_secret`:入站 `/webhooks/imessage` 的 HMAC 密钥,必填。签名格式为
  `hex(HMAC-SHA256(secret, x-arkret-timestamp + "\n" + raw_body))`,放入
  `x-arkret-signature-256`;时间戳为 Unix 秒,并参与重放防护。未配置时 fail closed 拒绝。
- `database.url`:`sqlite://...` / `postgres://...`(对应 feature)。

## 待办

- `send_to_app` 的 endpoint 与字段按实际网关(BlueBubbles / AirMessage)确认。
- 入站网关 webhook 回调已接入(`webhook_router`,必需 timestamp+body HMAC)。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
