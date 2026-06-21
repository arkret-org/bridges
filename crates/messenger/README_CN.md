# cokret-bridge-messenger

Rust 实现的 **cokret ⇄ Messenger** 桥接(通用 / Facebook Messenger)。基于共享核心
[`cokret-bridge-runtime`](../runtime) + [`cokret-bridge-messaging`](../messaging),应用侧仅用
[`reqwest`](https://crates.io/crates/reqwest),不引入专有 SDK。对接 **Facebook Graph API**。

## 架构

- **入站(Messenger → cokret)**:Facebook 经 webhook 推送的 `messages` 事件由
  `MessageBridge::webhook_router` 暴露的路由处理(含 GET `verify_token` 验证握手与
  POST `X-Hub-Signature-256` 校验),
  经 `webhook::submit` → `MessageContext::submit_app_message` 构造并签名
  `ck.message.create` 事件 → `events_submit` 提交到 cokret;`run` 为保活循环。
- **出站(cokret → Messenger)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST `https://graph.facebook.com/v20.0/me/messages`
  (Bearer `page_access_token`,`recipient` + `message`)。
- **映射**:PSID↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.page_access_token / verify_token / app_secret
cargo run -p cokret-bridge-messenger -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.page_access_token`:Facebook Page 访问令牌(发送鉴权)。
- `app.verify_token`:webhook 验证令牌(GET 握手比对)。
- `app.app_secret`:Meta App Secret,必填;POST 投递用 `X-Hub-Signature-256` 校验。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待办

- Messenger webhook(验证握手 + `messages` 事件解析)已接入(`webhook_router`)。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
