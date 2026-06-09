# cokret-bridge-googlechat

Rust 实现的 **cokret ⇄ Google Chat** 桥接。基于共享核心
[`cokret-bridge-runtime`](../core) + [`cokret-bridge-messaging`](../messaging),应用侧仅用
[`reqwest`](https://crates.io/crates/reqwest),不引入专有 SDK。对接 **Google Chat REST API**。

## 架构

- **入站(Google Chat → cokret)**:Google Chat 的 HTTP webhook 事件由
  `MessageBridge::webhook_router` 暴露的路由接收,先校验 `Authorization: Bearer <JWT>`
  (Google JWKS + issuer/audience),再经 `webhook::submit` →
  `MessageContext::submit_app_message` 构造并签名 `ck.message.create` 事件 →
  `events_submit` 提交到 cokret;`run` 为保活循环。
- **出站(cokret → Google Chat)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` POST `https://chat.googleapis.com/v1/{space}/messages` 发到 space。
- **映射**:space↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 鉴权

Google Chat API 需 OAuth2 Bearer 令牌(scope `https://www.googleapis.com/auth/chat.bot`)。

- 简单方式:在 `app.token` 直接填入已就绪的 access_token。
- 推荐方式:在 `app.service_account_json` 填 service-account JSON 路径,由其 JWT
  断言向 `https://oauth2.googleapis.com/token` 换取 access_token —— **此换取逻辑标注为
  `// TODO`,尚未实现**。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.token 或 service_account_json
cargo run -p cokret-bridge-googlechat -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.token` / `app.service_account_json`:Google Chat 鉴权,二选一。
- `app.inbound_jwt`:Google Chat webhook Bearer JWT 验签配置(`issuer`/`audience`/`jwks_url`)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待办

- service-account JSON → OAuth2 access_token 的换取(`bearer_token` 中的 TODO)。
- Pub/Sub 订阅模式可作后续可选增强。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
