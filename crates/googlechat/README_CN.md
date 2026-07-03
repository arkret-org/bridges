# cokret-bridge-googlechat

Rust 实现的 **cokret ⇄ Google Chat** 桥接。基于共享核心
[`cokret-bridge-runtime`](../runtime) + [`cokret-bridge-messaging`](../messaging),应用侧仅用
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

- 简单方式:在 `app.token` 直接填入已就绪的短期 access_token。
- 推荐方式:在 `app.service_account_json` 填 service-account JSON 对象,由其 JWT
  断言向 `https://oauth2.googleapis.com/token` 换取 access_token 并缓存到过期前。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.token 或 service_account_json
cargo run -p cokret-bridge-googlechat -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.token` / `app.service_account_json`:Google Chat 鉴权,二选一;推荐 `service_account_json` 自动刷新。
- `app.inbound_jwt`:Google Chat webhook Bearer JWT 验签配置(`issuer`/`audience`/`jwks_url`)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 安全注意(平台固有限制)

- **Bearer JWT 不绑定请求体**:Google Chat 的入站验证模型是 per-request Bearer JWT,
  签名只覆盖 token 自身、不覆盖 POST body。与 HMAC-over-body 桥(Meta/LINE 类)相比,
  一枚被捕获的有效 JWT 可在其有效期(约 1 小时)内伪造任意入站事件体。桥侧缓解:
  以消息资源名 `message.name` 建持久重放/去重窗(契约 G-4 扩展面,TTL 覆盖 token
  生命期,重启/多副本下依然生效)。
- **日志卫生是硬前提**:上述模型依赖 `Authorization` 头永不落日志、永不被中间层
  (TLS 终止代理、访问日志、APM)记录。反代与日志管道必须显式剥离/遮蔽该头。

## 待办

- Pub/Sub 订阅模式可作后续可选增强。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
