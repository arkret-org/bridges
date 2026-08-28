# arkret-bridge-teams

Rust 实现的 **arkret ⇄ Microsoft Teams** 桥接。基于共享核心
[`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),应用侧使用 **Bot Framework** REST API
(`ctx.http` / reqwest)发送消息。

## 架构

- **出站(arkret → Teams)**:arkret server 经 applet 端点
  `POST /_arkret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`:
  1. 用 client_credentials 向 AAD(`login.microsoftonline.com/botframework.com`)取
     access token;
  2. `ctx.http` POST `{serviceUrl}/v3/conversations/{conversationId}/activities`
     发送 `message` Activity。
- **入站(Teams → arkret)**:Bot Framework 通过 HTTPS webhook 把 Activity POST 到
  bot 的 `/api/messages`,由 `MessageBridge::webhook_router` 暴露的路由接收,先校验
  `Authorization: Bearer <JWT>`(Bot Framework JWKS + issuer/audience),再解析入站 Activity
  并经 `webhook::submit` 入站;`run` 为保活循环。
- **映射**:conversation↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与 app.app_id / app.app_password
cargo run -p arkret-bridge-teams -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.app_id` / `app.app_password`:Azure Bot 注册的应用 ID 与密钥。
- `app.service_url`:Bot Framework serviceUrl 基地址(必填,按区域不同)。
- `app.inbound_jwt`:Teams webhook Bearer JWT 验签配置(`issuer`/`audience`/`jwks_url`)。
- `database.url`:`sqlite://...` / `postgres://...`(对应 feature)。

## 安全注意(平台固有限制)

- **Bearer JWT 不绑定请求体**:Bot Framework 的入站验证模型是 per-request Bearer JWT,
  签名只覆盖 token 自身、不覆盖 POST body。与 HMAC-over-body 桥(Meta/LINE 类)相比,
  一枚被捕获的有效 JWT 可在其有效期(约 1 小时)内伪造任意入站 Activity。桥侧缓解:
  1. token 的 `serviceUrl` claim **必须存在**且必须与 Activity 的 `serviceUrl` 一致,
     缺失即拒(fail closed);
  2. 以 Activity `id` 建持久重放/去重窗(契约 G-4 扩展面,TTL 覆盖 token 生命期,
     重启/多副本下依然生效)。
- **日志卫生是硬前提**:上述模型依赖 `Authorization` 头永不落日志、永不被中间层
  (TLS 终止代理、访问日志、APM)记录。反代与日志管道必须显式剥离/遮蔽该头。

## 待完善(TODO)

- `service_url` 实际值随会话由 Bot Framework 下发,出站前应以入站 Activity 携带的
  serviceUrl 为准;当前实现要求显式配置。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
