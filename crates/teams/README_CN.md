# cokret-bridge-teams

Rust 实现的 **cokret ⇄ Microsoft Teams** 桥接。基于共享核心
[`cokret-bridge-runtime`](../core) + [`cokret-bridge-messaging`](../messaging),应用侧使用 **Bot Framework** REST API
(`ctx.http` / reqwest)发送消息。

## 架构

- **出站(cokret → Teams)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`:
  1. 用 client_credentials 向 AAD(`login.microsoftonline.com/botframework.com`)取
     access token;
  2. `ctx.http` POST `{serviceUrl}/v3/conversations/{conversationId}/activities`
     发送 `message` Activity。
- **入站(Teams → cokret)**:Bot Framework 通过 HTTPS webhook 把 Activity POST 到
  bot 的 `/api/messages`,由 `MessageBridge::webhook_router` 暴露的路由接收并解析
  入站 Activity,再经 `webhook::submit` 入站;`run` 为保活循环。
- **映射**:conversation↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.app_id / app.app_password
cargo run -p cokret-bridge-teams -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.app_id` / `app.app_password`:Azure Bot 注册的应用 ID 与密钥。
- `app.service_url`:Bot Framework serviceUrl 基地址(随入站 Activity 下发,按区域不同)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 不确定点 / TODO

- 入站 `/api/messages` webhook 已接入(`webhook_router`)。
- `service_url` 实际值随会话由 Bot Framework 下发,出站前应以入站 Activity 携带的
  serviceUrl 为准;此处先用配置缺省值。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
