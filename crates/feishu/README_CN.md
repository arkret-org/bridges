# cokret-bridge-feishu

Rust 实现的 **cokret ⇄ 飞书(Feishu / Lark)** 桥接。基于共享核心
[`cokret-bridge-core`](../core),应用侧**仅使用**
[`reqwest`](https://crates.io/crates/reqwest)(不引入飞书 SDK)。

## 架构

- **入站(飞书 → cokret)**:飞书通过「事件订阅」HTTP 回调推送
  `im.message.receive_v1` 等事件。该回调需 `cokret-bridge-core` 暴露额外的
  webhook 路由接收;在此之前 `run` 以保活循环占位(见 TODO)。
- **出站(cokret → 飞书)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` 先换 `tenant_access_token`,再
  `POST https://open.feishu.cn/open-apis/im/v1/messages` 发送文本消息。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.app_id / app_secret
cargo run -p cokret-bridge-feishu -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.app_id` / `app.app_secret`:飞书开放平台应用凭证(用于换取 tenant_access_token)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 不确定点(TODO)

- 入站事件订阅 webhook 待 core 暴露额外路由后接入(含 challenge 校验与事件分发)。
- `tenant_access_token` 当前每次发送现取,未做缓存与过期刷新。
- 出站 `receive_id_type` 默认 `chat_id`,实际可能为 `open_id`/`user_id`,需按频道键格式确定。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
