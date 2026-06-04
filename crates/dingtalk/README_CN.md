# cokret-bridge-dingtalk

Rust 实现的 **cokret ⇄ 钉钉(DingTalk)** 桥接。基于共享核心
[`cokret-bridge-core`](../core),应用侧仅使用
[`reqwest`](https://crates.io/crates/reqwest) 直连钉钉开放平台 HTTP API。

## 架构

- **入站(钉钉 → cokret)**:钉钉支持 Stream 长连(wss)与回调 webhook 推送消息。
  当前 core 尚未向适配器暴露额外的入站路由 / stream 接入点,故 `run` 先以保活循环占位;
  待 core 暴露后,在收到消息时调 `BridgeContext::submit_app_message` 构造并签名
  `ck.message.create` 事件提交到 cokret。
- **出站(cokret → 钉钉)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http`(reqwest)先以 `app_key`/`app_secret` 换取 `access_token`,再
  POST 钉钉企业机器人发消息接口。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.app_key / app_secret / robot_code
cargo run -p cokret-bridge-dingtalk -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.app_key` / `app.app_secret`:钉钉企业内部应用凭据,用于换取 access_token。
- `app.robot_code`:钉钉机器人编码(robotCode)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待完善(TODO)

- `send_to_app` 中的发送接口 URL(群消息 `groupMessages/send` vs 单聊
  `oToMessages/batchSend`)需按实际会话类型确认。
- `access_token` 当前每次发送现取,生产环境应缓存并按有效期(约 7200s)刷新。
- 入站 stream/webhook 接入待 core 暴露额外路由后补全。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
