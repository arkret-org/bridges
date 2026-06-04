# cokret-bridge-wechat

Rust 实现的 **cokret ⇄ 微信(企业微信 / 公众号)** 桥接。基于共享核心
[`cokret-bridge-core`](../core),应用侧**仅使用**
[`reqwest`](https://crates.io/crates/reqwest)(不引入微信 SDK,也不另起端口)。

## 架构

- **入站(微信 → cokret)**:微信经平台后台配置的「接收消息服务器」回调推送消息
  (XML,可能加密)。该回调需 `cokret-bridge-core` 暴露额外的 webhook 路由接收
  (含 URL 校验 echostr 与消息解密);在此之前 `run` 以保活循环占位(见 TODO)。
- **出站(cokret → 微信)**:cokret server 经 applet 端点
  `POST /_cokret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `ctx.http` 先用 corp_id/corp_secret(或 app_id/app_secret)换 `access_token`,
  再 POST 企业微信应用消息 / 公众号客服消息接口。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 cokret.access_token / signing_key_seed_hex 与 app.corp_id / corp_secret / agent_id
cargo run -p cokret-bridge-wechat -- --config config.yaml
```

## 配置要点

- `cokret.*`:cokret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.corp_id` / `app.corp_secret` / `app.agent_id`:企业微信应用凭证;
  公众号场景改填 `app.app_id` / `app.app_secret`。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 不确定点(TODO)

- 入站回调 webhook 待 core 暴露额外路由后接入(含 echostr 校验与消息解密)。
- `access_token` 当前每次发送现取,未做缓存与过期刷新。
- 出站 URL 与消息体当前按**企业微信应用消息**实现;公众号客服消息需切换
  `https://api.weixin.qq.com` 基址、`message/custom/send` 路径与不同消息体结构。

详见 [`../_bridges_todos.md`](../../_bridges_todos.md) 的总体规划与映射表。
