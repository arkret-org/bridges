# cokret-bridge-wechat

Rust 实现的 **cokret ⇄ 微信(企业微信 / 公众号)** 桥接。基于共享核心
[`cokret-bridge-runtime`](../runtime) + [`cokret-bridge-messaging`](../messaging),应用侧**仅使用**
[`reqwest`](https://crates.io/crates/reqwest)(不引入微信 SDK,也不另起端口)。

## 架构

- **入站(微信 → cokret)**:微信经平台后台配置的「接收消息服务器」回调推送消息
  (plaintext XML),由 `MessageBridge::webhook_router` 暴露的路由接收
  (含 URL 校验 echostr 与 plaintext `signature` 校验),再经 `webhook::submit` 入站;`run` 为保活循环。
  加密(安全)模式已实现:配置 `app.encoding_aes_key`(43 字符 EncodingAESKey)即启用
  `msg_signature` 校验 + AES-256-CBC 解密 + receiveid 绑定;未配置时回退 plaintext 模式;
  企业微信(`agent_id`)入站强制要求安全模式,缺 `encoding_aes_key` 则启动即 fail closed。
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
- `app.webhook_token`:微信回调 Token,必填;GET/POST 均校验 plaintext `signature`。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待完善(TODO)

- 入站回调 webhook 已接入(`webhook_router`,含 echostr 与 plaintext `signature` 校验;
  加密(安全)模式亦已实现:`msg_signature` 校验 + AES-256-CBC 解密 + receiveid 绑定,企业微信入站强制启用)。
- `access_token` 经 `TokenCache` 缓存,按 `expires_in` 提前 60s 刷新(不再每次现取)。
- 出站 URL 与消息体当前按**企业微信应用消息**实现;公众号客服消息需切换
  `https://api.weixin.qq.com` 基址、`message/custom/send` 路径与不同消息体结构。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
