# cokret-bridge-dingtalk

Rust 实现的 **cokret ⇄ 钉钉(DingTalk)** 桥接。基于共享核心
[`cokret-bridge-runtime`](../runtime) + [`cokret-bridge-messaging`](../messaging),应用侧仅使用
[`reqwest`](https://crates.io/crates/reqwest) 直连钉钉开放平台 HTTP API。

## 架构

- **入站(钉钉 → cokret)**:钉钉回调 webhook 先校验原生 `timestamp`/`sign`;由于该签名不覆盖
  请求体,实际消息入库前还必须由可信 ingress 代理补充
  `x-cokret-timestamp`/`x-cokret-signature-256` body HMAC,再经 `webhook::submit` →
  `MessageContext::submit_app_message` 构造并签名 `ck.message.create` 事件提交到 cokret;`run`
  为保活循环。
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
- `app.webhook_body_hmac_secret`:入站消息体 HMAC 密钥,必填。签名格式为
  `hex(HMAC-SHA256(secret, x-cokret-timestamp + "\n" + raw_body))`,放入
  `x-cokret-signature-256`;时间戳为 Unix 秒。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 待完善(TODO)

- `send_to_app` 中的发送接口 URL(群消息 `groupMessages/send` vs 单聊
  `oToMessages/batchSend`)需按实际会话类型确认。
- `access_token` 经 `TokenCache` 缓存,按 `expireIn` 提前 60s 刷新(不再每次现取)。
- 入站 webhook 已接入(`webhook_router`);明文 outgoing-robot body 未被钉钉签名覆盖,因此未配置
  body HMAC 时非 challenge 投递会 fail closed。Stream 长连(wss)模式可作为后续可选增强。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
