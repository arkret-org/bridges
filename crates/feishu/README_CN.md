# cokret-bridge-feishu

Rust 实现的 **cokret ⇄ 飞书(Feishu / Lark)** 桥接。基于共享核心
[`cokret-bridge-runtime`](../runtime) + [`cokret-bridge-messaging`](../messaging),应用侧**仅使用**
[`reqwest`](https://crates.io/crates/reqwest)(不引入飞书 SDK)。

## 架构

- **入站(飞书 → cokret)**:飞书通过「事件订阅」HTTP 回调推送
  `im.message.receive_v1` 等事件,由 `MessageBridge::webhook_router` 暴露的路由接收
  (含 challenge 与 Verification Token 校验),再经 `webhook::submit` 入站;`run` 为保活循环。
  配置 Encrypt Key 时当前会 fail closed 拒绝加密回调,AES 解密尚未实现。
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
- `app.verification_token`:事件订阅 Verification Token,必填;challenge 与事件投递均会常量时间校验。
- `app.encrypt_key`:**必填(生产强制)**。启用加密回调模式后,飞书对每次投递附带
  `X-Lark-Signature`(`sha256(timestamp+nonce+encrypt_key+body)`)。本桥对**每条**投递强制:
  (1) 验签;(2) 时间戳新鲜度(±300s);(3) 重放窗口去重;(4) 解密 `{"encrypt":...}` 信封。
  明文回调无逐次来源签名,违反 bridge 合约,故 `encrypt_key` 留空时 webhook 路由**不挂载**(fail closed)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 不确定点(TODO)

- 入站事件订阅 webhook 已接入(`webhook_router`,含每条投递强制 `X-Lark-Signature` 验签、
  时间戳新鲜度、重放窗口、challenge 校验与事件分发)。
- `tenant_access_token` 经 `TokenCache` 缓存,按 `expire` 提前 60s 刷新(不再每次现取)。
- 出站 `receive_id_type` 默认 `chat_id`,实际可能为 `open_id`/`user_id`,需按频道键格式确定。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
