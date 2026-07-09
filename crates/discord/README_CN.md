# arkret-bridge-discord

Rust 实现的 **arkret ⇄ Discord** 桥接。基于共享核心 [`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),
应用侧使用 [`serenity`](https://crates.io/crates/serenity) gateway。

## 架构

- **入站(Discord → arkret)**:serenity gateway 收到消息 → `MessageContext::submit_app_message`
  → 核心构造并签名 `ck.message.create` 事件 → `events_submit` 提交到 arkret。
- **出站(arkret → Discord)**:arkret server 经 applet 端点
  `POST /_arkret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 serenity HTTP 发到 Discord 频道。
- **媒体(双向)**:入站附件从 Discord CDN 下载 → `upload_blob` → `submit_media_message`;
  出站 `MediaContent` 经 `download_blob` → serenity `CreateAttachment` 发回频道。
- **映射**:频道↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与 app.bot_token
cargo run -p arkret-bridge-discord -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.bot_token`:Discord bot token。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
