# arkret-bridge-telegram

Rust 实现的 **arkret ⇄ Telegram** 桥接。基于共享核心 [`arkret-bridge-runtime`](../runtime) + [`arkret-bridge-messaging`](../messaging),
应用侧使用 [`teloxide`](https://crates.io/crates/teloxide) 长轮询。

## 架构

- **入站(Telegram → arkret)**:`teloxide::repl` 长轮询收到文本消息 →
  `MessageContext::submit_app_message` → 核心构造并签名 `ck.message.create` 事件 →
  `events_submit` 提交到 arkret。
- **出站(arkret → Telegram)**:arkret server 经 applet 端点
  `POST /_arkret/edge/applet/transactions` 推送事件 → 核心入站队列 → `send_to_app`
  用 `Bot::send_message`(媒体则 `send_document`)发到对应 chat。
- **媒体(双向)**:入站 photo/document 经 `get_file` 下载 → `upload_blob` → `submit_media_message`;
  出站 `MediaContent` 经 `download_blob` → `InputFile::memory` 以 `send_document` 发回。
- **映射**:chat↔realm、消息↔event、用户↔actor 存于 diesel 数据库(默认 sqlite)。

## 快速开始

```bash
cp config/config.sample.yaml config.yaml
# 填入 arkret.access_token / signing_key_seed_hex 与 app.bot_token
cargo run -p arkret-bridge-telegram -- --config config.yaml
```

## 配置要点

- `arkret.*`:arkret 接入(server_url、service_did、applet_id、access_token、签名种子)。
- `app.bot_token`:Telegram bot token(从 @BotFather 获取)。
- `database.url`:`sqlite://...` / `postgres://...` / `mysql://...`(对应 feature)。

## 说明

- 入站转发文本与 photo/document 媒体;贴纸等其他类型暂未处理。
- `app_channel` 为 Telegram chat id(整数,可为负的群组 id)。

契约与共享层约束见仓库根目录 [`_BRIDGE_CONTRACT.md`](../../_BRIDGE_CONTRACT.md)。
