# cokret-applets

cokret 协议的桥接(bridge)applet 集合,与 `palpo-im` 的 `matrix-bridge-*` 一一对应,
把 **cokret 去中心化协作协议** 与各第三方 chat app 互联。Rust 实现,技术栈 salvo + diesel,
协议侧基于 [`cokret-rust-sdk`](../cokret/cokret-rust-sdk)。

## 结构

Cargo workspace,所有 crate 位于 `crates/`(文件夹名去掉 `cokret-bridge-` 前缀,
包名仍为 `cokret-bridge-*`)。例:`crates/discord/` ⇒ 包 `cokret-bridge-discord`。

| crate(包名) | 对端 app | 应用侧技术 | 端口 |
|---|---|---|---|
| `cokret-bridge-core` | — | 共享核心(cokret 接入/DB/web/队列) | — |
| `cokret-bridge-discord` | Discord | serenity gateway | 9101 |
| `cokret-bridge-telegram` | Telegram | teloxide | 9102 |
| `cokret-bridge-slack` | Slack | tungstenite socket mode | 9103 |
| `cokret-bridge-feishu` | 飞书 | reqwest | 9104 |
| `cokret-bridge-wechat` | 微信 | reqwest | 9105 |
| `cokret-bridge-dingtalk` | 钉钉 | reqwest | 9106 |
| `cokret-bridge-zulip` | Zulip | reqwest + tungstenite | 9107 |
| `cokret-bridge-whatsapp` | WhatsApp | reqwest (Cloud API) | 9108 |
| `cokret-bridge-line` | LINE | reqwest | 9109 |
| `cokret-bridge-qq` | QQ | reqwest (OneBot/官方) | 9110 |
| `cokret-bridge-googlechat` | Google Chat | reqwest | 9111 |
| `cokret-bridge-imessage` | iMessage | reqwest (网关) | 9112 |
| `cokret-bridge-messager` | Messenger | reqwest (Graph API) | 9113 |
| `cokret-bridge-teams` | MS Teams | reqwest (Bot Framework) | 9114 |

## 架构

每个桥都是一个 cokret **Applet**:

- **入站(cokret → app)**:cokret server 经 `POST /_cokret/edge/applet/transactions`
  推送事件 → 核心 `BridgeAppletHandler` 入队 → 消费循环 → 适配器 `send_to_app`。
- **出站(app → cokret)**:适配器收到 app 消息 → `BridgeContext::submit_app_message`
  → 核心构造并签名 `ck.message.create` 事件 → `events_submit` 提交。
- **映射**:频道↔realm、消息↔event、用户↔actor 持久化于 diesel(sqlite/postgres/mysql)。

详见 [`_bridges_todos.md`](_bridges_todos.md)(规划/并行/进度)与
[`_BRIDGE_CONTRACT.md`](_BRIDGE_CONTRACT.md)(适配器编写契约)。

## 构建

```bash
cargo check --workspace
cargo run -p cokret-bridge-discord -- --config config.yaml
```

每个 crate 默认 `sqlite` feature;`--features postgres` / `--features mysql` 切换后端。
