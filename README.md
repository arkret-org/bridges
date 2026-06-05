# cokret-applets

cokret 协议的桥接(bridge)applet 集合,与 `palpo-im` 的 `matrix-bridge-*` 一一对应,
把 **cokret 去中心化协作协议** 与各第三方 chat app 互联。Rust 实现,技术栈 salvo + diesel,
协议侧基于 [`cokret-rust-sdk`](../cokret/cokret-rust-sdk)。

## 结构

Cargo workspace,所有 crate 位于 `crates/`(文件夹名去掉 `cokret-bridge-` 前缀,
包名仍为 `cokret-bridge-*`)。例:`crates/discord/` ⇒ 包 `cokret-bridge-discord`。

共享层拆为两个 crate(均在 `crates/` 下,目录名与包名不同):

- `crates/runtime/` ⇒ 包 **`cokret-bridge-runtime`**:与聊天无关的**通用桥运行时**——cokret 接入
  (`CokretEdge`/`BridgeAppletHandler`)、DB 连接池、salvo web、队列/缓存、配置/日志,契约是
  泛型 trait `BridgeApp`(收发裸 `cokret::Event`)。非聊天集成(IoT/工单/CI)可直接实现它。
- `crates/messaging/` ⇒ 包 **`cokret-bridge-messaging`**:在 runtime 之上的**消息层**——频道/
  用户/消息映射表、`ck.message.create` 转换、actor/realm 反查解析、webhook 助手,契约是
  `MessageBridge`/`MessageContext`(14 个聊天桥都实现它,经 `run_message_bridge` 装配)。

| crate(包名) | 对端 app | 应用侧技术 | 端口 |
|---|---|---|---|
| `cokret-bridge-runtime`(`crates/runtime`) | — | 通用桥运行时(cokret 接入/DB/web/队列) | — |
| `cokret-bridge-messaging`(`crates/messaging`) | — | 消息层(映射/`ck.message.create`/webhook 助手) | — |
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
  推送事件 → runtime `BridgeAppletHandler` 入队 → `consume_inbound` 消费循环 →
  `MessageBridge::on_cokret_event` → 适配器 `send_to_app`。
- **出站(app → cokret)**:适配器收到 app 消息(gateway/长轮询/webhook)→
  `MessageContext::submit_app_message` → runtime 构造并签名带 `external_ref` 溯源的
  `ck.message.create` 事件 → `events_submit` 提交。当前写侧事件由 bridge service actor
  署名,外部用户身份通过规范化 `external_ref` 记录;per-user Ghost Actor 委托签名尚未接入。
  纯 HTTP 桥的入站经各自
  `MessageBridge::webhook_router`(已实现验签)挂到 web 服务。
- **映射 / 解析**:频道↔realm、消息↔event、用户↔actor 持久化于 diesel(sqlite/postgres/mysql);
  反查驱动 applet `resolve_actor`/`resolve_realm`(ghost/portal 读侧解析)。用户↔actor 映射
  目前不参与 app→cokret 事件署名。
- **序号**:服务 actor 的事件 seq 经 DB 块预留持久化,重启后严格单调。
- **消息内容**:对齐 SDK 规范类型 `TextMessageContent`(`{body}`)/`MediaContent`
  (`{body,blob,mimetype,filename,size}`)。
- **媒体**:`MessageContext::{upload_blob,download_blob,submit_media_message}` + `Attachment`;
  discord/telegram 收发双向、whatsapp/line 入站已接,余者文本(通用能力就绪)。
- **防回声**:`on_cokret_event` 跳过本桥 `external_ref.source` 自发事件,避免出站回环。

详见 [`_bridges_todos.md`](_bridges_todos.md)(规划/并行/进度)与
[`_BRIDGE_CONTRACT.md`](_BRIDGE_CONTRACT.md)(适配器编写契约)。

## 构建

```bash
cargo check --workspace
cargo run -p cokret-bridge-discord -- --config config.yaml
```

每个 crate 默认 `sqlite` feature;`--features postgres` / `--features mysql` 切换后端。
配置文件支持 YAML 与 KDL；KDL loader 只覆盖当前桥配置使用的标量与嵌套节点形态。
需要数组或多值节点时使用 YAML，避免 KDL 转换时丢失结构。
