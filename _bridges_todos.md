# 共享层变更 / 待办登记(bridges)

`_BRIDGE_CONTRACT.md` 要求适配器**勿改两个共享 crate**(`arkret-bridge-runtime` /
`arkret-bridge-messaging`)。当某项能力确属跨桥共享、必须下沉到共享层时,在此登记,
让契约约束有一个可承载的记录面(否则共享层会被各桥各自悄悄改动)。

登记规则:

- 只登记**共享层**(runtime / messaging)的改动或待办;单桥 adapter 细节不在此列。
- 已落地的改动:记一行 changelog;尚未动手的:记一条 todo。
- 每条注明日期、改动面(runtime/messaging)、动机,够后人冷读即可。

## Changelog(已落地的共享层改动)

| 日期 | 改动面 | 摘要 |
|---|---|---|
| 2026-06-25 | runtime + messaging | 新增 `arkret_bridge_messages_total` 指标(`record_bridge_message`),入站提交 / 出站投递 / 入站媒体各计成功失败;messaging `MessageContext` 增 `report_outbound_bridge_error`,出站 `send_to_app` 失败补审计 + retriable 分类(对称入站) |
| 2026-06-29 | runtime + messaging | BRG-REL-001 启动期 fail-fast:`BridgeApp` / `MessageBridge` 新增 `expects_webhook_inbound()`(默认 `false`),`run_bridge` 在该桥声明 webhook 入站面但 `webhook_router` 返回 `None`(如 Feishu `encrypt_key` 缺失)时返回 `BridgeError::Config` 拒绝启动,而非降级为无入站面的“健康”进程。10 个纯 webhook 桥重写为 `true`,gateway 桥(discord/slack/telegram/zulip)保持默认 |
| 2026-07-09 | messaging | `MessageBridge::redact_in_app` 回调签名改为 `(ctx, app_channel, app_message_id)`,共享层反查 redaction target 时保留 channel+message 双键,为平台删除 API 接线清掉结构性阻碍。 |
| 2026-07-09 | discord | Discord override `redact_in_app`,用 channel id + message id 调 `delete_message`,作为出站删除接线示范。 |
| 2026-07-11 | messaging + line | LINE `unsend` 映射为 `InboundAppDelete` 并调用 `submit_app_delete`;`ak.typing` 通过 `on_ephemeral` 映射为 LINE loading indicator。 |
| 2026-07-11 | messaging + adapters | 新增平台无关 `InboundMediaFetcher` 和有界 HTTP 实现;Discord、Telegram、Slack、LINE、WhatsApp、Messenger 接入真实媒体下载,无可验证下载引用的平台显式拒绝。 |
| 2026-07-11 | runtime | `ArkretEdge` 新增注入已认证 SDK `Client`、`Ed25519MoveSigner`、可复用 `SeqAllocator` 的 outbound-only 构造路径，公开 delegated unsigned mint 以允许 host 在首次签名前加密；`SeqAllocator` 可克隆并共享预留窗口，新增通用 `FileSeqStore`，用于 Savfox applet 出站链路消除重复 mint/HLC/签名/提交实现。 |
| 2026-07-13 | messaging | 删除从未接入 `MessageContext`、也无任何 adapter 使用的 calendar / RSVP 映射守卫；现行 calendar spec 与 Rust SDK 类型保持不变，未来有真实接入方时再随提交链路实现。 |
| 2026-07-16 | runtime | `arkret_edge.rs` 出站传输策略注释的 `cleartext` 改为 `plaintext`，对齐 `forbidden-model-terms.json` hard_reject 条目（该条目明确覆盖 code comments）。仅注释,无行为变更。 |

## Todo(尚未落地的共享层待办)

- **(messaging) 其余平台出站删除 `redact_in_app` 接线未完成**(BRG-HYG-003,
  2026-06-29 登记):驱动链路(`on_arkret_event` 收 `ak.message.redact` → 反查
  `(app_channel, app_message_id)` → 调 `redact_in_app`)已就绪,Discord 已作为示范桥接线。
  待办:按平台能力补其余桥的 `redact_in_app`;LINE 的 typing ephemeral 已接线,其余
  ephemeral 类型和平台按原生能力逐桥实现。
