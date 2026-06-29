# 共享层变更 / 待办登记(bridges)

`_BRIDGE_CONTRACT.md` 要求适配器**勿改两个共享 crate**(`cokret-bridge-runtime` /
`cokret-bridge-messaging`)。当某项能力确属跨桥共享、必须下沉到共享层时,在此登记,
让契约约束有一个可承载的记录面(否则共享层会被各桥各自悄悄改动)。

登记规则:

- 只登记**共享层**(runtime / messaging)的改动或待办;单桥 adapter 细节不在此列。
- 已落地的改动:记一行 changelog;尚未动手的:记一条 todo。
- 每条注明日期、改动面(runtime/messaging)、动机,够后人冷读即可。

## Changelog(已落地的共享层改动)

| 日期 | 改动面 | 摘要 |
|---|---|---|
| 2026-06-25 | runtime + messaging | 新增 `cokret_bridge_messages_total` 指标(`record_bridge_message`),入站提交 / 出站投递 / 入站媒体各计成功失败;messaging `MessageContext` 增 `report_outbound_bridge_error`,出站 `send_to_app` 失败补审计 + retriable 分类(对称入站) |
| 2026-06-29 | runtime + messaging | BRG-REL-001 启动期 fail-fast:`BridgeApp` / `MessageBridge` 新增 `expects_webhook_inbound()`(默认 `false`),`run_bridge` 在该桥声明 webhook 入站面但 `webhook_router` 返回 `None`(如 Feishu `encrypt_key` 缺失)时返回 `BridgeError::Config` 拒绝启动,而非降级为无入站面的“健康”进程。10 个纯 webhook 桥重写为 `true`,gateway 桥(discord/slack/telegram/zulip)保持默认 |

## Todo(尚未落地的共享层待办)

- **(messaging) 日历桥接接入点未补**(BRG-HYG-001,2026-06-29 登记):`calendar.rs` 的
  日历事件 / RSVP 映射守卫(`bridge_calendar_schedule_fields` / `bridge_rsvp_payload` /
  `CALENDAR_EVENT_PROFILE`)已实现并有单测,但 `MessageContext` 上**已补一个最小提交入口
  `submit_calendar_event`**(走映射守卫 → `ck.object.create` 形态留待协议确认),仍**无任何
  adapter 接通**(无桥把外部日历事件喂进来)。待办:确认日历事件的权威 payload/operation 形态后,
  补至少一个桥(如有原生日历事件的平台)的接入示例。

- **(messaging) 入站删除 `submit_app_delete` 无 adapter 接通**(BRG-HYG-002,2026-06-29 登记):
  共享层链路完整且有单测,但没有桥构造 `InboundAppDelete` 调用它。阻碍点:
  (a) 多数平台的删除 gateway 事件(如 Discord `message_delete`)**不带执行删除的 actor**,而
  `submit_app_delete` 需要 `app_user` 做 ghost 映射;(b) 需要桥订阅删除事件 intent。待办:为有
  完整删除事件(含 actor)的平台接一个示范桥;若平台不带 actor,需先定 ghost 归属规则。

- **(messaging) 出站删除 `redact_in_app` / `on_ephemeral` 全默认 no-op**(BRG-HYG-003,
  2026-06-29 登记):驱动链路(`on_cokret_event` 收 `ck.message.redact` → 反查 app_message_id →
  调 `redact_in_app`)已就绪,但无桥 override。阻碍点:`redact_in_app(ctx, app_message_id)`
  只传 app 消息 id,而多数平台的删除 API(如 Discord `delete_message`)还需要 **channel id**,
  当前回调签名不带。待办:把 `redact_in_app` 的回调签名扩成带 `(app_channel, app_message_id)`
  (共享层 trait 签名变更,触及全部桥),再示范接一个桥;`on_ephemeral` 同理按需 override。
