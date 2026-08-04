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
| 2026-07-29 | runtime + messaging | 迁移到现行 SDK wire：入站 `EphemeralEnvelope`/`req.ephemeral` 改为 encrypted-only `SignalEnvelope`/`req.signals`，队列与 adapter hook 改名为 Signal 且不再读取外层不存在的明文 kind/payload；Event authoring 改用签名 `ScopeRef`，签名器改为 `Ed25519PayloadSigner`，service kind / applet protocol field definitions 跟随现行 owner/字段名。出站新增 `submit_initial` 与 host 可注入的 `EventInitialSubmissionProvider`；旧 convenience flows 通过 provider 取得真实 wrapper，未安装 provider 时在网络请求前 fail closed，不伪造 lease。 |

| 2026-07-31 | runtime | 随 SDK `DidUrl` 强类型迁移修编译（`AppletHandler::resolve_verification_method(&DidUrl)`、`Ed25519PayloadSigner`/`sign_event` 的 `DidUrl` 形参、`Proof.verification_method` fixture），并落地 DID-P1-B01/B02：新增 `crates/runtime/src/did_binding.rs`，把通用网络 resolver 收进 `DidAuthority`（私有字段、无 accessor，全仓唯一构造点），`web.rs::verify_transaction_events` 改为只接受无 resolver 的 `AcceptedDidBindings`，普通 transaction 的 DID 解析增量为 0；HTTP Message Signature 走 `purpose=service` 的 config 锚定 binding，Event proof 走 `purpose=principal` 的 accepted binding，两者因 store key 不同不可互换。`ArkretConfig` 新增 `verification_method_for(actor) -> DidUrl`（`verification_method_id` 仍是 `#fragment` 配置形态），`ArkretEdge::service_verification_method()` 返回类型由 `String` 改为 `DidUrl`（messaging `ghost.rs` 同步）。 |
| 2026-07-31 | runtime | 收敛到 SDK 的 canonical digest / Event proof API，删除 `did_binding.rs` 的四处本地实现：(1) `document_evidence_placeholder`（值只是 `f(did)` + 两个硬编码字符串，不承载任何 method evidence）改为 SDK `EvidenceEnvelope`——resolve 两条路径走 `resolve_and_verify_binding_with_evidence` + `DeferredEvidenceResolveRequest`，在**已解析 document** 上算 `EvidenceEnvelope::for_document(doc, policy_digest)`；config 锚定的 service binding 改为同一 envelope + `method.source_key_state_digest` 扩展成员（不再把 key-state digest 原样当 evidence）。(2) 手写的 `resolver_policy_digest` JSON 快照（含 `fail_mode → "fail_closed"` 手写映射）改为 `arkret::identity::policy_digest`（`ak.did.resolver_policy.v1`，`fail_mode` 由 SDK `ResolverFailMode::as_str()` 承担），跨仓同一 `ResolverPolicy` 现在产出同一 digest。(3) `web.rs::verify_transaction_events` 的「取公钥 + `verify_ed25519_detached_jws_proof`」两步改为一次 `verify_event_proof_with_binding`（保留 Event profile 头部严格性，额外复核 binding 状态 / method↔issuer / pinned document digest）。(4) 本地 `AcceptedDidBindings::public_key_material` 及其为兼容 `#key-1` 写法而加的 `#{fragment}` 重试整体删除，全部改用 `arkret_identity::public_key_material_from_binding`（SDK `basics.rs` 与 `verifier.rs` 的查找语义已收敛）。**行为变化**：`policy_digest` 是 store key 的一维，换算法后已存 acceptance 会一次性全部不可达并重新建立（预期，非 bug）；SDK 的取公钥路径会把发布材料解码成 `VerifyingKey`，非法曲线点在查表时即拒（收紧），`did_binding.rs` 测试 fixture 相应改用真实 Ed25519 公钥。 |

## Todo(尚未落地的共享层待办)

- **(runtime) Event signer binding 的 version / epoch 维度目前为空**
  (2026-07-31 登记):`did_binding.rs` 的所有 binding 都以 `version_id: None` +
  `LimitedTrustReason::MethodHasNeitherHistoryNorVersion` 记录 limited trust。原因有二:
  (1) bridges 全仓不参与 Applet registration，拿不到 `registration_epoch`
  （`AppletPackage` 由安装该 applet 的 Arkret node 持有，transaction body 与配置都不携带），
  按 `applet-integration.md` §12 改用该方向规定的 “source service DID key-state evidence”
  （即既有的 `source_key_state_digest`）作为 evidence 维度;
  (2) `CompositeDidResolver::resolve_did` 只返回裸 `DidDocument`，没有 `history_head` /
  `version_id` 可 pin。若将来 SDK resolver 暴露 webvh version evidence，应把它填进
  `BindingAcceptanceTerms` 并让 store key 的 `version_id` 生效。
  2026-07-31 收敛到 SDK `EvidenceEnvelope` 后**结论不变**：envelope 只是让 evidence 变成
  可重算的形状（`document_digest` + `policy_digest` + `method{}`），并没有让
  `registration_epoch` 或 webvh version evidence 变得可达；resolve 路径的
  `method_proofs` 因此仍为空数组。

- **(messaging) 其余平台出站删除 `redact_in_app` 接线未完成**(BRG-HYG-003,
  2026-06-29 登记):驱动链路(`on_arkret_event` 收 `ak.message.redact` → 反查
  `(app_channel, app_message_id)` → 调 `redact_in_app`)已就绪,Discord 已作为示范桥接线。
  待办:按平台能力补其余桥的 `redact_in_app`;现行 Signal 是 encrypted-only envelope，
  LINE typing 不能再从外层读取 kind/payload。若要恢复 loading indicator，host 必须提供
  合法解密后的 typed Signal 派发边界，不能由桥猜测 ciphertext 内容。

- **(runtime + messaging) 为标准 bridge 进程接入 publication evidence provider**
  (2026-07-29 登记):现行 `events_submit` 只接受
  `EventInitialSubmission { event, authorization_lease, cba_proof_bundles[] }`。runtime 已提供
  `ArkretEdge::submit_initial` 及 `EventInitialSubmissionProvider` 注入点，message/redaction/
  portal-strand/bridge-error convenience flows 会把最终签名 Event 交给 provider，并校验 wrapper
  没有替换或改写 Event。当前各独立 bridge binary 尚无 issuer/authz 集成，未安装 provider 时
  会在发送前 fail closed。待 host 提供与最终 actor/scope/action/basis 绑定且 authority-signed
  的 lease（以及需要的 CBA bundles）后，在 adapter factory 中通过
  `MessageContext::set_initial_submission_provider` 安装；不得由 bridge 用 access token、
  grant ref 或本地 signing key 制造替代 lease。
