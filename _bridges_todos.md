# 共享层变更 / 待办登记(bridges)

- 2026-09-13: ordinary authoring 持久层改为 indexed atomic CAS；file 后端使用 redb，删除自制 JSONL 整段历史重写，增加写入/同步失败 poison 与掉电恢复回归。真实 1k/10k/100k 增长测试为显式 ignored benchmark，尚待统一执行。

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
| 2026-07-15 | teams | Teams override `redact_in_app`,用 conversation id + activity id 调 Bot Framework `DELETE /activities`。至此出站删除接线的桥为 Discord + Teams;其余 12 桥保留共享层的 fail-closed 默认(返回 `BridgeError::App`),按各平台删除 API 能力逐桥补齐,属单桥 adapter 事项,不再在本文件登记。 |
| 2026-07-16 | runtime | `arkret_edge.rs` 出站传输策略注释的 `cleartext` 改为 `plaintext`，对齐 `forbidden-model-terms.json` hard_reject 条目（该条目明确覆盖 code comments）。仅注释,无行为变更。 |
| 2026-07-29 | runtime + messaging | 迁移到现行 SDK wire：入站 `EphemeralEnvelope`/`req.ephemeral` 改为 encrypted-only `SignalEnvelope`/`req.signals`，队列与 adapter hook 改名为 Signal 且不再读取外层不存在的明文 kind/payload；Event authoring 改用签名 `ScopeRef`，签名器改为 `Ed25519PayloadSigner`，service kind / applet protocol field definitions 跟随现行 owner/字段名。出站新增 `submit_initial` 与 host 可注入的 `EventInitialSubmissionProvider`；旧 convenience flows 通过 provider 取得真实 wrapper，未安装 provider 时在网络请求前 fail closed，不伪造 lease。 |
| 2026-07-29 | runtime | `ArkretEdge::new` 默认安装 `StationSubmissionProvider`（转调 SDK `Client::prepare_initial_submission`），标准 bridge 进程的出站发布证据链路因此已闭合，不再存在"未安装 provider 就 fail closed"的常态。`set_initial_submission_provider` 保留为**另一条生产 authority 传输**（例如延迟发布 / 本地 authority 组件）的覆盖点，返回的 wrapper 仍在发网络请求前校验 Event 未被替换或改写；仍不得由 bridge 用 access token、grant ref 或本地 signing key 制造替代 lease。 |
| 2026-07-31 | runtime | 随 SDK `DidUrl` 强类型迁移修编译（`AppletHandler::resolve_verification_method(&DidUrl)`、`Ed25519PayloadSigner`/`sign_event` 的 `DidUrl` 形参、`Proof.verification_method` fixture），并落地 DID-P1-B01/B02：新增 `crates/runtime/src/did_binding.rs`，把通用网络 resolver 收进 `DidAuthority`（私有字段、无 accessor，全仓唯一构造点），`web.rs::verify_transaction_events` 改为只接受无 resolver 的 `AcceptedDidBindings`，普通 transaction 的 DID 解析增量为 0；HTTP Message Signature 走 `purpose=service` 的 config 锚定 binding，Event proof 走 `purpose=principal` 的 accepted binding，两者因 store key 不同不可互换。`ArkretConfig` 新增 `verification_method_for(actor) -> DidUrl`（`verification_method_fragment` 仍是 `#fragment` 配置形态），`ArkretEdge::service_verification_method()` 返回类型由 `String` 改为 `DidUrl`（messaging `ghost.rs` 同步）。 |
| 2026-07-31 | runtime | 收敛到 SDK 的 canonical digest / Event proof API，删除 `did_binding.rs` 的四处本地实现：(1) `document_evidence_placeholder`（值只是 `f(did)` + 两个硬编码字符串，不承载任何 method evidence）改为 SDK `EvidenceEnvelope`——resolve 两条路径走 `resolve_and_verify_binding_with_evidence` + `DeferredEvidenceResolveRequest`，在**已解析 document** 上算 `EvidenceEnvelope::for_document(doc, policy_digest)`；config 锚定的 service binding 改为同一 envelope + `method.source_key_state_digest` 扩展成员（不再把 key-state digest 原样当 evidence）。(2) 手写的 `resolver_policy_digest` JSON 快照（含 `fail_mode → "fail_closed"` 手写映射）改为 `arkret::identity::policy_digest`（`ak.did.resolver_policy.v1`，`fail_mode` 由 SDK `ResolverFailMode::as_str()` 承担），跨仓同一 `ResolverPolicy` 现在产出同一 digest。(3) `web.rs::verify_transaction_events` 的「取公钥 + `verify_ed25519_detached_jws_proof`」两步改为一次 `verify_event_proof_with_binding`（保留 Event profile 头部严格性，额外复核 binding 状态 / method↔issuer / pinned document digest）。(4) 本地 `AcceptedDidBindings::public_key_material` 及其为兼容 `#key-1` 写法而加的 `#{fragment}` 重试整体删除，全部改用 `arkret_identity::public_key_material_from_binding`（SDK `basics.rs` 与 `verifier.rs` 的查找语义已收敛）。**行为变化**：`policy_digest` 是 store key 的一维，换算法后已存 acceptance 会一次性全部不可达并重新建立（预期，非 bug）；SDK 的取公钥路径会把发布材料解码成 `VerifyingKey`，非法曲线点在查表时即拒（收紧），`did_binding.rs` 测试 fixture 相应改用真实 Ed25519 公钥。 |
| 2026-08-14 | runtime | 删除 `ArkretEdge::new_outbound`（2026-07-11 那行登记的 outbound-only 构造路径），理由是"本仓无调用者"。**该判定只查了本仓**：仓外下游 `../savfox-ai/savfox/crates/gateway-server/src/channels/arkret_applet.rs` 仍在调用它，并以 `default-features = false, features = ["edge"]` 依赖本 crate，因此该下游当时编译不过。`SeqAllocator` / `FileSeqStore` / `Config` 等同批 edge 面仍在。删共享层 pub 面前必须把 savfox 一并当消费者查。 |
| 2026-08-18 | runtime | 恢复 `ArkretEdge::new_outbound`（实现逐字取自被删提交 `26cce50` 的 git 历史）：savfox 是 bridges 共享层的已确认真实消费者（空 feature `edge` 亦为它保留），恢复成本低于改消费者。Cargo.toml `edge` 注释、lib.rs crate 文档与函数 doc comment 均注明外部消费者约束；`_BRIDGE_CONTRACT.md`「不要做」新增流程规则：删共享层 pub 符号前消费者证据必须包含 `../savfox-ai/savfox`。 |
| 2026-08-19 | runtime + messaging | 死代码清理（所有判定均双仓 grep：本仓 + `../savfox-ai/savfox`）。删除：`ArkretEdge::config()` accessor（双仓 0 调用）、runtime lib.rs 对 `IdempotencyIdentity`/`TransactionClaim`/`TransactionIdempotencyStore` 的 re-export（仓内 web.rs/db.rs 与 savfox 全部直连 `arkret`）、`Config::from_yaml`（生产只走 `Config::load` → 私有 `from_yaml_with_base_dir`，3 个测试改调后者）、`set_initial_submission_provider` 覆盖点（runtime + messaging 两处：2026-07-29 登记保留的「另一条生产 authority 传输」至今双仓零调用且无具体接入计划，savfox 出站链路用的是它自建的 `ArkretInitialSubmissionProvider`；provider 随之固定为构造期安装，`Mutex` 包装移除）。可见性收缩（非删除）：`InboundMediaReference`/`InboundMediaFetchPolicy`/`InboundMediaFetcher`/`HttpInboundMediaFetcher`、`MessageContext::submit_media_message`、`MAX_WEBHOOK_BODY_BYTES` 收为 crate 内——桥侧媒体入口统一是 `forward_external_media`；`InboundMediaAuthorization` 被 slack/zulip/line/whatsapp 四桥使用，保持 pub。复核后**保留**：`DidAuthority::invalidate_did`（spec `identity/did-usage-and-verification.md` §5.6 MUST：rotation / deactivation / witness fork / revocation 必须失效受影响 binding，`for_did` 清扫是该节声明的安全下界；待接线：rotation 通知 → `invalidate_did` 的运行时触发路径——**已于 2026-08-20 接线，见下行**）。 |
| 2026-08-20 | runtime | 接线 2026-08-19 行保留的 `DidAuthority::invalidate_did` 运行时触发路径：admin 面新增 operator 命令端点 `POST /admin/did-bindings/invalidate`（body `{did, trust_domain?}`，`trust_domain` 为误操作护栏，不匹配则 409 拒绝不清扫），直达 `invalidate_did` 的 §5.6 `for_did` 域内粗清扫，幂等（清扫 0 条也是 200）。选 admin 端点而非 CLI 子命令：bridge 是常驻进程，binding store 在进程内存里，CLI 子命令够不到运行中进程的 store；暴露方式与 `/health`、`/metrics` 一致（默认回环绑定、无请求级鉴权，BRG-06-004）。新增指标 `arkret_bridge_did_binding_invalidations_total`；`did_binding.rs` 模块文档的失效引用「§4 row 7 / policy-change invalidation」（已被 spec 移除）订正为 §5.6；触发责任归属写入 README「DID binding 失效」段。**不含** §5.6 的 evidence dependency 反查 selective invalidation：bridge 的 config 锚定 binding 走 `MethodEvidence::none()`，非 evidence-bearing，该 MUST 不落在 bridges 头上。测试经 salvo `TestClient` 走真实挂载路由覆盖清扫 / trust-domain 护栏 / 非法 DID / 幂等四类路径（runtime dev-dependencies 增 salvo `test` feature，仅测试构建生效）。 |
| 2026-08-23 | runtime | 死代码清理复核（双仓 grep 本仓 + savfox，全量 pub 符号与依赖均有消费者，无删除）。仅订正过时文档：`arkret_edge.rs` 模块文档与 `lib.rs` crate 文档仍引用已删除的 `mint_event_unsigned_async`/`mint_event_as_unsigned_async`/`resign_event` 与 "asynchronous unsigned-mint methods" 措辞，改为描述现行 `service_intent`/`delegated_intent`/`author_and_sign`/`submit_event` 面。仅注释,无行为变更。 |

| 2026-09-13 | runtime + messaging | 删除全局批量序号预留及旧文件存储，改用 SDK Realm/完整 Actor frontier 与持久 CAS publication journal；发送前冻结完整签名 Event，未知结果原件重试，receiver-local 拒绝释放当前槽但保留历史原件；新 operation 合并完整已观察 siblings，按 16/64 上限限制候选。Savfox 同步使用真实交付 ID 和恢复 worker。静态完成，真实编译及崩溃/多站联合验收仍待执行。 |

| 2026-09-16 | runtime + messaging | authority-commit clean break。出站改为 author + 签名 + 提交当前治理 Station，`EventCommitSubmission` 是唯一提交 DTO，accepted 后保留 exact `CommittedEventRef`；新增 `runtime::authority` 协议核心（submission queue / stream cursor book / join bootstrap / handoff / producer 与 managed-actor proof 校验）。publication journal 改为「每个稳定 operation id 一条不可变冻结记录 + 原子结算行」，表名 `ordinary_authoring` → `authoring_journal`。ghost portal strand 的 §10.1 最早生效判定改用 Realm 自己的 commit stream 升序扫描。`user_mappings.profile_event_ref` / `accountability_grant_ref` 改存完整 canonical `CommittedEventRef`。`scripts/deletion_gate.sh` 增加 22 条零基线禁用标识。**未闭合**：`build_ghost_bundle` fail-closed，因 SDK 只剩验证侧、没有 producer 侧 bundle authoring API，详见 [`CAPABILITY-MIGRATION.md`](CAPABILITY-MIGRATION.md)。 |

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
