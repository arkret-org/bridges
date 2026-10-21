# arkret-applets

arkret 协议的桥接(bridge)applet 集合,与 `palpo-im` 的 `matrix-bridge-*` 一一对应,
把 **arkret 去中心化协作协议** 与各第三方 chat app 互联。Rust 实现,技术栈 salvo + diesel,
协议侧基于 [`arkret-rust-sdk`](../arkret-rust-sdk)。

## 结构

Cargo workspace,所有 crate 位于 `crates/`(文件夹名去掉 `arkret-bridge-` 前缀,
包名仍为 `arkret-bridge-*`)。例:`crates/discord/` ⇒ 包 `arkret-bridge-discord`。

共享层拆为两个 crate(均在 `crates/` 下,目录名与包名不同):

- `crates/runtime/` ⇒ 包 **`arkret-bridge-runtime`**:与聊天无关的**通用桥运行时**——arkret 接入
  (`ArkretEdge`/`BridgeAppletHandler`)、DB 连接池、salvo web、队列/缓存、配置/日志,契约是
  泛型 trait `BridgeApp`(收发裸 `arkret::Event`)。非聊天集成(IoT/工单/CI)可直接实现它。
- `crates/messaging/` ⇒ 包 **`arkret-bridge-messaging`**:在 runtime 之上的**消息层**——频道/
  用户/消息映射表、`ak.message.create` 转换、actor/realm 反查解析、webhook 助手,契约是
  `MessageBridge`/`MessageContext`(14 个聊天桥都实现它,经 `run_message_bridge` 装配)。

| crate(包名) | 对端 app | 应用侧技术 | 端口 |
|---|---|---|---|
| `arkret-bridge-runtime`(`crates/runtime`) | — | 通用桥运行时(arkret 接入/DB/web/队列) | — |
| `arkret-bridge-messaging`(`crates/messaging`) | — | 消息层(映射/`ak.message.create`/webhook 助手) | — |
| `arkret-bridge-discord` | Discord | serenity gateway | 9101 |
| `arkret-bridge-telegram` | Telegram | teloxide | 9102 |
| `arkret-bridge-slack` | Slack | tungstenite socket mode | 9103 |
| `arkret-bridge-feishu` | 飞书 | reqwest | 9104 |
| `arkret-bridge-wechat` | 微信 | reqwest | 9105 |
| `arkret-bridge-dingtalk` | 钉钉 | reqwest | 9106 |
| `arkret-bridge-zulip` | Zulip | reqwest event queue long-polling | 9107 |
| `arkret-bridge-whatsapp` | WhatsApp | reqwest (Cloud API) | 9108 |
| `arkret-bridge-line` | LINE | reqwest | 9109 |
| `arkret-bridge-qq` | QQ | reqwest (OneBot/官方) | 9110 |
| `arkret-bridge-googlechat` | Google Chat | reqwest | 9111 |
| `arkret-bridge-imessage` | iMessage | reqwest (网关) | 9112 |
| `arkret-bridge-messenger` | Messenger | reqwest (Graph API) | 9113 |
| `arkret-bridge-teams` | MS Teams | reqwest (Bot Framework) | 9114 |

## 架构

每个桥都是一个 arkret **Applet**:

- **管理接入**：HTTPS `arkret.applet_base_url` 用于发现、主体 authoring 与签名 completion。安装只接纳 Service，Bot／Ghost 通过单个 `ak.realm.actor.create` 建立 Realm Actor 身份及独立 DID。
- **入站(arkret → app)**：群内容由具体 Realm Actor 的 accepted Device 从原生数据面获取。`BridgeAppletHandler` 拒绝群 transaction 推送；启用 `device.mls` 后，Device reader 验证 Welcome、原签 stream 与 MLS 群状态，并耐久交付解密消息。支持媒体的消费者单独取得经过当前权限核验和解密的附件。
- **出站(app → arkret)**:适配器收到 app 消息(gateway/长轮询/webhook)→
  `MessageContext::submit_app_message` → 查找已持久化的 per-user Ghost Actor 映射；首次用户通过
  Station preview → Applet `managed-actors/author` → Station commit 创建正式
  Ghost，再构造带 `external_ref` 溯源的 `ak.message.create` 事件并提交。Ghost WebVH root/next key
  使用独立随机材料和配置的 32-byte key 加密落库；author ledger 按完整请求 digest 保存 exact
  bundle，按完整 scope 与外部 tuple 隔离身份，支持并发、重启和成功请求过期后的逐字重放；已接受 Ghost 复用原创建记录与完整 Realm ActorId，不创建另一份身份。纯 HTTP 桥的入站经各自
  `MessageBridge::webhook_router` 挂到 web 服务,平台来源验签在 handler 解析 JSON 前完成。
  部分桥(WeChat / Feishu / DingTalk / iMessage / QQ / LINE 等)的入站还需要 body-bound
  验签材料(EncodingAESKey / Encrypt Key / 注入式 HMAC secret / signing secret);缺失时入站面
  **fail-closed**:WeChat 整类 POST 投递被拒(仅 GET 握手可用),Feishu 直接不挂载 webhook 路由,
  且声明 webhook 入站面的桥若 `webhook_router` 因此返回 `None` 会在**启动期 fail-fast**(不会降级为
  无入站面的“健康”进程)。配齐 access token 不等于入站可用,还须配齐这些 body 验签材料。
- **映射 / 解析**:频道↔realm、消息↔event、用户↔actor 持久化于 diesel(sqlite/postgres);
  反查驱动 applet `resolve_actor`/`resolve_realm`(ghost/portal 读侧解析)。用户↔actor 映射
  同时参与 app→arkret 写侧署名。创建身份不授予消息权限，实际业务必须由有效的 Service parent／terminal child 和 Station 持续准入证明。
- **提交与定序**:出站 Event 由桥自己 author + 签名,再提交给当前治理 Station;
  Station 返回 authority-signed `RealmCommit`,它才是该 Event 的唯一位置事实。
  Realm、每个 Circle、每个 Sidecar 各有独立 commit stream,桥不合并、也不比较跨 stream 的位置。
  桥侧持久层只保存冻结的签名字节与 accepted 后的 exact `CommittedEventRef`。
- **消息内容**:使用 SDK `MessageCreatePayload` 与 `ContentBlock`；附件使用 SDK `EncryptedAttachment`，存储站只接收密文和最小加密分类。
- **媒体**:`MessageContext::forward_external_media` 经 Realm Actor Device 加密上传；`Attachment` 中的本地明文由 native runtime 验证后提供；
  discord/telegram 收发双向,whatsapp/line/slack/messenger/zulip 入站已接,余者文本
  (通用能力就绪)。
- **防回声**:`on_arkret_event` 跳过本桥 `external_ref.source` 自发事件、由本桥
  service actor 署名的事件,以及已在消息映射表记录的 event,避免出站回环。

详见 [`_BRIDGE_CONTRACT.md`](_BRIDGE_CONTRACT.md)(适配器编写契约)。

## 构建

```bash
cargo check --workspace
cargo run -p arkret-bridge-discord -- --config config.yaml
```

每个 crate 默认启用 `sqlite` feature。PostgreSQL 构建必须关闭默认 features，
例如 `cargo check --workspace --all-targets --locked --no-default-features --features postgres`。
仅追加 `--features postgres` 会同时保留 SQLite，不能验证 PostgreSQL 后端。

CI 的两组有效集合覆盖所有 provider binary、messaging 和 runtime：

| 集合 | Clippy | 测试 |
|---|---|---|
| 默认 SQLite | `cargo clippy --workspace --all-targets --locked -- -D warnings` | `cargo test --workspace --locked` |
| PostgreSQL-only | `cargo clippy --workspace --all-targets --locked --no-default-features --features postgres -- -D warnings` | `cargo test --workspace --locked --no-default-features --features postgres` |

Ubuntu 需要 `pkg-config`、`libssl-dev`（provider 原生 TLS）与 `libpq-dev`（PostgreSQL）；
SQLite 由 runtime 的 `libsqlite3-sys/bundled` 编译。PostgreSQL 测试还需独立 UTF-8 数据库，
通过 `BRIDGES_TEST_DATABASE_URL` 提供；CI 使用独立 PostgreSQL 18 service。
MSRV 检查保留默认 SQLite 集合：`cargo check --workspace --all-targets --locked`。
跨仓依赖证据继续使用 SDK 现有 compatibility manifest/runner；其 all-features 检查
会保留 SQLite，不能替代这里的 PostgreSQL-only 集合。
配置文件使用 YAML。
HTTP 宿主还必须配置 `arkret.service_resolution`：填写身份生成器导出的完整 SDK
`AuthenticatedServiceResolution` 对象（YAML 中可直接嵌入 JSON），其中 `service_kind`
为 `applet_service`，DID、当前 assertion method 和公钥必须与本宿主配置一致。
这是公开的原生 DID 日志、见证与文档，不含私钥；不能用一个 DID 字符串或自填摘要替代。
缺少材料、历史被篡改、角色错误或签名密钥不匹配时，HTTP 宿主拒绝启动。
`edge` 出站嵌入可由独立身份宿主发布材料，但启用共享 HTTP 路由时同样需要完整材料。
反向代理需要公开 `/_arkret/describe`、`/_arkret/open/services/{service_id}/resolution`
以及 Service DID 对应的 `did.json`、`did.jsonl` 和见证路径；这些路径由共享运行时发布。
Service 轮换时原子替换完整公开历史与当前签名密钥后重启，不改写旧日志；Bot／Ghost 的
独立控制私钥仍由各主体的加密存储保管，不写入上述公开对象。
所有桥都必须显式建立 app channel 到 Realm 的映射；没有 channel-realm mapping 的入站消息会直接失败,
不再回退到默认 Realm。
推荐在配置文件的 `mappings` 段声明静态映射；各桥 `config.sample.yaml` 均包含注释样例,启动时会自动 upsert。

三个信任面绑在**两个独立监听**上,默认即隔离,不再仅靠反代 path 规则:

- **公网 webhook 面**(`/webhooks/*`,Teams 另含 Bot Framework 的 `/api/messages`):
  绑 `webhook_bind:port`,默认 `webhook_bind=0.0.0.0`,必须可被对应平台回调可达。
- **内网 admin/edge 面**(受信协议面 `/_arkret/edge/applet/*`、运维面 `/health`、
  `/metrics` 与 operator 命令面 `/admin/*`):绑 `admin_bind:admin_port`,默认
  `admin_bind=127.0.0.1`(仅回环),`admin_port` 省略时回落到 `port + 1000`。即使不配
  反向代理,协议面与运维面也默认不对公网开放。

`/_arkret/edge/applet/*` 配置 `trusted_server_did` 与 `trusted_verification_methods` 后会
校验 HTTP Message Signature、source/destination DID 与 event proof;生产仍建议在反代/网络层
进一步限制为仅可信 Arkret server 访问,并对 `/metrics` 做内网或认证访问控制。若需把 admin/edge
面也对外(如 arkret server 在另一网段),显式设置 `admin_bind` 即可,但应自行收敛网络层暴露面。

**DID binding 失效(operator 命令面)**:spec `identity/did-usage-and-verification.md`
§5.6 要求 rotation / deactivation / witness fork / explicit revocation **必须**使受影响的
DID binding 失效。bridge 不持有 resolver、也收不到上游 rotation 通知,因此**该义务的运行时
触发责任在 operator**:得知受信 server DID 发生上述事件后,operator 必须在 admin 面调用失效
端点(随后按新 key 更新 `arkret.trusted_verification_methods` 并重启;失效后、重新播种前的
入站推送会 fail-closed 被拒——这正是 revocation 期望的行为):

```bash
curl -sS -X POST http://127.0.0.1:<admin_port>/admin/did-bindings/invalidate \
  -H 'content-type: application/json' \
  -d '{"did": "did:webvh:...:server.example"}'
# => {"ok":true,"did":"...","trust_domain":"...","invalidated_bindings":1}
```

body 可选 `trust_domain` 字段作误操作护栏:填写时必须等于该 bridge 配置的 trust domain,
否则 409 拒绝且不清扫。清扫是 §5.6 认可的 `for_did` 粗粒度安全下界,幂等,
`invalidated_bindings: 0` 也是成功。该端点与 `/health`、`/metrics` 同等暴露方式——仅靠
admin 面默认回环绑定隔离,无请求级鉴权;若显式放宽 `admin_bind`,必须在网络层/反代收敛
整个 admin 面的可达性。

公网 webhook 面**默认启用每源 IP 速率限制**(`bridge.webhook_rate_limit`,默认
`enabled: true`、`max_requests: 600`、`window_secs: 60`,即每 IP 持续 10 rps),用于无反代
裸跑时的基本抗泛洪;阈值刻意宽松,正常单租户回调远达不到。注意:部分平台的**重投风暴**
(如 Meta 对 5xx 的批量重投)可能从少量回调 IP 集中打来,若观察到被限,应按平台回调 IP 段
放宽 `max_requests` 或置 `enabled: false` 改由反代限流。

**重放守卫与 vendor token 缓存均持久化于桥数据库**(`webhook_replay_guard` / `token_cache`
表):重启后 TTL 内的捕获报文无法重放,且同一桥的多副本共享同一守卫与同一 vendor access token
(WeChat 类"取新令旧失效"平台在多副本下因此可用)。水平扩展多副本时,各副本必须指向同一
`database.url`(共享 postgres;sqlite 仅适合单副本)。

## 容器发布

仓库提供一个统一的多阶段 `Dockerfile`,通过 `BRIDGE_BIN` 选择要打包的桥二进制。由于 workspace
依赖 sibling `arkret-rust-sdk`,Docker build context 必须是同时包含 `bridges/` 与
`arkret-rust-sdk/` 的父目录:

```bash
docker build -f bridges/Dockerfile \
  --build-arg BRIDGE_BIN=arkret-bridge-slack \
  -t arkret-bridge-slack:local .
```

tag 推送会触发 `.github/workflows/release.yml`,矩阵构建 14 个桥镜像并推送到 GHCR,同时生成
CycloneDX SBOM;tag 发布的镜像会通过 keyless cosign 签名。


### Publication storage

The edge derives each Event's one content-bound identity, signs it, and freezes
it under the upstream delivery identity before transport. The frozen bytes, the
settled Station answer and the exact `CommittedEventRef` of an accepted
publication are stored in separate rows written in one atomic batch. A terminal
Station rejection settles the publication without claiming the Event can never
be accepted; replaying that logical delivery preserves its exact signed bytes,
and an accepted publication keeps its committed reference forever.

Edge-only deployments use `FileAuthoringStore`, backed by redb with immediate,
two-phase durable transactions. All instances of the same canonical path in one
process share its database owner. A second process cannot open that file. Use the
PostgreSQL or SQLite authoring backend for deployments with multiple processes.
Any storage error poisons the shared file owner: reads and sends stop until every
owner closes and reopening completes a successful durability barrier. Never copy
an open database file or treat a failed commit as proof that its changes rolled
back.

The indexed path does not load or rewrite prior completed publications. The
ignored `indexed_journal_growth_1000_10000_100000` test records real file growth
and elapsed time at those sizes; ordinary unit tests do not imply that this
benchmark has been run. Bootstrap authorization evidence is a separate
requirement from the publication journal.

## 正式治理同步（0160）

`ArkretEdge::prepare_bot_provision` 在已安装 Service 身份下运行 Station preview → HTTPS base_url author，并返回必须原样持久保存的 creation body；`provision_bot` 使用原 signed request digest 重试提交，不隐式追加业务 grant。

Service 管理请求使用 SDK RFC9421 来源／目标签名，不申请 Applet session。`ArkretEdge::managed_device_client` 使用完整 Realm ActorId、accepted authorization Event、精确 scope 与独立 Device key。普通 AccountId 与 PCR 不用于 Applet Bot／Ghost 身份。

已经接通独立身份创建、首 Device、成员加入、Service parent 与 terminal child、原生 Welcome／群状态／consume／ACK、stream 解密、加密消息与附件收发、精确重试及本地存储冷恢复。附件上传不授予消息发布或读取权；读取仍核验 accepted 消息来源及当前设备／安装／内容权限。纯文本消费者不会取得附件明文。Circle 首次上传已按正式裁决使用治理方验证的创建目标和不可变私有绑定，生产联合验证仍在进行。

Circle 主体可用 `prepare_ghost_in_scope` 发起现有 authoring 流程；创建不自动加入父 Realm 或 Circle。`join_circle_after_realm_join` 使用主体本人已接受的父 Realm 加入 Commit，并由 Circle Device 原签 Circle 加入。两者分别需要现有安装、原签 Device 范围和原有加入授权；父 Realm 设备可只含 `ak.applet.join`，不必取得父 Realm 的上传或内容读取权限。没有获准的父加入来源时保持未就绪，不由管理员代写第三方 join。

创建 scope 内的本人 Realm join 使用原 accepted create 的 `creation_authorization_ref` 作为安装来源，不按业务 grant 排序猜测。公开的跨 scope 加入 API 要求调用者先以 `remember_installation_outcome(&scope, &outcome)` 登记该 scope 真实安装 HTTP 响应的 SDK `AppletInstallOutcome`；没有此输入就保持未就绪。该记录只是本地候选来源，每次使用仍读取正式 authority/material、验证当前 scope／Service／Applet／epoch，最终由 Station 检查 exact installation；不能自行构造一个成功 outcome、复用另一 scope 的 grant 或把 `current_binding=active` 当作授权。现有 portal、消息与附件产品调用均使用 `device_for_actor` 的 creation scope，跨 scope API 不隐式启动额外产品工作流。

此 runtime 的 Realm 消息与加密 portal 由主体 Device 原签。协议允许的 Service 自身写入仍须引用覆盖实际 action/resource 的有效安装授权，Service 签名本身不授予权限。完整 MLS 发起端 worker、主体控制轮换／恢复、持续授权与全部消费者仍需独立验收，不声明全部已登记 operation 的 runtime 已交付。

设备撤销使用 `ManagedDeviceRuntime::revoke_device`，以稳定本地操作标识保存 controller 原签申请；重复标识不能改变目标或原因代码。申请的 Commit 只表示登记，必须由私有材料中的 `device_revoke` 结果确认 pending／accepted／rejected。`reconcile_device_revocations` 与 host worker 会冷续跑原申请及结果查询，pending 不删除密钥。若治理站已接受但本地未保存回执，先由管理 Service 读取已签结果及精确原件，核验后恢复，无须重发控制签名申请。永久 accepted 后，已收取的队列工作完成才通过 `erase_revoked_device` 删除设备私钥、MLS 私态和附件私有检查点；保留公开授权原件、最终材料和退役标记，原设备创建操作不能自动换钥重建。拒绝与未知结果不视为永久撤销。Realm／Circle 真实 HTTPS 与 PostgreSQL 联合测试已覆盖丢回执冷恢复、pending 保留密钥、生产终态任务、清理和防重建；其它生命周期与完整 operation 验收仍在进行。

Managed Principal custody and the canonical Bot/Ghost author operation live in
`arkret-bridge-runtime` behind `managed-authoring`.
`ManagedActorAuthoringService` is shared with Savfox; the messaging layer only
adapts first-seen external users to that same authority. The private identity and
exact authoring ledger use its existing atomic `AuthoringStore` host port. The root,
next-root and operational controller seeds remain separate and encrypted with the
explicit deployment key. Principal custody alone does not provide the MLS runner.

The authoring router also publishes the retained Principal's native
`/webvh/<local_id>/did.json` and `did.jsonl` resources. The publication URL index is
written atomically with private custody and only returns its verified public
inception history. Configure the Principal endpoint's HTTPS origin to reach this
host. Unknown identities return no material; rotation remains a separate native
history installation obligation.

受管 Bot／Ghost 的首 Device 可通过 `managed_actor_authoring.device` 显式启用：
`actions` 为非空 capability 列表，`lifetime_seconds` 为正数有限时长。默认关闭。
共享 runtime 在验证原创建 completion 后，先于请求保存加密 Device／HPKE 私钥与
Principal 原签授权；后台重试与重启沿用同一原件、exact 创建 scope 和期限。
Device接纳不授予业务权，也不自动加入Realm／Circle。显式device.mls启用独立Welcome worker；消息stream、附件与回复由同一原生设备 runtime 分别核验和处理。

`device.mls = true` 启用耐久原生MLS KeyPackage库存与每个Device独立的Welcome worker，
`key_package_inventory_target` 默认为 8（1..=1000），每周期最多补 20 个。
私有 identity、完整私有 KeyPackage bundles 和原签 batch 在同一次原有加密 custody CAS 中提交，
先于 HTTP；重启／丢响应／outcome 落盘失败均重投原 batch，不重新生成已在途材料。
只有已持久确认的 upload outcome 才计入 SDK 本地 inventory；该 inventory 不是服务端可 claim 状态的证明。
发布仍依赖实际 membership／独立 E2EE consent、原授权 scope、current 安装与 Station 业务门；
它不自动加入群。读取还要求原签scope项含ak.event.read、当前Service读取上界及实际membership／E2EE同意。

worker绑定完整Realm Actor／Device／authorization／scope、有限授权窗口与当前host实例。队列页先耐久保存；Welcome须验证实际accepted Commit、原历史producer、本人claim receipt、完整signed roster和Genesis材料，才由SDK用本地私有包加入。群状态、scope私有identity与原签consume同一加密CAS落盘后才发送consume／累计ACK；丢响应重投相同签名请求，重启恢复原游标。补包同步刷新同一群provider，防止冷恢复丢失新私有包。host退出立即退休reader，各Device网络周期最多八路并发。扩scope或续期仍须合法replacement authorize，不自动改写原授权。

worker 消费已有正式 scope 的 Welcome 和内容 stream，附件按消费者需要解密；已有群的重新加入、完整 MLS 发起端与 Principal rotation 继续独立验收。群内容不发往管理 base_url。
