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

- **管理接入**：HTTPS `arkret.applet_base_url` 用于发现、主体 authoring 与签名 completion。安装只接纳 Service，独立 Bot／Ghost 通过四 Event provision 接入。
- **入站(arkret → app)**：群 Event／Signal 只能由具体受管 Account 的 accepted Device 从原生数据面获取。`BridgeAppletHandler` 已禁止旧群 transaction 推送；新的 Device reader／MLS Welcome／Blob 执行器尚未接线，当前不会降级到 Service 群订阅。
- **出站(app → arkret)**:适配器收到 app 消息(gateway/长轮询/webhook)→
  `MessageContext::submit_app_message` → 查找已持久化的 per-user Ghost Actor 映射；首次用户通过
  Station preview → Applet `managed-actors/author` → Station commit 创建正式
  Ghost，再构造带 `external_ref` 溯源的 `ak.message.create` 事件并提交。Ghost WebVH root/next key
  使用独立随机材料和配置的 32-byte key 加密落库；author ledger 按完整请求 digest 保存 exact
  bundle，按完整 scope 与外部 tuple 隔离身份，支持并发、重启和成功请求过期后的逐字重放；已接受 Ghost 只复用原四项身份锚点，不创建新的 authoring completion。纯 HTTP 桥的入站经各自
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
- **消息内容**:对齐 SDK 规范类型 `TextMessageContent`(`{body}`)/`MediaContent`
  (`{body,blob,mimetype,filename,size}`)。
- **媒体**:`MessageContext::{upload_blob,download_blob,forward_external_media}` + `Attachment`;
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

每个 crate 默认 `sqlite` feature;`--features postgres` 切换后端。
配置文件使用 YAML。
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

Service 管理请求使用 SDK RFC9421 来源／目标签名，不申请 Applet session。`ArkretEdge::managed_device_client` 组合 SDK 的受限 Device HTTP transport，要求完整 Account、accepted authorization Event、scope 与独立 Device key；真实接纳和 21 项原生 operation allowlist 仍由 SDK／Station 校验。当前已实现 Bot／Ghost producer authoring 和持久 completion，尚未实现首 Device 私有状态／possession、自动 Welcome／ACK／MLS／Blob reader、native resolution rotation installer 与跨 scope current refresh；不声明完整群内容运行时。

Managed Account message/profile/join execution also remains closed: the Service
signer cannot consume a Bot or Ghost terminal child grant. Legacy retained
Service-proxy publications are rejected before replay. Creation/completion and
Service-subject maintenance operations remain available; Ghost message and
redaction helpers require a future native managed-Account/Device executor.

Managed Principal custody and the canonical Bot/Ghost author operation live in
`arkret-bridge-runtime` behind `managed-authoring`.
`ManagedActorAuthoringService` is shared with Savfox; the messaging layer only
adapts first-seen external users to that same authority. The private identity and
exact authoring ledger use its existing atomic `AuthoringStore` host port. The root,
next-root and operational controller seeds remain separate and encrypted with the
explicit deployment key. This does not provide the managed Device/MLS runner.

The authoring router also publishes the retained Principal's native
`/webvh/<local_id>/did.json` and `did.jsonl` resources. The publication URL index is
written atomically with private custody and only returns its verified public
inception history. Configure the Principal endpoint's HTTPS origin to reach this
host. Unknown identities return no material; rotation remains a separate native
history installation obligation.
