# arkret-bridge-<app> 编写契约(子代理必读)

每个 bridge 只实现「app 适配器」,其余全在共享 crate:`arkret-bridge-runtime`(通用桥运行时)+
`arkret-bridge-messaging`(消息层)。**必须**严格按本契约,与参考实现 `crates/discord/` 保持一致
结构,确保 `cargo check` 通过。

> 历史:共享层早期为单 crate `arkret-bridge-core`/trait `BridgeApp`,现已拆为 runtime+messaging,
> 聊天桥实现 `MessageBridge`(不再直接实现 `BridgeApp`)。`BridgeApp` 仍是 runtime 的泛型底座,
> 供非聊天集成直接使用。

## 核心 API(聊天桥用 `arkret-bridge-messaging`;勿改两个共享 crate)

```rust
// arkret-bridge-messaging(lib.rs)—— 聊天桥装配入口
pub async fn run_message_bridge<M, F>(config: Config, factory: F) -> Result<()>
where M: MessageBridge, F: FnOnce(Arc<MessageContext>) -> Result<M>;

// arkret-bridge-runtime 重导出:Config(Config::load(path))、BridgeError/Result、logging::init
pub struct MessageContext { pub http: reqwest::Client, /* + core()/store() */ }
impl MessageContext {
    // 出站:把 app 入站消息作为 per-user Ghost Actor 事件提交到 arkret portal strand,
    // 返回 event_id。payload 按权威 message_create_payload 组装
    // ({strand_id, track_name:"discussion", content: content_block, blob_refs[]}),
    // 外部 location 的映射单位是 (realm_id, strand_id)(applet-integration §10.1):
    // portal strand 按「持久化映射 → projection 按 external_ref 匹配 → ak.strand.create」
    // 顺序惰性解析并缓存在 channel_realm_mappings.portal_strand_id。
    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String>;
}
pub struct InboundAppMessage  { pub app_channel: String, pub app_user: String,
                                pub app_message_id: String, pub body: String }
pub struct OutboundAppMessage { pub app_channel: String, pub sender_display: String,
                                pub body: String, pub attachment: Option<Attachment> }
pub struct Attachment { pub blob_ref: String, pub media_type: Option<String>,
                        pub filename: Option<String>, pub size: Option<u64>,
                        pub caption: String }
pub struct AppMessageRef { pub app_message_id: String }

#[async_trait]
pub trait MessageBridge: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()>;    // app 接收循环
    async fn send_to_app(&self, ctx: Arc<MessageContext>, msg: OutboundAppMessage)
        -> Result<AppMessageRef>;                                             // arkret→app 发送
    async fn redact_in_app(
        &self,
        _ctx: Arc<MessageContext>,
        _app_channel: &str,
        _app_message_id: &str,
    ) -> Result<()> { Ok(()) }
    // 纯 HTTP 桥重写此项,返回入站 webhook 路由(由 runtime web 服务挂载);默认 None
    fn webhook_router(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Option<salvo::Router> { None }
}
```

下行(arkret→app)由 messaging 的 `MessageAdapter::on_arkret_event` 自动驱动 `send_to_app`,
适配器无需自己实现 `on_arkret_event`;只转发 portal strand 上的 `ak.message.create`(§10.1 映射
单位是 `(realm_id, strand_id)`),正文从 `payload.content`(content_block)解析,媒体从
`blob_ref`/`blob_refs[]` 解析。`config.app` 放该 app 专属配置(token 等),由
`bridge_main` 经 serde 反序列化成每桥自定义的强类型 `AppConfig`(缺字段由 serde 按字段名报错)。
错误统一用 `BridgeError::App(String)`。

> **能力就绪、尚未接线(BRG-HYG-001):** 三条删除 / ephemeral 链路在共享层(messaging)
> 已**完整实现并有单测**,但目前**没有任何适配器接线**,运行时不会真实触达:
> (a) 入站删除 `submit_app_delete`(app→arkret 删除)无桥构造 `InboundAppDelete`;
> (b) 出站删除 `redact_in_app`(arkret→app 删除转发)已有 Discord 示例接线,其余桥仍默认 no-op;
> (c) `on_ephemeral`(typing/presence/receipts 转发)在所有桥都是默认 no-op。
> 接线计划见 [`_bridges_todos.md`](_bridges_todos.md)。读者勿误以为删除 / typing 已在所有桥生效。

### Provenance 与回环防护(裁决记录)

- spec 现行裁决(applet-integration §8、event-envelope.schema.json):桥接事件的
  `external_ref`/`applet_id` 是 **签名 envelope 顶层字段**;`unsigned.external_ref` 只能作
  可丢弃 hint,MUST NOT 用于安全决策。
- 当前 SDK `Event` 模型已暴露顶层 `external_ref`/`applet_id`;桥侧提交前必须设置这些签名字段,
  不得把安全相关 provenance 放入 `unsigned`。**回环判据只用签名覆盖的字段**
  (`executed_by == service_did` 或 `actor_id == service_did`),不读取 unsigned。portal strand
  的外部 location 同时写入 envelope 顶层 `external_ref` 与 strand 对象签名 metadata
  (`metadata.fields.external_ref`,受 event_digest 覆盖),前者用于 provenance/审计,后者用于
  §10.1 projection 扫描匹配。

## 每个 crate 必须产出的文件

1. `Cargo.toml`:应用 crate 只直接依赖 `arkret-bridge-messaging`(`{ workspace = true }`)；
   如需通用运行时类型，通过 `arkret_bridge_messaging::runtime` 使用 re-export，勿绕过消息层。
   + 该 app 传输库;`[[bin]]` name 同 crate;features 转发 sqlite/postgres/mysql 到这两个 crate(见 discord)。
   只声明源码实际 `use` 的依赖(`ctx.http` 已带 reqwest,桥自身通常无需再声明)。
2. `src/main.rs`:定义 `#[derive(Deserialize)] struct AppConfig {...}` →
   `bridge_main("arkret <-> Xxx bridge", |app: AppConfig, _ctx| Ok(App::new(...)))`(CLI/配置加载/
   日志初始化/`run_message_bridge` 都在 `messaging::bridge_main` 里,勿在桥内重写)。
3. `src/<app>.rs`:实现 `MessageBridge`。
4. `config/config.sample.yaml`:含 `bridge`/`arkret`/`database`/`logging`/`app` 段
   (照抄 discord,改 bridge_id、端口、app 段)。
5. `README_CN.md`:照 discord 风格。残留待办 / 不确定项小节统一用标题
   `## 待完善(TODO)`(勿用「不确定点(TODO)」「不确定点 / TODO」等变体)。

## 适配器实现指引

- **有 SDK 的**(telegram=teloxide):`run` 跑 SDK 的接收循环,回调里调
  `ctx.submit_app_message(InboundAppMessage{..})`;`send_to_app` 用 SDK 发消息。
- **websocket 的**(slack=tokio-tungstenite):`run` 建立 ws 长连,
  读循环解析消息→`submit_app_message`;`send_to_app` 用 `ctx.http`(reqwest)POST app API。
- **长轮询的**(zulip):`run` 建立官方 event queue 并长轮询,
  读循环解析消息→`submit_app_message`;`send_to_app` 用 `ctx.http` POST app API。
- **纯 HTTP/webhook 的**(feishu/wechat/dingtalk/whatsapp/line/qq/googlechat/imessage/messenger/teams):
  `send_to_app` 用 `ctx.http` POST 到 app 的发送 API;`run` 为保活循环
  (`loop { tokio::time::sleep(30s).await }`),入站走 `webhook_router`——返回一个 salvo `Router`,
  handler 内**对每条投递做来源验签**,再构造 `InboundAppMessage` 调 `webhook::submit(ctx, ..)`。
  参考 `messaging::webhook` 的 HMAC/JWKS helper。接入握手回显(GET `challenge`/`echostr`、
  `hub.verify_token`)只用于订阅注册,不得替代后续 POST 投递验签。
  **任何不含 per-body nonce 的验证方案**——包括覆盖 raw body 但不携带 timestamp/nonce 的
  HMAC(Meta/LINE 类),也包括完全不覆盖 body 的 per-request Bearer JWT(Google Chat/Teams
  类)——handler 都 MUST 使用平台 message id / delivery id / 等价稳定事件 id 建 bounded
  replay/dedupe 窗(经 `ctx.replay_window(ttl)` 取共享 DB 持久化守卫,重启与多副本下依然
  生效;TTL 须覆盖该方案的凭据/签名可被接受的整个窗口)；缺少稳定 id 的投递不得进入
  `submit_app_message`。如果平台原生签名不覆盖 raw body(如钉钉 outgoing
  robot),桥必须要求可信 ingress 额外注入覆盖 `timestamp + "\n" + raw_body` 的
  `x-arkret-signature-256`(或同等 body HMAC)并在未配置时 fail closed;不得把只覆盖 app secret
  或 handshake 的平台签名宣称为 body-bound 来源验签。
  关键是**编译通过、出入站链路真实可读**;来源验签未补齐者 MUST 明确标 TODO,不得宣称"已验签"。

## 端口分配(避免冲突,写进各自 sample 配置)

discord=9101, telegram=9102, slack=9103, feishu=9104, wechat=9105, dingtalk=9106,
zulip=9107, whatsapp=9108, line=9109, qq=9110, googlechat=9111, imessage=9112,
messenger=9113, teams=9114。

## 不要做

- 只有跨桥共享能力才放入 `arkret-bridge-runtime` / `arkret-bridge-messaging`;
  单桥协议细节留在各自 adapter。确需下沉到共享层的改动 / 待办登记到
  [`_bridges_todos.md`](_bridges_todos.md)。
- 各 crate 位于 `crates/<短名>`(去掉 `arkret-bridge-` 前缀;包名仍 `arkret-bridge-*`);
  workspace `members = ["crates/*"]` 自动纳入,无需手改根 `Cargo.toml`。
- 不要引入未缓存的专有 SDK(feishu-sdk/dingtalk-sdk 等);一律用 `reqwest`。
