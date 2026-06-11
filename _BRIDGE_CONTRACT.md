# cokret-bridge-<app> 编写契约(子代理必读)

每个 bridge 只实现「app 适配器」,其余全在共享 crate:`cokret-bridge-runtime`(通用桥运行时)+
`cokret-bridge-messaging`(消息层)。**必须**严格按本契约,与参考实现 `crates/discord/` 保持一致
结构,确保 `cargo check` 通过。

> 历史:共享层早期为单 crate `cokret-bridge-core`/trait `BridgeApp`,现已拆为 runtime+messaging,
> 聊天桥实现 `MessageBridge`(不再直接实现 `BridgeApp`)。`BridgeApp` 仍是 runtime 的泛型底座,
> 供非聊天集成直接使用。

## 核心 API(聊天桥用 `cokret-bridge-messaging`;勿改两个共享 crate)

```rust
// cokret-bridge-messaging(lib.rs)—— 聊天桥装配入口
pub async fn run_message_bridge<M, F>(config: Config, factory: F) -> Result<()>
where M: MessageBridge, F: FnOnce(Arc<MessageContext>) -> Result<M>;

// cokret-bridge-runtime 重导出:Config(Config::load(path))、BridgeError/Result、logging::init
pub struct MessageContext { pub http: reqwest::Client, /* + core()/store() */ }
impl MessageContext {
    // 出站:把 app 入站消息作为 per-user Ghost Actor 事件提交到 cokret portal flow,
    // 返回 event_id。payload 按权威 message_create_payload 组装
    // ({flow_id, track_name:"discussion", content: content_block, blob_refs[]}),
    // 外部 location 的映射单位是 (realm_id, flow_id)(applet-integration §10.1):
    // portal flow 按「持久化映射 → projection 按 external_ref 匹配 → ck.flow.create」
    // 顺序惰性解析并缓存在 room_mappings.portal_flow_id。
    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String>;
}
pub struct InboundAppMessage  { pub app_channel: String, pub app_user: String,
                                pub app_message_id: String, pub body: String }
pub struct OutboundAppMessage { pub app_channel: String, pub sender_display: String,
                                pub body: String, pub reply_to: Option<String> }
pub struct Appmessengeref { pub app_message_id: String }

#[async_trait]
pub trait MessageBridge: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()>;    // app 接收循环
    async fn send_to_app(&self, ctx: Arc<MessageContext>, msg: OutboundAppMessage)
        -> Result<Appmessengeref>;                                            // cokret→app 发送
    async fn redact_in_app(&self, _ctx: Arc<MessageContext>, _id: &str) -> Result<()> { Ok(()) }
    // 纯 HTTP 桥重写此项,返回入站 webhook 路由(由 runtime web 服务挂载);默认 None
    fn webhook_router(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Option<salvo::Router> { None }
}
```

下行(cokret→app)由 messaging 的 `MessageAdapter::on_cokret_event` 自动驱动 `send_to_app`,
适配器无需自己实现 `on_cokret_event`;只转发 portal flow 上的 `ck.message.create`(§10.1 映射
单位是 `(realm_id, flow_id)`),正文从 `payload.content`(content_block)解析,媒体从
`blob_ref`/`blob_refs[]` 解析。`config.app` 放该 app 专属配置(token 等),由
`bridge_main` 经 serde 反序列化成每桥自定义的强类型 `AppConfig`(缺字段由 serde 按字段名报错)。
错误统一用 `BridgeError::App(String)`。

### Provenance 与回环防护(裁决记录)

- spec 现行裁决(applet-integration §8、event-envelope.schema.json):桥接事件的
  `external_ref`/`applet_id` 是 **签名 envelope 顶层字段**;`unsigned.external_ref` 只能作
  可丢弃 hint,MUST NOT 用于安全决策。
- 当前 SDK `Event` 模型(HEAD)尚未暴露这两个顶层字段(wire 形 deny_unknown_fields),本仓
  不改 SDK,故桥侧现状为:`unsigned.applet_id`/`unsigned.external_ref` 仅作传输 hint;
  **回环判据只用签名覆盖的字段**(`executed_by == service_did` 或 `actor_id == service_did`),
  不再读取 unsigned。portal flow 的外部 location 出处写入 flow 对象的签名 metadata
  (`metadata.fields.external_ref`,受 event_digest 覆盖)。SDK 补齐 envelope 顶层签名
  `external_ref`/`applet_id` 后,应迁移到顶层签名承载位。

## 每个 crate 必须产出的文件

1. `Cargo.toml`:依赖 `cokret-bridge-runtime` + `cokret-bridge-messaging`(均 `{ workspace = true }`)
   + 该 app 传输库;`[[bin]]` name 同 crate;features 转发 sqlite/postgres/mysql 到这两个 crate(见 discord)。
   只声明源码实际 `use` 的依赖(`ctx.http` 已带 reqwest,桥自身通常无需再声明)。
2. `src/main.rs`:定义 `#[derive(Deserialize)] struct AppConfig {...}` →
   `bridge_main("cokret <-> Xxx bridge", |app: AppConfig, _ctx| Ok(App::new(...)))`(CLI/配置加载/
   日志初始化/`run_message_bridge` 都在 `messaging::bridge_main` 里,勿在桥内重写)。
3. `src/<app>.rs`:实现 `MessageBridge`。
4. `config/config.sample.yaml`:含 `bridge`/`cokret`/`database`/`logging`/`app` 段
   (照抄 discord,改 bridge_id、端口、app 段)。
5. `README_CN.md`:照 discord 风格。

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
  关键是**编译通过、出入站链路真实可读**;来源验签未补齐者 MUST 明确标 TODO,不得宣称"已验签"。

## 端口分配(避免冲突,写进各自 sample 配置)

discord=9101, telegram=9102, slack=9103, feishu=9104, wechat=9105, dingtalk=9106,
zulip=9107, whatsapp=9108, line=9109, qq=9110, googlechat=9111, imessage=9112,
messenger=9113, teams=9114。

## 不要做

- 只有跨桥共享能力才放入 `cokret-bridge-runtime` / `cokret-bridge-messaging`;
  单桥协议细节留在各自 adapter。
- 各 crate 位于 `crates/<短名>`(去掉 `cokret-bridge-` 前缀;包名仍 `cokret-bridge-*`);
  workspace `members = ["crates/*"]` 自动纳入,无需手改根 `Cargo.toml`。
- 不要引入未缓存的专有 SDK(feishu-sdk/dingtalk-sdk 等);一律用 `reqwest`。
