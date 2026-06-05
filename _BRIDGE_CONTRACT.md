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
    // 出站:把 app 入站消息提交到 cokret realm(签名 external_ref),返回 event_id
    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String>;
}
pub struct InboundAppMessage  { pub app_channel: String, pub app_user: String,
                                pub app_message_id: String, pub body: String }
pub struct OutboundAppMessage { pub app_channel: String, pub sender_display: String,
                                pub body: String, pub reply_to: Option<String> }
pub struct AppMessageRef { pub app_message_id: String }

#[async_trait]
pub trait MessageBridge: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()>;    // app 接收循环
    async fn send_to_app(&self, ctx: Arc<MessageContext>, msg: OutboundAppMessage)
        -> Result<AppMessageRef>;                                            // cokret→app 发送
    async fn redact_in_app(&self, _ctx: Arc<MessageContext>, _id: &str) -> Result<()> { Ok(()) }
    // 纯 HTTP 桥重写此项,返回入站 webhook 路由(由 runtime web 服务挂载);默认 None
    fn webhook_router(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Option<salvo::Router> { None }
}
```

下行(cokret→app)由 messaging 的 `MessageAdapter::on_cokret_event` 自动驱动 `send_to_app`,
适配器无需自己实现 `on_cokret_event`。`config.app` 是 `serde_json::Value`,放该 app 专属配置
(token 等),适配器自取。错误统一用 `BridgeError::App(String)`。

## 每个 crate 必须产出的文件

1. `Cargo.toml`:依赖 `cokret-bridge-runtime` + `cokret-bridge-messaging`(均 `{ workspace = true }`)
   + 该 app 传输库;`[[bin]]` name 同 crate;features 转发 sqlite/postgres/mysql 到这两个 crate(见 discord)。
2. `src/main.rs`:`clap` 解析 `--config` → `Config::load` → `logging::init` →
   从 `config.app` 取 token → `run_message_bridge(config, move |_ctx| Ok(App::new(...)))`。
3. `src/<app>.rs`:实现 `MessageBridge`。
4. `config/config.sample.yaml`:含 `bridge`/`cokret`/`database`/`logging`/`app` 段
   (照抄 discord,改 bridge_id、端口、app 段)。
5. `README_CN.md`:照 discord 风格。

## 适配器实现指引

- **有 SDK 的**(telegram=teloxide):`run` 跑 SDK 的接收循环,回调里调
  `ctx.submit_app_message(InboundAppMessage{..})`;`send_to_app` 用 SDK 发消息。
- **websocket 的**(slack/zulip/teams=tokio-tungstenite):`run` 建立 ws 长连,
  读循环解析消息→`submit_app_message`;`send_to_app` 用 `ctx.http`(reqwest)POST app API。
- **纯 HTTP/webhook 的**(feishu/wechat/dingtalk/whatsapp/line/qq/googlechat/imessage/messager):
  `send_to_app` 用 `ctx.http` POST 到 app 的发送 API;`run` 为保活循环
  (`loop { tokio::time::sleep(30s).await }`),入站走 `webhook_router`——返回一个 salvo `Router`,
  handler 内**对每条投递做来源验签**,再构造 `InboundAppMessage` 调 `webhook::submit(ctx, ..)`。
  参考 `crates/line`(`x-line-signature` HMAC-SHA256 是当前唯一完整正例)。
  **⚠ 验签现状(勿混淆"接入握手回显"与"投递验签"):**
  - **平台接入握手回显**(GET `challenge`/`echostr`、`hub.verify_token`)**只在订阅注册时用一次,
    不是对后续每条投递的来源认证**,不可当作验签。
  - 飞书 `challenge`、微信 `echostr`、WhatsApp/Messenger 的 `hub.verify_token` 均属此类——
    其后续 POST 投递目前**仍缺**真正验签(`X-Hub-Signature-256` / `signature`/`msg_signature` /
    各平台 JWT),属待补 TODO,见 `_bridges_todos.md §3.0.b` 与 `_code_review/bridges/02-security.md`。
  关键是**编译通过、出入站链路真实可读**;来源验签未补齐者 MUST 明确标 TODO,不得宣称"已验签"。

## 端口分配(避免冲突,写进各自 sample 配置)

discord=9101, telegram=9102, slack=9103, feishu=9104, wechat=9105, dingtalk=9106,
zulip=9107, whatsapp=9108, line=9109, qq=9110, googlechat=9111, imessage=9112,
messager=9113, teams=9114。

## 不要做

- 不要修改两个共享 crate `cokret-bridge-runtime` / `cokret-bridge-messaging`
  (发现确需改动,写到 `_bridges_todos.md` §3,勿擅改)。
- 各 crate 位于 `crates/<短名>`(去掉 `cokret-bridge-` 前缀;包名仍 `cokret-bridge-*`);
  workspace `members = ["crates/*"]` 自动纳入,无需手改根 `Cargo.toml`。
- 不要引入未缓存的专有 SDK(feishu-sdk/dingtalk-sdk 等);一律用 `reqwest`。
