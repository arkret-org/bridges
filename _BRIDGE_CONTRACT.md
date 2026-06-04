# cokret-bridge-<app> 编写契约(子代理必读)

每个 bridge 只实现「app 适配器」,其余全在 `cokret-bridge-core`。**必须**严格按本契约,
与参考实现 `cokret-bridge-discord/` 保持一致结构,确保 `cargo check` 通过。

## 核心 API(来自 `cokret-bridge-core`,勿改核心)

```rust
// lib.rs
pub async fn run_bridge<A, F>(config: Config, app_factory: F) -> Result<()>
where A: BridgeApp, F: FnOnce(Arc<BridgeContext>) -> Result<A>;
pub use config::Config;            // Config::load(path) -> Result<Config>
pub use error::{BridgeError, Result};
pub mod logging;                   // logging::init(&config.logging)

// app.rs
pub struct BridgeContext { pub config, pub edge, pub db, pub queue, pub http: reqwest::Client }
impl BridgeContext {
    // 出站:把 app 入站消息提交到 cokret realm,返回 event_id
    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String>;
}
pub struct InboundAppMessage  { pub app_channel: String, pub app_user: String,
                                pub app_message_id: String, pub body: String }
pub struct OutboundAppMessage { pub app_channel: String, pub sender_display: String,
                                pub body: String, pub reply_to: Option<String> }
pub struct AppMessageRef { pub app_message_id: String }

#[async_trait]
pub trait BridgeApp: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn run(self: Arc<Self>, ctx: Arc<BridgeContext>) -> Result<()>;     // app 接收循环
    async fn send_to_app(&self, ctx: Arc<BridgeContext>, msg: OutboundAppMessage)
        -> Result<AppMessageRef>;                                            // cokret→app 发送
    async fn redact_in_app(&self, _ctx: Arc<BridgeContext>, _id: &str) -> Result<()> { Ok(()) }
}
```

`config.app` 是 `serde_json::Value`,放该 app 专属配置(token 等),适配器自取。
错误统一用 `BridgeError::App(String)`。

## 每个 crate 必须产出的文件

1. `Cargo.toml`:依赖 `cokret-bridge-core = { workspace = true }` + 该 app 传输库;
   `[[bin]]` name 同 crate;features 转发 sqlite/postgres/mysql 到 core(见 discord)。
2. `src/main.rs`:`clap` 解析 `--config` → `Config::load` → `logging::init` →
   从 `config.app` 取 token → `run_bridge(config, move |_ctx| Ok(App::new(...)))`。
3. `src/<app>.rs`:实现 `BridgeApp`。
4. `config/config.sample.yaml`:含 `bridge`/`cokret`/`database`/`logging`/`app` 段
   (照抄 discord,改 bridge_id、端口、app 段)。
5. `README_CN.md`:照 discord 风格。

## 适配器实现指引

- **有 SDK 的**(telegram=teloxide):`run` 跑 SDK 的接收循环,回调里调
  `ctx.submit_app_message(InboundAppMessage{..})`;`send_to_app` 用 SDK 发消息。
- **websocket 的**(slack/zulip/teams=tokio-tungstenite):`run` 建立 ws 长连,
  读循环解析消息→`submit_app_message`;`send_to_app` 用 `ctx.http`(reqwest)POST app API。
- **纯 HTTP/webhook 的**(feishu/wechat/dingtalk/whatsapp/line/qq/googlechat/imessage/messager):
  `send_to_app` 用 `ctx.http` POST 到 app 的发送 API(URL/字段按该 app 文档,缺凭据处用
  `// TODO` 标注真实 endpoint);`run` 暂以长生命周期轮询/保活循环实现(可
  `loop { tokio::time::sleep(30s).await }` 占位并注释「webhook 接入待 core 暴露额外路由」)。
  关键是**编译通过、出站链路真实可读**。

## 端口分配(避免冲突,写进各自 sample 配置)

discord=9101, telegram=9102, slack=9103, feishu=9104, wechat=9105, dingtalk=9106,
zulip=9107, whatsapp=9108, line=9109, qq=9110, googlechat=9111, imessage=9112,
messager=9113, teams=9114。

## 不要做

- 不要修改 `cokret-bridge-core`(发现确需改动,写到 `_bridges_todos.md` §3,勿擅改)。
- 各 crate 位于 `crates/<短名>`(去掉 `cokret-bridge-` 前缀;包名仍 `cokret-bridge-*`);
  workspace `members = ["crates/*"]` 自动纳入,无需手改根 `Cargo.toml`。
- 不要引入未缓存的专有 SDK(feishu-sdk/dingtalk-sdk 等);一律用 `reqwest`。
