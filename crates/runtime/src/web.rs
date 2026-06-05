//! salvo HTTP service: health check / metrics / provisioning, plus mounting
//! the cokret applet routes (`/_cokret/edge/applet/*`) to receive event pushes
//! from the cokret server.

use std::sync::Arc;
use std::time::Duration;

use salvo::prelude::*;

use crate::app::BridgeContext;
use crate::cokret_edge::BridgeAppletHandler;
use crate::error::{BridgeError, Result};

/// Start the web service and run it blocking. `extra` is each app adapter's
/// webhook routes (optional).
pub async fn serve(ctx: Arc<BridgeContext>, extra: Option<Router>) -> Result<()> {
    let handler = BridgeAppletHandler::new(&ctx.edge, ctx.resolver());
    let idempotency = cokret::idempotency::IdempotencyWindow::new(Duration::from_secs(300));
    let service = cokret::AppletService::new(handler, idempotency);

    // The applet routes provided by cokret (/_cokret/edge/applet/...).
    let applet = cokret::applet_router(service)?;

    let mut router = Router::new()
        .push(Router::with_path("health").get(health))
        .push(Router::with_path("metrics").get(metrics))
        .push(applet);

    if let Some(app_routes) = extra {
        router = router.push(app_routes);
    }

    let addr = format!(
        "{}:{}",
        ctx.config.bridge.bind_address, ctx.config.bridge.port
    );
    tracing::info!(%addr, "web service listening");

    let acceptor = TcpListener::new(addr).bind().await;
    Server::new(acceptor).serve(router).await;
    Err(BridgeError::Runtime(
        "web service exited unexpectedly".into(),
    ))
}

#[handler]
async fn health(res: &mut Response) {
    res.render(Json(serde_json::json!({ "status": "ok" })));
}

#[handler]
async fn metrics(res: &mut Response) {
    // Placeholder: can be wired to metrics-exporter-prometheus.
    res.render(Text::Plain("# cokret bridge metrics\n"));
}
