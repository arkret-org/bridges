//! Small helpers for adapter-owned Salvo webhook handlers.

use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::{InboundAppMessage, MessageContext};

pub async fn json_body(req: &mut Request, res: &mut Response) -> Option<Value> {
    match req.parse_json::<Value>().await {
        Ok(value) => Some(value),
        Err(err) => {
            bad_request(res, format!("invalid JSON body: {err}"));
            None
        }
    }
}

pub fn ok_json(res: &mut Response, value: Value) {
    res.render(Json(value));
}

pub fn ok_text(res: &mut Response, value: impl Into<String>) {
    res.render(Text::Plain(value.into()));
}

pub fn bad_request(res: &mut Response, message: impl Into<String>) {
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(json!({ "ok": false, "error": message.into() })));
}

pub fn unauthorized(res: &mut Response, message: impl Into<String>) {
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(json!({ "ok": false, "error": message.into() })));
}

pub async fn submit(ctx: Arc<MessageContext>, label: &str, inbound: InboundAppMessage) {
    if let Err(error) = ctx.submit_app_message(inbound).await {
        tracing::warn!(%error, bridge = label, "webhook submission failed");
    }
}

pub fn str_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

pub fn string_at(value: &Value, pointer: &str) -> Option<String> {
    str_at(value, pointer).map(str::to_owned)
}

pub fn first_string_at(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| string_at(value, pointer))
}

pub fn body_text_from_json_string(raw: &str, key: &str) -> String {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|value| value.get(key).and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| raw.to_owned())
}
