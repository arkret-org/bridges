//! Bridge message-flow metrics.
//!
//! Counters for the app↔cokret message bridge so inbound submits, outbound
//! deliveries and media bridging are observable alongside the applet
//! transaction counters in [`crate::web`]. The actual prometheus recorder is
//! installed by the `web` feature ([`crate::web::serve`]); when that feature is
//! absent these calls are cheap no-ops, so the messaging layer can record
//! unconditionally without pulling in the exporter.

/// Direction of a bridged message relative to cokret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDirection {
    /// App → cokret submission (inbound).
    Inbound,
    /// cokret → app delivery (outbound).
    Outbound,
    /// App → cokret media (blob) bridging (inbound attachment).
    InboundMedia,
}

impl MessageDirection {
    fn as_label(self) -> &'static str {
        match self {
            MessageDirection::Inbound => "inbound",
            MessageDirection::Outbound => "outbound",
            MessageDirection::InboundMedia => "inbound_media",
        }
    }
}

/// The bridge-message counter metric name (labelled by `bridge`, `direction`,
/// `result`). Registered with a description in [`crate::web`].
pub const BRIDGE_MESSAGES_METRIC: &str = "cokret_bridge_messages_total";

/// Record one bridged message attempt. `result` is `"ok"` or `"error"`;
/// `bridge` is the adapter name (e.g. `"slack"`). No-op unless the `web`
/// feature compiled the prometheus recorder in.
pub fn record_bridge_message(bridge: &str, direction: MessageDirection, result: &'static str) {
    #[cfg(feature = "web")]
    {
        ::metrics::counter!(
            BRIDGE_MESSAGES_METRIC,
            "bridge" => bridge.to_owned(),
            "direction" => direction.as_label(),
            "result" => result,
        )
        .increment(1);
    }
    #[cfg(not(feature = "web"))]
    {
        let _ = (bridge, direction, result);
    }
}
