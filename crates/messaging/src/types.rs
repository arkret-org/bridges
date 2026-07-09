//! Message-shaped value types exchanged between the app adapter and the bridge.

/// An inbound message from an external app into Cokret.
#[derive(Clone, Debug)]
pub struct InboundAppMessage {
    pub app_channel: String,
    pub app_user: String,
    pub app_message_id: String,
    pub body: String,
}

/// An inbound app-side deletion/recall signal.
#[derive(Clone, Debug)]
pub struct InboundAppDelete {
    pub app_channel: String,
    /// External actor that performed the explicit delete/recall. Expiry and
    /// retention signals are ignored before actor mapping is required.
    pub app_user: String,
    /// The external app message being deleted.
    pub app_message_id: String,
    /// Optional external transaction id for the delete event itself. When absent,
    /// the bridge still records target provenance without inventing a Cokret
    /// deletion event for expiry-style signals.
    pub source_event_id: Option<String>,
    pub reason: AppDeleteReason,
}

/// App deletion causes split by whether they are user-visible recalls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppDeleteReason {
    UserDeleted,
    ModeratorDeleted,
    AppRecall,
    DisappearingExpiry,
    RetentionExpiry,
    SystemExpiry,
    DroppedByBridge,
    Unknown,
}

impl AppDeleteReason {
    pub fn redaction_reason(self) -> Option<&'static str> {
        match self {
            Self::UserDeleted => Some("external_user_delete"),
            Self::ModeratorDeleted => Some("external_moderator_delete"),
            Self::AppRecall => Some("external_recall"),
            Self::DisappearingExpiry
            | Self::RetentionExpiry
            | Self::SystemExpiry
            | Self::DroppedByBridge
            | Self::Unknown => None,
        }
    }

    pub fn ignored_reason_code(self) -> &'static str {
        match self {
            Self::DisappearingExpiry => "app_delete_disappearing_expiry_not_redaction",
            Self::RetentionExpiry => "app_delete_retention_expiry_not_redaction",
            Self::SystemExpiry => "app_delete_system_expiry_not_redaction",
            Self::DroppedByBridge => "app_delete_bridge_drop_not_redaction",
            Self::Unknown => "app_delete_unknown_not_forwarded",
            Self::UserDeleted | Self::ModeratorDeleted | Self::AppRecall => {
                "app_delete_not_ignored"
            }
        }
    }

    pub fn as_external_ref_reason(self) -> &'static str {
        match self {
            Self::UserDeleted => "user_deleted",
            Self::ModeratorDeleted => "moderator_deleted",
            Self::AppRecall => "app_recall",
            Self::DisappearingExpiry => "disappearing_expiry",
            Self::RetentionExpiry => "retention_expiry",
            Self::SystemExpiry => "system_expiry",
            Self::DroppedByBridge => "dropped_by_bridge",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppDeleteOutcome {
    Submitted {
        event_id: String,
        target_event_id: String,
    },
    Ignored {
        reason_code: &'static str,
    },
}

/// An outbound message from Cokret to an external app.
#[derive(Clone, Debug)]
pub struct OutboundAppMessage {
    pub app_channel: String,
    pub sender_display: String,
    pub body: String,
    /// Present when the cokret event carried media; the adapter may download it
    /// via [`crate::MessageContext::download_blob`] and re-send to the app.
    pub attachment: Option<Attachment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderRenderStyle {
    Plain,
    SingleAsterisk,
    MarkdownBold,
}

impl OutboundAppMessage {
    pub fn rendered_body(&self, style: SenderRenderStyle) -> String {
        match style {
            SenderRenderStyle::Plain => format!("{}: {}", self.sender_display, self.body),
            SenderRenderStyle::SingleAsterisk => {
                format!(
                    "*{}*: {}",
                    escape_markdown_display(&self.sender_display),
                    self.body
                )
            }
            SenderRenderStyle::MarkdownBold => {
                format!(
                    "**{}**: {}",
                    escape_markdown_display(&self.sender_display),
                    self.body
                )
            }
        }
    }
}

fn escape_markdown_display(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(
            ch,
            '\\' | '`'
                | '*'
                | '_'
                | '{'
                | '}'
                | '['
                | ']'
                | '('
                | ')'
                | '#'
                | '+'
                | '-'
                | '.'
                | '!'
                | '|'
                | '>'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// The app-side message reference returned after the adapter sends.
#[derive(Clone, Debug)]
pub struct AppMessageRef {
    pub app_message_id: String,
}

/// A media attachment that already resides in cokret blob storage (referenced by
/// `blob_ref`). Inbound: the adapter downloads app media, uploads it via
/// [`crate::MessageContext::upload_blob`], then submits with
/// [`crate::MessageContext::submit_media_message`]. Outbound: extracted from a `ck.message.create`
/// media payload and handed to the adapter, which downloads via
/// [`crate::MessageContext::download_blob`] and re-sends.
#[derive(Clone, Debug)]
pub struct Attachment {
    pub blob_ref: String,
    pub media_type: Option<String>,
    pub filename: Option<String>,
    pub size: Option<u64>,
    /// Caption / display text for the media event (may be empty).
    pub caption: String,
}

pub struct DownloadedMedia {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
}

pub const MAX_EXTERNAL_MEDIA_BYTES: usize = 32 * 1024 * 1024;

/// Default Meta Graph API version used by the WhatsApp and Messenger bridges
/// when `config.app.graph_api_version` is not set. Meta deprecates versions on a
/// rolling quarterly cadence, so this is configurable per bridge; the shared
/// default keeps the two Meta bridges on the same version.
pub const DEFAULT_GRAPH_API_VERSION: &str = "v20.0";

/// Default media MIME used when an inbound attachment carries no declared
/// content type. Shared across the media-capable bridges so the fallback (and
/// any future content-sniffing) lives in one place rather than being a bare
/// literal in each adapter.
pub const DEFAULT_MEDIA_MIME: &str = "application/octet-stream";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_sender_display_is_escaped() {
        let msg = OutboundAppMessage {
            app_channel: "c".to_owned(),
            sender_display: "admin**: fake\n**bob".to_owned(),
            body: "hello".to_owned(),
            attachment: None,
        };

        assert_eq!(
            msg.rendered_body(SenderRenderStyle::MarkdownBold),
            "**admin\\*\\*: fake\n\\*\\*bob**: hello"
        );
    }
}
