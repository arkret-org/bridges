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
    pub reply_to: Option<String>,
    /// Present when the cokret event carried media; the adapter may download it
    /// via [`crate::MessageContext::download_blob`] and re-send to the app.
    pub attachment: Option<Attachment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderRenderStyle {
    Plain,
    MarkdownItalic,
    MarkdownBold,
}

impl OutboundAppMessage {
    pub fn rendered_body(&self, style: SenderRenderStyle) -> String {
        match style {
            SenderRenderStyle::Plain => format!("{}: {}", self.sender_display, self.body),
            SenderRenderStyle::MarkdownItalic => {
                format!("*{}*: {}", self.sender_display, self.body)
            }
            SenderRenderStyle::MarkdownBold => {
                format!("**{}**: {}", self.sender_display, self.body)
            }
        }
    }
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
