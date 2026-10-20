//! Message-shaped value types exchanged between the app adapter and the bridge.

/// An inbound message from an external app into Arkret.
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
    /// the bridge still records target provenance without inventing a Arkret
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

/// Static capabilities declared by an app adapter and enforced by the shared
/// message bridge driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageBridgeCapabilities {
    /// The adapter sends Arkret media attachments as native app attachments.
    /// When false, the shared outbound guard downgrades attachments into a text
    /// notice before the adapter sees the message.
    pub outbound_native_attachments: bool,
}

impl MessageBridgeCapabilities {
    pub const fn text_only() -> Self {
        Self {
            outbound_native_attachments: false,
        }
    }

    pub const fn native_outbound_attachments() -> Self {
        Self {
            outbound_native_attachments: true,
        }
    }
}

impl Default for MessageBridgeCapabilities {
    fn default() -> Self {
        Self::text_only()
    }
}

/// An outbound message from Arkret to an external app.
#[derive(Clone, Debug)]
pub struct OutboundAppMessage {
    pub app_channel: String,
    pub sender_display: String,
    pub body: String,
    /// Verified local media, ready for the adapter to re-send to the app.
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

    pub(crate) fn downgrade_attachment_to_text(&mut self) -> Option<AttachmentDowngrade> {
        let attachment = self.attachment.take()?;
        let notice = attachment_downgrade_notice(&attachment);
        if self.body.trim().is_empty() {
            if attachment.caption.trim().is_empty() {
                self.body = notice.clone();
            } else {
                self.body = attachment.caption.clone();
                self.body.push_str("\n\n");
                self.body.push_str(&notice);
            }
        } else {
            self.body.push_str("\n\n");
            self.body.push_str(&notice);
        }
        Some(AttachmentDowngrade {
            blob_ref: attachment.blob_ref,
            filename: attachment.filename,
            media_type: attachment.media_type,
            size: attachment.size,
            notice,
        })
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

/// Local media view retaining the immutable ciphertext resource identity.
#[derive(Clone, Debug)]
pub struct Attachment {
    pub blob_ref: String,
    pub media_type: Option<String>,
    pub filename: Option<String>,
    pub size: Option<u64>,
    /// Caption / display text for the media event (may be empty).
    pub caption: String,
    /// Filled only after native MLS and attachment verification.
    pub plaintext: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttachmentDowngrade {
    pub(crate) blob_ref: String,
    pub(crate) filename: Option<String>,
    pub(crate) media_type: Option<String>,
    pub(crate) size: Option<u64>,
    pub(crate) notice: String,
}

impl AttachmentDowngrade {
    pub(crate) fn audit_message(&self) -> String {
        format!("outbound attachment downgraded to text: {}", self.notice)
    }
}

fn attachment_downgrade_notice(attachment: &Attachment) -> String {
    let filename = attachment
        .filename
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unnamed attachment");
    let mut details = vec![format!("filename: {filename}")];
    if let Some(media_type) = attachment
        .media_type
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        details.push(format!("type: {media_type}"));
    }
    if let Some(size) = attachment.size {
        details.push(format!("size: {size} bytes"));
    }
    format!(
        "[attachment not sent: {}; native attachment delivery is not supported by this bridge]",
        details.join(", ")
    )
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

    #[test]
    fn bridge_capabilities_default_to_text_only() {
        assert_eq!(
            MessageBridgeCapabilities::default(),
            MessageBridgeCapabilities::text_only()
        );
        assert!(!MessageBridgeCapabilities::default().outbound_native_attachments);
        assert!(
            MessageBridgeCapabilities::native_outbound_attachments().outbound_native_attachments
        );
    }

    #[test]
    fn attachment_downgrade_removes_attachment_and_appends_notice() {
        let mut msg = OutboundAppMessage {
            app_channel: "c".to_owned(),
            sender_display: "alice".to_owned(),
            body: "see this".to_owned(),
            attachment: Some(Attachment {
                blob_ref: "ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                media_type: Some("image/png".to_owned()),
                filename: Some("shot.png".to_owned()),
                size: Some(2048),
                caption: "caption from media".to_owned(),
                plaintext: None,
            }),
        };

        let downgrade = msg
            .downgrade_attachment_to_text()
            .expect("attachment was downgraded");

        assert!(msg.attachment.is_none());
        assert!(msg.body.contains("see this"));
        assert!(msg.body.contains("attachment not sent"));
        assert!(msg.body.contains("shot.png"));
        assert!(msg.body.contains("image/png"));
        assert!(msg.body.contains("2048 bytes"));
        assert_eq!(downgrade.filename.as_deref(), Some("shot.png"));
        assert!(downgrade.audit_message().contains("downgraded to text"));
    }

    #[test]
    fn attachment_downgrade_uses_caption_when_body_is_empty() {
        let mut msg = OutboundAppMessage {
            app_channel: "c".to_owned(),
            sender_display: "alice".to_owned(),
            body: String::new(),
            attachment: Some(Attachment {
                blob_ref: "ak:blob:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
                media_type: None,
                filename: None,
                size: None,
                caption: "media caption".to_owned(),
                plaintext: None,
            }),
        };

        msg.downgrade_attachment_to_text()
            .expect("attachment was downgraded");

        assert!(
            msg.body
                .starts_with("media caption\n\n[attachment not sent")
        );
        assert!(msg.body.contains("unnamed attachment"));
    }
}
