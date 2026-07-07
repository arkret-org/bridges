//! Calendar-event bridge mapping guards.
//!
//! Calendar events are Cokret Strand profile fields plus `ck.rsvp.set`; this
//! module intentionally rejects provider-specific preservation/downgrade fields
//! instead of smuggling them into Strand metadata or message content.
//!
//! Status (BRG-HYG-001): these mapping guards are **shared-capability ready and
//! unit-tested, but no adapter is wired to them yet** — no bridge feeds external
//! calendar events through `bridge_calendar_schedule_fields` /
//! `bridge_rsvp_payload`, and `MessageContext` exposes no `submit_calendar_*`
//! entry point. This is a deliberately latent capability tracked in
//! `_bridges_todos.md`; do not treat calendar bridging as available until an
//! adapter and a submit entry point land.

use std::fmt;

use cokret::{CalendarEventFields, EncryptedEnvelope, RsvpSetPayload};
use serde_json::Value;

pub const CALENDAR_EVENT_PROFILE: &str = "ck.profile.calendar_event.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalendarMapError {
    InvalidPayload { reason: String },
    UnsupportedField { field: String },
    PlaintextRsvpComment,
}

impl CalendarMapError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPayload { .. } => "calendar_payload_invalid",
            Self::UnsupportedField { .. } => "calendar_field_unsupported",
            Self::PlaintextRsvpComment => "calendar_rsvp_plaintext_comment_unsupported",
        }
    }
}

impl fmt::Display for CalendarMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayload { reason } => write!(f, "{}: {reason}", self.code()),
            Self::UnsupportedField { field } => write!(f, "{}: {field}", self.code()),
            Self::PlaintextRsvpComment => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for CalendarMapError {}

/// Validate external calendar schedule fields for the
/// `ck.profile.calendar_event.v1` Strand metadata field shape. Callers must map
/// provider-specific input into SDK wire types before calling this helper; this
/// layer does not preserve downgrade/raw provider fields.
pub fn bridge_calendar_schedule_fields(
    fields: CalendarEventFields,
) -> Result<CalendarEventFields, CalendarMapError> {
    fields
        .validate()
        .map_err(|err| CalendarMapError::InvalidPayload {
            reason: err.to_string(),
        })?;
    if !fields.attendees.is_empty() {
        return Err(CalendarMapError::UnsupportedField {
            field: "attendees".to_owned(),
        });
    }
    Ok(fields)
}

/// Validate external RSVP data for the `ck.rsvp.set` payload shape. RSVP
/// updates do not modify schedule, attendees, or access policy.
pub fn bridge_rsvp_payload(payload: RsvpSetPayload) -> Result<RsvpSetPayload, CalendarMapError> {
    if let Some(comment) = payload.comment.as_ref()
        && !is_encrypted_envelope(comment)
    {
        return Err(CalendarMapError::PlaintextRsvpComment);
    }
    Ok(payload)
}

fn is_encrypted_envelope(value: &Value) -> bool {
    serde_json::from_value::<EncryptedEnvelope>(value.clone())
        .is_ok_and(|envelope| envelope.validate().is_ok())
}
