//! Calendar-event bridge mapping guards.
//!
//! Calendar events are Cokret Strand profile fields plus `ck.rsvp.set`; this
//! module intentionally rejects provider-specific preservation/downgrade fields
//! instead of smuggling them into Strand metadata or message content.

use std::fmt;

use cokret::{CalendarEventFields, RsvpSetPayload};
use serde_json::{Map, Value};

pub const CALENDAR_EVENT_PROFILE: &str = "ck.profile.calendar_event.v1";

const SCHEDULE_FIELDS: [&str; 7] = [
    "start",
    "end",
    "timezone",
    "all_day",
    "recurrence",
    "location",
    "call_id",
];
const RSVP_FIELDS: [&str; 4] = ["event_ref", "status", "occurrence", "comment"];
const DOWNGRADE_FIELDS: [&str; 8] = [
    "raw",
    "raw_event",
    "provider_payload",
    "preserved_fields",
    "unsupported_fields",
    "downgrade",
    "downgraded",
    "explicit_downgrade",
];
const PLAINTEXT_LOCATION_FIELDS: [&str; 4] = ["title", "address", "geo_uri", "url"];
const ENCRYPTED_ENVELOPE_REQUIRED_FIELDS: [&str; 11] = [
    "scheme",
    "version",
    "group_id",
    "epoch",
    "content_type",
    "ciphertext",
    "aad_visibility_event_id",
    "aad",
    "key_ref",
    "aad_digest",
    "payload_digest",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalendarMapError {
    InvalidPayload { reason: String },
    UnsupportedField { field: String },
    DowngradeFieldForbidden { field: String },
    PlaintextRsvpComment,
}

impl CalendarMapError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPayload { .. } => "calendar_payload_invalid",
            Self::UnsupportedField { .. } => "calendar_field_unsupported",
            Self::DowngradeFieldForbidden { .. } => "calendar_downgrade_field_forbidden",
            Self::PlaintextRsvpComment => "calendar_rsvp_plaintext_comment_unsupported",
        }
    }
}

impl fmt::Display for CalendarMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayload { reason } => write!(f, "{}: {reason}", self.code()),
            Self::UnsupportedField { field } => write!(f, "{}: {field}", self.code()),
            Self::DowngradeFieldForbidden { field } => write!(f, "{}: {field}", self.code()),
            Self::PlaintextRsvpComment => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for CalendarMapError {}

/// Validate and normalize external calendar schedule fields to the
/// `ck.profile.calendar_event.v1` Strand metadata field shape. Only the
/// schedule subset is accepted; attendees and provider-specific preservation
/// hints are rejected.
pub fn bridge_calendar_schedule_fields(input: Value) -> Result<Value, CalendarMapError> {
    let object = require_object(&input)?;
    reject_forbidden_fields(object, &SCHEDULE_FIELDS)?;
    if object.contains_key("attendees") {
        return Err(CalendarMapError::UnsupportedField {
            field: "attendees".to_owned(),
        });
    }

    let fields: CalendarEventFields =
        serde_json::from_value(input).map_err(|err| CalendarMapError::InvalidPayload {
            reason: err.to_string(),
        })?;
    if fields.timezone.trim().is_empty() {
        return Err(CalendarMapError::InvalidPayload {
            reason: "timezone must not be empty".to_owned(),
        });
    }
    if !fields.attendees.is_empty() {
        return Err(CalendarMapError::UnsupportedField {
            field: "attendees".to_owned(),
        });
    }
    if let Some(recurrence) = fields.recurrence.as_ref() {
        if recurrence.count.is_some() && recurrence.expires_at.is_some() {
            return Err(CalendarMapError::InvalidPayload {
                reason: "recurrence count and expires_at are mutually exclusive".to_owned(),
            });
        }
        if recurrence.count.is_some_and(|count| count > 10_000) {
            return Err(CalendarMapError::InvalidPayload {
                reason: "recurrence count exceeds 10000".to_owned(),
            });
        }
    }
    if let Some(location) = fields.location.as_ref() {
        validate_calendar_location(location)?;
    }
    serde_json::to_value(fields).map_err(|err| CalendarMapError::InvalidPayload {
        reason: err.to_string(),
    })
}

/// Validate and normalize external RSVP data to the `ck.rsvp.set` payload
/// shape. RSVP updates do not modify schedule, attendees, or access policy.
pub fn bridge_rsvp_payload(input: Value) -> Result<Value, CalendarMapError> {
    let object = require_object(&input)?;
    reject_forbidden_fields(object, &RSVP_FIELDS)?;
    let payload: RsvpSetPayload =
        serde_json::from_value(input).map_err(|err| CalendarMapError::InvalidPayload {
            reason: err.to_string(),
        })?;
    if let Some(comment) = payload.comment.as_ref()
        && !is_encrypted_envelope(comment)
    {
        return Err(CalendarMapError::PlaintextRsvpComment);
    }
    serde_json::to_value(payload).map_err(|err| CalendarMapError::InvalidPayload {
        reason: err.to_string(),
    })
}

fn require_object(value: &Value) -> Result<&Map<String, Value>, CalendarMapError> {
    value
        .as_object()
        .ok_or_else(|| CalendarMapError::InvalidPayload {
            reason: "payload must be an object".to_owned(),
        })
}

fn reject_forbidden_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), CalendarMapError> {
    for field in object.keys() {
        if DOWNGRADE_FIELDS.contains(&field.as_str()) {
            return Err(CalendarMapError::DowngradeFieldForbidden {
                field: field.clone(),
            });
        }
        if !allowed.contains(&field.as_str()) {
            return Err(CalendarMapError::UnsupportedField {
                field: field.clone(),
            });
        }
    }
    Ok(())
}

fn validate_calendar_location(value: &Value) -> Result<(), CalendarMapError> {
    if is_encrypted_envelope(value) {
        return Ok(());
    }
    let object = require_object(value)?;
    if object.keys().any(|field| {
        ENCRYPTED_ENVELOPE_REQUIRED_FIELDS.contains(&field.as_str())
            || field == "cleartext_commitment"
            || field == "authentication_tag"
    }) {
        return Err(CalendarMapError::InvalidPayload {
            reason: "location encrypted envelope is incomplete or invalid".to_owned(),
        });
    }
    if object.is_empty() {
        return Err(CalendarMapError::InvalidPayload {
            reason: "calendar location must not be empty".to_owned(),
        });
    }
    for (field, value) in object {
        if !PLAINTEXT_LOCATION_FIELDS.contains(&field.as_str()) {
            return Err(CalendarMapError::UnsupportedField {
                field: format!("location.{field}"),
            });
        }
        let Some(text) = value
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        else {
            return Err(CalendarMapError::InvalidPayload {
                reason: format!("location.{field} must be a non-empty string"),
            });
        };
        if field == "geo_uri" && !text.starts_with("geo:") {
            return Err(CalendarMapError::InvalidPayload {
                reason: "location.geo_uri must start with geo:".to_owned(),
            });
        }
        if field == "url" && reqwest::Url::parse(text).is_err() {
            return Err(CalendarMapError::InvalidPayload {
                reason: "location.url must be a URI".to_owned(),
            });
        }
    }
    Ok(())
}

fn is_encrypted_envelope(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("scheme")
        .and_then(Value::as_str)
        .is_some_and(|scheme| scheme == "mls-rfc9420")
        && ENCRYPTED_ENVELOPE_REQUIRED_FIELDS
            .iter()
            .all(|field| object.contains_key(*field))
        && !object.contains_key("cleartext_commitment")
        && !object.contains_key("authentication_tag")
}
