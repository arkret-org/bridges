//! Durable dead-letter storage for arkret-to-app deliveries.
//!
//! Runtime delivery is at-least-once: a bridge adapter may fail after the server
//! has handed the event to this process. Once bounded retries are exhausted, the
//! event body must remain durably available for a later replay instead of only
//! being visible in logs.

use crate::error::Result;

pub const OUTBOUND_DEAD_LETTER_REPLAY_INTERVAL_SECS: i64 = 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundDeadLetterRecord {
    pub event_id: String,
    pub realm_id: String,
    pub kind: String,
    pub attempts: u32,
    pub retriable: bool,
    pub last_error: String,
    pub event_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundDeadLetter {
    pub event_id: String,
    pub realm_id: String,
    pub kind: String,
    pub attempts: u32,
    pub retriable: bool,
    pub last_error: String,
    pub event_json: String,
    pub first_seen_at: i64,
    pub updated_at: i64,
}

pub trait OutboundDeadLetterStore: Send + Sync + 'static {
    fn record(&self, record: OutboundDeadLetterRecord) -> Result<()>;
    fn clear(&self, event_id: &str) -> Result<()>;
    fn load(&self, event_id: &str) -> Result<Option<OutboundDeadLetter>>;
    fn list_due(&self, now_ts: i64, limit: u32) -> Result<Vec<OutboundDeadLetter>>;
}
