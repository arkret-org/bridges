//! Diesel row models for the messaging helper layer.

use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use super::schema::{message_mappings, room_mappings, user_mappings};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = room_mappings)]
pub struct RoomMapping {
    pub id: i64,
    pub app_channel_id: String,
    pub cokret_realm_id: String,
    pub portal_alias: Option<String>,
    /// The portal flow this external location maps to (applet-integration
    /// §10.1: mapping unit is `(realm_id, flow_id)`); resolved lazily.
    pub portal_flow_id: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = room_mappings)]
pub struct NewRoomMapping<'a> {
    pub app_channel_id: &'a str,
    pub cokret_realm_id: &'a str,
    pub portal_alias: Option<&'a str>,
    pub portal_flow_id: Option<&'a str>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = message_mappings)]
pub struct MessageMapping {
    pub id: i64,
    pub app_channel_id: String,
    pub app_message_id: String,
    /// Normalized external sender; part of the §16 dedup key.
    pub normalized_sender: String,
    pub cokret_event_id: String,
    pub cokret_realm_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = message_mappings)]
pub struct NewMessageMapping<'a> {
    pub app_channel_id: &'a str,
    pub app_message_id: &'a str,
    pub normalized_sender: &'a str,
    pub cokret_event_id: &'a str,
    pub cokret_realm_id: &'a str,
    pub created_at: i64,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = user_mappings)]
pub struct UserMapping {
    pub id: i64,
    pub protocol: String,
    pub tenant: String,
    pub external_user_id: String,
    pub cokret_actor_id: String,
    pub profile_event_ref: String,
    pub accountability_grant_ref: String,
    pub authorization_ref: String,
    pub display_name: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = user_mappings)]
pub struct NewUserMapping<'a> {
    pub protocol: &'a str,
    pub tenant: &'a str,
    pub external_user_id: &'a str,
    pub cokret_actor_id: &'a str,
    pub profile_event_ref: &'a str,
    pub accountability_grant_ref: &'a str,
    pub authorization_ref: &'a str,
    pub display_name: Option<&'a str>,
    pub created_at: i64,
}
