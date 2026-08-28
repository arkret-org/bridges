//! Diesel row models for the messaging helper layer.

use arkret::{Did, DidCoreId};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use super::schema::{channel_realm_mappings, message_mappings, user_mappings};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = channel_realm_mappings)]
pub struct ChannelRealmMapping {
    pub id: i64,
    pub app_channel_id: String,
    pub arkret_realm_id: String,
    pub portal_alias: Option<String>,
    /// The portal strand this external location maps to (applet-integration
    /// §10.1: mapping unit is `(realm_id, strand_id)`); resolved lazily.
    pub portal_strand_id: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = channel_realm_mappings)]
pub struct NewChannelRealmMapping<'a> {
    pub app_channel_id: &'a str,
    pub arkret_realm_id: &'a str,
    pub portal_alias: Option<&'a str>,
    pub portal_strand_id: Option<&'a str>,
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
    pub arkret_event_id: String,
    pub arkret_realm_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = message_mappings)]
pub struct NewMessageMapping<'a> {
    pub app_channel_id: &'a str,
    pub app_message_id: &'a str,
    pub normalized_sender: &'a str,
    pub arkret_event_id: &'a str,
    pub arkret_realm_id: &'a str,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMapping {
    pub id: i64,
    pub protocol: String,
    pub tenant: String,
    pub external_user_id: String,
    pub arkret_actor_id: DidCoreId,
    pub arkret_actor_did: Did,
    pub profile_event_ref: String,
    pub accountability_grant_ref: String,
    pub authorization_ref: String,
    pub display_name: Option<String>,
    pub created_at: i64,
}

/// Raw persistence boundary. Both actor identity columns are validated into
/// [`UserMapping`] immediately after Diesel reads the row.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_mappings)]
pub(crate) struct UserMappingRow {
    id: i64,
    protocol: String,
    tenant: String,
    external_user_id: String,
    arkret_actor_id: String,
    arkret_actor_did: String,
    profile_event_ref: String,
    accountability_grant_ref: String,
    authorization_ref: String,
    display_name: Option<String>,
    created_at: i64,
}

impl TryFrom<UserMappingRow> for UserMapping {
    type Error = arkret::identifiers::IdentifierError;

    fn try_from(row: UserMappingRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            protocol: row.protocol,
            tenant: row.tenant,
            external_user_id: row.external_user_id,
            arkret_actor_id: DidCoreId::new(row.arkret_actor_id)?,
            arkret_actor_did: Did::new(row.arkret_actor_did)?,
            profile_event_ref: row.profile_event_ref,
            accountability_grant_ref: row.accountability_grant_ref,
            authorization_ref: row.authorization_ref,
            display_name: row.display_name,
            created_at: row.created_at,
        })
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = user_mappings)]
pub struct NewUserMapping<'a> {
    pub protocol: &'a str,
    pub tenant: &'a str,
    pub external_user_id: &'a str,
    pub arkret_actor_id: &'a str,
    pub arkret_actor_did: &'a str,
    pub profile_event_ref: &'a str,
    pub accountability_grant_ref: &'a str,
    pub authorization_ref: &'a str,
    pub display_name: Option<&'a str>,
    pub created_at: i64,
}
