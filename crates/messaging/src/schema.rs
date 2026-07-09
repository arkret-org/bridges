//! Diesel table definitions for the messaging helper layer.

diesel::table! {
    /// App channel/conversation <-> Arkret portal mapping. The mapping unit is
    /// `(realm_id, strand_id)` per applet-integration §10.1: `portal_strand_id` is
    /// resolved lazily through the §10.1 acquisition path and cached here.
    channel_realm_mappings (id) {
        id -> BigInt,
        app_channel_id -> Text,
        cokret_realm_id -> Text,
        portal_alias -> Nullable<Text>,
        portal_strand_id -> Nullable<Text>,
        created_at -> BigInt,
    }
}

diesel::table! {
    /// App message id <-> Arkret event id mapping. `normalized_sender` is part
    /// of the dedup key (applet-integration §16 minimum key set).
    message_mappings (id) {
        id -> BigInt,
        app_channel_id -> Text,
        app_message_id -> Text,
        normalized_sender -> Text,
        cokret_event_id -> Text,
        cokret_realm_id -> Text,
        created_at -> BigInt,
    }
}

diesel::table! {
    /// External protocol/user <-> Arkret actor DID mapping.
    user_mappings (id) {
        id -> BigInt,
        protocol -> Text,
        tenant -> Text,
        external_user_id -> Text,
        cokret_actor_id -> Text,
        profile_event_ref -> Text,
        accountability_grant_ref -> Text,
        authorization_ref -> Text,
        display_name -> Nullable<Text>,
        created_at -> BigInt,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    channel_realm_mappings,
    message_mappings,
    user_mappings
);
