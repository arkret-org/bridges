//! Diesel table definitions for the messaging helper layer.

diesel::table! {
    /// App channel/conversation <-> Cokret realm mapping.
    room_mappings (id) {
        id -> BigInt,
        app_channel_id -> Text,
        cokret_realm_id -> Text,
        portal_alias -> Nullable<Text>,
        created_at -> BigInt,
    }
}

diesel::table! {
    /// App message id <-> Cokret event id mapping.
    message_mappings (id) {
        id -> BigInt,
        app_channel_id -> Text,
        app_message_id -> Text,
        cokret_event_id -> Text,
        cokret_realm_id -> Text,
        created_at -> BigInt,
    }
}

diesel::table! {
    /// External protocol/user <-> Cokret actor DID mapping.
    user_mappings (id) {
        id -> BigInt,
        protocol -> Text,
        tenant -> Text,
        external_user_id -> Text,
        cokret_actor_did -> Text,
        profile_event_ref -> Text,
        accountability_grant_ref -> Text,
        authorization_ref -> Text,
        display_name -> Nullable<Text>,
        created_at -> BigInt,
    }
}

diesel::allow_tables_to_appear_in_same_query!(room_mappings, message_mappings, user_mappings);
