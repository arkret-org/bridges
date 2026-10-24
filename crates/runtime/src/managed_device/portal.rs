//! Portal discovery uses currently admitted originals, never a Service read.
use arkret::{CommitStreamRef, CurrentSelector, CurrentState, StrandId};
use serde_json::Value;

use super::*;

impl ManagedDeviceRuntime {
    /// Select an existing local identity without minting another Bot or Ghost.
    /// Device bootstrap and every remote read independently check current access.
    pub async fn local_actor_for_realm(&self, realm: &arkret::RealmId) -> Result<Option<ActorId>> {
        let mut actors = self.authoring.managed_actor_ids().await?;
        actors.sort();
        Ok(actors.into_iter().find(|actor| {
            actor
                .as_realm_actor_id()
                .is_some_and(|id| &id.realm_id == realm)
        }))
    }

    /// Find the earliest accepted create with this exact signed location.
    /// Incomplete or withheld history cannot establish that no portal exists.
    pub async fn find_portal_strand(
        &self,
        actor: &ActorId,
        realm: &arkret::RealmId,
        location: &Value,
    ) -> Result<Option<StrandId>> {
        for key in ["protocol", "network_id", "location_id"] {
            if !location
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                return Err(invalid(
                    "portal location must contain all three nonempty identifiers",
                ));
            }
        }
        let device = self.device_for_actor(actor).await?;
        let scope = &device.effective_scope;
        if scope.realm_id() != realm
            || !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. })
        {
            return Err(invalid(
                "portal discovery requires this exact Realm Device scope",
            ));
        }
        self.ensure_realm_membership(&device).await?;
        let reader = self.open_reader(&device).await?;
        let response = reader.client().snapshot_head(realm).await?;
        let current = garth::own_station_results::consume_own_station_device_snapshot(&response)
            .map_err(|e| invalid(e.to_string()))?;
        let stream = CommitStreamRef::from_scope(scope, None)?;
        let cap = current
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == stream)
            .ok_or_else(|| invalid("portal current omits the Realm stream"))?;
        // Discover the current objects rather than requiring unrelated history
        // below a since-join floor. The signed create still supplies provenance;
        // inaccessible create originals cannot be treated as a negative match.
        let mut earliest: Option<(u64, StrandId)> = None;
        for row in &current.current_state_entries {
            let CurrentState::Value {
                selector: CurrentSelector::Strand { strand_id },
                source_stream_ref,
                ..
            } = row
            else {
                continue;
            };
            if source_stream_ref != &stream {
                return Err(invalid("portal projection contains another scope"));
            }
            let event_id = arkret::EventId::from_token_bytes(strand_id.token_bytes())?;
            let original = garth::own_station_results::consume_own_station_device_event(
                reader.client(),
                &event_id,
                reader.client().committed_event_get(&event_id).await?,
            )
            .await
            .map_err(|e| invalid(e.to_string()))?;
            let full = original.full().map_err(|e| invalid(e.to_string()))?;
            if full.event.kind != arkret::EventKind::StrandCreate
                || full.commit.stream_ref != stream
                || full.commit.stream_position > cap.stream_position
                || (full.commit.stream_position == cap.stream_position
                    && full.commit.commit_id != cap.commit_id)
            {
                return Err(invalid(
                    "portal create differs from its admitted projection",
                ));
            }
            if full.event.external_ref.as_ref().is_some_and(|external| {
                ["protocol", "network_id", "location_id"]
                    .iter()
                    .all(|key| external.get(*key) == location.get(*key))
            }) && earliest
                .as_ref()
                .is_none_or(|(position, _)| full.commit.stream_position < *position)
            {
                earliest = Some((full.commit.stream_position, strand_id.clone()));
            }
        }
        response.value()?;
        reader.check_device(&device)?;
        Ok(earliest.map(|(_, id)| id))
    }
}
