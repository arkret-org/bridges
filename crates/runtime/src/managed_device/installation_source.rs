//! Local hints from accepted installation results, never another authority rail.

use arkret_models_collaboration::applet_installation_authority::{
    AppletAuthorityMaterialRequestBody, AppletAuthorityMaterialResponseBody,
    AppletInstallationCurrentBinding,
};
use arkret_models_collaboration::exact_current_state::{
    ExactCurrentStateEntry, ExactCurrentStateReadResponseBody,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilityGrantStatus, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_integration::{AppletInstallResponseBody, AppletRegistrationPayload};

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationHint {
    effective_scope: ScopeRef,
    outcome: AppletInstallResponseBody,
}

fn hint_key(applet: &str, service: &arkret::DidCoreId, scope: &ScopeRef) -> Result<String> {
    Ok(format!(
        "managed-installation-source/v1/{}",
        canonical_sha256(&(applet, service, scope))?
    ))
}

fn source_request(
    applet: &str,
    scope: &ScopeRef,
    creation_scope: &ScopeRef,
    creation_source: Option<&arkret::GrantId>,
    hint: Option<&InstallationHint>,
) -> Result<(
    AppletAuthorityMaterialRequestBody,
    Option<(arkret::EventId, arkret::Hash)>,
)> {
    if scope.realm_id() != creation_scope.realm_id() {
        return Err(invalid(
            "installation source must stay in the actor's Realm",
        ));
    }
    if scope == creation_scope && hint.is_none() {
        let creation_source = creation_source.ok_or_else(|| {
            invalid("a replacement Service requires its own accepted installation outcome")
        })?;
        return Ok((
            AppletAuthorityMaterialRequestBody {
                effective_scope: scope.clone(),
                grant_ids: vec![creation_source.clone()],
            },
            None,
        ));
    }
    let hint = hint.ok_or_else(|| {
        invalid("another scope requires its actual accepted installation outcome")
    })?;
    if &hint.effective_scope != scope || hint.outcome.applet_id.as_str() != applet {
        return Err(invalid(
            "installation hint belongs to another Applet or scope",
        ));
    }
    let id =
        hint.outcome.capability_grant_refs.first().ok_or_else(|| {
            invalid("accepted installation outcome has no capability grant source")
        })?;
    Ok((
        AppletAuthorityMaterialRequestBody {
            effective_scope: scope.clone(),
            grant_ids: vec![id.clone()],
        },
        Some((
            hint.outcome.registration_event_ref.clone(),
            hint.outcome.registration_epoch.clone(),
        )),
    ))
}

/// Validate a fresh exact read against an independently retained source hint.
/// `current_binding` alone does not prove that an arbitrary business parent
/// belongs to the installation aggregate; the hint comes from its actual
/// install outcome, or from an already accepted creation's authorization ref.
fn source_grant(
    applet: &arkret::AppletId,
    service: &arkret::DidCoreId,
    request: &AppletAuthorityMaterialRequestBody,
    material: &AppletAuthorityMaterialResponseBody,
    registration: Option<(&arkret::EventId, &arkret::Hash)>,
) -> Result<CapabilityGrant> {
    material.validate_for_request(applet, request)?;
    let AppletInstallationCurrentBinding::Active {
        registration_ref,
        registration_epoch,
        service_id,
    } = &material.current_binding
    else {
        return Err(invalid("exact Applet installation is inactive"));
    };
    let payload: AppletRegistrationPayload =
        serde_json::from_value(serde_json::to_value(&material.registration.event.payload)?)?;
    if service_id != service
        || payload.service_id != *service
        || payload.applet_id != *applet
        || &payload.registration_epoch != registration_epoch
        || registration_ref.event_id != material.registration.event.event_id
        || registration_ref.commit_id != material.registration.commit.commit_id
        || registration_ref.stream_ref != material.registration.commit.stream_ref
        || registration_ref.stream_position != material.registration.commit.stream_position
        || registration.is_some_and(|(event, epoch)| {
            event != &registration_ref.event_id || epoch != registration_epoch
        })
    {
        return Err(invalid(
            "installation source differs from its current registration",
        ));
    }
    let [id] = request.grant_ids.as_slice() else {
        return Err(invalid("installation source requires one exact grant"));
    };
    let mut rows = material
        .current_states
        .iter()
        .filter_map(|entry| match entry {
            ExactCurrentStateReadResponseBody::Present {
                entry: ExactCurrentStateEntry::CapabilityGrant(row),
                ..
            } if &row.selector.grant_id == id => Some(row),
            _ => None,
        });
    let row = rows
        .next()
        .ok_or_else(|| invalid("installation source has no exact current grant"))?;
    if rows.next().is_some() {
        return Err(invalid(
            "installation source repeats the exact current grant",
        ));
    }
    let bindings: Vec<_> = row
        .value
        .constraints
        .iter()
        .filter(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                && constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
        })
        .collect();
    if &row.selector.grant_id != id
        || &row.value.id != id
        || row.value.status != CapabilityGrantStatus::Active
        || bindings.len() != 1
        || bindings[0].registration_epoch.as_ref() != Some(registration_epoch)
    {
        return Err(invalid("installation source grant is not active"));
    }
    Ok(row.value.clone())
}

impl ManagedDeviceRuntime {
    /// Remember the result returned by an actual installation operation for a
    /// second scope or replacement Service. The host passes the exact SDK install
    /// result before starting that Service's managed business work. This is a
    /// local source hint, not proof of membership in
    /// the installation aggregate or a cached business allow. Every use reads
    /// fresh exact material; the Station still enforces the exact installation.
    pub async fn remember_installation_outcome(
        &self,
        effective_scope: &ScopeRef,
        outcome: &AppletInstallResponseBody,
    ) -> Result<()> {
        let hint = InstallationHint {
            effective_scope: effective_scope.clone(),
            outcome: outcome.clone(),
        };
        self.read_installation_hint(&hint).await?;
        let key = hint_key(
            self.edge.applet_id(),
            self.edge.service_actor_id(),
            effective_scope,
        )?;
        let current = self.read(&key).await?;
        let next = self.authoring.encrypt_key_material(&key, &hint)?;
        if !self.cas(&key, current, next).await? {
            return Err(invalid(
                "installation source changed concurrently; retry the same outcome",
            ));
        }
        Ok(())
    }

    async fn read_installation_hint(&self, hint: &InstallationHint) -> Result<CapabilityGrant> {
        if !matches!(
            hint.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        ) || hint.outcome.applet_id.as_str() != self.edge.applet_id()
            || hint.outcome.service_id != *self.edge.service_actor_id()
        {
            return Err(invalid(
                "installation hint belongs to another Applet or scope",
            ));
        }
        let id = hint.outcome.capability_grant_refs.first().ok_or_else(|| {
            invalid("accepted installation outcome has no capability grant source")
        })?;
        self.exact_source_grant(
            &hint.effective_scope,
            id,
            Some((
                &hint.outcome.registration_event_ref,
                &hint.outcome.registration_epoch,
            )),
        )
        .await
    }

    pub(super) async fn subject_installation_source(
        &self,
        device: &ManagedDevice,
    ) -> Result<arkret::GrantId> {
        let original = self.edge.retained_managed_actor(&device.actor_id)?;
        let creation = crate::managed_authoring::creation_payload(
            crate::managed_authoring::creation_event(&original)?,
        )?;
        let key = hint_key(
            self.edge.applet_id(),
            self.edge.service_actor_id(),
            &device.effective_scope,
        )?;
        let hint = self
            .read(&key)
            .await?
            .map(|raw| {
                self.authoring
                    .decrypt_key_material::<InstallationHint>(&key, &raw)
            })
            .transpose()?;
        let (request, mut registration) = source_request(
            self.edge.applet_id(),
            &device.effective_scope,
            &creation.creation_scope,
            (creation.service_id == *self.edge.service_actor_id())
                .then_some(&creation.creation_authorization_ref),
            hint.as_ref(),
        )?;
        if registration.is_none() {
            let arkret::RealmActorMaterial::Event {
                producer_signer_fact,
                ..
            } = &original.authoring_context.material.material
            else {
                return Err(invalid("creation source lost its original signer fact"));
            };
            let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(fact) =
                producer_signer_fact
            else {
                return Err(invalid("creation source requires its historical Service fact"));
            };
            registration = Some((
                creation.registration_ref,
                fact.key.registration_epoch.clone(),
            ));
        }
        Ok(self
            .exact_source_grant(
                &device.effective_scope,
                &request.grant_ids[0],
                registration.as_ref().map(|(event, epoch)| (event, epoch)),
            )
            .await?
            .id)
    }

    async fn exact_source_grant(
        &self,
        scope: &ScopeRef,
        id: &arkret::GrantId,
        registration: Option<(&arkret::EventId, &arkret::Hash)>,
    ) -> Result<CapabilityGrant> {
        let request = AppletAuthorityMaterialRequestBody {
            effective_scope: scope.clone(),
            grant_ids: vec![id.clone()],
        };
        let route = self.edge.realm_route(scope.realm_id()).await?;
        let material = route
            .client
            .applet_authority_material(self.edge.applet_id(), &request)
            .await?;
        let commits: Vec<_> = std::iter::once(&material.registration.commit)
            .chain(material.grant_events.iter().map(|pair| &pair.commit))
            .collect();
        let keys = garth::historical_station_keys::fetch_historical_station_keys_for_commits(
            &route.client,
            &route.bundle,
            &commits,
        )
        .await
        .map_err(|error| invalid(error.to_string()))?;
        for original in std::iter::once(&material.registration).chain(&material.grant_events) {
            route
                .authority
                .verify_committed_item(
                    &arkret::CommittedEventFullView {
                        event: original.event.clone(),
                        commit: original.commit.clone(),
                    },
                    &keys,
                )
                .map_err(|error| invalid(error.to_string()))?;
        }
        if material.current_states.iter().any(|row| {
            !matches!(row, ExactCurrentStateReadResponseBody::Present { governance_generation, .. }
                if *governance_generation == route.authority.current_generation())
        }) {
            return Err(invalid(
                "installation current belongs to another governance cut",
            ));
        }
        source_grant(
            &arkret::AppletId::new(self.edge.applet_id())?,
            self.edge.service_actor_id(),
            &request,
            &material,
            registration,
        )
    }
}

#[cfg(test)]
mod tests;
