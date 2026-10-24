//! Private MLS identity and exact original publication in the Device custody CAS.
use std::collections::{BTreeMap, BTreeSet};

use arkret::mls::{ArkretMlsIdentity, ArkretMlsSigner};
use arkret::{
    KeyPackagesUploadRequestBody, KeyPackagesUploadResponseBody, LocalMlsKeyPackageInventory,
    LocalMlsKeyPackageInventoryEntry, MlsEndpointIdentity, MlsKeyPackageRecord, MlsKeyPackageState,
};

use super::*;

const MAX_NEW_PACKAGES_PER_CYCLE: usize = 20;
const CAS_ATTEMPTS: usize = 8;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedMlsState {
    scopes: BTreeMap<String, ScopeInventory>,
    #[serde(default)]
    pub(super) inboxes: BTreeMap<String, super::inbox::ScopeInbox>,
    #[serde(default)]
    pub(super) streams: BTreeMap<String, super::stream::ScopeStream>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeInventory {
    scope: ScopeRef,
    identity: Vec<u8>,
    publications: Vec<Publication>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    request: KeyPackagesUploadRequestBody,
    records: Vec<MlsKeyPackageRecord>,
    outcome: Option<KeyPackagesUploadResponseBody>,
}

fn endpoint(record: &DeviceRecord) -> Result<MlsEndpointIdentity> {
    Ok(MlsEndpointIdentity::human_device(
        record.plan.actor_id.signing_principal_id().clone(),
        payload(record)?.device_id,
    ))
}

pub(super) fn identity(record: &DeviceRecord, scope: &ScopeRef) -> Result<ArkretMlsIdentity> {
    let actor = record.plan.actor_id.clone();
    match record
        .mls
        .scopes
        .get(&scope.canonical_mls_group_id()?.to_string())
    {
        Some(state) if &state.scope == scope => {
            let bytes = &state.identity;
            ArkretMlsIdentity::restore_from_private_state(actor, endpoint(record)?, bytes).map_err(
                |_| invalid("MLS private identity cannot be restored for its original endpoint"),
            )
        }
        None => ArkretMlsIdentity::new_realm_device(
            actor,
            payload(record)?.device_id,
            ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&seed(
                &record.device_seed,
            )?)),
        )
        .map_err(|_| invalid("MLS identity cannot be initialized for its original endpoint")),
        _ => Err(invalid("MLS inventory has another original scope identity")),
    }
}

fn accepted_refs(publication: &Publication) -> Result<BTreeSet<String>> {
    let Some(outcome) = &publication.outcome else {
        return Ok(BTreeSet::new());
    };
    let submitted: BTreeSet<_> = publication
        .request
        .keypackages
        .iter()
        .map(|entry| entry.keypackage_ref.clone())
        .collect();
    let mut accepted: BTreeSet<_> = outcome.keypackage_refs.iter().cloned().collect();
    // The contract permits omission of refs. An all-accepted response is
    // unambiguous; a partial response must identify the actual accepted subset.
    if accepted.is_empty()
        && outcome.accepted_count as usize == submitted.len()
        && outcome.rejections.is_empty()
    {
        accepted = submitted.clone();
    }
    if accepted.len() != outcome.accepted_count as usize
        || (!outcome.keypackage_refs.is_empty() && accepted.len() != outcome.keypackage_refs.len())
        || !accepted.is_subset(&submitted)
        || (accepted.len() != submitted.len() && outcome.rejections.is_empty())
    {
        return Err(invalid(
            "MLS publication response does not bind its original batch",
        ));
    }
    Ok(accepted)
}

fn validate_publication(
    record: &DeviceRecord,
    scope: &ScopeRef,
    batch: &Publication,
) -> Result<()> {
    let request = &batch.request;
    request.validate_shape().map_err(invalid)?;
    let p = payload(record)?;
    let method = format!("{}#{}", record.principal_did, p.device_id);
    if request.actor_id != record.plan.actor_id.clone()
        || request.principal_id != *record.plan.actor_id.signing_principal_id()
        || request.device_id.as_ref() != Some(&p.device_id)
        || request.agent_verification_method.is_some()
        || request.agent_key_authorize_event_id.is_some()
        || request.mls_group_id.as_ref() != Some(&scope.canonical_mls_group_id()?)
        || request.strand_id.is_some()
        || request.endpoint_signature.kid.as_str() != method
        || batch.records.len() != request.keypackages.len()
    {
        return Err(invalid(
            "MLS publication differs from its original Device or scope",
        ));
    }
    let key = SigningKey::from_bytes(&seed(&record.device_seed)?);
    arkret::signatures::keypackages::verify_keypackage_signing_input(
        key.verifying_key().as_bytes(),
        &method,
        &arkret::keypackages_upload_signing_input(&request.unsigned())?,
        &request.endpoint_signature,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let identity = identity(record, scope)?;
    for (original, entry) in batch.records.iter().zip(&request.keypackages) {
        if original.actor_id != record.plan.actor_id.clone()
            || original.endpoint != endpoint(record)?
        {
            return Err(invalid(
                "MLS inventory record has another complete endpoint",
            ));
        }
        let live = original.expires_at.is_none_or(|expiry| expiry > Utc::now());
        // Expired originals remain authenticated audit, not current RFC
        // candidates. Their expiry must not block an unrelated fresh batch.
        let expected = if live {
            let expected = identity
                .key_package_upload_entry(original)
                .map_err(|error| invalid(error.to_string()))?;
            let leaf = arkret::mls::author_leaf_from_key_package_bytes(
                &arkret::base64url_decode(&original.keypackage)?,
                0,
            )
            .map_err(|error| invalid(error.to_string()))?;
            if leaf.signature_key.as_slice() != key.verifying_key().as_bytes() {
                return Err(invalid(
                    "MLS KeyPackage leaf differs from the actual Device key",
                ));
            }
            expected
        } else {
            arkret::mls_key_package_record_upload_entry(original).map_err(invalid)?
        };
        if canonical_json_bytes(&expected)? != canonical_json_bytes(entry)? {
            return Err(invalid(
                "MLS inventory differs from its frozen public record",
            ));
        }
        if original.state == MlsKeyPackageState::Published
            && live
            && !identity
                .holds_private_key_package(original)
                .map_err(|error| invalid(error.to_string()))?
        {
            return Err(invalid(
                "MLS publication lost its original private KeyPackage",
            ));
        }
    }
    accepted_refs(batch)?;
    Ok(())
}

fn inventory(record: &DeviceRecord, scope: &ScopeRef) -> Result<LocalMlsKeyPackageInventory> {
    let mut result = LocalMlsKeyPackageInventory {
        endpoint: endpoint(record)?,
        entries: BTreeMap::new(),
    };
    let mut references = BTreeSet::new();
    let group = scope.canonical_mls_group_id()?.to_string();
    let Some(state) = record.mls.scopes.get(&group) else {
        return Ok(result);
    };
    if &state.scope != scope {
        return Err(invalid("MLS inventory has another actual scope"));
    }
    let private_identity = identity(record, scope)?;
    for batch in &state.publications {
        validate_publication(record, scope, batch)?;
        let accepted = accepted_refs(batch)?;
        for package in &batch.records {
            if batch.outcome.is_none() {
                continue;
            }
            if !references.insert(package.keypackage_ref.clone()) {
                return Err(invalid("MLS inventory repeats a private KeyPackage bundle"));
            }
            let entry = LocalMlsKeyPackageInventoryEntry {
                keypackage_id: package.keypackage_id.clone(),
                keypackage_ref: package.keypackage_ref.clone(),
                state: if accepted.contains(package.keypackage_ref.as_str()) {
                    package.state
                } else {
                    MlsKeyPackageState::Retired
                },
                has_private_state: package.state == MlsKeyPackageState::Published
                    && package.expires_at.is_none_or(|expiry| expiry > Utc::now())
                    && private_identity
                        .holds_private_key_package(package)
                        .map_err(|error| invalid(error.to_string()))?,
                created_at: package.created_at,
                expires_at: package
                    .expires_at
                    .ok_or_else(|| invalid("MLS package has no expiry"))?,
                last_resort: package.last_resort,
            };
            if result
                .entries
                .insert(entry.keypackage_id.clone(), entry)
                .is_some()
            {
                return Err(invalid("MLS inventory repeats a KeyPackage identity"));
            }
        }
    }
    Ok(result)
}

impl ManagedDeviceRuntime {
    pub(super) async fn accepted_device_record(
        &self,
        device: &ManagedDevice,
    ) -> Result<(String, String, DeviceRecord)> {
        let operation_key = format!(
            "managed-device/v1/{}",
            canonical_sha256(&(&device.actor_id, &device.operation_id))?
        );
        let raw = self
            .read(&operation_key)
            .await?
            .ok_or_else(|| invalid("MLS Device custody is unavailable"))?;
        let record: DeviceRecord = self.decrypt_device_record(&operation_key, &raw).await?;
        self.validate(&record)?;
        if record.plan.actor_id != device.actor_id
            || record.plan.operation_id != device.operation_id
            || payload(&record)?.device_id != device.device_id
            || record.authorization.event_id() != &device.authorization_event_id
            || !record.plan.scopes.contains_scope(&device.effective_scope)
            || !matches!(&record.outcome, Some(AuthoritySubmitResponseBody::Accepted { commit, .. }) if commit == &device.authorization_commit)
        {
            return Err(invalid(
                "MLS state belongs to another original Device instance",
            ));
        }
        Ok((operation_key, raw, record))
    }

    /// Local metadata only; pending HTTP publications never count as available.
    pub async fn mls_key_package_inventory(
        &self,
        device: &ManagedDevice,
    ) -> Result<LocalMlsKeyPackageInventory> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        inventory(&record, &device.effective_scope)
    }

    /// Commit the private identity, private bundles and exact signed batch in
    /// one existing custody CAS before permitting any network attempt.
    pub async fn prepare_mls_key_packages(
        &self,
        device: &ManagedDevice,
        low_water: usize,
    ) -> Result<Option<KeyPackagesUploadRequestBody>> {
        if !(1..=1000).contains(&low_water) {
            return Err(BridgeError::Config(
                "MLS inventory target must be 1..=1000".into(),
            ));
        }
        for _ in 0..CAS_ATTEMPTS {
            let (operation_key, previous, mut record) = self.accepted_device_record(device).await?;
            let now = Utc::now();
            if now < record.plan.not_before || now >= record.plan.expires_at {
                return Err(invalid(
                    "MLS publication Device is outside its original lifetime",
                ));
            }
            let scope = &device.effective_scope;
            let group = scope.canonical_mls_group_id()?.to_string();
            let current = inventory(&record, scope)?;
            if let Some(state) = record.mls.scopes.get(&group) {
                if let Some(pending) = state
                    .publications
                    .iter()
                    .find(|batch| batch.outcome.is_none())
                {
                    return Ok(Some(pending.request.clone()));
                }
                if state.publications.iter().any(|batch| {
                    batch
                        .outcome
                        .as_ref()
                        .is_some_and(|outcome| !outcome.rejections.is_empty())
                }) {
                    return Err(BridgeError::App(
                        "MLS inventory has a terminal publication rejection".into(),
                    ));
                }
            }
            let deficit = current
                .maintenance_deficit(now, low_water)
                .min(MAX_NEW_PACKAGES_PER_CYCLE);
            if deficit == 0 {
                return Ok(None);
            }
            // A scope owns one provider. Generate additional private bundles
            // through its live group so checkpoint restore cannot resurrect
            // an older provider and discard newly published KeyPackages.
            let live_group = super::inbox::restore_group(&record, device)?;
            let standalone = if live_group.is_none() {
                Some(identity(&record, scope)?)
            } else {
                None
            };
            let identity = live_group
                .as_ref()
                .map(|group| group.identity())
                .or(standalone.as_ref())
                .ok_or_else(|| invalid("MLS scope identity is unavailable"))?;
            let records = (0..deficit)
                .map(|_| {
                    identity
                        .key_package_record()
                        .map_err(|error| invalid(error.to_string()))
                })
                .collect::<Result<Vec<_>>>()?;
            let p = payload(&record)?;
            let method = format!("{}#{}", record.principal_did, p.device_id);
            let mut unsigned = identity
                .signed_key_packages_upload_request(&records, &method)
                .map_err(|error| invalid(error.to_string()))?
                .unsigned();
            unsigned.mls_group_id = Some(scope.canonical_mls_group_id()?);
            let key = SigningKey::from_bytes(&seed(&record.device_seed)?);
            let signature = arkret::signatures::keypackages::keypackage_signature_from_bytes(
                &method,
                &key.sign(&arkret::keypackages_upload_signing_input(&unsigned)?)
                    .to_bytes(),
            )
            .map_err(|error| invalid(error.to_string()))?;
            let request = unsigned.into_signed(signature);
            let private_identity = identity
                .export_private_state()
                .map_err(|error| invalid(error.to_string()))?;
            if let Some(group) = &live_group {
                super::inbox::refresh_group_private_state(
                    &mut record,
                    device,
                    group
                        .export_state_record()
                        .map_err(|error| invalid(error.to_string()))?,
                )?;
            }
            let scope_state =
                record
                    .mls
                    .scopes
                    .entry(group.clone())
                    .or_insert_with(|| ScopeInventory {
                        scope: scope.clone(),
                        identity: Vec::new(),
                        publications: Vec::new(),
                    });
            scope_state.identity = private_identity;
            let publication = Publication {
                request: request.clone(),
                records,
                outcome: None,
            };
            validate_publication(&record, scope, &publication)?;
            record
                .mls
                .scopes
                .get_mut(&group)
                .ok_or_else(|| invalid("MLS scope disappeared"))?
                .publications
                .push(publication);
            let next = self
                .authoring
                .encrypt_key_material(&operation_key, &record)?;
            if self.cas(&operation_key, Some(previous), next).await? {
                return Ok(Some(request));
            }
        }
        Err(BridgeError::Runtime(
            "MLS preparation contended; reload durable custody".into(),
        ))
    }

    /// Replays the frozen original after a lost response or failed outcome CAS.
    pub async fn maintain_mls_key_packages(
        &self,
        device: &ManagedDevice,
        low_water: usize,
    ) -> Result<()> {
        let Some(request) = self.prepare_mls_key_packages(device, low_water).await? else {
            return Ok(());
        };
        let response = device.client().keypackages_upload(&request).await?;
        let digest = canonical_sha256(&request)?;
        for _ in 0..CAS_ATTEMPTS {
            let (operation_key, previous, mut record) = self.accepted_device_record(device).await?;
            let group = device.effective_scope.canonical_mls_group_id()?.to_string();
            let state = record
                .mls
                .scopes
                .get_mut(&group)
                .ok_or_else(|| invalid("MLS publication scope disappeared"))?;
            let mut index = None;
            for (position, batch) in state.publications.iter().enumerate() {
                if canonical_sha256(&batch.request)? == digest {
                    index = Some(position);
                    break;
                }
            }
            let batch = &mut state.publications
                [index.ok_or_else(|| invalid("MLS publication original disappeared"))?];
            if let Some(winner) = &batch.outcome {
                if canonical_json_bytes(winner)? != canonical_json_bytes(&response)? {
                    return Err(invalid(
                        "MLS publication outcome conflicts with its durable winner",
                    ));
                }
                return publication_result(&response);
            }
            batch.outcome = Some(response.clone());
            accepted_refs(batch)?;
            let next = self
                .authoring
                .encrypt_key_material(&operation_key, &record)?;
            if self.cas(&operation_key, Some(previous), next).await? {
                return publication_result(&response);
            }
        }
        Err(BridgeError::Runtime(
            "MLS outcome persistence contended; retry the original".into(),
        ))
    }
}

fn publication_result(outcome: &KeyPackagesUploadResponseBody) -> Result<()> {
    if outcome.rejections.is_empty() {
        Ok(())
    } else {
        Err(BridgeError::App(
            "MLS publication rejections are retained in original custody".into(),
        ))
    }
}

/// Retain publication bytes while recording that its original private bundle
/// was used by a durable Welcome. Last-resort bundles remain reusable.
pub(super) fn mark_welcome_package(
    record: &mut DeviceRecord,
    scope: &ScopeRef,
    claim: &arkret::KeyPackageClaimRecord,
    consumed: bool,
) -> Result<()> {
    let group = scope.canonical_mls_group_id()?.to_string();
    let state = record
        .mls
        .scopes
        .get_mut(&group)
        .ok_or_else(|| invalid("Welcome has no original local publication"))?;
    if &state.scope != scope {
        return Err(invalid("Welcome publication scope changed"));
    }
    let mut found = false;
    for batch in &mut state.publications {
        let accepted = accepted_refs(batch)?;
        for package in &mut batch.records {
            if package.keypackage_ref.as_str() != claim.keypackage_ref {
                continue;
            }
            if found
                || !accepted.contains(package.keypackage_ref.as_str())
                || package.keypackage != claim.keypackage
                || package.actor_id != claim.actor_id
                || !matches!(&package.endpoint, MlsEndpointIdentity::HumanDevice { device_id, .. } if claim.device_id.as_ref() == Some(device_id) && claim.agent_verification_method.is_none())
            {
                return Err(invalid(
                    "Welcome claim differs from original published KeyPackage",
                ));
            }
            found = true;
            if !package.last_resort {
                if !consumed && package.state == MlsKeyPackageState::Consumed {
                    return Err(invalid(
                        "Welcome reuses an already consumed single-use KeyPackage",
                    ));
                }
                if package
                    .claim_id
                    .as_deref()
                    .is_some_and(|id| id != claim.claim_id)
                {
                    return Err(invalid(
                        "single-use KeyPackage was already used by another claim",
                    ));
                }
                if !matches!(
                    package.state,
                    MlsKeyPackageState::Published
                        | MlsKeyPackageState::Claimed
                        | MlsKeyPackageState::Consumed
                ) {
                    return Err(invalid("Welcome uses a retired KeyPackage"));
                }
                package.claim_id = Some(claim.claim_id.clone());
                package.state = if consumed || package.state == MlsKeyPackageState::Consumed {
                    MlsKeyPackageState::Consumed
                } else {
                    MlsKeyPackageState::Claimed
                };
            }
        }
    }
    if !found {
        return Err(invalid("Welcome has no original local private KeyPackage"));
    }
    Ok(())
}

pub(super) fn retain_scope_identity(
    record: &mut DeviceRecord,
    scope: &ScopeRef,
    bytes: Vec<u8>,
) -> Result<()> {
    let state = record
        .mls
        .scopes
        .get_mut(&scope.canonical_mls_group_id()?.to_string())
        .ok_or_else(|| invalid("joined MLS scope has no private publication identity"))?;
    if &state.scope != scope {
        return Err(invalid("joined MLS identity has another scope"));
    }
    state.identity = bytes;
    Ok(())
}
