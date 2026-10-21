//! Native recipient pages and MLS checkpoints share the encrypted Device CAS.

use std::collections::{BTreeMap, BTreeSet};

use arkret::mls::ArkretMlsGroup;
use arkret::{
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, KeyPackageClaimRecord,
    KeyPackagesClaimQueryRequestBody, KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody,
    MlsEndpointIdentity, MlsGroupStateRecord, MlsMemberRosterAuthorityReadRequestBody,
    MlsWelcomeDelivery, RecipientDelivery, RecipientMlsDurableSigner,
};

use super::*;

const CAS_ATTEMPTS: usize = 8;
const MAX_ROSTER_PAGES: usize = 4096;

struct ReceivedRoster {
    request: MlsMemberRosterAuthorityReadRequestBody,
    pages: Vec<arkret::MlsSelfRosterAuthorityReadOutcome>,
    material: arkret::MlsGroupStateMaterialOutcome,
}

impl ReceivedRoster {
    fn install(&self, group: &mut ArkretMlsGroup) -> Result<arkret::EventId> {
        arkret::install_verified_mls_self_roster_bindings(
            group,
            &self.pages,
            &self.request,
            &self.material,
        )
        .map_err(invalid)?;
        Ok(self.pages[0].roster.manifest.genesis_event_ref.clone())
    }

    fn claim_issuer(
        &self,
        delivery: &MlsWelcomeDelivery,
        outcome: &arkret::KeyPackagesClaimOutcome,
    ) -> Result<&arkret::AuthenticatedServiceResolution> {
        let mut matches = self
            .pages
            .iter()
            .flat_map(|page| &page.roster.records)
            .filter_map(|record| match record {
                arkret::MlsRosterRecord::Add {
                    commit_event_ref,
                    attestation,
                    claim_issuer_resolution: Some(resolution),
                    ..
                } if commit_event_ref == &delivery.commit_event_ref
                    && attestation.actor_id == delivery.recipient_actor_id
                    && attestation.endpoint == delivery.recipient_endpoint
                    && attestation.welcome_id == delivery.welcome_id
                    && attestation.claim_id == delivery.keypackage_claim_ref =>
                {
                    Some((resolution, &attestation.claim_receipt))
                }
                _ => None,
            });
        let (resolution, receipt) = matches.next().ok_or_else(|| {
            invalid("Welcome claim has no exact imported historical issuer closure")
        })?;
        if matches.next().is_some() {
            return Err(invalid(
                "Welcome claim has duplicate historical issuer closures",
            ));
        }
        if canonical_json_bytes(receipt)? != canonical_json_bytes(&outcome.claim_receipt)? {
            return Err(invalid(
                "Welcome claim differs from its frozen historical receipt",
            ));
        }
        Ok(resolution)
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopeInbox {
    scope: Option<ScopeRef>,
    cursor: Option<String>,
    page: Option<DeviceMessagesGetOutcome>,
    group: Option<InstalledGroup>,
    welcomes: BTreeMap<String, DurableWelcome>,
}

pub(super) fn has_pending_work(record: &DeviceRecord) -> bool {
    record.mls.inboxes.values().any(|state| {
        state.page.is_some()
            || state
                .welcomes
                .values()
                .any(|welcome| welcome.outcome.is_none())
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledGroup {
    accepted: arkret_wire::CommittedEventFullView,
    state: MlsGroupStateRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableWelcome {
    delivery: MlsWelcomeDelivery,
    claim: KeyPackageClaimRecord,
    consume: KeyPackagesConsumeRequestBody,
    outcome: Option<KeyPackagesConsumeOutcome>,
}

/// One cycle's durable progress. Content items remain in the original page
/// until their own consumer checkpoints them; they never get skipped by ACK.
#[derive(Clone, Copy, Debug, Default)]
pub struct ManagedQueueProgress {
    pub durable_welcomes: usize,
    pub acknowledged: bool,
    pub has_more: bool,
}

fn group_key(device: &ManagedDevice) -> Result<String> {
    Ok(device.effective_scope.canonical_mls_group_id()?.to_string())
}

fn inbox<'a>(record: &'a DeviceRecord, device: &ManagedDevice) -> Result<Option<&'a ScopeInbox>> {
    let Some(inbox) = record.mls.inboxes.get(&group_key(device)?) else {
        return Ok(None);
    };
    if inbox.scope.as_ref() != Some(&device.effective_scope) {
        return Err(invalid("recipient inbox belongs to another exact scope"));
    }
    Ok(Some(inbox))
}

fn inbox_mut<'a>(
    record: &'a mut DeviceRecord,
    device: &ManagedDevice,
) -> Result<&'a mut ScopeInbox> {
    let inbox = record
        .mls
        .inboxes
        .entry(group_key(device)?)
        .or_insert_with(|| ScopeInbox {
            scope: Some(device.effective_scope.clone()),
            ..Default::default()
        });
    if inbox.scope.as_ref() != Some(&device.effective_scope) {
        return Err(invalid("recipient inbox belongs to another exact scope"));
    }
    Ok(inbox)
}

fn page_digest(page: &DeviceMessagesGetOutcome) -> Result<String> {
    Ok(canonical_sha256(page)?)
}

fn check_page(page: &DeviceMessagesGetOutcome, device: &ManagedDevice) -> Result<()> {
    page.validate_realm_device_recipient(
        &device.actor_id,
        &device.device_id,
        &device.effective_scope,
    )?;
    if page.deliveries.len() > 100
        || page.lost == Some(true)
        || (!page.deliveries.is_empty()
            && page.ack_token.as_ref().is_none_or(|token| token.is_empty()))
        || (page.has_more
            && page
                .next_cursor
                .as_ref()
                .is_none_or(|cursor| cursor.is_empty()))
    {
        return Err(invalid(
            "recipient queue page is incomplete or has lost items",
        ));
    }
    let mut welcomes = BTreeSet::new();
    for delivery in &page.deliveries {
        if let RecipientDelivery::MlsWelcome { mls_welcome } = delivery {
            garth::mls::admit_welcome(
                mls_welcome,
                &garth::LocalMlsEndpoint::device(
                    mls_welcome.realm_id.clone(),
                    device.actor_id.clone(),
                    device.device_id.clone(),
                ),
                &mls_welcome.commit_event_ref,
            )
            .map_err(|error| invalid(error.to_string()))?;
            if mls_welcome.effective_scope != device.effective_scope
                || !welcomes.insert(mls_welcome.welcome_id.clone())
            {
                return Err(invalid("recipient queue repeats a Welcome or mixes scopes"));
            }
        }
    }
    Ok(())
}

impl ManagedDeviceRuntime {
    /// Persist the authenticated original page before processing its contents.
    /// A cold worker resumes this page rather than advancing its opaque cursor.
    async fn durable_recipient_page(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
    ) -> Result<DeviceMessagesGetOutcome> {
        reader.check_device(device)?;
        let (_, _, record) = self.accepted_device_record(device).await?;
        if let Some(page) = inbox(&record, device)?.and_then(|inbox| inbox.page.as_ref()) {
            check_page(page, device)?;
            return Ok(page.clone());
        }
        let mut cursor = inbox(&record, device)?.and_then(|inbox| inbox.cursor.clone());
        let response = match reader
            .client()
            .receive_device_messages(cursor.as_deref(), Some(100))
            .await
        {
            Ok(response) => response,
            Err(error)
                if cursor.is_some()
                    && error.error_code() == Some(arkret_wire::ErrorCode::CursorExpired) =>
            {
                self.retire_expired_recipient_cursor(
                    device,
                    reader,
                    cursor
                        .as_deref()
                        .ok_or_else(|| invalid("expired cursor is absent"))?,
                )
                .await?;
                cursor = None;
                // This is a new authorized queue read, never a repaired cursor
                // or permission to skip outstanding items. The group and all
                // original delivery/consume checkpoints remain unchanged.
                reader
                    .client()
                    .receive_device_messages(None, Some(100))
                    .await?
            }
            Err(error) => return Err(error.into()),
        };
        let page = response.value()?.clone();
        check_page(&page, device)?;
        if page.deliveries.is_empty()
            && page.ack_token.is_none()
            && page.next_cursor.is_none()
            && !page.has_more
        {
            // An idle read has no material or continuation to checkpoint.
            return Ok(page);
        }
        for _ in 0..CAS_ATTEMPTS {
            reader.check_device(device)?;
            let (key, previous, mut record) = self.accepted_device_record(device).await?;
            let state = inbox_mut(&mut record, device)?;
            if let Some(winner) = &state.page {
                return Ok(winner.clone());
            }
            if state.cursor != cursor {
                return Err(invalid("recipient cursor changed during the read"));
            }
            state.page = Some(page.clone());
            let next = self.authoring.encrypt_key_material(&key, &record)?;
            response.value()?;
            if self.cas(&key, Some(previous), next).await? {
                return Ok(page);
            }
        }
        Err(invalid(
            "recipient page persistence contended; reload the durable page",
        ))
    }

    async fn retire_expired_recipient_cursor(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        expired: &str,
    ) -> Result<()> {
        for _ in 0..CAS_ATTEMPTS {
            reader.check_device(device)?;
            let (key, previous, mut record) = self.accepted_device_record(device).await?;
            let state = inbox_mut(&mut record, device)?;
            if state.page.is_some() || state.cursor.as_deref() != Some(expired) {
                return Err(invalid(
                    "recipient state changed while retiring its expired cursor",
                ));
            }
            state.cursor = None;
            let next = self.authoring.encrypt_key_material(&key, &record)?;
            reader.check_device(device)?;
            if self.cas(&key, Some(previous), next).await? {
                return Ok(());
            }
        }
        Err(invalid(
            "expired recipient cursor persistence contended; reload custody",
        ))
    }

    async fn install_received_welcome(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        delivery: &MlsWelcomeDelivery,
    ) -> Result<()> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        if let Some(prior) = inbox(&record, device)?
            .and_then(|inbox| inbox.welcomes.get(delivery.welcome_id.as_str()))
        {
            if canonical_json_bytes(&prior.delivery)? != canonical_json_bytes(delivery)? {
                return Err(invalid(
                    "durable Welcome id was reused for another delivery",
                ));
            }
            return Ok(());
        }
        let original = reader
            .client()
            .committed_event_get(&delivery.commit_event_ref)
            .await?;
        let original = garth::own_station_results::consume_own_station_device_event(
            reader.client(),
            &delivery.commit_event_ref,
            original,
        )
        .await
        .map_err(|error| invalid(error.to_string()))?;
        original
            .verify_welcome(delivery)
            .map_err(|error| invalid(error.to_string()))?;
        let accepted = original
            .full()
            .map_err(|error| invalid(error.to_string()))?
            .clone();
        let outcome = reader
            .client()
            .keypackages_claim_query(&KeyPackagesClaimQueryRequestBody {
                claim_id: delivery.keypackage_claim_ref.clone(),
            })
            .await?;
        let outcome = outcome.value()?.clone();
        let route = self.edge.realm_route(&delivery.realm_id).await?;
        let roster = self.read_received_roster(device, reader, &accepted).await?;
        // The frozen Add closure carries the original issuer's native history.
        // A current governor's key or a live fetch from the former Station
        // cannot replace that historical signature evidence after handoff.
        let resolution = roster.claim_issuer(delivery, &outcome)?;
        arkret::verify_peer_keypackage_claim_receipt_signature(&outcome.claim_receipt, resolution)?;
        let claim = garth::mls::verify_welcome_claim(
            delivery,
            &garth::LocalMlsEndpoint::device(
                delivery.realm_id.clone(),
                device.actor_id.clone(),
                device.device_id.clone(),
            ),
            &accepted.event,
            &outcome,
            garth::mls::WelcomeClaimAuthority::Realm {
                current_station: route.authority.current_service_id(),
                authority: &route.authority,
            },
            &device.authorization_event_id,
        )
        .map_err(|error| invalid(error.to_string()))?;
        // Network reads precede the custody snapshot used by RFC MLS. Any
        // concurrent private-state write makes the final CAS lose and retry.
        let (key, previous, mut record) = self.accepted_device_record(device).await?;
        if let Some(state) = inbox(&record, device)? {
            if state.welcomes.contains_key(delivery.welcome_id.as_str()) {
                return Ok(());
            }
            if state.group.is_some() {
                return Err(invalid(
                    "new Welcome requires explicit existing-group recovery",
                ));
            }
        }
        super::mls::mark_welcome_package(&mut record, &device.effective_scope, &claim, false)?;
        let mut group = ArkretMlsGroup::join_from_verified_welcome_delivery(
            super::mls::identity(&record, &device.effective_scope)?,
            delivery,
            &accepted,
        )
        .map_err(|error| invalid(error.to_string()))?;
        roster.install(&mut group)?;
        let method = arkret::DidUrl::new(format!("{}#{}", record.principal_did, device.device_id))
            .map_err(invalid)?;
        let signing_key = SigningKey::from_bytes(&seed(&record.device_seed)?);
        let consume = garth::mls::signed_welcome_consume(
            delivery,
            &outcome,
            RecipientMlsDurableSigner::RealmDevice {
                recipient_actor_id: device.actor_id.clone(),
                recipient_device_id: device.device_id.clone(),
                device_verification_method: method.clone(),
            },
            &outcome.claim_receipt.destination_id,
            group.epoch(),
            arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            |kid, input| {
                if kid != method.as_str() {
                    return Err(garth::Error::Protocol(
                        "consume method differs from the original Device".into(),
                    ));
                }
                arkret::signatures::keypackages::keypackage_signature_from_bytes(
                    kid,
                    &signing_key.sign(input).to_bytes(),
                )
                .map_err(|error| garth::Error::Protocol(error.to_string()))
            },
        )
        .map_err(|error| invalid(error.to_string()))?;
        let checkpoint = InstalledGroup {
            accepted,
            state: group
                .export_state_record()
                .map_err(|error| invalid(error.to_string()))?,
        };
        super::mls::retain_scope_identity(
            &mut record,
            &device.effective_scope,
            group
                .identity()
                .export_private_state()
                .map_err(|error| invalid(error.to_string()))?,
        )?;
        let state = inbox_mut(&mut record, device)?;
        state.group = Some(checkpoint);
        state.welcomes.insert(
            delivery.welcome_id.as_str().to_owned(),
            DurableWelcome {
                delivery: delivery.clone(),
                claim,
                consume,
                outcome: None,
            },
        );
        // Original verification, reader lifetime, private identity, group and
        // frozen signed consume become one encrypted durable custody write.
        original
            .full()
            .map_err(|error| invalid(error.to_string()))?;
        reader.check_device(device)?;
        let next = self.authoring.encrypt_key_material(&key, &record)?;
        if !self.cas(&key, Some(previous), next).await? {
            return Err(invalid(
                "Welcome checkpoint contended; reload original private state",
            ));
        }
        reader.check_device(device)?;
        Ok(())
    }

    pub(super) async fn install_received_roster(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        accepted: &arkret_wire::CommittedEventFullView,
        group: &mut ArkretMlsGroup,
    ) -> Result<arkret::EventId> {
        let roster = self.read_received_roster(device, reader, accepted).await?;
        roster.install(group)
    }

    async fn read_received_roster(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        accepted: &arkret_wire::CommittedEventFullView,
    ) -> Result<ReceivedRoster> {
        let transition =
            garth::mls::accepted_artifact::accepted_mls_transition(accepted).map_err(invalid)?;
        let request = MlsMemberRosterAuthorityReadRequestBody {
            realm_id: accepted.event.realm_id.clone(),
            effective_scope: device.effective_scope.clone(),
            mls_group_id: transition.mls_group_id,
            target_commit_event_ref: accepted.event.event_id.clone(),
            target_epoch: transition.next_epoch,
            caller_actor_id: device.actor_id.clone(),
            cursor: None,
        };
        let mut page_request = request.clone();
        let mut pages = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let response = reader
                .client()
                .self_mls_roster_authority(&page_request)
                .await?;
            let page = response.value()?.clone();
            page_request.cursor = page.roster.next_cursor.clone();
            pages.push(page);
            if page_request.cursor.is_none() {
                break;
            }
            if pages.len() >= MAX_ROSTER_PAGES || !seen.insert(page_request.cursor.clone()) {
                return Err(invalid(
                    "MLS roster pagination does not terminate within the local budget",
                ));
            }
        }
        let peer = arkret::verify_mls_member_roster_authority_pages(&pages, &request)?;
        let material_request =
            arkret::mls_roster_genesis_material_request(&peer, &pages[0].roster.manifest);
        let material = reader
            .client()
            .self_mls_group_state_material(&material_request)
            .await?;
        reader.check_device(device)?;
        Ok(ReceivedRoster {
            request,
            pages,
            material: material.value()?.clone(),
        })
    }

    /// Cleanup sends only previously durable commands. It may complete after
    /// installation loss and never fetches new group material or content.
    pub async fn drain_durable_welcome_consumes(&self, device: &ManagedDevice) -> Result<()> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        let pending = inbox(&record, device)?
            .map(|inbox| {
                inbox
                    .welcomes
                    .values()
                    .filter(|welcome| welcome.outcome.is_none())
                    .map(|welcome| {
                        (
                            welcome.delivery.welcome_id.as_str().to_owned(),
                            welcome.consume.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (id, request) in pending {
            let outcome = device.client().keypackages_consume(&request).await?;
            let receipt = &outcome.consume_receipt;
            if receipt.claim_id != request.claim_id
                || receipt.request_digest.as_str() != canonical_sha256(&request)?
                || canonical_json_bytes(&receipt.recipient_durable_receipt)?
                    != canonical_json_bytes(&request.recipient_durable_receipt)?
            {
                return Err(invalid(
                    "consume receipt differs from the exact durable request",
                ));
            }
            let realm = device
                .actor_id
                .as_realm_actor_id()
                .ok_or_else(|| invalid("Realm actor required"))?
                .realm_id
                .clone();
            let route = self.edge.realm_route(&realm).await?;
            let issuer_did = arkret::verification_method_did(receipt.signature.kid.as_str())
                .map_err(|e| invalid(e.to_string()))?;
            let issuer = arkret::project_did_to_core_id(&issuer_did)?;
            if !route
                .authority
                .authorizes_issuer_at(&issuer, None, receipt.consumed_at)
            {
                return Err(invalid(
                    "consume receipt signer did not govern the Realm at consumption",
                ));
            }
            let resolution = if issuer == *route.authority.current_service_id() {
                route.resolution.clone()
            } else {
                device
                    .client()
                    .resolve_service_from_did(&issuer_did, arkret::ServiceKind::Station)
                    .await
                    .map_err(|error| invalid(format!("historical consume issuer: {error}")))?
            };
            arkret::verify_peer_keypackage_consume_receipt_signature(
                receipt,
                &issuer,
                &resolution,
            )?;
            for attempt in 0..CAS_ATTEMPTS {
                let (key, previous, mut record) = self.accepted_device_record(device).await?;
                let state = inbox_mut(&mut record, device)?;
                let welcome = state
                    .welcomes
                    .get_mut(&id)
                    .ok_or_else(|| invalid("durable Welcome disappeared"))?;
                if canonical_json_bytes(&welcome.consume)? != canonical_json_bytes(&request)? {
                    return Err(invalid("durable consume original changed"));
                }
                if let Some(winner) = &welcome.outcome {
                    if canonical_json_bytes(winner)? != canonical_json_bytes(&outcome)? {
                        return Err(invalid("consume terminal receipt changed"));
                    }
                    break;
                }
                let claim = welcome.claim.clone();
                welcome.outcome = Some(outcome.clone());
                super::mls::mark_welcome_package(
                    &mut record,
                    &device.effective_scope,
                    &claim,
                    true,
                )?;
                let next = self.authoring.encrypt_key_material(&key, &record)?;
                if self.cas(&key, Some(previous), next).await? {
                    break;
                }
                if attempt + 1 == CAS_ATTEMPTS {
                    return Err(invalid("consume outcome contended; retry original command"));
                }
            }
        }
        Ok(())
    }

    pub async fn poll_welcome_queue(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
    ) -> Result<ManagedQueueProgress> {
        reader.check_device(device)?;
        self.drain_durable_welcome_consumes(device).await?;
        let page = self.durable_recipient_page(device, reader).await?;
        let mut progress = ManagedQueueProgress {
            has_more: page.has_more,
            ..Default::default()
        };
        for item in &page.deliveries {
            match item {
                RecipientDelivery::MlsWelcome { mls_welcome } => {
                    self.install_received_welcome(device, reader, mls_welcome)
                        .await?;
                    progress.durable_welcomes += 1;
                }
                RecipientDelivery::DeviceMessage { .. } => {
                    return Err(invalid("Realm Device queue cannot process DeviceMessage"));
                }
            }
        }
        self.drain_durable_welcome_consumes(device).await?;
        progress.acknowledged =
            self.complete_durable_recipient_page(device).await? && page.ack_token.is_some();
        Ok(progress)
    }
}

pub(super) fn restore_group(
    record: &DeviceRecord,
    device: &ManagedDevice,
) -> Result<Option<ArkretMlsGroup>> {
    let Some(installed) = inbox(record, device)?.and_then(|state| state.group.as_ref()) else {
        return Ok(None);
    };
    let group = ArkretMlsGroup::restore_from_state_record(&installed.state)
        .map_err(|error| invalid(error.to_string()))?;
    if group.scope() != &device.effective_scope
        || group.identity().actor_id != device.actor_id.clone()
        || group.identity().endpoint
            != MlsEndpointIdentity::human_device(
                device.actor_id.signing_principal_id().clone(),
                device.device_id.clone(),
            )
    {
        return Err(invalid(
            "MLS checkpoint belongs to another scope or original Device",
        ));
    }
    group
        .verify_installed_historical_base(&installed.accepted, &installed.accepted.event.event_id)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(Some(group))
}

pub(super) fn accepted_group_original(
    record: &DeviceRecord,
    device: &ManagedDevice,
) -> Result<Option<arkret_wire::CommittedEventFullView>> {
    restore_group(record, device)?;
    Ok(inbox(record, device)?
        .and_then(|state| state.group.as_ref())
        .map(|group| group.accepted.clone()))
}

pub(super) fn install_remote_group_checkpoint(
    record: &mut DeviceRecord,
    device: &ManagedDevice,
    previous: &arkret::EventId,
    accepted: arkret_wire::CommittedEventFullView,
    state: MlsGroupStateRecord,
) -> Result<()> {
    let installed = inbox_mut(record, device)?
        .group
        .as_mut()
        .ok_or_else(|| invalid("MLS checkpoint disappeared"))?;
    if &installed.accepted.event.event_id != previous
        || installed.state.group_id != state.group_id
        || installed.state.actor_id != state.actor_id
        || installed.state.endpoint != state.endpoint
        || installed.state.epoch.checked_add(1) != Some(state.epoch)
    {
        return Err(invalid(
            "remote MLS checkpoint differs from its exact previous state",
        ));
    }
    let group = ArkretMlsGroup::restore_from_state_record(&state)
        .map_err(|error| invalid(error.to_string()))?;
    group
        .verify_installed_historical_base(&accepted, &accepted.event.event_id)
        .map_err(|error| invalid(error.to_string()))?;
    installed.accepted = accepted;
    installed.state = state;
    Ok(())
}

pub(super) fn refresh_group_private_state(
    record: &mut DeviceRecord,
    device: &ManagedDevice,
    state: MlsGroupStateRecord,
) -> Result<()> {
    let installed = inbox_mut(record, device)?
        .group
        .as_mut()
        .ok_or_else(|| invalid("MLS checkpoint disappeared"))?;
    if installed.state.group_id != state.group_id
        || installed.state.actor_id != state.actor_id
        || installed.state.endpoint != state.endpoint
        || installed.state.epoch != state.epoch
    {
        return Err(invalid(
            "private KeyPackage maintenance changed the accepted MLS group",
        ));
    }
    installed.state = state;
    Ok(())
}

impl ManagedDeviceRuntime {
    /// Read local durable progress without requesting new key material. This
    /// is an epoch observation, not current membership or remote authority.
    pub async fn installed_mls_epoch(&self, device: &ManagedDevice) -> Result<Option<u64>> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        Ok(restore_group(&record, device)?.map(|group| group.epoch()))
    }
}

impl ManagedDeviceRuntime {
    /// Complete only an already stored page whose every item was made durable.
    /// This cleanup path never performs a queue list or reads new key material.
    pub async fn complete_durable_recipient_page(&self, device: &ManagedDevice) -> Result<bool> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        let Some(state) = inbox(&record, device)? else {
            return Ok(false);
        };
        let Some(page) = &state.page else {
            return Ok(false);
        };
        let page = page.clone();
        check_page(&page, device)?;
        for item in &page.deliveries {
            let RecipientDelivery::MlsWelcome { mls_welcome } = item else {
                return Ok(false);
            };
            let Some(welcome) = state.welcomes.get(mls_welcome.welcome_id.as_str()) else {
                return Ok(false);
            };
            if canonical_json_bytes(&welcome.delivery)? != canonical_json_bytes(mls_welcome)? {
                return Err(invalid(
                    "durable recipient page differs from its completed Welcome",
                ));
            }
            if welcome.outcome.is_none() {
                return Ok(false);
            }
        }
        if let Some(token) = &page.ack_token {
            device
                .client()
                .ack_device_messages(&DeviceMessagesAckRequestBody {
                    ack_token: token.clone(),
                })
                .await?;
        }
        let digest = page_digest(&page)?;
        for _ in 0..CAS_ATTEMPTS {
            let (key, previous, mut record) = self.accepted_device_record(device).await?;
            let state = inbox_mut(&mut record, device)?;
            let Some(actual) = &state.page else {
                return Ok(true);
            };
            if page_digest(actual)? != digest {
                return Err(invalid("recipient page changed before cursor checkpoint"));
            }
            if let Some(cursor) = &page.next_cursor {
                state.cursor = Some(cursor.clone());
            }
            state.page = None;
            let next = self.authoring.encrypt_key_material(&key, &record)?;
            if self.cas(&key, Some(previous), next).await? {
                return Ok(true);
            }
        }
        Err(invalid(
            "recipient cursor checkpoint contended; replay original ACK",
        ))
    }
}

impl ManagedDeviceRuntime {
    pub(super) async fn has_pending_recipient_work(&self, device: &ManagedDevice) -> Result<bool> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        Ok(inbox(&record, device)?.is_some_and(|state| {
            state.page.is_some()
                || state
                    .welcomes
                    .values()
                    .any(|welcome| welcome.outcome.is_none())
        }))
    }
}
