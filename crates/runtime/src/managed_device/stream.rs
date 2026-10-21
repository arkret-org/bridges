//! Continuous originals and private MLS progress share the encrypted Device CAS.

use std::collections::BTreeMap;

use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventView, EventKind, RealmStateSnapshot,
    StreamScanDirection, StreamScanRequest,
};

use super::*;

const MAX_PENDING_EVENTS: usize = 128;
const SCAN_PAGE_SIZE: usize = 64;
const MAX_PENDING_CANONICAL_BYTES: usize = 8_388_608;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopeStream {
    scope: ScopeRef,
    head: CommitStreamHead,
    processed_through: CommitStreamHead,
    current: RealmStateSnapshot,
    pending: BTreeMap<u64, CommittedEventView>,
    #[serde(default)]
    delivery: Option<NativeContent>,
    // A bounded private diagnostic, containing ciphertext and signed originals
    // only. It is committed with the receive ratchet, never sent to a sink.
    last_rejected_content: Option<arkret::CommittedEventFullView>,
}

/// Local custody observations never assert current remote business permission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagedStreamProgress {
    pub durable_events: usize,
    pub pending_events: usize,
    pub last_position: Option<u64>,
    pub epoch: Option<u64>,
}

fn stream_key(device: &ManagedDevice) -> Result<String> {
    Ok(device.effective_scope.canonical_mls_group_id()?.to_string())
}

fn state<'a>(record: &'a DeviceRecord, device: &ManagedDevice) -> Result<Option<&'a ScopeStream>> {
    let saved = record.mls.streams.get(&stream_key(device)?);
    if let Some(saved) = saved {
        validate_state(saved, &device.effective_scope)?;
    }
    Ok(saved)
}

fn validate_state(saved: &ScopeStream, scope: &ScopeRef) -> Result<()> {
    let stream = CommitStreamRef::from_scope(scope, None)?;
    if saved.scope != *scope
        || saved.head.stream_ref != stream
        || saved.processed_through.stream_ref != stream
        || saved.current.realm_id != *scope.realm_id()
        || saved.processed_through.stream_position > saved.head.stream_position
        || saved.pending.len() > MAX_PENDING_EVENTS
    {
        return Err(invalid(
            "native stream custody has another scope or incomplete progress",
        ));
    }
    if let Some(delivery) = &saved.delivery {
        if delivery.original().event.scope_ref != *scope
            || head(&CommittedEventView::Full(delivery.original().clone()))
                != saved.processed_through
        {
            return Err(invalid(
                "native delivery differs from the durable processed cut",
            ));
        }
    }
    if let Some(rejected) = &saved.last_rejected_content {
        let rejected_head = head(&CommittedEventView::Full(rejected.clone()));
        if rejected.event.scope_ref != *scope
            || rejected.event.kind != EventKind::MessageCreate
            || rejected_head.stream_ref != saved.processed_through.stream_ref
            || rejected_head.stream_position > saved.processed_through.stream_position
            || (rejected_head.stream_position == saved.processed_through.stream_position
                && rejected_head.commit_id != saved.processed_through.commit_id)
        {
            return Err(invalid("rejected content differs from the durable stream"));
        }
    }
    let mut previous = saved.processed_through.clone();
    for (position, row) in &saved.pending {
        let commit = row.commit();
        if previous.stream_position.checked_add(1) != Some(*position)
            || commit.stream_position != *position
            || commit.stream_ref != stream
            || commit.previous_commit_ref.as_ref() != Some(&previous.commit_id)
        {
            return Err(invalid(
                "native durable originals are not one continuous pending tail",
            ));
        }
        previous.stream_position = *position;
        previous.commit_id = commit.commit_id.clone();
    }
    if previous != saved.head
        || canonical_json_bytes(&saved.pending)?.len() > MAX_PENDING_CANONICAL_BYTES
    {
        return Err(invalid("native durable tail does not cover its exact head"));
    }
    Ok(())
}

fn current_covers(current: &RealmStateSnapshot, expected: &CommitStreamHead) -> Result<()> {
    let Some(cap) = current
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == expected.stream_ref)
    else {
        return Err(invalid("native current omits the durable stream"));
    };
    if cap.stream_position < expected.stream_position
        || (cap.stream_position == expected.stream_position && cap.commit_id != expected.commit_id)
    {
        return Err(invalid(
            "native current is behind or forks the durable stream",
        ));
    }
    Ok(())
}

fn head(row: &CommittedEventView) -> CommitStreamHead {
    let commit = row.commit();
    CommitStreamHead {
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
        commit_id: commit.commit_id.clone(),
    }
}

impl ManagedDeviceRuntime {
    /// Local private diagnostics, not another protocol notification or proof
    /// of current read access. No rejected plaintext is retained or delivered.
    pub async fn last_rejected_content(
        &self,
        device: &ManagedDevice,
    ) -> Result<Option<arkret::CommittedEventFullView>> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        Ok(state(&record, device)?.and_then(|saved| saved.last_rejected_content.clone()))
    }

    pub async fn durable_stream_progress(
        &self,
        device: &ManagedDevice,
    ) -> Result<ManagedStreamProgress> {
        let (_, _, record) = self.accepted_device_record(device).await?;
        let Some(saved) = state(&record, device)? else {
            return Ok(ManagedStreamProgress::default());
        };
        Ok(ManagedStreamProgress {
            durable_events: 0,
            pending_events: saved.pending.len() + usize::from(saved.delivery.is_some()),
            last_position: Some(saved.head.stream_position),
            epoch: super::inbox::restore_group(&record, device)?.map(|group| group.epoch()),
        })
    }

    /// A fresh current read and re-admitted exact head precede every tail read.
    /// The first head is the accepted Welcome Add, never a later snapshot cut.
    /// Unhandled or withheld rows remain ordered and prevent later MLS merges.
    pub async fn poll_content_stream(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
    ) -> Result<ManagedStreamProgress> {
        reader.check_device(device)?;
        let (_, _, record) = self.accepted_device_record(device).await?;
        if state(&record, device)?.is_some_and(|saved| saved.delivery.is_some()) {
            return self.durable_stream_progress(device).await;
        }
        if super::inbox::accepted_group_original(&record, device)?.is_none() {
            return Ok(ManagedStreamProgress::default());
        }
        let response = reader
            .client()
            .snapshot_head(device.effective_scope.realm_id())
            .await
            .map_err(|error| invalid(format!("native stream current read: {error}")))?;
        let current = garth::own_station_results::consume_own_station_device_snapshot(&response)
            .map_err(|error| invalid(error.to_string()))?
            .clone();
        let (key, previous, mut record) = self.accepted_device_record(device).await?;
        let actual_base = super::inbox::accepted_group_original(&record, device)?
            .ok_or_else(|| invalid("accepted MLS base disappeared during the current read"))?;
        let saved = state(&record, device)?;
        let expected = if let Some(saved) = saved {
            if current.governance_generation < saved.current.governance_generation {
                return Err(invalid("native current governance generation rolled back"));
            }
            saved.head.clone()
        } else {
            head(&CommittedEventView::Full(actual_base.clone()))
        };
        current_covers(&current, &expected)?;
        let pending_len = saved.map_or(0, |state| state.pending.len());
        let limit = SCAN_PAGE_SIZE.min(MAX_PENDING_EVENTS - pending_len);
        let mut replica = garth::own_station_results::OwnStationDeviceReplica::new(
            device.effective_scope.clone(),
        )
        .map_err(|error| invalid(error.to_string()))?;
        replica
            .install_current(response)
            .map_err(|error| invalid(error.to_string()))?;
        replica
            .restore_checkpoint_head(reader.client(), &expected)
            .await
            .map_err(|error| invalid(format!("native stream original checkpoint: {error}")))?;
        let page =
            if limit == 0 {
                None
            } else {
                let request = StreamScanRequest {
                    realm_id: device.effective_scope.realm_id().clone(),
                    stream_ref: expected.stream_ref.clone(),
                    direction: StreamScanDirection::After(Some(expected.stream_position)),
                    limit: limit as u16,
                };
                Some(
                    replica
                        .apply_bound_scan(
                            reader.client(),
                            reader.client().scan_commit_stream(&request).await.map_err(
                                |error| invalid(format!("native stream tail read: {error}")),
                            )?,
                        )
                        .await
                        .map_err(|error| {
                            invalid(format!("native stream tail verification: {error}"))
                        })?,
                )
            };
        let rows = match &page {
            Some(page) => page.rows().map_err(|error| invalid(error.to_string()))?,
            None => &[],
        };
        if rows.len() > limit {
            return Err(invalid("native stream exceeded its bounded page"));
        }
        let next_head = replica
            .head()
            .map_err(|error| invalid(error.to_string()))?
            .ok_or_else(|| invalid("native stream lost its independently verified head"))?
            .clone();
        let mut pending = saved.map(|saved| saved.pending.clone()).unwrap_or_default();
        let mut processed_through = saved
            .map(|saved| saved.processed_through.clone())
            .unwrap_or_else(|| expected.clone());
        for row in rows {
            if let CommittedEventView::Full(full) = row {
                arkret_event_draft::validate_event_for_submit(&full.event)
                    .map_err(|error| invalid(error.to_string()))?;
            }
            if pending
                .insert(row.commit().stream_position, row.clone())
                .is_some()
            {
                return Err(invalid("native stream tried to replace a durable original"));
            }
        }
        let mut group = super::inbox::restore_group(&record, device)?
            .ok_or_else(|| invalid("native stream has no private MLS checkpoint"))?;
        let mut accepted = actual_base;
        let mut advanced = false;
        let mut delivery = None;
        let mut last_rejected_content = saved.and_then(|saved| saved.last_rejected_content.clone());
        let mut recovered = Vec::new();
        while let Some((position, row)) = pending.first_key_value() {
            let position = *position;
            let full = match row {
                CommittedEventView::Full(full) => full.clone(),
                _ => {
                    if self
                        .already_applied_local_content(device, row.commit())
                        .await?
                    {
                        processed_through = head(row);
                        pending.remove(&position);
                        advanced = true;
                        continue;
                    }
                    // A previously withheld prefix must be re-admitted at
                    // current authority; never skip it or replace its Commit.
                    let id = row.commit().event_ref.clone();
                    let original = garth::own_station_results::consume_own_station_device_event(
                        reader.client(),
                        &id,
                        reader.client().committed_event_get(&id).await?,
                    )
                    .await
                    .map_err(|error| invalid(format!("native withheld recovery: {error}")))?;
                    if original
                        .view()
                        .map_err(|e| invalid(e.to_string()))?
                        .commit()
                        != row.commit()
                    {
                        return Err(invalid("recovered original changed its accepted Commit"));
                    }
                    let CommittedEventView::Full(full) =
                        original.view().map_err(|e| invalid(e.to_string()))?
                    else {
                        break;
                    };
                    let full = full.clone();
                    recovered.push(original);
                    full
                }
            };
            if full.event.kind != EventKind::MlsCommit {
                if matches!(
                    full.event.kind,
                    EventKind::MessageCreate | EventKind::MessageRedact
                ) && !self.is_local_publication(&full.event).await?
                {
                    delivery = NativeContent::decrypt(&full, &accepted, &mut group)?;
                    self.retain_attachment_checkpoint(device, &accepted, &group)
                        .await?;
                    if delivery.is_none() {
                        last_rejected_content = Some(full.clone());
                    }
                    super::inbox::refresh_group_private_state(
                        &mut record,
                        device,
                        group
                            .export_state_record()
                            .map_err(|e| invalid(e.to_string()))?,
                    )?;
                }
                processed_through = head(&CommittedEventView::Full(full));
                pending.remove(&position);
                advanced = true;
                if delivery.is_some() {
                    break;
                }
                continue;
            }
            self.retain_attachment_checkpoint(device, &accepted, &group)
                .await?;
            group
                .install_recovered_remote_commit(&full, &accepted.event.event_id)
                .map_err(|error| invalid(error.to_string()))?;
            self.install_received_roster(device, reader, &full, &mut group)
                .await?;
            super::inbox::install_remote_group_checkpoint(
                &mut record,
                device,
                &accepted.event.event_id,
                full.clone(),
                group
                    .export_state_record()
                    .map_err(|error| invalid(error.to_string()))?,
            )?;
            super::mls::retain_scope_identity(
                &mut record,
                &device.effective_scope,
                group
                    .identity()
                    .export_private_state()
                    .map_err(|error| invalid(error.to_string()))?,
            )?;
            processed_through = head(&CommittedEventView::Full(full.clone()));
            accepted = full;
            pending.remove(&position);
            advanced = true;
        }
        let progress = ManagedStreamProgress {
            durable_events: rows.len(),
            pending_events: pending.len() + usize::from(delivery.is_some()),
            last_position: Some(next_head.stream_position),
            epoch: Some(group.epoch()),
        };
        if !advanced
            && rows.is_empty()
            && state(&record, device)?.is_some_and(|saved| saved.current == current)
        {
            if let Some(page) = &page {
                page.rows().map_err(|error| invalid(error.to_string()))?;
            }
            for original in &recovered {
                original
                    .full()
                    .map_err(|error| invalid(error.to_string()))?;
            }
            reader.check_device(device)?;
            return Ok(progress);
        }
        let next = ScopeStream {
            scope: device.effective_scope.clone(),
            head: next_head,
            processed_through,
            current,
            pending,
            delivery,
            last_rejected_content,
        };
        validate_state(&next, &device.effective_scope)?;
        record.mls.streams.insert(stream_key(device)?, next);
        if let Some(page) = &page {
            page.rows().map_err(|error| invalid(error.to_string()))?;
        }
        for original in &recovered {
            original
                .full()
                .map_err(|error| invalid(error.to_string()))?;
        }
        reader.check_device(device)?;
        let encrypted = self.authoring.encrypt_key_material(&key, &record)?;
        if !self.cas(&key, Some(previous), encrypted).await? {
            return Err(invalid(
                "native stream checkpoint contended; reload original custody",
            ));
        }
        reader.check_device(device)?;
        Ok(progress)
    }
    /// The plaintext and receive ratchet were committed before this callback.
    /// Recheck remote access before delivery and acknowledge only the exact item.
    pub async fn drain_content(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        sink: &dyn NativeContentSink,
    ) -> Result<bool> {
        reader.check_device(device)?;
        let (key, previous, mut record) = self.accepted_device_record(device).await?;
        let Some(mut content) = state(&record, device)?.and_then(|saved| saved.delivery.clone())
        else {
            return Ok(false);
        };
        let current = reader
            .client()
            .snapshot_head(device.effective_scope.realm_id())
            .await?;
        current.value()?;
        let original = garth::own_station_results::consume_own_station_device_event(
            reader.client(),
            &content.original().event.event_id,
            reader
                .client()
                .committed_event_get(&content.original().event.event_id)
                .await?,
        )
        .await
        .map_err(|e| invalid(e.to_string()))?;
        if original.full().map_err(|e| invalid(e.to_string()))? != content.original() {
            return Err(invalid(
                "pending delivery differs from its currently authorized original",
            ));
        }
        if sink.requires_attachments() {
            if !content.attachments_opened {
                let group = super::inbox::restore_group(&record, device)?
                    .ok_or_else(|| invalid("pending attachment has no private epoch"))?;
                let accepted = super::inbox::accepted_group_original(&record, device)?
                    .ok_or_else(|| invalid("pending attachment has no accepted base"))?;
                content
                    .open_attachments(self, device, reader, &accepted, &group)
                    .await?;
                record
                    .mls
                    .streams
                    .get_mut(&stream_key(device)?)
                    .ok_or_else(|| invalid("pending content disappeared"))?
                    .delivery = Some(content.clone());
                original.full().map_err(|e| invalid(e.to_string()))?;
                reader.check_device(device)?;
                let encrypted = self.authoring.encrypt_key_material(&key, &record)?;
                if !self.cas(&key, Some(previous), encrypted).await? {
                    return Err(invalid("attachment delivery checkpoint contended"));
                }
            } else {
                for attachment in content.attachments() {
                    self.read_attachment_ciphertext(device, reader, &attachment.descriptor)
                        .await?;
                }
            }
        }
        original.full().map_err(|e| invalid(e.to_string()))?;
        current.value()?;
        reader.check_device(device)?;
        let view = if sink.requires_attachments() {
            content.clone()
        } else {
            content.without_attachment_bytes()
        };
        let recipient = super::content::NativeContentRecipient::new(device, reader, &view)?;
        sink.deliver(&recipient, &view).await?;
        for _ in 0..8 {
            let (key, previous, mut record) = self.accepted_device_record(device).await?;
            let saved = record
                .mls
                .streams
                .get_mut(&stream_key(device)?)
                .ok_or_else(|| invalid("native content checkpoint disappeared"))?;
            let Some(pending) = &saved.delivery else {
                return Ok(true);
            };
            if canonical_json_bytes(pending)? != canonical_json_bytes(&content)? {
                return Err(invalid("native delivery changed during acknowledgement"));
            }
            saved.delivery = None;
            let encrypted = self.authoring.encrypt_key_material(&key, &record)?;
            if self.cas(&key, Some(previous), encrypted).await? {
                return Ok(true);
            }
        }
        Err(invalid("native delivery acknowledgement contended"))
    }
}
