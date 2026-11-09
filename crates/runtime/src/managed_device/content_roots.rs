//! The host's encrypted atomic journal backs history roots and crypto intents.
//! Accepted originals supply backup references; local persistence never claims
//! a successful remote PUT or broadens the receiving Device's authority.

use arkret::EventPayloadExt as _;
use arkret::mls::ArkretMlsGroup;
use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::{ContentRootBackupEntry, ContentRootContext, ContentRootItemKind};
use arkret_wire::{BackupId, CommittedEventFullView, EventId, Hash, MlsWelcomeRecipientEndpoint};
use garth::{SecureKeyStore, SecureKeyStoreBackendInfo, SecureKeyStoreError, SecureKeyStoreResult};

use super::*;

pub(super) struct RootStore {
    store: Arc<dyn AuthoringStore>,
    authoring: Arc<ManagedActorAuthoringService>,
    retired: String,
}

fn storage_error(error: impl std::fmt::Display) -> SecureKeyStoreError {
    SecureKeyStoreError::Backend(error.to_string())
}

impl RootStore {
    fn read(&self, key: &str) -> SecureKeyStoreResult<Option<arkret::KeyBytes>> {
        self.store
            .load(key)
            .map_err(storage_error)?
            .map(|raw| {
                let bytes: Vec<u8> = self
                    .authoring
                    .decrypt_key_material(key, &raw)
                    .map_err(storage_error)?;
                Ok(arkret::KeyBytes::new(bytes))
            })
            .transpose()
    }
}

impl SecureKeyStore for RootStore {
    fn store_secret_bytes(&self, _key: &str, _value: &[u8]) -> SecureKeyStoreResult<()> {
        Err(SecureKeyStoreError::Unsupported(
            "root writes require atomic durable CAS",
        ))
    }
    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<arkret::KeyBytes>> {
        self.read(key)
    }
    fn delete_secret(&self, _key: &str) -> SecureKeyStoreResult<()> {
        Err(SecureKeyStoreError::Unsupported(
            "root deletion requires explicit retirement",
        ))
    }
    fn list_secret_keys(&self, prefix: Option<&str>) -> SecureKeyStoreResult<Vec<String>> {
        self.store
            .entries_with_prefix(prefix.unwrap_or("content-"))
            .map_err(storage_error)
            .map(|rows| rows.into_iter().map(|(key, _)| key).collect())
    }
    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            name: "managed-encrypted-journal",
            hardware_backed: false,
            exportable: true,
        }
    }
    fn read_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = SecureKeyStoreResult<Option<arkret::KeyBytes>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.read(key) })
    }
    fn compare_exchange_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        expected: Option<&'a [u8]>,
        replacement: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SecureKeyStoreResult<bool>> + Send + 'a>>
    {
        Box::pin(async move {
            let current = self.store.load(key).map_err(storage_error)?;
            let plain = current
                .as_ref()
                .map(|raw| {
                    self.authoring
                        .decrypt_key_material::<Vec<u8>>(key, raw)
                        .map(arkret::KeyBytes::new)
                        .map_err(storage_error)
                })
                .transpose()?;
            if plain.as_ref().map(|value| value.as_slice()) != expected {
                return Ok(false);
            }
            let encrypted = self
                .authoring
                .encrypt_key_material(key, &replacement)
                .map_err(storage_error)?;
            self.store
                .compare_exchange_batch(
                    &[(key.to_owned(), current), (self.retired.clone(), None)],
                    &[(key.to_owned(), Some(encrypted))],
                )
                .map_err(storage_error)
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSource {
    context: ContentRootContext,
    source: CommittedEventFullView,
    backups: Vec<BackupId>,
}

impl ManagedDeviceRuntime {
    pub(super) fn content_root_store(&self, device: &ManagedDevice) -> Result<RootStore> {
        Ok(RootStore {
            store: self.store.clone(),
            authoring: self.authoring.clone(),
            retired: super::revocation::retirement_key(&device.actor_id, &device.operation_id)?,
        })
    }

    pub(super) async fn content_root_context(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        accepted: &CommittedEventFullView,
        group: &ArkretMlsGroup,
        genesis: &EventId,
    ) -> Result<ContentRootContext> {
        group
            .verify_installed_historical_base(accepted, &accepted.event.event_id)
            .map_err(invalid)?;
        let realm = device.effective_scope.realm_id();
        let create_id = EventId::from_digest(
            realm.digest_suite_code().digest_suite(),
            realm.digest_bytes(),
        );
        let original = garth::own_station_results::consume_own_station_device_event(
            reader.client(),
            &create_id,
            reader.client().committed_event_get(&create_id).await?,
        )
        .await
        .map_err(invalid)?;
        let original = original.full().map_err(invalid)?;
        if original.event.kind != arkret::EventKind::RealmCreate
            || original.event.realm_id != *realm
            || original.event.event_id != create_id
        {
            return Err(invalid(
                "content strategy is not the Realm's accepted original",
            ));
        }
        let strategy = original
            .event
            .as_realm_create()?
            .object
            .initial_encryption_backup_strategy;
        let context = ContentRootContext {
            effective_scope: device.effective_scope.clone(),
            genesis_event_ref: genesis.clone(),
            epoch: group.epoch(),
            group_state_ref: accepted.event.event_id.clone(),
            cipher_suite: group
                .group_ciphersuite_canonical_id()
                .map_err(invalid)?
                .to_owned(),
            encryption_backup_strategy: strategy,
            backup_strategy_ref: original.event.event_id.clone(),
        };
        context.validate()?;
        reader.check_device(device)?;
        Ok(context)
    }

    fn root_source_key(device: &ManagedDevice, root: &Hash) -> Result<String> {
        Ok(format!(
            "managed-root-source/v1/{}",
            canonical_sha256(&(&device.actor_id, &device.operation_id, root))?
        ))
    }

    pub(super) async fn retain_original_content_roots(
        &self,
        device: &ManagedDevice,
        original: &CommittedEventFullView,
        context: &ContentRootContext,
        group: &ArkretMlsGroup,
    ) -> Result<()> {
        let root = group.export_content_root(context).map_err(invalid)?;
        let reference =
            arkret::crypto::content_history::content_root_ref(&root, context).map_err(invalid)?;
        let mut backups = std::collections::BTreeSet::new();
        for carrier in original.event.event_content_envelopes().map_err(invalid)? {
            let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
                root_ref,
                epoch,
                group_state_ref,
                protection,
                ..
            } = carrier.envelope.encryption_context;
            if epoch != context.epoch
                || group_state_ref != context.group_state_ref
                || root_ref != reference
            {
                return Err(invalid(
                    "received content root differs from its exact accepted epoch",
                ));
            }
            backups.extend(protection.backup_refs);
        }
        if backups.is_empty() {
            return Ok(());
        }
        let store = self.content_root_store(device)?;
        let endpoint = MlsWelcomeRecipientEndpoint::Device {
            device_id: device.device_id.clone(),
        };
        let vault =
            garth::mls::content_roots::ContentRootVault::new(&store, &device.actor_id, &endpoint);
        vault
            .retain_root(&ContentRootBackupEntry {
                item_kind: ContentRootItemKind::ContentEpochRoot,
                secret_id: format!("root_{}", reference.as_str().trim_start_matches("sha256:")),
                root_context: context.clone(),
                root_ref: reference.clone(),
                root_base64url: root,
            })
            .await
            .map_err(invalid)?;
        let key = Self::root_source_key(device, &reference)?;
        let source = RootSource {
            context: context.clone(),
            source: original.clone(),
            backups: backups.into_iter().collect(),
        };
        let encoded = self.authoring.encrypt_key_material(&key, &source)?;
        self.cas(&key, None, encoded).await?;
        Ok(())
    }

    pub(super) async fn retained_root_backups(
        &self,
        device: &ManagedDevice,
        context: &ContentRootContext,
        reference: &Hash,
    ) -> Result<Vec<BackupId>> {
        let key = Self::root_source_key(device, reference)?;
        let raw = self
            .read(&key)
            .await?
            .ok_or_else(|| invalid("content waits for an accepted durable root backup source"))?;
        let source: RootSource = self.authoring.decrypt_key_material(&key, &raw)?;
        if source.context != *context || source.backups.is_empty() {
            return Err(invalid(
                "retained root backup source differs from the current context",
            ));
        }
        Ok(source.backups)
    }
}
