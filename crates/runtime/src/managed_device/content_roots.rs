//! The host's encrypted atomic journal backs history roots and crypto intents.
//! Accepted originals supply backup references; local persistence never claims
//! a successful remote PUT or broadens the receiving Device's authority.

use arkret::EventPayloadExt as _;
use arkret::mls::ArkretMlsGroup;
use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::{ContentRootBackupEntry, ContentRootContext, ContentRootItemKind};
use arkret_wire::{CommittedEventFullView, EventId, Hash, MlsWelcomeRecipientEndpoint};
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

impl ManagedDeviceRuntime {
    fn root_publication_operation(
        device: &ManagedDevice,
        operation: &str,
        root: &ContentRootBackupEntry,
    ) -> Result<String> {
        Ok(format!(
            "native-root/v1/{}",
            canonical_sha256(&(
                &device.actor_id,
                &device.operation_id,
                operation,
                &root.root_context,
                &root.root_ref,
            ))?
        ))
    }

    /// Repair original unknown ACKs with the original current credential. This
    /// deliberately returns historical records, never business publication refs.
    /// No new MLS, prepare, epoch, recipient or business gate is read first.
    pub async fn repair_content_root_publication(
        &self,
        device: &ManagedDevice,
        business_operation: &str,
        root_ref: &Hash,
    ) -> Result<Vec<garth::mls::content_roots::NativeRootPublicationHistory>> {
        let reader = self.open_reader(device).await?;
        let store = self.content_root_store(device)?;
        let endpoint = MlsWelcomeRecipientEndpoint::Device {
            device_id: device.device_id.clone(),
        };
        let vault =
            garth::mls::content_roots::ContentRootVault::new(&store, &device.actor_id, &endpoint);
        let root = vault
            .root(root_ref)
            .await
            .map_err(invalid)?
            .ok_or_else(|| invalid("original durable publication root is unavailable"))?;
        if root.root_context.effective_scope != device.effective_scope {
            return Err(invalid(
                "original publication belongs to another Device scope",
            ));
        }
        let operation = Self::root_publication_operation(device, business_operation, &root)?;
        let history = garth::mls::content_roots::retry_frozen_native_root_publication(
            reader.client(),
            &vault,
            &operation,
        )
        .await
        .map_err(invalid)?;
        reader.check_device(device)?;
        Ok(history)
    }

    pub(crate) async fn retain_history_root(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        root: &ContentRootBackupEntry,
    ) -> Result<()> {
        reader.check_device(device)?;
        if root.root_context.effective_scope != device.effective_scope {
            return Err(invalid(
                "history root belongs to another exact Device scope",
            ));
        }
        let store = self.content_root_store(device)?;
        let endpoint = MlsWelcomeRecipientEndpoint::Device {
            device_id: device.device_id.clone(),
        };
        let vault =
            garth::mls::content_roots::ContentRootVault::new(&store, &device.actor_id, &endpoint);
        vault.retain_root(root).await.map_err(invalid)?;
        reader.check_device(device)
    }

    pub(super) async fn publish_content_root(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        operation: &str,
        root: &ContentRootBackupEntry,
        created_at: DateTime<Utc>,
    ) -> Result<garth::mls::content_roots::NativeRootPublicationOutcome> {
        reader.check_device(device)?;
        let (_, _, record) = self.accepted_device_record(device).await?;
        let signing_key = SigningKey::from_bytes(&seed(&record.device_seed)?);
        let route = self
            .edge
            .realm_route(device.effective_scope.realm_id())
            .await?;
        let store = self.content_root_store(device)?;
        let endpoint = MlsWelcomeRecipientEndpoint::Device {
            device_id: device.device_id.clone(),
        };
        let vault =
            garth::mls::content_roots::ContentRootVault::new(&store, &device.actor_id, &endpoint);
        let publication_operation = Self::root_publication_operation(device, operation, root)?;
        let publication = garth::mls::content_roots::publish_native_content_root(
            reader.client(),
            &vault,
            garth::mls::content_roots::NativeRootPublicationParameters {
                operation: &publication_operation,
                root,
                created_at,
                author: arkret::crypto::backup::KeyBackupAuthBinding {
                    device_id: device.device_id.clone(),
                    verification_method: arkret::DidUrl::new(device.signer.verification_method())
                        .map_err(invalid)?,
                    signature_algorithm: arkret_models_crypto::KeyBackupSignatureAlgorithm::Ed25519,
                    device_authorize_event_id: device.authorization_event_id.clone(),
                },
                domain_separation: arkret_models_crypto::KeyBackupDomainSeparation {
                    subdomain: "key_backup".into(),
                    aead_aad_extensions: Default::default(),
                },
                authority: &route.authority,
                station_resolution: &route.resolution,
                authority_keys: &route.keys,
            },
            |bytes| Ok(signing_key.sign(bytes).to_bytes().to_vec()),
        )
        .await
        .map_err(invalid)?;
        reader.check_device(device)?;
        publication.backup_refs().map_err(invalid)?;
        Ok(publication)
    }

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
        reader.check_device(device)?;
        let response = reader.client().committed_event_get(&create_id).await?;
        let response = garth::own_station_results::consume_own_station_device_realm_genesis(
            reader.client(),
            realm,
            response,
        )
        .await
        .map_err(invalid)?;
        let arkret_wire::CommittedEventView::Full(original) = response.value()? else {
            return Err(invalid("Realm Genesis original was not disclosed"));
        };
        let original = &original.event;
        if original.kind != arkret::EventKind::RealmCreate
            || original.realm_id != *realm
            || original.event_id != create_id
            || original.scope_ref != ScopeRef::RealmGenesis
        {
            return Err(invalid(
                "content strategy is not the Realm's accepted original",
            ));
        }
        let strategy = original
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
            backup_strategy_ref: original.event_id.clone(),
        };
        context.validate()?;
        reader.check_device(device)?;
        Ok(context)
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
        Ok(())
    }
}
