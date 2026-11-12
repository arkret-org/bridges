//! Manager-only archive custody, deliberately outside daily authoring storage.
//!
//! Its database and wrapping key are explicit manager capabilities. Neither is
//! placed in shared runtime configuration or a managed Device/authoring object.

use std::path::Path;
use std::sync::Mutex;

use arkret::{CommittedEventRef, KeyBytes, RealmActorId};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};

use crate::{BridgeError, Result};

const KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("manager_archive_keys");
const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("manager_archive_records");

#[cfg(test)]
mod custody_tests;

/// Possession of this object is the manager's local archive capability. A daily
/// Device never receives it, its wrapping key or a generic decrypt adapter.
pub struct ManagerArchiveVault {
    database: Mutex<Option<Database>>,
    wrapping_key: KeyBytes,
}

impl std::fmt::Debug for ManagerArchiveVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagerArchiveVault")
            .field("private_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn invalid(error: impl std::fmt::Display) -> BridgeError {
    BridgeError::Database(format!("manager archive vault: {error}"))
}

impl ManagerArchiveVault {
    /// Open a distinct, process-locked manager database. Using the already-open
    /// daily journal file fails at its OS lock rather than sharing its engine.
    /// The caller supplies a separately unlocked manager key; no Config fallback
    /// or derivation from a Device/control/authoring key is permitted.
    pub fn open(path: &Path, wrapping_key: KeyBytes) -> Result<Self> {
        if wrapping_key.as_slice().len() != 32 {
            return Err(invalid("independent wrapping key must contain 32 bytes"));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(invalid)?;
        }
        let database = Database::create(path).map_err(invalid)?;
        {
            let transaction = database.begin_read().map_err(invalid)?;
            if transaction
                .list_tables()
                .map_err(invalid)?
                .any(|table| table.name() != KEYS.name() && table.name() != RECORDS.name())
                || transaction
                    .list_multimap_tables()
                    .map_err(invalid)?
                    .next()
                    .is_some()
            {
                return Err(invalid(
                    "manager archive cannot share another store's database",
                ));
            }
        }
        let mut transaction = database.begin_write().map_err(invalid)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(invalid)?;
        transaction.set_two_phase_commit(true);
        transaction.open_table(KEYS).map_err(invalid)?;
        transaction.open_table(RECORDS).map_err(invalid)?;
        transaction.commit().map_err(invalid)?;
        let vault = Self {
            database: Mutex::new(Some(database)),
            wrapping_key,
        };
        vault.with_database(|database| {
            let mut transaction = database.begin_write().map_err(invalid)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(invalid)?;
            transaction.set_two_phase_commit(true);
            {
                let mut table = transaction.open_table(KEYS).map_err(invalid)?;
                let key = "manager-archive/v1/wrapping-key-confirmation";
                let existing = table
                    .get(key)
                    .map_err(invalid)?
                    .map(|value| value.value().to_vec());
                if let Some(existing) = existing {
                    if vault.decrypt(key, &existing)?.as_slice() != [0x61; 32] {
                        return Err(invalid("wrapping key confirmation differs"));
                    }
                } else {
                    let encrypted = vault.encrypt(key, &[0x61; 32])?;
                    table.insert(key, encrypted.as_slice()).map_err(invalid)?;
                }
            }
            transaction.commit().map_err(invalid)?;
            Ok(())
        })?;
        Ok(vault)
    }

    pub(crate) fn require_distinct_authoring_key(&self, authoring_key: &[u8]) -> Result<()> {
        if authoring_key.len() == self.wrapping_key.as_slice().len()
            && authoring_key
                .iter()
                .zip(self.wrapping_key.as_slice())
                .fold(0u8, |difference, (left, right)| difference | (left ^ right))
                == 0
        {
            return Err(invalid(
                "manager archive and daily authoring keys must be independent",
            ));
        }
        Ok(())
    }

    pub(crate) fn matches_wrapping_key(&self, key: &[u8]) -> bool {
        key.len() == self.wrapping_key.as_slice().len()
            && key
                .iter()
                .zip(self.wrapping_key.as_slice())
                .fold(0u8, |difference, (left, right)| difference | (left ^ right))
                == 0
    }

    pub(crate) fn bind_manager(
        &self,
        applet: &arkret::AppletId,
        service: &arkret::DidCoreId,
    ) -> Result<()> {
        let key = "manager-archive/v1/deployment-owner";
        let expected = arkret::canonical::canonical_json_bytes(&(applet, service))?;
        self.compare_exchange_record(key, None, &expected)?;
        let owner = self
            .read_record(key)?
            .ok_or_else(|| invalid("manager vault owner disappeared"))?;
        if owner.as_slice() != expected {
            return Err(invalid(
                "manager archive belongs to another Applet or Service deployment",
            ));
        }
        Ok(())
    }

    fn key(actor: &RealmActorId, kind: &str, identity: &impl serde::Serialize) -> Result<String> {
        Ok(format!(
            "manager-archive/v1/{kind}/{}",
            arkret::canonical::canonical_sha256(&(actor, identity))?
        ))
    }

    fn encrypt(&self, key: &str, private: &[u8]) -> Result<Vec<u8>> {
        if private.len() != 32 {
            return Err(invalid("archive private keys must contain 32 bytes"));
        }
        self.encrypt_payload(key, private)
    }

    fn encrypt_payload(&self, key: &str, private: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(invalid)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.wrapping_key.as_slice()).map_err(invalid)?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: private,
                    aad: key.as_bytes(),
                },
            )
            .map_err(|_| invalid("archive encryption failed"))?;
        let mut record = Vec::with_capacity(24 + encrypted.len());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&encrypted);
        Ok(record)
    }

    fn decrypt(&self, key: &str, record: &[u8]) -> Result<KeyBytes> {
        if record.len() != 24 + 32 + 16 {
            return Err(invalid("encrypted archive key has an invalid length"));
        }
        self.decrypt_payload(key, record)
    }

    fn decrypt_payload(&self, key: &str, record: &[u8]) -> Result<KeyBytes> {
        if record.len() < 24 + 16 {
            return Err(invalid("encrypted manager record is truncated"));
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.wrapping_key.as_slice()).map_err(invalid)?;
        cipher
            .decrypt(
                XNonce::from_slice(&record[..24]),
                Payload {
                    msg: &record[24..],
                    aad: key.as_bytes(),
                },
            )
            .map(KeyBytes::new)
            .map_err(|_| invalid("archive key authentication failed"))
    }

    fn with_database<T>(&self, operation: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
        let mut database = self.database.lock().map_err(invalid)?;
        let current = database
            .as_ref()
            .ok_or_else(|| invalid("vault has an unknown durable outcome; reopen it"))?;
        let result = operation(current);
        if result.is_err() {
            // A write error may have committed. Fail closed until a fresh open
            // establishes a durability barrier; never regenerate an old intent.
            *database = None;
        }
        result
    }

    pub(crate) fn read_record(&self, key: &str) -> Result<Option<KeyBytes>> {
        self.with_database(|database| {
            let transaction = database.begin_read().map_err(invalid)?;
            let table = transaction.open_table(RECORDS).map_err(invalid)?;
            table
                .get(key)
                .map_err(invalid)?
                .map(|record| self.decrypt_payload(key, record.value()))
                .transpose()
        })
    }

    /// Compare plaintext bytes while retaining only authenticated ciphertext in
    /// the distinct manager database. A failed/unknown commit poisons the handle
    /// and can only be reconciled by a cold reopen, never by regenerating keys.
    pub(crate) fn compare_exchange_record(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool> {
        self.with_database(|database| {
            let mut transaction = database.begin_write().map_err(invalid)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(invalid)?;
            transaction.set_two_phase_commit(true);
            {
                let mut table = transaction.open_table(RECORDS).map_err(invalid)?;
                let existing = table
                    .get(key)
                    .map_err(invalid)?
                    .map(|record| self.decrypt_payload(key, record.value()))
                    .transpose()?;
                if existing.as_ref().map(KeyBytes::as_slice) != expected {
                    return Ok(false);
                }
                let encrypted = self.encrypt_payload(key, replacement)?;
                table.insert(key, encrypted.as_slice()).map_err(invalid)?;
            }
            transaction.commit().map_err(invalid)?;
            Ok(true)
        })
    }

    /// Freeze an independently random recipient before any public declaration.
    /// The same intent recovers exactly its original private key after restart.
    pub fn prepare_recipient(&self, actor: &RealmActorId, intent: &str) -> Result<[u8; 32]> {
        if intent.is_empty() || intent.len() > 256 {
            return Err(invalid("recipient intent must be bounded and nonempty"));
        }
        let key = Self::key(actor, "prepared", &intent)?;
        self.prepare_key(&key)
    }

    /// The subject digest binds the exact Realm/Applet and stable provisioning
    /// identity before inception. The future Actor ID depends on this public
    /// key through the WebVH SCID, so it cannot key the initial private intent.
    pub(crate) fn prepare_candidate_recipient(&self, subject_digest: &str) -> Result<[u8; 32]> {
        self.prepare_key(&Self::candidate_key(subject_digest)?)
    }

    fn candidate_key(subject_digest: &str) -> Result<String> {
        let digest = subject_digest
            .strip_prefix("sha256:")
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| invalid("candidate custody requires a canonical subject digest"))?;
        if digest.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(invalid(
                "candidate subject digest must be canonical lowercase",
            ));
        }
        Ok(format!("manager-archive/v1/candidate/{digest}"))
    }

    fn prepare_key(&self, key: &str) -> Result<[u8; 32]> {
        self.with_database(|database| {
            let mut transaction = database.begin_write().map_err(invalid)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(invalid)?;
            transaction.set_two_phase_commit(true);
            let public = {
                let mut table = transaction.open_table(KEYS).map_err(invalid)?;
                let existing = table
                    .get(key)
                    .map_err(invalid)?
                    .map(|value| value.value().to_vec());
                if let Some(existing) = existing {
                    let private = self.decrypt(key, &existing)?;
                    arkret::crypto::hpke::x25519_public_key(private.as_slice()).map_err(invalid)?
                } else {
                    let pair = arkret::crypto::hpke::generate_x25519_keypair().map_err(invalid)?;
                    let encrypted = self.encrypt(key, pair.private_key())?;
                    table.insert(key, encrypted.as_slice()).map_err(invalid)?;
                    *pair.public_key()
                }
            };
            transaction.commit().map_err(invalid)?;
            Ok(public)
        })
    }

    /// Bind only an independently verified accepted declaration to its already
    /// durable private key. No current authorization is inferred from this row.
    pub(crate) fn accept_recipient(
        &self,
        actor: &RealmActorId,
        intent: &str,
        reference: &CommittedEventRef,
        expected_public: &[u8; 32],
    ) -> Result<()> {
        let prepared = Self::key(actor, "prepared", &intent)?;
        let accepted = Self::key(actor, "accepted", reference)?;
        self.accept_key(&prepared, &accepted, expected_public)
    }

    pub(crate) fn accept_candidate_recipient(
        &self,
        actor: &RealmActorId,
        subject_digest: &str,
        reference: &CommittedEventRef,
        expected_public: &[u8; 32],
    ) -> Result<()> {
        let prepared = Self::candidate_key(subject_digest)?;
        let accepted = Self::key(actor, "accepted", reference)?;
        self.accept_key(&prepared, &accepted, expected_public)
    }

    fn accept_key(&self, prepared: &str, accepted: &str, expected_public: &[u8; 32]) -> Result<()> {
        self.with_database(|database| {
            let mut transaction = database.begin_write().map_err(invalid)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(invalid)?;
            transaction.set_two_phase_commit(true);
            {
                let mut table = transaction.open_table(KEYS).map_err(invalid)?;
                let raw = table
                    .get(prepared)
                    .map_err(invalid)?
                    .ok_or_else(|| invalid("declared recipient intent is missing"))?
                    .value()
                    .to_vec();
                let private = self.decrypt(prepared, &raw)?;
                if arkret::crypto::hpke::x25519_public_key(private.as_slice()).map_err(invalid)?
                    != *expected_public
                {
                    return Err(invalid(
                        "accepted recipient differs from durable private custody",
                    ));
                }
                let existing = table
                    .get(accepted)
                    .map_err(invalid)?
                    .map(|value| value.value().to_vec());
                if let Some(existing) = existing {
                    if self.decrypt(accepted, &existing)?.as_slice() != private.as_slice() {
                        return Err(invalid(
                            "recipient original already binds another private key",
                        ));
                    }
                } else {
                    let encrypted = self.encrypt(accepted, private.as_slice())?;
                    table
                        .insert(accepted, encrypted.as_slice())
                        .map_err(invalid)?;
                }
            }
            transaction.commit().map_err(invalid)?;
            Ok(())
        })
    }

    /// Only the manager facade uses this for its verified private handover or
    /// history-only recovery. The Device facade never owns a vault capability.
    pub(crate) fn import_recipient_keys(
        &self,
        actor: &RealmActorId,
        keys: &[arkret_models_integration::RealmActorContentBackupPrivateRecipientKey],
        record_key: &str,
        record: &[u8],
    ) -> Result<()> {
        self.with_database(|database| {
            let mut transaction = database.begin_write().map_err(invalid)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(invalid)?;
            transaction.set_two_phase_commit(true);
            {
                let mut table = transaction.open_table(KEYS).map_err(invalid)?;
                for entry in keys {
                    entry.content_backup_recipient.validate().map_err(invalid)?;
                    let private = entry.private_key_base64url.expose();
                    if arkret::base64url_encode(
                        arkret::crypto::hpke::x25519_public_key(private).map_err(invalid)?,
                    ) != entry.content_backup_recipient.public_key_base64url
                    {
                        return Err(invalid(
                            "imported archive key differs from its original recipient",
                        ));
                    }
                    let key = Self::key(actor, "accepted", &entry.recipient_ref)?;
                    let existing = table
                        .get(key.as_str())
                        .map_err(invalid)?
                        .map(|record| self.decrypt(&key, record.value()))
                        .transpose()?;
                    if let Some(existing) = existing {
                        if existing.as_slice() != private {
                            return Err(invalid(
                                "archive import conflicts with an existing original key",
                            ));
                        }
                    } else {
                        let encrypted = self.encrypt(&key, private)?;
                        table
                            .insert(key.as_str(), encrypted.as_slice())
                            .map_err(invalid)?;
                    }
                }
            }
            {
                let mut table = transaction.open_table(RECORDS).map_err(invalid)?;
                let existing = table
                    .get(record_key)
                    .map_err(invalid)?
                    .map(|value| self.decrypt_payload(record_key, value.value()))
                    .transpose()?;
                if let Some(existing) = existing {
                    if existing.as_slice() != record {
                        return Err(invalid("archive import changed its frozen private outcome"));
                    }
                } else {
                    let encrypted = self.encrypt_payload(record_key, record)?;
                    table
                        .insert(record_key, encrypted.as_slice())
                        .map_err(invalid)?;
                }
            }
            transaction.commit().map_err(invalid)?;
            Ok(())
        })
    }

    pub(crate) fn with_accepted_key<T>(
        &self,
        actor: &RealmActorId,
        reference: &CommittedEventRef,
        operation: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let key = Self::key(actor, "accepted", reference)?;
        self.with_stored_key(&key, operation)
    }

    pub(crate) fn with_prepared_key<T>(
        &self,
        actor: &RealmActorId,
        intent: &str,
        operation: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        self.with_stored_key(&Self::key(actor, "prepared", &intent)?, operation)
    }

    fn with_stored_key<T>(
        &self,
        key: &str,
        operation: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        self.with_database(|database| {
            let transaction = database.begin_read().map_err(invalid)?;
            let table = transaction.open_table(KEYS).map_err(invalid)?;
            let raw = table
                .get(key)
                .map_err(invalid)?
                .ok_or_else(|| invalid("original recipient private custody is missing"))?;
            let private = self.decrypt(key, raw.value())?;
            operation(private.as_slice())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(byte: u8) -> RealmActorId {
        RealmActorId {
            realm_id: arkret::RealmId::from_event_id(&arkret::EventId::from_digest(
                arkret::DigestSuite::Sha256,
                [byte; 32],
            )),
            principal_id: arkret::DidCoreId::new("ak:did_core:web:archive.invalid").unwrap(),
        }
    }

    fn path() -> std::path::PathBuf {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        std::env::temp_dir().join(format!(
            "arkret-manager-archive-{}.redb",
            hex::encode(nonce)
        ))
    }

    #[test]
    fn archive_recipient_survives_cold_open_with_independent_key_and_actor_partition() {
        let path = path();
        let original = {
            let vault = ManagerArchiveVault::open(&path, KeyBytes::new(vec![31; 32])).unwrap();
            let original = vault.prepare_recipient(&actor(1), "creation").unwrap();
            assert_eq!(
                original,
                vault.prepare_recipient(&actor(1), "creation").unwrap()
            );
            assert_ne!(
                original,
                vault.prepare_recipient(&actor(2), "creation").unwrap()
            );
            assert_ne!(
                original,
                vault.prepare_recipient(&actor(1), "replacement").unwrap()
            );
            assert!(vault.require_distinct_authoring_key(&[31; 32]).is_err());
            vault.require_distinct_authoring_key(&[32; 32]).unwrap();
            assert!(!format!("{vault:?}").contains("31"));
            original
        };
        assert!(ManagerArchiveVault::open(&path, KeyBytes::new(vec![32; 32])).is_err());
        let reopened = ManagerArchiveVault::open(&path, KeyBytes::new(vec![31; 32])).unwrap();
        assert_eq!(
            original,
            reopened.prepare_recipient(&actor(1), "creation").unwrap()
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn manager_archive_cannot_share_an_open_daily_journal_database() {
        let path = path();
        let daily = crate::FileAuthoringStore::new(path.clone()).unwrap();
        assert!(ManagerArchiveVault::open(&path, KeyBytes::new(vec![41; 32])).is_err());
        drop(daily);
        assert!(ManagerArchiveVault::open(&path, KeyBytes::new(vec![41; 32])).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn candidate_archive_key_precedes_actor_identity_and_binds_exact_original_after_cold_open() {
        let path = path();
        let subject = arkret::canonical::canonical_sha256(&(
            "managed-candidate",
            actor(1).realm_id,
            "applet",
            "creation",
        ))
        .unwrap();
        let other = arkret::canonical::canonical_sha256(&(
            "managed-candidate",
            actor(2).realm_id,
            "applet",
            "creation",
        ))
        .unwrap();
        let reference = CommittedEventRef {
            event_id: arkret::EventId::from_digest(arkret::DigestSuite::Sha256, [4; 32]),
            commit_id: arkret::RealmCommitId::from_digest([5; 32]),
            stream_ref: arkret::CommitStreamRef::RealmControl {
                realm_id: actor(1).realm_id,
            },
            stream_position: 1,
        };
        let public = {
            let vault = ManagerArchiveVault::open(&path, KeyBytes::new(vec![42; 32])).unwrap();
            let public = vault.prepare_candidate_recipient(&subject).unwrap();
            assert_ne!(public, vault.prepare_candidate_recipient(&other).unwrap());
            assert!(
                vault
                    .prepare_candidate_recipient("unbounded caller key")
                    .is_err()
            );
            public
        };
        {
            let vault = ManagerArchiveVault::open(&path, KeyBytes::new(vec![42; 32])).unwrap();
            assert_eq!(public, vault.prepare_candidate_recipient(&subject).unwrap());
            vault
                .accept_candidate_recipient(&actor(1), &subject, &reference, &public)
                .unwrap();
        }
        let vault = ManagerArchiveVault::open(&path, KeyBytes::new(vec![42; 32])).unwrap();
        vault
            .with_accepted_key(&actor(1), &reference, |private| {
                assert_eq!(
                    arkret::crypto::hpke::x25519_public_key(private).unwrap(),
                    public
                );
                Ok(())
            })
            .unwrap();
        drop(vault);
        std::fs::remove_file(path).unwrap();
    }
}
