//! Real redb/AEAD custody and SDK HPKE tests. Local lookup references below do
//! not assert accepted governance, manager authorization, HTTP or PG admission.

use std::collections::BTreeMap;
use std::path::PathBuf;

use arkret_models_crypto::{
    ContentBackupRecipientHpkeSuite, RealmActorContentBackupRecipient, SecretBytes,
};
use arkret_models_integration::RealmActorContentBackupPrivateRecipientKey;

use super::*;

struct TemporaryArchive {
    directory: PathBuf,
    path: PathBuf,
}

impl TemporaryArchive {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let directory =
            std::env::temp_dir().join(format!("arkret-manager-custody-{}", hex::encode(nonce)));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("manager.redb");
        Self { directory, path }
    }

    fn open(&self) -> ManagerArchiveVault {
        ManagerArchiveVault::open(&self.path, KeyBytes::new(vec![91; 32])).unwrap()
    }
}

impl Drop for TemporaryArchive {
    fn drop(&mut self) {
        // redb owns only this one file; never recurse into a computed path.
        let file = if self.path.exists() {
            std::fs::remove_file(&self.path)
        } else {
            Ok(())
        };
        let directory = std::fs::remove_dir(&self.directory);
        if !std::thread::panicking() {
            file.expect("release the test redb file after its last handle");
            directory.expect("remove the empty private test directory");
        }
    }
}

fn subject() -> RealmActorId {
    RealmActorId {
        realm_id: arkret::RealmId::from_event_id(&arkret::EventId::from_digest(
            arkret::DigestSuite::Sha256,
            [41; 32],
        )),
        principal_id: arkret::DidCoreId::new("ak:did_core:web:manager-custody.invalid").unwrap(),
    }
}

fn local_reference(byte: u8) -> CommittedEventRef {
    CommittedEventRef {
        event_id: arkret::EventId::from_digest(arkret::DigestSuite::Sha256, [byte; 32]),
        commit_id: arkret::RealmCommitId::from_digest([byte.wrapping_add(1); 32]),
        stream_ref: arkret::CommitStreamRef::RealmControl {
            realm_id: subject().realm_id,
        },
        stream_position: u64::from(byte),
    }
}

fn import_key(byte: u8) -> RealmActorContentBackupPrivateRecipientKey {
    let private = [byte; 32];
    let public = arkret::crypto::hpke::x25519_public_key(&private).unwrap();
    RealmActorContentBackupPrivateRecipientKey {
        recipient_ref: local_reference(byte),
        content_backup_recipient: RealmActorContentBackupRecipient {
            key_agreement_ref: arkret::DidUrl::new(format!(
                "did:web:manager-custody.invalid#archive-{byte}"
            ))
            .unwrap(),
            hpke_suite: ContentBackupRecipientHpkeSuite::AkHpkeX25519AeadChacha20poly1305V1,
            public_key_base64url: arkret::base64url_encode(public),
        },
        private_key_base64url: SecretBytes::new(private),
    }
}

type RawTable = BTreeMap<String, Vec<u8>>;

fn raw_tables(vault: &ManagerArchiveVault) -> (RawTable, RawTable) {
    vault
        .with_database(|database| {
            let transaction = database.begin_read().map_err(invalid)?;
            let collect = |definition| -> Result<RawTable> {
                let table = transaction.open_table(definition).map_err(invalid)?;
                table
                    .iter()
                    .map_err(invalid)?
                    .map(|row| {
                        let (key, value) = row.map_err(invalid)?;
                        Ok((key.value().to_owned(), value.value().to_vec()))
                    })
                    .collect()
            };
            Ok((collect(KEYS)?, collect(RECORDS)?))
        })
        .unwrap()
}

#[test]
fn manager_private_record_cold_reopen_and_losing_cas_preserve_original_ciphertext() {
    let directory = TemporaryArchive::new();
    let key = ManagerArchiveVault::key(&subject(), "custody-test", &"private-outcome").unwrap();
    let plaintext = b"original private outcome with durable import details";
    let original = {
        let vault = directory.open();
        assert!(
            vault
                .compare_exchange_record(&key, None, plaintext)
                .unwrap()
        );
        let before = raw_tables(&vault);
        let encrypted = &before.1[&key];
        assert_eq!(encrypted.len(), 24 + plaintext.len() + 16);
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(
            vault
                .decrypt_payload("different-record-identity", encrypted)
                .is_err()
        );
        assert!(
            !vault
                .compare_exchange_record(&key, None, b"losing replacement")
                .unwrap()
        );
        assert!(
            !vault
                .compare_exchange_record(&key, Some(b"wrong prior bytes"), b"another loser")
                .unwrap()
        );
        assert_eq!(raw_tables(&vault), before);
        assert_eq!(
            vault.read_record(&key).unwrap().unwrap().as_slice(),
            plaintext
        );
        before
    };
    let reopened = directory.open();
    assert_eq!(raw_tables(&reopened), original);
    assert_eq!(
        reopened.read_record(&key).unwrap().unwrap().as_slice(),
        plaintext
    );
}

#[test]
fn committed_unknown_manager_outcome_poison_requires_reopen_without_recipient_regeneration() {
    let directory = TemporaryArchive::new();
    let subject = subject();
    let digest =
        arkret::canonical::canonical_sha256(&("candidate custody test", &subject)).unwrap();
    let record_key = ManagerArchiveVault::key(&subject, "custody-test", &"unknown-commit").unwrap();
    let original_bytes = b"committed private operation; caller did not receive its success";
    let vault = directory.open();
    let candidate_public = vault.prepare_candidate_recipient(&digest).unwrap();
    let prepared_public = vault
        .prepare_recipient(&subject, "prepared-for-unknown")
        .unwrap();
    let keys_before = raw_tables(&vault).0;
    let sealed = arkret::crypto::hpke::seal_x25519_chacha20poly1305(
        &prepared_public,
        b"prepared private key remains usable",
        b"custody test info",
        b"exact subject test AAD",
    )
    .unwrap();
    let encrypted_record = vault.encrypt_payload(&record_key, original_bytes).unwrap();
    let unknown: Result<()> = vault.with_database(|database| {
        let mut transaction = database.begin_write().map_err(invalid)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(invalid)?;
        transaction.set_two_phase_commit(true);
        {
            let mut records = transaction.open_table(RECORDS).map_err(invalid)?;
            records
                .insert(record_key.as_str(), encrypted_record.as_slice())
                .map_err(invalid)?;
        }
        transaction.commit().map_err(invalid)?;
        // Inject at the actual post-commit result boundary, not before writing:
        // with_database must drop its handle instead of trusting this outcome.
        Err(invalid(
            "injected unknown result after actual durable commit",
        ))
    });
    assert!(
        unknown
            .unwrap_err()
            .to_string()
            .contains("after actual durable commit")
    );
    assert!(vault.database.lock().unwrap().is_none());
    assert!(
        vault
            .read_record(&record_key)
            .unwrap_err()
            .to_string()
            .contains("unknown durable outcome")
    );
    assert!(
        vault
            .prepare_candidate_recipient(&digest)
            .unwrap_err()
            .to_string()
            .contains("unknown durable outcome")
    );
    assert!(
        vault
            .with_prepared_key(&subject, "prepared-for-unknown", |_| Ok(()))
            .is_err()
    );
    drop(vault);

    let reopened = directory.open();
    assert_eq!(raw_tables(&reopened).0, keys_before);
    assert_eq!(raw_tables(&reopened).1[&record_key], encrypted_record);
    assert_eq!(
        reopened
            .read_record(&record_key)
            .unwrap()
            .unwrap()
            .as_slice(),
        original_bytes
    );
    assert_eq!(
        reopened.prepare_candidate_recipient(&digest).unwrap(),
        candidate_public
    );
    assert_eq!(
        reopened
            .prepare_recipient(&subject, "prepared-for-unknown")
            .unwrap(),
        prepared_public
    );
    reopened
        .with_prepared_key(&subject, "prepared-for-unknown", |private| {
            let opened = arkret::crypto::hpke::open_x25519_chacha20poly1305(
                private,
                &sealed,
                b"custody test info",
                b"exact subject test AAD",
            )
            .map_err(invalid)?;
            assert_eq!(opened, b"prepared private key remains usable");
            Ok(())
        })
        .unwrap();
    assert_eq!(raw_tables(&reopened).0, keys_before);
}

#[test]
fn later_recipient_import_failure_rolls_back_earlier_key_and_outcome_record_together() {
    let directory = TemporaryArchive::new();
    let subject = subject();
    let vault = directory.open();
    let before = raw_tables(&vault);
    let first = import_key(51);
    let mut second = import_key(52);
    // Both descriptors are valid X25519 recipients; only the second private /
    // public binding is wrong, after the first row was tentatively inserted.
    second.private_key_base64url = SecretBytes::new([53; 32]);
    let record_key = ManagerArchiveVault::key(&subject, "custody-test", &"failed-import").unwrap();
    let result =
        vault.import_recipient_keys(&subject, &[first, second], &record_key, b"not committed");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("differs from its original recipient")
    );
    assert!(vault.database.lock().unwrap().is_none());
    drop(vault);
    let reopened = directory.open();
    assert_eq!(raw_tables(&reopened), before);
    assert!(reopened.read_record(&record_key).unwrap().is_none());
    let accepted_key =
        ManagerArchiveVault::key(&subject, "accepted", &local_reference(51)).unwrap();
    assert!(!raw_tables(&reopened).0.contains_key(&accepted_key));
}

#[test]
fn conflicting_import_outcome_rolls_back_all_tentative_recipient_keys() {
    let directory = TemporaryArchive::new();
    let subject = subject();
    let vault = directory.open();
    let record_key =
        ManagerArchiveVault::key(&subject, "custody-test", &"immutable-import").unwrap();
    assert!(
        vault
            .compare_exchange_record(&record_key, None, b"previous immutable result")
            .unwrap()
    );
    let before = raw_tables(&vault);
    let result = vault.import_recipient_keys(
        &subject,
        &[import_key(61), import_key(62)],
        &record_key,
        b"changed result",
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("changed its frozen private outcome")
    );
    drop(vault);
    let reopened = directory.open();
    assert_eq!(raw_tables(&reopened), before);
    assert_eq!(
        reopened
            .read_record(&record_key)
            .unwrap()
            .unwrap()
            .as_slice(),
        b"previous immutable result"
    );
}

#[test]
fn imported_recipient_private_material_survives_cold_reopen_and_actually_opens_sdk_hpke() {
    let directory = TemporaryArchive::new();
    let subject = subject();
    let keys = [import_key(71), import_key(72)];
    let record_key =
        ManagerArchiveVault::key(&subject, "custody-test", &"completed-import").unwrap();
    let record = b"durable outcome for both imported recipient originals";
    let sealed: Vec<_> = keys
        .iter()
        .map(|entry| {
            let public =
                arkret::crypto::hpke::x25519_public_key(entry.private_key_base64url.expose())
                    .unwrap();
            arkret::crypto::hpke::seal_x25519_chacha20poly1305(
                &public,
                b"actual imported root material",
                b"imported key test info",
                b"original exact recipient test AAD",
            )
            .unwrap()
        })
        .collect();
    let original = {
        let vault = directory.open();
        vault
            .import_recipient_keys(&subject, &keys, &record_key, record)
            .unwrap();
        let before = raw_tables(&vault);
        // Exact import retry must neither rewrap old keys nor rewrite its ACK.
        vault
            .import_recipient_keys(&subject, &keys, &record_key, record)
            .unwrap();
        assert_eq!(raw_tables(&vault), before);
        before
    };
    let reopened = directory.open();
    assert_eq!(raw_tables(&reopened), original);
    assert_eq!(
        reopened
            .read_record(&record_key)
            .unwrap()
            .unwrap()
            .as_slice(),
        record
    );
    for (entry, ciphertext) in keys.iter().zip(&sealed) {
        reopened
            .with_accepted_key(&subject, &entry.recipient_ref, |private| {
                assert_eq!(private, entry.private_key_base64url.expose());
                let opened = arkret::crypto::hpke::open_x25519_chacha20poly1305(
                    private,
                    ciphertext,
                    b"imported key test info",
                    b"original exact recipient test AAD",
                )
                .map_err(invalid)?;
                assert_eq!(opened, b"actual imported root material");
                assert!(
                    arkret::crypto::hpke::open_x25519_chacha20poly1305(
                        private,
                        ciphertext,
                        b"wrong info",
                        b"original exact recipient test AAD",
                    )
                    .is_err()
                );
                assert!(
                    arkret::crypto::hpke::open_x25519_chacha20poly1305(
                        private,
                        ciphertext,
                        b"imported key test info",
                        b"wrong AAD",
                    )
                    .is_err()
                );
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(raw_tables(&reopened), original);
}

#[test]
fn manager_owner_binding_survives_cold_reopen_and_foreign_deployments_do_not_poison_it() {
    let directory = TemporaryArchive::new();
    let applet = arkret::AppletId::new("ak:applet:019a0000-0000-7000-8000-000000000031").unwrap();
    let other_applet =
        arkret::AppletId::new("ak:applet:019a0000-0000-7000-8000-000000000032").unwrap();
    let service = arkret::DidCoreId::new("ak:did_core:web:original-manager.invalid").unwrap();
    let other_service = arkret::DidCoreId::new("ak:did_core:web:next-manager.invalid").unwrap();
    let owner_key = "manager-archive/v1/deployment-owner";
    let owner = arkret::canonical::canonical_json_bytes(&(&applet, &service)).unwrap();
    let record_key =
        ManagerArchiveVault::key(&subject(), "custody-test", &"owner-private-outcome").unwrap();
    let original_bytes = b"original manager private operation";
    let original = {
        let vault = directory.open();
        assert!(vault.read_record(owner_key).unwrap().is_none());
        vault.bind_manager(&applet, &service).unwrap();
        assert_eq!(
            vault.read_record(owner_key).unwrap().unwrap().as_slice(),
            owner
        );
        assert!(
            vault
                .compare_exchange_record(&record_key, None, original_bytes)
                .unwrap()
        );
        let before = raw_tables(&vault);
        assert_ne!(before.1[owner_key], owner);
        vault.bind_manager(&applet, &service).unwrap();
        assert_eq!(raw_tables(&vault), before);
        before
    };

    let reopened = directory.open();
    reopened.bind_manager(&applet, &service).unwrap();
    assert_eq!(raw_tables(&reopened), original);
    for (requested_applet, requested_service) in [
        (&applet, &other_service),
        (&other_applet, &service),
        (&other_applet, &other_service),
    ] {
        let before = raw_tables(&reopened);
        let error = reopened
            .bind_manager(requested_applet, requested_service)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("belongs to another Applet or Service deployment")
        );
        assert!(reopened.database.lock().unwrap().is_some());
        assert_eq!(raw_tables(&reopened), before);
        reopened.bind_manager(&applet, &service).unwrap();
        assert_eq!(
            reopened
                .read_record(&record_key)
                .unwrap()
                .unwrap()
                .as_slice(),
            original_bytes
        );
        assert!(
            reopened
                .compare_exchange_record(
                    &record_key,
                    Some(original_bytes),
                    b"legitimate manager can still write"
                )
                .unwrap()
        );
        assert!(
            reopened
                .compare_exchange_record(
                    &record_key,
                    Some(b"legitimate manager can still write"),
                    original_bytes
                )
                .unwrap()
        );
        assert_eq!(
            reopened.read_record(owner_key).unwrap().unwrap().as_slice(),
            owner
        );
        assert_eq!(raw_tables(&reopened).1[owner_key], original.1[owner_key]);
    }
    drop(reopened);
    let final_open = directory.open();
    final_open.bind_manager(&applet, &service).unwrap();
    assert_eq!(
        final_open
            .read_record(&record_key)
            .unwrap()
            .unwrap()
            .as_slice(),
        original_bytes
    );
    assert_eq!(raw_tables(&final_open).1[owner_key], original.1[owner_key]);
}
