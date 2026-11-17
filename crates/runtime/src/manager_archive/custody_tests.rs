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
            let collect = |definition: TableDefinition<&str, &[u8]>| -> Result<RawTable> {
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
fn real_sdk_handover_rechecks_acceptance_time_before_first_or_cold_vault_write() {
    use std::cell::Cell;

    use arkret::identity::{RealmAuthorityFreshness, RealmAuthorityKeyMap};
    use arkret::signatures::detached_object::sign_detached_object;
    use arkret::{
        CommitStreamHead, DetachedSignatureContext, RealmAuthorityBundle,
        RealmAuthorityCurrentAssertion,
    };
    use arkret_models_integration::{
        RealmActorArchiveInventoryEntry, RealmActorArchiveInventoryManifest,
        RealmActorContentBackupHandoverOfferSignatureInput,
    };

    // A Series-only formal cut isolates the SDK crypto/HPKE/durable callback
    // boundary. It does not claim a complete live inventory or PG admission.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json"
    )))
    .unwrap();
    let mut manifest: RealmActorArchiveInventoryManifest =
        serde_json::from_value(fixture["archive_inventory"].clone()).unwrap();
    manifest
        .entries
        .retain(|entry| matches!(entry, RealmActorArchiveInventoryEntry::Series(_)));
    assert_eq!(manifest.entries.len(), 1);
    let RealmActorArchiveInventoryEntry::Series(series) = &manifest.entries[0] else {
        unreachable!()
    };
    let series_commit = series.source.commit.clone();
    let genesis = &fixture["native_source"]["governance_history"]["genesis"];
    let genesis_event: arkret::Event = serde_json::from_value(genesis["event"].clone()).unwrap();
    let original_commit: arkret::RealmCommit =
        serde_json::from_value(genesis["commit"].clone()).unwrap();
    let resolution: arkret::AuthenticatedServiceResolution = serde_json::from_value(
        fixture["native_source"]["governance_history"]["genesis_resolution"].clone(),
    )
    .unwrap();
    let governor = ed25519_dalek::SigningKey::from_bytes(
        &hex::decode(
            fixture["original_authority_reference"]["governor_seed_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );
    let original_offer: arkret_models_integration::RealmActorContentBackupHandoverOffer =
        serde_json::from_value(fixture["private_handover"]["sealed"]["offer"].clone()).unwrap();
    let first_at = original_offer.signature.created_at + chrono::Duration::seconds(1);
    // Rebuild the authenticated carrier from the fixture's unchanged signed
    // native logs; its older wrapper receipt is not itself a trusted proof.
    let native = &fixture["native_source"]["governance_history"]["genesis_resolution"]["method_history_evidence"];
    let mut entries = native["log_entries"].as_array().unwrap().clone();
    let mut witnesses = native["witness_records"].as_array().unwrap().clone();
    // The formal actor log publishes control-0 only for authentication.
    // Add its assertion relationship through a real, witnessed native update
    // before Genesis; never patch the unverified normalized projection.
    let history = &fixture["original_authority_reference"]["governor_history"];
    let seed = |value: &serde_json::Value| -> [u8; 32] {
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let did = arkret::Did::new(entries.last().unwrap()["state"]["id"].as_str().unwrap()).unwrap();
    let mut state = entries.last().unwrap()["state"].clone();
    state["assertionMethod"] = serde_json::json!([original_commit.signature.verification_method]);
    let rotated = arkret_signatures::webvh::prepare_service_rotation(
        &arkret_signatures::webvh::ServiceRotationInput {
            did: did.as_str(),
            previous_entries: &entries,
            state: &state,
            current_update_seed: &seed(&history["root_test_seeds_hex"][1]),
            next_update_public_key_multibase:
                &arkret::canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&seed(
                        &history["root_test_seeds_hex"][2],
                    ))
                    .verifying_key()
                    .as_bytes(),
                ),
            version_created_at: original_commit.committed_at - chrono::Duration::days(1),
        },
    )
    .unwrap();
    let proof = arkret_signatures::webvh::sign_did_webvh_witness_proof(
        &rotated.version_id,
        &seed(&history["witness_test_seed_hex"]),
    );
    witnesses.push(serde_json::json!({"versionId":rotated.version_id,"proof":[proof]}));
    entries.push(rotated.log_entry);
    let resolution = arkret::identity::build_authenticated_webvh_service_resolution(
        resolution.service_id,
        resolution.service_kind,
        serde_json::from_value(entries.last().unwrap()["state"].clone()).unwrap(),
        entries,
        witnesses,
        first_at,
    )
    .unwrap();
    arkret::identity::authenticated_service_document_at(
        &resolution,
        &resolution.service_id,
        series_commit.committed_at,
    )
    .unwrap();

    let authorities = |genesis_at| {
        let mut commit = original_commit.clone();
        commit.committed_at = genesis_at;
        commit.commit_id = arkret::RealmCommitId::from_digest(arkret::canonical::sha256_bytes(
            commit.canonical_id_bytes().unwrap(),
        ));
        commit.signature = sign_detached_object(
            &arkret::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            original_commit.signature.verification_method.clone(),
            genesis_at,
            &governor,
        )
        .unwrap();
        commit.validate_content_address().unwrap();
        let head = CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: 0,
            commit_id: commit.commit_id.clone(),
        };
        let nonce = arkret::Base64UrlString::new(arkret::base64url_encode([31; 32])).unwrap();
        let mut assertion = RealmAuthorityCurrentAssertion {
            realm_id: genesis_event.realm_id.clone(),
            current_generation: 0,
            current_service_id: resolution.service_id.clone(),
            last_handoff_ref: None,
            realm_stream_head: head.clone(),
            nonce: nonce.clone(),
            expires_at: first_at + chrono::Duration::seconds(60),
            signature: commit.signature.clone(),
        };
        assertion.signature = sign_detached_object(
            &arkret::canonical::unsigned_value(&assertion, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            original_commit.signature.verification_method.clone(),
            first_at,
            &governor,
        )
        .unwrap();
        let bundle = RealmAuthorityBundle {
            realm_id: genesis_event.realm_id.clone(),
            genesis_event: genesis_event.clone(),
            genesis_commit: commit,
            producer_signer_fact: Some(genesis["producer_signer_fact"].clone()),
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: resolution.service_id.clone(),
            current_route_record: serde_json::to_value(&resolution).unwrap(),
            realm_stream_head: head,
            bundle_issued_at: first_at,
            current_assertion: assertion,
        };
        let mut keys = RealmAuthorityKeyMap::new();
        for (method, at) in [
            (
                &bundle.genesis_commit.signature.verification_method,
                bundle.genesis_commit.signature.created_at,
            ),
            (
                &bundle.current_assertion.signature.verification_method,
                bundle.current_assertion.signature.created_at,
            ),
            (
                &series_commit.signature.verification_method,
                series_commit.signature.created_at,
            ),
            (
                &series_commit.signature.verification_method,
                series_commit.committed_at,
            ),
        ] {
            let document = arkret::identity::authenticated_service_document_at(
                &resolution,
                &resolution.service_id,
                at,
            )
            .unwrap();
            arkret::identity::validate_verification_method_relationship(
                &document,
                method,
                &document.id,
                arkret::identity::DidVerificationRelationship::AssertionMethod,
            )
            .unwrap();
            let key =
                arkret::identity::public_key_material_from_document(&document, method).unwrap();
            keys.insert_at(method, at, key);
        }
        let authority = arkret::identity::verify_realm_authority_bundle(
            &bundle,
            &RealmAuthorityFreshness::new(first_at, nonce),
            &keys,
        )
        .unwrap();
        // Both variants reach the original SDK's complete Series crypto check.
        arkret::identity::verify_realm_actor_archive_inventory(&manifest, &authority, &keys)
            .unwrap();
        (authority, keys)
    };
    let (valid_authority, valid_keys) = authorities(original_commit.committed_at);
    let (late_authority, late_keys) =
        authorities(series_commit.committed_at + chrono::Duration::seconds(1));
    late_authority
        .verify_commit(&series_commit, &late_keys)
        .unwrap();
    assert!(!late_authority.authorizes_issuer_at(
        &resolution.service_id,
        Some(&series_commit.authority_ref),
        series_commit.committed_at
    ));

    let offer_key = ed25519_dalek::SigningKey::from_bytes(
        &hex::decode(
            fixture["handover_offer_case"]["test_seed_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );
    let method = original_offer.signature.verification_method.clone();
    let did = arkret::verification_method_did(method.as_str()).unwrap();
    // These leaf relationship inputs have the SDK's existing test boundary;
    // they do not claim native Service registration or HTTP authentication.
    let document: arkret::DidDocument = serde_json::from_value(serde_json::json!({
        "id":did,"verificationMethod":[{"id":method,"controller":did,"type":"Multikey",
        "publicKeyMultibase":arkret::canonical::ed25519_pubkey_to_did_key_multibase(offer_key.verifying_key().as_bytes())}],
        "assertionMethod":[method]
    })).unwrap();
    let offer = arkret::identity::sign_realm_actor_backup_handover_offer(
        RealmActorContentBackupHandoverOfferSignatureInput {
            realm_actor_id: manifest.realm_actor_id.clone(),
            manager_ref: manifest.manager_ref.clone(),
            new_service_id: original_offer.new_service_id,
            next_content_backup_recipient: original_offer.next_content_backup_recipient,
            inventory_digest: manifest.inventory_digest().unwrap(),
            archive_revision: manifest.archive_revision,
            expires_at: original_offer.expires_at,
            nonce: original_offer.nonce,
        },
        method.clone(),
        original_offer.signature.created_at,
        &offer_key,
    )
    .unwrap();
    let pending = arkret::identity::seal_realm_actor_backup_handover(
        offer,
        &document,
        manifest,
        vec![],
        first_at,
    )
    .unwrap();
    let private = SecretBytes::new(
        hex::decode(
            fixture["test_material"]["next_archive_private_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );
    let record_key = "accepted-time-import";
    let run = |vault: &ManagerArchiveVault,
               authority: &arkret::identity::VerifiedRealmAuthority,
               keys: &RealmAuthorityKeyMap,
               at| {
        let reached = Cell::new(false);
        let context = arkret::identity::RealmActorBackupHandoverImportContext {
            offer_original_document: &document,
            confirmation_current_document: &document,
            confirmation_method: method.clone(),
            confirmation_signing_key: &offer_key,
            confirmed_at: at,
        };
        let result = arkret::identity::import_realm_actor_backup_handover(
            pending.sealed(),
            &private,
            authority,
            keys,
            &context,
            |identity| {
                let prior = vault.read_record(record_key).map_err(|error| {
                    arkret::identity::IdentityError::Protocol(error.to_string())
                })?;
                let Some(prior) = prior else { return Ok(None) };
                let prior: serde_json::Value = serde_json::from_slice(prior.as_slice())?;
                assert_eq!(
                    prior["sealed_digest"],
                    serde_json::to_value(&identity.sealed_digest).unwrap()
                );
                assert_eq!(
                    prior["inventory_digest"],
                    serde_json::to_value(&identity.inventory_digest).unwrap()
                );
                Ok(Some(serde_json::from_value(prior["imported_at"].clone())?))
            },
            |identity, plaintext, imported_at| {
                reached.set(true);
                crate::realm_governance::validate_archive_commit_coordinates(
                    &plaintext.inventory_manifest,
                    authority,
                    keys,
                )
                .map_err(|error| arkret::identity::IdentityError::Protocol(error.to_string()))?;
                let record = arkret::canonical::canonical_json_bytes(&serde_json::json!({
                    "sealed_digest":identity.sealed_digest,"inventory_digest":identity.inventory_digest,
                    "imported_at":imported_at,"plaintext":plaintext,
                }))?;
                vault
                    .import_recipient_keys(
                        &identity.realm_actor_id,
                        &plaintext.recipient_keys,
                        record_key,
                        &record,
                    )
                    .map_err(|error| arkret::identity::IdentityError::Protocol(error.to_string()))
            },
        );
        (result, reached.get())
    };
    let temporary = TemporaryArchive::new();
    {
        let vault = temporary.open();
        let before = raw_tables(&vault);
        let (bad, reached) = run(&vault, &late_authority, &late_keys, first_at);
        assert!(
            reached,
            "HPKE and original SDK crypto must reach the durable adapter"
        );
        assert!(
            bad.unwrap_err()
                .to_string()
                .contains("outside its verified Realm governance tenure")
        );
        assert_eq!(raw_tables(&vault), before);
        assert!(vault.read_record(record_key).unwrap().is_none());
        let (valid, reached) = run(&vault, &valid_authority, &valid_keys, first_at);
        assert!(reached);
        pending
            .verify_confirmation(&valid.unwrap(), &document)
            .unwrap();
        assert!(vault.read_record(record_key).unwrap().is_some());
    }
    let vault = temporary.open();
    let before = raw_tables(&vault);
    let (bad, reached) = run(
        &vault,
        &late_authority,
        &late_keys,
        first_at + chrono::Duration::seconds(2),
    );
    assert!(
        reached,
        "cold replay still revalidates the original cut before mutation"
    );
    assert!(
        bad.unwrap_err()
            .to_string()
            .contains("outside its verified Realm governance tenure")
    );
    assert_eq!(raw_tables(&vault), before);
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
