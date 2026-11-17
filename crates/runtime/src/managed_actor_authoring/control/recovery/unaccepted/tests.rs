//! Signed current material is not permission to contradict a witnessed coordinate.
use arkret::identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyMap, VerifiedRealmActorMaterial,
    VerifiedRealmAuthority, verify_realm_actor_material, verify_realm_authority_bundle,
};
use arkret::signatures::detached_object::sign_detached_object;
use arkret::{
    Base64UrlString, CommitStreamHead, CommitStreamRef, DetachedSignatureContext, EventId,
    RealmActorMaterialRequestBody, RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
    RealmCommitAuthorityRef, RealmCommitId, ScopeRef,
};
use arkret_test_kit::service_identity::ServiceIdentityFixture;

use super::*;

struct Fixture {
    station: ServiceIdentityFixture,
    authority: VerifiedRealmAuthority,
    keys: RealmAuthorityKeyMap,
    prepared: PreparedRecovery,
    rotation: super::super::super::PreparedControlRotation,
    current: RealmActorMaterialResponseBody,
}

fn kat() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-signature-kat-fixture.json",
            ),
        )
        .unwrap(),
    )
    .unwrap()
}

fn seed(value: &Value) -> SigningKey {
    SigningKey::from_bytes(
        &hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn seal_commit(commit: &mut RealmCommit, station: &ServiceIdentityFixture) {
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        commit.canonical_id_bytes().unwrap(),
    ));
    commit.signature = sign_detached_object(
        &arkret_canonical::unsigned_value(commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        station.verification_method.clone(),
        commit.committed_at,
        &station.signing_key,
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
}

impl Fixture {
    fn new() -> Self {
        let kat = kat();
        let at = "2026-11-08T00:00:00Z".parse().unwrap();
        let station = ServiceIdentityFixture::webvh(
            &url::Url::parse("https://closure-station.example").unwrap(),
            730,
            [0x73; 32],
            "closure",
            at - chrono::Duration::days(1),
            at,
        )
        .unwrap();
        let genesis = arkret_wire::test_support::raw_event_at(
            "ak.realm.create",
            ScopeRef::RealmGenesis,
            DidCoreId::new("ak:did_core:web:closure-owner.example").unwrap(),
            station.service_id.clone(),
            json!({"object":{"purpose":"collaboration","governance_station_id":station.service_id}}),
            at - chrono::Duration::hours(1),
        )
        .unwrap();
        let mut genesis_commit = arkret_wire::test_support::structural_realm_commit_at(
            &genesis,
            genesis.realm_id.clone(),
            0,
            station.verification_method.clone(),
            genesis.created_at,
        );
        genesis_commit.previous_commit_ref = None;
        genesis_commit.authority_ref =
            RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
        seal_commit(&mut genesis_commit, &station);
        let head = CommitStreamHead {
            stream_ref: genesis_commit.stream_ref.clone(),
            commit_id: genesis_commit.commit_id.clone(),
            stream_position: 0,
        };
        let nonce = Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let mut assertion = RealmAuthorityCurrentAssertion {
            realm_id: genesis.realm_id.clone(),
            current_generation: 0,
            current_service_id: station.service_id.clone(),
            last_handoff_ref: None,
            realm_stream_head: head.clone(),
            nonce: nonce.clone(),
            expires_at: at + chrono::Duration::seconds(60),
            signature: genesis_commit.signature.clone(),
        };
        assertion.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&assertion, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            station.verification_method.clone(),
            at,
            &station.signing_key,
        )
        .unwrap();
        let bundle = RealmAuthorityBundle {
            realm_id: genesis.realm_id.clone(),
            genesis_event: genesis.clone(),
            genesis_commit,
            producer_signer_fact: None,
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: station.service_id.clone(),
            current_route_record: serde_json::to_value(&station.resolution).unwrap(),
            realm_stream_head: head,
            bundle_issued_at: at,
            current_assertion: assertion,
        };
        let keys = RealmAuthorityKeyMap::new().with_key(
            &station.verification_method,
            PublicKeyMaterial::Ed25519Raw {
                bytes: station.signing_key.verifying_key().to_bytes().to_vec(),
            },
        );
        let authority =
            verify_realm_authority_bundle(&bundle, &RealmAuthorityFreshness::new(at, nonce), &keys)
                .unwrap();
        let mut actor: ActorId =
            serde_json::from_value(kat["cases"][0]["candidate"]["actor_id"].clone()).unwrap();
        let mut actor_json = serde_json::to_value(&actor).unwrap();
        actor_json["realm_actor_id"]["realm_id"] = json!(genesis.realm_id);
        actor = serde_json::from_value(actor_json).unwrap();
        let stream = CommitStreamRef::RealmControl {
            realm_id: genesis.realm_id.clone(),
        };
        // These signed coordinates model an authority's exact private read.
        // Source existence is the Station's obligation; the host must still
        // reject contradictions between independently authenticated reads.
        let before = CommittedEventRef {
            event_id: EventId::from_digest(crate::PRODUCER_DIGEST_SUITE, [0x41; 32]),
            commit_id: RealmCommitId::from_digest([0x42; 32]),
            stream_ref: stream.clone(),
            stream_position: 4,
        };
        let mut transcript = kat["cases"][4]["unsigned_projection"].clone();
        transcript["service_id"] = json!(station.service_id);
        let payload = &mut transcript["payload_without_control_signature"];
        payload["target_actor_id"] = json!(actor);
        payload["manager_ref"] = json!(before);
        payload["recovery_ref"] = json!(before);
        for field in [
            "expected_control_commit_id",
            "expected_owner_status_commit_id",
            "expected_governance_status_commit_id",
            "expected_device_generation_commit_id",
        ] {
            payload[field] = json!(before.commit_id);
        }
        let signature = sign_detached_object(
            &transcript,
            DetachedSignatureContext::RealmActorRecoveryAcceptance,
            serde_json::from_value(kat["cases"][4]["signature"]["verification_method"].clone())
                .unwrap(),
            at,
            &seed(&kat["cases"][4]["test_seed_hex"]),
        )
        .unwrap();
        let mut payload = transcript["payload_without_control_signature"].clone();
        payload["control_signature"] = json!(signature);
        let payload: arkret::RealmActorRecoveryBeginPayload =
            serde_json::from_value(payload).unwrap();
        let applet: AppletId =
            serde_json::from_value(kat["cases"][0]["candidate"]["applet_id"].clone()).unwrap();
        let mut begin = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorRecoveryBegin,
        >::new(
            ScopeRef::RealmControl {
                realm_id: genesis.realm_id.clone(),
            },
            ActorId::service(station.service_id.clone()),
            payload,
        )
        .unwrap()
        .with_applet_id(applet.clone())
        .into_intent(at)
        .unwrap()
        .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)
        .unwrap();
        let signer = arkret::Ed25519PayloadSigner::new(
            station.signing_key.clone(),
            arkret::verification_method_did(station.verification_method.as_str()).unwrap(),
            station.verification_method.clone(),
        );
        sign_event(
            &mut begin,
            &signer,
            SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        begin.verify_identity().unwrap();
        let source_revisions = super::super::recovery_read_selectors(&actor)
            .into_iter()
            .map(|selector| {
                (
                    selector,
                    CurrentRevision {
                        commit_id: before.commit_id.clone(),
                        stream_position: before.stream_position,
                    },
                )
            })
            .collect::<Vec<_>>();
        let publication =
            serde_json::from_value(kat["cases"][0]["candidate"]["method_history_evidence"].clone())
                .unwrap();
        let prepared = PreparedRecovery {
            operation_id: "closure-regression".into(),
            actor_id: actor.clone(),
            begin,
            source_revisions,
            next_root_seed: arkret::base64url_encode([0x43; 32]),
            controller_seed: arkret::base64url_encode([0x44; 32]),
            publication,
            begin_receipt: None,
            reset: None,
            reset_receipt: None,
            terminal: None,
            terminal_material: None,
            unaccepted_proof: None,
        };
        let mut control_transcript = kat["cases"][1]["unsigned_projection"].clone();
        control_transcript["actor_id"] = json!(actor);
        control_transcript["expected_commit_id"] = json!(before.commit_id);
        let next_signature = sign_detached_object(
            &control_transcript,
            DetachedSignatureContext::RealmActorControlAcceptance,
            serde_json::from_value(kat["cases"][1]["signature"]["verification_method"].clone())
                .unwrap(),
            at,
            &seed(&kat["cases"][1]["test_seed_hex"]),
        )
        .unwrap();
        control_transcript
            .as_object_mut()
            .unwrap()
            .remove("actor_id");
        control_transcript["next_method_signature"] = json!(next_signature);
        let control_payload: arkret::RealmActorControlUpdatePayload =
            serde_json::from_value(control_transcript).unwrap();
        let mut rotation_event = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorControlUpdate,
        >::new(
            ScopeRef::RealmControl {
                realm_id: genesis.realm_id.clone(),
            },
            actor.clone(),
            control_payload,
        )
        .unwrap()
        .with_applet_id(applet)
        .into_intent(at)
        .unwrap()
        .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)
        .unwrap();
        let old_control = &kat["cases"][0]["candidate"];
        let control_signer = arkret::Ed25519PayloadSigner::new(
            seed(&kat["cases"][0]["test_seed_hex"]),
            serde_json::from_value(old_control["initial_resolution"]["did"].clone()).unwrap(),
            serde_json::from_value(old_control["control_method_kid"].clone()).unwrap(),
        );
        sign_event(
            &mut rotation_event,
            &control_signer,
            SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let control = json!({
            "resolution": {
                "did":old_control["initial_resolution"]["did"],
                "method_history_head":old_control["initial_resolution"]["method_history_head"],
                "version_id":old_control["initial_resolution"]["version_id"],
                "resolution_event_ref":before.event_id,
                "updated_at":arkret_canonical::format_timestamp_canonical(at)
            },
            "control_method_kid":old_control["control_method_kid"]
        });
        let rotation = super::super::super::PreparedControlRotation {
            operation_id: "rotation-closure-regression".into(),
            actor_id: actor.clone(),
            previous_control: serde_json::from_value(control.clone()).unwrap(),
            previous_reference: before.clone(),
            event: rotation_event,
            outcome: None,
            closure: None,
        };
        let values = [
            control,
            json!({"service_id":station.service_id,"registration_ref":before.event_id,"binding_ref":before}),
            json!({"kind":"manager_native","enabled":true,"pending":null,
                "content_backup_recipient":old_control["recovery"]["content_backup_recipient"],
                "content_backup_recipient_ref":before}),
            json!({"current_device_generation_ref":1}),
            json!("active"),
            json!("active"),
        ];
        let entries = prepared
            .source_revisions
            .iter()
            .zip(values)
            .map(|((selector, revision), value)| {
                json!({"status":"present","current_state":{
                    "selector":selector,"source_stream_ref":stream,"revision":revision,"value":value
                },"source_ref":before})
            })
            .collect::<Vec<_>>();
        let current = serde_json::from_value(json!({
            "realm_id":genesis.realm_id,"actor_id":actor,"purpose":"current",
            "request_digest":Hash::new(canonical_sha256(&entries).unwrap()).unwrap(),
            "request_nonce":"BBBBBBBBBBBBBBBBBBBBBB",
            "requester_actor_id":ActorId::service(station.service_id.clone()),
            "governance_generation":"0","authority_ref":genesis.event_id,
            "control_stream_head":{"stream_ref":stream,"commit_id":RealmCommitId::from_digest([0x45;32]),"stream_position":10},
            "issued_at":arkret_canonical::format_timestamp_canonical(at),
            "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::seconds(60)),
            "material":{"entries":entries},"signature":bundle.current_assertion.signature
        }))
        .unwrap();
        let mut fixture = Self {
            station,
            authority,
            keys,
            prepared,
            rotation,
            current,
        };
        let witnessed = fixture.verify(fixture.current.clone());
        fixture.prepared.source_revisions =
            super::super::recovery_read_selectors(&fixture.prepared.actor_id)
                .into_iter()
                .map(|selector| {
                    let (revision, ..) = row(witnessed.material(), &selector).unwrap();
                    (selector, revision.clone())
                })
                .collect();
        fixture
    }

    fn verify(&self, mut material: RealmActorMaterialResponseBody) -> VerifiedRealmActorMaterial {
        let request = match &material.material {
            RealmActorMaterial::Current { entries, .. } => RealmActorMaterialRequestBody::Current {
                actor_id: material.actor_id.clone(),
                request_nonce: material.request_nonce.clone(),
                selectors: entries
                    .iter()
                    .map(|entry| match entry {
                        RealmActorMaterialCurrentEntry::Present {
                            current_state: CurrentState::Value { selector, .. },
                            ..
                        }
                        | RealmActorMaterialCurrentEntry::NeverWritten { selector } => {
                            selector.clone()
                        }
                    })
                    .collect(),
            },
            RealmActorMaterial::RequestStatus {
                target_request_digest,
                ..
            } => RealmActorMaterialRequestBody::RequestStatus {
                actor_id: material.actor_id.clone(),
                request_nonce: material.request_nonce.clone(),
                target_request_digest: target_request_digest.clone(),
            },
            _ => panic!("closure tests require current or exact outcome"),
        };
        material.request_digest = Hash::new(canonical_sha256(&request).unwrap()).unwrap();
        material.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&material, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmActorMaterial,
            self.station.verification_method.clone(),
            material.issued_at,
            &self.station.signing_key,
        )
        .unwrap();
        let now = material.issued_at;
        verify_realm_actor_material(
            material,
            &request,
            &ActorId::service(self.station.service_id.clone()),
            &self.authority,
            &self.station.resolution,
            &self.keys,
            now,
        )
        .unwrap()
    }

    fn outcome(
        &self,
        current: &RealmActorMaterialResponseBody,
        rotation: bool,
    ) -> RealmActorMaterialResponseBody {
        let event = if rotation {
            &self.rotation.event
        } else {
            &self.prepared.begin
        };
        let request =
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
                arkret::EventAdmissionSubmission::new(event.event().clone()),
            );
        let mut outcome = current.clone();
        outcome.purpose = arkret_models_integration::RealmActorMaterialPurpose::RequestStatus;
        outcome.request_nonce = "CCCCCCCCCCCCCCCCCCCCCC".into();
        outcome.material = RealmActorMaterial::RequestStatus {
            target_request_digest: Hash::new(canonical_sha256(&request).unwrap()).unwrap(),
            request_status: arkret::RealmActorRequestStatus::Status {
                status: arkret::RealmActorOperationStatus::Unknown,
            },
        };
        outcome
    }

    fn check(&self, current: RealmActorMaterialResponseBody, rotation: bool) -> Result<()> {
        let outcome = self.outcome(&current, rotation);
        self.check_pair(current, outcome, rotation)
    }

    fn check_pair(
        &self,
        current: RealmActorMaterialResponseBody,
        outcome: RealmActorMaterialResponseBody,
        rotation: bool,
    ) -> Result<()> {
        let current = self.verify(current);
        let outcome = self.verify(outcome);
        if rotation {
            super::super::super::unaccepted::validate_closure(
                &self.rotation,
                current.material(),
                outcome.material(),
                &self.station.service_id,
            )
        } else {
            validate_closure(
                &self.prepared,
                current.material(),
                outcome.material(),
                &self.station.service_id,
            )
        }
    }
}

fn with_revision(
    current: &RealmActorMaterialResponseBody,
    commit_id: RealmCommitId,
    position: u64,
) -> RealmActorMaterialResponseBody {
    let mut value = serde_json::to_value(current).unwrap();
    let row = &mut value["material"]["entries"][0];
    row["current_state"]["revision"] = json!({"commit_id":commit_id,"stream_position":position});
    row["source_ref"]["commit_id"] = json!(commit_id);
    row["source_ref"]["stream_position"] = json!(position);
    serde_json::from_value(value).unwrap()
}

#[test]
fn signed_same_commit_at_another_position_cannot_release_recovery_or_rotation() {
    let fixture = Fixture::new();
    let original = fixture.prepared.source_revisions[0].1.commit_id.clone();
    for position in [3, 5] {
        for rotation in [false, true] {
            assert!(
                fixture
                    .check(
                        with_revision(&fixture.current, original.clone(), position),
                        rotation
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn signed_fork_or_regression_cannot_release_recovery_or_rotation() {
    let fixture = Fixture::new();
    for position in [3, 4] {
        for rotation in [false, true] {
            assert!(
                fixture
                    .check(
                        with_revision(
                            &fixture.current,
                            RealmCommitId::from_digest([0x51; 32]),
                            position
                        ),
                        rotation
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn exact_unknown_without_a_changed_scalar_guard_preserves_both_originals() {
    let fixture = Fixture::new();
    for rotation in [false, true] {
        assert!(fixture.check(fixture.current.clone(), rotation).is_err());
    }
}

#[test]
fn changed_commit_at_a_later_position_with_subsequent_exact_unknown_closes_both() {
    let fixture = Fixture::new();
    let advanced = with_revision(&fixture.current, RealmCommitId::from_digest([0x52; 32]), 5);
    for rotation in [false, true] {
        fixture.check(advanced.clone(), rotation).unwrap();
    }
}

#[test]
fn conflicting_signed_head_coordinates_do_not_establish_a_subsequent_cut() {
    let fixture = Fixture::new();
    let advanced = with_revision(&fixture.current, RealmCommitId::from_digest([0x53; 32]), 5);
    for rotation in [false, true] {
        for position in [9, 11] {
            let mut outcome = fixture.outcome(&advanced, rotation);
            outcome
                .control_stream_head
                .as_mut()
                .unwrap()
                .stream_position = position;
            assert!(
                fixture
                    .check_pair(advanced.clone(), outcome, rotation)
                    .is_err()
            );
        }
        let mut fork = fixture.outcome(&advanced, rotation);
        fork.control_stream_head.as_mut().unwrap().commit_id =
            RealmCommitId::from_digest([0x54; 32]);
        assert!(
            fixture
                .check_pair(advanced.clone(), fork, rotation)
                .is_err()
        );
    }
}

#[test]
fn a_truly_subsequent_head_and_exact_replayed_outcome_keep_the_original_digest() {
    let fixture = Fixture::new();
    let advanced = with_revision(&fixture.current, RealmCommitId::from_digest([0x55; 32]), 5);
    for rotation in [false, true] {
        let mut outcome = fixture.outcome(&advanced, rotation);
        let head = outcome.control_stream_head.as_mut().unwrap();
        head.stream_position += 1;
        head.commit_id = RealmCommitId::from_digest([0x56; 32]);
        fixture
            .check_pair(advanced.clone(), outcome.clone(), rotation)
            .unwrap();
        fixture
            .check_pair(advanced.clone(), outcome, rotation)
            .unwrap();
        let mut wrong = fixture.outcome(&advanced, rotation);
        let RealmActorMaterial::RequestStatus {
            target_request_digest,
            ..
        } = &mut wrong.material
        else {
            unreachable!()
        };
        *target_request_digest = Hash::new(format!("sha256:{}", "77".repeat(32))).unwrap();
        assert!(
            fixture
                .check_pair(advanced.clone(), wrong, rotation)
                .is_err()
        );
    }
}

#[test]
fn a_missing_required_current_row_never_becomes_a_first_write() {
    let fixture = Fixture::new();
    let mut partial = with_revision(&fixture.current, RealmCommitId::from_digest([0x57; 32]), 5);
    let RealmActorMaterial::Current { entries, .. } = &mut partial.material else {
        unreachable!()
    };
    entries.remove(0);
    for rotation in [false, true] {
        assert!(fixture.check(partial.clone(), rotation).is_err());
    }
}
