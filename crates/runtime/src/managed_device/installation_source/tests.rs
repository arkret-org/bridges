//! Typed source selection/cut regressions; live installation admission remains
//! covered by the Coland HTTPS runtime drivers, not by this local fixture.
use arkret_models_collaboration::exact_current_results::{
    CapabilityGrantExactCurrentRow, CapabilityGrantExactCurrentSelector,
    CapabilityGrantExactCurrentSelectorKind,
};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use arkret_models_integration::{AppletInstallEffectiveStatus, AppletRegistrationEpochEvidence};
use arkret_test_kit::SignedEventFixtureBuilder;
use arkret_test_kit::authority_objects::signed_commit;
use serde_json::json;

use super::*;

fn fixture() -> (InstallationHint, AppletAuthorityMaterialOutcome) {
    let now: DateTime<Utc> = "2026-10-21T01:00:00.000Z".parse().unwrap();
    let applet: arkret::AppletId = "ak:applet:01964137-0000-7000-8000-000000000081"
        .parse()
        .unwrap();
    let root = arkret::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [31; 32]);
    let realm = arkret::RealmId::from_event_id(&root);
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let signer = arkret_test_kit::seeded_signer(
        "did:web:applet.example".parse().unwrap(),
        arkret::DidUrl::new("did:web:applet.example#admin").unwrap(),
    );
    let service = ActorId::service("ak:did_core:web:applet.example".parse().unwrap());
    let key = SigningKey::from_bytes(&[37; 32]);
    let method = arkret::DidUrl::new("did:web:station.example#authority").unwrap();
    let document = arkret::DidDocument::new(
        "did:key:z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT"
            .parse()
            .unwrap(),
        "key-1",
        "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
    );
    let evidence = AppletRegistrationEpochEvidence::from_did_document(
        &document,
        arkret_models_integration::AppletDidMethodVersionEvidence::versioned(
            "did:key",
            Some("immutable".into()),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let epoch: arkret::Hash = format!("sha256:{}", "4".repeat(64)).parse().unwrap();
    let payload = AppletRegistrationPayload {
        applet_id: applet.clone(),
        service_id: service.signing_principal_id().clone(),
        controller_principal_id: service.signing_principal_id().clone(),
        base_url: "https://applet.example".into(),
        claimed_profiles: vec![],
        protocols: vec![],
        namespaces: Default::default(),
        receive_events: false,
        receive_signals: false,
        rate_limited: false,
        requested_scopes: vec![],
        registration_epoch: epoch.clone(),
        webhook_auth: arkret_models_integration::WebhookAuth::http_message_signature(
            arkret::DidUrl::new("did:web:applet.example#admin").unwrap(),
            vec![arkret_models_integration::HttpMessageSignatureAlgorithm::Ed25519],
        ),
        manifest: arkret_models_integration::AppletRegistrationManifest {
            claimed_profiles: vec![],
            limits: Default::default(),
            ghost_policy: Default::default(),
            delegation_policy: Default::default(),
            e2ee_policy: Default::default(),
            widget: None,
            registration_epoch_evidence: evidence,
        },
        proof: arkret_models_integration::DetachedProof {
            kind: "detached_jws".into(),
            verification_method: arkret::DidUrl::new("did:web:applet.example#admin").unwrap(),
            payload_digest: epoch.clone(),
            created_at: now,
            domain: None,
            audience: None,
            jws: "fixture..fixture".into(),
            extra: Default::default(),
        },
        created_at: now,
    };
    let registration = SignedEventFixtureBuilder::new(
        "ak.applet.registration",
        scope.clone(),
        service.clone(),
        serde_json::to_value(payload).unwrap(),
    )
    .with_created_at(now)
    .sign_verifiable(&signer)
    .unwrap()
    .expect_verifiable();
    let registration_commit =
        signed_commit(&method, &key, &registration, 0, None, root.clone(), None).unwrap();
    // The source is a real typed installation grant, not a fabricated join action.
    let body = json!({
        "schema":"ak.schema.capability.v1", "realm_id":realm, "issuer_id":service, "subject":service,
        "actions":["ak.applet.bot.provision"], "resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[GrantConstraint::applet_authority(applet.clone(), service.clone(), epoch.clone())],
        "issued_at":arkret_canonical::format_timestamp_canonical(now),
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":root,"authority_generation":0}],
    });
    let grant = SignedEventFixtureBuilder::new(
        "ak.capability.grant",
        scope.clone(),
        service,
        json!({"grant":body}),
    )
    .with_created_at(now)
    .sign_verifiable(&signer)
    .unwrap()
    .expect_verifiable();
    let commit = signed_commit(
        &method,
        &key,
        &grant,
        1,
        Some(registration_commit.commit_id.clone()),
        root,
        None,
    )
    .unwrap();
    let id = arkret::GrantId::from_event_id(&grant.event_id);
    let mut value = body;
    value["id"] = json!(id);
    value["status"] = json!("active");
    value["authority_depth"] = json!(1);
    value["authority_root_refs"] = value["issuer_authority_refs"].clone();
    let row = ExactCurrentResultsReadOutcome::Present {
        realm_id: realm,
        governance_generation: 0,
        effective_stream_head: arkret::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: 1,
            commit_id: commit.commit_id.clone(),
        },
        entry: ExactCurrentResultEntry::CapabilityGrant(CapabilityGrantExactCurrentRow {
            selector: CapabilityGrantExactCurrentSelector {
                kind: CapabilityGrantExactCurrentSelectorKind::CapabilityGrant,
                grant_id: id.clone(),
            },
            source_stream_ref: commit.stream_ref.clone(),
            revision: arkret::CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: 1,
            },
            value: serde_json::from_value(value).unwrap(),
        }),
    };
    let hint = InstallationHint {
        effective_scope: scope.clone(),
        outcome: AppletInstallOutcome {
            install_id: "actual-install-result".into(),
            applet_id: applet.clone(),
            registration_event_ref: registration.event_id.clone(),
            registration_epoch: epoch.clone(),
            capability_grant_refs: vec![id],
            e2ee_authorization_refs: vec![],
            widget_policy_ref: None,
            effective_status: AppletInstallEffectiveStatus::Installed,
            rejections: vec![],
        },
    };
    let material = AppletAuthorityMaterialOutcome {
        applet_id: applet,
        effective_scope: scope,
        current_binding: AppletInstallationCurrentBinding::Active {
            registration_ref: arkret::CommittedEventRef {
                event_id: registration.event_id.clone(),
                commit_id: registration_commit.commit_id.clone(),
                stream_ref: registration_commit.stream_ref.clone(),
                stream_position: 0,
            },
            registration_epoch: epoch,
            service_id: "ak:did_core:web:applet.example".parse().unwrap(),
        },
        registration:
            arkret_models_collaboration::applet_installation_authority::AppletCommittedEvent {
                event: registration,
                commit: registration_commit,
                producer_device_evidence: None,
            },
        grant_events: vec![
            arkret_models_collaboration::applet_installation_authority::AppletCommittedEvent {
                event: grant,
                commit,
                producer_device_evidence: None,
            },
        ],
        current_results: vec![row],
    };
    (hint, material)
}

#[test]
fn same_scope_source_ignores_a_business_parent_that_sorts_first() {
    let (hint, material) = fixture();
    let source = &hint.outcome.capability_grant_refs[0];
    let competing = (0..=255)
        .map(|byte| {
            arkret::GrantId::from_event_id(&arkret::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [byte; 32],
            ))
        })
        .find(|candidate| candidate < source)
        .unwrap();
    let mut effective_ids = vec![source.clone(), competing.clone()];
    effective_ids.sort();
    assert_eq!(
        effective_ids[0], competing,
        "the former first-match path chooses a non-install parent"
    );
    for _ in 0..2 {
        let (request, registration) = source_request(
            hint.outcome.applet_id.as_str(),
            &hint.effective_scope,
            &hint.effective_scope,
            source,
            None,
        )
        .unwrap();
        assert_eq!(request.grant_ids, vec![source.clone()]);
        assert!(registration.is_none());
        assert_eq!(
            source_grant(
                &hint.outcome.applet_id,
                &"ak:did_core:web:applet.example".parse().unwrap(),
                &request,
                &material,
                None
            )
            .unwrap()
            .id,
            *source
        );
        effective_ids.reverse();
    }
}

#[test]
fn another_scope_requires_the_exact_typed_install_outcome() {
    let (mut hint, _) = fixture();
    let creation_scope = ScopeRef::Circle {
        realm_id: hint.effective_scope.realm_id().clone(),
        circle_id: arkret::CircleId::from_event_id(&arkret::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [51; 32],
        )),
    };
    let source = hint.outcome.capability_grant_refs[0].clone();
    let applet = hint.outcome.applet_id.clone();
    assert!(
        source_request(
            applet.as_str(),
            &hint.effective_scope,
            &creation_scope,
            &source,
            None
        )
        .is_err()
    );
    let (request, registration) = source_request(
        applet.as_str(),
        &hint.effective_scope,
        &creation_scope,
        &source,
        Some(&hint),
    )
    .unwrap();
    assert_eq!(request.grant_ids, hint.outcome.capability_grant_refs);
    assert_eq!(
        registration,
        Some((
            hint.outcome.registration_event_ref.clone(),
            hint.outcome.registration_epoch.clone()
        ))
    );
    let scope = hint.effective_scope.clone();
    hint.effective_scope = creation_scope.clone();
    assert!(
        source_request(
            applet.as_str(),
            &scope,
            &creation_scope,
            &source,
            Some(&hint)
        )
        .is_err()
    );
    hint.effective_scope = scope.clone();
    hint.outcome.capability_grant_refs.clear();
    assert!(
        source_request(
            applet.as_str(),
            &scope,
            &creation_scope,
            &source,
            Some(&hint)
        )
        .is_err()
    );
}

#[test]
fn inactive_missing_wrong_scope_epoch_or_service_material_fails_closed() {
    let (hint, material) = fixture();
    let request = AppletAuthorityMaterialRequestBody {
        effective_scope: hint.effective_scope.clone(),
        grant_ids: hint.outcome.capability_grant_refs.clone(),
    };
    let service = "ak:did_core:web:applet.example".parse().unwrap();
    let verify = |candidate: &AppletAuthorityMaterialOutcome, epoch: &arkret::Hash| {
        source_grant(
            &hint.outcome.applet_id,
            &service,
            &request,
            candidate,
            Some((&hint.outcome.registration_event_ref, epoch)),
        )
    };
    assert!(verify(&material, &hint.outcome.registration_epoch).is_ok());
    let wrong_epoch = format!("sha256:{}", "5".repeat(64)).parse().unwrap();
    assert!(verify(&material, &wrong_epoch).is_err());
    for mutation in 0..5 {
        let mut changed = material.clone();
        match mutation {
            0 => changed.current_binding = AppletInstallationCurrentBinding::Inactive,
            1 => changed.grant_events.clear(),
            2 => changed.current_results.clear(),
            3 => {
                changed.effective_scope = ScopeRef::Realm {
                    realm_id: arkret::RealmId::from_event_id(&arkret::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [52; 32],
                    )),
                }
            }
            _ => {
                if let AppletInstallationCurrentBinding::Active { service_id, .. } =
                    &mut changed.current_binding
                {
                    *service_id = "ak:did_core:web:foreign.example".parse().unwrap();
                }
            }
        }
        assert!(
            verify(&changed, &hint.outcome.registration_epoch).is_err(),
            "mutation {mutation}"
        );
    }
}
