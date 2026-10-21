//! Durable Applet-side configuration execution. Governance acceptance stays
//! with the governing Station; this journal never manufactures a Commit.
use std::sync::Arc;

use arkret::signatures::Ed25519DetachedJwsVerifier;
use arkret::{ActorId, AppletManagedActorAuthoringRequest, CommittedEventRef};
use arkret_models_integration::{
    AppletConfigurationCommand as Command, AppletConfigurationExecutionIntent as Intent,
    AppletConfigurationExecutionOutcome as Outcome, AppletConfigurationExecutionRequest as Request,
    AppletConfigurationExecutionStatus as Status, AppletConfigurationSelection as Selection,
    AppletConfigurationSignature,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::managed_actor_authoring::ManagedActorAuthoringService;
use crate::realm_governance::{RealmRoute, invalid};
use crate::{ArkretEdge, AuthoringStore, Result};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Execution {
    intent: Intent,
    started: bool,
    preview: Option<AppletManagedActorAuthoringRequest>,
    review_request_id: arkret_wire::RequestId,
    outcome: Outcome,
}

/// Shared by standalone bridges and agent hosts. Every returned result is
/// durably retained, including its original signature and evaluation time.
pub struct AppletConfigurationService {
    edge: Arc<ArkretEdge>,
    authoring: ManagedActorAuthoringService,
    store: Arc<dyn AuthoringStore>,
    recovery_cursor: std::sync::atomic::AtomicUsize,
}

fn storage_key(intent: &Intent) -> Result<String> {
    Ok(format!(
        "applet-configuration/v1/{}",
        arkret::canonical::canonical_sha256(&(
            &intent.applet_id,
            intent.effective_scope.realm_id(),
            &intent.request_id,
        ))?
    ))
}

fn author_request_id(intent: &Intent) -> Result<String> {
    // The public configuration RequestId and the native authoring opaque id
    // have different formats. Domain separation also prevents accidental reuse
    // by an independent automatic-provisioning caller.
    let digest =
        arkret::canonical::canonical_sha256(&("ak.applet.configuration.authoring.v1", intent))?;
    Ok(digest
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("configuration digest has an unexpected suite"))?
        .to_owned())
}

impl AppletConfigurationService {
    pub fn new(edge: Arc<ArkretEdge>) -> Result<Self> {
        Ok(Self {
            authoring: ManagedActorAuthoringService::new(edge.clone())?,
            store: edge.authoring_store(),
            edge,
            recovery_cursor: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Recover acceptance independently of the administrator's response. The
    /// candidate remains immutable; only verified original Commit material can
    /// install custody and make the subject available to Device workers.
    pub async fn recover_accepted_configurations(&self) -> Result<usize> {
        use std::sync::atomic::Ordering;
        let entries = self.store.entries_with_prefix("applet-configuration/v1/")?;
        if entries.is_empty() {
            return Ok(0);
        }
        let start = self.recovery_cursor.load(Ordering::Relaxed) % entries.len();
        let mut attempted = 0;
        let mut installed = 0;
        for offset in 0..entries.len() {
            let index = (start + offset) % entries.len();
            self.recovery_cursor
                .store((index + 1) % entries.len(), Ordering::Relaxed);
            let (key, raw) = &entries[index];
            let record: Execution = self.authoring.decrypt_key_material(key, raw)?;
            if record.outcome.status != Status::Candidate {
                continue;
            }
            record.outcome.validate_for(&record.intent)?;
            let event = record
                .outcome
                .create_event
                .as_deref()
                .ok_or_else(|| invalid("configuration candidate is missing"))?;
            let actor = crate::managed_authoring::creation_payload(event)?.actor_id;
            if self
                .edge
                .installed_managed_authoring(&record.intent.effective_scope, &actor)?
                .is_some()
            {
                continue;
            }
            match self.recover_candidate(&record.intent, event).await {
                Ok(()) => installed += 1,
                Err(error) => tracing::debug!(%error, request_id = %record.intent.request_id,
                    "configuration acceptance is not yet available"),
            }
            attempted += 1;
            if attempted == 16 {
                break;
            }
        }
        Ok(installed)
    }

    async fn recover_candidate(&self, intent: &Intent, event: &arkret::Event) -> Result<()> {
        let candidate = crate::managed_authoring::creation_payload(event)?;
        let route = self
            .edge
            .realm_route(intent.effective_scope.realm_id())
            .await?;
        let requester = ActorId::service(intent.service_id.clone());
        let selector = arkret::CurrentSelector::RealmActorIdentity {
            actor_id: candidate.actor_id.clone(),
        };
        let current = route
            .material(
                &arkret::RealmActorMaterialRequest::Current {
                    actor_id: candidate.actor_id.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    selectors: vec![selector.clone()],
                },
                &requester,
            )
            .await?;
        let arkret::RealmActorMaterialResult::Current { entries } = &current.material().result
        else {
            return Err(invalid("configuration identity current is unavailable"));
        };
        let target = entries
            .iter()
            .find_map(|entry| match entry {
                arkret::RealmActorMaterialCurrentEntry::Present {
                    row:
                        arkret::TypedCurrentRow::Value {
                            selector: found,
                            source_stream_ref,
                            revision,
                            ..
                        },
                } if found == &selector => Some(CommittedEventRef {
                    event_id: event.event_id.clone(),
                    commit_id: revision.commit_id.clone(),
                    stream_ref: source_stream_ref.clone(),
                    stream_position: revision.stream_position,
                }),
                _ => None,
            })
            .ok_or_else(|| invalid("configuration identity has not been accepted"))?;
        let original = route
            .material(
                &arkret::RealmActorMaterialRequest::Event {
                    actor_id: candidate.actor_id,
                    request_nonce: crate::realm_governance::nonce()?,
                    target,
                },
                &requester,
            )
            .await?;
        let arkret::RealmActorMaterialResult::Event {
            event: accepted, ..
        } = &original.material().result
        else {
            return Err(invalid("configuration original creation is unavailable"));
        };
        if accepted != event {
            return Err(invalid(
                "configuration original differs from the frozen candidate",
            ));
        }
        self.edge
            .install_managed_authoring_completion(&arkret::AppletAuthoringTransactionRequestBody {
                applet_id: intent.applet_id.clone(),
                source_id: route.authority.current_service_id().clone(),
                authoring_context: arkret::AppletManagedActorAuthoringContext {
                    material: original.into_material(),
                },
            })
            .await?;
        Ok(())
    }

    pub(crate) async fn verify_request(&self, request: &Request) -> Result<RealmRoute> {
        request.validate_at(Utc::now())?;
        if request.intent.applet_id.as_str() != self.edge.config().arkret.applet_id
            || &request.intent.service_id != self.edge.service_actor_id()
        {
            return Err(invalid("configuration targets another Applet Service"));
        }
        let route = self
            .edge
            .realm_route(request.intent.effective_scope.realm_id())
            .await?;
        if route.authority.current_service_id() != &request.governance_station_id
            || route.authority.current_generation() != request.governance_generation
            || route
                .authority
                .authority_service_at(request.intent.governance_generation)
                != Some(&request.intent.governance_station_id)
        {
            return Err(invalid(
                "configuration is not on the verified governance chain",
            ));
        }
        let key = route.station_key(&request.proof.verification_method, request.issued_at)?;
        Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(&request.proof.jws, &request.signature_payload()?, &key)
            .map_err(invalid)?;
        Ok(route)
    }

    /// Hosts must also authenticate the registered S2S transport. The signed
    /// inner command is verified here even for an exact stored-result replay.
    pub async fn execute(&self, request: &Request) -> Result<Outcome> {
        let route = self.verify_request(request).await?;
        let key = storage_key(&request.intent)?;
        loop {
            let (raw, mut record) = self.load_or_create(&key, &request.intent)?;
            if record.outcome.status != Status::Pending {
                // Candidate means only that authoring completed. Cancellation
                // after it was released is settled by the Station's atomic
                // candidate/admission ledger, not by pretending to undo it here.
                if request.command != Command::Cancel {
                    self.ensure_review(&route, &record).await?;
                }
                return Ok(record.outcome);
            }
            if request.command == Command::Recover && !record.started {
                return Ok(record.outcome);
            }
            if request.command == Command::Cancel {
                record.outcome = self.outcome(&record.intent, Status::Cancelled)?;
                if self.replace(&key, &raw, &record)? {
                    return Ok(record.outcome);
                }
                continue;
            }
            if !record.started {
                record.started = true;
                self.replace(&key, &raw, &record)?;
                continue;
            }
            match &record.intent.selection {
                Selection::NewBot { display_name } => {
                    if record.preview.is_none() {
                        let preview = route
                            .client
                            .applet_bot_preview(
                                record.intent.applet_id.as_str(),
                                &arkret::AppletBotPreviewRequestBody {
                                    effective_scope: record.intent.effective_scope.clone(),
                                    request_id: author_request_id(&record.intent)?,
                                    display_name: display_name.clone(),
                                },
                            )
                            .await?
                            .authoring_request;
                        Self::check_preview(&record.intent, &preview)?;
                        record.preview = Some(preview);
                        // Freeze the exact signed preview before generating keys.
                        // Concurrent requests must recover this winner's preview.
                        self.replace(&key, &raw, &record)?;
                        continue;
                    }
                    let preview = record.preview.as_ref().expect("checked preview");
                    Self::check_preview(&record.intent, preview)?;
                    let event = self.authoring.author(preview).await?;
                    record.outcome = self.outcome(&record.intent, Status::Candidate)?;
                    record.outcome.create_event = Some(Box::new(event));
                    record.outcome.sign(self.edge.signer())?;
                }
                Selection::ExistingRealmActor { actor_id } => {
                    let reference = self.existing(&route, &record.intent, actor_id).await?;
                    record.outcome = self.outcome(&record.intent, Status::Reused)?;
                    record.outcome.actor_id = Some(actor_id.clone());
                    record.outcome.creation_refs = Some(vec![reference]);
                    record.outcome.sign(self.edge.signer())?;
                }
            }
            record.outcome.validate_for(&record.intent)?;
            if self.replace(&key, &raw, &record)? {
                self.ensure_review(&route, &record).await?;
                return Ok(record.outcome);
            }
            // Cancellation or a concurrent execution won while authoring.
            // Never release an unrecorded candidate after that CAS failed.
        }
    }

    /// Only the actual Applet Service asks for review. The private reference
    /// binds its exact original candidate to the administrator's frozen intent.
    async fn ensure_review(&self, route: &RealmRoute, record: &Execution) -> Result<()> {
        if record.outcome.status != Status::Candidate {
            return Ok(());
        }
        let event = record
            .outcome
            .create_event
            .as_ref()
            .ok_or_else(|| invalid("configuration candidate absent"))?;
        let request = arkret_models_integration::ManagementReviewRequestBody {
            request_id: record.review_request_id.to_string(),
            effective_scope: record.intent.effective_scope.clone(),
            management_operation: arkret_wire::ManagementOperation::CreateBot,
            requester_actor_id: ActorId::service(record.intent.service_id.clone()),
            target: arkret_models_integration::ManagementReviewTarget::Event {
                event: event.clone(),
            },
            configuration_ref: Some(
                arkret_models_integration::management_review::AppletConfigurationRef {
                    request_id: record.intent.request_id.clone(),
                    intent_digest: record.intent.digest()?,
                },
            ),
        };
        match route.client.management_review_request(&request).await {
            Ok(outcome)
                if outcome.request_id == request.request_id
                    && outcome.target_digest == request.target.canonical_target_digest()? =>
            {
                Ok(())
            }
            Ok(_) => Err(invalid(
                "configuration review response differs from the original candidate",
            )),
            // No review is created when Policy permits direct admission. The
            // governor still independently checks the candidate and Policy.
            Err(error)
                if error.error_code() == Some(arkret_wire::ErrorCode::FailedPrecondition) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn check_preview(intent: &Intent, preview: &AppletManagedActorAuthoringRequest) -> Result<()> {
        preview.validate_bindings()?;
        let arkret::AppletManagedActorAuthoringBasis::ProvisionBot(basis) = &preview.basis else {
            return Err(invalid("configuration preview is not a Bot request"));
        };
        let Selection::NewBot { display_name } = &intent.selection else {
            return Err(invalid("existing identity must not enter authoring"));
        };
        if basis.applet_id != intent.applet_id
            || basis.service_id != intent.service_id
            || basis.effective_scope != intent.effective_scope
            || basis.request_id != author_request_id(intent)?
            || &basis.display_name != display_name
            || basis.registration_event_ref != intent.registration_ref.event_id
        {
            return Err(invalid(
                "configuration preview differs from the original intent",
            ));
        }
        Ok(())
    }

    async fn existing(
        &self,
        route: &RealmRoute,
        intent: &Intent,
        actor: &ActorId,
    ) -> Result<CommittedEventRef> {
        let original = self.authoring.original_managed_controller(actor).await?;
        let event = crate::managed_authoring::creation_event(&original.original)?;
        let candidate = crate::managed_authoring::creation_payload(event)?;
        if candidate.applet_id != intent.applet_id || candidate.actor_id != *actor {
            return Err(invalid("selected identity belongs to another Applet"));
        }
        let selector = arkret::CurrentSelector::RealmActorManager {
            actor_id: actor.clone(),
        };
        let material = route
            .material(
                &arkret::RealmActorMaterialRequest::Current {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    selectors: vec![selector.clone()],
                },
                &ActorId::service(intent.service_id.clone()),
            )
            .await?;
        let arkret::RealmActorMaterialResult::Current { entries } = &material.material().result
        else {
            return Err(invalid("selected identity manager result is unavailable"));
        };
        let manager = entries
            .iter()
            .find_map(|entry| match entry {
                arkret::RealmActorMaterialCurrentEntry::Present {
                    row:
                        arkret::TypedCurrentRow::Value {
                            selector: found,
                            value,
                            ..
                        },
                } if found == &selector => Some(value.clone()),
                _ => None,
            })
            .ok_or_else(|| invalid("selected identity has no current manager"))?;
        let manager: arkret::RealmActorManagerValue = serde_json::from_value(manager)?;
        if manager.service_id != intent.service_id
            || manager.registration_ref != intent.registration_ref.event_id
        {
            return Err(invalid(
                "selected identity is not currently managed by this registration",
            ));
        }
        let arkret::RealmActorMaterialResult::Event { commit, .. } =
            &original.original.authoring_context.material.result
        else {
            return Err(invalid(
                "selected identity has no retained original creation",
            ));
        };
        Ok(CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
        })
    }

    fn outcome(&self, intent: &Intent, status: Status) -> Result<Outcome> {
        let mut outcome = Outcome {
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest()?,
            service_id: intent.service_id.clone(),
            status,
            actor_id: None,
            creation_refs: None,
            evaluated_at: arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            proof: AppletConfigurationSignature {
                verification_method: self.edge.service_verification_method()?,
                jws: String::new(),
            },
            create_event: None,
        };
        outcome.sign(self.edge.signer())?;
        Ok(outcome)
    }

    fn load_or_create(&self, key: &str, intent: &Intent) -> Result<(String, Execution)> {
        loop {
            if let Some(raw) = self.store.load(key)? {
                let record: Execution = self.authoring.decrypt_key_material(key, &raw)?;
                if record.intent != *intent {
                    return Err(invalid("duplicate_conflict: configuration intent changed"));
                }
                record.outcome.validate_for(intent)?;
                if let Some(preview) = &record.preview {
                    Self::check_preview(intent, preview)?;
                }
                return Ok((raw, record));
            }
            let record = Execution {
                intent: intent.clone(),
                started: false,
                preview: None,
                review_request_id: arkret_wire::new_prefixed_uuid7("ak:request:")
                    .parse()
                    .map_err(invalid)?,
                outcome: self.outcome(intent, Status::Pending)?,
            };
            let raw = self.authoring.encrypt_key_material(key, &record)?;
            if self.store.compare_exchange_batch(
                &[(key.to_owned(), None)],
                &[(key.to_owned(), Some(raw.clone()))],
            )? {
                return Ok((raw, record));
            }
        }
    }

    fn replace(&self, key: &str, expected: &str, record: &Execution) -> Result<bool> {
        record.outcome.validate_for(&record.intent)?;
        let raw = self.authoring.encrypt_key_material(key, record)?;
        self.store.compare_exchange_batch(
            &[(key.to_owned(), Some(expected.to_owned()))],
            &[(key.to_owned(), Some(raw))],
        )
    }
}

#[cfg(test)]
mod tests {
    use arkret::{Did, EventId, RealmId};
    use serde_json::json;

    use super::*;

    fn edge(store: Arc<dyn AuthoringStore>) -> Arc<ArkretEdge> {
        let config: crate::Config = serde_json::from_value(json!({
            "bridge": {"bridge_id": "configuration-test"},
            "arkret": {
                "server_url": "https://station.example",
                "applet_base_url": "https://applet.example",
                "service_did": "did:webvh:zservicescid:applet.example",
                "trust_domain": "ak:trust_domain:station.example",
                "applet_id": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb",
                "signing_key_seed_hex": "22".repeat(32),
                "verification_method_fragment": "#key-1",
                "trusted_server_did": "did:webvh:zstationscid:station.example",
                "applet_namespaces": {
                    "actors": [{"pattern": "did:webvh:*:applet.example:webvh:*", "exclusive": true}],
                    "realms": [], "handles": []
                },
                "managed_actor_authoring": {
                    "principal_endpoint": "https://applet.example/actors/test",
                    "key_encryption_key_hex": "33".repeat(32)
                }
            }
        }))
        .unwrap();
        let (sender, _) = tokio::sync::mpsc::channel(1);
        Arc::new(ArkretEdge::new(Arc::new(config), store, sender).unwrap())
    }

    fn intent() -> Intent {
        let core = |did: &str| arkret::project_did_to_core_id(&Did::new(did).unwrap()).unwrap();
        let event = EventId::from_digest(arkret::canonical::DigestSuite::Sha256, [1; 32]);
        let realm = RealmId::from_event_id(&event);
        serde_json::from_value(json!({
            "request_id": "ak:request:01904100-0000-7000-8000-bbbbbbbbbbbb",
            "applet_id": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb",
            "service_id": core("did:webvh:zservicescid:applet.example"),
            "governance_station_id": core("did:webvh:zstationscid:station.example"),
            "governance_generation": 0,
            "effective_scope": {"kind": "realm", "realm_id": realm},
            "registration_ref": {
                "event_id": event,
                "commit_id": arkret::RealmCommitId::from_digest([2; 32]),
                "stream_ref": {"kind": "realm", "realm_id": realm},
                "stream_position": 1
            },
            "registration_epoch": format!("sha256:{}", "03".repeat(32)),
            "originating_actor_id": ActorId::account(arkret::AccountId {
                principal_id: core("did:webvh:zuserscid:user.example"),
                station_id: core("did:webvh:zstationscid:station.example"),
            }),
            "selection": {"kind": "new_bot", "display_name": "Configured Bot"}
        }))
        .unwrap()
    }

    struct DatabaseFile(std::path::PathBuf);
    impl DatabaseFile {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "arkret-configuration-{}.redb",
                crate::realm_governance::nonce().unwrap()
            )))
        }
        fn open(&self) -> Arc<dyn AuthoringStore> {
            Arc::new(crate::FileAuthoringStore::new(self.0.clone()).unwrap())
        }
    }
    impl Drop for DatabaseFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[cfg(feature = "web")]
    #[tokio::test]
    async fn production_managed_host_exposes_public_role_description() {
        use salvo::test::{ResponseExt, TestClient};
        let file = DatabaseFile::new();
        let template = edge(file.open());
        assert!(crate::web::managed_applet_router(template.clone()).is_err());
        let now = chrono::Utc::now();
        let mut identity = arkret_test_kit::service_identity::ServiceIdentityFixture::webvh(
            &"https://applet.example/".parse().unwrap(),
            801,
            [0x22; 32],
            "key-1",
            now - chrono::Duration::minutes(1),
            now,
        )
        .unwrap();
        identity.resolution.service_kind = "applet_service".to_owned();
        let mut config = template.config().as_ref().clone();
        config.arkret.service_did = identity.resolution.normalized_did_document.id.clone();
        config.arkret.service_resolution = Some(identity.resolution.clone());
        crate::service_identity::validate(&config).unwrap();
        let mut wrong = config.clone();
        wrong.arkret.signing_key_seed_hex = "01".repeat(32);
        assert!(crate::service_identity::validate(&wrong).is_err());
        wrong = config.clone();
        wrong
            .arkret
            .service_resolution
            .as_mut()
            .unwrap()
            .service_kind = "station".into();
        assert!(crate::service_identity::validate(&wrong).is_err());
        wrong = config.clone();
        if let arkret::ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } = &mut wrong
            .arkret
            .service_resolution
            .as_mut()
            .unwrap()
            .method_history_evidence
        {
            log_entries[0]["state"]["id"] = json!("did:web:unrelated.example");
        }
        assert!(crate::service_identity::validate(&wrong).is_err());
        let (sender, _) = tokio::sync::mpsc::channel(1);
        let edge = Arc::new(ArkretEdge::new(Arc::new(config), file.open(), sender).unwrap());
        let embedded = crate::web::ManagedAppletHttpHost::new(edge.clone()).unwrap();
        let mut headers = salvo::http::HeaderMap::new();
        headers.insert(
            "arkret-operation",
            arkret::ServiceOperationId::SERVER_READ_DESCRIBE_V1
                .parse()
                .unwrap(),
        );
        let (status, returned_headers, bytes) = embedded
            .receive(
                salvo::http::Method::GET,
                "https://applet.example/_arkret/describe".parse().unwrap(),
                headers,
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(status, salvo::http::StatusCode::OK);
        assert_eq!(
            returned_headers["arkret-operation"],
            arkret::ServiceOperationId::SERVER_READ_DESCRIBE_V1
        );
        let embedded_description: arkret_models_discovery::ServiceDescribe =
            serde_json::from_slice(&bytes).unwrap();
        embedded_description.validate().unwrap();
        let (_, _, history) = embedded
            .receive(
                salvo::http::Method::GET,
                arkret::identity::DidWebvhResolver::log_url(
                    &identity.resolution.normalized_did_document.id,
                )
                .unwrap()
                .parse()
                .unwrap(),
                salvo::http::HeaderMap::new(),
                Vec::new(),
            )
            .await
            .unwrap();
        arkret::identity::verify_did_webvh_v1_chain_bytes(
            &identity.resolution.normalized_did_document.id,
            &history,
        )
        .unwrap();
        for path in ["configuration", "managed-actors/author", "transactions"] {
            let (status, _, bytes) = embedded
                .receive(
                    salvo::http::Method::POST,
                    format!("https://applet.example/_arkret/edge/applet/{path}")
                        .parse()
                        .unwrap(),
                    salvo::http::HeaderMap::new(),
                    b"not-json".to_vec(),
                )
                .await
                .unwrap();
            assert_eq!(status, salvo::http::StatusCode::BAD_REQUEST, "{path}");
            let problem: arkret::Problem = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(problem.code(), "operation_selector_required", "{path}");
        }
        let mut headers = salvo::http::HeaderMap::new();
        headers.insert(
            "arkret-operation",
            arkret::ServiceOperationId::EDGE_APPLET_CONFIGURATION_COMMAND_EXECUTE_V1
                .parse()
                .unwrap(),
        );
        let uri = "https://applet.example/_arkret/edge/applet/configuration"
            .parse::<salvo::http::uri::Uri>()
            .unwrap();
        // The framework default must not truncate a permitted operation body.
        let padded = format!("{{\"padding\":\"{}\"}}", "a".repeat(80_000)).into_bytes();
        let (status, _, bytes) = embedded
            .receive(
                salvo::http::Method::POST,
                uri.clone(),
                headers.clone(),
                padded,
            )
            .await
            .unwrap();
        assert_eq!(status, salvo::http::StatusCode::BAD_REQUEST);
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("Idempotency-Key")
        );
        let oversized = format!("{{\"padding\":\"{}\"}}", "a".repeat(262_144)).into_bytes();
        let (status, _, bytes) = embedded
            .receive(
                salvo::http::Method::POST,
                uri.clone(),
                headers.clone(),
                oversized,
            )
            .await
            .unwrap();
        assert_eq!(status, salvo::http::StatusCode::PAYLOAD_TOO_LARGE);
        let problem: arkret::Problem = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem.code(), "payload_too_large");
        let (status, _, bytes) = embedded
            .receive(
                salvo::http::Method::POST,
                uri.clone(),
                headers.clone(),
                br#"{"command":"configure","command":"recover"}"#.to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(status, salvo::http::StatusCode::BAD_REQUEST);
        let problem: arkret::Problem = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem.code(), "schema_violation");
        headers.insert("content-encoding", "identity".parse().unwrap());
        let (status, ..) = embedded
            .receive(salvo::http::Method::POST, uri, headers, b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(status, salvo::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let router = salvo::Service::new(crate::web::managed_applet_router(edge.clone()).unwrap());
        let mut response = TestClient::get("https://applet.example/_arkret/describe")
            .add_header(
                "arkret-operation",
                arkret::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
                true,
            )
            .send(&router)
            .await;
        assert_eq!(response.status_code, Some(salvo::http::StatusCode::OK));
        let description: arkret_models_discovery::ServiceDescribe =
            response.take_json().await.unwrap();
        description.validate().unwrap();
        assert_eq!(description.service_kind, arkret::ServiceKind::AppletService);
        assert!(description.supported_profiles.is_empty());
        assert_eq!(
            description.service_resolution,
            crate::service_identity::commitment(edge.config()).unwrap()
        );
        let value = serde_json::to_value(description).unwrap();
        assert!(
            value
                .to_string()
                .contains("ak.operation_bundle.applet_service.describe.v1")
        );
        assert!(!value.to_string().contains("signing_key_seed_hex"));
        let resolution_url = format!(
            "https://applet.example{}",
            arkret::canonical_service_resolution_path(&identity.service_id)
        );
        let mut response = TestClient::get(resolution_url.clone())
            .add_header(
                "arkret-operation",
                arkret::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
                true,
            )
            .send(&router)
            .await;
        assert_eq!(response.status_code, Some(salvo::http::StatusCode::OK));
        assert_eq!(
            response.headers().get("arkret-operation").unwrap(),
            arkret::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1
        );
        let published: arkret::AuthenticatedServiceResolution = response.take_json().await.unwrap();
        assert_eq!(json!(published), json!(identity.resolution));
        arkret::identity::verify_authenticated_service_resolution_history(
            &published,
            &identity.service_id,
            now,
        )
        .unwrap();
        let did = &identity.resolution.normalized_did_document.id;
        let mut response =
            TestClient::get(arkret::identity::DidWebvhResolver::log_url(did).unwrap())
                .send(&router)
                .await;
        assert_eq!(response.status_code, Some(salvo::http::StatusCode::OK));
        let log = response.take_bytes(None).await.unwrap();
        arkret::identity::verify_did_webvh_v1_chain_bytes(did, &log).unwrap();
        let mut response =
            TestClient::get(arkret::identity::DidWebvhResolver::document_url(did).unwrap())
                .send(&router)
                .await;
        assert_eq!(response.status_code, Some(salvo::http::StatusCode::OK));
        let document: serde_json::Value = response.take_json().await.unwrap();
        assert_eq!(document["id"], json!(did));
        assert!(document.get("verificationMethod").is_some());
        let mut response =
            TestClient::get("https://applet.example/_arkret/open/services/unknown/resolution")
                .add_header(
                    "arkret-operation",
                    arkret::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
                    true,
                )
                .send(&router)
                .await;
        assert_eq!(
            response.status_code,
            Some(salvo::http::StatusCode::NOT_FOUND)
        );
        let problem: arkret_wire::Problem = response.take_json().await.unwrap();
        assert_eq!(problem.code(), "not_found");
        for (url, operation, post) in [
            (
                "https://applet.example/_arkret/describe".to_owned(),
                arkret::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
                false,
            ),
            (
                resolution_url,
                arkret::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
                false,
            ),
            (
                "https://applet.example/_arkret/edge/applet/configuration".to_owned(),
                arkret::ServiceOperationId::EDGE_APPLET_CONFIGURATION_COMMAND_EXECUTE_V1,
                true,
            ),
            (
                "https://applet.example/_arkret/edge/applet/managed-actors/author".to_owned(),
                arkret::ServiceOperationId::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1,
                true,
            ),
        ] {
            for kind in ["missing", "wrong", "duplicate"] {
                let mut request = if post {
                    TestClient::post(&url).body("{invalid JSON")
                } else {
                    TestClient::get(&url)
                };
                if kind == "wrong" {
                    request = request.add_header(
                        "arkret-operation",
                        arkret::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                        true,
                    );
                } else if kind == "duplicate" {
                    request = request
                        .add_header("arkret-operation", operation, false)
                        .add_header("arkret-operation", operation, false);
                }
                let mut response = request.send(&router).await;
                let (status, code) = if kind == "missing" {
                    (
                        salvo::http::StatusCode::BAD_REQUEST,
                        "operation_selector_required",
                    )
                } else {
                    (
                        salvo::http::StatusCode::UNPROCESSABLE_ENTITY,
                        "unsupported_operation_version",
                    )
                };
                assert_eq!(response.status_code, Some(status), "{kind} {url}");
                let problem: arkret_wire::Problem = response.take_json().await.unwrap();
                assert_eq!(problem.code(), code);
            }
        }
        assert!(
            edge.authoring_store()
                .entries_with_prefix("applet-configuration/v1/")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn configuration_result_survives_reopen_without_resigning_or_disclosing_plaintext() {
        let file = DatabaseFile::new();
        let intent = intent();
        let key = storage_key(&intent).unwrap();
        let original;
        {
            let store = file.open();
            let service = AppletConfigurationService::new(edge(store.clone())).unwrap();
            let (_, record) = service.load_or_create(&key, &intent).unwrap();
            original = arkret::canonical::canonical_json_bytes(&record.outcome).unwrap();
            let rows = store
                .entries_with_prefix("applet-configuration/v1/")
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert!(!rows[0].1.contains("Configured Bot"));
            assert!(!rows[0].1.contains("originating_actor_id"));
            assert_eq!(record.outcome.status, Status::Pending);
            assert!(!record.started);
            assert!(record.preview.is_none());
            assert!(record.outcome.creation_refs.is_none());
        }
        let store = file.open();
        let service = AppletConfigurationService::new(edge(store.clone())).unwrap();
        let (raw, record) = service.load_or_create(&key, &intent).unwrap();
        assert_eq!(
            arkret::canonical::canonical_json_bytes(&record.outcome).unwrap(),
            original
        );
        let mut different = intent.clone();
        different.selection = Selection::NewBot {
            display_name: Some("Other Bot".into()),
        };
        assert_eq!(storage_key(&different).unwrap(), key);
        assert!(service.load_or_create(&key, &different).is_err());
        let mut corrupted = raw.clone().into_bytes();
        let index = corrupted.len() - 10;
        corrupted[index] = if corrupted[index] == b'A' { b'B' } else { b'A' };
        assert!(
            store
                .compare_exchange_batch(
                    &[(key.clone(), Some(raw))],
                    &[(key.clone(), Some(String::from_utf8(corrupted).unwrap()))],
                )
                .unwrap()
        );
        assert!(service.load_or_create(&key, &intent).is_err());
    }

    #[test]
    fn cancellation_fences_a_concurrent_execution_and_opaque_id_binds_the_full_intent() {
        let file = DatabaseFile::new();
        let service = AppletConfigurationService::new(edge(file.open())).unwrap();
        let intent = intent();
        let key = storage_key(&intent).unwrap();
        let (raw, mut worker) = service.load_or_create(&key, &intent).unwrap();
        let (_, mut cancellation) = service.load_or_create(&key, &intent).unwrap();
        cancellation.outcome = service.outcome(&intent, Status::Cancelled).unwrap();
        assert!(service.replace(&key, &raw, &cancellation).unwrap());
        worker.started = true;
        assert!(!service.replace(&key, &raw, &worker).unwrap());
        let (_, terminal) = service.load_or_create(&key, &intent).unwrap();
        assert_eq!(terminal.outcome.status, Status::Cancelled);
        assert!(terminal.preview.is_none());
        let id = author_request_id(&intent).unwrap();
        assert!((22..=128).contains(&id.len()));
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        );
        let mut other = intent.clone();
        other.originating_actor_id = ActorId::account(arkret::AccountId {
            principal_id: other
                .originating_actor_id
                .as_account_id()
                .unwrap()
                .principal_id
                .clone(),
            station_id: other.service_id.clone(),
        });
        assert_ne!(author_request_id(&other).unwrap(), id);
    }
}
