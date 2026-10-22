//! Same-Applet Service replacement; the Station alone accepts per-actor manager changes.
use arkret::identity::VerifiedRealmActorMaterial;
use arkret::{CurrentSelector, RealmActorMaterialRequest, RealmActorMaterialResult};

use super::*;
use crate::managed_actor_authoring::control::manager::{reference, revision};

fn selectors(actor: &ActorId) -> Vec<CurrentSelector> {
    vec![
        CurrentSelector::RealmActorControl {
            actor_id: actor.clone(),
        },
        CurrentSelector::RealmActorManager {
            actor_id: actor.clone(),
        },
        CurrentSelector::RealmActorDeviceGeneration {
            actor_id: actor.clone(),
        },
        CurrentSelector::RealmActorStatus {
            actor_id: actor.clone(),
            gate: arkret::RealmActorStatusGate::Owner,
        },
        CurrentSelector::RealmActorRecovery {
            actor_id: actor.clone(),
        },
    ]
}
fn row<'a>(
    material: &'a VerifiedRealmActorMaterial,
    selector: &CurrentSelector,
) -> Result<(&'a serde_json::Value, &'a arkret::CommittedEventRef)> {
    let RealmActorMaterialResult::Current { entries } = &material.material().result else {
        return Err(invalid("manager transfer requires a verified current cut"));
    };
    entries
        .iter()
        .find_map(|entry| match entry {
            arkret::RealmActorMaterialCurrentEntry::Present {
                row:
                    arkret::TypedCurrentRow::Value {
                        selector: found,
                        value,
                        ..
                    },
                source_ref,
            } if found == selector => Some((value, source_ref)),
            _ => None,
        })
        .ok_or_else(|| invalid("manager transfer current row unavailable"))
}
fn paused(material: &VerifiedRealmActorMaterial, actor: &ActorId) -> Result<()> {
    let owner = row(
        material,
        &CurrentSelector::RealmActorStatus {
            actor_id: actor.clone(),
            gate: arkret::RealmActorStatusGate::Owner,
        },
    )?
    .0;
    let recovery: arkret::RealmActorRecoveryValue = serde_json::from_value(
        row(
            material,
            &CurrentSelector::RealmActorRecovery {
                actor_id: actor.clone(),
            },
        )?
        .0
        .clone(),
    )?;
    if owner != "paused" || recovery.pending.is_some() {
        return Err(invalid(
            "manager transfer requires owner paused and no pending recovery",
        ));
    }
    Ok(())
}

impl ManagedDeviceRuntime {
    /// Coordinate Service replacement after the operator has preserved the Applet's
    /// complete data and key custody in the receiving deployment. Individual phases
    /// can run in separate processes against that retained custody.
    pub async fn prepare_management_transfer_to(
        &self,
        receiving: &Self,
        plan: &ManagementTransferPlan,
    ) -> Result<()> {
        if self.edge.applet_id() != receiving.edge.applet_id() {
            return Err(invalid("management transfer must retain the Applet ID"));
        }
        if receiving
            .authoring
            .retained_manager_event(plan)
            .await
            .is_ok_and(|event| event.is_some())
        {
            return Ok(());
        }
        let creation = self.authoring.managed_creation(&plan.actor_id).await?;
        let did = crate::managed_authoring::creation_payload(&creation.event)?
            .initial_resolution
            .did;
        let offer = receiving.management_transfer_offer(plan, &did).await?;
        let proposal = self.management_control_transcript(&offer).await?;
        let signature = receiving
            .sign_management_control_transcript(plan, &proposal)
            .await?;
        let commit = self.submit_management_control(plan, &signature).await?;
        let release = self.release_management_native(plan, &commit).await?;
        receiving
            .prepare_management_acceptance(
                plan,
                &release,
                &reference(&commit),
                &reference(&creation.commit),
            )
            .await
    }

    /// Verify retained custody and durably prepare the receiving Service's new keys.
    /// The returned operational offer contains public keys only.
    pub async fn management_transfer_offer(
        &self,
        plan: &ManagementTransferPlan,
        did: &Did,
    ) -> Result<ManagementTransferOffer> {
        self.authoring.prepare_manager_offer(plan, did).await
    }

    async fn management_source_current(
        &self,
        actor: &ActorId,
    ) -> Result<VerifiedRealmActorMaterial> {
        let realm = actor
            .as_realm_actor_id()
            .ok_or_else(|| invalid("Realm actor required"))?;
        let route = self.edge.realm_route(&realm.realm_id).await?;
        let current = route
            .material(
                &RealmActorMaterialRequest::Current {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    selectors: selectors(actor),
                },
                &ActorId::service(self.edge.service_actor_id().clone()),
            )
            .await?;
        paused(&current, actor)?;
        let manager: arkret::RealmActorManagerValue = serde_json::from_value(
            row(
                &current,
                &CurrentSelector::RealmActorManager {
                    actor_id: actor.clone(),
                },
            )?
            .0
            .clone(),
        )?;
        if manager.service_id != *self.edge.service_actor_id() {
            return Err(invalid(
                "releasing Service is no longer the accepted manager",
            ));
        }
        Ok(current)
    }

    /// Prepare the old holder's exact native proposal after checking the current
    /// owner pause, recovery gate and manager. This does not publish it yet.
    pub async fn management_control_transcript(
        &self,
        offer: &ManagementTransferOffer,
    ) -> Result<arkret::RealmActorControlAcceptanceTranscript> {
        let current = self.management_source_current(&offer.plan.actor_id).await?;
        let (value, reference) = row(
            &current,
            &CurrentSelector::RealmActorControl {
                actor_id: offer.plan.actor_id.clone(),
            },
        )?;
        let control = serde_json::from_value(value.clone())?;
        self.authoring
            .prepare_manager_control(offer, &control, reference)
            .await
    }

    /// Sign only this receiving host's exact proposal with its new daily key.
    pub async fn sign_management_control_transcript(
        &self,
        plan: &ManagementTransferPlan,
        proposal: &arkret::RealmActorControlAcceptanceTranscript,
    ) -> Result<arkret::DetachedObjectSignature> {
        self.authoring.sign_manager_control(plan, proposal).await
    }

    /// Publish and submit the old controller's frozen Event, or recover its
    /// original receipt. Neither caller can substitute a different Event.
    pub async fn submit_management_control(
        &self,
        plan: &ManagementTransferPlan,
        signature: &arkret::DetachedObjectSignature,
    ) -> Result<RealmCommit> {
        self.management_source_current(&plan.actor_id).await?;
        let operation = self
            .authoring
            .freeze_manager_control(plan, signature)
            .await?;
        Box::pin(self.control_transition(&plan.actor_id, &operation, None)).await
    }

    /// Consume the old native commitment and commit the receiving public update
    /// key. No old private key is returned or copied to the receiving host.
    pub async fn release_management_native(
        &self,
        plan: &ManagementTransferPlan,
        accepted: &RealmCommit,
    ) -> Result<Vec<serde_json::Value>> {
        let current = self.management_source_current(&plan.actor_id).await?;
        if row(
            &current,
            &CurrentSelector::RealmActorControl {
                actor_id: plan.actor_id.clone(),
            },
        )?
        .1 != &reference(accepted)
        {
            return Err(invalid("control advanced before native manager release"));
        }
        self.authoring.release_manager_native(plan, accepted).await
    }

    /// The receiving controller independently reads verified private originals,
    /// finishes its native update and freezes manager.change. The stable public
    /// DID resource must serve this host's publication before completion.
    pub async fn prepare_management_acceptance(
        &self,
        plan: &ManagementTransferPlan,
        release: &[serde_json::Value],
        control_ref: &arkret::CommittedEventRef,
        creation_ref: &arkret::CommittedEventRef,
    ) -> Result<()> {
        if self.authoring.retained_manager_event(plan).await?.is_some() {
            return Ok(());
        }
        let query = RealmActorMaterialRequest::Current {
            actor_id: plan.actor_id.clone(),
            request_nonce: crate::realm_governance::nonce()?,
            selectors: selectors(&plan.actor_id),
        };
        let current = self
            .manager_control_material(plan, control_ref, &query)
            .await?;
        paused(&current, &plan.actor_id)?;
        if row(
            &current,
            &CurrentSelector::RealmActorControl {
                actor_id: plan.actor_id.clone(),
            },
        )?
        .1 != control_ref
        {
            return Err(invalid(
                "control advanced before receiving manager acceptance",
            ));
        }
        self.authoring.receive_manager_native(plan, release).await?;
        let created = self
            .manager_control_material(
                plan,
                control_ref,
                &RealmActorMaterialRequest::Event {
                    actor_id: plan.actor_id.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target: creation_ref.clone(),
                },
            )
            .await?;
        self.authoring
            .prepare_manager_event(plan, &current, &created)
            .await?;
        Ok(())
    }

    async fn manager_control_client(
        &self,
        plan: &ManagementTransferPlan,
        control_ref: &arkret::CommittedEventRef,
        route: &crate::realm_governance::RealmRoute,
    ) -> Result<Client> {
        let (key, method) = self.authoring.incoming_controller(plan).await?;
        Ok(route.client.clone().with_realm_actor_control_http_signer(
            arkret::RealmActorControlHttpMetadata {
                actor_id: plan.actor_id.clone(),
                control_ref: control_ref.clone(),
                nonce: crate::realm_governance::nonce()?,
            },
            route.authority.current_service_id().clone(),
            arkret::http_client::HttpMessageSigner::new(method.to_string(), key),
        )?)
    }
    async fn manager_control_material(
        &self,
        plan: &ManagementTransferPlan,
        control_ref: &arkret::CommittedEventRef,
        request: &RealmActorMaterialRequest,
    ) -> Result<VerifiedRealmActorMaterial> {
        let realm = plan
            .actor_id
            .as_realm_actor_id()
            .ok_or_else(|| invalid("Realm actor required"))?;
        let route = self.edge.realm_route(&realm.realm_id).await?;
        let client = self
            .manager_control_client(plan, control_ref, &route)
            .await?;
        Ok(client
            .realm_actor_material(
                request,
                &plan.actor_id,
                &route.authority,
                &route.resolution,
                &route.keys,
            )
            .await?)
    }

    /// Submit or recover the exact manager original. Successful acceptance
    /// installs only new custody; it never resumes the owner or old Devices.
    pub async fn complete_management_transfer(
        &self,
        plan: &ManagementTransferPlan,
    ) -> Result<RealmCommit> {
        if let Some(full) = self.authoring.retained_manager_receipt(plan).await? {
            return Ok(full.commit);
        }
        let (event, old_control_ref) = self
            .authoring
            .retained_manager_event(plan)
            .await?
            .ok_or_else(|| invalid("management transfer has not been prepared"))?;
        let realm = plan
            .actor_id
            .as_realm_actor_id()
            .ok_or_else(|| invalid("Realm actor required"))?;
        let route = self.edge.realm_route(&realm.realm_id).await?;
        let request =
            SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.event().clone()));
        let digest = arkret::Hash::new(canonical_sha256(&request)?)?;
        let query = RealmActorMaterialRequest::Outcome {
            actor_id: plan.actor_id.clone(),
            request_nonce: crate::realm_governance::nonce()?,
            target_request_digest: digest,
        };
        // After a lost acceptance the old control_ref no longer authenticates.
        // The new Service can recover the original through its accepted binding.
        let service = ActorId::service(self.edge.service_actor_id().clone());
        let observed = match route.material(&query, &service).await {
            Ok(material) => material,
            Err(_) => {
                self.manager_control_material(plan, &old_control_ref, &query)
                    .await?
            }
        };
        let RealmActorMaterialResult::Outcome { outcome, .. } = &observed.material().result else {
            return Err(invalid("manager outcome returned another purpose"));
        };
        let accepted = match outcome {
            arkret::RealmActorOperationOutcome::Submitted(AuthoritySubmitOutcome::Accepted {
                commit,
                ..
            }) => commit.clone(),
            arkret::RealmActorOperationOutcome::Status {
                status: arkret::RealmActorOperationStatus::Unknown,
            } => {
                let current = self
                    .manager_control_material(
                        plan,
                        &old_control_ref,
                        &RealmActorMaterialRequest::Current {
                            actor_id: plan.actor_id.clone(),
                            request_nonce: crate::realm_governance::nonce()?,
                            selectors: selectors(&plan.actor_id),
                        },
                    )
                    .await?;
                paused(&current, &plan.actor_id)?;
                let payload: arkret::RealmActorManagerChangePayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                for (selector, expected) in [
                    (
                        CurrentSelector::RealmActorControl {
                            actor_id: plan.actor_id.clone(),
                        },
                        &payload.expected_control_revision,
                    ),
                    (
                        CurrentSelector::RealmActorManager {
                            actor_id: plan.actor_id.clone(),
                        },
                        &payload.expected_manager_revision,
                    ),
                    (
                        CurrentSelector::RealmActorDeviceGeneration {
                            actor_id: plan.actor_id.clone(),
                        },
                        &payload.expected_device_generation_revision,
                    ),
                ] {
                    if &revision(row(&current, &selector)?.1) != expected {
                        return Err(invalid(
                            "manager prestate changed; retain the original instead of authoring a replacement",
                        ));
                    }
                }
                let (key, method) = self.authoring.incoming_controller(plan).await?;
                let producer = arkret::ProducerVerificationContext {
                    actor: plan.actor_id.clone(),
                    verification_method: method,
                    public_key: PublicKeyMaterial::Ed25519Raw {
                        bytes: key.verifying_key().to_bytes().to_vec(),
                    },
                    digest_suite: crate::PRODUCER_DIGEST_SUITE,
                };
                let request = arkret::VerifiedSubmission::verify(request, |_| Ok(producer.clone()))
                    .map_err(|e| invalid(e.to_string()))?;
                let client = self
                    .manager_control_client(plan, &old_control_ref, &route)
                    .await?;
                let outcome = client
                    .submit_to_realm_authority(
                        &request,
                        &arkret::ClientRequestOptions::new()
                            .idempotency_key(event.event_id().as_str()),
                    )
                    .await?;
                let SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Accepted {
                    commit,
                    ..
                }) = outcome
                else {
                    return Err(invalid(
                        "manager transfer has not been accepted; retain its exact original",
                    ));
                };
                commit
            }
            _ => {
                return Err(invalid(
                    "manager transfer has a terminal rejection or unsupported outcome",
                ));
            }
        };
        let query = RealmActorMaterialRequest::Event {
            actor_id: plan.actor_id.clone(),
            request_nonce: crate::realm_governance::nonce()?,
            target: reference(&accepted),
        };
        let original = route.material(&query, &service).await?;
        self.authoring.accept_manager_event(plan, &original).await
    }
}
