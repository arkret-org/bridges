//! Encrypted, at-most-once external processing of an accepted native input.
//! An unknown provider result is never retried as a fresh model request.

use super::*;

#[derive(Clone)]
pub struct NativeReplyTicket {
    key: String,
    input_digest: String,
    source: Option<Arc<ReplySource>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplySource {
    actor_id: ActorId,
    content: NativeContent,
    processing_binding: serde_json::Value,
}

/// Durable model output waiting for publication, independently of input ACK.
pub struct PendingNativeReply {
    pub ticket: NativeReplyTicket,
    pub recipient: NativeContentRecipient,
    pub content: NativeContent,
    pub processing_binding: serde_json::Value,
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(path: &std::path::Path) -> ManagedDeviceRuntime {
        let config: crate::Config = serde_json::from_value(serde_json::json!({
            "bridge": {"bridge_id":"native-reply-test"},
            "arkret": {
                "server_url":"https://station.example", "applet_base_url":"https://applet.example",
                "service_did":"did:webvh:zservicescid:applet.example", "trust_domain":"ak:trust_domain:example.net",
                "applet_id":"ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb", "signing_key_seed_hex":"22".repeat(32),
                "verification_method_fragment":"#key-1", "trusted_server_did":"did:webvh:zstationscid:station.example",
                "applet_namespaces":{"realms":[],"handles":[]},
                "managed_actor_authoring":{"principal_endpoint":"https://applet.example", "key_encryption_key_hex":"33".repeat(32)}
            }
        })).unwrap();
        let (sender, _) = tokio::sync::mpsc::channel(1);
        let store = Arc::new(crate::FileAuthoringStore::new(path.to_owned()).unwrap());
        ManagedDeviceRuntime::new(Arc::new(
            ArkretEdge::new(Arc::new(config), store, sender).unwrap(),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn provider_claim_and_output_survive_restart_without_duplicate_handoff() {
        let path = std::env::temp_dir().join(format!(
            "arkret-native-reply-{}.redb",
            crate::realm_governance::nonce().unwrap()
        ));
        let ticket = NativeReplyTicket {
            key: "managed-native-reply/v1/test".into(),
            input_digest: canonical_sha256(&"original-input").unwrap(),
            source: None,
        };
        {
            let runtime = runtime(&path);
            assert!(
                runtime
                    .save_reply(&ticket, None, ReplyPhase::Ready)
                    .await
                    .unwrap()
            );
            let (first, second) = tokio::join!(
                runtime.claim_native_reply(&ticket, &"frozen-request"),
                runtime.claim_native_reply(&ticket, &"frozen-request")
            );
            let first = first.unwrap();
            let second = second.unwrap();
            assert_ne!(first.is_some(), second.is_some());
            let claim = first.or(second).unwrap();
            runtime
                .retain_native_reply_output(&claim, "retained reply")
                .await
                .unwrap();
            runtime
                .retain_native_reply_output(&claim, "retained reply")
                .await
                .unwrap();
            assert!(
                runtime
                    .retain_native_reply_output(&claim, "changed reply")
                    .await
                    .is_err()
            );
            let raw = runtime.reply_record(&ticket).await.unwrap().unwrap().0;
            assert!(!raw.contains("retained reply"));
            assert!(
                runtime
                    .claim_native_reply(&ticket, &"second-request")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        {
            let runtime = runtime(&path);
            let (_, record) = runtime.reply_record(&ticket).await.unwrap().unwrap();
            assert!(
                matches!(record.phase, ReplyPhase::Output { text, .. } if text == "retained reply")
            );
            let wrong = NativeReplyTicket {
                key: ticket.key.clone(),
                input_digest: canonical_sha256(&"changed-input").unwrap(),
                source: None,
            };
            assert!(runtime.reply_record(&wrong).await.is_err());
            let event =
                arkret::EventId::from_digest(arkret::canonical::DigestSuite::Sha256, [19; 32]);
            runtime.finish_native_reply(&ticket, &event).await.unwrap();
            runtime.finish_native_reply(&ticket, &event).await.unwrap();
            let other =
                arkret::EventId::from_digest(arkret::canonical::DigestSuite::Sha256, [20; 32]);
            assert!(runtime.finish_native_reply(&ticket, &other).await.is_err());
            assert!(
                runtime
                    .claim_native_reply(&ticket, &"second-request")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn expired_unknown_provider_cannot_claim_again_or_retain_late_output() {
        let path = std::env::temp_dir().join(format!(
            "arkret-native-reply-{}.redb",
            crate::realm_governance::nonce().unwrap()
        ));
        let ticket = NativeReplyTicket {
            key: "managed-native-reply/v1/unknown".into(),
            input_digest: canonical_sha256(&"input").unwrap(),
            source: None,
        };
        {
            let runtime = runtime(&path);
            runtime
                .save_reply(
                    &ticket,
                    None,
                    ReplyPhase::Started {
                        owner: "original-owner".into(),
                        expires_at: Utc::now() - chrono::Duration::seconds(1),
                        request_digest: canonical_sha256(&"request").unwrap(),
                    },
                )
                .await
                .unwrap();
        }
        {
            let runtime = runtime(&path);
            assert!(
                runtime
                    .claim_native_reply(&ticket, &"request")
                    .await
                    .unwrap()
                    .is_none()
            );
            let claim = NativeReplyClaim {
                ticket,
                owner: "original-owner".into(),
            };
            assert!(
                runtime
                    .retain_native_reply_output(&claim, "late response")
                    .await
                    .is_err()
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}

pub struct NativeReplyClaim {
    ticket: NativeReplyTicket,
    owner: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeReplyPreparation {
    Ready,
    InFlight,
    UnknownSettled,
    OutputRetained(String),
    Published(arkret::EventId),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyRecord {
    input_digest: String,
    source: Option<ReplySource>,
    phase: ReplyPhase,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ReplyPhase {
    Ready,
    Started {
        owner: String,
        expires_at: DateTime<Utc>,
        request_digest: String,
    },
    UnknownSettled,
    Output {
        owner: String,
        text: String,
    },
    Published {
        event_id: arkret::EventId,
    },
}

impl ManagedDeviceRuntime {
    async fn reply_record(
        &self,
        ticket: &NativeReplyTicket,
    ) -> Result<Option<(String, ReplyRecord)>> {
        let store = self.store.clone();
        let key = ticket.key.clone();
        let raw = run_blocking(move || store.load(&key)).await?;
        raw.map(|raw| {
            let record: ReplyRecord = self.authoring.decrypt_key_material(&ticket.key, &raw)?;
            if record.input_digest != ticket.input_digest {
                return Err(invalid(
                    "native reply input already binds another processing intent",
                ));
            }
            Ok((raw, record))
        })
        .transpose()
    }

    async fn save_reply(
        &self,
        ticket: &NativeReplyTicket,
        previous: Option<String>,
        phase: ReplyPhase,
    ) -> Result<bool> {
        let record = ReplyRecord {
            input_digest: ticket.input_digest.clone(),
            source: ticket.source.as_deref().cloned(),
            phase,
        };
        let encrypted = self.authoring.encrypt_key_material(&ticket.key, &record)?;
        self.cas(&ticket.key, previous, encrypted).await
    }

    /// The receiving identity and original Event fix the slot. Changing model
    /// settings or plaintext cannot silently turn the same input into new work.
    pub async fn prepare_native_reply<E: Serialize>(
        &self,
        recipient: &NativeContentRecipient,
        content: &NativeContent,
        processing_binding: &E,
    ) -> Result<(NativeReplyTicket, NativeReplyPreparation)> {
        recipient.check_content(content)?;
        if recipient.scope() != &content.original().event.scope_ref {
            return Err(invalid("native reply source has another scope"));
        }
        let original = self
            .authoring
            .managed_creation(recipient.actor_id())
            .await?;
        let creation = crate::managed_authoring::creation_payload(&original.event)?;
        if creation.actor_role != arkret::RealmActorCreatePayloadActorRole::Bot {
            return Err(invalid("native model replies require a managed Bot"));
        }
        let ticket = NativeReplyTicket {
            key: format!(
                "managed-native-reply/v1/{}",
                canonical_sha256(&(recipient.actor_id(), &content.original().event.event_id))?
            ),
            input_digest: canonical_sha256(&(
                recipient.actor_id(),
                content.original(),
                content.message(),
                processing_binding,
            ))?,
            source: Some(Arc::new(ReplySource {
                actor_id: recipient.actor_id().clone(),
                content: content.without_attachment_bytes(),
                processing_binding: serde_json::to_value(processing_binding)?,
            })),
        };
        for _ in 0..8 {
            if let Some((raw, record)) = self.reply_record(&ticket).await? {
                let state = match record.phase {
                    ReplyPhase::Ready => NativeReplyPreparation::Ready,
                    ReplyPhase::Started { expires_at, .. } if expires_at > Utc::now() => {
                        NativeReplyPreparation::InFlight
                    }
                    ReplyPhase::Started { .. } => {
                        if !self
                            .save_reply(&ticket, Some(raw), ReplyPhase::UnknownSettled)
                            .await?
                        {
                            continue;
                        }
                        NativeReplyPreparation::UnknownSettled
                    }
                    ReplyPhase::UnknownSettled => NativeReplyPreparation::UnknownSettled,
                    ReplyPhase::Output { text, .. } => NativeReplyPreparation::OutputRetained(text),
                    ReplyPhase::Published { event_id } => {
                        NativeReplyPreparation::Published(event_id)
                    }
                };
                return Ok((ticket, state));
            }
            if self.save_reply(&ticket, None, ReplyPhase::Ready).await? {
                return Ok((ticket, NativeReplyPreparation::Ready));
            }
        }
        Err(invalid("native reply preparation contended"))
    }

    /// Rebuild only source-reading capabilities; publishing still performs all
    /// current Device, membership, grant and MLS gates. No provider claim is made.
    pub async fn pending_native_reply_outputs(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
    ) -> Result<Vec<PendingNativeReply>> {
        reader.check_device(device)?;
        let store = self.store.clone();
        let authoring = self.authoring.clone();
        let records = run_blocking(move || {
            store
                .entries_with_prefix("managed-native-reply/v1/")?
                .into_iter()
                .map(|(key, raw)| {
                    let record: ReplyRecord = authoring.decrypt_key_material(&key, &raw)?;
                    Ok((key, record))
                })
                .collect::<Result<Vec<_>>>()
        })
        .await?;
        let mut pending = Vec::new();
        for (key, record) in records {
            let ReplyPhase::Output { text, .. } = record.phase else {
                continue;
            };
            let source = record
                .source
                .ok_or_else(|| invalid("native output source missing"))?;
            if source.actor_id != device.actor_id
                || source.content.original().event.scope_ref != device.effective_scope
            {
                continue;
            }
            let expected_key = format!(
                "managed-native-reply/v1/{}",
                canonical_sha256(&(&source.actor_id, &source.content.original().event.event_id,))?
            );
            if key != expected_key
                || record.input_digest
                    != canonical_sha256(&(
                        &source.actor_id,
                        source.content.original(),
                        source.content.message(),
                        &source.processing_binding,
                    ))?
            {
                return Err(invalid("native output differs from its frozen source"));
            }
            let recipient = NativeContentRecipient::new(device, reader, &source.content)?;
            pending.push(PendingNativeReply {
                ticket: NativeReplyTicket {
                    key,
                    input_digest: record.input_digest,
                    source: Some(Arc::new(source.clone())),
                },
                recipient,
                content: source.content,
                processing_binding: source.processing_binding,
                text,
            });
        }
        reader.check_device(device)?;
        Ok(pending)
    }

    /// Called by the actual provider transport immediately before IO. The fixed
    /// deadline bounds the owner; expiry settles Unknown without another call.
    pub async fn claim_native_reply<E: Serialize>(
        &self,
        ticket: &NativeReplyTicket,
        provider_request: &E,
    ) -> Result<Option<NativeReplyClaim>> {
        for _ in 0..8 {
            let (raw, record) = self
                .reply_record(ticket)
                .await?
                .ok_or_else(|| invalid("native reply intent missing"))?;
            if !matches!(record.phase, ReplyPhase::Ready) {
                return Ok(None);
            }
            let owner = crate::realm_governance::nonce()?.to_string();
            let phase = ReplyPhase::Started {
                owner: owner.clone(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
                request_digest: canonical_sha256(provider_request)?,
            };
            if self.save_reply(ticket, Some(raw), phase).await? {
                return Ok(Some(NativeReplyClaim {
                    ticket: ticket.clone(),
                    owner,
                }));
            }
        }
        Err(invalid("native reply provider claim contended"))
    }

    pub async fn retain_native_reply_output(
        &self,
        claim: &NativeReplyClaim,
        text: &str,
    ) -> Result<()> {
        if text.trim().is_empty() || text.len() > 65_536 {
            return Err(invalid("native reply output is empty or too large"));
        }
        for _ in 0..8 {
            let (raw, record) = self
                .reply_record(&claim.ticket)
                .await?
                .ok_or_else(|| invalid("native reply claim missing"))?;
            match record.phase {
                ReplyPhase::Started {
                    owner, expires_at, ..
                } if owner == claim.owner && expires_at > Utc::now() => {}
                ReplyPhase::Output {
                    owner,
                    text: original,
                } if owner == claim.owner && original == text => return Ok(()),
                _ => return Err(invalid("native reply provider claim is no longer active")),
            }
            if self
                .save_reply(
                    &claim.ticket,
                    Some(raw),
                    ReplyPhase::Output {
                        owner: claim.owner.clone(),
                        text: text.into(),
                    },
                )
                .await?
            {
                return Ok(());
            }
        }
        Err(invalid("native reply output persistence contended"))
    }

    pub async fn finish_native_reply(
        &self,
        ticket: &NativeReplyTicket,
        event_id: &arkret::EventId,
    ) -> Result<()> {
        for _ in 0..8 {
            let (raw, record) = self
                .reply_record(ticket)
                .await?
                .ok_or_else(|| invalid("native reply output missing"))?;
            match record.phase {
                ReplyPhase::Output { .. } => {}
                ReplyPhase::Published { event_id: original } if &original == event_id => {
                    return Ok(());
                }
                _ => {
                    return Err(invalid(
                        "native reply has no retained output for this publication",
                    ));
                }
            }
            if self
                .save_reply(
                    ticket,
                    Some(raw),
                    ReplyPhase::Published {
                        event_id: event_id.clone(),
                    },
                )
                .await?
            {
                return Ok(());
            }
        }
        Err(invalid("native reply completion contended"))
    }
}
