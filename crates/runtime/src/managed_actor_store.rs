//! Private Principal custody and exact authoring leases over the host's atomic durable store.
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{AuthoringStore, BridgeError, Result, run_blocking};

pub(super) struct ManagedActorStore {
    store: Arc<dyn AuthoringStore>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedActorIdentityRecord {
    pub(crate) actor_did: String,
    pub(crate) initial_resolution_json: String,
    pub(crate) method_history_evidence_json: String,
    pub(crate) encrypted_key_material: String,
    pub(crate) encrypted_controller_material: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoringRecord {
    request_json: String,
    owner_token: String,
    lease_expires_at: i64,
    bundle_json: Option<String>,
}

pub(crate) enum ManagedActorAuthoringClaim {
    Acquired,
    Busy,
    Completed(String),
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}
fn identity_key(subject: &str) -> String {
    format!("managed-identity/v1/{subject}")
}
fn authoring_key(subject: &str, digest: &str) -> String {
    format!("managed-authoring/v1/{subject}/{digest}")
}
fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|error| BridgeError::Database(format!("managed custody encode failed: {error}")))
}
fn decode<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|error| {
        BridgeError::Database(format!("managed custody record is invalid: {error}"))
    })
}
fn require_request(record: &AuthoringRecord, request: &str) -> Result<()> {
    if record.request_json != request {
        return Err(BridgeError::Database(
            "managed actor request digest collision with different canonical bytes".into(),
        ));
    }
    Ok(())
}

impl ManagedActorStore {
    pub(super) fn new(store: Arc<dyn AuthoringStore>) -> Self {
        Self { store }
    }

    pub(crate) fn managed_actor_identity(
        &self,
        subject_key: &str,
    ) -> Result<Option<ManagedActorIdentityRecord>> {
        self.store
            .load(&identity_key(subject_key))?
            .map(|raw| decode(&raw))
            .transpose()
    }

    pub(super) async fn published_identity_async(
        self: Arc<Self>,
        document_url: String,
    ) -> Result<Option<(String, ManagedActorIdentityRecord)>> {
        run_blocking(move || {
            let Some(subject) = self
                .store
                .load(&format!("managed-publication/v1/{document_url}"))?
            else {
                return Ok(None);
            };
            let identity = self.managed_actor_identity(&subject)?.ok_or_else(|| {
                BridgeError::Database("managed publication has no retained identity".into())
            })?;
            let actual = arkret::identity::DidWebvhResolver::document_url(&arkret::Did::new(
                identity.actor_did.clone(),
            )?)
            .map_err(|error| {
                BridgeError::Database(format!("managed publication URL is invalid: {error}"))
            })?;
            if actual != document_url {
                return Err(BridgeError::Database(
                    "managed publication index differs from the native identity".into(),
                ));
            }
            Ok(Some((subject, identity)))
        })
        .await
    }

    fn completed_managed_actor_authoring(
        &self,
        subject_key: &str,
        request_digest: &str,
        request_json: &str,
    ) -> Result<Option<String>> {
        let Some(raw) = self
            .store
            .load(&authoring_key(subject_key, request_digest))?
        else {
            return Ok(None);
        };
        let record: AuthoringRecord = decode(&raw)?;
        require_request(&record, request_json)?;
        Ok(record.bundle_json)
    }

    pub(crate) async fn completed_managed_actor_authoring_async(
        self: Arc<Self>,
        subject_key: String,
        request_digest: String,
        request_json: String,
    ) -> Result<Option<String>> {
        run_blocking(move || {
            self.completed_managed_actor_authoring(&subject_key, &request_digest, &request_json)
        })
        .await
    }
    pub(crate) async fn managed_actor_identity_async(
        self: Arc<Self>,
        subject_key: String,
    ) -> Result<Option<ManagedActorIdentityRecord>> {
        run_blocking(move || self.managed_actor_identity(&subject_key)).await
    }

    fn install_managed_actor_identity(
        &self,
        subject_key: &str,
        candidate: &ManagedActorIdentityRecord,
    ) -> Result<ManagedActorIdentityRecord> {
        let key = identity_key(subject_key);
        if let Some(raw) = self.store.load(&key)? {
            return decode(&raw);
        }
        let reverse = format!("managed-identity-did/v1/{}", candidate.actor_did);
        let document_url = arkret::identity::DidWebvhResolver::document_url(&arkret::Did::new(
            candidate.actor_did.clone(),
        )?)
        .map_err(|error| {
            BridgeError::Database(format!("managed publication URL is invalid: {error}"))
        })?;
        let publication = format!("managed-publication/v1/{document_url}");
        let inserted = self.store.compare_exchange_batch(
            &[
                (key.clone(), None),
                (reverse.clone(), None),
                (publication.clone(), None),
            ],
            &[
                (key.clone(), Some(encode(candidate)?)),
                (reverse, Some(subject_key.into())),
                (publication, Some(subject_key.into())),
            ],
        )?;
        if inserted {
            return Ok(candidate.clone());
        }
        self.managed_actor_identity(subject_key)?.ok_or_else(|| {
            BridgeError::Database("managed identity conflict has no winning subject".into())
        })
    }
    pub(crate) async fn install_managed_actor_identity_async(
        self: Arc<Self>,
        subject_key: String,
        candidate: ManagedActorIdentityRecord,
    ) -> Result<ManagedActorIdentityRecord> {
        run_blocking(move || self.install_managed_actor_identity(&subject_key, &candidate)).await
    }

    fn claim_managed_actor_authoring(
        &self,
        subject_key: &str,
        request_digest: &str,
        request_json: &str,
        owner_token: &str,
        lease_secs: i64,
    ) -> Result<ManagedActorAuthoringClaim> {
        let key = authoring_key(subject_key, request_digest);
        let before = self.store.load(&key)?;
        let now = now_ts();
        if let Some(raw) = &before {
            let record: AuthoringRecord = decode(raw)?;
            require_request(&record, request_json)?;
            if let Some(bundle) = record.bundle_json {
                return Ok(ManagedActorAuthoringClaim::Completed(bundle));
            }
            if record.lease_expires_at > now {
                return Ok(ManagedActorAuthoringClaim::Busy);
            }
        }
        let identity = identity_key(subject_key);
        let original = self.store.load(&identity)?.ok_or_else(|| {
            BridgeError::Database("managed authoring subject has no durable identity".into())
        })?;
        let record = AuthoringRecord {
            request_json: request_json.into(),
            owner_token: owner_token.into(),
            lease_expires_at: now
                .checked_add(lease_secs)
                .ok_or_else(|| BridgeError::Database("managed authoring lease overflow".into()))?,
            bundle_json: None,
        };
        let acquired = self.store.compare_exchange_batch(
            &[(key.clone(), before), (identity, Some(original))],
            &[(key, Some(encode(&record)?))],
        )?;
        Ok(if acquired {
            ManagedActorAuthoringClaim::Acquired
        } else {
            ManagedActorAuthoringClaim::Busy
        })
    }
    pub(crate) async fn claim_managed_actor_authoring_async(
        self: Arc<Self>,
        subject_key: String,
        request_digest: String,
        request_json: String,
        owner_token: String,
        lease_secs: i64,
    ) -> Result<ManagedActorAuthoringClaim> {
        run_blocking(move || {
            self.claim_managed_actor_authoring(
                &subject_key,
                &request_digest,
                &request_json,
                &owner_token,
                lease_secs,
            )
        })
        .await
    }

    fn complete_managed_actor_authoring(
        &self,
        subject_key: &str,
        request_digest: &str,
        owner_token: &str,
        bundle_json: &str,
    ) -> Result<()> {
        let lost = || {
            BridgeError::Database("managed actor authoring lease was lost before completion".into())
        };
        let key = authoring_key(subject_key, request_digest);
        let before = self.store.load(&key)?.ok_or_else(lost)?;
        let mut record: AuthoringRecord = decode(&before)?;
        if record.owner_token != owner_token || record.bundle_json.is_some() {
            return Err(lost());
        }
        record.bundle_json = Some(bundle_json.into());
        record.lease_expires_at = 0;
        if !self.store.compare_exchange_batch(
            &[(key.clone(), Some(before))],
            &[(key, Some(encode(&record)?))],
        )? {
            return Err(lost());
        }
        Ok(())
    }
    pub(crate) async fn complete_managed_actor_authoring_async(
        self: Arc<Self>,
        subject_key: String,
        request_digest: String,
        owner_token: String,
        bundle_json: String,
    ) -> Result<()> {
        run_blocking(move || {
            self.complete_managed_actor_authoring(
                &subject_key,
                &request_digest,
                &owner_token,
                &bundle_json,
            )
        })
        .await
    }
    fn abandon_managed_actor_authoring(
        &self,
        subject_key: &str,
        request_digest: &str,
        owner_token: &str,
    ) -> Result<()> {
        let key = authoring_key(subject_key, request_digest);
        let Some(before) = self.store.load(&key)? else {
            return Ok(());
        };
        let record: AuthoringRecord = decode(&before)?;
        if record.owner_token == owner_token && record.bundle_json.is_none() {
            self.store
                .compare_exchange_batch(&[(key.clone(), Some(before))], &[(key, None)])?;
        }
        Ok(())
    }
    pub(crate) async fn abandon_managed_actor_authoring_async(
        self: Arc<Self>,
        subject_key: String,
        request_digest: String,
        owner_token: String,
    ) -> Result<()> {
        run_blocking(move || {
            self.abandon_managed_actor_authoring(&subject_key, &request_digest, &owner_token)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authoring_takeover_preserves_completed_generations_and_rejects_stale_owners() {
        let path = std::env::temp_dir().join(format!(
            "managed-cas-{}-{}.redb",
            std::process::id(),
            now_ts()
        ));
        let store =
            ManagedActorStore::new(crate::FileAuthoringStore::shared(path.clone()).unwrap());
        let identity = ManagedActorIdentityRecord {
            actor_did: "did:webvh:fixture:managed.example:one".into(),
            initial_resolution_json: "resolution".into(),
            method_history_evidence_json: "evidence".into(),
            encrypted_key_material: "ciphertext".into(),
            encrypted_controller_material: Some("opaque-controller".into()),
        };
        store
            .install_managed_actor_identity("subject", &identity)
            .unwrap();
        assert!(matches!(
            store
                .claim_managed_actor_authoring("subject", "digest", "request", "owner", -1)
                .unwrap(),
            ManagedActorAuthoringClaim::Acquired
        ));
        assert!(matches!(
            store
                .claim_managed_actor_authoring("subject", "digest", "request", "winner", 30)
                .unwrap(),
            ManagedActorAuthoringClaim::Acquired
        ));
        assert!(
            store
                .complete_managed_actor_authoring("subject", "digest", "owner", "wrong")
                .is_err()
        );
        store
            .abandon_managed_actor_authoring("subject", "digest", "owner")
            .unwrap();
        assert!(matches!(
            store
                .claim_managed_actor_authoring("subject", "digest", "request", "third", 30)
                .unwrap(),
            ManagedActorAuthoringClaim::Busy
        ));
        store
            .complete_managed_actor_authoring("subject", "digest", "winner", "bundle")
            .unwrap();
        assert!(
            store
                .claim_managed_actor_authoring("subject", "digest", "different", "third", 30)
                .is_err()
        );
        assert!(matches!(
            store
                .claim_managed_actor_authoring("subject", "next", "new request", "next", 30)
                .unwrap(),
            ManagedActorAuthoringClaim::Acquired
        ));
        assert_eq!(
            store
                .completed_managed_actor_authoring("subject", "digest", "request")
                .unwrap()
                .as_deref(),
            Some("bundle")
        );
        drop(store);
        let reopened =
            ManagedActorStore::new(crate::FileAuthoringStore::shared(path.clone()).unwrap());
        assert_eq!(
            reopened
                .completed_managed_actor_authoring("subject", "digest", "request")
                .unwrap()
                .as_deref(),
            Some("bundle")
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
}
