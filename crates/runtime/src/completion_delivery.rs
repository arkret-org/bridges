//! Durable historical creation confirmation shared by file and SQL hosts.
use arkret_models_integration::{AppletDeliveryAuthenticationRecord, AppletTransactionOutcome};
use serde::{Deserialize, Serialize};

use crate::{ArkretEdge, Result};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    #[serde(rename = "canonical_body_digest")]
    body_digest: String,
    #[serde(rename = "delivery_authentication_record")]
    authentication: AppletDeliveryAuthenticationRecord,
    #[serde(rename = "delivery_authentication_record_digest")]
    authentication_digest: arkret_wire::Hash,
    #[serde(rename = "accepted_outcome")]
    outcome: Option<AppletTransactionOutcome>,
}

impl Receipt {
    fn matches(&self, body: &str, binding: &arkret_wire::Hash) -> Result<bool> {
        let digest = self
            .authentication
            .stable_digest()
            .map_err(crate::BridgeError::App)?;
        if digest != self.authentication_digest {
            return Err(crate::BridgeError::App(
                "retained completion authentication digest differs".into(),
            ));
        }
        Ok(self.body_digest == body && &digest == binding)
    }
}

/// Authentication and private material verification precede this function.
/// Installing the same immutable creation is independently idempotent, so a
/// crash between custody retention and outcome retention can safely resume.
pub(crate) fn confirm(
    edge: &ArkretEdge,
    verified: crate::arkret_edge::VerifiedManagedCompletion,
    authentication: AppletDeliveryAuthenticationRecord,
    body_digest: String,
) -> Result<Option<AppletTransactionOutcome>> {
    let store = edge.authoring_store();
    let key = format!(
        "applet-completion/v1/{}",
        arkret::canonical::canonical_sha256(&(
            &edge.config().arkret.applet_id,
            authentication.operation_id,
            authentication.direction,
            &authentication.source_id,
            &authentication.destination_id,
            &authentication.idempotency_key,
        ))?
    );
    let binding = authentication
        .stable_digest()
        .map_err(crate::BridgeError::App)?;
    let pending = Receipt {
        body_digest: body_digest.clone(),
        authentication,
        authentication_digest: binding.clone(),
        outcome: None,
    };
    let pending_raw = serde_json::to_string(&pending)?;
    loop {
        let old = store.load(&key)?;
        if let Some(raw) = &old {
            let prior: Receipt = serde_json::from_str(raw)?;
            if !prior.matches(&body_digest, &binding)? {
                return Ok(None);
            }
            if let Some(outcome) = prior.outcome {
                return Ok(Some(outcome));
            }
            break;
        }
        if store.compare_exchange_batch(
            &[(key.clone(), None)],
            &[(key.clone(), Some(pending_raw.clone()))],
        )? {
            break;
        }
    }
    edge.install_verified_managed_completion(verified)?;
    loop {
        let raw = store.load(&key)?.ok_or_else(|| {
            crate::BridgeError::App("durable completion receipt disappeared".into())
        })?;
        let mut prior: Receipt = serde_json::from_str(&raw)?;
        if !prior.matches(&body_digest, &binding)? {
            return Ok(None);
        }
        if let Some(outcome) = prior.outcome {
            return Ok(Some(outcome));
        }
        let outcome = AppletTransactionOutcome::Accepted {
            committed_event_refs: Vec::new(),
            rejections: Vec::new(),
            retry_after_ms: None,
        };
        prior.outcome = Some(outcome.clone());
        if store.compare_exchange_batch(
            &[(key.clone(), Some(raw))],
            &[(key.clone(), Some(serde_json::to_string(&prior)?))],
        )? {
            return Ok(Some(outcome));
        }
    }
}
