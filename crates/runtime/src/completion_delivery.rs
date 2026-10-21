//! Shared admission of a pushed, historical Realm actor creation completion.
//! Framework adapters supply HTTP coordinates; they do not select authority,
//! registration epochs, or reconstruct the delivery authentication transcript.
use arkret::signatures::generated::http_signature_contract::HttpSignatureScenario;
use arkret::signatures::http_signature::{
    Component, HttpMessageVerificationError, SignaturePolicyError, SignatureVerificationPolicy,
    SignedRequestParts, parse_signature_input, public_key_from_bytes,
    validate_signed_canonical_json_body, verify_http_content_digest,
    verify_signed_canonical_json_message,
};
use arkret::{
    AppletAuthoringTransactionRequestBody, AppletDeliveryAuthenticationRecord,
    AppletDeliveryDirection, DidCoreId, DidUrl, Hash, HttpMessageSignatureAlgorithm,
    ServiceOperationId,
};
use chrono::Utc;

use crate::{ArkretEdge, BridgeError, VerifiedManagedCompletion};

/// Registered rejection code and diagnostic from shared completion admission.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CompletionAdmissionError {
    pub code: &'static str,
    pub message: String,
}

impl CompletionAdmissionError {
    fn invalid(message: impl std::fmt::Display) -> Self {
        Self {
            code: "http_signature_invalid",
            message: message.to_string(),
        }
    }
}
impl From<BridgeError> for CompletionAdmissionError {
    fn from(error: BridgeError) -> Self {
        Self::invalid(error)
    }
}
impl From<HttpMessageVerificationError> for CompletionAdmissionError {
    fn from(error: HttpMessageVerificationError) -> Self {
        let code = match &error {
            HttpMessageVerificationError::MissingHeader(_) => "http_signature_required",
            HttpMessageVerificationError::Policy(
                SignaturePolicyError::InvalidValidityWindow
                | SignaturePolicyError::CreatedInFuture
                | SignaturePolicyError::CreatedTooOld
                | SignaturePolicyError::Expired,
            ) => "signature_window_invalid",
            _ => "http_signature_invalid",
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

/// Verify exact content integrity and the canonical wire/envelope policy
/// before any business JSON deserialization, authority lookup or local write.
/// This is a byte-level prerequisite, not proof of signer authority.
pub fn precheck_applet_completion_envelope(
    headers: &[(String, String)],
    raw_body: &[u8],
) -> Result<(), CompletionAdmissionError> {
    let digest = verify_http_content_digest(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        raw_body,
        true,
    )?;
    validate_signed_canonical_json_body(
        headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding")),
        raw_body,
    )?;
    let parts = SignedRequestParts {
        method: String::new(),
        target_uri: String::new(),
        authority: String::new(),
        path: String::new(),
        headers: headers.to_vec(),
        body_digest: None,
    };
    let input = parts.header("signature-input").ok_or_else(|| {
        CompletionAdmissionError::from(HttpMessageVerificationError::MissingHeader(
            "Signature-Input",
        ))
    })?;
    parts.header("signature").ok_or_else(|| {
        CompletionAdmissionError::from(HttpMessageVerificationError::MissingHeader("Signature"))
    })?;
    let input = parse_signature_input(&input).map_err(CompletionAdmissionError::invalid)?;
    let policy =
        SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::AppletTransactionV1, &[])
            .map_err(|error| {
                CompletionAdmissionError::from(HttpMessageVerificationError::Policy(error))
            })?;
    policy
        .validate(
            &input,
            digest.as_ref().map(|digest| digest.wire_value.as_str()),
            Utc::now().timestamp(),
        )
        .map_err(|error| {
            CompletionAdmissionError::from(HttpMessageVerificationError::Policy(error))
        })?;
    Ok(())
}

impl ArkretEdge {
    /// Authenticate every delivery before consulting an outcome cache. This
    /// proves the local frozen candidate, current governance and manager,
    /// exact historical acceptance, and the current canonical HTTP signature.
    pub async fn admit_managed_authoring_delivery(
        &self,
        request: &SignedRequestParts,
        raw_body: &[u8],
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<VerifiedManagedCompletion, CompletionAdmissionError> {
        precheck_applet_completion_envelope(&request.headers, raw_body)?;
        let mut completion = self.verify_managed_completion(body).await?;
        let record = authenticate_http_delivery(request, raw_body, &completion)?;
        completion.retained_outcome = match self
            .journal
            .managed_delivery_admission(body, &record)?
        {
            crate::managed_authoring::ManagedDeliveryAdmission::New => None,
            crate::managed_authoring::ManagedDeliveryAdmission::Accepted(outcome) => Some(outcome),
            crate::managed_authoring::ManagedDeliveryAdmission::Conflict => {
                return Err(CompletionAdmissionError {
                    code: "duplicate_conflict",
                    message: "completion differs from its durable delivery receipt".into(),
                });
            }
        };
        completion.delivery = Some(record);
        Ok(completion)
    }
}

fn authenticate_http_delivery(
    request: &SignedRequestParts,
    raw_body: &[u8],
    completion: &VerifiedManagedCompletion,
) -> Result<AppletDeliveryAuthenticationRecord, CompletionAdmissionError> {
    let expected = arkret::canonical::canonical_json_bytes(&completion.body)
        .map_err(CompletionAdmissionError::invalid)?;
    if raw_body != expected {
        return Err(CompletionAdmissionError::invalid(
            "completion body is not the exact canonical parsed object",
        ));
    }
    let input = parse_signature_input(&request.header("signature-input").ok_or_else(|| {
        CompletionAdmissionError::from(HttpMessageVerificationError::MissingHeader(
            "signature-input",
        ))
    })?)
    .map_err(CompletionAdmissionError::invalid)?;
    let method = DidUrl::new(input.key_id.clone()).map_err(CompletionAdmissionError::invalid)?;
    let now = Utc::now();
    let key = completion.route.station_key(&method, now)?;
    verify_delivery_signature(
        request,
        raw_body,
        &key,
        completion.route.authority.current_service_id(),
        &completion.destination_id,
        &completion.registration_epoch,
        now.timestamp(),
    )
}

// Only the opaque verified completion selects these anchors in production.
fn verify_delivery_signature(
    request: &SignedRequestParts,
    raw_body: &[u8],
    key: &arkret::signatures::PublicKeyMaterial,
    expected_source: &DidCoreId,
    expected_destination: &DidCoreId,
    registration_epoch: &Hash,
    now: i64,
) -> Result<AppletDeliveryAuthenticationRecord, CompletionAdmissionError> {
    let required = |name: &'static str| {
        request.header(name).ok_or_else(|| {
            CompletionAdmissionError::from(HttpMessageVerificationError::MissingHeader(name))
        })
    };
    let input = parse_signature_input(&required("signature-input")?)
        .map_err(CompletionAdmissionError::invalid)?;
    let method = DidUrl::new(input.key_id.clone()).map_err(CompletionAdmissionError::invalid)?;
    let source = DidCoreId::new(required("source-service-id")?)
        .map_err(CompletionAdmissionError::invalid)?;
    let destination = DidCoreId::new(required("destination-service-id")?)
        .map_err(CompletionAdmissionError::invalid)?;
    let signer_did = arkret::verification_method_did(method.as_str())
        .map_err(CompletionAdmissionError::invalid)?;
    let signer =
        arkret::project_did_to_core_id(&signer_did).map_err(CompletionAdmissionError::invalid)?;
    if source != *expected_source
        || signer != source
        || destination != *expected_destination
        || required("arkret-operation")? != ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1
        || required("idempotency-key")?.trim().is_empty()
    {
        return Err(CompletionAdmissionError::invalid(
            "completion HTTP coordinates differ from verified authority and body",
        ));
    }
    // The framework selects the registered transaction route. Keep the exact
    // externally mounted path in the signature base (including a host prefix).
    if request.method != "POST" {
        return Err(CompletionAdmissionError::invalid(
            "completion HTTP method is not POST",
        ));
    }
    let key_bytes = key
        .ed25519_bytes()
        .map_err(CompletionAdmissionError::invalid)?;
    let public_key =
        public_key_from_bytes(&key_bytes).map_err(CompletionAdmissionError::invalid)?;
    let policy =
        SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::AppletTransactionV1, &[])
            .map_err(|error| {
                CompletionAdmissionError::from(HttpMessageVerificationError::Policy(error))
            })?;
    let verified = verify_signed_canonical_json_message(
        &request.method,
        &request.target_uri,
        &request.authority,
        &request.path,
        request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        request.header("content-encoding").is_some(),
        raw_body,
        &public_key,
        &policy,
        now,
    )?;
    let signature = verified.signature_input;
    let algorithm = match signature.algorithm.as_str() {
        "ed25519" => HttpMessageSignatureAlgorithm::Ed25519,
        _ => {
            return Err(CompletionAdmissionError::invalid(
                "unsupported verified completion signature algorithm",
            ));
        }
    };
    Ok(AppletDeliveryAuthenticationRecord {
        operation_id: ServiceOperationId::from_wire(
            ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
        )
        .ok_or_else(|| CompletionAdmissionError::invalid("missing operation descriptor"))?,
        direction: AppletDeliveryDirection::NodeToApplet,
        source_id: source,
        destination_id: destination,
        signature_label: signature.label,
        verification_method: method,
        verification_key_digest: Hash::new(arkret::canonical::canonical_digest(&key_bytes))
            .map_err(CompletionAdmissionError::invalid)?,
        signature_algorithm: algorithm,
        registration_epoch: registration_epoch.clone(),
        idempotency_key: required("idempotency-key")?,
        content_digest: verified
            .content_digest
            .ok_or_else(|| CompletionAdmissionError::invalid("missing verified Content-Digest"))?
            .wire_value,
        covered_components: signature
            .covered_components
            .iter()
            .map(Component::canonical_name)
            .collect(),
        created: signature.created,
        expires: signature.expires,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use arkret::http_signature::{
        ContentDigest, ContentDigestAlgorithm, sign_http_message_for_scenario,
    };
    use arkret::{
        AppletTransactionOutcome, IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity,
        IdempotencyWindow,
    };
    use ed25519_dalek::SigningKey;

    use super::*;

    const NOW: i64 = 1_800_000_000;
    fn signature_request(
        body: &[u8],
        created: i64,
    ) -> (SignedRequestParts, arkret::signatures::PublicKeyMaterial) {
        let key = SigningKey::from_bytes(&[0x62; 32]);
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        let mut request = SignedRequestParts {
            method: "POST".into(),
            target_uri: "https://applet.example/_arkret/edge/applet/transactions".into(),
            authority: "applet.example".into(),
            path: "/_arkret/edge/applet/transactions".into(),
            headers: vec![
                (
                    "arkret-operation".into(),
                    ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1.into(),
                ),
                (
                    "source-service-id".into(),
                    "ak:did_core:webvh:zstation".into(),
                ),
                (
                    "destination-service-id".into(),
                    "ak:did_core:webvh:zapplet".into(),
                ),
                ("idempotency-key".into(), "completion-1".into()),
                ("content-digest".into(), digest.wire_value.clone()),
            ],
            body_digest: Some(digest.wire_value),
        };
        let signed = sign_http_message_for_scenario(
            &request,
            HttpSignatureScenario::AppletTransactionV1,
            &[],
            "sig1",
            "did:webvh:zstation:station.example#key-1",
            created,
            &key,
        )
        .unwrap();
        request
            .headers
            .push(("signature-input".into(), signed.signature_input_header));
        request
            .headers
            .push(("signature".into(), signed.signature_header));
        (
            request,
            arkret::signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        )
    }
    fn verify(
        request: &SignedRequestParts,
        body: &[u8],
        key: &arkret::signatures::PublicKeyMaterial,
    ) -> Result<AppletDeliveryAuthenticationRecord, CompletionAdmissionError> {
        verify_delivery_signature(
            request,
            body,
            key,
            &DidCoreId::new("ak:did_core:webvh:zstation").unwrap(),
            &DidCoreId::new("ak:did_core:webvh:zapplet").unwrap(),
            &Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            NOW,
        )
    }

    #[test]
    fn fresh_signature_times_preserve_completion_outcome_and_full_audit_records() {
        let body = b"{}";
        let (first, key) = signature_request(body, NOW - 10);
        let (retry, _) = signature_request(body, NOW);
        let first = verify(&first, body, &key).unwrap();
        let retry = verify(&retry, body, &key).unwrap();
        assert_ne!(first.created, retry.created);
        assert_ne!(first.expires, retry.expires);
        let binding = first.stable_digest().unwrap();
        assert_eq!(binding, retry.stable_digest().unwrap());
        let window = IdempotencyWindow::new(Duration::from_secs(300));
        let identity = IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            first.source_id.clone(),
            first.destination_id.clone(),
            first.idempotency_key.clone(),
        );
        let body_hash = Hash::new(arkret::canonical::canonical_digest(body)).unwrap();
        assert!(matches!(
            window.claim(&identity, &body_hash, binding.as_str()),
            IdempotencyClaim::Fresh
        ));
        let outcome = AppletTransactionOutcome::Accepted {
            committed_event_refs: Vec::new(),
            rejections: Vec::new(),
            retry_after_ms: None,
        };
        assert!(window.complete(&identity, outcome.clone()));
        match window.claim(
            &identity,
            &body_hash,
            retry.stable_digest().unwrap().as_str(),
        ) {
            IdempotencyClaim::Duplicate {
                outcome: retained, ..
            } => assert_eq!(retained, outcome),
            other => panic!("freshly re-signed exact delivery did not recover outcome: {other:?}"),
        }
        assert_eq!(serde_json::to_value(retry).unwrap()["created"], NOW);
    }

    #[test]
    fn expired_signature_cannot_use_a_stable_cached_binding() {
        let (old, key) = signature_request(b"{}", NOW - 600);
        assert_eq!(
            verify(&old, b"{}", &key).unwrap_err().code,
            "signature_window_invalid"
        );
        let (fresh, _) = signature_request(b"{}", NOW);
        assert!(verify(&fresh, b"{}", &key).is_ok());
    }

    #[test]
    fn canonical_body_operation_source_destination_and_key_are_reverified() {
        let (request, key) = signature_request(b"{}", NOW);
        for (name, value) in [
            (
                "arkret-operation",
                "ak.self.applet.bot.command.provision.v1",
            ),
            ("source-service-id", "ak:did_core:webvh:zother"),
            ("destination-service-id", "ak:did_core:webvh:zother"),
            ("content-encoding", "identity"),
        ] {
            let mut changed = request.clone();
            changed.headers.retain(|(header, _)| header != name);
            changed.headers.push((name.into(), value.into()));
            assert!(verify(&changed, b"{}", &key).is_err(), "{name}");
        }
        assert!(verify(&request, b"{ }", &key).is_err());
        assert!(verify(&request, b"{\"changed\":true}", &key).is_err());
        let wrong = arkret::signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[0x63; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        assert!(verify(&request, b"{}", &wrong).is_err());
    }
}
