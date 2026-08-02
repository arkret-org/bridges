//! Typed external-effect execution boundary.
//!
//! The protocol's only irreversible decision is the qCOMMIT contained in the
//! SDK-owned [`ExecutionBundle`].  A bridge must never manufacture a value,
//! infer a commit from local state, or treat delivery of a bundle as another
//! commit point.  This module therefore accepts only the closed SDK bundle,
//! validates it before handing it to an adapter, and exposes no raw-JSON or
//! compatibility input path.

use arkret_models_collaboration::protocol_journey::ExecutionBundle;

use crate::error::{BridgeError, Result};

/// An SDK execution bundle whose structural qDA/qCOMMIT binding has passed
/// [`ExecutionBundle::validate`].
///
/// Construction is deliberately private: bridge adapters can execute only a
/// bundle admitted by [`execute_external_effect`] or
/// [`ValidatedExecutionBundle::try_from_bundle`].  Signature/replica
/// authority is still the responsibility of the SDK/service authority that
/// supplied the bundle; this runtime does not recreate that verifier.
#[derive(Clone, Debug)]
pub struct ValidatedExecutionBundle(ExecutionBundle);

impl ValidatedExecutionBundle {
    /// Validate and retain an exact SDK-owned execution bundle.
    pub fn try_from_bundle(bundle: ExecutionBundle) -> Result<Self> {
        bundle
            .validate()
            .map_err(|error| BridgeError::Arkret(format!("invalid execution bundle: {error}")))?;
        Ok(Self(bundle))
    }

    /// The exact validated bundle.  The caller must not mutate it or derive a
    /// second commit decision from it.
    pub fn bundle(&self) -> &ExecutionBundle {
        &self.0
    }
}

/// App-specific external-effect adapter.
///
/// Implementations must make exact replay of the same effect id idempotent
/// and obtain destination-signed terminal evidence through their owning
/// service.  This boundary supplies no alternate persistence or protocol
/// representation.
pub trait ExternalEffectExecutor {
    type Output;

    fn execute(&self, bundle: &ValidatedExecutionBundle) -> Result<Self::Output>;
}

/// Validate a closed SDK bundle, then invoke an app-specific executor.
///
/// A malformed bundle, absent qDA/qCOMMIT binding, or empty per-view ancestry
/// never reaches the executor.  Calling this function does not create a new
/// protocol point of no return; it only acts after the bundle's qCOMMIT has
/// been validated by the SDK.
pub fn execute_external_effect<E>(bundle: ExecutionBundle, executor: &E) -> Result<E::Output>
where
    E: ExternalEffectExecutor,
{
    let bundle = ValidatedExecutionBundle::try_from_bundle(bundle)?;
    executor.execute(&bundle)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use arkret_models_collaboration::protocol_journey::{
        ConsensusEnvelope, ConsensusEnvelopeDomain, ConsensusPhase, EffectValueCore,
        ExecutionBundle, PerViewCertificate, PreparedCertificate, PreparedCertificateDomain,
        PreparedCertificateKind, ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature,
        QcommitCertificate, QdaCertificate, QdaReceipt, QdaReceiptDomain,
    };
    use arkret_wire::{Base64UrlString, Did, DidUrl, Hash};
    use chrono::{TimeZone, Utc};

    use super::{ExternalEffectExecutor, ValidatedExecutionBundle, execute_external_effect};
    use crate::Result;

    fn hash(nibble: char) -> Hash {
        Hash::new(format!("sha256:{}", nibble.to_string().repeat(64))).unwrap()
    }

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:{name}.example")).unwrap()
    }

    fn signature(name: &str) -> ProtocolSignature {
        ProtocolSignature {
            verification_method: DidUrl::new(format!("did:webvh:{name}.example#key-1")).unwrap(),
            created_at: Utc.with_ymd_and_hms(2026, 8, 3, 0, 0, 0).unwrap(),
            jws: Base64UrlString::new("AQ".to_owned()).unwrap(),
        }
    }

    fn bundle() -> ExecutionBundle {
        let pair_registry_id = ProtocolOpaqueId::new("registry".to_owned()).unwrap();
        let operation_id =
            ProtocolOperationId::new("ak:operation:external-effect".to_owned()).unwrap();
        let effect_id = ProtocolOpaqueId::new("effect".to_owned()).unwrap();
        let pair_key = hash('1');
        let journal_root = hash('2');
        let destination = did("destination");
        let value = EffectValueCore {
            pair_registry_id: pair_registry_id.clone(),
            pair_key: pair_key.clone(),
            operation_id: operation_id.clone(),
            attempt_sequence: 1,
            effect_id: effect_id.clone(),
            effect_digest: hash('3'),
            destination: destination.clone(),
            expected_host_epoch: 7,
            predecessor_head_digest: hash('4'),
            journal_root: journal_root.clone(),
        };
        let value_digest = value.value_digest().unwrap();
        let receipts = ["replica-a", "replica-b", "replica-c"]
            .into_iter()
            .map(|name| QdaReceipt {
                domain: QdaReceiptDomain::V1,
                pair_registry_id: pair_registry_id.clone(),
                pair_key: pair_key.clone(),
                operation_id: operation_id.clone(),
                attempt_sequence: 1,
                effect_id: effect_id.clone(),
                value_digest: value_digest.clone(),
                journal_root: journal_root.clone(),
                destination: destination.clone(),
                expected_host_epoch: 7,
                replica_id: did(name),
                signature: signature(name),
            })
            .collect();
        let qda_certificate = QdaCertificate {
            pair_registry_id: pair_registry_id.clone(),
            pair_key: pair_key.clone(),
            operation_id: operation_id.clone(),
            attempt_sequence: 1,
            effect_id,
            value_digest: value_digest.clone(),
            journal_root,
            destination,
            expected_host_epoch: 7,
            n: 4,
            f: 1,
            quorum: 3,
            receipts,
        };
        let qda_certificate_digest = qda_certificate.digest().unwrap();
        let commits = ["replica-a", "replica-b", "replica-c"]
            .into_iter()
            .map(|name| ConsensusEnvelope {
                domain: ConsensusEnvelopeDomain::V1,
                pair_registry_id: pair_registry_id.clone(),
                pair_key: pair_key.clone(),
                operation_id: operation_id.clone(),
                attempt_sequence: 1,
                view: 1,
                phase: ConsensusPhase::Commit,
                value_digest: value_digest.clone(),
                qda_certificate_digest: qda_certificate_digest.clone(),
                prepared_certificate_digest: None,
                replica_id: did(name),
                signature: signature(name),
            })
            .collect::<Vec<_>>();
        let prepares = commits
            .iter()
            .cloned()
            .map(|mut envelope| {
                envelope.phase = ConsensusPhase::Prepare;
                envelope
            })
            .collect();
        ExecutionBundle {
            value_core: value,
            qda_certificate,
            per_view_certificates: vec![PerViewCertificate::Prepared(PreparedCertificate {
                certificate_kind: PreparedCertificateKind::Prepared,
                domain: PreparedCertificateDomain::V1,
                pair_registry_id: pair_registry_id.clone(),
                pair_key: pair_key.clone(),
                operation_id: operation_id.clone(),
                attempt_sequence: 1,
                view: 1,
                value_digest: value_digest.clone(),
                qda_certificate_digest: qda_certificate_digest.clone(),
                n: 4,
                f: 1,
                quorum: 3,
                prepares,
            })],
            qcommit_certificate: QcommitCertificate {
                pair_registry_id,
                pair_key,
                operation_id,
                attempt_sequence: 1,
                view: 1,
                value_digest,
                qda_certificate_digest,
                n: 4,
                f: 1,
                quorum: 3,
                commits,
            },
            authenticated_encrypted_journal_bytes: Base64UrlString::new("AQ".to_owned()).unwrap(),
        }
    }

    struct RecordingExecutor(Cell<u8>);

    impl ExternalEffectExecutor for RecordingExecutor {
        type Output = ();

        fn execute(&self, _bundle: &ValidatedExecutionBundle) -> Result<Self::Output> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn valid_qcommit_bundle_reaches_executor_once() {
        let executor = RecordingExecutor(Cell::new(0));
        execute_external_effect(bundle(), &executor).unwrap();
        assert_eq!(executor.0.get(), 1);
    }

    #[test]
    fn missing_per_view_ancestry_never_reaches_executor() {
        let executor = RecordingExecutor(Cell::new(0));
        let mut invalid = bundle();
        invalid.per_view_certificates.clear();
        assert!(execute_external_effect(invalid, &executor).is_err());
        assert_eq!(executor.0.get(), 0);
    }

    #[test]
    fn qda_mismatch_never_reaches_executor() {
        let executor = RecordingExecutor(Cell::new(0));
        let mut invalid = bundle();
        invalid.qda_certificate.value_digest = hash('f');
        assert!(execute_external_effect(invalid, &executor).is_err());
        assert_eq!(executor.0.get(), 0);
    }
}
