//! Typed external-effect execution boundary.
//!
//! The protocol's only irreversible decision is the qCOMMIT contained in the
//! SDK-owned [`ExecutionBundle`].  A bridge must never manufacture a value,
//! infer a commit from local state, or treat delivery of a bundle as another
//! commit point.  This module therefore accepts only the closed SDK bundle,
//! validates it before handing it to an adapter, and exposes no alternate
//! protocol representation.

use arkret_models_collaboration::protocol_journey::{
    AttemptAdvanceValue, AttemptCleanupValue, ExecutionBundle, HostTransferPrepareValue,
    HostTransferValue, JournalValidationOutcome, JournalValidationReceipt,
    JournalValidationRequest, OperationControlEffect, OrdinaryExternalEffect,
};
use arkret_wire::Did;
use chrono::TimeDelta;

use crate::error::{BridgeError, Result};

fn invalid_journal(message: &str) -> BridgeError {
    BridgeError::Arkret(format!("invalid operation-control journal: {message}"))
}

fn validate_journal_request_binding(
    request: &JournalValidationRequest,
    destination: &Did,
) -> Result<()> {
    let authorization = &request.registry_authorization;
    let core = &request.validation_core;
    let journal = &request.authenticated_encrypted_journal;
    let aad = &journal.aad_core;

    if &core.destination != destination || &journal.recipient_service_id != destination {
        return Err(invalid_journal(
            "destination does not equal the local service",
        ));
    }
    if authorization.core.registry_digest != core.registry_digest
        || authorization.core.pair_registry_id != core.pair_registry_id
        || authorization.core.pair_key != core.pair_key
        || authorization.core.operation_id != core.operation_id
        || authorization.registry_statement.registry_digest != core.registry_digest
        || authorization.registry_statement.pair_registry_id != core.pair_registry_id
        || authorization.registry_statement.core.pair_key != core.pair_key
    {
        return Err(invalid_journal(
            "registry authorization does not match the validation core",
        ));
    }
    if journal.plaintext_digest != core.payload_digest
        || aad.registry_digest != core.registry_digest
        || aad.pair_registry_id != core.pair_registry_id
        || aad.pair_key != core.pair_key
        || aad.operation_id != core.operation_id
        || aad.attempt_sequence != core.attempt_sequence
        || aad.effect_id != core.effect_id
        || aad.effect_digest != core.effect_digest
        || aad.payload_digest != core.payload_digest
        || aad.destination != core.destination
        || aad.expected_host_service_id != core.expected_host_service_id
        || aad.expected_host_epoch != core.expected_host_epoch
        || aad.resulting_host_service_id != core.resulting_host_service_id
        || aad.resulting_host_epoch != core.resulting_host_epoch
        || aad.predecessor_head_digest != core.predecessor_head_digest
    {
        return Err(invalid_journal(
            "authenticated journal AAD does not match the validation core",
        ));
    }
    validate_host_fence(
        &core.effect,
        &core.destination,
        &core.expected_host_service_id,
        core.expected_host_epoch,
        &core.resulting_host_service_id,
        core.resulting_host_epoch,
    )
}

fn validate_host_fence(
    effect: &OperationControlEffect,
    destination: &Did,
    expected_host_service_id: &Did,
    expected_host_epoch: u64,
    resulting_host_service_id: &Did,
    resulting_host_epoch: u64,
) -> Result<()> {
    match effect {
        OperationControlEffect::HostTransferPrepare(effect) => {
            if destination != &effect.to_host_service_id
                || expected_host_service_id != &effect.from_host_service_id
                || resulting_host_service_id != &effect.from_host_service_id
                || expected_host_epoch != effect.from_host_epoch
                || resulting_host_epoch != effect.from_host_epoch
                || effect.from_host_epoch.checked_add(1) != Some(effect.to_host_epoch)
            {
                return Err(invalid_journal(
                    "host-transfer prepare has an invalid host fence",
                ));
            }
        }
        OperationControlEffect::HostTransfer(effect) => {
            if destination != &effect.to_host_service_id
                || expected_host_service_id != &effect.from_host_service_id
                || resulting_host_service_id != &effect.to_host_service_id
                || expected_host_epoch != effect.from_host_epoch
                || resulting_host_epoch != effect.to_host_epoch
                || effect.from_host_epoch.checked_add(1) != Some(effect.to_host_epoch)
            {
                return Err(invalid_journal(
                    "host transfer has an invalid host transition fence",
                ));
            }
        }
        OperationControlEffect::OrdinaryExternal(_)
        | OperationControlEffect::AttemptCleanup(_)
        | OperationControlEffect::AttemptAdvance(_) => {
            if expected_host_service_id != resulting_host_service_id
                || expected_host_epoch != resulting_host_epoch
            {
                return Err(invalid_journal(
                    "non-transfer effect changes the operation host fence",
                ));
            }
        }
    }
    Ok(())
}

fn validation_receipt(outcome: &JournalValidationOutcome) -> &JournalValidationReceipt {
    match outcome {
        JournalValidationOutcome::Accepted { receipt }
        | JournalValidationOutcome::Duplicate { receipt } => receipt,
    }
}

/// Destination-side decryptor and schema validator for qDA preflight.
///
/// Implementations must authenticate the committed registry authorization,
/// recompute the journal root and AAD digest, decrypt with the exact referenced
/// key, validate the selected SDK plaintext schema and recompute every typed
/// effect digest before signing the receipt.  Preflight must not execute or
/// reserve the effect.
pub trait OperationControlJournalValidator {
    fn destination_service_id(&self) -> &Did;

    fn validate_journal(
        &self,
        request: &JournalValidationRequest,
    ) -> Result<JournalValidationOutcome>;
}

/// Validate a journal without executing it and bind the returned receipt to
/// the exact request.
pub fn preflight_operation_control_journal<V>(
    request: JournalValidationRequest,
    validator: &V,
) -> Result<JournalValidationOutcome>
where
    V: OperationControlJournalValidator,
{
    validate_journal_request_binding(&request, validator.destination_service_id())?;
    let outcome = validator.validate_journal(&request)?;
    let receipt = validation_receipt(&outcome);
    let core = &request.validation_core;
    let journal = &request.authenticated_encrypted_journal;
    let lifetime = receipt
        .expires_at
        .signed_duration_since(receipt.validated_at);
    if receipt.validation_request_id != request.validation_request_id
        || receipt.journal_root != core.journal_root
        || receipt.effect_digest != core.effect_digest
        || receipt.payload_digest != core.payload_digest
        || receipt.destination != core.destination
        || receipt.issuer != core.destination
        || receipt.recipient_key_ref != journal.recipient_key_ref
        || lifetime <= TimeDelta::zero()
        || lifetime > TimeDelta::minutes(5)
    {
        return Err(invalid_journal(
            "validation receipt does not bind the exact live request",
        ));
    }
    Ok(outcome)
}

/// An SDK execution bundle whose structure and protocol authority have passed
/// validation.
///
/// Construction is deliberately private: bridge adapters can execute only a
/// bundle admitted by [`execute_operation_control_effect`].
#[derive(Clone, Debug)]
pub struct VerifiedExecutionBundle(ExecutionBundle);

impl VerifiedExecutionBundle {
    fn verify<V>(bundle: ExecutionBundle, verifier: &V) -> Result<Self>
    where
        V: ExecutionBundleAuthorityVerifier,
    {
        bundle
            .validate()
            .map_err(|error| BridgeError::Arkret(format!("invalid execution bundle: {error}")))?;
        verifier.verify_authority(&bundle)?;
        Ok(Self(bundle))
    }

    /// The exact validated bundle.  The caller must not mutate it or derive a
    /// second commit decision from it.
    pub fn bundle(&self) -> &ExecutionBundle {
        &self.0
    }

    /// The exact closed effect selected by the q-committed value.
    pub fn effect(&self) -> &OperationControlEffect {
        &self.0.value_core.effect
    }
}

fn validate_destination_binding(bundle: &ExecutionBundle, destination: &Did) -> Result<()> {
    let value = &bundle.value_core;
    let journal = &bundle.authenticated_encrypted_journal;
    let receipt = &bundle.journal_validation_receipt;
    let aad = &journal.aad_core;

    if &value.destination != destination
        || &journal.recipient_service_id != destination
        || &receipt.destination != destination
        || &receipt.issuer != destination
        || receipt.recipient_key_ref != journal.recipient_key_ref
        || receipt.journal_root != value.journal_root
        || receipt.effect_digest != value.effect_digest
        || receipt.payload_digest != value.payload_digest
        || journal.plaintext_digest != value.payload_digest
        || aad.registry_digest != value.registry_digest
        || aad.pair_registry_id != value.pair_registry_id
        || aad.pair_key != value.pair_key
        || aad.operation_id != value.operation_id
        || aad.attempt_sequence != value.attempt_sequence
        || aad.effect_id != value.effect_id
        || aad.effect_digest != value.effect_digest
        || aad.payload_digest != value.payload_digest
        || aad.destination != value.destination
        || aad.expected_host_service_id != value.expected_host_service_id
        || aad.expected_host_epoch != value.expected_host_epoch
        || aad.resulting_host_service_id != value.resulting_host_service_id
        || aad.resulting_host_epoch != value.resulting_host_epoch
        || aad.predecessor_head_digest != value.predecessor_head_digest
    {
        return Err(BridgeError::Arkret(
            "execution bundle journal is not bound to the committed value and local destination"
                .to_owned(),
        ));
    }

    validate_host_fence(
        &value.effect,
        &value.destination,
        &value.expected_host_service_id,
        value.expected_host_epoch,
        &value.resulting_host_service_id,
        value.resulting_host_epoch,
    )
}

/// Trust-store-backed verifier for all signatures and historical authority in
/// an SDK execution bundle.
///
/// Implementations must verify the committed registry authorization, the live
/// destination journal-validation receipt, every qDA/PBFT witness and every
/// certificate in the per-view ancestry.  Structural validation alone is not
/// authority validation and cannot implement this trait correctly.
pub trait ExecutionBundleAuthorityVerifier {
    fn verify_authority(&self, bundle: &ExecutionBundle) -> Result<()>;
}

/// Destination adapter for the closed operation-control effect set.
///
/// Implementations must make exact replay of the same effect id idempotent
/// and return destination-signed terminal evidence through their owning
/// service.  Separate required methods prevent an administrative effect from
/// falling through to an ordinary external-operation handler.  Each method
/// must decrypt the exact journal and recheck its SDK schema and payload digest
/// before mutating destination state.
pub trait OperationControlEffectExecutor {
    type Output;

    /// The local service identity allowed to decrypt and execute the bundle.
    fn destination_service_id(&self) -> &Did;

    fn execute_ordinary_external(
        &self,
        bundle: &VerifiedExecutionBundle,
        effect: &OrdinaryExternalEffect,
    ) -> Result<Self::Output>;

    fn execute_attempt_cleanup(
        &self,
        bundle: &VerifiedExecutionBundle,
        effect: &AttemptCleanupValue,
    ) -> Result<Self::Output>;

    fn execute_attempt_advance(
        &self,
        bundle: &VerifiedExecutionBundle,
        effect: &AttemptAdvanceValue,
    ) -> Result<Self::Output>;

    fn execute_host_transfer_prepare(
        &self,
        bundle: &VerifiedExecutionBundle,
        effect: &HostTransferPrepareValue,
    ) -> Result<Self::Output>;

    fn execute_host_transfer(
        &self,
        bundle: &VerifiedExecutionBundle,
        effect: &HostTransferValue,
    ) -> Result<Self::Output>;
}

/// Validate a closed SDK bundle, then invoke an app-specific executor.
///
/// A malformed bundle, absent qDA/qCOMMIT binding, or empty per-view ancestry
/// never reaches the executor.  Calling this function does not create a new
/// protocol point of no return; it only acts after the bundle's qCOMMIT has
/// been validated by the SDK.
pub fn execute_operation_control_effect<E, V>(
    bundle: ExecutionBundle,
    verifier: &V,
    executor: &E,
) -> Result<E::Output>
where
    E: OperationControlEffectExecutor,
    V: ExecutionBundleAuthorityVerifier,
{
    let bundle = VerifiedExecutionBundle::verify(bundle, verifier)?;
    validate_destination_binding(bundle.bundle(), executor.destination_service_id())?;
    match bundle.effect() {
        OperationControlEffect::OrdinaryExternal(effect) => {
            executor.execute_ordinary_external(&bundle, effect)
        }
        OperationControlEffect::AttemptCleanup(effect) => {
            executor.execute_attempt_cleanup(&bundle, effect)
        }
        OperationControlEffect::AttemptAdvance(effect) => {
            executor.execute_attempt_advance(&bundle, effect)
        }
        OperationControlEffect::HostTransferPrepare(effect) => {
            executor.execute_host_transfer_prepare(&bundle, effect)
        }
        OperationControlEffect::HostTransfer(effect) => {
            executor.execute_host_transfer(&bundle, effect)
        }
    }
}
