//! Privileged manager archive capability, separate from Device authoring custody.
use super::*;

/// The embedding Service must provide an independently unlocked manager vault.
/// This capability must never be passed to a Device Runtime or backed by its
/// generic authoring KEK. There is deliberately no successful default adapter.
#[async_trait::async_trait]
pub trait ManagerArchiveCustody: Send + Sync {
    /// Return a stable public key only after its independent private key is durable.
    async fn prepare_creation_key(
        &self,
        subject_key: &str,
        request: &AppletManagedActorAuthoringRequest,
    ) -> Result<[u8; 32]>;

    /// Durably bind the held private key to the complete identity and original declaration.
    async fn bind_creation_recipient(
        &self,
        subject_key: &str,
        actor: &arkret::RealmActorId,
        recipient: &arkret::RealmActorContentBackupRecipient,
    ) -> Result<()>;

    /// Generate and retain a fresh incoming recipient before its public offer.
    async fn prepare_manager_recipient(
        &self,
        plan: &ManagementTransferPlan,
        did: &Did,
    ) -> Result<arkret::RealmActorContentBackupRecipient>;

    /// Complete the real inventory-bound HPKE transfer and secret challenge
    /// confirmation before the old native controller can be changed or released.
    /// The adapter must authenticate the Station inventory, include all immutable
    /// first-PUT custody and pending intents, and retain the exact confirmation.
    async fn confirm_outgoing_handover(&self, offer: &ManagementTransferOffer) -> Result<()>;

    /// Return the real new-Service signed acceptance only after durable import,
    /// full native inventory equality and the HPKE challenge/HMAC confirmation.
    /// Public descriptors, counters, copied ACK journals or operator flags alone
    /// cannot satisfy this operation. Runtime rechecks every native control field.
    async fn accept_manager_handover(
        &self,
        plan: &ManagementTransferPlan,
        recipient: &arkret::RealmActorContentBackupRecipient,
        current: &arkret::identity::VerifiedRealmActorMaterial,
        creation: &arkret::identity::VerifiedRealmActorMaterial,
        next_resolution: &ResolutionCommitment,
        method_history_evidence: &arkret::AppletManagedActorMethodHistoryEvidence,
    ) -> Result<arkret::RealmActorManagerChangePayload>;
}
