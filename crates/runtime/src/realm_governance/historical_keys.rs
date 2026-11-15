//! Private historical directory for SDK verification after an encrypted cut opens.

use std::collections::{BTreeMap, BTreeSet};

use arkret::identity::{DidVerificationRelationship, RealmAuthorityKeyDirectory};
use arkret::signatures::PublicKeyMaterial;
use arkret::{AuthenticatedServiceResolution, DidCoreId, DidUrl};
use chrono::{DateTime, Utc};

use super::{RealmRoute, invalid};
use crate::Result;

/// Each lookup verifies native history at the original signature's exact time.
/// These public candidates never establish a Commit's governance or permission.
pub(crate) struct HistoricalStationKeys {
    histories: BTreeMap<DidCoreId, Vec<AuthenticatedServiceResolution>>,
    bundle_pins: BTreeMap<(DidUrl, DateTime<Utc>), [u8; 32]>,
}

impl HistoricalStationKeys {
    fn new(
        known: &BTreeSet<DidCoreId>,
        histories: Vec<AuthenticatedServiceResolution>,
        bundle_pins: BTreeMap<(DidUrl, DateTime<Utc>), [u8; 32]>,
    ) -> Result<Self> {
        let mut by_station: BTreeMap<DidCoreId, Vec<AuthenticatedServiceResolution>> =
            BTreeMap::new();
        for history in histories {
            if history.service_kind != "station" || !known.contains(&history.service_id) {
                return Err(invalid(
                    "historical source is not a verified Realm governor",
                ));
            }
            by_station
                .entry(history.service_id.clone())
                .or_default()
                .push(history);
        }
        if known
            .iter()
            .any(|station| !by_station.contains_key(station))
        {
            return Err(invalid(
                "verified Realm governor lacks public native history",
            ));
        }
        let directory = Self {
            histories: by_station,
            bundle_pins,
        };
        for (method, signed_at) in directory.bundle_pins.keys() {
            if directory.public_key_at(method, *signed_at).is_none() {
                return Err(invalid(
                    "native history contradicts or omits a verified bundle signature pin",
                ));
            }
        }
        Ok(directory)
    }
}

impl RealmAuthorityKeyDirectory for HistoricalStationKeys {
    fn public_key(&self, _method: &DidUrl) -> Option<PublicKeyMaterial> {
        // A present-day method or a plain index cannot prove a historical key.
        None
    }

    fn public_key_at(
        &self,
        method: &DidUrl,
        signed_at: DateTime<Utc>,
    ) -> Option<PublicKeyMaterial> {
        let did = arkret::verification_method_did(method.as_str()).ok()?;
        let station = arkret::project_did_to_core_id(&did).ok()?;
        let mut selected = None;
        let mut selected_bytes = None;
        for history in self.histories.get(&station)? {
            let Ok(document) =
                arkret::identity::authenticated_service_document_at(history, &station, signed_at)
            else {
                continue;
            };
            if document.id != did
                || arkret::identity::validate_verification_method_relationship(
                    &document,
                    method,
                    &did,
                    DidVerificationRelationship::AssertionMethod,
                )
                .is_err()
            {
                continue;
            }
            let key =
                arkret::identity::public_key_material_from_document(&document, method).ok()?;
            let bytes = key.ed25519_bytes().ok()?;
            if selected_bytes.is_some_and(|previous| previous != bytes) {
                return None;
            }
            selected_bytes = Some(bytes);
            selected = Some(key);
        }
        if self
            .bundle_pins
            .get(&(method.clone(), signed_at))
            .is_some_and(|expected| selected_bytes.as_ref() != Some(expected))
        {
            return None;
        }
        selected
    }
}

impl RealmRoute {
    pub(crate) async fn historical_key_directory(&self) -> Result<HistoricalStationKeys> {
        let mut known = BTreeSet::new();
        for generation in 0..=self.bundle.authority_transitions.len() {
            let generation = u64::try_from(generation).map_err(invalid)?;
            let station = self
                .authority
                .authority_service_at(generation)
                .ok_or_else(|| invalid("verified Realm lacks its governor generation"))?;
            known.insert(station.clone());
        }
        let signatures = [
            &self.bundle.genesis_commit.signature,
            &self.bundle.current_assertion.signature,
        ]
        .into_iter()
        .chain(
            self.bundle
                .authority_transitions
                .iter()
                .flat_map(|transition| {
                    [
                        &transition.change_commit.signature,
                        &transition.handoff.old_authority_signature,
                        &transition.handoff.new_authority_acceptance_signature,
                    ]
                }),
        );
        let mut locators = BTreeMap::new();
        let mut bundle_pins = BTreeMap::new();
        for signature in signatures {
            let did = arkret::verification_method_did(signature.verification_method.as_str())
                .map_err(invalid)?;
            let station = arkret::project_did_to_core_id(&did)?;
            if !known.contains(&station) {
                return Err(invalid(
                    "historical locator is outside verified Realm governors",
                ));
            }
            // Only the bundle's actual 2+3*N signature coordinates are old pins.
            // Do not sample its plain fallback at an archive's new point.
            let bytes = self
                .keys
                .public_key_at(&signature.verification_method, signature.created_at)
                .ok_or_else(|| invalid("verified bundle signature has no original exact pin"))?
                .ed25519_bytes()
                .map_err(invalid)?;
            if bundle_pins
                .insert(
                    (signature.verification_method.clone(), signature.created_at),
                    bytes,
                )
                .is_some_and(|previous| previous != bytes)
            {
                return Err(invalid("verified bundle signature pins conflict"));
            }
            locators.entry(station).or_insert(did);
        }
        let mut histories = Vec::new();
        for (station, did) in locators {
            histories.push(if &station == self.authority.current_service_id() {
                self.resolution.clone()
            } else {
                self.client
                    .resolve_service_from_did(&did, arkret::ServiceKind::Station)
                    .await?
            });
        }
        HistoricalStationKeys::new(&known, histories, bundle_pins)
    }
}

/// Acceptance-time governance is additional to the SDK's original crypto
/// verification. Apply it before fetching histories or mutating a vault.
pub(crate) fn validate_archive_commit_tenures(
    manifest: &arkret_models_integration::RealmActorArchiveInventoryManifest,
    authority: &arkret::identity::VerifiedRealmAuthority,
) -> Result<()> {
    if &manifest.realm_actor_id.realm_id != authority.realm_id() {
        return Err(invalid("archive belongs to another verified Realm"));
    }
    for commit in archive_commits(manifest) {
        commit.validate_shape().map_err(invalid)?;
        let did = arkret::verification_method_did(commit.signature.verification_method.as_str())
            .map_err(invalid)?;
        let station = arkret::project_did_to_core_id(&did)?;
        if &commit.realm_id != authority.realm_id()
            || authority.authority_service_at(commit.governance_generation) != Some(&station)
            || !authority.authorizes_issuer_at(
                &station,
                Some(&commit.authority_ref),
                commit.committed_at,
            )
        {
            return Err(invalid(
                "archive Commit is outside its verified Realm governance tenure",
            ));
        }
    }
    Ok(())
}

fn archive_commits(
    manifest: &arkret_models_integration::RealmActorArchiveInventoryManifest,
) -> Vec<&arkret::RealmCommit> {
    use arkret_models_integration::RealmActorArchiveInventoryEntry;

    let mut commits = Vec::new();
    for entry in &manifest.entries {
        match entry {
            RealmActorArchiveInventoryEntry::Series(entry) => commits.push(&entry.source.commit),
            RealmActorArchiveInventoryEntry::Recipient(entry) => {
                commits.push(&entry.declaration.commit);
                if let Some(begin) = &entry.recovery_begin {
                    commits.push(&begin.commit);
                }
            }
            RealmActorArchiveInventoryEntry::Backup(_) => {}
        }
    }
    commits
}

/// Preserve the existing Garth Commit rule: its key is qualified at acceptance,
/// while the SDK addresses that key by the original signature coordinate.
pub(crate) fn validate_archive_commit_coordinates(
    manifest: &arkret_models_integration::RealmActorArchiveInventoryManifest,
    authority: &arkret::identity::VerifiedRealmAuthority,
    keys: &dyn RealmAuthorityKeyDirectory,
) -> Result<()> {
    validate_archive_commit_tenures(manifest, authority)?;
    for commit in archive_commits(manifest) {
        validate_commit_key_times(commit, keys)?;
    }
    Ok(())
}

fn validate_commit_key_times(
    commit: &arkret::RealmCommit,
    keys: &dyn RealmAuthorityKeyDirectory,
) -> Result<()> {
    let method = &commit.signature.verification_method;
    let signed = keys
        .public_key_at(method, commit.signature.created_at)
        .ok_or_else(|| invalid("archive Commit lacks its original signing-time key"))?
        .ed25519_bytes()
        .map_err(invalid)?;
    let accepted = keys
        .public_key_at(method, commit.committed_at)
        .ok_or_else(|| invalid("archive Commit lacks its original acceptance-time key"))?
        .ed25519_bytes()
        .map_err(invalid)?;
    if signed != accepted {
        return Err(invalid(
            "archive Commit signing key was not effective at its acceptance time",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, ServiceRotationInput,
        prepare_service_registration_inception, prepare_service_rotation,
    };
    use rand_chacha::rand_core::SeedableRng as _;
    use serde_json::json;

    use super::*;

    fn unanchored(
        known: &BTreeSet<DidCoreId>,
        histories: Vec<AuthenticatedServiceResolution>,
    ) -> Result<HistoricalStationKeys> {
        HistoricalStationKeys::new(known, histories, BTreeMap::new())
    }

    struct NativeRotation {
        earlier: AuthenticatedServiceResolution,
        later: AuthenticatedServiceResolution,
        method: DidUrl,
        signing: ed25519_dalek::SigningKey,
        original_signing: ed25519_dalek::SigningKey,
        inception_at: DateTime<Utc>,
        signed_at: DateTime<Utc>,
    }

    fn native_rotation(seed: u8, assertion: bool, foreign_controller: bool) -> NativeRotation {
        native_rotation_change(seed, assertion, foreign_controller, false)
    }

    fn native_rotation_change(
        seed: u8,
        assertion: bool,
        foreign_controller: bool,
        replace_method: bool,
    ) -> NativeRotation {
        let at: DateTime<Utc> = "2026-11-15T00:00:00Z".parse().unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let registration = arkret::ServiceRegistrationKey::new(
            arkret::ServiceKind::Station,
            arkret::CanonicalServiceUrl::new("https://archive.example/").unwrap(),
        )
        .unwrap();
        let inception = prepare_service_registration_inception(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.example/".parse().unwrap(),
                registration_key: &registration,
                also_known_as: &[],
                version_created_at: at,
                did_key_fragment: None,
            },
        )
        .unwrap();
        let did = arkret::Did::new(inception.did.clone()).unwrap();
        let issuer = arkret::project_did_to_core_id(&did).unwrap();
        let earlier = arkret::identity::build_authenticated_webvh_service_resolution(
            issuer.clone(),
            "station".into(),
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
            vec![inception.log_entry.clone()],
            vec![],
            at,
        )
        .unwrap();
        let method = if replace_method {
            DidUrl::new(inception.did_key_id.clone()).unwrap()
        } else {
            DidUrl::new(format!("{did}#archive-added-key")).unwrap()
        };
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let multibase = arkret::canonical::ed25519_pubkey_to_did_key_multibase(
            signing.verifying_key().as_bytes(),
        );
        let controller = if foreign_controller {
            "did:web:unrelated-controller.example"
        } else {
            did.as_str()
        };
        let mut state = inception.log_entry["state"].clone();
        let published = json!({
            "id":method,"controller":controller,"type":"Multikey","publicKeyMultibase":multibase,
        });
        if replace_method {
            *state["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|value| value["id"].as_str() == Some(method.as_str()))
                .unwrap() = published;
        } else {
            state["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .push(published);
        }
        if assertion
            && !state["assertionMethod"]
                .as_array()
                .unwrap()
                .contains(&json!(method))
        {
            state["assertionMethod"]
                .as_array_mut()
                .unwrap()
                .push(json!(method));
        }
        let rotated = prepare_service_rotation(&ServiceRotationInput {
            did: did.as_str(),
            previous_entries: std::slice::from_ref(&inception.log_entry),
            state: &state,
            current_update_seed: &inception.next_update_key_seed,
            next_update_public_key_multibase:
                &arkret::canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&[120; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
            version_created_at: at + chrono::Duration::seconds(1),
        })
        .unwrap();
        let signed_at = at + chrono::Duration::seconds(2);
        let later = arkret::identity::build_authenticated_webvh_service_resolution(
            issuer,
            "station".into(),
            serde_json::from_value(state).unwrap(),
            vec![inception.log_entry.clone(), rotated.log_entry],
            vec![],
            signed_at,
        )
        .unwrap();
        NativeRotation {
            earlier,
            later,
            method,
            signing,
            original_signing: ed25519_dalek::SigningKey::from_bytes(&inception.did_key_seed),
            inception_at: at,
            signed_at,
        }
    }

    #[test]
    fn public_native_history_has_no_unqualified_or_pre_inception_key() {
        let at = "2026-11-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let fixture = arkret_test_kit::service_identity::ServiceIdentityFixture::webvh(
            &"https://governor.example/".parse().unwrap(),
            31,
            [71; 32],
            "governor-key",
            at,
            at + chrono::Duration::seconds(5),
        )
        .unwrap();
        let keys = unanchored(
            &BTreeSet::from([fixture.service_id]),
            vec![fixture.resolution],
        )
        .unwrap();
        assert!(keys.public_key(&fixture.verification_method).is_none());
        assert!(
            keys.public_key_at(
                &fixture.verification_method,
                at - chrono::Duration::seconds(1)
            )
            .is_none()
        );
        assert_eq!(
            keys.public_key_at(
                &fixture.verification_method,
                at + chrono::Duration::seconds(2)
            )
            .unwrap()
            .ed25519_bytes()
            .unwrap(),
            fixture.signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn native_rotation_selects_the_method_only_at_its_original_time() {
        let fixture = native_rotation(119, true, false);
        let known = BTreeSet::from([fixture.later.service_id.clone()]);
        let earlier_only = unanchored(&known, vec![fixture.earlier.clone()]).unwrap();
        assert!(
            earlier_only
                .public_key_at(&fixture.method, fixture.signed_at)
                .is_none()
        );
        let keys = unanchored(&known, vec![fixture.earlier, fixture.later]).unwrap();
        assert!(
            keys.public_key_at(&fixture.method, fixture.inception_at)
                .is_none()
        );
        assert_eq!(
            keys.public_key_at(&fixture.method, fixture.signed_at)
                .unwrap()
                .ed25519_bytes()
                .unwrap(),
            fixture.signing.verifying_key().to_bytes()
        );
    }

    #[test]
    fn only_the_independently_verified_governor_namespace_is_loaded() {
        let fixture = native_rotation(119, true, false);
        let unrelated = DidCoreId::new("ak:did_core:web:unrelated-governor.example").unwrap();
        assert!(unanchored(&BTreeSet::from([unrelated]), vec![fixture.later.clone()]).is_err());
        let mut wrong_kind = fixture.later.clone();
        wrong_kind.service_kind = "applet".into();
        let known = BTreeSet::from([fixture.later.service_id.clone()]);
        assert!(unanchored(&known, vec![wrong_kind]).is_err());
        let keys = unanchored(&known, vec![fixture.later]).unwrap();
        assert!(
            keys.public_key_at(
                &DidUrl::new("did:web:unrelated-governor.example#key").unwrap(),
                fixture.signed_at,
            )
            .is_none()
        );
    }

    #[test]
    fn published_native_keys_still_require_assertion_and_the_original_controller() {
        for (assertion, foreign_controller) in [(false, false), (true, true)] {
            let fixture = native_rotation(119, assertion, foreign_controller);
            // These are real, signed native histories with a published key.
            // The rejection must come from its assertion/controller binding.
            let document = arkret::identity::authenticated_service_document_at(
                &fixture.later,
                &fixture.later.service_id,
                fixture.signed_at,
            )
            .unwrap();
            assert!(
                arkret::identity::public_key_material_from_document(&document, &fixture.method)
                    .is_ok()
            );
            let keys = unanchored(
                &BTreeSet::from([fixture.later.service_id.clone()]),
                vec![fixture.later],
            )
            .unwrap();
            assert!(
                keys.public_key_at(&fixture.method, fixture.signed_at)
                    .is_none()
            );
        }
    }

    #[test]
    fn conflicting_native_history_forks_cannot_supply_one_signature_coordinate() {
        let first = native_rotation(119, true, false);
        let second = native_rotation(121, true, false);
        assert_eq!(first.later.service_id, second.later.service_id);
        for fixture in [&first, &second] {
            let keys = unanchored(
                &BTreeSet::from([fixture.later.service_id.clone()]),
                vec![fixture.later.clone()],
            )
            .unwrap();
            assert_eq!(
                keys.public_key_at(&fixture.method, fixture.signed_at)
                    .unwrap()
                    .ed25519_bytes()
                    .unwrap(),
                fixture.signing.verifying_key().to_bytes()
            );
        }
        let keys = unanchored(
            &BTreeSet::from([first.later.service_id.clone()]),
            vec![first.later, second.later],
        )
        .unwrap();
        assert!(keys.public_key_at(&first.method, first.signed_at).is_none());
    }

    #[test]
    fn one_new_native_fork_cannot_replace_an_already_verified_exact_pin() {
        let first = native_rotation(119, true, false);
        let second = native_rotation(121, true, false);
        let known = BTreeSet::from([first.later.service_id.clone()]);
        let old = unanchored(&known, vec![first.later.clone()]).unwrap();
        let pin = old
            .public_key_at(&first.method, first.signed_at)
            .unwrap()
            .ed25519_bytes()
            .unwrap();
        let pins = BTreeMap::from([((first.method, first.signed_at), pin)]);
        assert!(HistoricalStationKeys::new(&known, vec![first.later], pins.clone()).is_ok());
        let replacement = unanchored(&known, vec![second.later.clone()]).unwrap();
        assert!(
            replacement
                .public_key_at(&second.method, second.signed_at)
                .is_some()
        );
        assert!(HistoricalStationKeys::new(&known, vec![second.later], pins).is_err());
    }

    #[test]
    fn an_old_signature_pin_does_not_become_a_plain_key_pin_at_a_new_time() {
        let fixture = native_rotation_change(119, true, false, true);
        let known = BTreeSet::from([fixture.later.service_id.clone()]);
        let original = unanchored(&known, vec![fixture.earlier]).unwrap();
        let old_bytes = original
            .public_key_at(&fixture.method, fixture.inception_at)
            .unwrap()
            .ed25519_bytes()
            .unwrap();
        let pins = BTreeMap::from([((fixture.method.clone(), fixture.inception_at), old_bytes)]);
        let keys = HistoricalStationKeys::new(&known, vec![fixture.later], pins).unwrap();
        let at_new_time = keys
            .public_key_at(&fixture.method, fixture.signed_at)
            .unwrap()
            .ed25519_bytes()
            .unwrap();
        assert_eq!(at_new_time, fixture.signing.verifying_key().to_bytes());
        assert_ne!(at_new_time, old_bytes);
    }

    #[test]
    fn one_station_key_rotation_is_checked_at_signing_and_acceptance_without_equal_times() {
        let fixture = native_rotation_change(119, true, false, true);
        let keys = unanchored(
            &BTreeSet::from([fixture.later.service_id.clone()]),
            vec![fixture.later],
        )
        .unwrap();
        // A real Commit signature can be cryptographically valid at its old
        // signing time while that same Station has rotated before acceptance.
        // This unit checks that key-time boundary, not native admission.
        let formal: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json"
        )))
        .unwrap();
        let original = formal["archive_inventory"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["kind"] == "series")
            .unwrap();
        let mut commit: arkret::RealmCommit =
            serde_json::from_value(original["source"]["commit"].clone()).unwrap();
        let sign =
            |commit: &mut arkret::RealmCommit, signed_at, signing: &ed25519_dalek::SigningKey| {
                commit.commit_id = arkret::RealmCommitId::from_digest(
                    arkret::canonical::sha256_bytes(commit.canonical_id_bytes().unwrap()),
                );
                commit.signature = arkret_signatures::detached_object::sign_detached_object(
                    &arkret::canonical::unsigned_value(commit, &["signature"]).unwrap(),
                    arkret::DetachedSignatureContext::RealmCommit,
                    fixture.method.clone(),
                    signed_at,
                    signing,
                )
                .unwrap();
                commit.validate_content_address().unwrap();
                arkret_signatures::detached_object::verify_detached_object_signature(
                    &commit.signature,
                    &arkret::canonical::unsigned_value(commit, &["signature"]).unwrap(),
                    arkret::DetachedSignatureContext::RealmCommit,
                    &keys.public_key_at(&fixture.method, signed_at).unwrap(),
                )
                .unwrap();
            };
        commit.committed_at = fixture.signed_at;
        sign(&mut commit, fixture.inception_at, &fixture.original_signing);
        assert!(validate_commit_key_times(&commit, &keys).is_err());
        commit.committed_at = fixture.signed_at + chrono::Duration::seconds(1);
        sign(&mut commit, fixture.signed_at, &fixture.signing);
        assert_ne!(commit.signature.created_at, commit.committed_at);
        validate_commit_key_times(&commit, &keys).unwrap();
    }
}
