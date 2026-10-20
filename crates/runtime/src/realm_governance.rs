//! Verified Realm routing shared by managed identity and Device operations.

use arkret::http_client::{Client, HttpMessageSigner};
use arkret::identity::{RealmAuthorityKeyMap, VerifiedRealmActorMaterial, VerifiedRealmAuthority};
use arkret::{ActorId, DidUrl, RealmId};
use arkret_models_integration::{RealmActorMaterialOutcome, RealmActorMaterialRequest};
use chrono::{DateTime, Utc};

use crate::{ArkretEdge, BridgeError, Result};

pub(crate) fn invalid(error: impl std::fmt::Display) -> BridgeError {
    BridgeError::App(error.to_string())
}

pub(crate) fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(invalid)?;
    Ok(arkret::base64url_encode(bytes))
}

pub(crate) struct RealmRoute {
    pub client: Client,
    pub authority: VerifiedRealmAuthority,
    pub resolution: arkret::AuthenticatedServiceResolution,
    pub keys: RealmAuthorityKeyMap,
    pub bundle: arkret::RealmAuthorityBundle,
}

impl ArkretEdge {
    /// The configured Station is a locator. Only a fresh verified authority
    /// chain selects the destination and its Service signature identity.
    pub(crate) async fn realm_route(&self, realm: &RealmId) -> Result<RealmRoute> {
        let request = arkret::AuthorityBundleRequest {
            realm_id: realm.clone(),
            nonce: arkret::Base64UrlString::new(nonce()?).map_err(invalid)?,
        };
        let bundle = garth::AuthorityClient::new(self.client().clone())
            .resolve_authority(&request)
            .await
            .map_err(invalid)?;
        let keys = garth::historical_station_keys::fetch_historical_station_key_directory(
            self.client(),
            &bundle,
            None,
            None,
        )
        .await
        .map_err(invalid)?;
        let authority = arkret::identity::verify_realm_authority_bundle(
            &bundle,
            &arkret::identity::RealmAuthorityFreshness::new(Utc::now(), request.nonce),
            &keys,
        )
        .map_err(invalid)?;
        let resolution: arkret::AuthenticatedServiceResolution =
            serde_json::from_value(bundle.current_route_record.clone())?;
        let base = resolution.projection().map_err(invalid)?.base_url;
        let key = ed25519_dalek::SigningKey::from_bytes(&self.config().signing_seed()?);
        if key.verifying_key() != self.signer().verifying_key() {
            return Err(invalid("Service HTTP key differs from its producer key"));
        }
        let client = self
            .client()
            .with_base_url(url::Url::parse(&base).map_err(invalid)?)?
            .with_service_http_signer(
                self.service_actor_id().clone(),
                authority.current_service_id().clone(),
                HttpMessageSigner::new(self.service_verification_method()?.to_string(), key),
            );
        Ok(RealmRoute {
            client,
            authority,
            resolution,
            keys,
            bundle,
        })
    }
}

impl RealmRoute {
    pub async fn historical_station_key(
        &self,
        station: &arkret::DidCoreId,
        method: &DidUrl,
        signed_at: DateTime<Utc>,
    ) -> Result<arkret::signatures::PublicKeyMaterial> {
        if !self
            .authority
            .authorizes_issuer_at(station, None, signed_at)
        {
            return Err(invalid(
                "Station did not govern this Realm at the signing time",
            ));
        }
        let did = arkret::verification_method_did(method.as_str()).map_err(invalid)?;
        if arkret::project_did_to_core_id(&did)? != *station {
            return Err(invalid(
                "historical signature method belongs to another Station",
            ));
        }
        let resolution = if station == self.authority.current_service_id() {
            self.resolution.clone()
        } else {
            self.client
                .resolve_service_from_did(&did, arkret::ServiceKind::Station)
                .await?
        };
        let document =
            arkret::identity::authenticated_service_document_at(&resolution, station, signed_at)
                .map_err(invalid)?;
        arkret::identity::validate_verification_method_relationship(
            &document,
            method,
            &document.id,
            arkret::identity::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(invalid)?;
        arkret::identity::public_key_material_from_document(&document, method).map_err(invalid)
    }
    pub fn station_key(
        &self,
        method: &DidUrl,
        signed_at: DateTime<Utc>,
    ) -> Result<arkret::signatures::PublicKeyMaterial> {
        let document = arkret::identity::authenticated_service_document_at(
            &self.resolution,
            self.authority.current_service_id(),
            signed_at,
        )
        .map_err(invalid)?;
        arkret::identity::validate_verification_method_relationship(
            &document,
            method,
            &document.id,
            arkret::identity::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(invalid)?;
        arkret::identity::public_key_material_from_document(&document, method).map_err(invalid)
    }

    pub async fn material(
        &self,
        request: &RealmActorMaterialRequest,
        requester: &ActorId,
    ) -> Result<VerifiedRealmActorMaterial> {
        Ok(self
            .client
            .realm_actor_material(
                request,
                requester,
                &self.authority,
                &self.resolution,
                &self.keys,
            )
            .await?)
    }

    /// A pushed material object still needs the original query coordinates and
    /// historical Commit key. Transport authentication alone cannot install it.
    pub async fn verify_material(
        &self,
        material: RealmActorMaterialOutcome,
        request: &RealmActorMaterialRequest,
        requester: &ActorId,
    ) -> Result<VerifiedRealmActorMaterial> {
        let commits = match &material.result {
            arkret::RealmActorMaterialResult::Event { commit, .. } => vec![commit],
            _ => vec![],
        };
        let keys = garth::historical_station_keys::fetch_historical_station_keys_for_commits(
            &self.client,
            &self.bundle,
            &commits,
        )
        .await
        .map_err(invalid)?;
        arkret::identity::verify_realm_actor_material(
            material,
            request,
            requester,
            &self.authority,
            &self.resolution,
            &keys,
            Utc::now(),
        )
        .map_err(invalid)
    }
}
