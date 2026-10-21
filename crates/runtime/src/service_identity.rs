//! Publication of the host's verified, public Service identity history.

use arkret::identity::{
    DidVerificationRelationship, authenticated_service_document_at,
    public_key_material_from_document, validate_verification_method_relationship,
};

use crate::{BridgeError, Config, Result};

fn invalid(error: impl std::fmt::Display) -> BridgeError {
    BridgeError::Config(format!("Applet Service identity: {error}"))
}

pub(crate) fn validate(config: &Config) -> Result<&arkret::AuthenticatedServiceResolution> {
    let resolution = config.arkret.service_resolution.as_ref().ok_or_else(|| {
        invalid("HTTP publication requires service_resolution with complete native history")
    })?;
    let service = arkret::project_did_to_core_id(&config.arkret.service_did)?;
    if resolution.service_kind != arkret::ServiceKind::AppletService.as_str()
        || resolution.normalized_did_document.id != config.arkret.service_did
        || config.arkret.service_did.method() != "webvh"
    {
        return Err(invalid("the history does not identify this Applet Service"));
    }
    let document = authenticated_service_document_at(resolution, &service, chrono::Utc::now())
        .map_err(invalid)?;
    if arkret::identity::document_canonical_digest(&document).map_err(invalid)?
        != arkret::identity::document_canonical_digest(&resolution.normalized_did_document)
            .map_err(invalid)?
    {
        return Err(invalid("the configured history head is not effective yet"));
    }
    let method = config
        .arkret
        .verification_method_for(&config.arkret.service_did)?;
    validate_verification_method_relationship(
        &document,
        &method,
        &config.arkret.service_did,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    let published = public_key_material_from_document(&document, &method)
        .map_err(invalid)?
        .ed25519_bytes()
        .map_err(invalid)?;
    let actual = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed()?);
    if published != actual.verifying_key().to_bytes() {
        return Err(invalid(
            "the current public method differs from the configured signing key",
        ));
    }
    Ok(resolution)
}

pub(crate) fn commitment(config: &Config) -> Result<arkret::ResolutionCommitment> {
    let resolution = validate(config)?;
    let boundary = resolution.method_history_evidence.boundary();
    Ok(arkret::ResolutionCommitment {
        did: config.arkret.service_did.clone(),
        method_history_head: boundary.to_method_history_head.clone(),
        version_id: boundary.to_version_id.clone(),
    })
}

#[cfg(feature = "web")]
pub(crate) fn router(config: &Config) -> Result<salvo::Router> {
    use arkret::identity::DidWebvhResolver;
    use salvo::prelude::*;
    let resolution = validate(config)?;
    let arkret::ResolutionMethodHistoryEvidence::WebvhLog {
        log_entries,
        witness_records,
        ..
    } = &resolution.method_history_evidence
    else {
        return Err(invalid("publication requires native WebVH history"));
    };
    let document = &log_entries.last().ok_or_else(|| invalid("empty history"))?["state"];
    let mut history = String::new();
    for entry in log_entries {
        history.push_str(&arkret::canonical::canonical_json_string(entry)?);
        history.push('\n');
    }
    let path = |url: String| -> Result<String> {
        Ok(url::Url::parse(&url)
            .map_err(invalid)?
            .path()
            .trim_start_matches('/')
            .to_owned())
    };
    let did = &config.arkret.service_did;
    let resources = [
        (
            "_arkret/open/services/{service_id}/resolution".to_owned(),
            "application/json",
            arkret::canonical::canonical_json_string(resolution)?,
        ),
        (
            path(DidWebvhResolver::document_url(did).map_err(invalid)?)?,
            "application/json",
            arkret::canonical::canonical_json_string(document)?,
        ),
        (
            path(DidWebvhResolver::log_url(did).map_err(invalid)?)?,
            "application/jsonl",
            history,
        ),
        (
            path(DidWebvhResolver::witness_url(did).map_err(invalid)?)?,
            "application/json",
            arkret::canonical::canonical_json_string(witness_records)?,
        ),
    ];
    let mut router = Router::new();
    for (path, content_type, body) in resources {
        let service_id = path
            .contains("{service_id}")
            .then(|| resolution.service_id.clone());
        let canonical = service_id.is_some();
        let mut resource = Router::with_path(path)
            .hoop(salvo::affix_state::inject(PublicResource {
                content_type,
                body: body.into(),
                service_id,
            }))
            .get(public_resource);
        if canonical {
            resource = resource.hoop(crate::web::OperationSelector(
                arkret::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
            ));
        }
        router = router.push(resource);
    }
    Ok(router)
}

#[cfg(feature = "web")]
#[derive(Clone)]
struct PublicResource {
    content_type: &'static str,
    body: std::sync::Arc<str>,
    service_id: Option<arkret::DidCoreId>,
}

#[cfg(feature = "web")]
#[salvo::handler]
async fn public_resource(
    req: &mut salvo::Request,
    depot: &mut salvo::Depot,
    res: &mut salvo::Response,
) {
    let resource = depot
        .get_typed::<PublicResource>()
        .expect("public identity resource injected");
    if resource.service_id.as_ref().is_some_and(|expected| {
        req.param::<String>("service_id").as_deref() != Some(expected.as_str())
    }) {
        crate::web::applet_error(
            res,
            salvo::http::StatusCode::NOT_FOUND,
            "not_found",
            "Service resolution not found",
        );
        return;
    }
    res.headers_mut().insert(
        "content-type",
        salvo::http::HeaderValue::from_static(resource.content_type),
    );
    res.headers_mut().insert(
        "cache-control",
        salvo::http::HeaderValue::from_static("no-cache"),
    );
    res.write_body(resource.body.to_string())
        .expect("public identity resource body");
}
