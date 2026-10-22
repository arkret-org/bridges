use arkret::WireResourceSelector;

use super::*;

#[test]
fn terminal_parent_rejects_disjoint_circles_without_rejecting_narrow_or_realm_wide_resources() {
    let realm = arkret::RealmId::from_event_id(&arkret::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [61; 32],
    ));
    let circle = |byte| {
        arkret::CircleId::from_event_id(&arkret::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [byte; 32],
        ))
    };
    let scope = ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle(62),
    };
    let fixture: CapabilityGrant = serde_json::from_value(serde_json::json!({
        "id":arkret::GrantId::from_event_id(&arkret::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[64;32])),
        "schema":"ak.schema.capability.v1", "realm_id":realm,
        "issuer_id":ActorId::service("ak:did_core:web:applet.example".parse().unwrap()),
        "subject":ActorId::service("ak:did_core:web:applet.example".parse().unwrap()),
        "actions":["ak.message.create"], "resources":[WireResourceSelector::circle(realm.clone(),circle(63))],
        "constraints":[], "issued_at":"2026-10-21T01:00:00.000Z", "status":"active",
        "authority_depth":0, "issuer_authority_refs":[], "authority_root_refs":[],
    })).unwrap();
    assert!(!parent_scope_candidate(&fixture, &scope));
    let mut grants = [fixture.clone(), fixture.clone()];
    grants[1].resources = vec![WireResourceSelector::circle(realm.clone(), circle(62))];
    assert!(std::ptr::eq(
        grants
            .iter()
            .find(|grant| parent_scope_candidate(grant, &scope))
            .unwrap(),
        &grants[1]
    ));
    let mut narrowed = fixture.clone();
    narrowed.resources = vec![WireResourceSelector::strand(
        realm.clone(),
        arkret::StrandId::from_event_id(&arkret::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [65; 32],
        )),
    )];
    assert!(
        parent_scope_candidate(&narrowed, &scope),
        "object ancestry stays Station-owned"
    );
    narrowed.resources = vec![WireResourceSelector::realm(realm.clone())];
    assert!(!parent_scope_candidate(&narrowed, &scope));
    narrowed.resources[0].match_scope = Some(arkret::ResourceMatchScope::RealmWide);
    assert!(parent_scope_candidate(&narrowed, &scope));
    assert!(!parent_scope_candidate(
        &fixture,
        &ScopeRef::Realm { realm_id: realm }
    ));
}
