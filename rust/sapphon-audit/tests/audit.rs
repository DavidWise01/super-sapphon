use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sapphon_audit::{
    Journal, PinRegistry, PublisherPin, SignedSnapshot, SnapshotPayload, SNAPSHOT_SCHEMA,
};
use std::collections::BTreeMap;

fn fixture() -> (SigningKey, PinRegistry, SnapshotPayload) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pins: PinRegistry = BTreeMap::from([(
        "publisher-one".into(),
        PublisherPin {
            control_root: "owned-root".into(),
            public_key: key.verifying_key().to_bytes(),
            revoked: false,
        },
    )]);
    let payload = SnapshotPayload {
        schema: SNAPSHOT_SCHEMA.into(),
        publisher_id: "publisher-one".into(),
        control_root: "owned-root".into(),
        generation: 1,
        issuer_generation: 1,
        operator_generation: 1,
        issuer_revoked: false,
        operator_revoked: false,
        previous_digest: None,
        mode: "synthetic-local-replica".into(),
    };
    (key, pins, payload)
}
fn sign(key: &SigningKey, payload: SnapshotPayload) -> SignedSnapshot {
    let bytes = payload.canonical_bytes().unwrap();
    let signature = key.sign(&bytes);
    SignedSnapshot {
        payload,
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    }
}
fn sample() -> (PinRegistry, SignedSnapshot, SignedSnapshot) {
    let (key, pins, p) = fixture();
    let a = sign(&key, p.clone());
    let b = sign(
        &key,
        SnapshotPayload {
            issuer_revoked: true,
            ..p
        },
    );
    (pins, a, b)
}
fn observe(
    j: &mut Journal,
    s: SignedSnapshot,
    id: &str,
    roots: &[&str],
    pins: &PinRegistry,
) -> String {
    j.ingest(s, id, roots.iter().map(|x| x.to_string()).collect(), pins)
        .unwrap()
        .decision
        .to_string()
}
#[test]
fn canonical_signature_matches_rust_verifier() {
    let (keys, a, _) = sample();
    let checksum = sapphon_audit::verify_signed(&a, &keys).unwrap();
    assert_eq!(checksum.len(), 64);
    assert!(checksum.bytes().all(|b| b.is_ascii_hexdigit()));
}
#[test]
fn payload_canonical_json_is_js_field_array() {
    let (_, _, p) = fixture();
    assert_eq!(String::from_utf8(p.canonical_bytes().unwrap()).unwrap(),
        "[\"sapphon-125-revocation-snapshot-v1\",\"publisher-one\",\"owned-root\",1,1,1,false,false,null,\"synthetic-local-replica\"]");
}
#[test]
fn two_valid_signed_forks_are_retained_without_winner() {
    let (pins, a, b) = sample();
    let mut j = Journal::default();
    assert_eq!(
        observe(&mut j, a, "source-alpha", &["owned-root"], &pins),
        "HOLD"
    );
    assert_eq!(
        observe(&mut j, b, "source-beta", &["owned-root"], &pins),
        "HOLD"
    );
    assert_eq!(j.observations.len(), 2);
    assert_eq!(j.conflicts.len(), 1);
    let result = j
        .assess("publisher-one", 1, &["owned-root".into()], &pins)
        .unwrap();
    assert!(result.conflict_detected);
    assert!(result.source_owned_overlap);
    assert!(result.shared_ancestry_detected);
    assert_eq!(result.decision, "HOLD");
    assert!(!result.external_finality);
}
#[test]
fn github_and_pages_are_same_ancestry_not_independent() {
    let (pins, a, _) = sample();
    let mut j = Journal::default();
    observe(&mut j, a.clone(), "github-mirror", &["owned-root"], &pins);
    observe(&mut j, a, "pages-mirror", &["owned-root"], &pins);
    let result = j.assess("publisher-one", 1, &[], &pins).unwrap();
    assert_eq!(result.observed_snapshots, 2);
    assert_eq!(result.distinct_declared_first_roots, 1);
    assert!(result.shared_ancestry_detected);
    assert!(!result.independent_witnesses_authenticated);
}
#[test]
fn duplicate_source_and_digest_is_idempotent() {
    let (pins, a, _) = sample();
    let mut j = Journal::default();
    observe(&mut j, a.clone(), "github-mirror", &["owned-root"], &pins);
    assert_eq!(
        observe(&mut j, a, "github-mirror", &["owned-root"], &pins),
        "DUPLICATE_OBSERVATION"
    );
    assert_eq!(j.observations.len(), 1);
    assert_eq!(j.revision, 1);
}
#[test]
fn forged_signature_is_rejected() {
    let (pins, a, _) = sample();
    let mut j = Journal::default();
    let bad_key = SigningKey::from_bytes(&[8u8; 32]);
    let bad = sign(&bad_key, a.payload);
    assert_eq!(
        j.ingest(bad, "forged", vec!["owned-root".into()], &pins)
            .unwrap_err()
            .0,
        "SNAPSHOT_SIGNATURE"
    );
    assert!(j.observations.is_empty());
}
#[test]
fn revoked_publisher_is_rejected() {
    let (mut pins, a, _) = sample();
    pins.get_mut("publisher-one").unwrap().revoked = true;
    assert_eq!(
        Journal::default()
            .ingest(a, "source", vec!["owned-root".into()], &pins)
            .unwrap_err()
            .0,
        "PUBLISHER_REVOKED"
    );
}
#[test]
fn conflicting_record_cannot_be_silently_removed() {
    let (pins, a, b) = sample();
    let mut j = Journal::default();
    observe(&mut j, a, "source-one", &["owned-root"], &pins);
    observe(&mut j, b, "source-two", &["owned-root"], &pins);
    j.conflicts.clear();
    assert_eq!(
        j.validate(&pins).unwrap_err().0,
        "MISSING_EQUIVOCATION_RECORD"
    );
}
#[test]
fn referenced_snapshot_cannot_be_deleted() {
    let (pins, a, b) = sample();
    let mut j = Journal::default();
    observe(&mut j, a, "source-one", &["owned-root"], &pins);
    observe(&mut j, b, "source-two", &["owned-root"], &pins);
    j.observations.pop();
    assert_eq!(j.validate(&pins).unwrap_err().0, "JOURNAL_CORRUPT");
}
#[test]
fn tampered_signed_payload_is_rejected() {
    let (pins, mut a, _) = sample();
    a.payload.issuer_revoked = true;
    assert_eq!(
        sapphon_audit::verify_signed(&a, &pins).unwrap_err().0,
        "SNAPSHOT_SIGNATURE"
    );
}
#[test]
fn altered_digest_does_not_survive_journal_validation() {
    let (pins, a, _) = sample();
    let mut j = Journal::default();
    observe(&mut j, a, "source-one", &["owned-root"], &pins);
    j.observations[0].digest = "f".repeat(64);
    assert_eq!(j.validate(&pins).unwrap_err().0, "JOURNAL_CORRUPT");
}
#[test]
fn invalid_or_repeated_ancestry_roots_fail_closed() {
    let (pins, a, _) = sample();
    let mut j = Journal::default();
    assert_eq!(
        j.ingest(a.clone(), "source", vec![], &pins).unwrap_err().0,
        "PROVENANCE_FIELDS"
    );
    assert_eq!(
        j.ingest(
            a,
            "source",
            vec!["owned-root".into(), "owned-root".into()],
            &pins
        )
        .unwrap_err()
        .0,
        "PROVENANCE_FIELDS"
    );
}
#[test]
fn disjoint_declared_roots_still_do_not_prove_independence() {
    let (pins, a, b) = sample();
    let mut j = Journal::default();
    observe(&mut j, a, "source-one", &["first-root"], &pins);
    observe(&mut j, b, "source-two", &["second-root"], &pins);
    let result = j.assess("publisher-one", 1, &[], &pins).unwrap();
    assert_eq!(result.distinct_declared_first_roots, 2);
    assert!(!result.independent_witnesses_authenticated);
    assert!(!result.publication_freshness_authenticated);
    assert!(!result.utc_authority);
}
#[test]
fn json_roundtrip_preserves_conflicts() {
    let (pins, a, b) = sample();
    let mut j = Journal::default();
    observe(&mut j, a, "source-one", &["owned-root"], &pins);
    observe(&mut j, b, "source-two", &["owned-root"], &pins);
    let json = serde_json::to_string_pretty(&j).unwrap();
    let copy: Journal = serde_json::from_str(&json).unwrap();
    copy.validate(&pins).unwrap();
    assert_eq!(copy.conflicts.len(), 1);
}
#[test]
fn unknown_fields_in_snapshot_are_rejected() {
    let (_, a, _) = sample();
    let mut v = serde_json::to_value(a).unwrap();
    v["payload"]["external_authority"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<SignedSnapshot>(v).is_err());
}
