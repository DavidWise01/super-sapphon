//! Synthetic cross-process signing fixtures. Keys are deterministic test seeds,
/// never outside witnesses or production credentials.
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sapphon_audit::{PinRegistry, PublisherPin, SignedSnapshot, SnapshotPayload, SNAPSHOT_SCHEMA};
use std::collections::BTreeMap;
pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[30u8; 32])
}
pub fn pins() -> PinRegistry {
    let key = signing_key();
    BTreeMap::from([(
        "publisher-one".into(),
        PublisherPin {
            control_root: "owned-root".into(),
            public_key: key.verifying_key().to_bytes(),
            revoked: false,
        },
    )])
}
pub fn signed(revoked: bool) -> SignedSnapshot {
    let payload = SnapshotPayload {
        schema: SNAPSHOT_SCHEMA.into(),
        publisher_id: "publisher-one".into(),
        control_root: "owned-root".into(),
        generation: 1,
        issuer_generation: 1,
        operator_generation: 1,
        issuer_revoked: revoked,
        operator_revoked: false,
        previous_digest: None,
        mode: "synthetic-local-replica".into(),
    };
    let sig = signing_key().sign(&payload.canonical_bytes().expect("valid fixture"));
    SignedSnapshot {
        payload,
        signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
    }
}
pub const AUTHORITY: &str = "HOLD";
