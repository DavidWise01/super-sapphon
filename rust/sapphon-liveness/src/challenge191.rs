//! SAPPHON-191: signed single-use proof-of-possession challenge, no custody promotion.
#![cfg(target_os = "linux")]
use crate::Error;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
pub const AUTHORITY: &str = "HOLD";
const SOURCE: &str = "9cdfc47714899d4f1791d7a51be813ba0790eca9";
const DOMAIN: &[u8] = b"SAPPHON-191-PROOF-OF-POSSESSION-V1\0";
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn hex64(x: &str) -> bool {
    x.len() == 64
        && x.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub source_sha: String,
    pub root_sha256: String,
    pub run_id: u64,
    pub attempt: u32,
    pub session_id: String,
    pub nonce_hex: String,
    pub key_fingerprint_sha256: String,
    pub issuer_independently_authenticated: bool,
    pub recovery_authorized: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub challenge: Challenge,
    pub public_key_b64: String,
    pub signature_b64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub response_set_sha256: String,
    pub signatures_valid: bool,
    pub blockers: Vec<String>,
    pub consumed_nonces: usize,
    pub independent_witnesses: u8,
    pub independently_authenticated_issuer: bool,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn message(x: &Challenge) -> Result<Vec<u8>, Error> {
    if x.source_sha != SOURCE
        || !hex64(&x.root_sha256)
        || !hex64(&x.nonce_hex)
        || !hex64(&x.key_fingerprint_sha256)
        || x.run_id == 0
        || x.attempt == 0
        || x.session_id.is_empty()
        || x.session_id.len() > 128
        || x.issuer_independently_authenticated
        || x.recovery_authorized
    {
        return Err(Error("CHALLENGE191_FIELDS"));
    }
    let mut bytes = DOMAIN.to_vec();
    for part in [
        x.source_sha.as_bytes(),
        x.root_sha256.as_bytes(),
        &x.run_id.to_be_bytes(),
        &x.attempt.to_be_bytes(),
        x.session_id.as_bytes(),
        x.nonce_hex.as_bytes(),
        x.key_fingerprint_sha256.as_bytes(),
    ] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    Ok(bytes)
}
pub fn verify(x: &Response) -> Result<bool, Error> {
    let data = message(&x.challenge)?;
    let pk = STANDARD
        .decode(&x.public_key_b64)
        .map_err(|_| Error("CHALLENGE191_KEY"))?;
    let public: [u8; 32] = pk
        .as_slice()
        .try_into()
        .map_err(|_| Error("CHALLENGE191_KEY"))?;
    if sha(&public) != x.challenge.key_fingerprint_sha256 {
        return Err(Error("CHALLENGE191_FINGERPRINT"));
    }
    let key = VerifyingKey::from_bytes(&public).map_err(|_| Error("CHALLENGE191_KEY"))?;
    let sig = STANDARD
        .decode(&x.signature_b64)
        .map_err(|_| Error("CHALLENGE191_SIGNATURE"))?;
    let signature = Signature::from_slice(&sig).map_err(|_| Error("CHALLENGE191_SIGNATURE"))?;
    Ok(key.verify(&data, &signature).is_ok())
}
pub fn adjudicate(responses: &[Response]) -> Result<Finding, Error> {
    if responses.len() > 128 {
        return Err(Error("CHALLENGE191_LIMIT"));
    }
    let mut used = BTreeSet::new();
    let mut blockers = Vec::new();
    let mut valid = !responses.is_empty();
    for (i, x) in responses.iter().enumerate() {
        if !verify(x)? {
            valid = false;
            blockers.push(format!("INVALID_SIGNATURE:{i}"));
        }
        if !used.insert(x.challenge.nonce_hex.clone()) {
            valid = false;
            blockers.push(format!("REPLAYED_NONCE:{i}"));
        }
        blockers.push(format!("NO_AUTHENTICATED_ISSUER:{i}"));
    }
    blockers.sort();
    blockers.dedup();
    let encoded = serde_json::to_vec(responses).map_err(|_| Error("CHALLENGE191_JSON"))?;
    Ok(Finding {
        schema: "sapphon-191-rust-pop-v1".into(),
        response_set_sha256: sha(&encoded),
        signatures_valid: valid,
        consumed_nonces: used.len(),
        blockers,
        independent_witnesses: 0,
        independently_authenticated_issuer: false,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "CHALLENGE_PROOF_OF_POSSESSION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-191-rust-pop-v1"
        || f.decision != "CHALLENGE_PROOF_OF_POSSESSION_HOLD"
        || f.independent_witnesses != 0
        || f.independently_authenticated_issuer
        || f.authenticated_utc
        || f.global_anti_rollback_authenticated
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("CHALLENGE191_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(f).map_err(|_| Error("CHALLENGE191_JSON"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("CHALLENGE191_EXISTS"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("CHALLENGE191_WRITE"))?;
    file.sync_all().map_err(|_| Error("CHALLENGE191_SYNC"))?;
    File::open(path.parent().ok_or(Error("CHALLENGE191_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("CHALLENGE191_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn signed() -> Response {
        // Deterministic test key, never an external custody credential.
        let private = SigningKey::from_bytes(&[9u8; 32]);
        let public = private.verifying_key().to_bytes();
        let c = Challenge {
            source_sha: SOURCE.into(),
            root_sha256: "a".repeat(64),
            run_id: 190,
            attempt: 1,
            session_id: "fixture-session".into(),
            nonce_hex: "b".repeat(64),
            key_fingerprint_sha256: sha(&public),
            issuer_independently_authenticated: false,
            recovery_authorized: false,
        };
        let sig = private.sign(&message(&c).unwrap()).to_bytes();
        Response {
            challenge: c,
            public_key_b64: STANDARD.encode(public),
            signature_b64: STANDARD.encode(sig),
        }
    }
    #[test]
    fn valid_signature_zero_external_witness() {
        let x = signed();
        assert!(verify(&x).unwrap());
        let f = adjudicate(&[x]).unwrap();
        assert!(f.signatures_valid);
        assert_eq!(f.independent_witnesses, 0);
        assert!(!f.recovery_authorized);
    }
    #[test]
    fn root_substitution_invalid() {
        let mut x = signed();
        x.challenge.root_sha256 = "c".repeat(64);
        assert!(!verify(&x).unwrap());
    }
    #[test]
    fn cross_session_invalid() {
        let mut x = signed();
        x.challenge.session_id = "other".into();
        assert!(!verify(&x).unwrap());
    }
    #[test]
    fn replay_detected() {
        let x = signed();
        let f = adjudicate(&[x.clone(), x]).unwrap();
        assert!(f.blockers.iter().any(|v| v.starts_with("REPLAYED_NONCE")));
    }
    #[test]
    fn wrong_attempt_invalid() {
        let mut x = signed();
        x.challenge.attempt = 2;
        assert!(!verify(&x).unwrap());
    }
    #[test]
    fn forged_external_issuer_rejected() {
        let mut x = signed();
        x.challenge.issuer_independently_authenticated = true;
        assert_eq!(verify(&x).unwrap_err().0, "CHALLENGE191_FIELDS");
    }
    #[test]
    fn empty_set_no_pass() {
        let f = adjudicate(&[]).unwrap();
        assert!(!f.signatures_valid && !f.recovery_authorized);
    }
    #[test]
    fn create_only() {
        let f = adjudicate(&[]).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon191-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &f).unwrap();
        assert_eq!(write_new(&p, &f).unwrap_err().0, "CHALLENGE191_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
