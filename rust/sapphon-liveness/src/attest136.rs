//! SAPPHON-136: verify cryptographic witness attestations against an
//! externally provisioned key registry. Signatures prove key possession;
//! they do NOT prove independent physical custody or clock authority.
use crate::{custody::LocalPin, pinned::marker_digest, Error};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const AUTHORITY: &str = "HOLD";

/// Provision these keys and ancestry associations outside this process.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub witness_id: String,
    pub ancestry_root: String,
    pub public_key_hex: String,
    pub revoked: bool,
    pub min_counter: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedWitness {
    pub witness_id: String,
    pub acquisition_digest: String,
    pub counter: u64,
    pub signature_base64: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub verified_signatures: usize,
    pub distinct_declared_ancestry_roots: usize,
    pub decision: &'static str,
    pub lock_cleared: bool,
    pub external_authority: bool,
    pub authenticated_utc: bool,
    pub independence_proven: bool,
}
fn digest_valid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Exact, versioned payload shared by signers and verifier.
pub fn message(witness_id: &str, acquisition_digest: &str, counter: u64) -> Vec<u8> {
    format!("SAPPHON-136-WITNESS-v1\n{witness_id}\n{acquisition_digest}\n{counter}\n").into_bytes()
}
pub fn expected_acquisition_digest(pin: &LocalPin) -> String {
    marker_digest(format!("sapphon-136-acquisition-v1\n{}\n{}\n{}\n{}\n{}\n",
        pin.owner_pid, pin.owner_start_ticks, pin.owner_boot_id,
        pin.marker_sha256, pin.journal_sha256).as_bytes())
}
/// Gate never grants recovery even after valid signatures. The registry
/// is trusted input that MUST have external custody and trusted revocation
/// state established elsewhere; this function does not certify that.
pub fn verify_signed_witnesses(
    pin: &LocalPin,
    registry: &[TrustedKey],
    signed: &[SignedWitness],
) -> Result<Verdict, Error> {
    if !digest_valid(&pin.marker_sha256) || !digest_valid(&pin.journal_sha256)
        || pin.owner_pid == 0 || pin.owner_start_ticks == 0 {
        return Err(Error("ATTEST_PIN_INVALID"));
    }
    if registry.len() > 32 || signed.len() > 32 {
        return Err(Error("ATTEST_LIMIT"));
    }
    let mut keys = HashMap::new();
    let mut unique_pubkeys = HashSet::new();
    for k in registry {
        if k.witness_id.is_empty() || k.ancestry_root.is_empty()
            || !unique_pubkeys.insert(k.public_key_hex.as_str())
            || keys.insert(k.witness_id.as_str(), k).is_some() {
            return Err(Error("ATTEST_REGISTRY_CONFLICT"));
        }
    }
    let expected = expected_acquisition_digest(pin);
    let mut seen = HashSet::new();
    let mut roots = HashSet::new();
    for evidence in signed {
        if !seen.insert(evidence.witness_id.as_str()) {
            return Err(Error("ATTEST_DUPLICATE"));
        }
        let entry = keys.get(evidence.witness_id.as_str()).ok_or(Error("ATTEST_UNKNOWN_KEY"))?;
        if entry.revoked {
            return Err(Error("ATTEST_REVOKED"));
        }
        if evidence.counter <= entry.min_counter {
            return Err(Error("ATTEST_REPLAY"));
        }
        if evidence.acquisition_digest != expected {
            return Err(Error("ATTEST_ACQUISITION_CONFLICT"));
        }
        let key_bytes = hex::decode(&entry.public_key_hex).map_err(|_| Error("ATTEST_KEY_INVALID"))?;
        let key_array: [u8;32] = key_bytes.try_into().map_err(|_| Error("ATTEST_KEY_INVALID"))?;
        let key = VerifyingKey::from_bytes(&key_array).map_err(|_| Error("ATTEST_KEY_INVALID"))?;
        let sig_bytes = STANDARD.decode(&evidence.signature_base64).map_err(|_| Error("ATTEST_SIG_INVALID"))?;
        let signature: [u8;64] = sig_bytes.try_into().map_err(|_| Error("ATTEST_SIG_INVALID"))?;
        key.verify(&message(&evidence.witness_id, &evidence.acquisition_digest, evidence.counter),
            &Signature::from_bytes(&signature)).map_err(|_| Error("ATTEST_SIGNATURE_MISMATCH"))?;
        if !roots.insert(entry.ancestry_root.as_str()) {
            return Err(Error("ATTEST_SHARED_ANCESTRY"));
        }
    }
    Ok(Verdict {
        verified_signatures: signed.len(), distinct_declared_ancestry_roots: roots.len(),
        decision: "HOLD", lock_cleared: false, external_authority: false,
        authenticated_utc: false, independence_proven: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn pin() -> LocalPin {
        LocalPin { schema: "sapphon-134-local-pin-v1".into(), owner_pid: 11,
            owner_start_ticks: 99, owner_boot_id: "boot-123456789".into(),
            journal_sha256: "a".repeat(64), marker_sha256: "b".repeat(64) }
    }
    fn pair(pin: &LocalPin, id: &str, ancestry: &str, seed: u8)
        -> (TrustedKey, SignedWitness) {
        let sk = SigningKey::from_bytes(&[seed;32]);
        let digest = expected_acquisition_digest(pin);
        let sig = sk.sign(&message(id, &digest, 2));
        (TrustedKey { witness_id: id.into(), ancestry_root: ancestry.into(),
            public_key_hex: hex::encode(sk.verifying_key().as_bytes()),
            revoked: false, min_counter: 1 },
         SignedWitness { witness_id: id.into(), acquisition_digest: digest,
            counter: 2, signature_base64: STANDARD.encode(sig.to_bytes()) })
    }
    #[test] fn three_valid_signatures_still_hold(){
        let p = pin();
        let pairs = [pair(&p,"one","root-a",1), pair(&p,"two","root-b",2),
                     pair(&p,"three","root-c",3)];
        let keys: Vec<_> = pairs.iter().map(|x| x.0.clone()).collect();
        let sigs: Vec<_> = pairs.iter().map(|x| x.1.clone()).collect();
        let verdict = verify_signed_witnesses(&p,&keys,&sigs).unwrap();
        assert_eq!(verdict.verified_signatures,3);
        assert_eq!(verdict.distinct_declared_ancestry_roots,3);
        assert!(!verdict.lock_cleared && !verdict.external_authority
            && !verdict.independence_proven && !verdict.authenticated_utc);
        assert_eq!(verdict.decision,"HOLD");
    }
    #[test] fn forged_signature_is_rejected(){
        let p=pin(); let (k,mut s)=pair(&p,"one","root-a",1);
        s.signature_base64=STANDARD.encode([0u8;64]);
        assert_eq!(verify_signed_witnesses(&p,&[k],&[s]).unwrap_err().0,
            "ATTEST_SIGNATURE_MISMATCH");
    }
    #[test] fn revoked_key_is_rejected(){
        let p=pin();let (mut k,s)=pair(&p,"one","root-a",1);k.revoked=true;
        assert_eq!(verify_signed_witnesses(&p,&[k],&[s]).unwrap_err().0,"ATTEST_REVOKED");
    }
    #[test] fn stale_counter_is_rejected(){
        let p=pin();let (mut k,s)=pair(&p,"one","root-a",1);k.min_counter=2;
        assert_eq!(verify_signed_witnesses(&p,&[k],&[s]).unwrap_err().0,"ATTEST_REPLAY");
    }
    #[test] fn shared_root_is_rejected(){
        let p=pin();let (a,x)=pair(&p,"one","same-root",1);
        let (b,y)=pair(&p,"two","same-root",2);
        assert_eq!(verify_signed_witnesses(&p,&[a,b],&[x,y]).unwrap_err().0,
            "ATTEST_SHARED_ANCESTRY");
    }
    #[test] fn changed_acquisition_digest_is_rejected(){
        let p=pin();let (k,mut s)=pair(&p,"one","root-a",1);
        s.acquisition_digest="0".repeat(64);
        assert_eq!(verify_signed_witnesses(&p,&[k],&[s]).unwrap_err().0,
            "ATTEST_ACQUISITION_CONFLICT");
    }
}
