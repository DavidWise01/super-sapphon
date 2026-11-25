//! SAPPHON-135: external-custody evidence screening, not authority.
//! Independent origin must be established OUTSIDE this process. Witness labels,
//! signatures from the same operator and multiple copies do not create independence.
use crate::{custody::LocalPin, pinned::marker_digest, Error};
use serde::{Deserialize, Serialize};

pub const AUTHORITY: &str = "HOLD";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub witness_id: String,
    pub custody_root: String,
    pub ancestry_root: String,
    pub acquisition_digest: String,
    pub marker_sha256: String,
    pub journal_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub independent_roots: usize,
    pub matching_witnesses: usize,
    pub eligible_for_manual_review: bool,
    pub decision: &'static str,
    pub lock_cleared: bool,
    pub external_authority: bool,
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid_name(s: &str) -> bool {
    (4..=96).contains(&s.len())
        && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}
/// The caller supplies custody/ancestry attestations; this function can reject
/// obvious shared ancestry, but CANNOT independently authenticate those claims.
/// No boolean in the result grants operational recovery authorization.
pub fn screen_witnesses(pin: &LocalPin, witnesses: &[Witness]) -> Result<Assessment, Error> {
    if !valid_digest(&pin.marker_sha256) || !valid_digest(&pin.journal_sha256) {
        return Err(Error("WITNESS_PIN_INVALID"));
    }
    if witnesses.len() > 32 { return Err(Error("WITNESS_LIMIT")); }
    let expected = marker_digest(
        format!("sapphon-135-v1\n{}\n{}\n{}\n{}\n{}",
            pin.owner_pid, pin.owner_start_ticks, pin.owner_boot_id,
            pin.marker_sha256, pin.journal_sha256).as_bytes());
    let mut roots = std::collections::HashSet::new();
    let mut identities = std::collections::HashSet::new();
    let mut matched = 0;
    for w in witnesses {
        if !valid_name(&w.witness_id) || !valid_name(&w.custody_root)
            || !valid_name(&w.ancestry_root) || !valid_digest(&w.acquisition_digest)
            || !valid_digest(&w.marker_sha256) || !valid_digest(&w.journal_sha256) {
            return Err(Error("WITNESS_FIELDS"));
        }
        if !identities.insert(w.witness_id.as_str()) {
            return Err(Error("WITNESS_DUPLICATE_ID"));
        }
        if w.marker_sha256 != pin.marker_sha256
            || w.journal_sha256 != pin.journal_sha256
            || w.acquisition_digest != expected {
            return Err(Error("WITNESS_CONFLICT"));
        }
        if !roots.insert(w.ancestry_root.as_str()) {
            return Err(Error("WITNESS_SHARED_ANCESTRY"));
        }
        matched += 1;
    }
    Ok(Assessment {
        independent_roots: roots.len(), matching_witnesses: matched,
        // Witness ancestry is merely DECLARED here, not independently verified.
        eligible_for_manual_review: false,
        decision: "HOLD", lock_cleared: false, external_authority: false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn pin() -> LocalPin { LocalPin {
        schema:"sapphon-134-local-pin-v1".into(), owner_pid:55,owner_start_ticks:1234,
        owner_boot_id:"01234567-aaaa-bbbb-cccc-dddddddddddd".into(),
        journal_sha256:"a".repeat(64),marker_sha256:"b".repeat(64)
    }}
    fn w(pin:&LocalPin,id:&str,ancestry:&str)->Witness {
        let digest=marker_digest(format!("sapphon-135-v1\n{}\n{}\n{}\n{}\n{}",
            pin.owner_pid,pin.owner_start_ticks,pin.owner_boot_id,
            pin.marker_sha256,pin.journal_sha256).as_bytes());
        Witness{witness_id:id.into(),custody_root:id.into(),ancestry_root:ancestry.into(),
            acquisition_digest:digest,marker_sha256:pin.marker_sha256.clone(),
            journal_sha256:pin.journal_sha256.clone()}
    }
    #[test] fn three_declared_roots_never_grant_authority(){
        let p=pin();let a=screen_witnesses(&p,&[w(&p,"first","root-one"),
            w(&p,"second","root-two"),w(&p,"third","root-three")]).unwrap();
        assert_eq!(a.independent_roots,3);
        assert!(!a.eligible_for_manual_review && !a.lock_cleared && !a.external_authority);
        assert_eq!(a.decision,"HOLD");
    }
    #[test] fn copied_ancestry_cannot_masquerade_as_multiple_roots(){
        let p=pin();assert_eq!(screen_witnesses(&p,&[w(&p,"first","same-root"),
            w(&p,"second","same-root")]).unwrap_err().0,"WITNESS_SHARED_ANCESTRY");
    }
    #[test] fn altered_digest_fails_closed(){
        let p=pin();let mut witness=w(&p,"first","root-one");
        witness.acquisition_digest="0".repeat(64);
        assert_eq!(screen_witnesses(&p,&[witness]).unwrap_err().0,"WITNESS_CONFLICT");
    }
    #[test] fn duplicated_identity_fails_closed(){
        let p=pin();assert_eq!(screen_witnesses(&p,&[w(&p,"same-id","root-one"),
            w(&p,"same-id","root-two")]).unwrap_err().0,"WITNESS_DUPLICATE_ID");
    }
    #[test] fn empty_witness_set_cannot_grant_recovery(){
        let p=pin();let a=screen_witnesses(&p,&[]).unwrap();
        assert_eq!(a.independent_roots,0);assert!(!a.eligible_for_manual_review);
    }
}
