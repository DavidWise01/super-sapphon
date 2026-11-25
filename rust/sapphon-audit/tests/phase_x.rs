use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sapphon_audit::{phase_x::close_phase_x, Journal, PinRegistry, PublisherPin, SignedSnapshot, SnapshotPayload, SNAPSHOT_SCHEMA};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn setup() -> (SigningKey,PinRegistry,SnapshotPayload) {
    let key=SigningKey::from_bytes(&[27u8;32]);
    let pins=BTreeMap::from([("publisher-one".into(), PublisherPin {
        control_root:"owned-root".into(),public_key:key.verifying_key().to_bytes(),revoked:false
    })]);
    let p=SnapshotPayload {schema:SNAPSHOT_SCHEMA.into(),publisher_id:"publisher-one".into(),
        control_root:"owned-root".into(),generation:1,issuer_generation:1,operator_generation:1,
        issuer_revoked:false,operator_revoked:false,previous_digest:None,
        mode:"synthetic-local-replica".into()};
    (key,pins,p)
}
fn signed(key:&SigningKey,p:SnapshotPayload)->SignedSnapshot {
    let sig=key.sign(&p.canonical_bytes().unwrap());
    SignedSnapshot {payload:p,signature:base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())}
}
fn sha(s:&SignedSnapshot)->String {hex::encode(Sha256::digest(s.payload.canonical_bytes().unwrap()))}
fn add(j:&mut Journal,s:SignedSnapshot,src:&str,ancestry:&[&str],pins:&PinRegistry) {
    j.ingest(s,src,ancestry.iter().map(|v|(*v).into()).collect(),pins).unwrap();
}
#[test]
fn phase_x_empty_journal_remains_hold() {
    let (_,pins,_)=setup();let r=close_phase_x(&Journal::default(),&pins).unwrap();
    assert_eq!(r.decision,"HOLD");assert_eq!(r.signed_observations,0);assert!(!r.external_effects_authorized);
}
#[test]
fn cross_generation_chain_preserves_predecessor() {
    let (key,pins,p)=setup();let first=signed(&key,p.clone());
    let second=signed(&key,SnapshotPayload {generation:2,previous_digest:Some(sha(&first)),..p});
    let mut j=Journal::default();
    add(&mut j,first,"source-alpha",&["owned-root"],&pins);
    add(&mut j,second,"source-beta",&["another-root"],&pins);
    let r=close_phase_x(&j,&pins).unwrap();
    assert_eq!(r.broken_predecessor_links,0);assert_eq!(r.generation_gaps,0);
}
#[test]
fn signed_broken_history_is_exposed() {
    let (key,pins,p)=setup();let mut j=Journal::default();
    add(&mut j,signed(&key,p.clone()),"first",&["owned-root"],&pins);
    add(&mut j,signed(&key,SnapshotPayload {generation:2,previous_digest:Some("f".repeat(64)),..p}),"second",&["owned-root"],&pins);
    let r=close_phase_x(&j,&pins).unwrap();
    assert_eq!(r.broken_predecessor_links,1);assert_eq!(r.decision,"HOLD");
}
#[test]
fn skipped_publication_generation_is_exposed() {
    let (key,pins,p)=setup();let one=signed(&key,p.clone());
    let three=signed(&key,SnapshotPayload {generation:3,previous_digest:Some(sha(&one)),..p});
    let mut j=Journal::default();
    add(&mut j,one,"first",&["owned-root"],&pins);
    add(&mut j,three,"second",&["owned-root"],&pins);
    assert_eq!(close_phase_x(&j,&pins).unwrap().generation_gaps,1);
}
#[test]
fn signed_revocation_resurrection_is_reported() {
    let (key,pins,p)=setup();
    let first=signed(&key,SnapshotPayload {issuer_revoked:true,..p.clone()});
    let second=signed(&key,SnapshotPayload {generation:2,previous_digest:Some(sha(&first)),..p});
    let mut j=Journal::default();
    add(&mut j,first,"first",&["owned-root"],&pins);
    add(&mut j,second,"second",&["owned-root"],&pins);
    assert_eq!(close_phase_x(&j,&pins).unwrap().revocation_resurrections,1);
}
#[test]
fn valid_signatures_with_same_generation_but_different_digest_are_forks() {
    let (key,pins,p)=setup();let mut j=Journal::default();
    add(&mut j,signed(&key,p.clone()),"source-a",&["first-root"],&pins);
    add(&mut j,signed(&key,SnapshotPayload {issuer_revoked:true,..p}),"source-b",&["second-root"],&pins);
    let r=close_phase_x(&j,&pins).unwrap();
    assert_eq!(r.conflicting_generations,1);assert_eq!(r.conflicting_digests,1);
    assert!(!r.cross_source_independence_authenticated);
}
#[test]
fn mirrored_sources_share_ancestry_and_cannot_prove_independence() {
    let (key,pins,p)=setup();let s=signed(&key,p);let mut j=Journal::default();
    add(&mut j,s.clone(),"github-mirror",&["owned-root"],&pins);
    add(&mut j,s,"pages-mirror",&["owned-root"],&pins);
    let r=close_phase_x(&j,&pins).unwrap();
    assert_eq!(r.shared_ancestry_pairs,1);
    assert!(!r.cross_source_independence_authenticated);
}
#[test]
fn shared_grandparent_is_one_ancestral_source() {
    let (key,pins,p)=setup();let mut j=Journal::default();
    add(&mut j,signed(&key,p.clone()),"source-a",&["alpha","ancestor"],&pins);
    add(&mut j,signed(&key,SnapshotPayload {operator_revoked:true,..p}),"source-b",&["beta","ancestor"],&pins);
    assert_eq!(close_phase_x(&j,&pins).unwrap().shared_ancestry_pairs,1);
}
#[test]
fn forged_signature_aborts_closure() {
    let (key,pins,p)=setup();let mut j=Journal::default();
    let s=signed(&key,p);add(&mut j,s,"good-source",&["owned-root"],&pins);
    let rogue=SigningKey::from_bytes(&[28u8;32]);
    j.observations[0].snapshot.signature=base64::engine::general_purpose::STANDARD.encode(
        rogue.sign(&j.observations[0].snapshot.payload.canonical_bytes().unwrap()).to_bytes());
    assert_eq!(close_phase_x(&j,&pins).unwrap_err().0,"SNAPSHOT_SIGNATURE");
}
#[test]
fn removed_conflict_ledger_blocks_phase_x() {
    let (key,pins,p)=setup();let mut j=Journal::default();
    add(&mut j,signed(&key,p.clone()),"source-a",&["owned-root"],&pins);
    add(&mut j,signed(&key,SnapshotPayload {issuer_revoked:true,..p}),"source-b",&["owned-root"],&pins);
    j.conflicts.clear();
    assert_eq!(close_phase_x(&j,&pins).unwrap_err().0,"MISSING_EQUIVOCATION_RECORD");
}
#[test]
fn malicious_utc_claim_cannot_enter_strict_snapshot_schema() {
    let (key,_,p)=setup();let sample=signed(&key,p);
    let mut v=serde_json::to_value(sample).unwrap();
    v["payload"]["trusted_utc"]=serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<SignedSnapshot>(v).is_err());
}
#[test]
fn phase_x_software_gate_never_grants_real_authority() {
    let (key,pins,p)=setup();let mut j=Journal::default();
    add(&mut j,signed(&key,p),"source-a",&["owned-root"],&pins);
    let r=close_phase_x(&j,&pins).unwrap();
    assert!(!r.physical_clock_authority);assert!(!r.utc_authority);
    assert!(!r.external_effects_authorized);assert_eq!(r.decision,"HOLD");
}
