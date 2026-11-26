//! SAPPHON-156 — dual-acquisition artifact custody review.
//! Different retrieval endpoints are not necessarily independent custody roots.
//! All claimed ancestry and externally pinned digests remain caller-provided.
#![cfg(target_os = "linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const MAX:usize=1024*1024;
fn hash(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn good_hash(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn good_commit(s:&str)->bool{s.len()==40&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt{
    pub schema:String,
    pub acquisition_id:String,
    pub acquisition_operator:String,
    pub claimed_custody_root:String,
    pub source_ancestry_sha256:String,
    pub artifact_sha256:String,
    pub repository:String,
    pub commit_sha:String,
    pub run_id:u64,
    pub attempt:u32,
}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
pub enum Finding{
    MatchingClaimedIndependentRootsUnqualified,
    SameAcquisitionOrOperator,
    SharedSourceAncestry,
    ConflictingArtifactDigest,
    ExternalPinnedDigestMismatch,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Review{
    pub schema:String,
    pub finding:Finding,
    pub acquisition_ids:Vec<String>,
    pub artifact_sha256_first:String,
    pub artifact_sha256_second:String,
    pub externally_claimed_sha256:String,
    pub evidence_statement_sha256:String,
    pub byte_agreement:bool,
    pub claimed_roots_distinct:bool,
    pub authenticated_custody_independence:bool,
    pub global_anti_rollback_authenticated:bool,
    pub recovery_authorized:bool,
    pub lock_cleared:bool,
    pub decision:String,
}
/// Strict comparison of two acquisition statements, not authentication of
/// their physical origin. The expected digest must be independently retained.
pub fn compare(first:&Receipt,second:&Receipt,expected_sha256:&str)->Result<Review,Error>{
    if !good_hash(expected_sha256) {return Err(Error("CUST156_EXPECTED_DIGEST"));}
    for r in [first,second]{
        if r.schema!="sapphon-156-receipt-v1"
           ||r.acquisition_id.is_empty()||r.acquisition_id.len()>128
           ||r.acquisition_operator.is_empty()||r.acquisition_operator.len()>128
           ||r.claimed_custody_root.is_empty()||r.claimed_custody_root.len()>128
           ||r.repository.is_empty()||r.repository.len()>256
           ||!good_hash(&r.source_ancestry_sha256)||!good_hash(&r.artifact_sha256)
           ||!good_commit(&r.commit_sha)||r.run_id==0||r.attempt==0 {
            return Err(Error("CUST156_RECEIPT_FIELDS"));
        }
    }
    if first.repository!=second.repository||first.commit_sha!=second.commit_sha
        ||first.run_id!=second.run_id||first.attempt!=second.attempt{
        return Err(Error("CUST156_DIFFERENT_RUN"));
    }
    let (a,b)=if first.acquisition_id<=second.acquisition_id {
        (first,second)
    }else{(second,first)};
    let distinct_roots=a.claimed_custody_root!=b.claimed_custody_root;
    let same_acquisition=a.acquisition_id==b.acquisition_id
        ||a.acquisition_operator==b.acquisition_operator;
    let finding=if same_acquisition{
        Finding::SameAcquisitionOrOperator
    }else if a.source_ancestry_sha256==b.source_ancestry_sha256
        ||!distinct_roots {
        Finding::SharedSourceAncestry
    }else if a.artifact_sha256!=b.artifact_sha256{
        Finding::ConflictingArtifactDigest
    }else if a.artifact_sha256!=expected_sha256{
        Finding::ExternalPinnedDigestMismatch
    }else{
        Finding::MatchingClaimedIndependentRootsUnqualified
    };
    let bytes=serde_json::to_vec(&(a,b,expected_sha256))
        .map_err(|_|Error("CUST156_ENCODING"))?;
    Ok(Review{
        schema:"sapphon-156-dual-receipt-review-v1".into(),
        finding,acquisition_ids:vec![a.acquisition_id.clone(),b.acquisition_id.clone()],
        artifact_sha256_first:a.artifact_sha256.clone(),
        artifact_sha256_second:b.artifact_sha256.clone(),
        externally_claimed_sha256:expected_sha256.into(),
        evidence_statement_sha256:hash(&bytes),
        byte_agreement:a.artifact_sha256==b.artifact_sha256,
        claimed_roots_distinct:distinct_roots,
        authenticated_custody_independence:false,
        global_anti_rollback_authenticated:false,
        recovery_authorized:false,lock_cleared:false,decision:"DUAL_READBACK_HOLD".into()
    })
}
/// Refuse duplicate acquisition IDs in a record collection even if each
/// operator presents a different display label.
pub fn validate_batch(receipts:&[Receipt])->Result<(),Error>{
    if receipts.is_empty()||receipts.len()>32{return Err(Error("CUST156_BATCH_LIMIT"));}
    let mut ids=BTreeSet::new();
    for r in receipts{
        if !ids.insert(r.acquisition_id.as_str()){
            return Err(Error("CUST156_DUPLICATE_ACQUISITION"));
        }
    }
    Ok(())
}
pub fn write_new(path:&Path,review:&Review)->Result<String,Error>{
    if review.schema!="sapphon-156-dual-receipt-review-v1"
        ||review.decision!="DUAL_READBACK_HOLD"
        ||review.authenticated_custody_independence
        ||review.global_anti_rollback_authenticated
        ||review.recovery_authorized||review.lock_cleared{
        return Err(Error("CUST156_AUTHORITY"));
    }
    let bytes=serde_json::to_vec(review).map_err(|_|Error("CUST156_ENCODING"))?;
    if bytes.len()>MAX{return Err(Error("CUST156_SIZE"));}
    let mut f=OpenOptions::new().create_new(true).write(true).open(path)
        .map_err(|_|Error("CUST156_EXISTS"))?;
    f.write_all(&bytes).map_err(|_|Error("CUST156_WRITE"))?;
    f.sync_all().map_err(|_|Error("CUST156_FSYNC"))?;
    File::open(path.parent().ok_or(Error("CUST156_PARENT"))?)
        .and_then(|p|p.sync_all()).map_err(|_|Error("CUST156_DIRSYNC"))?;
    Ok(hash(&bytes))
}
#[cfg(test)]
mod tests{
    use super::*;
    fn receipt(id:&str,operator:&str,root:&str,source:&str,digest:&str)->Receipt{
        Receipt{schema:"sapphon-156-receipt-v1".into(),
            acquisition_id:id.into(),acquisition_operator:operator.into(),
            claimed_custody_root:root.into(),source_ancestry_sha256:source.into(),
            artifact_sha256:digest.into(),repository:"DavidWise01/super-sapphon".into(),
            commit_sha:"a".repeat(40),run_id:42,attempt:2}
    }
    fn pair()->(Receipt,Receipt,String){
        let expected="b".repeat(64);
        (receipt("readback-one","operator-a","github-actions",&"1".repeat(64),&expected),
         receipt("readback-two","operator-b","custodian-external",&"2".repeat(64),&expected),
         expected)
    }
    #[test]fn two_claimed_roots_cannot_prove_custody(){
        let(a,b,h)=pair();let r=compare(&a,&b,&h).unwrap();
        assert_eq!(r.finding,Finding::MatchingClaimedIndependentRootsUnqualified);
        assert!(r.byte_agreement&&r.claimed_roots_distinct);
        assert!(!r.authenticated_custody_independence&&!r.recovery_authorized);
    }
    #[test]fn distinct_labels_same_ancestry_are_not_independent(){
        let(a,mut b,h)=pair();b.source_ancestry_sha256=a.source_ancestry_sha256.clone();
        assert_eq!(compare(&a,&b,&h).unwrap().finding,Finding::SharedSourceAncestry);
    }
    #[test]fn mirrored_github_copy_same_declared_root_detected(){
        let(a,mut b,h)=pair();b.claimed_custody_root=a.claimed_custody_root.clone();
        assert_eq!(compare(&a,&b,&h).unwrap().finding,Finding::SharedSourceAncestry);
    }
    #[test]fn different_artifact_bytes_are_conflict(){
        let(a,mut b,h)=pair();b.artifact_sha256="c".repeat(64);
        assert_eq!(compare(&a,&b,&h).unwrap().finding,Finding::ConflictingArtifactDigest);
    }
    #[test]fn externally_pinned_digest_mismatch_fails_closed(){
        let(a,b,_)=pair();let r=compare(&a,&b,&"d".repeat(64)).unwrap();
        assert_eq!(r.finding,Finding::ExternalPinnedDigestMismatch);
    }
    #[test]fn replayed_acquisition_id_cannot_be_second_witness(){
        let(a,mut b,h)=pair();b.acquisition_id=a.acquisition_id.clone();
        assert_eq!(compare(&a,&b,&h).unwrap().finding,Finding::SameAcquisitionOrOperator);
        assert_eq!(validate_batch(&[a,b]).unwrap_err().0,
            "CUST156_DUPLICATE_ACQUISITION");
    }
    #[test]fn mismatched_run_attempt_rejected(){
        let(a,mut b,h)=pair();b.attempt=3;
        assert_eq!(compare(&a,&b,&h).unwrap_err().0,"CUST156_DIFFERENT_RUN");
    }
    #[test]fn swapping_receipts_preserves_digest(){
        let(a,b,h)=pair();assert_eq!(compare(&a,&b,&h).unwrap(),compare(&b,&a,&h).unwrap());
    }
    #[test]fn create_only_hold_receipt_cannot_overwrite(){
        let(a,b,h)=pair();let r=compare(&a,&b,&h).unwrap();
        let path=std::env::temp_dir().join(format!("sapphon156-{}.json",std::process::id()));
        let _=std::fs::remove_file(&path);
        write_new(&path,&r).unwrap();
        assert_eq!(write_new(&path,&r).unwrap_err().0,"CUST156_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
