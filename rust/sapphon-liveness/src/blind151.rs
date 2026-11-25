//! SAPPHON-151: blinded cross-custody adversarial challenge matrix.
//! The challenge records provenance claims; it does not prove physical custody.
#![cfg(target_os="linux")]
use crate::{anchor145::{self,Anchor,ProvisionedProvider},Error};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use std::{collections::{BTreeMap,BTreeSet},fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const LIMIT:usize=1024*1024;
fn hash(bytes:&[u8])->String{hex::encode(Sha256::digest(bytes))}
fn digest_ok(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ChallengePacket{
    pub schema:String,
    pub case_id:String,
    pub display_name:String,
    pub claimed_root:String,
    pub receipt_origin_sha256:String,
    pub registry_sha256:String,
    pub intent_sha256:String,
    pub provider_config_sha256:String,
    pub anchor:Anchor,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq,PartialOrd,Ord)]
#[serde(deny_unknown_fields)]
pub struct Finding{
    pub kind:String,
    pub left_id:String,
    pub right_id:String,
    pub detail:String,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ChallengeReport{
    pub schema:String,
    pub challenge_id:String,
    pub packet_ids:Vec<String>,
    pub findings:Vec<Finding>,
    pub verified_signatures:usize,
    pub claimed_roots:usize,
    pub independent_custody_proven:bool,
    pub recovery_authorized:bool,
    pub replacement_key_accepted:bool,
    pub lock_cleared:bool,
    pub decision:String,
}
fn packet_valid(p:&ChallengePacket)->bool{
    p.schema=="sapphon-151-packet-v1" && !p.case_id.is_empty() &&
      p.case_id.len()<=64 && !p.claimed_root.is_empty() &&
      p.claimed_root.len()<=128 &&
      digest_ok(&p.receipt_origin_sha256) &&
      digest_ok(&p.registry_sha256) &&
      digest_ok(&p.intent_sha256) &&
      digest_ok(&p.provider_config_sha256)
}
/// Trusted providers must come from an independently provisioned caller, not
/// the packet being challenged. Display names have no security meaning.
/// Same-byte mirrors and same-ancestry claims are never independent votes.
pub fn challenge(
    challenge_id:&str,packets:&[ChallengePacket],
    trusted:&[ProvisionedProvider],
)->Result<ChallengeReport,Error>{
    if challenge_id.is_empty()||challenge_id.len()>96||
       packets.is_empty()||packets.len()>32||trusted.len()>32{
        return Err(Error("CHALLENGE_FIELDS"));
    }
    let mut providers=BTreeMap::new();
    for p in trusted{
        if providers.insert(p.provider_id.as_str(),p).is_some(){
            return Err(Error("CHALLENGE_PROVIDER_DUPLICATE"));
        }
    }
    let mut seen=BTreeSet::new();
    for p in packets{
        if !packet_valid(p)||!seen.insert(p.case_id.as_str()){
            return Err(Error("CHALLENGE_PACKET_FIELDS"));
        }
        let provider=providers.get(p.anchor.provider_id.as_str())
            .ok_or(Error("CHALLENGE_UNTRUSTED_PROVIDER"))?;
        anchor145::verify_anchor(&p.anchor,provider)?;
    }
    let mut ordered=packets.to_vec();
    ordered.sort_by(|a,b|a.case_id.cmp(&b.case_id));
    let mut findings=BTreeSet::new();
    let mut roots=BTreeSet::new();
    for p in &ordered {roots.insert(p.claimed_root.as_str());}
    for i in 0..ordered.len(){
        for j in i+1..ordered.len(){
            let a=&ordered[i];let b=&ordered[j];
            let mut add=|kind:&str,detail:&str|{
                findings.insert(Finding{kind:kind.into(),left_id:a.case_id.clone(),
                    right_id:b.case_id.clone(),detail:detail.into()});
            };
            if a.claimed_root==b.claimed_root{
                add("SHARED_ANCESTRY","Same declared origin is not a second witness");
            }
            if a.receipt_origin_sha256==b.receipt_origin_sha256{
                add("COPIED_RECEIPT_ANCESTRY","Same originating receipt fingerprint");
            }
            if a.registry_sha256==b.registry_sha256 &&
                a.intent_sha256==b.intent_sha256 &&
                a.provider_config_sha256==b.provider_config_sha256{
                add("MIRRORED_STATE","Three matching local copies do not imply custody independence");
            }
            if a.anchor.provider_id==b.anchor.provider_id{
                add("SHARED_SIGNER","One provisioned provider cannot count twice");
                if a.anchor.sequence==b.anchor.sequence &&
                   a.anchor.head_sha256!=b.anchor.head_sha256{
                    add("SIGNED_EQUIVOCATION","One key claims different heads at same sequence");
                }
            }else{
                let pa=providers.get(a.anchor.provider_id.as_str())
                    .ok_or(Error("CHALLENGE_UNTRUSTED_PROVIDER"))?;
                let pb=providers.get(b.anchor.provider_id.as_str())
                    .ok_or(Error("CHALLENGE_UNTRUSTED_PROVIDER"))?;
                if pa.public_key_hex==pb.public_key_hex{
                    add("SHARED_PUBLIC_KEY","Distinct names retain same verification key");
                }
                if a.anchor.sequence==b.anchor.sequence &&
                    a.anchor.head_sha256!=b.anchor.head_sha256{
                    add("CROSS_PROVIDER_CONFLICT","Signed same-sequence heads diverge");
                }else if a.anchor.sequence!=b.anchor.sequence{
                    add("ASYNC_SEQUENCE","Different floors need prefix ancestry verification");
                }
            }
        }
    }
    Ok(ChallengeReport{
        schema:"sapphon-151-blind-challenge-v1".into(),
        challenge_id:challenge_id.into(),
        packet_ids:ordered.iter().map(|p|p.case_id.clone()).collect(),
        findings:findings.into_iter().collect(),
        verified_signatures:ordered.len(),
        claimed_roots:roots.len(),
        independent_custody_proven:false,recovery_authorized:false,
        replacement_key_accepted:false,lock_cleared:false,decision:"HOLD".into()
    })
}
/// Create-only report with exact digest. Custody of the digest remains external.
pub fn write_new(path:&Path,r:&ChallengeReport)->Result<String,Error>{
    if r.schema!="sapphon-151-blind-challenge-v1" ||r.decision!="HOLD"||
       r.independent_custody_proven||r.recovery_authorized||
       r.replacement_key_accepted||r.lock_cleared{
        return Err(Error("CHALLENGE_REPORT_FIELDS"));
    }
    let bytes=serde_json::to_vec(r).map_err(|_|Error("CHALLENGE_ENCODING"))?;
    if bytes.len()>LIMIT{return Err(Error("CHALLENGE_LIMIT"));}
    let mut f=OpenOptions::new().create_new(true).write(true).open(path)
       .map_err(|_|Error("CHALLENGE_ALREADY_EXISTS"))?;
    f.write_all(&bytes).map_err(|_|Error("CHALLENGE_WRITE"))?;
    f.sync_all().map_err(|_|Error("CHALLENGE_FSYNC"))?;
    File::open(path.parent().ok_or(Error("CHALLENGE_PARENT"))?)
       .and_then(|p|p.sync_all()).map_err(|_|Error("CHALLENGE_DIRSYNC"))?;
    Ok(hash(&bytes))
}
#[cfg(test)]
mod tests{
    use super::*;
    use base64::{engine::general_purpose::STANDARD,Engine as _};
    use ed25519_dalek::{Signer,SigningKey};
    fn provider(seed:u8,id:&str)->(SigningKey,ProvisionedProvider){
        let sk=SigningKey::from_bytes(&[seed;32]);
        let p=ProvisionedProvider{provider_id:id.into(),
            public_key_hex:hex::encode(sk.verifying_key().as_bytes()),
            min_counter:0,min_sequence:0,min_epoch:0,revoked:false};
        (sk,p)
    }
    fn packet(sk:&SigningKey,id:&str,case:&str,root:&str,head:&str)->ChallengePacket{
        let mut a=Anchor{schema:"sapphon-145-anchor-v1".into(),
            provider_id:id.into(),sequence:1,head_sha256:head.into(),
            epoch:2,counter:3,signature_base64:String::new()};
        a.signature_base64=STANDARD.encode(sk.sign(&anchor145::anchor_message(&a)).to_bytes());
        ChallengePacket{schema:"sapphon-151-packet-v1".into(),
            case_id:case.into(),display_name:format!("Witness {case}"),
            claimed_root:root.into(),receipt_origin_sha256:"a".repeat(64),
            registry_sha256:"b".repeat(64),intent_sha256:"c".repeat(64),
            provider_config_sha256:"d".repeat(64),anchor:a}
    }
    #[test]fn same_root_and_copied_receipt_detected(){
        let(sk,p)=provider(1,"provider-a");
        let a=packet(&sk,"provider-a","a","shared-root",&"e".repeat(64));
        let b=packet(&sk,"provider-a","b","shared-root",&"e".repeat(64));
        let r=challenge("blind-case",&[a,b],&[p]).unwrap();
        assert!(r.findings.iter().any(|f|f.kind=="SHARED_ANCESTRY"));
        assert!(r.findings.iter().any(|f|f.kind=="COPIED_RECEIPT_ANCESTRY"));
        assert!(!r.independent_custody_proven&&!r.recovery_authorized);
    }
    #[test]fn two_valid_keys_with_conflicting_heads_stay_hold(){
        let(sa,pa)=provider(1,"provider-a");
        let(sb,pb)=provider(2,"provider-b");
        let a=packet(&sa,"provider-a","a","root-one",&"e".repeat(64));
        let b=packet(&sb,"provider-b","b","root-two",&"f".repeat(64));
        let r=challenge("case",&[a,b],&[pa,pb]).unwrap();
        assert!(r.findings.iter().any(|f|f.kind=="CROSS_PROVIDER_CONFLICT"));
        assert_eq!(r.verified_signatures,2);
        assert_eq!(r.decision,"HOLD");
    }
    #[test]fn display_names_cannot_change_finding(){
        let(sa,pa)=provider(1,"provider-a");let(sb,pb)=provider(2,"provider-b");
        let a=packet(&sa,"provider-a","a","root-one",&"e".repeat(64));
        let mut b=packet(&sb,"provider-b","b","root-two",&"e".repeat(64));
        let x=challenge("case",&[a.clone(),b.clone()],&[pa.clone(),pb.clone()]).unwrap();
        b.display_name="Independent miracle witness".into();
        let y=challenge("case",&[b,a],&[pb,pa]).unwrap();
        assert_eq!(x,y);
    }
    #[test]fn forged_signed_packet_rejected(){
        let(sa,pa)=provider(1,"provider-a");
        let mut a=packet(&sa,"provider-a","a","root-one",&"e".repeat(64));
        a.anchor.signature_base64=STANDARD.encode([0u8;64]);
        assert_eq!(challenge("case",&[a],&[pa]).unwrap_err().0,"ANCHOR_SIGNATURE");
    }
    #[test]fn missing_trusted_provider_fails_closed(){
        let(sa,_)=provider(1,"provider-a");
        let a=packet(&sa,"provider-a","a","root-one",&"e".repeat(64));
        assert_eq!(challenge("case",&[a],&[]).unwrap_err().0,
           "CHALLENGE_UNTRUSTED_PROVIDER");
    }
    #[test]fn asynchronous_claims_not_labeled_equivocation(){
        let(sa,pa)=provider(1,"provider-a");let(sb,pb)=provider(2,"provider-b");
        let a=packet(&sa,"provider-a","a","root-one",&"e".repeat(64));
        let mut b=packet(&sb,"provider-b","b","root-two",&"f".repeat(64));
        b.anchor.sequence=2;
        b.anchor.signature_base64=STANDARD.encode(sb.sign(&anchor145::anchor_message(&b.anchor)).to_bytes());
        let r=challenge("case",&[a,b],&[pa,pb]).unwrap();
        assert!(r.findings.iter().any(|f|f.kind=="ASYNC_SEQUENCE"));
        assert!(!r.findings.iter().any(|f|f.kind=="CROSS_PROVIDER_CONFLICT"));
    }
    #[test]fn create_only_report_cannot_overwrite(){
        let(sa,pa)=provider(1,"provider-a");
        let a=packet(&sa,"provider-a","a","root-one",&"e".repeat(64));
        let r=challenge("case",&[a],&[pa]).unwrap();
        let path=std::env::temp_dir().join(format!("sapphon151-{}.json",std::process::id()));
        let _=std::fs::remove_file(&path);
        write_new(&path,&r).unwrap();
        assert_eq!(write_new(&path,&r).unwrap_err().0,"CHALLENGE_ALREADY_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
