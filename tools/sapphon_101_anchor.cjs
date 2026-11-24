"use strict";
/* SAPPHON-101 externally retained audit-anchor comparison.
   Anchor must be supplied from a separately trusted channel; GitHub is NOT one.
   Recomputes all event signatures and compares the complete pinned prefix.
   Never produces clock decisions or claims independent time witnesses. */
const crypto=require("node:crypto");
const {verifyCheckpoint}=require("./sapphon_100_checkpoint.cjs");
const {hashEvent}=require("./sapphon_099_enrollment.cjs");
function bad(reason){throw Error(reason)}
const id=/^[a-z0-9-]{4,64}$/;
function anchorFrom(ledger,checkpoint,governancePublicKey,keyId){
 const verified=verifyCheckpoint(ledger,checkpoint,governancePublicKey,keyId);
 const fingerprint=crypto.createHash("sha256").update(governancePublicKey.export({format:"der",type:"spki"})).digest("hex");
 return {schema:"sapphon-external-anchor-v1",key_id:keyId,governance_spki_sha256:fingerprint,
   head:verified.head,count:verified.event_count,checkpoint_signature:checkpoint.signature,
   independently_retained:false,recorded_utc:null};
}
function compare(anchor,baseLedger,baseCheckpoint,currentLedger,currentCheckpoint,governancePublicKey,keyId){
 if(!anchor||Object.keys(anchor).sort().join("|")!==["schema","key_id","governance_spki_sha256","head","count","checkpoint_signature","independently_retained","recorded_utc"].sort().join("|"))
   bad("ANCHOR_SCHEMA");
 if(anchor.schema!=="sapphon-external-anchor-v1"||anchor.key_id!==keyId||
  anchor.recorded_utc!==null||anchor.independently_retained!==false)bad("ANCHOR_SCOPE");
 const pinned=anchorFrom(baseLedger,baseCheckpoint,governancePublicKey,keyId);
 for(const key of ["key_id","governance_spki_sha256","head","count","checkpoint_signature"]){
   if(anchor[key]!==pinned[key])bad("PINNED_ANCHOR_MISMATCH");
 }
 // Require the same externally supplied anchor, even if the latest ledger is internally valid.
 const later=verifyCheckpoint(currentLedger,currentCheckpoint,governancePublicKey,keyId);
 if(later.event_count<anchor.count)bad("ROLLBACK");
 if(later.event_count===anchor.count&&later.head!==anchor.head)bad("SAME_HEIGHT_FORK");
 // Per-entry prefix checks detect divergence at any historical index, even if a fork
 // is independently re-signed under the same governance authority.
 for(let n=0;n<anchor.count;n++){
   if(!currentLedger[n])bad("MISSING_PREFIX");
   const a=baseLedger[n],b=currentLedger[n];
   if(hashEvent(a.event,a.signature)!==hashEvent(b.event,b.signature))
     bad("HISTORICAL_FORK_AT_"+n);
 }
 if(currentLedger[anchor.count-1].event.prev_event_hash!==baseLedger[anchor.count-1].event.prev_event_hash)
   bad("HISTORICAL_FORK");
 return {status:later.event_count===anchor.count?"ANCHOR_MATCH":"APPEND_ONLY_CONTINUATION",
  anchored_count:anchor.count,latest_count:later.event_count,new_events:later.event_count-anchor.count,
  source_roots_authenticated:false,independent_anchor_confirmed:false,utc_authority:false,
  anchor_head:anchor.head,latest_head:later.head};
}
module.exports={anchorFrom,compare};