"use strict";
/* SAPPHON-100: governance-signed audit checkpoint over SAPPHON-099 ledger.
 * Verifies entire original enrollment chain, fixes an exact head and publishes
 * deterministic source-state summary. Signed != independently witnessed.
 */
const crypto=require("node:crypto");
const {parseEntries}=require("./sapphon_099_enrollment.cjs");
function fail(code){throw Error(code)}
function summary(parsed){
 return [...parsed.sources.values()].map(s=>({
   source_id:s.source_id,ancestry_root:s.root,role:s.role,
   key_id:s.key_id,generation:s.generation,status:s.status
 })).sort((a,b)=>a.source_id.localeCompare(b.source_id,"en"));
}
function payloadBytes(p){
 if(!p||Object.keys(p).sort().join("|")!==["schema","head","count","sources","governance_key_id"].sort().join("|"))
   fail("CHECKPOINT_FIELDS");
 if(p.schema!=="sapphon-enrollment-checkpoint-v1"||typeof p.governance_key_id!=="string"||
  !/^[a-z0-9-]{4,64}$/.test(p.governance_key_id)||
  !Number.isSafeInteger(p.count)||p.count<1||p.count>4096||
  typeof p.head!=="string"||!/^[a-f0-9]{64}$/.test(p.head)||
  !Array.isArray(p.sources))fail("CHECKPOINT_FORMAT");
 const keys=["source_id","ancestry_root","role","key_id","generation","status"];
 for(const s of p.sources) {
  if(!s||Object.keys(s).sort().join("|")!==keys.slice().sort().join("|")||
   !Number.isSafeInteger(s.generation)||s.generation<0||
   !["ACTIVE","REVOKED"].includes(s.status))fail("CHECKPOINT_SOURCE_FORMAT");
 }
 return Buffer.from(JSON.stringify([p.schema,p.head,p.count,p.governance_key_id,
  p.sources.map(s=>keys.map(k=>s[k]))]),"utf8");
}
function createCheckpoint(entries,governancePrivateKey,governancePublicKey,keyId){
 const parsed=parseEntries(entries,governancePublicKey);
 if(!parsed.head)fail("EMPTY_LEDGER");
 const payload={schema:"sapphon-enrollment-checkpoint-v1",head:parsed.head,
  count:entries.length,governance_key_id:keyId,sources:summary(parsed)};
 return {payload,signature:crypto.sign(null,payloadBytes(payload),governancePrivateKey).toString("base64")};
}
function verifyCheckpoint(entries,cp,governancePublicKey,expectedKeyId){
 if(!cp||Object.keys(cp).sort().join("|")!=="payload|signature")fail("CHECKPOINT_ENVELOPE");
 const bytes=payloadBytes(cp.payload);
 if(cp.payload.governance_key_id!==expectedKeyId)fail("UNTRUSTED_GOVERNANCE_KEY");
 if(typeof cp.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(cp.signature)||
   !crypto.verify(null,bytes,governancePublicKey,Buffer.from(cp.signature,"base64")))
   fail("CHECKPOINT_SIGNATURE");
 const parsed=parseEntries(entries,governancePublicKey);
 if(cp.payload.head!==parsed.head||cp.payload.count!==entries.length)fail("HEAD_MISMATCH");
 if(JSON.stringify(cp.payload.sources)!==JSON.stringify(summary(parsed)))fail("SOURCE_STATE_MISMATCH");
 return {status:"VALID_SAME_GOVERNANCE_ROOT",event_count:parsed.ledger.length,
  root_count:new Set(cp.payload.sources.map(s=>s.ancestry_root)).size,
  head:parsed.head,independent_witnesses_verified:false,clock_authority:false};
}
module.exports={summary,payloadBytes,createCheckpoint,verifyCheckpoint};
