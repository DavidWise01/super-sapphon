"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {canonical,testEnvelope,inspectEnvelope,gate}=require("./sapphon_105_intake.cjs");
const keys=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519"),other=crypto.generateKeyPairSync("ed25519");
const hex=x=>crypto.createHash("sha256").update(x).digest("hex");
const fingerprint=p=>hex(p.export({type:"spki",format:"der"}));
const domain="davidwise01.github.io";
const custody={schema:"sapphon-external-intake-v1",root_id:"synthetic-custodian",
 public_key_spki_sha256:fingerprint(keys.publicKey),source_kind:"custodian",
 ownership_domain:domain,reference:"https://example.org/test-evidence-only",
 evidence_sha256:"a".repeat(64),declared_independent:true,
 calibration_reference:"",calibration_sha256:""};
const physical={...custody,root_id:"synthetic-physical",
 public_key_spki_sha256:fingerprint(other.publicKey),source_kind:"physical-clock",
 ownership_domain:"test-physical-fixture",calibration_reference:"synthetic-calibration",
 calibration_sha256:"b".repeat(64)};
const e1=testEnvelope(custody,keys.privateKey,"test-owner-key");
const e2=testEnvelope(physical,other.privateKey,"test-physical-key");
const registry={
 "test-owner-key":{publicKey:keys.publicKey,root_id:custody.root_id,source_kind:custody.source_kind,ownership_domain:domain,external_review_evidence:true},
 "test-physical-key":{publicKey:other.publicKey,root_id:physical.root_id,source_kind:physical.source_kind,ownership_domain:physical.ownership_domain,external_review_evidence:true,calibration_review_evidence:true}
};
const copy=x=>JSON.parse(JSON.stringify(x));let n=0;
function check(name,fn){fn();console.log("PASS",++n,name)}
function rejects(name,fn,code){check(name,()=>assert.throws(fn,e=>e.message===code))}
check("valid synthetic custody signature cannot grant external qualification",()=>{
 const out=inspectEnvelope(e1,registry,[domain]);assert.equal(out.signature_verified,true);
 assert.equal(out.ownership_collision,true);assert.equal(out.external_custody_qualified,false);
 assert.equal(out.decision,"HOLD");
});
check("physical fixture signature and claimed calibration cannot prove physical UTC",()=>{
 const out=inspectEnvelope(e2,registry,[domain]);assert.equal(out.physical_clock_qualified,false);
 assert.equal(out.calibration_review_declared,true);assert.equal(out.utc_authorized,false);
});
check("combined signed sources still hold both qualification gates",()=>{
 const out=gate([e1,e2],registry,[domain]);assert.equal(out.verified_signatures,2);
 assert.equal(out.external_custody,"HOLD");assert.equal(out.physical_clock,"HOLD");
 assert.equal(out.independent_physical_sources,0);assert.equal(out.independent_custodians,0);
});
rejects("tampered declared independence rejected by signature",()=>{
 const x=copy(e1);x.payload.declared_independent=false;inspectEnvelope(x,registry,[domain]);
},"BAD_SOURCE_SIGNATURE");
rejects("forged evidence digest rejected by signature",()=>{
 const x=copy(e1);x.payload.evidence_sha256="c".repeat(64);inspectEnvelope(x,registry,[domain]);
},"BAD_SOURCE_SIGNATURE");
rejects("substituted ownership domain blocked",()=>{
 const x=testEnvelope({...custody,ownership_domain:"pretend-independent"},keys.privateKey,"test-owner-key");
 inspectEnvelope(x,registry,[domain]);
},"ROOT_IDENTITY_MISMATCH");
rejects("wrong signer rejected",()=>{
 const x=testEnvelope(custody,rogue.privateKey,"test-owner-key");
 inspectEnvelope(x,registry,[domain]);
},"BAD_SOURCE_SIGNATURE");
rejects("unknown root rejected",()=>inspectEnvelope({...e1,key_id:"outsider-key"},registry,[domain]),"UNTRUSTED_ROOT");
rejects("revoked source key rejected",()=>inspectEnvelope(e1,{"test-owner-key":{...registry["test-owner-key"],revoked:true}},[domain]),"REVOKED_ROOT");
rejects("different public key cannot impersonate enrolled source",()=>{
 inspectEnvelope(e1,{"test-owner-key":{...registry["test-owner-key"],publicKey:rogue.publicKey}},[domain]);
},"ROOT_IDENTITY_MISMATCH");
rejects("duplicate source root cannot be double-counted",()=>gate([e1,e1],registry,[domain]),"DUPLICATE_SOURCE_ROOT");
rejects("physical claim missing calibration digest rejected",()=>canonical({...physical,calibration_sha256:""}),"CALIBRATION_REQUIRED");
rejects("custodian cannot carry physical calibration fields",()=>canonical({...custody,calibration_sha256:"d".repeat(64)}),"CUSTODIAN_CALIBRATION_CONFLICT");
rejects("unknown source kind rejected",()=>canonical({...custody,source_kind:"independent-by-declaration"}),"INTAKE_SCHEMA");
rejects("unauthorized clock field rejected",()=>canonical({...custody,clock_authority:true}),"INTAKE_SCHEMA");
rejects("untrusted ownership reference with malformed hash rejected",()=>canonical({...custody,evidence_sha256:"na"}),"INTAKE_SCHEMA");
check("valid source structures retain exact declared source ancestry",()=>{
 assert.equal(gate([e1,e2],registry,[domain]).assessments[0].ownership_collision,true);
});
check("cryptographic intake does not modify frozen payloads",()=>{
 const before=JSON.stringify([e1,e2]);gate([e1,e2],registry,[domain]);assert.equal(JSON.stringify([e1,e2]),before);
});
console.log("SAPPHON-105:",n,"external evidence qualification checks passed");
