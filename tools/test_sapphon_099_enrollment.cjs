"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {signedForTest,parseEntries,appendEvent,sourceTrust}=require("./sapphon_099_enrollment.cjs");
const {signForTest,verifyEnvelope}=require("./sapphon_097_auth.cjs");
const gov=crypto.generateKeyPairSync("ed25519"),impostor=crypto.generateKeyPairSync("ed25519"),
      original=crypto.generateKeyPairSync("ed25519"),replacement=crypto.generateKeyPairSync("ed25519"),
      extra=crypto.generateKeyPairSync("ed25519");
const pub=k=>k.export({type:"spki",format:"pem"});
const source="synthetic-archive",root="owned-test-origin";
const body=(type,key,index,generation,prev,options={})=>({
 type,source_id:options.source_id||source,ancestry_root:options.ancestry_root||root,role:options.role||"synthetic-test",
 key_id:key,public_key_pem:type==="REVOKE"?null:pub(options.public_key||original.publicKey),
 reason:type==="REVOKE"?(options.reason||"Synthetic compromised key"):null,
 generation,index,prev_event_hash:prev,
});
const e0=signedForTest(body("ENROLL","source-key-a",0,0,null),gov.privateKey);
const one=appendEvent([],e0,gov.publicKey);
const e1=signedForTest(body("REVOKE","source-key-a",1,0,one.head),gov.privateKey);
const two=appendEvent(one.entries,e1,gov.publicKey);
const e2=signedForTest(body("REENROLL","source-key-b",2,1,two.head,{public_key:replacement.publicKey}),gov.privateKey);
const three=appendEvent(two.entries,e2,gov.publicKey);
const copy=x=>JSON.parse(JSON.stringify(x));
let n=0;
function test(name,fn){fn();console.log("PASS",++n,name)}
function rejects(name,fn,error){test(name,()=>assert.throws(fn,e=>e.message===error))}
test("governance signed enrollment creates active synthetic key",()=>assert.equal(one.sources.get(source).status,"ACTIVE"));
test("enrollment cryptographically binds public key and source root",()=>{assert.equal(one.sources.get(source).root,root);assert.equal(one.sources.get(source).key_id,"source-key-a")});
test("revocation retains immutable historic enrollment entry",()=>{assert.equal(two.ledger.length,2);assert.equal(two.ledger[0].event_hash,one.head)});
rejects("revoked source cannot be used for signing",()=>sourceTrust(two,source),"SOURCE_NOT_ACTIVE");
test("re-enrollment requires new key and carries ancestry root",()=>{assert.equal(three.sources.get(source).key_id,"source-key-b");assert.equal(three.sources.get(source).root,root)});
test("re-enrolled signer can verify only correct new synthetic signature",()=>{
 const trust=sourceTrust(three,source),p={schema:"sapphon-source-envelope-v1",source_role:"synthetic-test",source_id:source,
 generation:1,start_seq:0,prev_hash:null,record_hashes:["a".repeat(64)]};
 const envelope=signForTest(p,replacement.privateKey,"source-key-b");
 assert.equal(verifyEnvelope(envelope,trust).status,"SIGNED_SYNTHETIC_TEST");
 assert.equal(verifyEnvelope(envelope,trust).authorized_time,false);
});
rejects("old key cannot sign after re-enrollment",()=>{
 const trust=sourceTrust(three,source),p={schema:"sapphon-source-envelope-v1",source_role:"synthetic-test",source_id:source,
 generation:1,start_seq:0,prev_hash:null,record_hashes:["a".repeat(64)]};
 verifyEnvelope(signForTest(p,original.privateKey,"source-key-a"),trust);
},"UNKNOWN_SIGNER");
rejects("forged governance signature rejected",()=>{
 const e=signedForTest(body("REVOKE","source-key-a",1,0,one.head),impostor.privateKey);
 appendEvent(one.entries,e,gov.publicKey);
},"GOVERNANCE_SIGNATURE");
rejects("altered reason rejects signed revocation",()=>{
 const e=copy(e1);e.event.reason="Quiet deletion";appendEvent(one.entries,e,gov.publicKey);
},"GOVERNANCE_SIGNATURE");
rejects("reordered ledger fails predecessor",()=>parseEntries([e1,e0],gov.publicKey),"BROKEN_LEDGER_CHAIN");
rejects("duplicate revocation rejected",()=>appendEvent(two.entries,
 signedForTest(body("REVOKE","source-key-a",2,0,two.head),gov.privateKey),gov.publicKey),"REVOCATION_CONFLICT");
rejects("re-enrollment without prior revocation rejected",()=>appendEvent(one.entries,
 signedForTest(body("REENROLL","source-key-b",1,1,one.head,{public_key:replacement.publicKey}),gov.privateKey),gov.publicKey),"REENROLLMENT_CONFLICT");
rejects("reused compromised public key rejected",()=>appendEvent(two.entries,
 signedForTest(body("REENROLL","source-key-b",2,1,two.head),gov.privateKey),gov.publicKey),"REUSED_COMPROMISED_KEY");
rejects("wrong generation re-enrollment rejected",()=>appendEvent(two.entries,
 signedForTest(body("REENROLL","source-key-b",2,2,two.head,{public_key:replacement.publicKey}),gov.privateKey),gov.publicKey),"REENROLLMENT_CONFLICT");
rejects("false ancestry root re-enrollment rejected",()=>appendEvent(two.entries,
 signedForTest(body("REENROLL","source-key-b",2,1,two.head,{public_key:replacement.publicKey,ancestry_root:"fake-second-origin"}),gov.privateKey),gov.publicKey),"REENROLLMENT_CONFLICT");
rejects("physical source claim blocked at enrollment",()=>appendEvent([],
 signedForTest(body("ENROLL","source-key-a",0,0,null,{role:"physical-source"}),gov.privateKey),gov.publicKey),"ROLE_NOT_ENROLLED");
rejects("missing revocation reason rejected",()=>appendEvent(one.entries,
 signedForTest({...body("REVOKE","source-key-a",1,0,one.head),reason:""},gov.privateKey),gov.publicKey),"REVOCATION_REASON");
rejects("event index gap rejected",()=>appendEvent(one.entries,
 signedForTest(body("REVOKE","source-key-a",3,0,one.head),gov.privateKey),gov.publicKey),"BROKEN_LEDGER_CHAIN");
rejects("incorrect previous event hash rejected",()=>appendEvent(one.entries,
 signedForTest(body("REVOKE","source-key-a",1,0,"f".repeat(64)),gov.privateKey),gov.publicKey),"BROKEN_LEDGER_CHAIN");
rejects("compromised key cannot be re-enrolled under old key ID",()=>appendEvent(two.entries,
 signedForTest(body("REENROLL","source-key-a",2,1,two.head,{public_key:replacement.publicKey}),gov.privateKey),gov.publicKey),"REENROLLMENT_CONFLICT");
test("second source may enroll but does not prove independent origin",()=>{
 const e=signedForTest(body("ENROLL","other-source-key",3,0,three.head,{source_id:"other-synthetic",public_key:extra.publicKey}),gov.privateKey);
 const four=appendEvent(three.entries,e,gov.publicKey);
 assert.equal(four.sources.size,2);assert.equal(four.sources.get("other-synthetic").root,root);
});
test("rejected mutations preserve prior immutable state",()=>{assert.equal(one.entries.length,1);assert.equal(two.entries.length,2);assert.equal(three.entries.length,3)});
console.log("SAPPHON-099:",n,"source enrollment/revocation tests passed");