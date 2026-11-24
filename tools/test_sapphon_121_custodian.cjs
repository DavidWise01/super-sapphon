"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {enrollmentForTest,enrollmentBytes,attestationBytes,signForTest,assess}=require("./sapphon_121_custodian.cjs");
const {canonical:checkpointBytes}=require("./sapphon_118_anchor.cjs");
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
const owner="davidwise01-owned-github";
const ck={schema:"sapphon-118-checkpoint-v1",anchor_id:"test-anchorer",custody_root:owner,
 receiver_id:"receiver-one",revision:17,state_sha256:"a".repeat(64),
 previous_checkpoint_sha256:"b".repeat(64),mode:"synthetic-local-anchor"};
const keys=[0,1,2].map(()=>crypto.generateKeyPairSync("ed25519"));
const roots=["test-custody-root-a","test-custody-root-b","test-custody-root-c"];
const enrollments=keys.map((k,i)=>enrollmentForTest("custodian-"+(i+1),roots[i],"test-custodian-key-"+(i+1),
 k.publicKey,[roots[i]]));
const registry=Object.fromEntries(keys.map((k,i)=>[enrollments[i].key_id,
 {publicKey:k.publicKey,custodian_id:enrollments[i].custodian_id,custody_root:roots[i]}]));
function signed(e,i,changes={}){
 return signForTest({schema:"sapphon-121-custody-attestation-v1",
 custodian_id:e.custodian_id,custody_root:e.custody_root,key_id:e.key_id,
 receiver_id:ck.receiver_id,receiver_revision:ck.revision,receiver_state_sha256:ck.state_sha256,
 checkpoint_sha256:sha(checkpointBytes(ck)),previous_anchor_sha256:ck.previous_checkpoint_sha256,
 kind:"synthetic-retention-fixture",...changes},keys[i].privateKey);
}
const a=enrollments.map((e,i)=>signed(e,i));
function run(ee=enrollments.slice(0,2),aa=a.slice(0,2),reg=registry,sources=[owner]){
 return assess({checkpoint:ck,enrollments:ee,attestations:aa,registry:reg,sourceAncestry:sources});
}
let count=0;function check(name,fn){fn();count++;console.log("PASS",count,name)}
function rejects(name,fn,code){check(name,()=>assert.throws(fn,e=>e.message===code))}
const copy=x=>JSON.parse(JSON.stringify(x));
check("two synthetic signers with declared disjoint roots still cannot claim external authority",()=>{
 const x=run();assert.equal(x.tested_custodians,2);assert.equal(x.decision,"HOLD");
 assert.equal(x.ancestry_independence_authenticated,false);assert.equal(x.utc_authority,false);
});
check("one custodian still returns HOLD",()=>assert.equal(run(enrollments.slice(0,1),a.slice(0,1)).decision,"HOLD"));
check("three unverified signers remain synthetic not physical witnesses",()=>{
 const x=run(enrollments,a);assert.equal(x.tested_custodians,3);assert.equal(x.external_retention_authenticated,false);
});
rejects("self-custody root matching source is rejected",()=>{
 const changed=enrollmentForTest("custodian-1",owner,enrollments[0].key_id,keys[0].publicKey,[owner]);
 run([changed],[a[0]]);
},"CUSTODIAN_PIN_MISMATCH");
rejects("custody ancestry cannot contain source owner root",()=>{
 const altered={...enrollments[0],ancestry_roots:[roots[0],owner]};
 run([altered],[a[0]]);
},"CUSTODY_SOURCE_SHARED_ANCESTRY");
rejects("second custodian cannot reuse first custodian ancestral root",()=>{
 const altered={...enrollments[1],ancestry_roots:[roots[1],roots[0]]};
 run([enrollments[0],altered],[a[0],a[1]]);
},"CUSTODIAN_SHARED_ANCESTRY");
rejects("two signers with same declared custody root are not independent",()=>{
 const other=enrollmentForTest("custodian-2",roots[0],enrollments[1].key_id,keys[1].publicKey,[roots[0]]);
 const reg={...registry,[other.key_id]:{...registry[other.key_id],custody_root:roots[0]}};
 const att=signForTest({...a[1].payload,custody_root:roots[0]},keys[1].privateKey);
 run([enrollments[0],other],[a[0],att],reg);
},"CUSTODIAN_SHARED_ANCESTRY");
rejects("duplicated custodian identity cannot become two witnesses",()=>{
 run([enrollments[0],enrollments[0]],[a[0],a[0]]);
},"DUPLICATE_CUSTODIAN");
rejects("duplicate custodian signing key denied",()=>{
 const e={...enrollments[1],key_id:enrollments[0].key_id,
  public_key_sha256:enrollments[0].public_key_sha256};
 const r={...registry,[enrollments[0].key_id]:{...registry[enrollments[0].key_id],custodian_id:e.custodian_id,custody_root:e.custody_root}};
 const att=signForTest({...a[1].payload,key_id:e.key_id},keys[0].privateKey);
 run([enrollments[0],e],[a[0],att],r);
},"CUSTODIAN_PIN_MISMATCH");
rejects("sender's own ownership root cannot masquerade as a distinct external ancestry",()=>{
 const own={...enrollments[0],ancestry_roots:[roots[0],owner]};run([own],[a[0]]);
},"CUSTODY_SOURCE_SHARED_ANCESTRY");
rejects("forged attestation signature denied",()=>run([enrollments[0]],[{...a[0],
 signature:crypto.sign(null,attestationBytes(a[0].payload),keys[2].privateKey).toString("base64")}]),"ATTESTATION_SIGNATURE");
rejects("altered signed checkpoint revision denied",()=>run([enrollments[0]],[signed(enrollments[0],0,{receiver_revision:18})]),"CHECKPOINT_BINDING");
rejects("wrong receiver state digest denied",()=>run([enrollments[0]],[signed(enrollments[0],0,{receiver_state_sha256:"f".repeat(64)})]),"CHECKPOINT_BINDING");
rejects("wrong checkpoint SHA denied",()=>run([enrollments[0]],[signed(enrollments[0],0,{checkpoint_sha256:"f".repeat(64)})]),"CHECKPOINT_BINDING");
rejects("incorrect previous anchor chain link denied",()=>run([enrollments[0]],[signed(enrollments[0],0,{previous_anchor_sha256:null})]),"CHECKPOINT_BINDING");
rejects("mismatched custodian ID denied",()=>run([enrollments[0]],[signed(enrollments[0],0,{custodian_id:"fake-custodian"})]),"ATTESTATION_IDENTITY");
rejects("unknown pinned custodian refused",()=>run([enrollments[0]],[a[0]],{}),"CUSTODIAN_NOT_REGISTERED");
rejects("revoked custody signing key refused",()=>run([enrollments[0]],[a[0]],{...registry,[enrollments[0].key_id]:{...registry[enrollments[0].key_id],revoked:true}}),"REVOKED_CUSTODIAN");
rejects("substituted enrollment key hash refused",()=>run([{...enrollments[0],public_key_sha256:"f".repeat(64)}],[a[0]]),"CUSTODIAN_PIN_MISMATCH");
rejects("mismatched declared root refused",()=>run([enrollments[0]],[a[0]],{...registry,[enrollments[0].key_id]:{...registry[enrollments[0].key_id],custody_root:"fake-root"}}),"CUSTODIAN_PIN_MISMATCH");
rejects("fabricated physical qualifier field refused",()=>run([enrollments[0]],[signed(enrollments[0],0,{physical_qualified:true})]),"ATTESTATION_FIELDS");
rejects("fabricated independent enrollment mode refused",()=>enrollmentBytes({...enrollments[0],enrollment_kind:"independent-external"}),"ENROLLMENT_FIELDS");
rejects("duplicate ancestors in one enrollment refused",()=>enrollmentBytes({...enrollments[0],ancestry_roots:[roots[0],roots[0]]}),"ANCESTRY_INVALID");
rejects("source provenance root list cannot be empty",()=>run(enrollments.slice(0,1),a.slice(0,1),registry,[]),"ANCESTRY_INVALID");
rejects("no witness attestation is insufficient",()=>run([],[]),"CUSTODY_SET_INVALID");
rejects("mismatch in number of attestations refused",()=>run(enrollments,[a[0]]),"CUSTODY_SET_INVALID");
rejects("unsigned attestation envelope refused",()=>run([enrollments[0]],[{payload:a[0].payload}]),"ATTESTATION_ENVELOPE");
rejects("mismatched pinned key identity refused",()=>{
 const e={...enrollments[0],key_id:enrollments[1].key_id};run([e],[a[0]]);
},"CUSTODIAN_PIN_MISMATCH");
check("synthetic observations expose source names without independence promotion",()=>{
 const x=run(enrollments,a);assert.deepEqual(x.custodians.map(r=>r.custody_root),roots);
 assert.equal(x.hardware_monotonicity_authenticated,false);assert.equal(x.globally_authoritative,false);
});
console.log("SAPPHON-121:",count,"synthetic custodian qualification and ancestry checks passed");
