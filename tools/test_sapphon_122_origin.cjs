"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {enrollmentForTest}=require("./sapphon_121_custodian.cjs");
const {certBytes,signForTest,qualify}=require("./sapphon_122_origin.cjs");
const key=()=>crypto.generateKeyPairSync("ed25519"),issuer=key(),old=key(),rotated=key(),fake=key();
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
const digest=k=>sha(k.publicKey.export({type:"spki",format:"der"}));
const issuerRegistry={"test-issuer":{publicKey:issuer.publicKey,issuer_id:"test-issuer",
 issuer_root:"test-issuer-root",control_group:"issuer-group"}};
const operatorRegistry={"test-operator-root":{control_root:"test-operator-root",
 custody_root:"test-custody-root",control_group:"operator-group"}};
const e1=enrollmentForTest("test-custodian","test-custody-root","test-key-one",old.publicKey);
const p1={schema:"sapphon-122-origin-certificate-v1",custodian_id:e1.custodian_id,
 custody_root:e1.custody_root,operator_root:"test-operator-root",issuer_id:"test-issuer",
 issuer_root:"test-issuer-root",key_id:e1.key_id,public_key_sha256:digest(old),
 generation:1,previous_certificate_sha256:null,kind:"synthetic-enrollment-origin"};
const c1=signForTest(p1,issuer.privateKey);
const v1={certificate:c1,certificate_sha256:sha(certBytes(p1))};
const e2=enrollmentForTest("test-custodian","test-custody-root","test-key-two",rotated.publicKey);
const p2={...p1,key_id:e2.key_id,public_key_sha256:digest(rotated),generation:2,
 previous_certificate_sha256:v1.certificate_sha256};
const c2=signForTest(p2,issuer.privateKey);
const cfg=(enrollment=e1,origin=c1,history=[],issuers=issuerRegistry,operators=operatorRegistry,
 sources=["owned-source-root"])=>({enrollment,origin,history,issuerRegistry:issuers,operatorRegistry:operators,sourceRoots:sources});
let n=0;function test(name,fn){fn();console.log("PASS",++n,name)}
function deny(name,fn,code){test(name,()=>assert.throws(fn,e=>e.message===code))}
test("valid signed fixture remains HOLD, never independent organizational proof",()=>{
 const x=qualify(cfg());assert.equal(x.decision,"HOLD");
 assert.equal(x.signed_origin_verified,true);assert.equal(x.independent_custody_authenticated,false);
});
test("generation two rotation verified with chained predecessor",()=>{
 const x=qualify(cfg(e2,c2,[v1]));assert.equal(x.generation,2);
 assert.equal(x.organizational_origin_authenticated,false);
});
deny("unsigned issuer certificate rejected",()=>qualify(cfg(e1,{payload:p1})),"ORIGIN_ENVELOPE");
deny("unknown issuer rejected",()=>qualify(cfg(e1,c1,[],{})),"UNKNOWN_ISSUER");
deny("revoked issuer rejected",()=>qualify(cfg(e1,c1,[],{"test-issuer":{...issuerRegistry["test-issuer"],revoked:true}})),"ISSUER_REVOKED");
deny("issuer signing key substitution rejected",()=>qualify(cfg(e1,c1,[],{"test-issuer":{...issuerRegistry["test-issuer"],publicKey:fake.publicKey}})),"ORIGIN_SIGNATURE");
deny("forged issuer certificate rejected",()=>qualify(cfg(e1,signForTest(p1,fake.privateKey))),"ORIGIN_SIGNATURE");
deny("mismatched issuer root rejected",()=>qualify(cfg(e1,c1,[],{"test-issuer":{...issuerRegistry["test-issuer"],issuer_root:"wrong-root"}})),"ISSUER_PIN_MISMATCH");
deny("certificate for wrong key cannot enroll",()=>qualify(cfg(e2,c1)),"ENROLLMENT_CERTIFICATE_MISMATCH");
deny("unregistered operator denied",()=>qualify(cfg(e1,c1,[],issuerRegistry,{})),"OPERATOR_NOT_ENROLLED");
deny("revoked operator denied",()=>qualify(cfg(e1,c1,[],issuerRegistry,{"test-operator-root":{...operatorRegistry["test-operator-root"],revoked:true}})),"OPERATOR_REVOKED");
deny("issuer and operator under declared shared controller rejected",()=>qualify(cfg(e1,c1,[],{"test-issuer":{...issuerRegistry["test-issuer"],control_group:"operator-group"}})),"SHARED_DECLARED_CONTROLLER");
deny("issuer controlled by original source rejected",()=>qualify(cfg(e1,c1,[],issuerRegistry,operatorRegistry,["test-issuer-root"])),"SOURCE_CONTROL_COLLISION");
deny("operator controlled by source rejected",()=>qualify(cfg(e1,c1,[],issuerRegistry,operatorRegistry,["test-operator-root"])),"SOURCE_CONTROL_COLLISION");
deny("custodian source self enrollment rejected",()=>qualify(cfg(e1,c1,[],issuerRegistry,operatorRegistry,["test-custody-root"])),"SOURCE_CONTROL_COLLISION");
deny("operator ancestry hidden in custodian chain rejected",()=>{
 const e={...e1,ancestry_roots:["test-custody-root","test-operator-root"]};qualify(cfg(e,c1));
},"ANCESTRY_CONTROL_COLLISION");
deny("direct issuer self issued operator role rejected",()=>{
 const p={...p1,operator_root:"test-issuer-root"};
 const op={"test-issuer-root":{control_root:"test-issuer-root",custody_root:"test-custody-root",
 control_group:"another-group"}};
 qualify(cfg(e1,signForTest(p,issuer.privateKey),[],issuerRegistry,op));
},"ROLE_CONTROL_COLLISION");
deny("certificate cannot claim physical/UTC qualification field",()=>certBytes({...p1,utc_authorized:true}),"ORIGIN_CERTIFICATE_FIELDS");
deny("rotation without predecessor rejected",()=>qualify(cfg(e2,signForTest({...p2,previous_certificate_sha256:null},issuer.privateKey),[v1])),"ORIGIN_CERTIFICATE_FIELDS");
deny("rotation skipping a generation rejected",()=>qualify(cfg(e2,signForTest({...p2,generation:3},issuer.privateKey),[v1])),"STALE_OR_FORKED_ROTATION");
deny("rotation without signed history rejected",()=>qualify(cfg(e2,c2)),"STALE_OR_FORKED_ROTATION");
deny("replayed key ID in generation two rejected",()=>{
 const p={...p2,key_id:e1.key_id,public_key_sha256:e1.public_key_sha256};
 qualify(cfg(e1,signForTest(p,issuer.privateKey),[v1]));
},"KEY_REUSE");
deny("tampered historical checkpoint link rejected",()=>{
 qualify(cfg(e2,c2,[{certificate:c1,certificate_sha256:"f".repeat(64)}]));
},"ORIGIN_HISTORY_FORK");
deny("altered rotation ancestry rejected",()=>{
 const p={...p1,generation:1,issuer_id:"test-issuer",operator_root:"test-operator-root"};
 const e={...e1,ancestry_roots:["test-custody-root","owned-source-root"]};
 qualify(cfg(e,signForTest(p,issuer.privateKey)));
},"ANCESTRY_CONTROL_COLLISION");
deny("same key with altered issuer declaration rejected",()=>{
 const p={...p1,issuer_root:"invented-issuer-root"};
 qualify(cfg(e1,signForTest(p,issuer.privateKey)));
},"ISSUER_PIN_MISMATCH");
deny("certificate cannot declare fake non-fixture mode",()=>certBytes({...p1,kind:"physical-independent"}),"ORIGIN_CERTIFICATE_FIELDS");
deny("source roots cannot be empty",()=>qualify(cfg(e1,c1,[],issuerRegistry,operatorRegistry,[])),"SOURCE_ROOTS_INVALID");
test("key rotation preserves same custodian and issuer but never grants external authority",()=>{
 const x=qualify(cfg(e2,c2,[v1]));assert.equal(x.declared_issuer_root,"test-issuer-root");
 assert.equal(x.independent_operator_authenticated,false);assert.equal(x.utc_authority,false);
});
console.log("SAPPHON-122:",n,"origin-control separation and rotation tests passed");
