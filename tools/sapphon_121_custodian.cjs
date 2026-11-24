"use strict";
/* SAPPHON-121 — synthetic external-custodian qualification CONTRACT.
 * Pinned Ed25519 roots + declared ancestry and monotonic checkpoint binding.
 * Signature possession never implies actual third-party independence, custody,
 * hardware monotonicity or authenticated physical/UTC timing.
 */
const crypto=require("node:crypto");
const {canonical:checkpointBytes}=require("./sapphon_118_anchor.cjs");
const H=/^[a-f0-9]{64}$/,ID=/^[a-z0-9-]{4,64}$/;
const fail=x=>{throw Error(x)};
const hash=b=>crypto.createHash("sha256").update(b).digest("hex");
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const DER=k=>(k.type==="public"?k:crypto.createPublicKey(k)).export({type:"spki",format:"der"});
const EF=["schema","custodian_id","custody_root","ancestry_roots","key_id","public_key_sha256","enrollment_kind"];
const AF=["schema","custodian_id","custody_root","key_id","receiver_id","receiver_revision","receiver_state_sha256","checkpoint_sha256","previous_anchor_sha256","kind"];
function validRoots(roots){
 if(!Array.isArray(roots)||roots.length<1||roots.length>16||
    roots.some(x=>typeof x!=="string"||!ID.test(x))||
    new Set(roots).size!==roots.length)fail("ANCESTRY_INVALID");
}
function enrollmentBytes(e){
 if(!exact(e,EF)||e.schema!=="sapphon-121-custodian-enrollment-v1"||
 ![e.custodian_id,e.custody_root,e.key_id].every(x=>typeof x==="string"&&ID.test(x))||
 !H.test(e.public_key_sha256)||e.enrollment_kind!=="synthetic-fixture")fail("ENROLLMENT_FIELDS");
 validRoots(e.ancestry_roots);
 if(e.ancestry_roots[0]!==e.custody_root)fail("ANCESTRY_ROOT_MISMATCH");
 return Buffer.from(JSON.stringify(EF.map(x=>e[x])),"utf8");
}
function enrollmentForTest(custodian_id,custody_root,key_id,publicKey,ancestry_roots=[custody_root]){
 const e={schema:"sapphon-121-custodian-enrollment-v1",custodian_id,custody_root,
 ancestry_roots,key_id,public_key_sha256:hash(DER(publicKey)),enrollment_kind:"synthetic-fixture"};
 enrollmentBytes(e);return e;
}
function attestationBytes(p){
 if(!exact(p,AF)||p.schema!=="sapphon-121-custody-attestation-v1"||
 ![p.custodian_id,p.custody_root,p.key_id,p.receiver_id].every(x=>typeof x==="string"&&ID.test(x))||
 !Number.isSafeInteger(p.receiver_revision)||p.receiver_revision<0||
 ![p.receiver_state_sha256,p.checkpoint_sha256].every(x=>typeof x==="string"&&H.test(x))||
 !(p.previous_anchor_sha256===null||typeof p.previous_anchor_sha256==="string"&&H.test(p.previous_anchor_sha256))||
 p.kind!=="synthetic-retention-fixture")fail("ATTESTATION_FIELDS");
 return Buffer.from(JSON.stringify(AF.map(x=>p[x])),"utf8");
}
function signForTest(payload,key){
 return {payload,signature:crypto.sign(null,attestationBytes(payload),key).toString("base64")};
}
function verifyOne(e,a,registry,checkpoint){
 enrollmentBytes(e);
 if(!registry||!Object.hasOwn(registry,e.key_id))fail("CUSTODIAN_NOT_REGISTERED");
 const r=registry[e.key_id];
 if(r.revoked===true)fail("REVOKED_CUSTODIAN");
 if(!r.publicKey||r.custodian_id!==e.custodian_id||r.custody_root!==e.custody_root||
 hash(DER(r.publicKey))!==e.public_key_sha256)fail("CUSTODIAN_PIN_MISMATCH");
 if(!exact(a,["payload","signature"]))fail("ATTESTATION_ENVELOPE");
 const bytes=attestationBytes(a.payload),p=a.payload;
 if(p.custodian_id!==e.custodian_id||p.custody_root!==e.custody_root||p.key_id!==e.key_id)
  fail("ATTESTATION_IDENTITY");
 const chash=hash(checkpointBytes(checkpoint));
 if(p.receiver_id!==checkpoint.receiver_id||p.receiver_revision!==checkpoint.revision||
 p.receiver_state_sha256!==checkpoint.state_sha256||p.checkpoint_sha256!==chash||
 p.previous_anchor_sha256!==checkpoint.previous_checkpoint_sha256)fail("CHECKPOINT_BINDING");
 if(typeof a.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(a.signature)||
 !crypto.verify(null,bytes,r.publicKey,Buffer.from(a.signature,"base64")))
  fail("ATTESTATION_SIGNATURE");
 return {custodian_id:p.custodian_id,custody_root:p.custody_root,ancestry_roots:e.ancestry_roots.slice(),
   attestation_sha256:hash(bytes),fixture_signature_valid:true};
}
function assess({checkpoint,enrollments,attestations,registry,sourceAncestry}){
 checkpointBytes(checkpoint);
 validRoots(sourceAncestry);
 if(!Array.isArray(enrollments)||!Array.isArray(attestations)||
 enrollments.length!==attestations.length||enrollments.length<1||enrollments.length>3)
  fail("CUSTODY_SET_INVALID");
 const ids=new Set(),keys=new Set(),observations=[],custodyRoots=new Set(),sources=new Set(sourceAncestry);
 for(let i=0;i<enrollments.length;i++){
  const e=enrollments[i];
  const v=verifyOne(e,attestations[i],registry,checkpoint);
  if(ids.has(e.custodian_id)||keys.has(e.key_id))fail("DUPLICATE_CUSTODIAN");
  ids.add(e.custodian_id);keys.add(e.key_id);
  if(v.ancestry_roots.some(x=>sources.has(x)))fail("CUSTODY_SOURCE_SHARED_ANCESTRY");
  for(const ancestor of v.ancestry_roots){
   if(custodyRoots.has(ancestor))fail("CUSTODIAN_SHARED_ANCESTRY");
   custodyRoots.add(ancestor);
  }
  observations.push(v);
 }
 return {schema:"sapphon-121-qualification-assessment-v1",
  tested_custodians:observations.length,synthetic_signatures_verified:true,
  ancestry_collision_observed:false,custodians:observations,
  ancestry_independence_authenticated:false,external_retention_authenticated:false,
  hardware_monotonicity_authenticated:false,globally_authoritative:false,
  utc_authority:false,decision:"HOLD"};
}
module.exports={enrollmentForTest,enrollmentBytes,attestationBytes,signForTest,assess};
