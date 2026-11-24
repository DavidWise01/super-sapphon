"use strict";
/* SAPPHON-122 — enrollment origin and operator separation, synthetic only.
 * A pin certificate signed by an enrolling issuer cannot prove that issuer's
 * organization exists or is independent. Revocation and generation fencing
 * are enforced against an explicitly supplied local trust registry.
 */
const crypto=require("node:crypto");
const {enrollmentBytes}=require("./sapphon_121_custodian.cjs");
const ID=/^[a-z0-9-]{4,64}$/,H=/^[0-9a-f]{64}$/;
const fail=x=>{throw Error(x)};
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const hash=x=>crypto.createHash("sha256").update(x).digest("hex");
const keyhash=k=>hash(crypto.createPublicKey(k.type==="public"?k:crypto.createPublicKey(k)).export({type:"spki",format:"der"}));
const F=["schema","custodian_id","custody_root","operator_root","issuer_id","issuer_root","key_id","public_key_sha256","generation","previous_certificate_sha256","kind"];
function certBytes(p){
 if(!exact(p,F)||p.schema!=="sapphon-122-origin-certificate-v1"||
 ![p.custodian_id,p.custody_root,p.operator_root,p.issuer_id,p.issuer_root,p.key_id].every(x=>typeof x==="string"&&ID.test(x))||
 !H.test(p.public_key_sha256)||!Number.isSafeInteger(p.generation)||p.generation<1||
 !(p.previous_certificate_sha256===null||typeof p.previous_certificate_sha256==="string"&&H.test(p.previous_certificate_sha256))||
 p.kind!=="synthetic-enrollment-origin"||
 (p.generation===1)!==(p.previous_certificate_sha256===null))fail("ORIGIN_CERTIFICATE_FIELDS");
 return Buffer.from(JSON.stringify(F.map(k=>p[k])),"utf8");
}
function signForTest(payload,privateKey){return {payload,signature:crypto.sign(null,certBytes(payload),privateKey).toString("base64")}}
function verifyCert(signed,issuerRegistry){
 if(!exact(signed,["payload","signature"]))fail("ORIGIN_ENVELOPE");
 const bytes=certBytes(signed.payload),p=signed.payload;
 if(!issuerRegistry||!Object.hasOwn(issuerRegistry,p.issuer_id))fail("UNKNOWN_ISSUER");
 const v=issuerRegistry[p.issuer_id];
 if(v.revoked===true)fail("ISSUER_REVOKED");
 if(!v.publicKey||v.issuer_root!==p.issuer_root||v.issuer_id!==p.issuer_id)fail("ISSUER_PIN_MISMATCH");
 if(typeof signed.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(signed.signature)||
 !crypto.verify(null,bytes,v.publicKey,Buffer.from(signed.signature,"base64")))fail("ORIGIN_SIGNATURE");
 return hash(bytes);
}
function qualify({enrollment,origin,issuerRegistry,operatorRegistry,sourceRoots,history=[]}){
 enrollmentBytes(enrollment);
 const digest=verifyCert(origin,issuerRegistry),p=origin.payload;
 if(!Array.isArray(sourceRoots)||sourceRoots.length===0||sourceRoots.some(x=>typeof x!=="string"||!ID.test(x)))
  fail("SOURCE_ROOTS_INVALID");
 if(!Array.isArray(history)||history.length>16)fail("ORIGIN_HISTORY_INVALID");
 if(enrollment.custodian_id!==p.custodian_id||enrollment.custody_root!==p.custody_root||
 enrollment.key_id!==p.key_id||enrollment.public_key_sha256!==p.public_key_sha256)fail("ENROLLMENT_CERTIFICATE_MISMATCH");
 if(!operatorRegistry||!Object.hasOwn(operatorRegistry,p.operator_root))fail("OPERATOR_NOT_ENROLLED");
 const op=operatorRegistry[p.operator_root];
 if(op.revoked===true)fail("OPERATOR_REVOKED");
 if(op.control_root!==p.operator_root||op.custody_root!==p.custody_root)fail("OPERATOR_PIN_MISMATCH");
 const parents=new Set([...enrollment.ancestry_roots,...sourceRoots]);
 if(sourceRoots.some(r=>r===p.issuer_root||r===p.operator_root||r===p.custody_root))
  fail("SOURCE_CONTROL_COLLISION");
 if(p.operator_root===p.issuer_root||p.operator_root===p.custody_root||
 p.issuer_root===p.custody_root)fail("ROLE_CONTROL_COLLISION");
 if(enrollment.ancestry_roots.some(r=>sourceRoots.includes(r)||r===p.issuer_root||r===p.operator_root))
  fail("ANCESTRY_CONTROL_COLLISION");
 let previous=null,rev=0;
 for(const item of history){
  if(!exact(item,["certificate","certificate_sha256"]))fail("ORIGIN_HISTORY_INVALID");
  const stored=verifyCert(item.certificate,issuerRegistry),q=item.certificate.payload;
  if(stored!==item.certificate_sha256||q.generation!==rev+1||
   q.previous_certificate_sha256!==previous||q.custodian_id!==p.custodian_id||
   q.issuer_id!==p.issuer_id||q.operator_root!==p.operator_root||
   q.custody_root!==p.custody_root)fail("ORIGIN_HISTORY_FORK");
  previous=stored;rev=q.generation;
 }
 if(p.generation!==rev+1||p.previous_certificate_sha256!==previous)
  fail("STALE_OR_FORKED_ROTATION");
 if(history.some(x=>x.certificate.payload.key_id===p.key_id||
 x.certificate.payload.public_key_sha256===p.public_key_sha256))fail("KEY_REUSE");
 const signerRoot=issuerRegistry[p.issuer_id];
 const sameController=signerRoot.control_group===op.control_group;
 if(sameController)fail("SHARED_DECLARED_CONTROLLER");
 return {schema:"sapphon-122-origin-assessment-v1",decision:"HOLD",
  signed_origin_verified:true,declared_role_separation:true,
  certificate_sha256:digest,generation:p.generation,
  declared_issuer_root:p.issuer_root,declared_operator_root:p.operator_root,
  independent_operator_authenticated:false,organizational_origin_authenticated:false,
  independent_custody_authenticated:false,physical_clock_qualified:false,utc_authority:false};
}
module.exports={certBytes,signForTest,verifyCert,qualify};
