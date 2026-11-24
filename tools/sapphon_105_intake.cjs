"use strict";
/* SAPPHON-105: read-only external evidence qualification.
 * Distinct software checks do NOT themselves establish custody or physical time.
 * Hard gate: no field or self-declared trust string can authorize production.
 * External enrollment and calibration need verified evidence from outside this
 * owner's GitHub/Pages corpus. Synthetic fixtures always HOLD.
 */
const crypto=require("node:crypto");
const HEX=/^[a-f0-9]{64}$/;
const ID=/^[a-z0-9-]{4,64}$/;
function fail(s){throw Error(s)}
function digest(s){return crypto.createHash("sha256").update(s).digest("hex")}
function canonical(body){
 const keys=["schema","root_id","public_key_spki_sha256","source_kind","ownership_domain","reference","evidence_sha256","declared_independent","calibration_reference","calibration_sha256"];
 if(!body||Object.keys(body).sort().join("|")!==keys.slice().sort().join("|")||
    body.schema!=="sapphon-external-intake-v1"||
    typeof body.root_id!=="string"||!ID.test(body.root_id)||
    !HEX.test(body.public_key_spki_sha256)||!HEX.test(body.evidence_sha256)||
    !["custodian","physical-clock"].includes(body.source_kind)||
    typeof body.ownership_domain!=="string"||body.ownership_domain.length<4||
    typeof body.reference!=="string"||body.reference.length<8||
    typeof body.declared_independent!=="boolean"||
    typeof body.calibration_reference!=="string"||typeof body.calibration_sha256!=="string")
    fail("INTAKE_SCHEMA");
 if(body.source_kind==="physical-clock"){
  if(body.calibration_reference.length<8||!HEX.test(body.calibration_sha256))fail("CALIBRATION_REQUIRED");
 }else if(body.calibration_reference!==""||body.calibration_sha256!=="")
   fail("CUSTODIAN_CALIBRATION_CONFLICT");
 return Buffer.from(JSON.stringify(keys.map(k=>body[k])),"utf8");
}
function testEnvelope(body,privateKey,keyId){
 return {payload:body,key_id:keyId,signature:crypto.sign(null,canonical(body),privateKey).toString("base64")};
}
function inspectEnvelope(envelope,registry,knownOwnership=[]){
 if(!envelope||Object.keys(envelope).sort().join("|")!=="key_id|payload|signature")fail("ENVELOPE_FIELDS");
 const bytes=canonical(envelope.payload),p=envelope.payload;
 if(!registry||!Object.hasOwn(registry,envelope.key_id))fail("UNTRUSTED_ROOT");
 const trusted=registry[envelope.key_id];
 if(trusted.revoked)fail("REVOKED_ROOT");
 const spki=(trusted.publicKey.type==="public"?trusted.publicKey:crypto.createPublicKey(trusted.publicKey)).export({type:"spki",format:"der"});
 if(digest(spki)!==p.public_key_spki_sha256||trusted.root_id!==p.root_id||
   trusted.source_kind!==p.source_kind||trusted.ownership_domain!==p.ownership_domain)
   fail("ROOT_IDENTITY_MISMATCH");
 if(typeof envelope.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature)||
    !crypto.verify(null,bytes,trusted.publicKey,Buffer.from(envelope.signature,"base64")))
   fail("BAD_SOURCE_SIGNATURE");
 const sharedRoot=knownOwnership.includes(p.ownership_domain);
 const externalReviewed=trusted.external_review_evidence===true;
 const calibrationReviewed=trusted.calibration_review_evidence===true;
 // Signatures, URLs, assertions and even a test registry cannot independently
 // certify an external relationship. Admission remains HOLD pending a separate
 // operator-controlled source onboarding and physical measurement review.
 return {status:"SIGNED_EVIDENCE_INTAKE_TEST",source_kind:p.source_kind,
   signature_verified:true,claimed_independence:p.declared_independent,
   ownership_collision:sharedRoot,external_review_declared:externalReviewed,
   calibration_review_declared:calibrationReviewed,
   external_custody_qualified:false,physical_clock_qualified:false,
   utc_authorized:false,decision:"HOLD",evidence_digest:p.evidence_sha256};
}
function gate(envelopes,registry,ownedDomains){
 if(!Array.isArray(envelopes)||envelopes.length>64||!Array.isArray(ownedDomains))fail("INPUT_BATCH");
 const seen=new Set(),assessments=[];
 for(const e of envelopes){
  const inspected=inspectEnvelope(e,registry,ownedDomains);
  if(seen.has(e.payload.root_id))fail("DUPLICATE_SOURCE_ROOT");
  seen.add(e.payload.root_id);assessments.push(inspected);
 }
 return {schema:"sapphon-105-external-qualification-v1",assessment_count:assessments.length,
    verified_signatures:assessments.filter(x=>x.signature_verified).length,
    independent_physical_sources:0,independent_custodians:0,
    physical_clock:"HOLD",external_custody:"HOLD",utc_authority:false,
    next_action:"REQUIRE_EXTERNAL_CUSTODIAN_ATTESTATION_AND_PHYSICAL_CALIBRATION",
    assessments};
}
module.exports={canonical,testEnvelope,inspectEnvelope,gate};
