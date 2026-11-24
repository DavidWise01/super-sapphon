"use strict";
/* SAPPHON-106 real-source admission dossier screening.
   Screening is a schema/evidence sufficiency check, NOT proof of external
   custodianship or of UTC correctness. Admission remains HOLD until separately
   authenticated evidence is independently acquired and calibrated.
 */
const {inspectEnvelope}=require("./sapphon_105_intake.cjs");
const H=/^[a-f0-9]{64}$/,ID=/^[a-z0-9-]{4,64}$/;
function fail(s){throw Error(s)}
function keys(obj,wanted,error){
 if(!obj||typeof obj!=="object"||Array.isArray(obj)||
 Object.keys(obj).sort().join("|")!==wanted.slice().sort().join("|"))fail(error);
}
function str(s){return typeof s==="string"&&s.length>=8&&s.length<=2048}
function hash(s){return typeof s==="string"&&H.test(s)}
function admissionReview(dossier,registry,ownedDomains=[]){
 keys(dossier,["schema","envelope","custody","calibration","measurement","lineage","evidence"],"DOSSIER_SCHEMA");
 if(dossier.schema!=="sapphon-real-source-admission-v1")fail("DOSSIER_SCHEMA");
 const assessed=inspectEnvelope(dossier.envelope,registry,ownedDomains);
 const p=dossier.envelope.payload;
 if(p.source_kind!=="physical-clock")fail("NOT_PHYSICAL_CLOCK");
 keys(dossier.custody,["custodian_id","custody_root","receipt_sha256","retained_anchor_sha256","independent_verifier_id"],"CUSTODY_SCHEMA");
 const c=dossier.custody;
 if(![c.custodian_id,c.custody_root,c.independent_verifier_id].every(x=>typeof x==="string"&&ID.test(x))||
 !hash(c.receipt_sha256)||!hash(c.retained_anchor_sha256))fail("CUSTODY_INCOMPLETE");
 keys(dossier.calibration,["reference_id","reference_report_sha256","traceability_chain_sha256","uncertainty_ns","calibrated_at","valid_until"],"CALIBRATION_SCHEMA");
 const cal=dossier.calibration;
 if(!str(cal.reference_id)||!hash(cal.reference_report_sha256)||!hash(cal.traceability_chain_sha256)||
 !Number.isSafeInteger(cal.uncertainty_ns)||cal.uncertainty_ns<1||cal.uncertainty_ns>1e12||
 !str(cal.calibrated_at)||!str(cal.valid_until))fail("CALIBRATION_INCOMPLETE");
 const start=Date.parse(cal.calibrated_at),end=Date.parse(cal.valid_until);
 if(!Number.isFinite(start)||!Number.isFinite(end)||end<=start)fail("INVALID_CALIBRATION_PERIOD");
 if(cal.reference_report_sha256!==p.calibration_sha256||cal.reference_id!==p.calibration_reference)
 fail("CALIBRATION_BINDING");
 keys(dossier.measurement,["observation_sha256","measurement_series_sha256","capture_started_at","capture_ended_at","uncertainty_ns","time_scale","method"],"MEASUREMENT_SCHEMA");
 const m=dossier.measurement;
 if(!hash(m.observation_sha256)||!hash(m.measurement_series_sha256)||
 !str(m.capture_started_at)||!str(m.capture_ended_at)||
 !Number.isSafeInteger(m.uncertainty_ns)||m.uncertainty_ns<1||m.uncertainty_ns>1e12||
 !["UTC","TAI"].includes(m.time_scale)||!str(m.method))fail("MEASUREMENT_INCOMPLETE");
 const a=Date.parse(m.capture_started_at),b=Date.parse(m.capture_ended_at);
 if(!Number.isFinite(a)||!Number.isFinite(b)||b<a||a<start||b>end)fail("MEASUREMENT_OUTSIDE_CALIBRATION");
 if(m.observation_sha256!==p.evidence_sha256)fail("MEASUREMENT_BINDING");
 // A stated uncertainty smaller than calibrated reference is not defensible
 // without separately documented new uncertainty decomposition.
 if(m.uncertainty_ns<cal.uncertainty_ns)fail("UNSUPPORTED_UNCERTAINTY");
 keys(dossier.lineage,["source_root","owner_domain","independent_source_root","parent_source_roots"],"LINEAGE_SCHEMA");
 const l=dossier.lineage;
 if(![l.source_root,l.independent_source_root].every(x=>typeof x==="string"&&ID.test(x))||
 typeof l.owner_domain!=="string"||l.owner_domain.length<4||
 !Array.isArray(l.parent_source_roots)||l.parent_source_roots.length>32||
 !l.parent_source_roots.every(x=>typeof x==="string"&&ID.test(x)))
 fail("LINEAGE_INCOMPLETE");
 if(l.source_root!==p.root_id||l.owner_domain!==p.ownership_domain)fail("LINEAGE_BINDING");
 const sameRoot=l.independent_source_root===l.source_root||l.parent_source_roots.includes(l.independent_source_root)||
 new Set(l.parent_source_roots).size!==l.parent_source_roots.length;
 if(sameRoot)fail("SHARED_SOURCE_ANCESTRY");
 keys(dossier.evidence,["custody_bundle_sha256","calibration_bundle_sha256","measurement_bundle_sha256","chain_of_custody_sha256","verification_record_sha256"],"EVIDENCE_SCHEMA");
 const e=dossier.evidence;
 if(!Object.values(e).every(hash))fail("EVIDENCE_INCOMPLETE");
 const deficiencies=[];
 if(assessed.ownership_collision)deficiencies.push("OWNED_CORPUS_COLLISION");
 // These identifiers/digests are claims. Valid hashes do not establish that
 // files exist or that an independent reviewer has examined them.
 deficiencies.push("EXTERNAL_CUSTODY_NOT_AUTHENTICATED","CALIBRATION_NOT_INDEPENDENTLY_VERIFIED",
 "MEASUREMENT_NOT_PHYSICALLY_OBSERVED","LINEAGE_NOT_INDEPENDENTLY_ESTABLISHED");
 return {schema:"sapphon-106-admission-assessment-v1",source_root:p.root_id,
 signed_intake_verified:true,contract_complete:true,
 claimed_uncertainty_ns:m.uncertainty_ns,
 claimed_time_scale:m.time_scale,
 external_ownership_qualified:false,physical_clock_qualified:false,
 utc_authorized:false,decision:"HOLD",deficiencies};
}
module.exports={admissionReview};
