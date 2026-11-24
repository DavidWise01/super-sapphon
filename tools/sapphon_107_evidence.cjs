"use strict";
/* SAPPHON-107: verify real bytes of locally provided dossier evidence.
 * No network retrieval, remote attestations or UTC authority. A digest proves
 * byte agreement only, not truth, organization independence or physical origin.
 * Paths are fixed role names beneath a caller-controlled local evidence dir.
 */
const crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path");
const {admissionReview}=require("./sapphon_106_admission.cjs");
const ROLES=Object.freeze({
 custody_receipt:"custody.receipt_sha256",
 retained_anchor:"custody.retained_anchor_sha256",
 calibration_report:"calibration.reference_report_sha256",
 traceability_chain:"calibration.traceability_chain_sha256",
 observation:"measurement.observation_sha256",
 measurement_series:"measurement.measurement_series_sha256",
 custody_bundle:"evidence.custody_bundle_sha256",
 calibration_bundle:"evidence.calibration_bundle_sha256",
 measurement_bundle:"evidence.measurement_bundle_sha256",
 chain_of_custody:"evidence.chain_of_custody_sha256",
 verification_record:"evidence.verification_record_sha256"
});
function fail(code){throw Error(code)}
function exactly(o,keys,code){
 if(!o||typeof o!=="object"||Array.isArray(o)||Object.keys(o).sort().join("|")!==keys.slice().sort().join("|"))fail(code);
}
function nested(dotted,o){return dotted.split(".").reduce((a,k)=>a?.[k],o)}
function sha(b){return crypto.createHash("sha256").update(b).digest("hex")}
function readEvidence(dir,role){
 if(!Object.hasOwn(ROLES,role))fail("UNKNOWN_EVIDENCE_ROLE");
 const filename=path.join(dir,role+".json");
 let stat,real,b;
 try{
  const root=fs.realpathSync(dir),actual=fs.realpathSync(filename);
  if(path.dirname(actual)!==root)fail("EVIDENCE_ESCAPE");
  stat=fs.lstatSync(filename);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size<2||stat.size>262144)fail("EVIDENCE_FILE_TYPE");
  b=fs.readFileSync(filename);
 }catch(e){if(["EVIDENCE_ESCAPE","EVIDENCE_FILE_TYPE"].includes(e.message))throw e;fail("EVIDENCE_MISSING")}
 let obj;
 try{obj=JSON.parse(b.toString("utf8"))}catch{fail("EVIDENCE_INVALID_JSON")}
 if(!obj||typeof obj!=="object"||Array.isArray(obj))fail("EVIDENCE_INVALID_JSON");
 return {bytes:b,object:obj,sha256:sha(b)};
}
function verifyEvidence(dir,dossier,registry,ownedDomains=[]){
 const base=admissionReview(dossier,registry,ownedDomains),p=dossier.envelope.payload;
 const files={};
 for(const [role,field] of Object.entries(ROLES)){
  const file=readEvidence(dir,role),expected=nested(field,dossier);
  if(file.sha256!==expected)fail("EVIDENCE_DIGEST_MISMATCH:"+role);
  files[role]=file;
 }
 const j=role=>files[role].object;
 // Each piece of evidence must bind to the same source, custody root, clock
 // reference and observation interval. No self-declared source becomes a witness.
 exactly(j("custody_receipt"),["schema","source_root","custodian_id","custody_root","anchor_id"],"CUSTODY_DOCUMENT_SCHEMA");
 if(j("custody_receipt").schema!=="sapphon-107-test-custody-v1"||
    j("custody_receipt").source_root!==p.root_id||
    j("custody_receipt").custodian_id!==dossier.custody.custodian_id||
    j("custody_receipt").custody_root!==dossier.custody.custody_root)fail("CUSTODY_DOCUMENT_CONFLICT");
 exactly(j("retained_anchor"),["schema","source_root","anchor_id","custody_root"],"ANCHOR_DOCUMENT_SCHEMA");
 if(j("retained_anchor").schema!=="sapphon-107-test-anchor-v1"||
    j("retained_anchor").source_root!==p.root_id||
    j("retained_anchor").anchor_id!==j("custody_receipt").anchor_id||
    j("retained_anchor").custody_root!==dossier.custody.custody_root)fail("ANCHOR_DOCUMENT_CONFLICT");
 exactly(j("calibration_report"),["schema","source_root","reference_id","uncertainty_ns","calibrated_at","valid_until"],"CALIBRATION_DOCUMENT_SCHEMA");
 if(j("calibration_report").schema!=="sapphon-107-test-calibration-v1"||
    j("calibration_report").source_root!==p.root_id||
    j("calibration_report").reference_id!==dossier.calibration.reference_id||
    j("calibration_report").uncertainty_ns!==dossier.calibration.uncertainty_ns||
    j("calibration_report").calibrated_at!==dossier.calibration.calibrated_at||
    j("calibration_report").valid_until!==dossier.calibration.valid_until)fail("CALIBRATION_DOCUMENT_CONFLICT");
 exactly(j("traceability_chain"),["schema","source_root","reference_id","parent_reference_id"],"TRACEABILITY_SCHEMA");
 if(j("traceability_chain").schema!=="sapphon-107-test-trace-v1"||
    j("traceability_chain").source_root!==p.root_id||
    j("traceability_chain").reference_id!==dossier.calibration.reference_id||
    j("traceability_chain").parent_reference_id===dossier.calibration.reference_id)fail("TRACEABILITY_CONFLICT");
 exactly(j("observation"),["schema","source_root","capture_started_at","capture_ended_at","uncertainty_ns","time_scale"],"OBSERVATION_SCHEMA");
 if(j("observation").schema!=="sapphon-107-test-observation-v1"||
    j("observation").source_root!==p.root_id||
    j("observation").capture_started_at!==dossier.measurement.capture_started_at||
    j("observation").capture_ended_at!==dossier.measurement.capture_ended_at||
    j("observation").uncertainty_ns!==dossier.measurement.uncertainty_ns||
    j("observation").time_scale!==dossier.measurement.time_scale)fail("OBSERVATION_CONFLICT");
 exactly(j("measurement_series"),["schema","source_root","observation_digest","method"],"SERIES_SCHEMA");
 if(j("measurement_series").schema!=="sapphon-107-test-series-v1"||
    j("measurement_series").source_root!==p.root_id||
    j("measurement_series").observation_digest!==files.observation.sha256||
    j("measurement_series").method!==dossier.measurement.method)fail("SERIES_CONFLICT");
 for(const [role,refs] of Object.entries({
  custody_bundle:{source_root:p.root_id,custody_receipt_sha256:files.custody_receipt.sha256,anchor_sha256:files.retained_anchor.sha256},
  calibration_bundle:{source_root:p.root_id,calibration_sha256:files.calibration_report.sha256,traceability_sha256:files.traceability_chain.sha256},
  measurement_bundle:{source_root:p.root_id,observation_sha256:files.observation.sha256,series_sha256:files.measurement_series.sha256},
  chain_of_custody:{source_root:p.root_id,custodian_id:dossier.custody.custodian_id,anchor_sha256:files.retained_anchor.sha256},
  verification_record:{source_root:p.root_id,verifier_id:dossier.custody.independent_verifier_id,
    custody_bundle_sha256:files.custody_bundle.sha256,calibration_bundle_sha256:files.calibration_bundle.sha256,
    measurement_bundle_sha256:files.measurement_bundle.sha256}
 })){
  const x=j(role);
  exactly(x,["schema",...Object.keys(refs)],"CROSS_DOCUMENT_SCHEMA");
  if(x.schema!=="sapphon-107-test-"+role.replaceAll("_","-")+"-v1"||
     Object.entries(refs).some(([k,v])=>x[k]!==v))fail("CROSS_DOCUMENT_CONFLICT:"+role);
 }
 return {schema:"sapphon-107-byte-evidence-assessment-v1",decision:"HOLD",
   bytes_verified:Object.values(files).reduce((n,f)=>n+f.bytes.length,0),
   verified_file_count:Object.keys(files).length,
   verified_digests:Object.fromEntries(Object.entries(files).map(([role,f])=>[role,f.sha256])),
   complete_cross_document_links:true,source_root:p.root_id,admission:base.decision,
   external_custody_qualified:false,physical_clock_qualified:false,utc_authorized:false,
   deficiencies:["SYNTHETIC_ORIGIN_UNVERIFIED","EXTERNAL_RETENTION_UNVERIFIED","PHYSICAL_CALIBRATION_UNVERIFIED"]};
}
module.exports={ROLES,readEvidence,verifyEvidence};
