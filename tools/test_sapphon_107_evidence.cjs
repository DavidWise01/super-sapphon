"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {testEnvelope}=require("./sapphon_105_intake.cjs");
const {verifyEvidence,ROLES}=require("./sapphon_107_evidence.cjs");
const kp=crypto.generateKeyPairSync("ed25519"),root="test-physical-source",owner="owned-git-corpus";
const fp=crypto.createHash("sha256").update(kp.publicKey.export({type:"spki",format:"der"})).digest("hex");
const hash=x=>crypto.createHash("sha256").update(x).digest("hex");
const dir=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon107-"));
const calibration={reference_id:"test-reference-clock",uncertainty_ns:120,calibrated_at:"2026-01-01T00:00:00Z",valid_until:"2027-01-01T00:00:00Z"};
const measurement={capture_started_at:"2026-04-01T00:00:00Z",capture_ended_at:"2026-04-01T00:01:00Z",uncertainty_ns:180,time_scale:"UTC",method:"synthetic-comparison"};
const source=(evidence_sha256,calibration_sha256)=>({
 schema:"sapphon-external-intake-v1",root_id:root,public_key_spki_sha256:fp,source_kind:"physical-clock",ownership_domain:owner,
 reference:"https://example.org/synthetic-evidence",evidence_sha256,declared_independent:true,
 calibration_reference:calibration.reference_id,calibration_sha256
});
const registry={"test-source-key":{publicKey:kp.publicKey,root_id:root,source_kind:"physical-clock",ownership_domain:owner}};
const docs={};
const set=(role,data)=>{docs[role]=data;fs.writeFileSync(path.join(dir,role+".json"),JSON.stringify(data)+"\n")};
const digest=role=>hash(fs.readFileSync(path.join(dir,role+".json")));
set("custody_receipt",{schema:"sapphon-107-test-custody-v1",source_root:root,custodian_id:"synthetic-custodian",
 custody_root:"owned-custody-root",anchor_id:"synthetic-anchor"});
set("retained_anchor",{schema:"sapphon-107-test-anchor-v1",source_root:root,anchor_id:"synthetic-anchor",custody_root:"owned-custody-root"});
set("calibration_report",{schema:"sapphon-107-test-calibration-v1",source_root:root,...calibration});
set("traceability_chain",{schema:"sapphon-107-test-trace-v1",source_root:root,reference_id:calibration.reference_id,
 parent_reference_id:"synthetic-parent-reference"});
set("observation",{schema:"sapphon-107-test-observation-v1",source_root:root,...measurement,
 method:undefined});
set("measurement_series",{schema:"sapphon-107-test-series-v1",source_root:root,
 observation_digest:digest("observation"),method:measurement.method});
set("custody_bundle",{schema:"sapphon-107-test-custody-bundle-v1",source_root:root,
 custody_receipt_sha256:digest("custody_receipt"),anchor_sha256:digest("retained_anchor")});
set("calibration_bundle",{schema:"sapphon-107-test-calibration-bundle-v1",source_root:root,
 calibration_sha256:digest("calibration_report"),traceability_sha256:digest("traceability_chain")});
set("measurement_bundle",{schema:"sapphon-107-test-measurement-bundle-v1",source_root:root,
 observation_sha256:digest("observation"),series_sha256:digest("measurement_series")});
set("chain_of_custody",{schema:"sapphon-107-test-chain-of-custody-v1",source_root:root,
 custodian_id:"synthetic-custodian",anchor_sha256:digest("retained_anchor")});
set("verification_record",{schema:"sapphon-107-test-verification-record-v1",source_root:root,verifier_id:"test-verifier",
 custody_bundle_sha256:digest("custody_bundle"),calibration_bundle_sha256:digest("calibration_bundle"),
 measurement_bundle_sha256:digest("measurement_bundle")});
const dossier={
 schema:"sapphon-real-source-admission-v1",
 custody:{custodian_id:"synthetic-custodian",custody_root:"owned-custody-root",
  receipt_sha256:digest("custody_receipt"),retained_anchor_sha256:digest("retained_anchor"),independent_verifier_id:"test-verifier"},
 calibration:{...calibration,reference_report_sha256:digest("calibration_report"),traceability_chain_sha256:digest("traceability_chain")},
 measurement:{...measurement,observation_sha256:digest("observation"),measurement_series_sha256:digest("measurement_series")},
 lineage:{source_root:root,owner_domain:owner,independent_source_root:"declared-other-root",parent_source_roots:[]},
 evidence:{custody_bundle_sha256:digest("custody_bundle"),calibration_bundle_sha256:digest("calibration_bundle"),
 measurement_bundle_sha256:digest("measurement_bundle"),chain_of_custody_sha256:digest("chain_of_custody"),
 verification_record_sha256:digest("verification_record")}
};
function resign(d){d.envelope=testEnvelope(source(d.measurement.observation_sha256,d.calibration.reference_report_sha256),
kp.privateKey,"test-source-key");return d}
resign(dossier);
let n=0;
function check(name,fn){fn();n++;console.log("PASS",n,name)}
function reject(name,fn,code){check(name,()=>assert.throws(fn,e=>e.message===code))}
function editFile(role,changes,fn){
 const p=path.join(dir,role+".json"),old=fs.readFileSync(p);
 try{fs.writeFileSync(p,JSON.stringify({...docs[role],...changes})+"\n");fn()}
 finally{fs.writeFileSync(p,old)}
}
function copy(o){return JSON.parse(JSON.stringify(o))}
try{
 check("11 real files cryptographically match dossier digests and references",()=>{
  const r=verifyEvidence(dir,dossier,registry,[owner]);assert.equal(r.verified_file_count,11);
  assert.ok(r.bytes_verified>300);assert.equal(r.complete_cross_document_links,true);
  assert.equal(r.utc_authorized,false);assert.equal(r.decision,"HOLD");
 });
 check("bytes from distinct evidence files are checked rather than simply declared digests",()=>{
   assert.equal(Object.keys(ROLES).length,11);
   assert.deepEqual(Object.keys(verifyEvidence(dir,dossier,registry,[owner]).verified_digests),Object.keys(ROLES));
 });
 reject("missing required source document",()=>{
   const p=path.join(dir,"retained_anchor.json");fs.renameSync(p,p+".hold");
   try{verifyEvidence(dir,dossier,registry,[owner])}finally{fs.renameSync(p+".hold",p)}
 },"EVIDENCE_MISSING");
 reject("modified observation bytes rejected",()=>editFile("observation",{source_root:"impostor"},()=>verifyEvidence(dir,dossier,registry,[owner])),"EVIDENCE_DIGEST_MISMATCH:observation");
 reject("changed calibration bytes rejected",()=>editFile("calibration_report",{uncertainty_ns:1},()=>verifyEvidence(dir,dossier,registry,[owner])),"EVIDENCE_DIGEST_MISMATCH:calibration_report");
 reject("source digest changed but signed envelope unchanged",()=>{
  const d=copy(dossier);d.measurement.observation_sha256="f".repeat(64);verifyEvidence(dir,d,registry,[owner]);
 },"MEASUREMENT_BINDING");
 reject("unreadable binary data rejected",()=>{
  const file=path.join(dir,"traceability_chain.json"),old=fs.readFileSync(file);
  try{fs.writeFileSync(file,Buffer.from([0,255]));verifyEvidence(dir,dossier,registry,[owner])}
  finally{fs.writeFileSync(file,old)}
 },"EVIDENCE_INVALID_JSON");
 reject("directory instead of file rejected",()=>{
  const p=path.join(dir,"measurement_series.json");fs.renameSync(p,p+".hold");
  try{fs.mkdirSync(p);try{verifyEvidence(dir,dossier,registry,[owner])}finally{fs.rmdirSync(p)}}
  finally{fs.renameSync(p+".hold",p)}
 },"EVIDENCE_FILE_TYPE");
 reject("symlink escaping source directory rejected",()=>{
  const p=path.join(dir,"chain_of_custody.json");fs.renameSync(p,p+".hold");
  const outside=path.join(os.tmpdir(),"sapphon107-foreign.json");fs.writeFileSync(outside,"{}");
  try{fs.symlinkSync(outside,p);try{verifyEvidence(dir,dossier,registry,[owner])}finally{fs.unlinkSync(p)}}
  finally{fs.renameSync(p+".hold",p);fs.unlinkSync(outside)}
 },"EVIDENCE_ESCAPE");
 reject("digest valid but conflicting retained custody anchor reference rejected",()=>{
  editFile("retained_anchor",{anchor_id:"different-anchor"},()=>{
   const d=copy(dossier);d.custody.retained_anchor_sha256=digest("retained_anchor");
   verifyEvidence(dir,d,registry,[owner]);
  });
 },"ANCHOR_DOCUMENT_CONFLICT");
 reject("digest valid but wrong custodian ancestry rejected",()=>{
  editFile("custody_receipt",{custody_root:"other-control-root"},()=>{
   const d=copy(dossier);d.custody.receipt_sha256=digest("custody_receipt");verifyEvidence(dir,d,registry,[owner]);
  });
 },"CUSTODY_DOCUMENT_CONFLICT");
 reject("digest valid but conflicting traceability reference rejected",()=>{
  editFile("traceability_chain",{reference_id:"different-reference"},()=>{
   const d=copy(dossier);d.calibration.traceability_chain_sha256=digest("traceability_chain");
   verifyEvidence(dir,d,registry,[owner]);
  });
 },"TRACEABILITY_CONFLICT");
 reject("digest valid but conflicting calibration uncertainty rejected",()=>{
  editFile("calibration_report",{uncertainty_ns:999},()=>{
   const d=copy(dossier);d.calibration.reference_report_sha256=digest("calibration_report");
   resign(d);verifyEvidence(dir,d,registry,[owner]);
  });
 },"CALIBRATION_DOCUMENT_CONFLICT");
 reject("digest valid but observation interval contradicts signed dossier",()=>{
  editFile("observation",{capture_ended_at:"2026-04-02T00:00:00Z"},()=>{
   const d=copy(dossier);d.measurement.observation_sha256=digest("observation");
   resign(d);verifyEvidence(dir,d,registry,[owner]);
  });
 },"OBSERVATION_CONFLICT");
 reject("digest valid but measurement series points at wrong observation",()=>{
  editFile("measurement_series",{observation_digest:"e".repeat(64)},()=>{
   const d=copy(dossier);d.measurement.measurement_series_sha256=digest("measurement_series");
   verifyEvidence(dir,d,registry,[owner]);
  });
 },"SERIES_CONFLICT");
 reject("digest valid but calibration bundle points at wrong traceability",()=>{
  editFile("calibration_bundle",{traceability_sha256:"e".repeat(64)},()=>{
   const d=copy(dossier);d.evidence.calibration_bundle_sha256=digest("calibration_bundle");
   verifyEvidence(dir,d,registry,[owner]);
  });
 },"CROSS_DOCUMENT_CONFLICT:calibration_bundle");
 reject("digest valid but verification record references wrong bundle",()=>{
  editFile("verification_record",{custody_bundle_sha256:"e".repeat(64)},()=>{
   const d=copy(dossier);d.evidence.verification_record_sha256=digest("verification_record");
   verifyEvidence(dir,d,registry,[owner]);
  });
 },"CROSS_DOCUMENT_CONFLICT:verification_record");
 reject("missing evidence bundle hash rejected",()=>{
  const d=copy(dossier);d.evidence.custody_bundle_sha256="";verifyEvidence(dir,d,registry,[owner]);
 },"EVIDENCE_INCOMPLETE");
 reject("shared source ancestry fails even with all bytes present",()=>{
  const d=copy(dossier);d.lineage.independent_source_root=root;verifyEvidence(dir,d,registry,[owner]);
 },"SHARED_SOURCE_ANCESTRY");
 check("evidence scanner never modifies original files or dossier",()=>{
  const before=JSON.stringify(dossier),hashes=Object.keys(ROLES).map(digest);
  verifyEvidence(dir,dossier,registry,[owner]);
  assert.equal(JSON.stringify(dossier),before);
  assert.deepEqual(Object.keys(ROLES).map(digest),hashes);
 });
 console.log("SAPPHON-107:",n,"actual-file and cross-document traceability checks passed");
}finally{fs.rmSync(dir,{recursive:true,force:true})}
