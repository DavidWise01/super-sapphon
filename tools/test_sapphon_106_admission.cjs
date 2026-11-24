"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {testEnvelope}=require("./sapphon_105_intake.cjs");
const {admissionReview}=require("./sapphon_106_admission.cjs");
const kp=crypto.generateKeyPairSync("ed25519");
const fp=crypto.createHash("sha256").update(kp.publicKey.export({format:"der",type:"spki"})).digest("hex");
const h=c=>c.repeat(64),owner="synthetic-owned-corpus";
const p={schema:"sapphon-external-intake-v1",root_id:"synthetic-physical",
 public_key_spki_sha256:fp,source_kind:"physical-clock",ownership_domain:owner,
 reference:"https://example.org/test-only",evidence_sha256:h("a"),declared_independent:true,
 calibration_reference:"test-reference-clock",calibration_sha256:h("b")};
const reg={"physical-test-key":{publicKey:kp.publicKey,root_id:p.root_id,source_kind:p.source_kind,ownership_domain:owner}};
const dossier={
 schema:"sapphon-real-source-admission-v1",
 envelope:testEnvelope(p,kp.privateKey,"physical-test-key"),
 custody:{custodian_id:"test-custodian",custody_root:"one-owned-root",receipt_sha256:h("c"),retained_anchor_sha256:h("d"),independent_verifier_id:"test-verifier"},
 calibration:{reference_id:p.calibration_reference,reference_report_sha256:h("b"),traceability_chain_sha256:h("e"),uncertainty_ns:100,
  calibrated_at:"2026-01-01T00:00:00Z",valid_until:"2027-01-01T00:00:00Z"},
 measurement:{observation_sha256:h("a"),measurement_series_sha256:h("f"),capture_started_at:"2026-04-01T00:00:00Z",
  capture_ended_at:"2026-04-01T00:01:00Z",uncertainty_ns:200,time_scale:"UTC",method:"synthetic-phase-comparison"},
 lineage:{source_root:p.root_id,owner_domain:owner,independent_source_root:"declared-root-two",parent_source_roots:[]},
 evidence:{custody_bundle_sha256:h("1"),calibration_bundle_sha256:h("2"),measurement_bundle_sha256:h("3"),
  chain_of_custody_sha256:h("4"),verification_record_sha256:h("5")}
};
const clone=o=>JSON.parse(JSON.stringify(o));let n=0;function test(name,fn){fn();console.log("PASS",++n,name)}
function rejects(name,mutate,code){test(name,()=>{const d=clone(dossier);mutate(d);assert.throws(()=>admissionReview(d,reg,[owner]),e=>e.message===code)})}
test("complete synthetic dossier remains HOLD",()=>{
 const x=admissionReview(dossier,reg,[owner]);
 assert.equal(x.contract_complete,true);assert.equal(x.utc_authorized,false);assert.equal(x.decision,"HOLD");
 assert.ok(x.deficiencies.includes("OWNED_CORPUS_COLLISION"));
});
test("signed intake does not imply physical authority",()=>{
 const x=admissionReview(dossier,reg,[]);assert.equal(x.physical_clock_qualified,false);
 assert.equal(x.external_ownership_qualified,false);
});
rejects("missing custody receipt",d=>{d.custody.receipt_sha256=""},"CUSTODY_INCOMPLETE");
rejects("forged independent verifier ID",d=>{d.custody.independent_verifier_id=""},"CUSTODY_INCOMPLETE");
rejects("wrong calibration digest",d=>{d.calibration.reference_report_sha256=h("9")},"CALIBRATION_BINDING");
rejects("wrong calibration reference",d=>{d.calibration.reference_id="different-clock"},"CALIBRATION_BINDING");
rejects("calibration uncertainty must be positive",d=>{d.calibration.uncertainty_ns=0},"CALIBRATION_INCOMPLETE");
rejects("invalid calibration period",d=>{d.calibration.valid_until="2025-01-01T00:00:00Z"},"INVALID_CALIBRATION_PERIOD");
rejects("measurement outside calibration period",d=>{d.measurement.capture_ended_at="2028-01-01T00:00:00Z"},"MEASUREMENT_OUTSIDE_CALIBRATION");
rejects("wrong measured observation digest",d=>{d.measurement.observation_sha256=h("9")},"MEASUREMENT_BINDING");
rejects("reported uncertainty below reference floor",d=>{d.measurement.uncertainty_ns=50},"UNSUPPORTED_UNCERTAINTY");
rejects("unsupported time scale",d=>{d.measurement.time_scale="UT1"},"MEASUREMENT_INCOMPLETE");
rejects("same root cannot corroborate itself",d=>{d.lineage.independent_source_root=p.root_id},"SHARED_SOURCE_ANCESTRY");
rejects("shared parent lineage cannot claim independence",d=>{d.lineage.parent_source_roots=["declared-root-two"]},"SHARED_SOURCE_ANCESTRY");
rejects("duplicated ancestor roots fail closed",d=>{d.lineage.parent_source_roots=["common-root","common-root"]},"SHARED_SOURCE_ANCESTRY");
rejects("lineage ownership must match signed source",d=>{d.lineage.owner_domain="different-owner"},"LINEAGE_BINDING");
rejects("source root cannot be substituted",d=>{d.lineage.source_root="different-root"},"LINEAGE_BINDING");
rejects("missing chain of custody digest",d=>{d.evidence.chain_of_custody_sha256=""},"EVIDENCE_INCOMPLETE");
rejects("unsanctioned authorization field blocked",d=>{d.authorize_utc=true},"DOSSIER_SCHEMA");
rejects("tampered signed independence declaration",d=>{d.envelope.payload.declared_independent=false},"BAD_SOURCE_SIGNATURE");
rejects("unexpected payload field",d=>{d.envelope.payload.grant=true},"INTAKE_SCHEMA");
rejects("wrong signed kind",d=>{
 const cust={...p,source_kind:"custodian",calibration_reference:"",calibration_sha256:""};
 d.envelope=testEnvelope(cust,kp.privateKey,"physical-test-key");
},"ROOT_IDENTITY_MISMATCH");
test("review never modifies source dossier",()=>{
 const before=JSON.stringify(dossier);admissionReview(dossier,reg,[owner]);assert.equal(JSON.stringify(dossier),before);
});
console.log("SAPPHON-106:",n,"real-source admission contract tests passed");
