"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {sha,receiptForTest}=require("./sapphon_108_acquisition.cjs");
const {signedForTest:signTranscript}=require("./sapphon_109_transcript.cjs");
const {enrollmentForTest,evidenceBytes,signForTest}=require("./sapphon_110_capture.cjs");
const {init,issue,consume,inspect,retentionBytes,signRetentionTest}=require("./sapphon_111_durable_capture.cjs");
const {readJournal,compareDirectories,reviewSnapshots}=require("./sapphon_112_splitbrain.cjs");
const transport=crypto.generateKeyPairSync("ed25519"),agent=crypto.generateKeyPairSync("ed25519"),custodian=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519");
const bytes=Buffer.from("Synthetic SAPPHON-111 network capture; no actual HTTPS acquisition\n");
const owner="davidwise01-owned-github",url="https://github.com/DavidWise01/super-sapphon/blob/main/synthetic-fixture";
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon111-")),directory=path.join(root,"journal");
const identity={agent_id:"test-capture-agent",session_id:"test-session-111",acquisition_id:"test-acquisition-111"};
const transcript={schema:"sapphon-transport-transcript-v1",acquisition_id:identity.acquisition_id,
 session_id:identity.session_id,request_method:"GET",request_url:url,redirects:[],final_url:url,
 response_status:200,response_sha256:sha(bytes),response_byte_count:bytes.length,
 peer_spki_sha256:"a".repeat(64),transport_key_id:"test-transport-key",claimed_source_root:owner,
 collection_kind:"synthetic-transcript-fixture"};
const acquisitionReceipt=receiptForTest({schema:"sapphon-acquisition-receipt-v1",
 acquisition_id:identity.acquisition_id,source_url:url,source_root:owner,transport_key_id:"test-transport-key",
 observed_sha256:sha(bytes),byte_count:bytes.length,collection_kind:"synthetic-local-fixture",
 declared_time:null,parent_roots:[]},transport.privateKey);
const transportTranscript=signTranscript(transcript,transport.privateKey);
const transportRegistry={"test-transport-key":{source_root:owner,publicKey:transport.publicKey,
 pinned_peer_spki_sha256:"a".repeat(64)}};
const agentEnrollment=enrollmentForTest(identity.agent_id,owner,"test-agent-key",agent.publicKey);
const agentRegistry={"test-agent-key":{agent_id:identity.agent_id,owner_root:owner,publicKey:agent.publicKey}};
const retentionRegistry={"test-custodian":{custodian_id:"test-custodian",custody_root:owner,publicKey:custodian.publicKey}};
const hash=b=>crypto.createHash("sha256").update(b).digest("hex");
function scenario(c){
 const capture=signForTest({schema:"sapphon-capture-evidence-v1",
  challenge_sha256:sha(require("./sapphon_110_capture.cjs").challengeBytes(c)),
  transcript_sha256:c.transcript_sha256,capture_sha256:sha(bytes),capture_bytes:bytes.length,
  agent_id:identity.agent_id,owner_root:owner,key_id:"test-agent-key",
  retention_ref:"fixture:synthetic-111",peer_spki_sha256:transcript.peer_spki_sha256},agent.privateKey);
 const retention=signRetentionTest({schema:"sapphon-111-retention-v1",
  capture_sha256:hash(evidenceBytes(capture.payload)),challenge_sha256:sha(require("./sapphon_110_capture.cjs").challengeBytes(c)),
  agent_owner_root:owner,custodian_id:"test-custodian",custody_root:owner,
  retention_id:"test-retention-one",retention_kind:"synthetic-test-retention"},custodian.privateKey);
 return {args:{bytes,transcript,acquisitionReceipt,transportRegistry,transportTranscript,
  challenge:c,capture,agentEnrollment,agentRegistry},retention,retentionRegistry};
}

const right=path.join(root,"journal-peer"),cloneRoot=path.join(root,"journal-clone");
const file=d=>path.join(d,"registry.json");
function snapshot(d){return fs.readFileSync(file(d))}
function copyState(from,to){fs.writeFileSync(file(to),snapshot(from))}
function mutate(d,fn){const p=file(d),v=JSON.parse(fs.readFileSync(p,"utf8"));fn(v);fs.writeFileSync(p,JSON.stringify(v)+"\n")}
let n=0;function test(name,fn){fn();n++;console.log("PASS",n,name)}
function reject(name,fn,reason){test(name,()=>assert.throws(fn,e=>e.message===reason))}
function comparison(){return compareDirectories(directory,right)}
try{
 init(directory);init(right);init(cloneRoot);
 test("new isolated registries start valid but not globally authoritative",()=>{
  const x=comparison();assert.equal(x.status,"COPIES_CONSISTENT_ONLY");
  assert.equal(x.independent_global_replay_protection,false);assert.equal(x.decision,"HOLD");
 });
 const issued=issue(directory,identity,transcript,{now:1000,ttl_ms:1000,nonce:"b".repeat(64)});
 copyState(directory,right);
 const capture=scenario(issued.challenge);
 test("two disconnected journals independently consume the same signed challenge",()=>{
  assert.equal(consume(directory,capture.args,{now:1001,retention:capture.retention,retentionRegistry}).durable_replay,true);
  assert.equal(consume(right,capture.args,{now:1001,retention:capture.retention,retentionRegistry}).durable_replay,true);
 });
 test("split-brain comparison detects both accepted copies",()=>{
  const x=comparison();assert.equal(x.status,"SPLIT_BRAIN_OR_DIVERGENCE");
  assert.equal(x.duplicate_consumptions.length,1);
  assert.equal(x.duplicate_consumptions[0].type,"DUAL_CONSUMPTION_SAME_CAPTURE");
  assert.equal(x.utc_authority,false);
 });
 test("identical consumed journals still prove no single-host authority",()=>{
  const x=comparison();assert.equal(x.exact_copy,true);
  assert.equal(x.independent_global_replay_protection,false);
 });
 reject("replay remains blocked within each separate host",()=>{
  consume(directory,capture.args,{now:1002,retention:capture.retention,retentionRegistry});
 },"DURABLE_CAPTURE_REPLAY");
 test("differently declared custody roots still establish zero authenticated externals",()=>{
  const x=reviewSnapshots([
   {snapshot_id:"host-alpha",custody_root:"owner-a",journal_dir:directory},
   {snapshot_id:"host-beta",custody_root:"owner-b",journal_dir:right}]);
  assert.equal(x.claimed_custody_roots,2);assert.equal(x.independently_authenticated_roots,0);
 });
 test("repeated ownership roots cannot count as distinct witnesses",()=>{
  const x=reviewSnapshots([
   {snapshot_id:"host-alpha",custody_root:"one-controlled-root",journal_dir:directory},
   {snapshot_id:"host-beta",custody_root:"one-controlled-root",journal_dir:right}]);
  assert.equal(x.repeated_owner_roots,true);
 });
 test("different signed retention hashes expose contradictory dual consumption",()=>{
  mutate(right,d=>{d.records[0].retention_sha256="f".repeat(64)});
  assert.equal(comparison().duplicate_consumptions[0].type,"DUAL_CONSUMPTION_DIFFERENT_RETENTION");
 });
 test("issued and consumed state conflict detected",()=>{
  mutate(right,d=>{d.records[0].status="ISSUED";d.records[0].retention_sha256=null});
  assert.equal(comparison().conflicts[0].type,"UNSYNCHRONIZED_CONSUMPTION");
 });
 test("changed issued challenge SHA exposes issuance fork",()=>{
  mutate(right,d=>{d.records[0].challenge_sha256="d".repeat(64)});
  assert.equal(comparison().conflicts[0].type,"ISSUANCE_FORK");
 });
 test("a single-host extra nonce appears as unilateral history",()=>{
  const fresh=issue(directory,identity,transcript,{now:1010,nonce:"c".repeat(64)});
  const x=comparison();assert.equal(x.unilateral_nonces.length,1);
 });
 test("two identical copies do not automatically gain external custody",()=>{
  copyState(directory,cloneRoot);
  const x=compareDirectories(directory,cloneRoot);
  assert.equal(x.exact_copy,true);assert.equal(x.external_custody_qualified,false);
 });
 reject("unknown filesystem directory fails closed",()=>readJournal(path.join(root,"missing")),"JOURNAL_UNAVAILABLE");
 reject("truncated journal fails closed",()=>{
  const previous=snapshot(right);try{fs.writeFileSync(file(right),"{broken");readJournal(right)}
  finally{fs.writeFileSync(file(right),previous)}
 },"JOURNAL_UNAVAILABLE");
 reject("unknown journal schema fails closed",()=>{
  const old=snapshot(right);try{mutate(right,d=>{d.schema="fake-true-time"});readJournal(right)}
  finally{fs.writeFileSync(file(right),old)}
 },"JOURNAL_INVALID");
 reject("fabricated consumed state without retention digest fails closed",()=>{
  const old=snapshot(right);try{mutate(right,d=>{d.records[0].status="CONSUMED";d.records[0].retention_sha256=null});readJournal(right)}
  finally{fs.writeFileSync(file(right),old)}
 },"JOURNAL_INVALID");
 reject("duplicate nonce in one journal rejected",()=>{
  const old=snapshot(right);try{mutate(right,d=>{d.records.push({...d.records[0]})});readJournal(right)}
  finally{fs.writeFileSync(file(right),old)}
 },"JOURNAL_INVALID");
 reject("duplicate snapshot ID fails closed",()=>reviewSnapshots([
 {snapshot_id:"same-id",custody_root:"owner-a",journal_dir:directory},
 {snapshot_id:"same-id",custody_root:"owner-b",journal_dir:right}
 ]),"DUPLICATE_SNAPSHOT_ID");
 reject("invalid snapshot shape cannot declare UTC authority",()=>reviewSnapshots([
 {snapshot_id:"host-alpha",custody_root:"owner-a",journal_dir:directory,utc_authorized:true},
 {snapshot_id:"host-beta",custody_root:"owner-b",journal_dir:right}
 ]),"SNAPSHOT_FIELDS");
 test("comparisons never modify original journal bytes",()=>{
  const one=snapshot(directory),two=snapshot(right);comparison();
  assert.deepEqual(snapshot(directory),one);assert.deepEqual(snapshot(right),two);
 });
 console.log("SAPPHON-112:",n,"cross-host replay and hostile-journal tests passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
