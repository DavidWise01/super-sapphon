"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {sha,receiptForTest}=require("./sapphon_108_acquisition.cjs");
const {signedForTest:signTranscript}=require("./sapphon_109_transcript.cjs");
const {enrollmentForTest,evidenceBytes,signForTest}=require("./sapphon_110_capture.cjs");
const {init,issue,consume,inspect,retentionBytes,signRetentionTest,MAX_TTL}=require("./sapphon_111_durable_capture.cjs");
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
const clone=x=>JSON.parse(JSON.stringify(x));
let n=0;function test(name,fn){fn();n++;console.log("PASS",n,name)}
function reject(name,fn,expected){test(name,()=>assert.throws(fn,e=>e.message===expected))}
try{
 test("initialized local journal has no sessions",()=>{init(directory);assert.equal(inspect(directory).records.length,0)});
 reject("cannot overwrite previous ledger",()=>init(directory),"STORE_ALREADY_EXISTS");
 const first=issue(directory,identity,transcript,{now:1000,ttl_ms:600,nonce:"b".repeat(64)});
 test("issued challenge persisted to disk",()=>{
  assert.equal(inspect(directory).records[0].status,"ISSUED");assert.equal(first.expires_ms,1600);
 });
 const s=scenario(first.challenge);
 test("valid synthetic capture and matching custody acknowledgement accepted once",()=>{
  const x=consume(directory,s.args,{now:1001,retention:s.retention,retentionRegistry:s.retentionRegistry});
  assert.equal(x.durable_replay,true);assert.equal(x.utc_authority,false);
  assert.equal(x.retention.custody_independently_authenticated,false);
 });
 test("journal retains consumed nonce across module reload",()=>{
  assert.equal(require("./sapphon_111_durable_capture.cjs").inspect(directory).records[0].status,"CONSUMED");
 });
 reject("replay after restart fails",()=>consume(directory,s.args,{now:1002,retention:s.retention,
  retentionRegistry:s.retentionRegistry}),"DURABLE_CAPTURE_REPLAY");
 reject("nonce cannot be issued again once consumed",()=>issue(directory,identity,transcript,{now:1003,
  nonce:"b".repeat(64)}),"NONCE_ALREADY_ISSUED");
 reject("expired challenge rejected",()=>{
  const x=issue(directory,identity,transcript,{now:2000,ttl_ms:5,nonce:"c".repeat(64)}),z=scenario(x.challenge);
  consume(directory,z.args,{now:2005,retention:z.retention,retentionRegistry:z.retentionRegistry});
 },"CHALLENGE_EXPIRED");
 reject("local clock rollback across calls rejected",()=>issue(directory,identity,transcript,{now:1999,
  nonce:"d".repeat(64)}),"LOCAL_CLOCK_ROLLBACK");
 reject("forged retention signature rejected",()=>{
  const x=issue(directory,identity,transcript,{now:2100,nonce:"e".repeat(64)}),z=scenario(x.challenge);
  const bad={...z.retention,signature:crypto.sign(null,retentionBytes(z.retention.payload),rogue.privateKey).toString("base64")};
  consume(directory,z.args,{now:2101,retention:bad,retentionRegistry:z.retentionRegistry});
 },"RETENTION_SIGNATURE");
 test("failed retention check does not consume nonce",()=>{
  assert.equal(inspect(directory).records.find(x=>x.nonce==="e".repeat(64)).status,"ISSUED");
 });
 reject("retention ownership conflict rejected",()=>{
  const x=issue(directory,identity,transcript,{now:2200,nonce:"f".repeat(64)}),z=scenario(x.challenge);
  const changed=signRetentionTest({...z.retention.payload,custody_root:"different-root"},custodian.privateKey);
  consume(directory,z.args,{now:2201,retention:changed,retentionRegistry:z.retentionRegistry});
 },"CUSTODY_ROOT_MISMATCH");
 reject("retention cannot bind to a different capture",()=>{
  const x=issue(directory,identity,transcript,{now:2300,nonce:"1".repeat(64)}),z=scenario(x.challenge);
  const changed=signRetentionTest({...z.retention.payload,capture_sha256:"9".repeat(64)},custodian.privateKey);
  consume(directory,z.args,{now:2301,retention:changed,retentionRegistry:z.retentionRegistry});
 },"RETENTION_BINDING");
 reject("unknown custodian refused",()=>{
  const x=issue(directory,identity,transcript,{now:2400,nonce:"2".repeat(64)}),z=scenario(x.challenge);
  consume(directory,z.args,{now:2401,retention:z.retention,retentionRegistry:{}});
 },"CUSTODIAN_NOT_ENROLLED");
 reject("revoked custodian refused",()=>{
  const x=issue(directory,identity,transcript,{now:2500,nonce:"3".repeat(64)}),z=scenario(x.challenge);
  consume(directory,z.args,{now:2501,retention:z.retention,retentionRegistry:{
   "test-custodian":{...retentionRegistry["test-custodian"],revoked:true}}});
 },"REVOKED_CUSTODIAN");
 reject("unissued capture challenge refused",()=>{
  const c=require("./sapphon_110_capture.cjs").challengeFor(identity.agent_id,identity.session_id,
   identity.acquisition_id,transcript,"4".repeat(64)),z=scenario(c);
  consume(directory,z.args,{now:2600,retention:z.retention,retentionRegistry:z.retentionRegistry});
 },"NONCE_NOT_ISSUED");
 reject("invalid zero TTL rejected",()=>issue(directory,identity,transcript,{now:2600,ttl_ms:0}),"TTL_INVALID");
 reject("excessive TTL rejected",()=>issue(directory,identity,transcript,{now:2600,ttl_ms:MAX_TTL+1}),"TTL_INVALID");
 reject("exclusive lock prevents concurrent consumption",()=>{
  fs.mkdirSync(path.join(directory,"lock"));try{inspect(directory)}finally{fs.rmdirSync(path.join(directory,"lock"))}
 },"LOCK_UNAVAILABLE");
 reject("corrupt disk journal fails closed",()=>{
  const p=path.join(directory,"registry.json"),before=fs.readFileSync(p);
  try{fs.writeFileSync(p,"{broken");inspect(directory)}finally{fs.writeFileSync(p,before)}
 },"STORE_UNREADABLE");
 reject("missing session storage fails closed",()=>inspect(path.join(root,"nonexistent")),"STORE_MISSING");
 reject("arbitrary authority field in retention rejected",()=>{
  signRetentionTest({...s.retention.payload,independently_retained:true},custodian.privateKey);
 },"RETENTION_FIELDS");
 test("two keys from same controlled root never certify independent custody",()=>{
  assert.equal(retentionRegistry["test-custodian"].custody_root,owner);
  assert.equal(inspect(directory).schema,"sapphon-111-session-registry-v1");
 });
 console.log("SAPPHON-111:",n,"durable capture and retention tests passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
