"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {sha,receiptForTest}=require("./sapphon_108_acquisition.cjs");
const {signedForTest:signTranscript}=require("./sapphon_109_transcript.cjs");
const {enrollmentForTest,challengeFor,challengeBytes,signForTest,verifyCapture}=require("./sapphon_110_capture.cjs");
const keys=crypto.generateKeyPairSync("ed25519"),agent=crypto.generateKeyPairSync("ed25519"),
 rogue=crypto.generateKeyPairSync("ed25519"),bytes=Buffer.from("SAPPHON-110 synthetic signed capture\n");
const ownedRoot="davidwise01-owned-github",url="https://github.com/DavidWise01/super-sapphon/blob/main/test.json";
const peer="a".repeat(64);
const receiptData={schema:"sapphon-acquisition-receipt-v1",acquisition_id:"sample-acquisition",
 source_url:url,source_root:ownedRoot,transport_key_id:"test-transport",observed_sha256:sha(bytes),
 byte_count:bytes.length,collection_kind:"synthetic-local-fixture",declared_time:null,parent_roots:[]};
const acquisitionReceipt=receiptForTest(receiptData,keys.privateKey);
const transcript={schema:"sapphon-transport-transcript-v1",acquisition_id:receiptData.acquisition_id,
 session_id:"session-110",request_method:"GET",request_url:url,redirects:[],final_url:url,
 response_status:200,response_sha256:sha(bytes),response_byte_count:bytes.length,
 peer_spki_sha256:peer,transport_key_id:"test-transport",claimed_source_root:ownedRoot,
 collection_kind:"synthetic-transcript-fixture"};
const transportTranscript=signTranscript(transcript,keys.privateKey),transportRegistry={
 "test-transport":{source_root:ownedRoot,publicKey:keys.publicKey,pinned_peer_spki_sha256:peer}};
const agent_id="test-agent-110",owner_root=ownedRoot,key_id="test-agent-key";
const agentEnrollment=enrollmentForTest(agent_id,owner_root,key_id,agent.publicKey),agentRegistry={
 [key_id]:{agent_id,owner_root,publicKey:agent.publicKey,revoked:false}};
const challenge=challengeFor(agent_id,transcript.session_id,receiptData.acquisition_id,transcript,"b".repeat(64));
const payload={schema:"sapphon-capture-evidence-v1",challenge_sha256:sha(challengeBytes(challenge)),
 transcript_sha256:challenge.transcript_sha256,capture_sha256:sha(bytes),capture_bytes:bytes.length,
 agent_id,owner_root,key_id,retention_ref:"fixture:synthetic-only",peer_spki_sha256:peer};
const capture=signForTest(payload,agent.privateKey);
function clone(x){return JSON.parse(JSON.stringify(x))}
function context(patch={}){return {bytes,transcript,acquisitionReceipt,transportRegistry,transportTranscript,
 challenge,capture,agentEnrollment,agentRegistry,issuedChallenges:new Map([[challenge.nonce,sha(challengeBytes(challenge))]]),
 consumedNonces:new Set(),...patch}}
let n=0;function test(name,fn){fn();console.log("PASS",++n,name)}
function reject(name,fn,reason){test(name,()=>assert.throws(fn,e=>e.message===reason))}
test("signed synthetic capture verified while real authority remains held",()=>{
 const c=context(),x=verifyCapture(c);
 assert.equal(x.cryptographic_test_passed,true);assert.equal(x.decision,"HOLD");
 assert.equal(x.independent_capture_agent_verified,false);assert.equal(x.utc_authority,false);
});
test("verified challenge consumes nonce in supplied session registry",()=>{
 const c=context();verifyCapture(c);assert.equal(c.consumedNonces.size,1);
});
reject("second use of nonce is rejected",()=>{
 const c=context();verifyCapture(c);verifyCapture(c);
},"CAPTURE_SESSION_REPLAY");
reject("non-issued nonce is rejected",()=>verifyCapture(context({issuedChallenges:new Map()})),"CHALLENGE_NOT_ISSUED");
reject("missing session registry is rejected",()=>verifyCapture(context({issuedChallenges:null})),"TRUSTED_SESSION_STORE_REQUIRED");
reject("tampered request transcript cannot borrow captured evidence",()=>{
 const forged=signTranscript({...transcript,session_id:"session-alt"},keys.privateKey);
 verifyCapture(context({transportTranscript:forged}));
},"SESSION_BINDING");
reject("replaced transcript signature fails transport authentication",()=>{
 const forged=signTranscript(transcript,rogue.privateKey);
 verifyCapture(context({transportTranscript:forged}));
},"TRANSCRIPT_SIGNATURE");
reject("different capture-agent public key refused",()=>verifyCapture(context({
 agentRegistry:{[key_id]:{...agentRegistry[key_id],publicKey:rogue.publicKey}}
})),"AGENT_ENROLLMENT_MISMATCH");
reject("unknown capture-agent key refused",()=>verifyCapture(context({agentRegistry:{}})),"UNREGISTERED_AGENT");
reject("revoked capture agent refused",()=>verifyCapture(context({agentRegistry:{
 [key_id]:{...agentRegistry[key_id],revoked:true}}})),"REVOKED_AGENT");
reject("agent owner root substitution refused",()=>verifyCapture(context({agentEnrollment:{
 ...agentEnrollment,owner_root:"invented-root"}})),"AGENT_ENROLLMENT_MISMATCH");
reject("capture signature from wrong key refused",()=>verifyCapture(context({
 capture:signForTest(payload,rogue.privateKey)})),"CAPTURE_SIGNATURE");
reject("changed signed byte count refused",()=>verifyCapture(context({
 capture:signForTest({...payload,capture_bytes:bytes.length+1},agent.privateKey)})),"CAPTURE_BYTE_MISMATCH");
reject("changed signed capture digest refused",()=>verifyCapture(context({
 capture:signForTest({...payload,capture_sha256:"f".repeat(64)},agent.privateKey)})),"CAPTURE_BYTE_MISMATCH");
reject("wrong peer key fingerprint in captured evidence refused",()=>verifyCapture(context({
 capture:signForTest({...payload,peer_spki_sha256:"f".repeat(64)},agent.privateKey)})),"CAPTURE_BINDING");
reject("fake retention reference with invalid scheme refused",()=>verifyCapture(context({
 capture:signForTest({...payload,retention_ref:"https://external.example/claim"},agent.privateKey)})),"CAPTURE_FIELDS");
reject("capture nonce altered without reissuance refused",()=>verifyCapture(context({
 challenge:{...challenge,nonce:"c".repeat(64)}})),"CHALLENGE_NOT_ISSUED");
reject("session ID conflict refused",()=>verifyCapture(context({
 challenge:{...challenge,session_id:"session-other"}})),"SESSION_BINDING");
reject("acquisition ID conflict refused",()=>verifyCapture(context({
 challenge:{...challenge,acquisition_id:"acquisition-other"}})),"SESSION_BINDING");
reject("transcript digest cannot be replaced in signed capture",()=>verifyCapture(context({
 capture:signForTest({...payload,transcript_sha256:"f".repeat(64)},agent.privateKey)})),"CAPTURE_BINDING");
reject("capture ownership cannot assert different root",()=>verifyCapture(context({
 capture:signForTest({...payload,owner_root:"fake-independent"},agent.privateKey)})),"CAPTURE_BINDING");
reject("missing capture transcript peer pin refused",()=>verifyCapture(context({
 transportRegistry:{"test-transport":{source_root:ownedRoot,publicKey:keys.publicKey}}
})),"PEER_PIN_MISMATCH");
reject("unexpected evidence field refused",()=>verifyCapture(context({
 capture:signForTest({...payload,utc_authorized:true},agent.privateKey)})),"CAPTURE_FIELDS");
test("failed capture does not consume an issued challenge",()=>{
 const c=context({capture:signForTest(payload,rogue.privateKey)});
 try{verifyCapture(c)}catch{}assert.equal(c.consumedNonces.size,0);
});
test("test agent and transport may share owner and never qualify as independent",()=>{
 const x=verifyCapture(context());assert.equal(x.agent_owner_root,x.transport_source_root);
 assert.equal(x.external_retention_verified,false);assert.equal(x.real_network_acquisition_verified,false);
});
console.log("SAPPHON-110:",n,"capture enrollment, nonce and transcript checks passed");
