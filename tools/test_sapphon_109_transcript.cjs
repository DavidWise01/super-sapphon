"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {sha,receiptForTest}=require("./sapphon_108_acquisition.cjs");
const {canonical,signedForTest,verifyTranscripts,originRoot}=require("./sapphon_109_transcript.cjs");
const bytes=Buffer.from('{"synthetic":"transport evidence fixture"}\n');
const a=crypto.generateKeyPairSync("ed25519"),b=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519");
const root="davidwise01-owned-github",urlA="https://github.com/DavidWise01/super-sapphon/blob/main/evidence.json",
 urlB="https://davidwise01.github.io/super-sapphon/evidence.json",redirect="https://raw.githubusercontent.com/DavidWise01/super-sapphon/main/evidence.json";
const peerA="a".repeat(64),peerB="b".repeat(64);
const mkReceipt=(id,url,key)=>({schema:"sapphon-acquisition-receipt-v1",acquisition_id:id,source_url:url,
 source_root:root,transport_key_id:key,observed_sha256:sha(bytes),byte_count:bytes.length,
 collection_kind:"synthetic-local-fixture",declared_time:null,parent_roots:[]});
const receiptA=receiptForTest(mkReceipt("acquisition-a",urlA,"transport-a"),a.privateKey);
const receiptB=receiptForTest(mkReceipt("acquisition-b",urlB,"transport-b"),b.privateKey);
const registry={"transport-a":{source_root:root,publicKey:a.publicKey,pinned_peer_spki_sha256:peerA,revoked:false},
 "transport-b":{source_root:root,publicKey:b.publicKey,pinned_peer_spki_sha256:peerB,revoked:false}};
const payload=(r,peer,session,redirs=[])=>({schema:"sapphon-transport-transcript-v1",
 acquisition_id:r.payload.acquisition_id,session_id:session,request_method:"GET",
 request_url:r.payload.source_url,redirects:redirs,
 final_url:redirs.length?redirs.at(-1).to:r.payload.source_url,response_status:200,
 response_sha256:sha(bytes),response_byte_count:bytes.length,peer_spki_sha256:peer,
 transport_key_id:r.payload.transport_key_id,claimed_source_root:r.payload.source_root,
 collection_kind:"synthetic-transcript-fixture"});
const tA=signedForTest(payload(receiptA,peerA,"session-a",
 [{from:urlA,to:redirect,status:302}]),a.privateKey);
const tB=signedForTest(payload(receiptB,peerB,"session-b"),b.privateKey);
let n=0;const clone=x=>JSON.parse(JSON.stringify(x));
function test(label,fn){fn();console.log("PASS",++n,label)}
function reject(label,fn,code){test(label,()=>assert.throws(fn,e=>e.message===code))}
const run=(ts=[tA,tB],rs=[receiptA,receiptB],rg=registry)=>verifyTranscripts(bytes,rs,ts,rg);
test("synthetic matching request response and two signatures accepted for screening",()=>{
 const out=run();assert.equal(out.transcript_signatures_checked,2);assert.equal(out.decision,"HOLD");
 assert.equal(out.external_https_capture_verified,false);assert.equal(out.declared_roots,1);
});
test("GitHub and GitHub Pages resolve to same ancestry",()=>{
 assert.equal(originRoot(urlA),root);assert.equal(originRoot(urlB),root);assert.equal(originRoot(redirect),root);
});
test("one simulated owned redirect retains one root and no external authority",()=>{
 const out=run();assert.equal(out.audit[0].redirects_checked,1);assert.equal(out.utc_authority,false);
});
reject("tampered transcript response digest rejected",()=>run([signedForTest({...tA.payload,response_sha256:"c".repeat(64)},a.privateKey),tB]),"RESPONSE_BYTE_MISMATCH");
reject("tampered transcript byte count rejected",()=>run([signedForTest({...tA.payload,response_byte_count:bytes.length+1},a.privateKey),tB]),"RESPONSE_BYTE_MISMATCH");
reject("forged transcript signature rejected",()=>run([{...tA,signature:crypto.sign(null,canonical(tA.payload),rogue.privateKey).toString("base64")},tB]),"TRANSCRIPT_SIGNATURE");
reject("unknown peer TLS key fingerprint rejected",()=>run([signedForTest({...tA.payload,peer_spki_sha256:"d".repeat(64)},a.privateKey),tB]),"PEER_PIN_MISMATCH");
reject("revoked transport key rejected",()=>run([tA,tB],[receiptA,receiptB],{"transport-a":{...registry["transport-a"],revoked:true},"transport-b":registry["transport-b"]}),"REVOKED_TRANSPORT");
reject("same session cannot be replayed under second transport",()=>run([tA,signedForTest({...tB.payload,session_id:"session-a"},b.privateKey)]),"REPLAYED_SESSION");
reject("duplicate transcript for same acquisition rejected",()=>run([tA,tA]),"DUPLICATE_TRANSCRIPT");
reject("unknown acquisition identifier cannot inherit receipt",()=>run([signedForTest({...tA.payload,acquisition_id:"ghost-acquisition"},a.privateKey),tB]),"UNBOUND_TRANSCRIPT");
reject("request URL cannot differ from acquisition receipt URL",()=>run([signedForTest({...tA.payload,request_url:urlB,redirects:[],final_url:urlB},a.privateKey),tB]),"ACQUISITION_BINDING");
reject("transcript transport key cannot substitute identity",()=>run([signedForTest({...tA.payload,transport_key_id:"transport-b"},a.privateKey),tB]),"ACQUISITION_BINDING");
reject("redirect chain cannot begin from unrelated URL",()=>canonical({...tA.payload,redirects:[{from:urlB,to:redirect,status:302}]}),"REDIRECT_CHAIN");
reject("redirect to unverified different origin rejected",()=>canonical({...tA.payload,redirects:[{from:urlA,to:"https://example.org/unknown",status:302}],final_url:"https://example.org/unknown"}),"REDIRECT_ORIGIN_UNATTESTED");
reject("redirect loop fails closed",()=>canonical({...tA.payload,redirects:[{from:urlA,to:redirect,status:302},{from:redirect,to:urlA,status:302},{from:urlA,to:redirect,status:302}],final_url:redirect}),"REDIRECT_LOOP");
reject("inconsistent final response URL rejected",()=>canonical({...tA.payload,final_url:urlA}),"FINAL_URL_MISMATCH");
reject("redirect 200 is not a valid redirect status",()=>canonical({...tA.payload,redirects:[{from:urlA,to:redirect,status:200}]}),"REDIRECT_CHAIN");
reject("HTTP URL fails transport contract",()=>canonical({...tA.payload,request_url:"http://github.com/DavidWise01/super-sapphon"}),"TRANSCRIPT_URL");
reject("URL fragment disallowed",()=>canonical({...tA.payload,request_url:urlA+"#cache"}),"TRANSCRIPT_URL");
reject("query-bearing URL disallowed",()=>canonical({...tA.payload,request_url:urlA+"?x=1"}),"TRANSCRIPT_URL");
reject("unexpected time authorization field rejected",()=>canonical({...tA.payload,utc_proven:true}),"TRANSCRIPT_FIELDS");
reject("claimed live timestamp rejected",()=>canonical({...tA.payload,declared_time:"2026-11-24T00:00:00Z"}),"TRANSCRIPT_FIELDS");
reject("non-GET method rejected",()=>canonical({...tA.payload,request_method:"POST"}),"TRANSCRIPT_FIELDS");
reject("redirect chain cannot exceed four hops",()=>canonical({...tA.payload,redirects:Array.from({length:5},()=>({from:urlA,to:redirect,status:302}))}),"TRANSCRIPT_FIELDS");
test("transport verifier is observation only",()=>{
 const old=JSON.stringify([tA,tB]);run();assert.equal(JSON.stringify([tA,tB]),old);
});
console.log("SAPPHON-109:",n,"transport transcript tests passed");
