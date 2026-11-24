"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {signedForTest,appendEvent}=require("./sapphon_099_enrollment.cjs");
const {createCheckpoint}=require("./sapphon_100_checkpoint.cjs");
const {anchorFrom,compare}=require("./sapphon_101_anchor.cjs");
const gov=crypto.generateKeyPairSync("ed25519"),other=crypto.generateKeyPairSync("ed25519");
const first=crypto.generateKeyPairSync("ed25519"),second=crypto.generateKeyPairSync("ed25519");
const pub=k=>k.export({format:"pem",type:"spki"});
const keyId="test-governance-101";
function event(type,index,prev,key,gen,source="synthetic-archive",reason=null,material=first){
 return {type,source_id:source,ancestry_root:"owned-one-root",role:"synthetic-test",
 key_id:key,public_key_pem:type==="REVOKE"?null:pub(material.publicKey),
 reason,generation:gen,index,prev_event_hash:prev};
}
function add(history,body){return appendEvent(history,signedForTest(body,gov.privateKey),gov.publicKey)}
let base=add([],event("ENROLL",0,null,"test-key-a",0));
base=add(base.entries,event("REVOKE",1,base.head,"test-key-a",0,"synthetic-archive","Synthetic compromised key"));
base=add(base.entries,event("REENROLL",2,base.head,"test-key-b",1,"synthetic-archive",null,second));
const checkpoint=history=>createCheckpoint(history,gov.privateKey,gov.publicKey,keyId);
const cp0=checkpoint(base.entries);
const anchor=anchorFrom(base.entries,cp0,gov.publicKey,keyId);
const extended=add(base.entries,event("ENROLL",3,base.head,"other-test-key",0,"other-synthetic",null,other));
const cp1=checkpoint(extended.entries);
const clone=x=>JSON.parse(JSON.stringify(x));
let n=0;function test(name,fn){fn();console.log("PASS",++n,name)}
function rejects(name,fn,expected){test(name,()=>assert.throws(fn,e=>e.message===expected))}
test("signed baseline anchor stays self-described as not externally retained",()=>{assert.equal(anchor.independently_retained,false);assert.equal(anchor.recorded_utc,null)});
test("unchanged anchored ledger accepted",()=>{const r=compare(anchor,base.entries,cp0,base.entries,cp0,gov.publicKey,keyId);assert.equal(r.status,"ANCHOR_MATCH")});
test("valid signed extension after anchor accepted",()=>{const r=compare(anchor,base.entries,cp0,extended.entries,cp1,gov.publicKey,keyId);assert.equal(r.new_events,1);assert.equal(r.utc_authority,false)});
rejects("truncated ledger is rollback",()=>{const c=checkpoint(base.entries.slice(0,2));compare(anchor,base.entries,cp0,base.entries.slice(0,2),c,gov.publicKey,keyId)},"ROLLBACK");
rejects("wrong head in anchor fails pin",()=>compare({...anchor,head:"a".repeat(64)},base.entries,cp0,base.entries,cp0,gov.publicKey,keyId),"PINNED_ANCHOR_MISMATCH");
rejects("substituted public trust root rejected",()=>compare(anchor,base.entries,cp0,base.entries,cp0,other.publicKey,keyId),"CHECKPOINT_SIGNATURE");
rejects("replaced anchor signature fails pin",()=>compare({...anchor,checkpoint_signature:"A".repeat(86)+"=="},base.entries,cp0,base.entries,cp0,gov.publicKey,keyId),"PINNED_ANCHOR_MISMATCH");
rejects("bogus claim of independent retention refused",()=>compare({...anchor,independently_retained:true},base.entries,cp0,base.entries,cp0,gov.publicKey,keyId),"ANCHOR_SCOPE");
rejects("bogus UTC claim refused",()=>compare({...anchor,recorded_utc:"2026-11-24T15:00:00Z"},base.entries,cp0,base.entries,cp0,gov.publicKey,keyId),"ANCHOR_SCOPE");
rejects("different governance key identity rejected",()=>compare(anchor,base.entries,cp0,base.entries,cp0,gov.publicKey,"new-governance"),"ANCHOR_SCOPE");
// Entire alternate fork is correctly re-signed by the SAME governance key: signature verification
// alone cannot detect a rewritten history unless the old head is pinned elsewhere.
let fork=add([],event("ENROLL",0,null,"test-key-a",0));
fork=add(fork.entries,event("REVOKE",1,fork.head,"test-key-a",0,"synthetic-archive","Rewritten justification"));
fork=add(fork.entries,event("REENROLL",2,fork.head,"test-key-b",1,"synthetic-archive",null,second));
rejects("same height fully re-signed fork rejected",()=>compare(anchor,base.entries,cp0,fork.entries,checkpoint(fork.entries),gov.publicKey,keyId),"SAME_HEIGHT_FORK");
fork=add(fork.entries,event("ENROLL",3,fork.head,"other-test-key",0,"other-synthetic",null,other));
rejects("longer re-signed fork rejected at historical entry",()=>compare(anchor,base.entries,cp0,fork.entries,checkpoint(fork.entries),gov.publicKey,keyId),"HISTORICAL_FORK_AT_1");
rejects("altered unsigned historical entry rejected",()=>{const changed=clone(extended.entries);changed[0].event.source_id="impostor";compare(anchor,base.entries,cp0,changed,cp1,gov.publicKey,keyId)},"GOVERNANCE_SIGNATURE");
test("same source root for all new enrolled aliases",()=>{assert.equal(extended.sources.get("other-synthetic").root,extended.sources.get("synthetic-archive").root)});
test("failed comparisons do not alter history",()=>{assert.equal(base.entries.length,3);assert.equal(extended.entries.length,4)});
console.log("SAPPHON-101:",n,"anchor, rollback, fork and source-root tests passed");