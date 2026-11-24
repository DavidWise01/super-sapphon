"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),
  os=require("node:os"),path=require("node:path"),cp=require("node:child_process");
const {signedForTest,appendEvent}=require("./sapphon_099_enrollment.cjs");
const {createCheckpoint,verifyCheckpoint}=require("./sapphon_100_checkpoint.cjs");
const gov=crypto.generateKeyPairSync("ed25519"),other=crypto.generateKeyPairSync("ed25519"),
  first=crypto.generateKeyPairSync("ed25519"),second=crypto.generateKeyPairSync("ed25519");
const pub=x=>x.export({type:"spki",format:"pem"});
let entries=[],head=null;
function add(type,key,generation,material,reason=null){
 const event={type,source_id:"synthetic-archive",ancestry_root:"one-owned-root",
  role:"synthetic-test",key_id:key,public_key_pem:type==="REVOKE"?null:pub(material.publicKey),
  reason,generation,index:entries.length,prev_event_hash:head};
 const next=appendEvent(entries,signedForTest(event,gov.privateKey),gov.publicKey);
 entries=next.entries;head=next.head;
}
add("ENROLL","test-key-a",0,first);
add("REVOKE","test-key-a",0,first,"synthetic compromised key");
add("REENROLL","test-key-b",1,second);
const governanceId="test-governance-100";
const checkpoint=createCheckpoint(entries,gov.privateKey,gov.publicKey,governanceId);
const document={entries,checkpoint};
const clone=x=>JSON.parse(JSON.stringify(x));
let n=0;function test(name,fn){fn();console.log("PASS",++n,name)}
function rejects(name,fn,error){test(name,()=>assert.throws(fn,e=>e.message===error))}
test("valid checkpoint anchors exact ledger head",()=>{const result=verifyCheckpoint(entries,checkpoint,gov.publicKey,governanceId);assert.equal(result.event_count,3);assert.equal(result.root_count,1);assert.equal(result.clock_authority,false)});
test("checkpoint contains one active source after re-enrollment",()=>{assert.equal(checkpoint.payload.sources.length,1);assert.equal(checkpoint.payload.sources[0].status,"ACTIVE");assert.equal(checkpoint.payload.sources[0].key_id,"test-key-b")});
rejects("unknown governance root rejected",()=>verifyCheckpoint(entries,checkpoint,gov.publicKey,"other-root"),"UNTRUSTED_GOVERNANCE_KEY");
rejects("wrong public key rejects signature",()=>verifyCheckpoint(entries,checkpoint,other.publicKey,governanceId),"CHECKPOINT_SIGNATURE");
rejects("tampered checkpoint head breaks signature",()=>{const c=clone(checkpoint);c.payload.head="a".repeat(64);verifyCheckpoint(entries,c,gov.publicKey,governanceId)},"CHECKPOINT_SIGNATURE");
rejects("tampered source state breaks signature",()=>{const c=clone(checkpoint);c.payload.sources[0].ancestry_root="fake-root";verifyCheckpoint(entries,c,gov.publicKey,governanceId)},"CHECKPOINT_SIGNATURE");
rejects("truncated ledger rejected",()=>verifyCheckpoint(entries.slice(0,-1),checkpoint,gov.publicKey,governanceId),"HEAD_MISMATCH");
rejects("wrong event signature rejected",()=>{const e=clone(entries);e[0].signature=e[1].signature;verifyCheckpoint(e,checkpoint,gov.publicKey,governanceId)},"GOVERNANCE_SIGNATURE");
rejects("reordered event chain rejected",()=>verifyCheckpoint([entries[1],entries[0],entries[2]],checkpoint,gov.publicKey,governanceId),"BROKEN_LEDGER_CHAIN");
rejects("forged signature rejected",()=>{const c=clone(checkpoint);c.signature=crypto.sign(null,Buffer.from("forged"),other.privateKey).toString("base64");verifyCheckpoint(entries,c,gov.publicKey,governanceId)},"CHECKPOINT_SIGNATURE");
test("checkpoint verification does not mutate original entries",()=>{const baseline=JSON.stringify(entries);verifyCheckpoint(entries,checkpoint,gov.publicKey,governanceId);assert.equal(JSON.stringify(entries),baseline)});
test("separate Python implementation accepts same signed checkpoint",()=>{
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon100-"));
 try{fs.writeFileSync(path.join(tmp,"audit.json"),JSON.stringify(document));
     fs.writeFileSync(path.join(tmp,"root.pem"),pub(gov.publicKey));
     const run=cp.spawnSync("python3",["tools/sapphon_100_verify.py",path.join(tmp,"audit.json"),path.join(tmp,"root.pem"),governanceId],{encoding:"utf8"});
     assert.equal(run.status,0,run.stderr);
     const result=JSON.parse(run.stdout);assert.equal(result.events,3);assert.equal(result.roots,1);
     const bad=clone(document);bad.entries[1].event.reason="rewritten";fs.writeFileSync(path.join(tmp,"audit.json"),JSON.stringify(bad));
     const fail=cp.spawnSync("python3",["tools/sapphon_100_verify.py",path.join(tmp,"audit.json"),path.join(tmp,"root.pem"),governanceId],{encoding:"utf8"});
     assert.notEqual(fail.status,0,"Python accepted tampered history");
 }finally{fs.rmSync(tmp,{recursive:true,force:true})}
});
console.log("SAPPHON-100:",n,"cross-implementation audit tests passed");
