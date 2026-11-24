"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {init:writerInit,acquire,issue}=require("./sapphon_113_fence.cjs");
const {init,apply,inspect}=require("./sapphon_115_reconcile.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon115-")),dir=path.join(root,"canonical");
const n=x=>x.repeat(64),r=(id,nonce,epoch=1,writer="writer-alpha",now=1003)=>({effect_id:id,nonce:n(nonce),epoch,writer,payload_sha256:n("a"),now});
let tests=0;function check(label,cb){cb();console.log("PASS",++tests,label)}
function reject(label,cb,code){check(label,()=>assert.throws(cb,e=>e.message===code))}
try{
 writerInit(dir);acquire(dir,"writer-alpha",{now:1000,lease_ms:150});init(dir);
 reject("cannot overwrite durable effect journal",()=>init(dir),"JOURNAL_EXISTS");
 issue(dir,"writer-alpha",1,n("1"),{now:1001});
 issue(dir,"writer-alpha",1,n("2"),{now:1002});
 reject("crash after durable prepare leaves only intent",()=>apply(dir,r("effect-first","1"),{fault:"AFTER_PREPARE"}),"INJECTED_CRASH_AFTER_PREPARE");
 check("prepared record survives process restart",()=>{const d=require("./sapphon_115_reconcile.cjs").inspect(dir).journal.records[0];assert.equal(d.status,"PREPARED");assert.equal(d.committed_at,null)});
 check("restart reconciliation completes one prepared synthetic effect",()=>{
  const v=apply(dir,r("effect-first","1",1,"writer-alpha",1004));assert.equal(v.status,"COMMITTED");assert.equal(v.reconciled,true);
 });
 check("repeat request returns acknowledged result without second commit",()=>{
  const v=apply(dir,r("effect-first","1",1,"writer-alpha",1005));
  assert.equal(v.reconciled,true);assert.equal(inspect(dir).journal.records.length,1);
 });
 reject("effect ID cannot be reused with different payload",()=>apply(dir,{...r("effect-first","1"),payload_sha256:n("c")}),"EFFECT_ID_CONFLICT");
 reject("nonce reserved for another effect cannot be reused",()=>apply(dir,r("effect-second","1",1,"writer-alpha",1006)),"NONCE_ALREADY_RESERVED");
 reject("acknowledgement loss occurs after durable commit",()=>apply(dir,r("effect-second","2",1,"writer-alpha",1007),{fault:"AFTER_COMMIT"}),"INJECTED_ACK_LOSS_AFTER_COMMIT");
 check("retry after lost acknowledgement never adds another effect",()=>{
  const v=apply(dir,r("effect-second","2",1,"writer-alpha",1008));
  assert.equal(v.reconciled,true);assert.equal(inspect(dir).journal.records.filter(x=>x.status==="COMMITTED").length,2);
 });
 issue(dir,"writer-alpha",1,n("3"),{now:1009});
 reject("prepare third intent and interrupt",()=>apply(dir,r("effect-third","3",1,"writer-alpha",1010),{fault:"AFTER_PREPARE"}),"INJECTED_CRASH_AFTER_PREPARE");
 reject("lease expires before recovery and blocks synthetic effect",()=>apply(dir,r("effect-third","3",1,"writer-alpha",1150)),"LEASE_EXPIRED");
 check("expired prepared attempt becomes ABORTED, not committed",()=>{
  const x=inspect(dir).journal.records.find(x=>x.effect_id==="effect-third");assert.equal(x.status,"ABORTED");
 });
 reject("aborted effect cannot be revived",()=>apply(dir,r("effect-third","3",1,"writer-alpha",1151)),"ABORTED_EFFECT_REQUIRES_NEW_ID");
 acquire(dir,"writer-beta",{now:1152,lease_ms:100});
 issue(dir,"writer-beta",2,n("4"),{now:1153});
 reject("stale epoch request refused at destination",()=>apply(dir,r("effect-old","3",1,"writer-alpha",1154)),"STALE_EPOCH");
 check("fresh fencing epoch commits once",()=>{assert.equal(apply(dir,r("effect-new","4",2,"writer-beta",1155)).decision,"TEST_EFFECT_COMMITTED")});
 check("old committed result may be queried without executing a new effect",()=>{
  const v=apply(dir,r("effect-first","1",1,"writer-alpha",1156));assert.equal(v.reconciled,true);
  assert.equal(inspect(dir).journal.records.filter(x=>x.status==="COMMITTED").length,3);
 });
 reject("unissued nonce cannot create effect",()=>apply(dir,r("effect-no","5",2,"writer-beta",1157)),"UNISSUED_NONCE");
 reject("wrong active writer refused",()=>apply(dir,r("effect-wrong","5",2,"writer-alpha",1158)),"WRONG_WRITER");
 reject("caller local time rollback refused",()=>apply(dir,r("effect-back","5",2,"writer-beta",1150)),"LOCAL_TIME_ROLLBACK");
 reject("network-owned authority fields disallowed",()=>apply(dir,{...r("effect-fake","5",2,"writer-beta",1159),utc_authorized:true}),"BAD_EFFECT_REQUEST");
 reject("bogus fault mode disallowed",()=>apply(dir,r("effect-fake","5",2,"writer-beta",1159),{fault:"AFTER_PHYSICAL_ACTION"}),"BAD_FAULT_MODE");
 reject("missing authoritative store fails closed",()=>apply(path.join(root,"missing"),r("effect-missing","5",2,"writer-beta",1160)),"STORE_MISSING");
 reject("canonical lock prevents concurrent effect reconciliation",()=>{
  fs.mkdirSync(path.join(dir,"lock"));try{apply(dir,r("effect-busy","5",2,"writer-beta",1160))}finally{fs.rmdirSync(path.join(dir,"lock"))}
 },"STORE_BUSY");
 reject("corrupt effect journal fails closed",()=>{
  const f=path.join(dir,"reconcile.json"),old=fs.readFileSync(f);try{fs.writeFileSync(f,"{bad");inspect(dir)}finally{fs.writeFileSync(f,old)}
 },"JOURNAL_UNREADABLE");
 reject("fabricated commit status without committed time refused",()=>{
  const f=path.join(dir,"reconcile.json"),old=fs.readFileSync(f);try{
   const d=JSON.parse(old);d.records[0].committed_at=null;fs.writeFileSync(f,JSON.stringify(d));inspect(dir)
  }finally{fs.writeFileSync(f,old)}
 },"JOURNAL_CORRUPT");
 reject("forged journal authority field refused",()=>{
  const f=path.join(dir,"reconcile.json"),old=fs.readFileSync(f);try{
   const d=JSON.parse(old);d.utc_authority=true;fs.writeFileSync(f,JSON.stringify(d));inspect(dir)
  }finally{fs.writeFileSync(f,old)}
 },"JOURNAL_CORRUPT");
 check("all effects are local synthetic journal records, never physical actions",()=>{
  const d=inspect(dir);assert.equal(d.journal.records.filter(x=>x.status==="COMMITTED").length,3);
  assert.equal(d.journal.records.filter(x=>x.status==="ABORTED").length,1);
  assert.equal(d.journal.utc_authority,undefined);
 });
 console.log("SAPPHON-115:",tests,"crash-recovery and exact-once local journal checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
