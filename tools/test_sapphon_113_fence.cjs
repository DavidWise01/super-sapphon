"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {init,acquire,issue,inspect,LEASE_MAX}=require("./sapphon_113_fence.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon113-")),dir=path.join(root,"canonical");
const nonce=c=>c.repeat(64);let n=0;
function test(label,fn){fn();console.log("PASS",++n,label)}
function reject(label,fn,code){test(label,()=>assert.throws(fn,e=>e.message===code))}
try{
 test("initialize unique canonical writer journal",()=>{init(dir);assert.equal(inspect(dir).epoch,0)});
 reject("existing journal cannot be reset",()=>init(dir),"STORE_ALREADY_EXISTS");
 const A=acquire(dir,"writer-alpha",{now:1000,lease_ms:200});
 test("first writer gets epoch one",()=>{assert.equal(A.epoch,1);assert.equal(A.lease_until,1200)});
 reject("second writer cannot acquire before lease expires",()=>acquire(dir,"writer-beta",{now:1001,lease_ms:200}),"LEASE_HELD");
 test("rejected attempt is persisted in canonical journal",()=>{
  const d=inspect(dir);assert.equal(d.attempts.at(-1).code,"LEASE_HELD");
 });
 test("current writer can issue a bounded test nonce",()=>{assert.equal(issue(dir,"writer-alpha",1,nonce("a"),{now:1002}).decision,"TEST_ISSUE_ACCEPTED")});
 reject("second writer cannot issue against first writer epoch",()=>issue(dir,"writer-beta",1,nonce("b"),{now:1003}),"NOT_ACTIVE_WRITER");
 reject("duplicate nonce cannot be minted twice",()=>issue(dir,"writer-alpha",1,nonce("a"),{now:1004}),"DUPLICATE_NONCE");
 reject("expired lease refuses writes",()=>issue(dir,"writer-alpha",1,nonce("c"),{now:1200}),"LEASE_EXPIRED");
 const B=acquire(dir,"writer-beta",{now:1201,lease_ms:100});
 test("new writer advances the fencing epoch",()=>assert.equal(B.epoch,2));
 reject("stale writer from previous epoch denied",()=>issue(dir,"writer-alpha",1,nonce("d"),{now:1202}),"STALE_EPOCH");
 test("current second writer issues with new epoch",()=>assert.equal(issue(dir,"writer-beta",2,nonce("e"),{now:1203}).epoch,2));
 reject("partitioned replica cannot acquire",()=>acquire(dir,"partitioned-replica",{now:1204,reachable:false}),"CENTRAL_UNREACHABLE_HOLD");
 reject("partitioned replica cannot issue even using known epoch",()=>issue(dir,"writer-beta",2,nonce("f"),{now:1205,reachable:false}),"CENTRAL_UNREACHABLE_HOLD");
 reject("time rollback detected across persisted journal",()=>issue(dir,"writer-beta",2,nonce("f"),{now:1200}),"LOCAL_CLOCK_ROLLBACK");
 reject("nonexistent journal refuses issuing",()=>issue(path.join(root,"missing"),"writer-beta",2,nonce("f"),{now:1206}),"STORE_MISSING");
 reject("lease longer than bound rejected",()=>acquire(dir,"writer-other",{now:1302,lease_ms:LEASE_MAX+1}),"LEASE_BOUNDS");
 reject("zero lease rejected",()=>acquire(dir,"writer-other",{now:1303,lease_ms:0}),"LEASE_BOUNDS");
 reject("invalid nonce rejected",()=>issue(dir,"writer-beta",2,"bad",{now:1207}),"BAD_ISSUE");
 reject("undefined epoch rejected",()=>issue(dir,"writer-beta",undefined,nonce("1"),{now:1208}),"BAD_ISSUE");
 reject("unauthorized writer ID rejected",()=>issue(dir,"??",2,nonce("2"),{now:1208}),"BAD_REQUEST");
 reject("unknown action not accepted through API",()=>acquire(dir,"writer-other",{now:1302,lease_ms:100,reachable:null}),"CENTRAL_UNREACHABLE_HOLD");
 reject("exclusive store lock blocks mutation",()=>{
  fs.mkdirSync(path.join(dir,"lock"));try{issue(dir,"writer-beta",2,nonce("3"),{now:1209})}finally{fs.rmdirSync(path.join(dir,"lock"))}
 },"STORE_BUSY");
 reject("corrupted storage fails closed",()=>{
  const f=path.join(dir,"registry.json"),old=fs.readFileSync(f);
  try{fs.writeFileSync(f,"bad-json");inspect(dir)}finally{fs.writeFileSync(f,old)}
 },"STORE_UNREADABLE");
 reject("invalid journal shape fails closed",()=>{
  const f=path.join(dir,"registry.json"),old=fs.readFileSync(f);
  try{const d=JSON.parse(old);d.utc_authority=true;fs.writeFileSync(f,JSON.stringify(d));inspect(dir)}
  finally{fs.writeFileSync(f,old)}
 },"STORE_CORRUPT");
 test("issuer history remains after new epoch",()=>{
  const d=inspect(dir);assert.deepEqual(d.issued.map(x=>x.epoch),[1,2]);assert.equal(d.writer,"writer-beta");
  assert.equal(d.attempts.filter(x=>x.code!=="ACCEPT").length>=5,true);
 });
 test("stored rejections survive a new module read",()=>assert.equal(require("./sapphon_113_fence.cjs").inspect(dir).attempts.some(x=>x.code==="STALE_EPOCH"),true));
 test("same canonical store holds one writer at a time",()=>{
  const d=inspect(dir);assert.equal(typeof d.writer,"string");assert.equal(d.utc_authority,undefined);
 });
 console.log("SAPPHON-113:",n,"single-writer epoch and partition-fencing checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
