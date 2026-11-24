"use strict";
/* SAPPHON-115: crash-safe LOCAL journal effect reconciliation.
 * PREPARED is only intent, never an external side effect; COMMITTED is the
 * synthetic state transition. Both are fsynced/renamed under the exact
 * canonical writer lock used by SAPPHON-113/114. Cannot prove external exactly-once.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const ID=/^[a-z0-9-]{4,64}$/,H=/^[a-f0-9]{64}$/;
const SCHEMA="sapphon-115-effect-journal-v1",LIMIT=1024;
const fail=x=>{throw Error(x)};
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const recordFields=["effect_id","nonce","epoch","writer","payload_sha256","prepared_at","committed_at","status"];
function validRequest(r){
 if(!exact(r,["effect_id","nonce","epoch","writer","payload_sha256","now"])||
 !ID.test(r.effect_id)||!ID.test(r.writer)||!H.test(r.nonce)||!H.test(r.payload_sha256)||
 !Number.isSafeInteger(r.epoch)||r.epoch<1||!Number.isSafeInteger(r.now)||r.now<0)fail("BAD_EFFECT_REQUEST");
}
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("STORE_MISSING");
 const target=path.join(dir,"lock");
 try{fs.mkdirSync(target)}catch{fail("STORE_BUSY")}
 try{return fn()}finally{fs.rmdirSync(target)}
}
function canonical(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"registry.json"),"utf8"))}catch{fail("CANONICAL_UNREADABLE")}
 if(!exact(d,["schema","revision","epoch","writer","lease_until","last_now","issued","attempts"])||
 d.schema!=="sapphon-113-single-writer-v1"||
 !Number.isSafeInteger(d.epoch)||d.epoch<0||!Number.isSafeInteger(d.last_now)||d.last_now<0||
 !Number.isSafeInteger(d.lease_until)||d.lease_until<0||
 !Array.isArray(d.issued)||!(d.writer===null||typeof d.writer==="string"&&ID.test(d.writer)))fail("CANONICAL_INVALID");
 return d;
}
function journal(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"reconcile.json"),"utf8"))}catch{fail("JOURNAL_UNREADABLE")}
 if(!exact(d,["schema","revision","records","rejections"])||d.schema!==SCHEMA||
 !Number.isSafeInteger(d.revision)||d.revision<0||
 !Array.isArray(d.records)||d.records.length>LIMIT||
 !Array.isArray(d.rejections)||d.rejections.length>LIMIT)fail("JOURNAL_CORRUPT");
 const ids=new Set(),nonces=new Set();
 for(const r of d.records){
  if(!exact(r,recordFields)||!ID.test(r.effect_id)||!ID.test(r.writer)||
  !H.test(r.nonce)||!H.test(r.payload_sha256)||
  !Number.isSafeInteger(r.epoch)||r.epoch<1||
  !Number.isSafeInteger(r.prepared_at)||r.prepared_at<0||
  !["PREPARED","COMMITTED","ABORTED"].includes(r.status)||
  ((r.status==="COMMITTED")!==Number.isSafeInteger(r.committed_at))||
  (r.status==="COMMITTED"&&r.committed_at<r.prepared_at)||
  (r.status!=="COMMITTED"&&r.committed_at!==null)||
  ids.has(r.effect_id)||nonces.has(r.nonce))fail("JOURNAL_CORRUPT");
  ids.add(r.effect_id);nonces.add(r.nonce);
 }
 for(const r of d.rejections)
  if(!exact(r,["effect_id","code","at"])||!ID.test(r.effect_id)||
     typeof r.code!=="string"||!Number.isSafeInteger(r.at)||r.at<0)fail("JOURNAL_CORRUPT");
 return d;
}
function write(dir,d){
 const file=path.join(dir,"reconcile.json"),tmp=path.join(dir,".reconcile-"+crypto.randomBytes(8).toString("hex")+".tmp");
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,file);
  const directory=fs.openSync(dir,"r");try{fs.fsyncSync(directory)}finally{fs.closeSync(directory)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("JOURNAL_WRITE_FAILED")}
}
function init(dir){return lock(dir,()=>{
 canonical(dir);if(fs.existsSync(path.join(dir,"reconcile.json")))fail("JOURNAL_EXISTS");
 write(dir,{schema:SCHEMA,revision:0,records:[],rejections:[]});
})}
function current(c,r){
 if(r.now<c.last_now)return "LOCAL_TIME_ROLLBACK";
 if(c.writer===null||r.now>=c.lease_until)return "LEASE_EXPIRED";
 if(r.epoch!==c.epoch)return "STALE_EPOCH";
 if(r.writer!==c.writer)return "WRONG_WRITER";
 if(!c.issued.some(x=>x.nonce===r.nonce&&x.epoch===r.epoch&&x.writer===r.writer))return "UNISSUED_NONCE";
 return null;
}
function acknowledgement(r,replayed){
 return {schema:"sapphon-115-effect-result-v1",effect_id:r.effect_id,nonce:r.nonce,
  status:"COMMITTED",reconciled:replayed,physical_effect:false,utc_authority:false,decision:"TEST_EFFECT_COMMITTED"};
}
function apply(dir,r,{fault=null}={}){
 validRequest(r);
 if(![null,"AFTER_PREPARE","AFTER_COMMIT"].includes(fault))fail("BAD_FAULT_MODE");
 return lock(dir,()=>{
  const c=canonical(dir),d=journal(dir);
  const prior=d.records.find(x=>x.effect_id===r.effect_id);
  if(prior&&(prior.nonce!==r.nonce||prior.writer!==r.writer||prior.epoch!==r.epoch||prior.payload_sha256!==r.payload_sha256))
    fail("EFFECT_ID_CONFLICT");
  if(prior?.status==="COMMITTED")return acknowledgement(prior,true);
  if(prior?.status==="ABORTED")fail("ABORTED_EFFECT_REQUIRES_NEW_ID");
  const other=d.records.find(x=>x.nonce===r.nonce&&x.effect_id!==r.effect_id);
  if(other)fail("NONCE_ALREADY_RESERVED");
  const refusal=current(c,r);
  if(refusal){
   if(d.rejections.length>=LIMIT)fail("REJECTION_CAPACITY_HOLD");
   d.rejections.push({effect_id:r.effect_id,code:refusal,at:r.now});
   if(prior){prior.status="ABORTED";prior.committed_at=null}
   d.revision++;write(dir,d);fail(refusal);
  }
  if(!prior){
   if(d.records.length>=LIMIT)fail("EFFECT_CAPACITY_HOLD");
   d.records.push({effect_id:r.effect_id,nonce:r.nonce,epoch:r.epoch,writer:r.writer,
    payload_sha256:r.payload_sha256,prepared_at:r.now,committed_at:null,status:"PREPARED"});
   d.revision++;write(dir,d);
  }
  if(fault==="AFTER_PREPARE")fail("INJECTED_CRASH_AFTER_PREPARE");
  const effect=d.records.find(x=>x.effect_id===r.effect_id);
  effect.status="COMMITTED";effect.committed_at=r.now;
  d.revision++;write(dir,d);
  if(fault==="AFTER_COMMIT")fail("INJECTED_ACK_LOSS_AFTER_COMMIT");
  return acknowledgement(effect,!!prior);
 });
}
function inspect(dir){return lock(dir,()=>({canonical:canonical(dir),journal:journal(dir)}))}
module.exports={init,apply,inspect};
