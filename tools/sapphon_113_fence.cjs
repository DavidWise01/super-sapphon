"use strict";
/* SAPPHON-113: local canonical single-writer/epoch/fencing demonstration.
 * All authorizations must reach this one durable store. A disconnected replica
 * cannot authorize locally. This is NOT globally linearizable consensus.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const ID=/^[a-z0-9-]{4,64}$/,HEX=/^[0-9a-f]{64}$/;
const fail=c=>{throw Error(c)},sha=s=>crypto.createHash("sha256").update(s).digest("hex");
const SCHEMA="sapphon-113-single-writer-v1",MAX=2048,LEASE_MAX=300000;
function exact(o,k){return !!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|")}
function validate(d){
 if(!exact(d,["schema","revision","epoch","writer","lease_until","last_now","issued","attempts"])||
 d.schema!==SCHEMA||!Number.isSafeInteger(d.revision)||d.revision<0||
 !Number.isSafeInteger(d.epoch)||d.epoch<0||!Number.isSafeInteger(d.last_now)||d.last_now<0||
 !(d.writer===null||typeof d.writer==="string"&&ID.test(d.writer))||
 !Number.isSafeInteger(d.lease_until)||d.lease_until<0||
 (d.writer===null&&d.lease_until!==0)||
 !Array.isArray(d.issued)||d.issued.length>MAX||
 !Array.isArray(d.attempts)||d.attempts.length>MAX)fail("STORE_CORRUPT");
 const seen=new Set();
 for(const i of d.issued){
  if(!exact(i,["nonce","epoch","writer"])||!HEX.test(i.nonce)||seen.has(i.nonce)||
  !Number.isSafeInteger(i.epoch)||i.epoch<1||!ID.test(i.writer))fail("STORE_CORRUPT");
  seen.add(i.nonce);
 }
 for(const a of d.attempts){
  if(!exact(a,["action","code","epoch","writer","at"])||
  !["ACQUIRE","ISSUE"].includes(a.action)||typeof a.code!=="string"||
  !Number.isSafeInteger(a.epoch)||a.epoch<0||!Number.isSafeInteger(a.at)||a.at<0||
  typeof a.writer!=="string"||!ID.test(a.writer))fail("STORE_CORRUPT");
 }
 return d;
}
function withLock(dir,fn){
 if(!fs.existsSync(dir))fail("STORE_MISSING");
 const lock=path.join(dir,"lock");
 try{fs.mkdirSync(lock)}catch{fail("STORE_BUSY")}
 try{return fn(path.join(dir,"registry.json"))}finally{fs.rmdirSync(lock)}
}
function read(file){
 try{return validate(JSON.parse(fs.readFileSync(file,"utf8")))}
 catch(e){if(e.message==="STORE_CORRUPT")throw e;fail("STORE_UNREADABLE")}
}
function write(file,d){
 const tmp=path.join(path.dirname(file),".write-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,file);
  const fd2=fs.openSync(path.dirname(file),"r");try{fs.fsyncSync(fd2)}finally{fs.closeSync(fd2)}
 }catch(e){try{fs.unlinkSync(tmp)}catch{}fail("STORE_WRITE_FAILED")}
}
function init(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 return withLock(dir,file=>{
  if(fs.existsSync(file))fail("STORE_ALREADY_EXISTS");
  const d={schema:SCHEMA,revision:0,epoch:0,writer:null,lease_until:0,last_now:0,issued:[],attempts:[]};
  write(file,d);return d;
 });
}
function validWriter(writer,now){if(typeof writer!=="string"||!ID.test(writer)||!Number.isSafeInteger(now)||now<0)fail("BAD_REQUEST")}
function action(dir,{action,writer,now,epoch,nonce,lease_ms,reachable=true}){
 validWriter(writer,now);
 // A caller cannot assume local fallback when central storage is unreachable.
 if(reachable!==true)fail("CENTRAL_UNREACHABLE_HOLD");
 return withLock(dir,file=>{
  const d=read(file);
  if(now<d.last_now)fail("LOCAL_CLOCK_ROLLBACK");
  let error=null,result=null;
  if(action==="ACQUIRE"){
   if(!Number.isSafeInteger(lease_ms)||lease_ms<1||lease_ms>LEASE_MAX)fail("LEASE_BOUNDS");
   if(d.writer!==null&&now<d.lease_until)error="LEASE_HELD";
   else if(d.epoch===Number.MAX_SAFE_INTEGER||now+lease_ms>Number.MAX_SAFE_INTEGER)error="EPOCH_OVERFLOW";
   else{
    d.epoch++;d.writer=writer;d.lease_until=now+lease_ms;
    result={epoch:d.epoch,writer,lease_until:d.lease_until,decision:"TEST_LEASE_GRANTED"};
   }
  }else if(action==="ISSUE"){
   if(!HEX.test(nonce)||!Number.isSafeInteger(epoch)||epoch<1)fail("BAD_ISSUE");
   if(d.writer===null||now>=d.lease_until)error="LEASE_EXPIRED";
   else if(d.epoch!==epoch)error="STALE_EPOCH";
   else if(d.writer!==writer)error="NOT_ACTIVE_WRITER";
   else if(d.issued.some(x=>x.nonce===nonce))error="DUPLICATE_NONCE";
   else if(d.issued.length>=MAX)error="CAPACITY_HOLD";
   else{
    d.issued.push({nonce,epoch,writer});
    result={decision:"TEST_ISSUE_ACCEPTED",nonce,epoch,writer,utc_authority:false};
   }
  }else fail("UNKNOWN_ACTION");
  if(d.attempts.length>=MAX)fail("AUDIT_CAPACITY_HOLD");
  d.attempts.push({action,code:error||"ACCEPT",epoch:d.epoch,writer,at:now});
  d.last_now=now;d.revision++;
  write(file,d);
  if(error)fail(error);
  return result;
 });
}
function acquire(dir,writer,{now,lease_ms=60000,reachable=true}={}){return action(dir,{action:"ACQUIRE",writer,now,lease_ms,reachable})}
function issue(dir,writer,epoch,nonce,{now,reachable=true}={}){return action(dir,{action:"ISSUE",writer,epoch,nonce,now,reachable})}
function inspect(dir){return withLock(dir,file=>read(file))}
module.exports={init,acquire,issue,inspect,LEASE_MAX};
