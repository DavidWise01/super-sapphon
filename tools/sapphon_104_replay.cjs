"use strict";
/* SAPPHON-104 durable, locally issued nonce gate.
 * JSON on a dedicated writable volume. Atomic rename + exclusive directory lock.
 * Missing/replaced storage or stale locks fail closed; no unauthorized resets.
 * No network timestamp claims. Caller injects monotonic/test wall clock and owns
 * access control to issue challenges. Nonce expiry is administrative, not UTC proof.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {challengeFor,challengeBytes,verifySession}=require("./sapphon_103_challenge.cjs");
function fail(code){throw Error(code)}
const SCHEMA="sapphon-104-replay-registry-v1",MAX=4096,MAX_TTL=300000,LOCK="lock";
const digest=x=>crypto.createHash("sha256").update(x).digest("hex");
function validateTime(now){if(!Number.isSafeInteger(now)||now<0)fail("BAD_LOCAL_TIME")}
function storePaths(directory){return {dir:directory,file:path.join(directory,"registry.json"),lock:path.join(directory,LOCK)}}
function withLock(directory,callback){
 const p=storePaths(directory);
 if(!fs.existsSync(p.dir))fail("STORE_UNINITIALIZED");
 try{fs.mkdirSync(p.lock)}catch{fail("LOCK_UNAVAILABLE")}
 try{return callback(p)}finally{fs.rmdirSync(p.lock)}
}
function read(p){
 let d;
 try{d=JSON.parse(fs.readFileSync(p.file,"utf8"))}catch{fail("STORE_UNAVAILABLE")}
 if(!d||d.schema!==SCHEMA||!Number.isSafeInteger(d.revision)||d.revision<0||
    !Array.isArray(d.records)||d.records.length>MAX)fail("STORE_CORRUPT");
 const used=new Set();
 for(const r of d.records){
  if(!r||Object.keys(r).sort().join("|")!=="challenge_digest|expires_at|issued_at|nonce|state"||
    !/^[a-f0-9]{64}$/.test(r.nonce)||!/^[a-f0-9]{64}$/.test(r.challenge_digest)||
    !Number.isSafeInteger(r.issued_at)||!Number.isSafeInteger(r.expires_at)||
    r.expires_at<=r.issued_at||r.expires_at-r.issued_at>MAX_TTL||
    !["ISSUED","CONSUMED"].includes(r.state)||used.has(r.nonce))fail("STORE_CORRUPT");
  used.add(r.nonce);
 }
 return d;
}
function write(p,d){
 const tmp=path.join(p.dir,".registry-"+crypto.randomBytes(8).toString("hex")+".tmp");
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}
  finally{fs.closeSync(fd)}
  fs.renameSync(tmp,p.file);
  const folder=fs.openSync(p.dir,"r");try{fs.fsyncSync(folder)}finally{fs.closeSync(folder)}
 }catch(e){try{fs.unlinkSync(tmp)}catch{}fail("STORE_WRITE_FAILED")}
}
function initialize(directory){
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const p=storePaths(directory);
 withLock(directory,()=>{if(fs.existsSync(p.file))fail("STORE_EXISTS");write(p,{schema:SCHEMA,revision:0,records:[]})});
}
function prune(records,now){return records.filter(x=>x.expires_at>now)}
function issue(directory,anchor,identity,{now,ttl_ms=60000,nonce}={}){
 validateTime(now);
 if(!Number.isSafeInteger(ttl_ms)||ttl_ms<1||ttl_ms>MAX_TTL)fail("TTL_OUT_OF_BOUNDS");
 return withLock(directory,p=>{
  const d=read(p),records=prune(d.records,now);
  if(records.length>=MAX)fail("CAPACITY_FULL");
  const challenge=challengeFor(anchor,identity,nonce);
  if(records.some(x=>x.nonce===challenge.nonce))fail("DUPLICATE_ISSUANCE");
  const expires=now+ttl_ms;
  if(!Number.isSafeInteger(expires))fail("TIME_OVERFLOW");
  records.push({nonce:challenge.nonce,challenge_digest:digest(challengeBytes(challenge)),
    issued_at:now,expires_at:expires,state:"ISSUED"});
  write(p,{schema:SCHEMA,revision:d.revision+1,records});
  return {challenge,expires_at:expires};
 });
}
function consume(directory,args,{now}={}){
 validateTime(now);
 return withLock(directory,p=>{
  const d=read(p),challenge=args.response?.challenge;
  const bytes=challengeBytes(challenge),entry=d.records.find(x=>x.nonce===challenge.nonce);
  if(!entry)fail("NONCE_NOT_ISSUED_OR_EXPIRED");
  if(entry.state==="CONSUMED")fail("DURABLE_REPLAY");
  if(now>=entry.expires_at)fail("CHALLENGE_EXPIRED");
  if(now<entry.issued_at)fail("CLOCK_ROLLBACK");
  if(digest(bytes)!==entry.challenge_digest)fail("ISSUED_CHALLENGE_MISMATCH");
  const result=verifySession({...args,seenNonces:new Set(),sessionId:args.sessionId});
  const records=prune(d.records,now).map(x=>x.nonce===entry.nonce?{...x,state:"CONSUMED"}:x);
  write(p,{schema:SCHEMA,revision:d.revision+1,records});
  return {...result,durable_replay_protection:true,expiry_enforced:true,
     independent_custody_confirmed:false,utc_authority:false};
 });
}
function inspect(directory){return withLock(directory,p=>read(p))}
module.exports={initialize,issue,consume,inspect,MAX_TTL,MAX};
