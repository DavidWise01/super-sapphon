"use strict";
/* SAPPHON-117: transactional receiver state for synthetic effects.
 * One atomic file replacement contains BOTH message deduplication AND effect
 * ledger. No caller-controlled split commit; no real external side effects,
 * anti-rollback anchor, or authenticated UTC.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {canonical}=require("./sapphon_116_outbox_inbox.cjs");
const ID=/^[a-z0-9-]{4,64}$/,H=/^[a-f0-9]{64}$/;
const MAX=1024,SCHEMA="sapphon-117-transactional-receiver-v1";
const fail=x=>{throw Error(x)};
const hash=b=>crypto.createHash("sha256").update(b).digest("hex");
function exactly(o,keys){
 return !!o&&typeof o==="object"&&!Array.isArray(o)&&
  Object.keys(o).sort().join("|")===keys.slice().sort().join("|");
}
function sourceDigest(message,registry){
 if(!exactly(message,["payload","signature"]))fail("MESSAGE_ENVELOPE");
 const raw=canonical(message.payload),id=message.payload.sender_id;
 if(!registry||!Object.hasOwn(registry,id))fail("UNKNOWN_SENDER");
 const k=registry[id];if(k.revoked===true)fail("REVOKED_SENDER");
 if(!k.publicKey||typeof message.signature!=="string"||
 !/^[A-Za-z0-9+/]{86}==$/.test(message.signature)||
 !crypto.verify(null,raw,k.publicKey,Buffer.from(message.signature,"base64")))fail("MESSAGE_SIGNATURE");
 return hash(raw);
}
function receiptFor(p,digest){
 return hash(Buffer.from(JSON.stringify(["sapphon-116-receipt-v1",p.message_id,digest])));
}
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("RECEIVER_MISSING");
 const p=path.join(dir,"lock");
 try{fs.mkdirSync(p)}catch{fail("RECEIVER_LOCKED")}
 try{return fn()}finally{fs.rmdirSync(p)}
}
function validate(s){
 if(!exactly(s,["schema","revision","records","effects"])||s.schema!==SCHEMA||
 !Number.isSafeInteger(s.revision)||s.revision<0||
 !Array.isArray(s.records)||!Array.isArray(s.effects)||
 s.records.length>MAX||s.effects.length>MAX||s.records.length!==s.effects.length)fail("RECEIVER_CORRUPT");
 const m=new Set(),e=new Set(),n=new Set(),linked=new Map();
 for(const r of s.records){
  if(!exactly(r,["message_id","effect_id","nonce","message_sha256","payload_sha256","receipt_sha256"])||
   !ID.test(r.message_id)||!ID.test(r.effect_id)||
   ![r.nonce,r.message_sha256,r.payload_sha256,r.receipt_sha256].every(x=>typeof x==="string"&&H.test(x))||
   m.has(r.message_id)||e.has(r.effect_id)||n.has(r.nonce))fail("RECEIVER_CORRUPT");
  m.add(r.message_id);e.add(r.effect_id);n.add(r.nonce);
  if(r.receipt_sha256!==receiptFor({message_id:r.message_id},r.message_sha256))fail("RECEIVER_CORRUPT");
  linked.set(r.effect_id,r);
 }
 const effectIds=new Set();
 for(const effect of s.effects){
  if(!exactly(effect,["effect_id","message_id","nonce","payload_sha256","kind"])||
   effect.kind!=="synthetic-ledger-effect"||!ID.test(effect.effect_id)||effectIds.has(effect.effect_id)||
   !linked.has(effect.effect_id))fail("RECEIVER_CORRUPT");
  const r=linked.get(effect.effect_id);
  if(effect.message_id!==r.message_id||effect.nonce!==r.nonce||
   effect.payload_sha256!==r.payload_sha256)fail("RECEIVER_CORRUPT");
  effectIds.add(effect.effect_id);
 }
 if(effectIds.size!==s.records.length)fail("RECEIVER_CORRUPT");
 return s;
}
function read(dir){
 let s;try{s=JSON.parse(fs.readFileSync(path.join(dir,"transaction.json"),"utf8"))}
 catch{fail("RECEIVER_UNREADABLE")}
 return validate(s);
}
function write(dir,s){
 const file=path.join(dir,"transaction.json"),tmp=path.join(dir,".tx-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(s)+"\n");fs.fsyncSync(fd)}
  finally{fs.closeSync(fd)}
  fs.renameSync(tmp,file);
  const directoryFd=fs.openSync(dir,"r");try{fs.fsyncSync(directoryFd)}finally{fs.closeSync(directoryFd)}
 }catch(e){try{fs.unlinkSync(tmp)}catch{}fail("RECEIVER_WRITE_FAILED")}
}
function init(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 return lock(dir,()=>{
  if(fs.existsSync(path.join(dir,"transaction.json")))fail("RECEIVER_EXISTS");
  write(dir,{schema:SCHEMA,revision:0,records:[],effects:[]});
 });
}
function ack(r,duplicate){
 return {schema:"sapphon-116-receipt-v1",status:"RECEIVED",message_id:r.message_id,
 message_sha256:r.message_sha256,receipt_sha256:r.receipt_sha256,
 duplicate,external_effect:false};
}
function deliver(dir,message,registry,{fault=null}={}){
 if(![null,"BEFORE_TRANSACTION","AFTER_TRANSACTION"].includes(fault))fail("FAULT_MODE");
 const digest=sourceDigest(message,registry),p=message.payload;
 return lock(dir,()=>{
  const s=read(dir),prior=s.records.find(r=>
   r.message_id===p.message_id||r.effect_id===p.effect_id||r.nonce===p.nonce);
  if(prior){
   if(prior.message_id!==p.message_id||prior.effect_id!==p.effect_id||
    prior.nonce!==p.nonce||prior.message_sha256!==digest||
    prior.payload_sha256!==p.payload_sha256)fail("RECEIVER_CONFLICT");
   return ack(prior,true);
  }
  if(s.records.length>=MAX)fail("RECEIVER_CAPACITY_HOLD");
  if(fault==="BEFORE_TRANSACTION")fail("INJECTED_BEFORE_TRANSACTION");
  const r={message_id:p.message_id,effect_id:p.effect_id,nonce:p.nonce,
   message_sha256:digest,payload_sha256:p.payload_sha256,
   receipt_sha256:receiptFor(p,digest)};
  // Single replacement state: deduplication and synthetic effect are inseparable.
  s.records.push(r);
  s.effects.push({effect_id:p.effect_id,message_id:p.message_id,nonce:p.nonce,
   payload_sha256:p.payload_sha256,kind:"synthetic-ledger-effect"});
  s.revision++;
  write(dir,s);
  if(fault==="AFTER_TRANSACTION")fail("INJECTED_LOST_REPLY");
  return ack(r,false);
 });
}
function inspect(dir){return lock(dir,()=>read(dir))}
module.exports={init,deliver,inspect,receiptFor};
