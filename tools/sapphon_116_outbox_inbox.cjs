"use strict";
/* SAPPHON-116 — two independent LOCAL journals; receiver-side idempotency.
 * Sender retry is an authenticated replay of identical message, not new effect.
 * The receiver does not assert independently verified custody, UTC or real I/O.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const ID=/^[a-z0-9-]{4,64}$/,H=/^[a-f0-9]{64}$/;const MAX=1024;
function fail(x){throw Error(x)}
function exact(o,k){return !!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|")}
function sha(b){return crypto.createHash("sha256").update(b).digest("hex")}
function canonical(p){
 const fields=["schema","message_id","effect_id","sender_id","writer","epoch","nonce","payload_sha256"];
 if(!exact(p,fields)||p.schema!=="sapphon-116-message-v1"||
 ![p.message_id,p.effect_id,p.sender_id,p.writer].every(x=>typeof x==="string"&&ID.test(x))||
 !Number.isSafeInteger(p.epoch)||p.epoch<1||!H.test(p.nonce)||!H.test(p.payload_sha256))fail("MESSAGE_FIELDS");
 return Buffer.from(JSON.stringify(fields.map(k=>p[k])),"utf8");
}
function signForTest(p,key){return {payload:p,signature:crypto.sign(null,canonical(p),key).toString("base64")}}
function envelopeCheck(msg,registry){
 if(!exact(msg,["payload","signature"]))fail("MESSAGE_ENVELOPE");
 const b=canonical(msg.payload),p=msg.payload;
 if(!registry||!Object.hasOwn(registry,p.sender_id))fail("UNKNOWN_SENDER");
 const k=registry[p.sender_id];if(k.revoked===true)fail("REVOKED_SENDER");
 if(!k.publicKey||typeof msg.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(msg.signature)||
 !crypto.verify(null,b,k.publicKey,Buffer.from(msg.signature,"base64")))fail("MESSAGE_SIGNATURE");
 return sha(b);
}
function withLock(dir,fn){
 if(!fs.existsSync(dir))fail("JOURNAL_DIRECTORY_MISSING");
 const l=path.join(dir,"lock");try{fs.mkdirSync(l)}catch{fail("JOURNAL_LOCKED")}
 try{return fn()}finally{fs.rmdirSync(l)}
}
function load(dir,kind){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,kind+".json"),"utf8"))}catch{fail("JOURNAL_UNAVAILABLE")}
 if(!exact(d,["schema","revision","records"])||d.schema!=="sapphon-116-"+kind+"-v1"||
 !Number.isSafeInteger(d.revision)||d.revision<0||!Array.isArray(d.records)||d.records.length>MAX)fail("JOURNAL_CORRUPT");
 const ids=new Set(),effects=new Set(),nonces=new Set();
 for(const r of d.records){
  if(!exact(r,["message_id","effect_id","nonce","message_sha256","status","receipt_sha256"])||
  ![r.message_id,r.effect_id].every(x=>typeof x==="string"&&ID.test(x))||
  !H.test(r.nonce)||!H.test(r.message_sha256)||
  !["PENDING","RECEIVED","ACKED"].includes(r.status)||
  !(r.receipt_sha256===null||H.test(r.receipt_sha256))||
  ((kind==="inbox")!==(r.status==="RECEIVED"))||
  (kind==="outbox"&&!["PENDING","ACKED"].includes(r.status))||
  (r.status==="PENDING"&&r.receipt_sha256!==null)||
  (r.status!=="PENDING"&&r.receipt_sha256===null)||
  ids.has(r.message_id)||effects.has(r.effect_id)||nonces.has(r.nonce))fail("JOURNAL_CORRUPT");
  ids.add(r.message_id);effects.add(r.effect_id);nonces.add(r.nonce);
 }
 return d;
}
function write(dir,kind,data){
 const dest=path.join(dir,kind+".json"),tmp=path.join(dir,".tx-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(data)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,dest);
  const df=fs.openSync(dir,"r");try{fs.fsyncSync(df)}finally{fs.closeSync(df)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("JOURNAL_WRITE_FAILED")}
}
function initialize(dir,kind){
 if(!["outbox","inbox"].includes(kind))fail("JOURNAL_KIND");
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 return withLock(dir,()=>{
  if(fs.existsSync(path.join(dir,kind+".json")))fail("JOURNAL_EXISTS");
  write(dir,kind,{schema:"sapphon-116-"+kind+"-v1",revision:0,records:[]});
 });
}
function entry(p,message_sha256,status,receipt_sha256=null){
 return {message_id:p.message_id,effect_id:p.effect_id,nonce:p.nonce,message_sha256,status,receipt_sha256};
}
function queue(dir,msg,registry){
 const digest=envelopeCheck(msg,registry),p=msg.payload;
 return withLock(dir,()=>{
  const d=load(dir,"outbox");
  const previous=d.records.find(r=>r.message_id===p.message_id||r.effect_id===p.effect_id||r.nonce===p.nonce);
  if(previous){
   if(previous.message_id!==p.message_id||previous.effect_id!==p.effect_id||
      previous.nonce!==p.nonce||previous.message_sha256!==digest)fail("OUTBOX_CONFLICT");
   return {decision:"ALREADY_QUEUED",status:previous.status};
  }
  if(d.records.length>=MAX)fail("OUTBOX_CAPACITY");
  d.records.push(entry(p,digest,"PENDING"));d.revision++;write(dir,"outbox",d);
  return {decision:"QUEUED",status:"PENDING"};
 });
}
function receipt(p,digest){return sha(Buffer.from(JSON.stringify(["sapphon-116-receipt-v1",p.message_id,digest])))}
function deliver(dir,msg,registry,{fault=null}={}){
 if(![null,"AFTER_RECEIVER_COMMIT"].includes(fault))fail("FAULT_MODE");
 const digest=envelopeCheck(msg,registry),p=msg.payload;
 return withLock(dir,()=>{
  const d=load(dir,"inbox");
  const prior=d.records.find(r=>r.message_id===p.message_id||r.effect_id===p.effect_id||r.nonce===p.nonce);
  if(prior){
   if(prior.message_id!==p.message_id||prior.effect_id!==p.effect_id||
      prior.nonce!==p.nonce||prior.message_sha256!==digest)fail("RECEIVER_CONFLICT");
   return {schema:"sapphon-116-receipt-v1",status:"RECEIVED",message_id:p.message_id,
    message_sha256:digest,receipt_sha256:prior.receipt_sha256,duplicate:true,external_effect:false};
  }
  if(d.records.length>=MAX)fail("INBOX_CAPACITY");
  const rd=receipt(p,digest);
  d.records.push(entry(p,digest,"RECEIVED",rd));d.revision++;write(dir,"inbox",d);
  if(fault==="AFTER_RECEIVER_COMMIT")fail("INJECTED_LOST_REPLY");
  return {schema:"sapphon-116-receipt-v1",status:"RECEIVED",message_id:p.message_id,
   message_sha256:digest,receipt_sha256:rd,duplicate:false,external_effect:false};
 });
}
function acknowledge(dir,msg,registry,ack){
 const digest=envelopeCheck(msg,registry),p=msg.payload,expected=receipt(p,digest);
 if(!exact(ack,["schema","status","message_id","message_sha256","receipt_sha256","duplicate","external_effect"])||
 ack.schema!=="sapphon-116-receipt-v1"||ack.status!=="RECEIVED"||ack.message_id!==p.message_id||
 ack.message_sha256!==digest||ack.receipt_sha256!==expected||
 typeof ack.duplicate!=="boolean"||ack.external_effect!==false)fail("ACK_BINDING");
 return withLock(dir,()=>{
  const d=load(dir,"outbox"),prior=d.records.find(r=>r.message_id===p.message_id);
  if(!prior||prior.message_sha256!==digest)fail("OUTBOX_NOT_FOUND");
  if(prior.status==="ACKED"){
   if(prior.receipt_sha256!==expected)fail("ACK_CONFLICT");
   return {decision:"ALREADY_ACKED",acknowledged:true};
  }
  prior.status="ACKED";prior.receipt_sha256=expected;d.revision++;write(dir,"outbox",d);
  return {decision:"ACKED",acknowledged:true};
 });
}
function inspect(dir,kind){return withLock(dir,()=>load(dir,kind))}
module.exports={canonical,signForTest,initialize,queue,deliver,acknowledge,inspect};
