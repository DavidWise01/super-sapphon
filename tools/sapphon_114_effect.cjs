"use strict";
/* SAPPHON-114 — destination-enforced local fencing.
 * The destination uses the EXACT lock of SAPPHON-113's canonical lease registry
 * and checks current epoch under that lock before writing its side-effect
 * journal. No remote network/real-world effect, distributed consensus or UTC.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const ID=/^[a-z0-9-]{4,64}$/,H=/^[a-f0-9]{64}$/;
const SCHEMA="sapphon-114-effects-v1",MAX=1024;
const fail=x=>{throw Error(x)};
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("CANONICAL_STORE_MISSING");
 const p=path.join(dir,"lock");
 try{fs.mkdirSync(p)}catch{fail("CANONICAL_LOCK_UNAVAILABLE")}
 try{return fn()}finally{fs.rmdirSync(p)}
}
function exact(o,k){return !!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|")}
function readCanon(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"registry.json"),"utf8"))}catch{fail("CANONICAL_UNREADABLE")}
 if(!exact(d,["schema","revision","epoch","writer","lease_until","last_now","issued","attempts"])||
 d.schema!=="sapphon-113-single-writer-v1"||!Number.isSafeInteger(d.epoch)||d.epoch<0||
 !Number.isSafeInteger(d.last_now)||d.last_now<0||!Number.isSafeInteger(d.lease_until)||d.lease_until<0||
 !(d.writer===null||typeof d.writer==="string"&&ID.test(d.writer))||
 !Array.isArray(d.issued))fail("CANONICAL_INVALID");
 return d;
}
function readEffects(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"effects.json"),"utf8"))}catch{fail("EFFECTS_UNREADABLE")}
 if(!exact(d,["schema","revision","commits","rejections"])||d.schema!==SCHEMA||
 !Number.isSafeInteger(d.revision)||d.revision<0||
 !Array.isArray(d.commits)||d.commits.length>MAX||
 !Array.isArray(d.rejections)||d.rejections.length>MAX)fail("EFFECTS_CORRUPT");
 const seen=new Set();
 for(const c of d.commits){
  if(!exact(c,["effect_id","nonce","epoch","writer","payload_sha256","at"])||
     !ID.test(c.effect_id)||!H.test(c.nonce)||!H.test(c.payload_sha256)||
     !ID.test(c.writer)||!Number.isSafeInteger(c.epoch)||c.epoch<1||
     !Number.isSafeInteger(c.at)||c.at<0||seen.has(c.effect_id))fail("EFFECTS_CORRUPT");
  seen.add(c.effect_id);
 }
 for(const a of d.rejections){
  if(!exact(a,["effect_id","reason","epoch","writer","at"])||
   !ID.test(a.effect_id)||typeof a.reason!=="string"||!ID.test(a.writer)||
   !Number.isSafeInteger(a.epoch)||!Number.isSafeInteger(a.at))fail("EFFECTS_CORRUPT");
 }
 return d;
}
function write(file,d){
 const tmp=path.join(path.dirname(file),".effect-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,file);
  const folder=fs.openSync(path.dirname(file),"r");
  try{fs.fsyncSync(folder)}finally{fs.closeSync(folder)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("EFFECT_WRITE_FAILED")}
}
function init(dir){return lock(dir,()=>{
 readCanon(dir);
 const f=path.join(dir,"effects.json");
 if(fs.existsSync(f))fail("EFFECTS_ALREADY_EXISTS");
 write(f,{schema:SCHEMA,revision:0,commits:[],rejections:[]});
})}
function apply(dir,request){
 if(!exact(request,["effect_id","writer","epoch","nonce","payload_sha256","now"]))fail("BAD_EFFECT_REQUEST");
 const {effect_id,writer,epoch,nonce,payload_sha256,now}=request;
 if(!ID.test(effect_id)||!ID.test(writer)||!Number.isSafeInteger(epoch)||epoch<1||
 !H.test(nonce)||!H.test(payload_sha256)||!Number.isSafeInteger(now)||now<0)fail("BAD_EFFECT_REQUEST");
 return lock(dir,()=>{
  const c=readCanon(dir),e=readEffects(dir);
  let reason=null;
  if(now<c.last_now)reason="DESTINATION_CLOCK_ROLLBACK";
  else if(c.writer===null||now>=c.lease_until)reason="DESTINATION_LEASE_EXPIRED";
  else if(epoch!==c.epoch)reason="DESTINATION_STALE_EPOCH";
  else if(writer!==c.writer)reason="DESTINATION_WRONG_WRITER";
  else if(!c.issued.some(x=>x.nonce===nonce&&x.epoch===epoch&&x.writer===writer))reason="DESTINATION_NONCE_UNISSUED";
  else if(e.commits.some(x=>x.effect_id===effect_id||x.nonce===nonce))reason="DESTINATION_DUPLICATE_EFFECT";
  else if(e.commits.length>=MAX)reason="DESTINATION_CAPACITY_HOLD";
  if(e.rejections.length>=MAX)fail("REJECTION_AUDIT_CAPACITY_HOLD");
  if(reason)e.rejections.push({effect_id,reason,epoch,writer,at:now});
  else e.commits.push({effect_id,nonce,epoch,writer,payload_sha256,at:now});
  e.revision++;
  write(path.join(dir,"effects.json"),e);
  if(reason)fail(reason);
  return {schema:"sapphon-114-local-effect-v1",decision:"TEST_EFFECT_COMMITTED",
   effect_id,epoch,writer,physical_effect:false,utc_authority:false};
 });
}
function inspect(dir){return lock(dir,()=>({canonical:readCanon(dir),effects:readEffects(dir)}))}
module.exports={init,apply,inspect};
