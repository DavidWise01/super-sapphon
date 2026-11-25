"use strict";
/* SAPPHON-125: simulated signed revocation publisher and lagging replica.
 * No actual network, offsite custody, reliable wall clock or real authority.
 * A connected high-water reference is REQUIRED at every permission check.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const ID=/^[a-z0-9-]{4,64}$/,H=/^[0-9a-f]{64}$/;
const fail=s=>{throw Error(s)};
const hash=v=>crypto.createHash("sha256").update(v).digest("hex");
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const F=["schema","publisher_id","control_root","generation","issuer_generation","operator_generation","issuer_revoked","operator_revoked","previous_digest","mode"];
function bytes(p){
 if(!exact(p,F)||p.schema!=="sapphon-125-revocation-snapshot-v1"||
 !ID.test(p.publisher_id)||!ID.test(p.control_root)||
 ![p.generation,p.issuer_generation,p.operator_generation].every(x=>Number.isSafeInteger(x)&&x>0)||
 typeof p.issuer_revoked!=="boolean"||typeof p.operator_revoked!=="boolean"||
 !(p.previous_digest===null||typeof p.previous_digest==="string"&&H.test(p.previous_digest))||
 (p.generation===1)!==(p.previous_digest===null)||
 p.mode!=="synthetic-local-replica")fail("SNAPSHOT_FIELDS");
 return Buffer.from(JSON.stringify(F.map(k=>p[k])),"utf8");
}
function signForTest(p,privateKey){
 return {payload:p,signature:crypto.sign(null,bytes(p),privateKey).toString("base64")};
}
function checkSigned(x,pins){
 if(!exact(x,["payload","signature"]))fail("SNAPSHOT_ENVELOPE");
 const b=bytes(x.payload),p=x.payload;
 if(!pins||!Object.hasOwn(pins,p.publisher_id))fail("PUBLISHER_NOT_PINNED");
 const pin=pins[p.publisher_id];
 if(pin.revoked===true)fail("PUBLISHER_REVOKED");
 if(pin.control_root!==p.control_root||!pin.publicKey)fail("PUBLISHER_IDENTITY");
 if(typeof x.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(x.signature)||
 !crypto.verify(null,b,pin.publicKey,Buffer.from(x.signature,"base64")))fail("SNAPSHOT_SIGNATURE");
 return hash(b);
}
function locked(dir,fn){
 if(!fs.existsSync(dir))fail("REPLICA_MISSING");
 const p=path.join(dir,"lock");
 try{fs.mkdirSync(p)}catch{fail("REPLICA_BUSY")}
 try{return fn()}finally{fs.rmdirSync(p)}
}
const SCHEMA="sapphon-125-replica-v1";
function load(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"replica.json"),"utf8"))}
 catch{fail("REPLICA_UNREADABLE")}
 if(!exact(d,["schema","revision","snapshot","digest","last_authorization_nonce","permission_log"])||
 d.schema!==SCHEMA||!Number.isSafeInteger(d.revision)||d.revision<0||
 !Array.isArray(d.permission_log)||d.permission_log.length>1024||
 !(d.snapshot===null||exact(d.snapshot,["payload","signature"]))||
 !(d.digest===null||typeof d.digest==="string"&&H.test(d.digest))||
 (d.snapshot===null)!==(d.digest===null)||
 !(d.last_authorization_nonce===null||typeof d.last_authorization_nonce==="string"&&H.test(d.last_authorization_nonce)))
 fail("REPLICA_CORRUPT");
 const seen=new Set();
 for(const r of d.permission_log){
  if(!exact(r,["nonce","generation","decision"])||!H.test(r.nonce)||
   !Number.isSafeInteger(r.generation)||r.generation<1||
   r.decision!=="TEST_LOCAL_PERMISSION_ONLY"||seen.has(r.nonce))fail("REPLICA_CORRUPT");
  seen.add(r.nonce);
 }
 if((d.permission_log.at(-1)?.nonce||null)!==d.last_authorization_nonce)fail("REPLICA_CORRUPT");
 return d;
}
function write(dir,d){
 const target=path.join(dir,"replica.json"),tmp=path.join(dir,".replica-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,target);
  const parent=fs.openSync(dir,"r");try{fs.fsyncSync(parent)}finally{fs.closeSync(parent)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("REPLICA_WRITE_FAILED")}
}
function init(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 locked(dir,()=>{
  if(fs.existsSync(path.join(dir,"replica.json")))fail("REPLICA_EXISTS");
  write(dir,{schema:SCHEMA,revision:0,snapshot:null,digest:null,last_authorization_nonce:null,permission_log:[]});
 });
}
function update(dir,signed,pins){
 const digest=checkSigned(signed,pins);
 return locked(dir,()=>{
  const d=load(dir),p=signed.payload,prior=d.snapshot?.payload;
  if(prior&&p.publisher_id!==prior.publisher_id)fail("PUBLISHER_SWITCH");
  if(prior&&p.generation<prior.generation)fail("STALE_REPLICA_UPDATE");
  if(prior&&p.generation===prior.generation){
   if(d.digest!==digest)fail("GENERATION_FORK");
   return {decision:"SAME_SNAPSHOT",generation:p.generation};
  }
  if(prior&&p.generation!==prior.generation+1)fail("SKIPPED_HIGH_WATER_GENERATION");
  if(prior&&p.previous_digest!==d.digest)fail("BROKEN_PREDECESSOR");
  if(prior&&(p.issuer_generation<prior.issuer_generation||p.operator_generation<prior.operator_generation))
   fail("CREDENTIAL_GENERATION_ROLLBACK");
  if(prior&&(prior.issuer_revoked&&!p.issuer_revoked||prior.operator_revoked&&!p.operator_revoked))
   fail("REVOCATION_RESURRECTION");
  if(!prior&&p.generation!==1)fail("MISSING_GENESIS");
  d.snapshot=signed;d.digest=digest;d.revision++;write(dir,d);
  return {decision:"SYNTHETIC_REPLICA_ADVANCED",generation:p.generation};
 });
}
function gate(dir,{highWater,highWaterTrusted,pins,challenge_nonce,issuer_generation,operator_generation}={}){
 if(highWaterTrusted!==true||!highWater)fail("HIGH_WATER_UNAVAILABLE");
 const currentDigest=checkSigned(highWater,pins);
 if(!H.test(challenge_nonce)||![issuer_generation,operator_generation].every(x=>Number.isSafeInteger(x)&&x>0))
  fail("GATE_INPUT_INVALID");
 return locked(dir,()=>{
  const d=load(dir);
  if(!d.snapshot)fail("NO_LOCAL_SNAPSHOT");
  const localDigest=checkSigned(d.snapshot,pins),local=d.snapshot.payload,remote=highWater.payload;
  if(localDigest!==d.digest)fail("LOCAL_DIGEST_CONFLICT");
  if(remote.publisher_id!==local.publisher_id)fail("HIGH_WATER_PUBLISHER_CONFLICT");
  if(remote.generation<local.generation)fail("UNTRUSTED_RETROGRADE_HIGH_WATER");
  if(remote.generation>local.generation)fail("STALE_REPLICA_HOLD");
  if(remote.previous_digest!==local.previous_digest||currentDigest!==localDigest)
   fail("HIGH_WATER_SNAPSHOT_CONFLICT");
  if(remote.issuer_revoked||remote.operator_revoked)fail("CURRENT_ROLE_REVOKED");
  if(local.issuer_generation!==issuer_generation||local.operator_generation!==operator_generation)
   fail("CURRENT_CREDENTIAL_GENERATION_MISMATCH");
  if(d.permission_log.some(x=>x.nonce===challenge_nonce))fail("PERMISSION_NONCE_REPLAY");
  if(d.permission_log.length>=1024)fail("PERMISSION_LOG_CAPACITY_HOLD");
  d.permission_log.push({nonce:challenge_nonce,generation:local.generation,decision:"TEST_LOCAL_PERMISSION_ONLY"});
  d.last_authorization_nonce=challenge_nonce;d.revision++;write(dir,d);
  return {decision:"HOLD",test_local_permission:true,external_authority:false,
   independent_high_water_authenticated:false,utc_authority:false};
 });
}
function inspect(dir){return locked(dir,()=>load(dir))}
module.exports={bytes,signForTest,checkSigned,init,update,gate,inspect};
