"use strict";
/* SAPPHON-118: synthetic monotonic checkpoint held in separate local directory.
 * A provisioned Ed25519 root signs a receiver revision and digest. Detects
 * rollback relative to a trusted checkpoint, not compromise of both stores.
 * No remote custodian, hardware monotonic counter, external TLS or UTC claim.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {inspect:inspectReceiver}=require("./sapphon_117_transaction.cjs");
const H=/^[0-9a-f]{64}$/,ID=/^[a-z0-9-]{4,64}$/,MAX=1024;
const fail=s=>{throw Error(s)};
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const F=["schema","anchor_id","custody_root","receiver_id","revision","state_sha256","previous_checkpoint_sha256","mode"];
function canonical(p){
 if(!exact(p,F)||p.schema!=="sapphon-118-checkpoint-v1"||
 ![p.anchor_id,p.custody_root,p.receiver_id].every(x=>typeof x==="string"&&ID.test(x))||
 !Number.isSafeInteger(p.revision)||p.revision<0||
 !H.test(p.state_sha256)||(p.previous_checkpoint_sha256!==null&&!H.test(p.previous_checkpoint_sha256))||
 p.mode!=="synthetic-local-anchor")fail("CHECKPOINT_FIELDS");
 return Buffer.from(JSON.stringify(F.map(k=>p[k])),"utf8");
}
function signForTest(p,key){return {payload:p,signature:crypto.sign(null,canonical(p),key).toString("base64")}}
function verifySigned(r,registry){
 if(!exact(r,["payload","signature"]))fail("CHECKPOINT_ENVELOPE");
 const raw=canonical(r.payload),p=r.payload;
 if(!registry||!Object.hasOwn(registry,p.anchor_id))fail("UNKNOWN_ANCHOR");
 const root=registry[p.anchor_id];
 if(root.revoked===true)fail("REVOKED_ANCHOR");
 if(root.custody_root!==p.custody_root||!root.publicKey)fail("ANCHOR_ROOT_MISMATCH");
 if(typeof r.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(r.signature)||
 !crypto.verify(null,raw,root.publicKey,Buffer.from(r.signature,"base64")))
  fail("CHECKPOINT_SIGNATURE");
 return sha(raw);
}
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("ANCHOR_DIRECTORY_MISSING");
 const l=path.join(dir,"lock");try{fs.mkdirSync(l)}catch{fail("ANCHOR_LOCKED")}
 try{return fn()}finally{fs.rmdirSync(l)}
}
function read(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"anchor.json"),"utf8"))}
 catch{fail("ANCHOR_UNREADABLE")}
 if(!exact(d,["schema","generation","entries"])||d.schema!=="sapphon-118-anchor-store-v1"||
 !Number.isSafeInteger(d.generation)||d.generation<0||
 !Array.isArray(d.entries)||d.entries.length>MAX||d.generation!==d.entries.length)fail("ANCHOR_CORRUPT");
 let prev=null,rev=-1;
 for(const e of d.entries){
  if(!exact(e,["checkpoint","checkpoint_sha256"]))fail("ANCHOR_CORRUPT");
  let raw;try{raw=canonical(e.checkpoint.payload)}catch{fail("ANCHOR_CORRUPT")}
  if(!H.test(e.checkpoint_sha256)||sha(raw)!==e.checkpoint_sha256||
    e.checkpoint.payload.revision<=rev||
    e.checkpoint.payload.previous_checkpoint_sha256!==prev)fail("ANCHOR_CORRUPT");
  if(!exact(e.checkpoint,["payload","signature"])||
     typeof e.checkpoint.signature!=="string")fail("ANCHOR_CORRUPT");
  prev=e.checkpoint_sha256;rev=e.checkpoint.payload.revision;
 }
 return d;
}
function write(dir,d){
 const dest=path.join(dir,"anchor.json"),tmp=path.join(dir,".anchor-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,dest);
  const parent=fs.openSync(dir,"r");try{fs.fsyncSync(parent)}finally{fs.closeSync(parent)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("ANCHOR_WRITE_FAILED")}
}
function initialize(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 return lock(dir,()=>{
  if(fs.existsSync(path.join(dir,"anchor.json")))fail("ANCHOR_EXISTS");
  write(dir,{schema:"sapphon-118-anchor-store-v1",generation:0,entries:[]});
 });
}
function stateFingerprint(state){
 if(!state||state.schema!=="sapphon-117-transactional-receiver-v1"||
 !Number.isSafeInteger(state.revision)||state.revision<0)fail("RECEIVER_INVALID");
 return sha(Buffer.from(JSON.stringify(state)));
}
function propose(receiverDir,anchorDir,identity){
 if(!identity||![identity.anchor_id,identity.custody_root,identity.receiver_id].every(x=>typeof x==="string"&&ID.test(x)))
 fail("IDENTITY_INVALID");
 const state=inspectReceiver(receiverDir),digest=stateFingerprint(state),d=inspect(anchorDir);
 const last=d.entries.at(-1);
 return {schema:"sapphon-118-checkpoint-v1",...identity,
 revision:state.revision,state_sha256:digest,
 previous_checkpoint_sha256:last?last.checkpoint_sha256:null,mode:"synthetic-local-anchor"};
}
function publish(anchorDir,signed,registry,{fault=null}={}){
 if(![null,"AFTER_STORE"].includes(fault))fail("FAULT_MODE");
 const digest=verifySigned(signed,registry),p=signed.payload;
 return lock(anchorDir,()=>{
  const d=read(anchorDir),latest=d.entries.at(-1);
  if(latest&&latest.checkpoint_sha256===digest)return {decision:"ALREADY_ANCHORED",revision:p.revision};
  if(d.entries.length>=MAX)fail("ANCHOR_CAPACITY_HOLD");
  if((latest&&p.revision<=latest.checkpoint.payload.revision)||
    (latest&&p.previous_checkpoint_sha256!==latest.checkpoint_sha256)||
    (!latest&&p.previous_checkpoint_sha256!==null))fail("STALE_OR_FORKED_CHECKPOINT");
  d.entries.push({checkpoint:signed,checkpoint_sha256:digest});
  d.generation++;write(anchorDir,d);
  if(fault==="AFTER_STORE")fail("INJECTED_ANCHOR_REPLY_LOSS");
  return {decision:"CHECKPOINT_STORED",revision:p.revision,independent_custody:false};
 });
}
function compare(receiverDir,anchorDir,registry){
 const state=inspectReceiver(receiverDir),digest=stateFingerprint(state);
 return lock(anchorDir,()=>{
  const d=read(anchorDir);
  if(d.entries.length===0)fail("ANCHOR_NOT_ESTABLISHED");
  for(const e of d.entries)if(verifySigned(e.checkpoint,registry)!==e.checkpoint_sha256)fail("ANCHOR_SIGNATURE_INVALID");
  const current=d.entries.at(-1).checkpoint.payload;
  if(state.revision<current.revision)fail("RECEIVER_ROLLBACK_DETECTED");
  if(state.revision===current.revision&&digest!==current.state_sha256)fail("RECEIVER_STATE_CONFLICT");
  if(state.revision>current.revision)fail("UNANCHORED_RECEIVER_ADVANCE");
  return {schema:"sapphon-118-anti-rollback-v1",decision:"HOLD",
   state_verified_against_synthetic_anchor:true,receiver_revision:state.revision,
   anchor_revision:current.revision,checkpoint_entries:d.entries.length,
   independently_retained:false,physical_clock_qualified:false,utc_authority:false};
 });
}
function inspect(dir){return lock(dir,()=>read(dir))}
module.exports={canonical,signForTest,verifySigned,initialize,propose,publish,compare,inspect};
