"use strict";
/* SAPPHON-119 — explicit receiver-to-checkpoint handshake.
 * The receiver commit, handshake journal, and synthetic checkpoint store are
 * THREE local transactions. Recovery does not claim an atomic distributed commit.
 * Nothing becomes externally finalized; real custody and UTC stay HOLD.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {deliver:receiverDeliver,inspect:receiverInspect}=require("./sapphon_117_transaction.cjs");
const anchor=require("./sapphon_118_anchor.cjs");
const SCHEMA="sapphon-119-handshake-v1",MAX=1024,H=/^[0-9a-f]{64}$/;
const fail=x=>{throw Error(x)};
const sha=x=>crypto.createHash("sha256").update(x).digest("hex");
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
function stateHash(s){return sha(Buffer.from(JSON.stringify(s)))}
function locked(dir,fn){
 if(!fs.existsSync(dir))fail("HANDSHAKE_MISSING");
 const lock=path.join(dir,"lock");try{fs.mkdirSync(lock)}catch{fail("HANDSHAKE_LOCKED")}
 try{return fn()}finally{fs.rmdirSync(lock)}
}
function read(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"handshake.json"),"utf8"))}catch{fail("HANDSHAKE_UNREADABLE")}
 if(!exact(d,["schema","revision","records"])||d.schema!==SCHEMA||
 !Number.isSafeInteger(d.revision)||d.revision<0||!Array.isArray(d.records)||d.records.length>MAX)fail("HANDSHAKE_CORRUPT");
 let revision=0;
 for(const r of d.records){
  if(!exact(r,["receiver_revision","receiver_state_sha256","status","checkpoint_sha256"])||
  !Number.isSafeInteger(r.receiver_revision)||r.receiver_revision<=revision||
  !H.test(r.receiver_state_sha256)||
  !["PENDING_ANCHOR","LOCAL_ANCHOR_CONFIRMED"].includes(r.status)||
  ((r.status==="PENDING_ANCHOR")!==(r.checkpoint_sha256===null))||
  (r.checkpoint_sha256!==null&&!H.test(r.checkpoint_sha256)))fail("HANDSHAKE_CORRUPT");
  revision=r.receiver_revision;
 }
 return d;
}
function write(dir,d){
 const target=path.join(dir,"handshake.json"),temp=path.join(dir,".handshake-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(temp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(temp,target);
  const parent=fs.openSync(dir,"r");try{fs.fsyncSync(parent)}finally{fs.closeSync(parent)}
 }catch{try{fs.unlinkSync(temp)}catch{}fail("HANDSHAKE_WRITE_FAILED")}
}
function init(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 locked(dir,()=>{if(fs.existsSync(path.join(dir,"handshake.json")))fail("HANDSHAKE_EXISTS");
 write(dir,{schema:SCHEMA,revision:0,records:[]})});
}
function track(dir,state){
 if(state.revision<1)fail("NO_RECEIVER_EFFECT");
 const digest=stateHash(state);
 return locked(dir,()=>{
  const d=read(dir),found=d.records.find(r=>r.receiver_revision===state.revision);
  if(found){
   if(found.receiver_state_sha256!==digest)fail("PENDING_STATE_CONFLICT");
   return {revision:state.revision,status:found.status,recovered:true};
  }
  if(d.records.some(r=>r.receiver_revision>state.revision))fail("HANDSHAKE_ROLLBACK");
  if(d.records.length>=MAX)fail("HANDSHAKE_CAPACITY");
  d.records.push({receiver_revision:state.revision,receiver_state_sha256:digest,
   status:"PENDING_ANCHOR",checkpoint_sha256:null});
  d.revision++;write(dir,d);
  return {revision:state.revision,status:"PENDING_ANCHOR",recovered:false};
 });
}
function receive(receiverDir,handshakeDir,msg,senderRegistry,{fault=null}={}){
 if(![null,"AFTER_RECEIVER_COMMIT","AFTER_TRACK"].includes(fault))fail("FAULT_MODE");
 const receipt=receiverDeliver(receiverDir,msg,senderRegistry);
 if(fault==="AFTER_RECEIVER_COMMIT")fail("INJECTED_RECEIVER_HANDSHAKE_GAP");
 const current=track(handshakeDir,receiverInspect(receiverDir));
 if(fault==="AFTER_TRACK")fail("INJECTED_HANDSHAKE_ACK_LOSS");
 return {receipt,handshake:current,external_finalized:false};
}
function status(receiverDir,anchorDir,handshakeDir,anchorRegistry){
 const current=receiverInspect(receiverDir),digest=stateHash(current);
 const pending=locked(handshakeDir,()=>read(handshakeDir));
 const match=pending.records.find(r=>r.receiver_revision===current.revision);
 if(!match||match.receiver_state_sha256!==digest)return {status:"PENDING_ANCHOR",reason:"UNRECORDED_RECEIVER_COMMIT",
  external_finalized:false,decision:"HOLD"};
 try{
  const check=anchor.compare(receiverDir,anchorDir,anchorRegistry);
  if(check.receiver_revision!==current.revision)fail("ANCHOR_REVISION_MISMATCH");
  return {status:"LOCAL_ANCHOR_CONFIRMED",receiver_revision:current.revision,
   checkpoint_entries:check.checkpoint_entries,external_finalized:false,
   independent_custody:false,decision:"HOLD"};
 }catch(e){
  return {status:"PENDING_ANCHOR",reason:e.message,receiver_revision:current.revision,
   external_finalized:false,decision:"HOLD"};
 }
}
function reconcile(receiverDir,anchorDir,handshakeDir,anchorRegistry){
 const state=receiverInspect(receiverDir);
 const pending=track(handshakeDir,state);
 const checked=status(receiverDir,anchorDir,handshakeDir,anchorRegistry);
 if(checked.status==="LOCAL_ANCHOR_CONFIRMED"){
  const anchorState=anchor.inspect(anchorDir),last=anchorState.entries.at(-1);
  locked(handshakeDir,()=>{
   const d=read(handshakeDir),r=d.records.find(x=>x.receiver_revision===state.revision);
   if(!r||r.receiver_state_sha256!==stateHash(state))fail("HANDSHAKE_STATE_CHANGED");
   if(r.status!=="LOCAL_ANCHOR_CONFIRMED"){
    r.status="LOCAL_ANCHOR_CONFIRMED";r.checkpoint_sha256=last.checkpoint_sha256;
    d.revision++;write(handshakeDir,d);
   }else if(r.checkpoint_sha256!==last.checkpoint_sha256)fail("HANDSHAKE_ANCHOR_CONFLICT");
  });
 }
 return {...checked,recovered_pending_record:pending.recovered};
}
function publishCheckpoint(receiverDir,anchorDir,handshakeDir,identity,key,registry,{fault=null}={}){
 if(![null,"BEFORE_PUBLISH","AFTER_PUBLISH"].includes(fault))fail("FAULT_MODE");
 const s=receiverInspect(receiverDir),d=locked(handshakeDir,()=>read(handshakeDir));
 const tracked=d.records.find(r=>r.receiver_revision===s.revision);
 if(!tracked||tracked.receiver_state_sha256!==stateHash(s))fail("UNTRACKED_RECEIVER_COMMIT");
 if(tracked.status==="LOCAL_ANCHOR_CONFIRMED")
  return reconcile(receiverDir,anchorDir,handshakeDir,registry);
 const packet=anchor.signForTest(anchor.propose(receiverDir,anchorDir,identity),key);
 if(fault==="BEFORE_PUBLISH")fail("INJECTED_BEFORE_CHECKPOINT_PUBLISH");
 anchor.publish(anchorDir,packet,registry);
 if(fault==="AFTER_PUBLISH")fail("INJECTED_CHECKPOINT_ACK_LOSS");
 return reconcile(receiverDir,anchorDir,handshakeDir,registry);
}
function inspect(dir){return locked(dir,()=>read(dir))}
module.exports={init,receive,reconcile,publishCheckpoint,status,inspect};
