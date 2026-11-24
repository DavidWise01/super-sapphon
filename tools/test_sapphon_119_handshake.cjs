"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {signForTest:signMessage}=require("./sapphon_116_outbox_inbox.cjs");
const {init:receiverInit,inspect:receiverInspect}=require("./sapphon_117_transaction.cjs");
const anchor=require("./sapphon_118_anchor.cjs"),h=require("./sapphon_119_handshake.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon119-"));
const rec=path.join(root,"receiver"),anc=path.join(root,"anchor"),hand=path.join(root,"handshake");
const kp=crypto.generateKeyPairSync("ed25519"),actor=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519");
const keys={"sender-one":{publicKey:actor.publicKey}};
const anchors={"anchor-one":{publicKey:kp.publicKey,custody_root:"one-owned-root"}};
const id={anchor_id:"anchor-one",custody_root:"one-owned-root",receiver_id:"receiver-one"};
const msg=(num)=>signMessage({schema:"sapphon-116-message-v1",message_id:"message-"+num,effect_id:"effect-"+num,
 sender_id:"sender-one",writer:"writer-alpha",epoch:2,nonce:(num===1?"a":"b").repeat(64),
 payload_sha256:(num===1?"c":"d").repeat(64)},actor.privateKey);
let n=0;function check(name,fn){fn();console.log("PASS",++n,name)}
function reject(name,fn,code){check(name,()=>assert.throws(fn,e=>e.message===code))}
const snapshots=()=>({receiver:fs.readFileSync(path.join(rec,"transaction.json")),anchor:fs.readFileSync(path.join(anc,"anchor.json"))});
try{
 receiverInit(rec);anchor.initialize(anc);h.init(hand);
 const genesis=anchor.signForTest(anchor.propose(rec,anc,id),kp.privateKey);anchor.publish(anc,genesis,anchors);
 check("genesis checkpoint is pre-established while handshake records none",()=>{
  assert.equal(h.inspect(hand).records.length,0);assert.equal(anchor.compare(rec,anc,anchors).receiver_revision,0);
 });
 reject("handshake journal cannot be silently initialized twice",()=>h.init(hand),"HANDSHAKE_EXISTS");
 check("untracked receiver may not be called externally finalized",()=>{
  const s=h.status(rec,anc,hand,anchors);assert.equal(s.status,"PENDING_ANCHOR");assert.equal(s.external_finalized,false);
 });
 const empty=snapshots();
 reject("crash after receiver commit before handshake journal write",()=>h.receive(rec,hand,msg(1),keys,{fault:"AFTER_RECEIVER_COMMIT"}),"INJECTED_RECEIVER_HANDSHAKE_GAP");
 check("receiver committed one effect, handshake record still missing",()=>{
  assert.equal(receiverInspect(rec).revision,1);assert.equal(h.inspect(hand).records.length,0);
 });
 check("reconciliation exposes untracked receiver commitment as PENDING_ANCHOR",()=>{
  const x=h.status(rec,anc,hand,anchors);assert.equal(x.reason,"UNRECORDED_RECEIVER_COMMIT");
 });
 check("restart reconstruction creates pending record without external authority",()=>{
  const x=require("./sapphon_119_handshake.cjs").reconcile(rec,anc,hand,anchors);
  assert.equal(x.status,"PENDING_ANCHOR");assert.equal(h.inspect(hand).records[0].status,"PENDING_ANCHOR");
 });
 reject("checkpoint publication interrupted before persistent anchor",()=>h.publishCheckpoint(rec,anc,hand,id,kp.privateKey,anchors,{fault:"BEFORE_PUBLISH"}),"INJECTED_BEFORE_CHECKPOINT_PUBLISH");
 check("failure before publish leaves receiver unanchored",()=>{
  assert.equal(h.status(rec,anc,hand,anchors).status,"PENDING_ANCHOR");assert.equal(anchor.inspect(anc).entries.length,1);
 });
 check("signed checkpoint publication and reconciliation confirms LOCAL only",()=>{
  const x=h.publishCheckpoint(rec,anc,hand,id,kp.privateKey,anchors);
  assert.equal(x.status,"LOCAL_ANCHOR_CONFIRMED");assert.equal(x.external_finalized,false);
 });
 check("confirming identical local checkpoint is idempotent",()=>{
  const x=h.publishCheckpoint(rec,anc,hand,id,kp.privateKey,anchors);assert.equal(x.status,"LOCAL_ANCHOR_CONFIRMED");
  assert.equal(anchor.inspect(anc).entries.length,2);
 });
 check("retransmitted signed message does not add new receiver effect",()=>{
  const x=h.receive(rec,hand,msg(1),keys);assert.equal(x.receipt.duplicate,true);
  assert.equal(receiverInspect(rec).records.length,1);
 });
 reject("second receive loses handshake acknowledgement after tracking",()=>h.receive(rec,hand,msg(2),keys,{fault:"AFTER_TRACK"}),"INJECTED_HANDSHAKE_ACK_LOSS");
 check("second receiver effect is pending, never external finalized",()=>{
  assert.equal(h.status(rec,anc,hand,anchors).status,"PENDING_ANCHOR");
  assert.equal(h.inspect(hand).records[1].status,"PENDING_ANCHOR");
 });
 reject("checkpoint commits but acknowledgement is lost",()=>h.publishCheckpoint(rec,anc,hand,id,kp.privateKey,anchors,{fault:"AFTER_PUBLISH"}),"INJECTED_CHECKPOINT_ACK_LOSS");
 check("anchor persisted revision two while handshake awaits acknowledgement",()=>{
  assert.equal(anchor.inspect(anc).entries.at(-1).checkpoint.payload.revision,2);
  assert.equal(h.inspect(hand).records[1].status,"PENDING_ANCHOR");
 });
 check("restart reconciles lost acknowledgement without republishing checkpoint",()=>{
  const result=h.reconcile(rec,anc,hand,anchors);
  assert.equal(result.status,"LOCAL_ANCHOR_CONFIRMED");
  assert.equal(anchor.inspect(anc).entries.length,3);
 });
 check("confirmed local anchor still cannot claim independent custody or UTC",()=>{
  const x=h.status(rec,anc,hand,anchors);assert.equal(x.external_finalized,false);
  assert.equal(x.independent_custody,false);assert.equal(x.decision,"HOLD");
 });
 reject("wrong signing key cannot publish valid new checkpoint",()=>{
  const signed=anchor.signForTest({...anchor.propose(rec,anc,id),revision:3},rogue.privateKey);
  anchor.publish(anc,signed,anchors);
 },"CHECKPOINT_SIGNATURE");
 reject("invalid injection mode rejected",()=>h.receive(rec,hand,msg(1),keys,{fault:"EXTERNAL_CERTIFIED"}),"FAULT_MODE");
 reject("frozen absent handshake journal fails closed",()=>h.inspect(path.join(root,"missing")),"HANDSHAKE_MISSING");
 reject("exclusive local handshake lock blocks reconciliation",()=>{
  fs.mkdirSync(path.join(hand,"lock"));try{h.reconcile(rec,anc,hand,anchors)}finally{fs.rmdirSync(path.join(hand,"lock"))}
 },"HANDSHAKE_LOCKED");
 reject("corrupted handshake journal is rejected",()=>{
  const f=path.join(hand,"handshake.json"),prev=fs.readFileSync(f);
  try{fs.writeFileSync(f,"{bad");h.inspect(hand)}finally{fs.writeFileSync(f,prev)}
 },"HANDSHAKE_UNREADABLE");
 reject("forged external authority field in handshake rejected",()=>{
  const f=path.join(hand,"handshake.json"),prev=fs.readFileSync(f);
  try{const d=JSON.parse(prev);d.externally_finalized=true;fs.writeFileSync(f,JSON.stringify(d));h.inspect(hand)}
  finally{fs.writeFileSync(f,prev)}
 },"HANDSHAKE_CORRUPT");
 reject("broken confirmed state missing digest fails closed",()=>{
  const f=path.join(hand,"handshake.json"),prev=fs.readFileSync(f);
  try{const d=JSON.parse(prev);d.records[1].checkpoint_sha256=null;fs.writeFileSync(f,JSON.stringify(d));h.inspect(hand)}
  finally{fs.writeFileSync(f,prev)}
 },"HANDSHAKE_CORRUPT");
 check("receiver-only rollback remains detected while anchor persists",()=>{
  const f=path.join(rec,"transaction.json"),live=fs.readFileSync(f);
  try{fs.writeFileSync(f,empty.receiver);
   const x=h.status(rec,anc,hand,anchors);assert.equal(x.status,"PENDING_ANCHOR");
  }finally{fs.writeFileSync(f,live)}
 });
 check("complete local joint rollback is undetectable absent outside monotonic authority",()=>{
  const rf=path.join(rec,"transaction.json"),af=path.join(anc,"anchor.json");
  const original=snapshots(),old=JSON.parse(empty.anchor);
  try{
   fs.writeFileSync(rf,empty.receiver);fs.writeFileSync(af,JSON.stringify(old));
   const x=anchor.compare(rec,anc,anchors);assert.equal(x.receiver_revision,0);
  }finally{fs.writeFileSync(rf,original.receiver);fs.writeFileSync(af,original.anchor)}
 });
 check("all checkpoint records are locally chained and handshake has two confirmed effects",()=>{
  assert.equal(anchor.inspect(anc).entries.length,3);
  assert.equal(h.inspect(hand).records.filter(x=>x.status==="LOCAL_ANCHOR_CONFIRMED").length,2);
 });
 console.log("SAPPHON-119:",n,"cross-store checkpoint handshake and interrupted acknowledgement tests passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
