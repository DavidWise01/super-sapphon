"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {signForTest:signMessage}=require("./sapphon_116_outbox_inbox.cjs");
const {init:receiverInit,deliver,inspect:receiverInspect}=require("./sapphon_117_transaction.cjs");
const {signForTest,initialize,propose,publish,compare,inspect,verifySigned}=require("./sapphon_118_anchor.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon118-")),receiver=path.join(root,"receiver"),anchor=path.join(root,"local-anchor");
const signer=crypto.generateKeyPairSync("ed25519"),forger=crypto.generateKeyPairSync("ed25519"),sender=crypto.generateKeyPairSync("ed25519");
const registry={"test-anchorer":{publicKey:signer.publicKey,custody_root:"one-controlled-root",revoked:false}};
const enrollment={anchor_id:"test-anchorer",custody_root:"one-controlled-root",receiver_id:"receiver-one"};
const sendRegistry={"sender-one":{publicKey:sender.publicKey}};
function message(i){return signMessage({schema:"sapphon-116-message-v1",message_id:"message-"+i,effect_id:"effect-"+i,
 sender_id:"sender-one",writer:"writer-alpha",epoch:2,
 nonce:(i==="one"?"a":"b").repeat(64),payload_sha256:(i==="one"?"c":"d").repeat(64)},sender.privateKey)}
let n=0;const check=(name,cb)=>{cb();console.log("PASS",++n,name)},reject=(name,fn,code)=>check(name,()=>assert.throws(fn,e=>e.message===code));
const file=()=>path.join(receiver,"transaction.json"),snapshot=()=>fs.readFileSync(file());
try{
 receiverInit(receiver);initialize(anchor);
 reject("local anchor cannot silently reset",()=>initialize(anchor),"ANCHOR_EXISTS");
 reject("receiver cannot assert authority before checkpoint",()=>compare(receiver,anchor,registry),"ANCHOR_NOT_ESTABLISHED");
 const genesis=signForTest(propose(receiver,anchor,enrollment),signer.privateKey);
 check("genesis state checkpoint binds empty receiver",()=>assert.equal(publish(anchor,genesis,registry).revision,0));
 check("genesis checkpoint verifies current receiver",()=>assert.equal(compare(receiver,anchor,registry).receiver_revision,0));
 check("same signed checkpoint has idempotent publication",()=>assert.equal(publish(anchor,genesis,registry).decision,"ALREADY_ANCHORED"));
 const empty=snapshot();
 deliver(receiver,message("one"),sendRegistry);
 reject("unanchored receiver advance remains HOLD",()=>compare(receiver,anchor,registry),"UNANCHORED_RECEIVER_ADVANCE");
 const one=signForTest(propose(receiver,anchor,enrollment),signer.privateKey);
 check("first post-genesis checkpoint advances revision monotonically",()=>assert.equal(publish(anchor,one,registry).revision,1));
 check("current receiver passes signed checkpoint digest",()=>assert.equal(compare(receiver,anchor,registry).state_verified_against_synthetic_anchor,true));
 reject("older but internally consistent receiver snapshot is detected",()=>{
  const live=snapshot();try{fs.writeFileSync(file(),empty);compare(receiver,anchor,registry)}
  finally{fs.writeFileSync(file(),live)}
 },"RECEIVER_ROLLBACK_DETECTED");
 reject("tampered state with same revision is detected",()=>{
  const live=snapshot();try{const d=JSON.parse(live);d.records[0].payload_sha256="e".repeat(64);d.effects[0].payload_sha256="e".repeat(64);
   fs.writeFileSync(file(),JSON.stringify(d));compare(receiver,anchor,registry)}
  finally{fs.writeFileSync(file(),live)}
 },"RECEIVER_STATE_CONFLICT");
 reject("signed checkpoint cannot be forged with another key",()=>{
  const p=propose(receiver,anchor,enrollment);publish(anchor,signForTest(p,forger.privateKey),registry)
 },"CHECKPOINT_SIGNATURE");
 reject("unknown checkpoint signer fails closed",()=>publish(anchor,one,{}),"UNKNOWN_ANCHOR");
 reject("revoked checkpoint signer fails closed",()=>publish(anchor,one,{"test-anchorer":{...registry["test-anchorer"],revoked:true}}),"REVOKED_ANCHOR");
 reject("mismatched declared custody root rejected",()=>publish(anchor,one,{"test-anchorer":{...registry["test-anchorer"],custody_root:"different-root"}}),"ANCHOR_ROOT_MISMATCH");
 reject("republication of older checkpoint after advance rejected",()=>publish(anchor,genesis,registry),"STALE_OR_FORKED_CHECKPOINT");
 reject("checkpoint with wrong previous-link hash rejected",()=>{
  const p={...propose(receiver,anchor,enrollment),revision:2,previous_checkpoint_sha256:"f".repeat(64)};
  publish(anchor,signForTest(p,signer.privateKey),registry);
 },"STALE_OR_FORKED_CHECKPOINT");
 reject("checkpoint with retrograde revision is rejected",()=>{
  const p={...propose(receiver,anchor,enrollment),revision:0};
  publish(anchor,signForTest(p,signer.privateKey),registry);
 },"STALE_OR_FORKED_CHECKPOINT");
 deliver(receiver,message("two"),sendRegistry);
 const two=signForTest(propose(receiver,anchor,enrollment),signer.privateKey);
 reject("simulated lost acknowledgement after persisted anchor",()=>publish(anchor,two,registry,{fault:"AFTER_STORE"}),"INJECTED_ANCHOR_REPLY_LOSS");
 check("retry of lost acknowledgement recognizes same durable checkpoint",()=>assert.equal(publish(anchor,two,registry).decision,"ALREADY_ANCHORED"));
 check("second checkpoint verifies receiver revision two",()=>{
  const x=compare(receiver,anchor,registry);assert.equal(x.receiver_revision,2);assert.equal(x.checkpoint_entries,3);
 });
 reject("fabricated UTC claim excluded from signed checkpoint",()=>signForTest({...two.payload,utc_authority:true},signer.privateKey),"CHECKPOINT_FIELDS");
 reject("checkpoints absent a valid anchor store fail closed",()=>compare(receiver,path.join(root,"missing"),registry),"ANCHOR_DIRECTORY_MISSING");
 reject("exclusive anchor lock blocks concurrent writes",()=>{
  fs.mkdirSync(path.join(anchor,"lock"));try{inspect(anchor)}finally{fs.rmdirSync(path.join(anchor,"lock"))}
 },"ANCHOR_LOCKED");
 reject("corrupted anchor file fails closed",()=>{
  const f=path.join(anchor,"anchor.json"),prior=fs.readFileSync(f);
  try{fs.writeFileSync(f,"{bad");inspect(anchor)}finally{fs.writeFileSync(f,prior)}
 },"ANCHOR_UNREADABLE");
 reject("altered checkpoint chain fails closed",()=>{
  const f=path.join(anchor,"anchor.json"),prior=fs.readFileSync(f);
  try{const d=JSON.parse(prior);d.entries[1].checkpoint_sha256="e".repeat(64);
   fs.writeFileSync(f,JSON.stringify(d));inspect(anchor)}
  finally{fs.writeFileSync(f,prior)}
 },"ANCHOR_CORRUPT");
 reject("missing checkpoint entry with unchanged generation fails closed",()=>{
  const f=path.join(anchor,"anchor.json"),prior=fs.readFileSync(f);
  try{const d=JSON.parse(prior);d.entries.pop();fs.writeFileSync(f,JSON.stringify(d));inspect(anchor)}
  finally{fs.writeFileSync(f,prior)}
 },"ANCHOR_CORRUPT");
 check("consistent rollback of both local receiver and checkpoint remains undetectable without outside state",()=>{
  const rf=file(),af=path.join(anchor,"anchor.json"),rprior=fs.readFileSync(rf),aprior=fs.readFileSync(af);
  try{
   fs.writeFileSync(rf,empty);
   const d=JSON.parse(aprior);d.entries=[d.entries[0]];d.generation=1;
   fs.writeFileSync(af,JSON.stringify(d));
   const out=compare(receiver,anchor,registry);
   assert.equal(out.receiver_revision,0);assert.equal(out.independently_retained,false);
  }finally{fs.writeFileSync(rf,rprior);fs.writeFileSync(af,aprior)}
 });
 check("full signed chain remains intact after negative tests",()=>assert.equal(inspect(anchor).entries.length,3));
 console.log("SAPPHON-118:",n,"monotonic checkpoint and anti-rollback checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
