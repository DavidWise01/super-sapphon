"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const h=require("./sapphon_119_handshake.cjs"),a=require("./sapphon_118_anchor.cjs");
const {init:receiverInit,inspect:receiverInspect}=require("./sapphon_117_transaction.cjs");
const {signForTest:signMessage}=require("./sapphon_116_outbox_inbox.cjs");
const {evaluate,provePreserved}=require("./sapphon_120_audit.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon120-")),receiver=path.join(root,"receiver"),
 anchorDir=path.join(root,"anchor"),hand=path.join(root,"handshake");
const signer=crypto.generateKeyPairSync("ed25519"),sender=crypto.generateKeyPairSync("ed25519");
const key={anchor_id:"anchor-one",custody_root:"single-controlled-root",receiver_id:"receiver-one"};
const registry={"anchor-one":{publicKey:signer.publicKey,custody_root:key.custody_root}};
const sendRegistry={"sender-one":{publicKey:sender.publicKey}};
const msg=(i)=>signMessage({schema:"sapphon-116-message-v1",message_id:"message-"+i,effect_id:"effect-"+i,
 sender_id:"sender-one",writer:"writer-alpha",epoch:2,nonce:(i===1?"a":"b").repeat(64),
 payload_sha256:(i===1?"c":"d").repeat(64)},sender.privateKey);
const files={receiver:()=>path.join(receiver,"transaction.json"),
 anchor:()=>path.join(anchorDir,"anchor.json"),handshake:()=>path.join(hand,"handshake.json")};
let checks=0;function check(name,f){f();console.log("PASS",++checks,name)}
function reject(name,f,code){check(name,()=>assert.throws(f,e=>e.message===code))}
function audit(){return evaluate(receiver,anchorDir,hand,registry)}
function save(){return Object.fromEntries(Object.entries(files).map(([k,v])=>[k,fs.readFileSync(v())]))}
function restore(state){for(const [k,v] of Object.entries(state))fs.writeFileSync(files[k](),v)}
try{
 receiverInit(receiver);a.initialize(anchorDir);h.init(hand);
 const genesis=a.signForTest(a.propose(receiver,anchorDir,key),signer.privateKey);
 a.publish(anchorDir,genesis,registry);
 check("verified Phase VI-VIII source freeze manifests remain intact",()=>{
  const x=provePreserved(path.resolve(__dirname,".."));assert.equal(x.total_files,98);
 });
 check("genesis carries no external authority",()=>assert.equal(a.compare(receiver,anchorDir,registry).independently_retained,false));
 reject("receiver commit before handshake is an interrupted gap",()=>h.receive(receiver,hand,msg(1),sendRegistry,{fault:"AFTER_RECEIVER_COMMIT"}),"INJECTED_RECEIVER_HANDSHAKE_GAP");
 check("untracked commit discovered by observer audit",()=>{
  const x=audit();assert.equal(x.status,"HOLD_UNRESOLVED");assert.ok(x.observations.includes("UNTRACKED_RECEIVER_REVISION"));
 });
 check("reconcile fills pending record but does not grant external authority",()=>{
  h.reconcile(receiver,anchorDir,hand,registry);assert.ok(audit().observations.includes("PENDING_ANCHOR"));
 });
 reject("before publish checkpoint interruption leaves pending status",()=>h.publishCheckpoint(receiver,anchorDir,hand,key,signer.privateKey,registry,{fault:"BEFORE_PUBLISH"}),"INJECTED_BEFORE_CHECKPOINT_PUBLISH");
 check("checkpoint not published after before-publish fault",()=>assert.equal(a.inspect(anchorDir).entries.length,1));
 check("retry completes the signed local checkpoint",()=>{
  const x=h.publishCheckpoint(receiver,anchorDir,hand,key,signer.privateKey,registry);
  assert.equal(x.status,"LOCAL_ANCHOR_CONFIRMED");assert.equal(x.external_finalized,false);
 });
 check("locally consistent state is HOLD, not global authorization",()=>{
  const x=audit();assert.equal(x.status,"LOCAL_CONSISTENCY_ONLY");assert.equal(x.decision,"HOLD");
  assert.equal(x.external_finalized,false);assert.equal(x.globally_linearizable,false);
 });
 check("synthetic effect count equals receiver inbox count",()=>{
  const d=receiverInspect(receiver);assert.equal(d.effects.length,d.records.length);assert.equal(d.effects.length,1);
 });
 reject("receiver effect accepted while handshake reply is interrupted",()=>h.receive(receiver,hand,msg(2),sendRegistry,{fault:"AFTER_TRACK"}),"INJECTED_HANDSHAKE_ACK_LOSS");
 check("new unanchored receiver revision remains HOLD",()=>{
  const x=audit();assert.ok(x.observations.includes("PENDING_ANCHOR"));
  assert.equal(x.external_finalized,false);
 });
 reject("checkpoint publication succeeds but acknowledgement lost",()=>h.publishCheckpoint(receiver,anchorDir,hand,key,signer.privateKey,registry,{fault:"AFTER_PUBLISH"}),"INJECTED_CHECKPOINT_ACK_LOSS");
 check("observer reports acknowledgement gap until reconciliation",()=>{
  const x=audit();assert.equal(x.status,"HOLD_UNRESOLVED");assert.ok(x.observations.includes("PENDING_ANCHOR"));
 });
 check("reconciliation confirms local anchor without extra checkpoint",()=>{
  const count=a.inspect(anchorDir).entries.length;h.reconcile(receiver,anchorDir,hand,registry);
  assert.equal(a.inspect(anchorDir).entries.length,count);assert.equal(audit().status,"LOCAL_CONSISTENCY_ONLY");
 });
 const good=save();
 check("receiver-only rollback is explicitly detected",()=>{
  const state=JSON.parse(good.receiver);state.records.pop();state.effects.pop();state.revision--;
  fs.writeFileSync(files.receiver(),JSON.stringify(state));
  const x=audit();assert.ok(x.observations.includes("RECEIVER_ROLLBACK"));
  restore(good);
 });
 check("altered receiver effect digest is detected",()=>{
  const state=JSON.parse(good.receiver);
  state.records[0].payload_sha256="f".repeat(64);state.effects[0].payload_sha256="f".repeat(64);
  fs.writeFileSync(files.receiver(),JSON.stringify(state));
  const x=audit();assert.ok(x.observations.includes("RECEIVER_DIGEST_CONFLICT"));
  restore(good);
 });
 check("corrupt local checkpoint fails closed",()=>{
  fs.writeFileSync(files.anchor(),"{broken");
  reject("corrupted checkpoint rejects evaluation",()=>audit(),"ANCHOR_UNREADABLE");
  restore(good);
 });
 check("stale local checkpoint and current receiver hold unanchored state",()=>{
  const anchorState=JSON.parse(good.anchor);anchorState.entries.pop();anchorState.generation--;
  fs.writeFileSync(files.anchor(),JSON.stringify(anchorState));
  assert.ok(audit().observations.includes("UNANCHORED_ADVANCE"));restore(good);
 });
 check("rewritten confirmed handshake link is detected",()=>{
  const state=JSON.parse(good.handshake);
  state.records.at(-1).checkpoint_sha256="f".repeat(64);
  fs.writeFileSync(files.handshake(),JSON.stringify(state));
  const x=audit();assert.ok(x.observations.includes("ACK_LINK_MISMATCH"));restore(good);
 });
 check("joint local rollback remains a counterexample, not independent proof",()=>{
  const recState=JSON.parse(good.receiver),anchorState=JSON.parse(good.anchor);
  recState.records.pop();recState.effects.pop();recState.revision--;
  anchorState.entries.pop();anchorState.generation--;
  fs.writeFileSync(files.receiver(),JSON.stringify(recState));
  fs.writeFileSync(files.anchor(),JSON.stringify(anchorState));
  // Handshake may be rolled back too; the local records still cannot prove
  // that the deleted checkpoint existed without an external high-water mark.
  const handState=JSON.parse(good.handshake);handState.records.pop();handState.revision--;
  fs.writeFileSync(files.handshake(),JSON.stringify(handState));
  const x=audit();assert.equal(x.status,"LOCAL_CONSISTENCY_ONLY");
  assert.equal(x.independent_custody,false);restore(good);
 });
 reject("unavailable canonical handshake fails closed",()=>evaluate(receiver,anchorDir,path.join(root,"missing"),registry),"HANDSHAKE_MISSING");
 reject("missing receiver fails closed",()=>evaluate(path.join(root,"missing"),anchorDir,hand,registry),"RECEIVER_MISSING");
 check("replay still produces exactly two synthetic effects",()=>{
  h.receive(receiver,hand,msg(1),sendRegistry);
  h.receive(receiver,hand,msg(2),sendRegistry);
  assert.equal(receiverInspect(receiver).effects.length,2);
  assert.equal(audit().status,"LOCAL_CONSISTENCY_ONLY");
 });
 check("no authenticated UTC, real outside custody, or physical authority inferred",()=>{
  const x=audit();assert.equal(x.utc_authority,false);
  assert.equal(x.physical_clock_authorized,false);assert.equal(x.independent_custody,false);
 });
 console.log("SAPPHON-120:",checks,"final adversarial recovery and freeze checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
