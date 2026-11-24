"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {signForTest,initialize,queue,deliver,acknowledge,inspect}=require("./sapphon_116_outbox_inbox.cjs");
const key=crypto.generateKeyPairSync("ed25519"),badKey=crypto.generateKeyPairSync("ed25519");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon116-")),out=path.join(root,"sender"),inbox=path.join(root,"receiver");
const p={schema:"sapphon-116-message-v1",message_id:"message-001",effect_id:"effect-001",sender_id:"sender-a",writer:"writer-alpha",
 epoch:2,nonce:"a".repeat(64),payload_sha256:"b".repeat(64)};
const registry={"sender-a":{publicKey:key.publicKey,revoked:false}},msg=signForTest(p,key.privateKey);
let n=0;function check(label,fn){fn();console.log("PASS",++n,label)}
function rejects(label,fn,reason){check(label,()=>assert.throws(fn,e=>e.message===reason))}
try{
 initialize(out,"outbox");initialize(inbox,"inbox");
 check("separate outbox and receiver inbox are empty",()=>{
  assert.equal(inspect(out,"outbox").records.length,0);assert.equal(inspect(inbox,"inbox").records.length,0);
 });
 rejects("existing sender outbox cannot be silently reset",()=>initialize(out,"outbox"),"JOURNAL_EXISTS");
 check("signed sender request is durably queued",()=>assert.equal(queue(out,msg,registry).decision,"QUEUED"));
 check("identical sender retry does not add another outbox entry",()=>{
  assert.equal(queue(out,msg,registry).decision,"ALREADY_QUEUED");
  assert.equal(inspect(out,"outbox").records.length,1);
 });
 rejects("receiver commits, but simulated acknowledgement is lost",()=>deliver(inbox,msg,registry,{fault:"AFTER_RECEIVER_COMMIT"}),"INJECTED_LOST_REPLY");
 check("receiver has durable effect despite sender remaining pending",()=>{
  assert.equal(inspect(inbox,"inbox").records[0].status,"RECEIVED");
  assert.equal(inspect(out,"outbox").records[0].status,"PENDING");
 });
 check("retransmission after lost reply returns original receiver receipt",()=>{
  const x=deliver(inbox,msg,registry);
  assert.equal(x.duplicate,true);assert.equal(inspect(inbox,"inbox").records.length,1);
 });
 const ack=deliver(inbox,msg,registry);
 check("sender acknowledges receiver's prior durable effect",()=>assert.equal(acknowledge(out,msg,registry,ack).decision,"ACKED"));
 check("acknowledgement replay returns same result, no duplicate record",()=>{
  assert.equal(acknowledge(out,msg,registry,ack).decision,"ALREADY_ACKED");
  assert.equal(inspect(inbox,"inbox").records.length,1);
 });
 check("new module after restart reads both durable inbox and outbox",()=>{
  const m=require("./sapphon_116_outbox_inbox.cjs");
  assert.equal(m.inspect(out,"outbox").records[0].status,"ACKED");
  assert.equal(m.inspect(inbox,"inbox").records[0].status,"RECEIVED");
 });
 rejects("new payload under same message ID rejected by receiver",()=>{
  const forged=signForTest({...p,payload_sha256:"c".repeat(64)},key.privateKey);
  deliver(inbox,forged,registry);
 },"RECEIVER_CONFLICT");
 rejects("same nonce with new message and effect ID rejected by receiver",()=>{
  const forged=signForTest({...p,message_id:"message-002",effect_id:"effect-002"},key.privateKey);
  deliver(inbox,forged,registry);
 },"RECEIVER_CONFLICT");
 rejects("same effect under new message and nonce rejected",()=>{
  const forged=signForTest({...p,message_id:"message-003",nonce:"c".repeat(64)},key.privateKey);
  deliver(inbox,forged,registry);
 },"RECEIVER_CONFLICT");
 rejects("conflicting sender outbox payload rejected",()=>{
  const forged=signForTest({...p,payload_sha256:"c".repeat(64)},key.privateKey);
  queue(out,forged,registry);
 },"OUTBOX_CONFLICT");
 rejects("forged sender signature denied",()=>deliver(inbox,signForTest(p,badKey.privateKey),registry),"MESSAGE_SIGNATURE");
 rejects("revoked sender denied",()=>deliver(inbox,msg,{"sender-a":{...registry["sender-a"],revoked:true}}),"REVOKED_SENDER");
 rejects("unknown sender denied",()=>deliver(inbox,msg,{}),"UNKNOWN_SENDER");
 rejects("tampered signed message identity denied",()=>deliver(inbox,{...msg,payload:{...p,writer:"writer-beta"}},registry),"MESSAGE_SIGNATURE");
 rejects("sender cannot accept fabricated receiver receipt",()=>acknowledge(out,msg,registry,{...ack,receipt_sha256:"f".repeat(64)}),"ACK_BINDING");
 rejects("unexpected UTC authority declaration rejected",()=>deliver(inbox,signForTest({...p,utc_authority:true},key.privateKey),registry),"MESSAGE_FIELDS");
 rejects("invalid receiver acknowledgement shape rejected",()=>acknowledge(out,msg,registry,{...ack,physical_clock:true}),"ACK_BINDING");
 rejects("receiver unavailable fails closed without fallback",()=>deliver(path.join(root,"unavailable"),msg,registry),"JOURNAL_DIRECTORY_MISSING");
 rejects("sender unavailable cannot claim acknowledgement",()=>acknowledge(path.join(root,"unavailable"),msg,registry,ack),"JOURNAL_DIRECTORY_MISSING");
 rejects("inbox lock contention refuses reception",()=>{
  fs.mkdirSync(path.join(inbox,"lock"));try{deliver(inbox,msg,registry)}finally{fs.rmdirSync(path.join(inbox,"lock"))}
 },"JOURNAL_LOCKED");
 rejects("corrupted inbox fails closed",()=>{
  const file=path.join(inbox,"inbox.json"),old=fs.readFileSync(file);
  try{fs.writeFileSync(file,"{invalid");deliver(inbox,msg,registry)}
  finally{fs.writeFileSync(file,old)}
 },"JOURNAL_UNAVAILABLE");
 rejects("fabricated receipt digest in inbox refused",()=>{
  const file=path.join(inbox,"inbox.json"),old=fs.readFileSync(file);
  try{const d=JSON.parse(old);d.records[0].receipt_sha256=null;fs.writeFileSync(file,JSON.stringify(d));inspect(inbox,"inbox")}
  finally{fs.writeFileSync(file,old)}
 },"JOURNAL_CORRUPT");
 rejects("extra alleged authority in outbox refused",()=>{
  const file=path.join(out,"outbox.json"),old=fs.readFileSync(file);
  try{const d=JSON.parse(old);d.physical_authority=true;fs.writeFileSync(file,JSON.stringify(d));inspect(out,"outbox")}
  finally{fs.writeFileSync(file,old)}
 },"JOURNAL_CORRUPT");
 check("receiver did not duplicate synthetic effect during any replay",()=>{
  assert.equal(inspect(inbox,"inbox").records.length,1);
  assert.equal(inspect(out,"outbox").records.length,1);
 });
 console.log("SAPPHON-116:",n,"sender outbox and receiver idempotency checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
