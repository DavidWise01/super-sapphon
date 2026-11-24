"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {signForTest,initialize:senderInit,queue,acknowledge,inspect:senderInspect}=require("./sapphon_116_outbox_inbox.cjs");
const {init,deliver,inspect,receiptFor}=require("./sapphon_117_transaction.cjs");
const kp=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519");
const registry={"sender-test":{publicKey:kp.publicKey,revoked:false}};
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon117-")),receiver=path.join(root,"receiver"),sender=path.join(root,"sender");
const payload={schema:"sapphon-116-message-v1",message_id:"message-117",effect_id:"effect-117",
 sender_id:"sender-test",writer:"writer-alpha",epoch:7,nonce:"a".repeat(64),payload_sha256:"b".repeat(64)};
const msg=signForTest(payload,kp.privateKey);
let n=0;function check(label,fn){fn();console.log("PASS",++n,label)}
function reject(label,fn,code){check(label,()=>assert.throws(fn,e=>e.message===code))}
function snap(){return fs.readFileSync(path.join(receiver,"transaction.json"))}
try{
 init(receiver);senderInit(sender,"outbox");
 check("receiver begins with jointly empty inbox and effect ledger",()=>{
  const s=inspect(receiver);assert.equal(s.records.length,0);assert.equal(s.effects.length,0);
 });
 reject("receiver store cannot be reset",()=>init(receiver),"RECEIVER_EXISTS");
 check("sender records durable pending message",()=>assert.equal(queue(sender,msg,registry).decision,"QUEUED"));
 const before=snap();
 reject("crash before transaction produces no receiver entry",()=>deliver(receiver,msg,registry,{fault:"BEFORE_TRANSACTION"}),"INJECTED_BEFORE_TRANSACTION");
 check("pre-commit crash leaves exactly matching pre-transaction bytes",()=>assert.deepEqual(snap(),before));
 check("post-crash retry commits receiver inbox and effect together",()=>{
  const a=deliver(receiver,msg,registry);assert.equal(a.duplicate,false);
  const s=inspect(receiver);assert.equal(s.records.length,1);assert.equal(s.effects.length,1);
 });
 check("sender accepts resulting SAPPHON-116 compatible receipt",()=>{
  const a=deliver(receiver,msg,registry);assert.equal(acknowledge(sender,msg,registry,a).decision,"ACKED");
 });
 check("receiver replay does not mutate committed state",()=>{
  const data=snap(),a=deliver(receiver,msg,registry);
  assert.equal(a.duplicate,true);assert.deepEqual(snap(),data);
 });
 check("receiver receipt remains stable across a new module read",()=>{
  const a=require("./sapphon_117_transaction.cjs").deliver(receiver,msg,registry);
  assert.equal(a.duplicate,true);assert.equal(a.receipt_sha256,receiptFor(payload,a.message_sha256));
 });
 const second={...payload,message_id:"message-118",effect_id:"effect-118",nonce:"c".repeat(64)};
 const msg2=signForTest(second,kp.privateKey);
 check("second sender message is queued independently",()=>assert.equal(queue(sender,msg2,registry).status,"PENDING"));
 reject("crash after both receiver arrays durably commit, before reply",()=>deliver(receiver,msg2,registry,{fault:"AFTER_TRANSACTION"}),"INJECTED_LOST_REPLY");
 check("post-commit crash leaves both receiver arrays with two entries",()=>{
  const s=inspect(receiver);assert.equal(s.records.length,2);assert.equal(s.effects.length,2);
 });
 check("retry after lost reply returns same committed receipt",()=>{
  const prior=snap(),a=deliver(receiver,msg2,registry);
  assert.equal(a.duplicate,true);assert.deepEqual(snap(),prior);
  assert.equal(acknowledge(sender,msg2,registry,a).decision,"ACKED");
 });
 reject("same message ID with different payload fails",()=>deliver(receiver,signForTest({...payload,payload_sha256:"d".repeat(64)},kp.privateKey),registry),"RECEIVER_CONFLICT");
 reject("same effect ID with different nonce fails",()=>deliver(receiver,signForTest({...payload,message_id:"message-119",nonce:"e".repeat(64)},kp.privateKey),registry),"RECEIVER_CONFLICT");
 reject("same nonce with different effect ID fails",()=>deliver(receiver,signForTest({...payload,message_id:"message-120",effect_id:"effect-120"},kp.privateKey),registry),"RECEIVER_CONFLICT");
 reject("another sender key cannot forge source signature",()=>deliver(receiver,signForTest(payload,rogue.privateKey),registry),"MESSAGE_SIGNATURE");
 reject("revoked sender is not allowed to replay",()=>deliver(receiver,msg,{"sender-test":{publicKey:kp.publicKey,revoked:true}}),"REVOKED_SENDER");
 reject("unknown sender is denied",()=>deliver(receiver,msg,{}),"UNKNOWN_SENDER");
 reject("wrong authority metadata is excluded from signed schema",()=>deliver(receiver,signForTest({...payload,utc_authority:true},kp.privateKey),registry),"MESSAGE_FIELDS");
 reject("invalid crash injection mode fails closed",()=>deliver(receiver,msg,registry,{fault:"DURING_PARTIAL_ARRAY_WRITE"}),"FAULT_MODE");
 reject("lock contention prohibits receiver transaction",()=>{
  fs.mkdirSync(path.join(receiver,"lock"));
  try{deliver(receiver,msg,registry)}finally{fs.rmdirSync(path.join(receiver,"lock"))}
 },"RECEIVER_LOCKED");
 reject("missing receiver directory cannot create unauthorized local fallback",()=>deliver(path.join(root,"missing"),msg,registry),"RECEIVER_MISSING");
 reject("truncated receiver transaction fails closed",()=>{
  const file=path.join(receiver,"transaction.json"),prior=snap();
  try{fs.writeFileSync(file,"{broken");inspect(receiver)}finally{fs.writeFileSync(file,prior)}
 },"RECEIVER_UNREADABLE");
 reject("tampering to remove one effect fails linkage validation",()=>{
  const file=path.join(receiver,"transaction.json"),prior=snap();
  try{const d=JSON.parse(prior);d.effects.pop();fs.writeFileSync(file,JSON.stringify(d));inspect(receiver)}
  finally{fs.writeFileSync(file,prior)}
 },"RECEIVER_CORRUPT");
 reject("tampering to remove one inbox record fails linkage validation",()=>{
  const file=path.join(receiver,"transaction.json"),prior=snap();
  try{const d=JSON.parse(prior);d.records.pop();fs.writeFileSync(file,JSON.stringify(d));inspect(receiver)}
  finally{fs.writeFileSync(file,prior)}
 },"RECEIVER_CORRUPT");
 reject("tampering with linked payload digest fails validation",()=>{
  const file=path.join(receiver,"transaction.json"),prior=snap();
  try{const d=JSON.parse(prior);d.effects[0].payload_sha256="f".repeat(64);
   fs.writeFileSync(file,JSON.stringify(d));inspect(receiver)}
  finally{fs.writeFileSync(file,prior)}
 },"RECEIVER_CORRUPT");
 reject("forged receipt hash inside receiver journal fails validation",()=>{
  const file=path.join(receiver,"transaction.json"),prior=snap();
  try{const d=JSON.parse(prior);d.records[0].receipt_sha256="f".repeat(64);
   fs.writeFileSync(file,JSON.stringify(d));inspect(receiver)}
  finally{fs.writeFileSync(file,prior)}
 },"RECEIVER_CORRUPT");
 reject("forged external physical authority in receiver journal fails validation",()=>{
  const file=path.join(receiver,"transaction.json"),prior=snap();
  try{const d=JSON.parse(prior);d.utc_authorized=true;
   fs.writeFileSync(file,JSON.stringify(d));inspect(receiver)}
  finally{fs.writeFileSync(file,prior)}
 },"RECEIVER_CORRUPT");
 check("receiver journal has exactly two deduplication entries and two effects",()=>{
  const d=inspect(receiver);assert.equal(d.records.length,2);assert.equal(d.effects.length,2);
  assert.equal(senderInspect(sender,"outbox").records.filter(x=>x.status==="ACKED").length,2);
 });
 check("rollback of receiver file is not externally detectable in this local model",()=>{
  const old=snap();fs.writeFileSync(path.join(receiver,"transaction.json"),before);
  const d=inspect(receiver);assert.equal(d.records.length,0);
  fs.writeFileSync(path.join(receiver,"transaction.json"),old);
  assert.equal(inspect(receiver).records.length,2);
 });
 console.log("SAPPHON-117:",n,"transactional receiver coupling and crash tests passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
