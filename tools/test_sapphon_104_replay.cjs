"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto");
const {initialize,issue,consume,inspect,MAX_TTL}=require("./sapphon_104_replay.cjs");
const {enrollForTest,responseForTest}=require("./sapphon_103_challenge.cjs");
const {receiptForTest}=require("./sapphon_102_receipts.cjs");
const signer=crypto.generateKeyPairSync("ed25519"),forger=crypto.generateKeyPairSync("ed25519");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon104-")),storage=path.join(root,"durable");
const anchor={schema:"sapphon-external-anchor-v1",key_id:"test-governance-100",governance_spki_sha256:"1".repeat(64),
 head:"2".repeat(64),count:3,checkpoint_signature:"A".repeat(86)+"==",independently_retained:false,recorded_utc:null};
const identity={custodian_id:"test-custodian-a",custody_root:"one-owned-synthetic-root",key_id:"test-key-a",session_id:"session-104"};
const enrollment=enrollForTest(identity,signer.publicKey);
const receipt=receiptForTest(anchor,{...identity,receipt_serial:"receipt-104"},signer.privateKey);
function args(challenge,options={}){return {anchor,enrollment,receipt,response:responseForTest(challenge,signer.privateKey),publicKey:signer.publicKey,sessionId:identity.session_id,...options}}
let tests=0;function check(label,fn){fn();tests++;console.log("PASS",tests,label)}
function rejects(label,fn,code){check(label,()=>assert.throws(fn,e=>e.message===code))}
try{
 check("initialize private persistent registry",()=>{initialize(storage);assert.deepEqual(inspect(storage).records,[])});
 rejects("cannot silently reinitialize and erase history",()=>initialize(storage),"STORE_EXISTS");
 rejects("unissued nonce rejected",()=>{const x=issue(storage,anchor,identity,{now:1000,nonce:"a".repeat(64)});consume(storage,args({...x.challenge,nonce:"b".repeat(64)}),{now:1001})},"NONCE_NOT_ISSUED_OR_EXPIRED");
 check("first valid response commits consumed nonce to disk",()=>{
   const d=inspect(storage);const issued=d.records[0];const c=issue(storage,anchor,identity,{now:1100,nonce:"c".repeat(64)});
   const out=consume(storage,args(c.challenge),{now:1101});
   assert.equal(out.durable_replay_protection,true);assert.equal(out.utc_authority,false);
   assert.equal(inspect(storage).records.find(x=>x.nonce==="c".repeat(64)).state,"CONSUMED");
 });
 rejects("same nonce cannot be used after module-style restart",()=>{
   const c=issue(storage,anchor,identity,{now:1200,nonce:"d".repeat(64)});
   consume(storage,args(c.challenge),{now:1201});
   const fresh=require("./sapphon_104_replay.cjs");
   fresh.consume(storage,args(c.challenge),{now:1202});
 },"DURABLE_REPLAY");
 rejects("nonce expires at exact upper bound",()=>{
   const c=issue(storage,anchor,identity,{now:1300,ttl_ms:30,nonce:"e".repeat(64)});
   consume(storage,args(c.challenge),{now:1330});
 },"CHALLENGE_EXPIRED");
 rejects("nonce cannot be accepted before issuance",()=>{
   const c=issue(storage,anchor,identity,{now:1400,nonce:"f".repeat(64)});
   consume(storage,args(c.challenge),{now:1399});
 },"CLOCK_ROLLBACK");
 rejects("forged challenge response rejected",()=>{
   const c=issue(storage,anchor,identity,{now:1500,nonce:"1".repeat(64)});
   consume(storage,args(c.challenge,{response:responseForTest(c.challenge,forger.privateKey)}),{now:1501});
 },"CHALLENGE_SIGNATURE");
 check("failed forged response leaves nonce available for valid response",()=>{
   const c=inspect(storage).records.find(x=>x.nonce==="1".repeat(64));
   assert.equal(c.state,"ISSUED");
 });
 rejects("issued challenge cannot be altered while preserving nonce",()=>{
   const c=issue(storage,anchor,identity,{now:1600,nonce:"2".repeat(64)});
   consume(storage,args({...c.challenge,session_id:"altered-session"}),{now:1601});
 },"ISSUED_CHALLENGE_MISMATCH");
 rejects("missing registry fails closed",()=>{const valid=issue(storage,anchor,identity,{now:1650,nonce:"8".repeat(64)});consume(path.join(root,"missing"),args(valid.challenge),{now:1651})},"STORE_UNINITIALIZED");
 rejects("invalid low TTL",()=>issue(storage,anchor,identity,{now:1700,ttl_ms:0}),"TTL_OUT_OF_BOUNDS");
 rejects("invalid excessive TTL",()=>issue(storage,anchor,identity,{now:1700,ttl_ms:MAX_TTL+1}),"TTL_OUT_OF_BOUNDS");
 rejects("missing clock reference fails closed",()=>issue(storage,anchor,identity,{}),"BAD_LOCAL_TIME");
 rejects("duplicate nonce cannot be issued within retention window",()=>{
   issue(storage,anchor,identity,{now:1800,nonce:"3".repeat(64)});
   issue(storage,anchor,identity,{now:1801,nonce:"3".repeat(64)});
 },"DUPLICATE_ISSUANCE");
 rejects("exclusive file lock prevents concurrent mutation",()=>{
   fs.mkdirSync(path.join(storage,"lock"));
   try{issue(storage,anchor,identity,{now:1900,nonce:"4".repeat(64)})}
   finally{fs.rmdirSync(path.join(storage,"lock"))}
 },"LOCK_UNAVAILABLE");
 rejects("torn or corrupted ledger refuses consumption",()=>{
   const d=fs.readFileSync(path.join(storage,"registry.json"),"utf8");
   try{fs.writeFileSync(path.join(storage,"registry.json"),"{garbled");
     issue(storage,anchor,identity,{now:1900,nonce:"5".repeat(64)})}
   finally{fs.writeFileSync(path.join(storage,"registry.json"),d)}
 },"STORE_UNAVAILABLE");
 check("pruning expired entries never allows replay of an unissued nonce",()=>{
   const c=issue(storage,anchor,identity,{now:2000,ttl_ms:20,nonce:"6".repeat(64)});
   issue(storage,anchor,identity,{now:2030,nonce:"7".repeat(64)});
   assert.equal(inspect(storage).records.some(x=>x.nonce==="6".repeat(64)),false);
   assert.throws(()=>consume(storage,args(c.challenge),{now:2031}),e=>e.message==="NONCE_NOT_ISSUED_OR_EXPIRED");
 });
 check("previously consumed phase cannot become a new minted clock reading",()=>{
   const d=inspect(storage);assert.equal(d.schema,"sapphon-104-replay-registry-v1");
   assert.equal(Object.keys(d).join(","),"schema,revision,records");
 });
 console.log("SAPPHON-104:",tests,"durable replay and expiry tests passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
