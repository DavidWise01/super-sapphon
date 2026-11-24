"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {init:initializeWriter,acquire,issue}=require("./sapphon_113_fence.cjs");
const {init,apply,inspect}=require("./sapphon_114_effect.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon114-")),dir=path.join(root,"writer");
const non=c=>c.repeat(64);
let count=0;function test(name,fn){fn();console.log("PASS",++count,name)}
function reject(name,fn,code){test(name,()=>assert.throws(fn,e=>e.message===code))}
function req(effect_id,writer,epoch,nonce,now){return {effect_id,writer,epoch,nonce,payload_sha256:non("a"),now}}
try{
 initializeWriter(dir);
 test("destination journal initializes only alongside canonical lease",()=>{init(dir);assert.equal(inspect(dir).effects.commits.length,0)});
 reject("destination journal cannot be reset",()=>init(dir),"EFFECTS_ALREADY_EXISTS");
 acquire(dir,"writer-alpha",{now:1000,lease_ms:100});
 issue(dir,"writer-alpha",1,non("1"),{now:1001});
 test("valid downstream action commits under same canonical lock",()=>{
  const x=apply(dir,req("effect-one","writer-alpha",1,non("1"),1002));
  assert.equal(x.decision,"TEST_EFFECT_COMMITTED");assert.equal(x.physical_effect,false);
  assert.equal(inspect(dir).effects.commits.length,1);
 });
 reject("duplicate id and nonce refused",()=>apply(dir,req("effect-one","writer-alpha",1,non("1"),1003)),"DESTINATION_DUPLICATE_EFFECT");
 reject("different id cannot reuse committed nonce",()=>apply(dir,req("effect-two","writer-alpha",1,non("1"),1004)),"DESTINATION_DUPLICATE_EFFECT");
 reject("unknown unissued nonce refused at destination",()=>apply(dir,req("effect-two","writer-alpha",1,non("2"),1005)),"DESTINATION_NONCE_UNISSUED");
 reject("different writer refused despite correct epoch",()=>apply(dir,req("effect-two","writer-beta",1,non("1"),1006)),"DESTINATION_WRONG_WRITER");
 issue(dir,"writer-alpha",1,non("3"),{now:1007});
 reject("expired lease refused at side-effect boundary",()=>apply(dir,req("effect-expired","writer-alpha",1,non("3"),1100)),"DESTINATION_LEASE_EXPIRED");
 acquire(dir,"writer-beta",{now:1101,lease_ms:80});
 issue(dir,"writer-beta",2,non("4"),{now:1102});
 reject("old writer cannot act after new epoch granted",()=>apply(dir,req("effect-old","writer-alpha",1,non("3"),1103)),"DESTINATION_STALE_EPOCH");
 reject("correct writer using stale epoch refused",()=>apply(dir,req("effect-stale","writer-beta",1,non("4"),1104)),"DESTINATION_STALE_EPOCH");
 test("current writer can commit current nonce after rotation",()=>{
  const x=apply(dir,req("effect-new","writer-beta",2,non("4"),1105));assert.equal(x.epoch,2);
 });
 reject("unissued nonce from new epoch refused",()=>apply(dir,req("effect-fake","writer-beta",2,non("5"),1106)),"DESTINATION_NONCE_UNISSUED");
 reject("caller clock rollback refused",()=>apply(dir,req("effect-back","writer-beta",2,non("5"),1100)),"DESTINATION_CLOCK_ROLLBACK");
 test("failed actions are persisted with reason",()=>{
  const e=inspect(dir).effects;
  assert.equal(e.commits.length,2);
  assert.ok(e.rejections.some(x=>x.reason==="DESTINATION_STALE_EPOCH"));
 });
 reject("malformed id rejected before lock",()=>apply(dir,req("?","writer-beta",2,non("6"),1107)),"BAD_EFFECT_REQUEST");
 reject("client cannot assert authority field",()=>apply(dir,{...req("effect-claim","writer-beta",2,non("6"),1107),utc_authorized:true}),"BAD_EFFECT_REQUEST");
 reject("nonexistent canonical destination refused",()=>apply(path.join(root,"gone"),req("effect-gone","writer-beta",2,non("6"),1107)),"CANONICAL_STORE_MISSING");
 reject("exclusive canonical lock prevents the downstream effect",()=>{
  fs.mkdirSync(path.join(dir,"lock"));
  try{apply(dir,req("effect-busy","writer-beta",2,non("6"),1107))}finally{fs.rmdirSync(path.join(dir,"lock"))}
 },"CANONICAL_LOCK_UNAVAILABLE");
 reject("corrupted side-effect journal fails closed",()=>{
  const p=path.join(dir,"effects.json"),b=fs.readFileSync(p);
  try{fs.writeFileSync(p,"{bad");apply(dir,req("effect-broken","writer-beta",2,non("6"),1107))}
  finally{fs.writeFileSync(p,b)}
 },"EFFECTS_UNREADABLE");
 reject("extra authority field on side-effect journal fails closed",()=>{
  const p=path.join(dir,"effects.json"),b=fs.readFileSync(p);
  try{const d=JSON.parse(b);d.external_approval=true;fs.writeFileSync(p,JSON.stringify(d));inspect(dir)}
  finally{fs.writeFileSync(p,b)}
 },"EFFECTS_CORRUPT");
 reject("corrupted canonical epoch journal prevents side effect",()=>{
  const p=path.join(dir,"registry.json"),b=fs.readFileSync(p);
  try{fs.writeFileSync(p,"{broken");apply(dir,req("effect-canon","writer-beta",2,non("6"),1107))}
  finally{fs.writeFileSync(p,b)}
 },"CANONICAL_UNREADABLE");
 test("commits and denials survive new module read",()=>{
  const d=require("./sapphon_114_effect.cjs").inspect(dir);
  assert.deepEqual(d.effects.commits.map(x=>x.epoch),[1,2]);
  assert.ok(d.effects.rejections.length>=8);
 });
 test("no real physical side effects or UTC authority is inferred",()=>{
  const d=inspect(dir);assert.equal(d.effects.utc_authority,undefined);
 });
 console.log("SAPPHON-114:",count,"atomic local destination enforcement tests passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
