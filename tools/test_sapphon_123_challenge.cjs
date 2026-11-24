"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {challengeBytes,signForTest,init,issue,resolve,inspect}=require("./sapphon_123_challenge.cjs");
const dir=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon123-"));
const issuer=crypto.generateKeyPairSync("ed25519"),operator=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519");
const registries={"issuer-one":{publicKey:issuer.publicKey,control_root:"issuer-root",control_group:"issuer-group"},
 "operator-one":{publicKey:operator.publicKey,control_root:"operator-root",control_group:"operator-group"}};
const c={schema:"sapphon-123-challenge-v1",nonce:"a".repeat(64),issuer_id:"issuer-one",
 operator_id:"operator-one",custodian_id:"custodian-one",checkpoint_sha256:"b".repeat(64),
 generation:2,issued_tick:100,expires_tick:200};
const ctx={issuer_root:"issuer-root",operator_root:"operator-root",custodian_root:"custodian-root",source_roots:["owned-root"],tick:101};
const pair=x=>({issuer:signForTest(x,"ISSUER",issuer.privateKey),operator:signForTest(x,"OPERATOR",operator.privateKey)});
let n=0;function test(name,fn){fn();console.log("PASS",++n,name)}
function reject(name,fn,msg){test(name,()=>assert.throws(fn,e=>e.message===msg))}
try{
 init(dir);
 test("fresh challenge persists once",()=>assert.equal(issue(dir,c,{tick:100}).decision,"TEST_CHALLENGE_ISSUED"));
 reject("duplicate issued challenge nonce rejected",()=>issue(dir,c,{tick:100}),"NONCE_ALREADY_ISSUED");
 reject("unissued nonce not consumable",()=>resolve(dir,{...c,nonce:"f".repeat(64)},pair({...c,nonce:"f".repeat(64)}),registries,ctx),"NONCE_NOT_ISSUED");
 reject("wrong challenge digest rejected",()=>resolve(dir,{...c,checkpoint_sha256:"e".repeat(64)},pair({...c,checkpoint_sha256:"e".repeat(64)}),registries,ctx),"CHALLENGE_CONFLICT");
 reject("expired challenge rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,tick:200}),"CHALLENGE_EXPIRED");
 reject("logical tick regression rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,tick:99}),"LOGICAL_TICK_ROLLBACK");
 reject("issuer revocation independently blocks completion",()=>resolve(dir,c,pair(c),{...registries,"issuer-one":{...registries["issuer-one"],revoked:true}},ctx),"ROLE_REVOKED");
 reject("operator revocation independently blocks completion",()=>resolve(dir,c,pair(c),{...registries,"operator-one":{...registries["operator-one"],revoked:true}},ctx),"ROLE_REVOKED");
 reject("forged issuer signature denied",()=>resolve(dir,c,{...pair(c),issuer:signForTest(c,"ISSUER",rogue.privateKey)},registries,ctx),"RESPONSE_SIGNATURE");
 reject("forged operator signature denied",()=>resolve(dir,c,{...pair(c),operator:signForTest(c,"OPERATOR",rogue.privateKey)},registries,ctx),"RESPONSE_SIGNATURE");
 reject("cross-role issuer response swapped rejected",()=>resolve(dir,c,{issuer:pair(c).operator,operator:pair(c).issuer},registries,ctx),"RESPONSE_BINDING");
 reject("changed checkpoint in signed challenge cannot pass",()=>resolve(dir,{...c,checkpoint_sha256:"c".repeat(64)},pair(c),registries,ctx),"CHALLENGE_CONFLICT");
 reject("shared declared control group rejected",()=>resolve(dir,c,pair(c),{...registries,"operator-one":{...registries["operator-one"],control_group:"issuer-group"}},ctx),"ROLE_CONTROL_CONVERGENCE");
 reject("issuer and operator same root rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,operator_root:"issuer-root"}),"ROLE_ORIGIN_MISMATCH");
 reject("custodian and issuer share declared ancestry rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,custodian_root:"issuer-root"}),"ROLE_CONTROL_CONVERGENCE");
 reject("source owner controls issuer rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,source_roots:["issuer-root"]}),"ROLE_CONTROL_CONVERGENCE");
 reject("source owner controls operator rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,source_roots:["operator-root"]}),"ROLE_CONTROL_CONVERGENCE");
 reject("source owner controls custodian rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,source_roots:["custodian-root"]}),"ROLE_CONTROL_CONVERGENCE");
 reject("missing pinned issuer fails closed",()=>resolve(dir,c,pair(c),{"operator-one":registries["operator-one"]},ctx),"ROLE_NOT_PINNED");
 reject("missing pinned operator fails closed",()=>resolve(dir,c,pair(c),{"issuer-one":registries["issuer-one"]},ctx),"ROLE_NOT_PINNED");
 reject("wrong pinned issuer root rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,issuer_root:"fake-root"}),"ROLE_ORIGIN_MISMATCH");
 reject("wrong pinned operator root rejected",()=>resolve(dir,c,pair(c),registries,{...ctx,operator_root:"fake-root"}),"ROLE_ORIGIN_MISMATCH");
 reject("forged issuer key registry rejects prior signature",()=>resolve(dir,c,pair(c),{...registries,"issuer-one":{...registries["issuer-one"],publicKey:rogue.publicKey}},ctx),"RESPONSE_SIGNATURE");
 reject("forged operator key registry rejects prior signature",()=>resolve(dir,c,pair(c),{...registries,"operator-one":{...registries["operator-one"],publicKey:rogue.publicKey}},ctx),"RESPONSE_SIGNATURE");
 reject("invalid extra challenge authority field refused",()=>challengeBytes({...c,external_authority:true}),"CHALLENGE_FIELDS");
 reject("invalid extra response authority field refused",()=>resolve(dir,c,{...pair(c),operator:{...pair(c).operator,utc:true}},registries,ctx),"RESPONSE_BINDING");
 test("valid two-role signatures consume exactly one durable nonce",()=>{
  const x=resolve(dir,c,pair(c),registries,ctx);
  assert.equal(x.nonce_consumed,true);assert.equal(x.decision,"HOLD");assert.equal(x.external_custody_authenticated,false);
 });
 reject("replay after completed response is blocked",()=>resolve(dir,c,pair(c),registries,{...ctx,tick:102}),"NONCE_REPLAY");
 test("spent nonce remains consumed through new module read",()=>assert.equal(require("./sapphon_123_challenge.cjs").inspect(dir).sessions[0].status,"USED"));
 reject("reissuing used nonce rejected",()=>issue(dir,{...c,issued_tick:103,expires_tick:203},{tick:103}),"NONCE_ALREADY_ISSUED");
 const c2={...c,nonce:"d".repeat(64),issued_tick:110,expires_tick:120};
 test("subsequent independent challenge can be issued",()=>assert.equal(issue(dir,c2,{tick:110}).decision,"TEST_CHALLENGE_ISSUED"));
 reject("reusing old signatures with new nonce denied",()=>resolve(dir,c2,pair(c),registries,{...ctx,tick:111}),"RESPONSE_BINDING");
 reject("session store cannot be reinitialized",()=>init(dir),"SESSION_STORE_EXISTS");
 reject("local lock contention fails closed",()=>{
  fs.mkdirSync(path.join(dir,"lock"));try{inspect(dir)}finally{fs.rmdirSync(path.join(dir,"lock"))}
 },"SESSION_STORE_BUSY");
 reject("damaged local session journal fails closed",()=>{
  const f=path.join(dir,"sessions.json"),bytes=fs.readFileSync(f);
  try{fs.writeFileSync(f,"{broken");inspect(dir)}finally{fs.writeFileSync(f,bytes)}
 },"SESSION_STORE_UNREADABLE");
 reject("forged journal physical authority field fails closed",()=>{
  const f=path.join(dir,"sessions.json"),bytes=fs.readFileSync(f);
  try{const d=JSON.parse(bytes);d.utc_authority=true;fs.writeFileSync(f,JSON.stringify(d));inspect(dir)}
  finally{fs.writeFileSync(f,bytes)}
 },"SESSION_STORE_CORRUPT");
 test("final fixture cannot certify physical time or independent organizations",()=>{
  const s=inspect(dir);assert.equal(s.sessions.length,2);assert.equal(s.sessions.filter(x=>x.status==="USED").length,1);
 });
 console.log("SAPPHON-123:",n,"split-control challenges and revocation checks passed");
}finally{fs.rmSync(dir,{recursive:true,force:true})}
