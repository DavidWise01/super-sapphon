"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto");
const eng=require("./sapphon_124_revocation.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon124-"));
let sequence=0,n=0;
function check(name,fn){fn();console.log("PASS",++n,name)}
function reject(name,fn,code){check(name,()=>assert.throws(fn,e=>e.message===code))}
function setup(){
 const dir=path.join(root,"case-"+(++sequence));
 const i=crypto.generateKeyPairSync("ed25519"),o=crypto.generateKeyPairSync("ed25519");
 eng.init(dir,{ISSUER:{id:"issuer-one",control_root:"issuer-root",control_group:"issuer-group",publicKey:i.publicKey},
 OPERATOR:{id:"operator-one",control_root:"operator-root",control_group:"operator-group",publicKey:o.publicKey}});
 const c=(nonce="a",at=100)=>({schema:"sapphon-123-challenge-v1",nonce:nonce.repeat(64),
 issuer_id:"issuer-one",operator_id:"operator-one",custodian_id:"custodian-one",
 checkpoint_sha256:"f".repeat(64),generation:1,issued_tick:at,expires_tick:at+100});
 const responses=(challenge,ik=i.privateKey,ok=o.privateKey,ig=1,og=1)=>({
  issuer:eng.signedForTest(challenge,"ISSUER",ig,ik),
  operator:eng.signedForTest(challenge,"OPERATOR",og,ok)});
 return {dir,i,o,c,responses};
}
const allowed={source_roots:["owned-source-root"]};
try{
 let x=setup(),c=x.c();
 check("initial challenge persists both credential generations",()=>{
  const p=eng.issue(x.dir,c,{tick:100});
  assert.equal(p.issuer_generation,1);assert.equal(p.operator_generation,1);
 });
 check("valid current role pair consumes exactly one nonce",()=>{
  const y=eng.complete(x.dir,c,x.responses(c),{tick:101,...allowed});
  assert.equal(y.nonce_consumed,true);assert.equal(y.externally_qualified,false);
 });
 reject("completed challenge cannot replay",()=>eng.complete(x.dir,c,x.responses(c),{tick:102,...allowed}),"NONCE_REPLAY");
 check("spent nonce survives module reload",()=>{
  const d=require("./sapphon_124_revocation.cjs").inspect(x.dir);
  assert.equal(d.challenges[0].status,"CONSUMED");
 });
 reject("previous nonce cannot be issued again",()=>eng.issue(x.dir,x.c("a",110),{tick:110}),"NONCE_ALREADY_ISSUED");
 reject("logical tick rollback refused",()=>eng.issue(x.dir,x.c("b",99),{tick:99}),"LOGICAL_TICK_ROLLBACK");
 reject("cannot reset active credential state",()=>eng.init(x.dir,{ISSUER:{id:"issuer-one",control_root:"issuer-root",control_group:"issuer-group",publicKey:x.i.publicKey},OPERATOR:{id:"operator-one",control_root:"operator-root",control_group:"operator-group",publicKey:x.o.publicKey}}),"STATE_EXISTS");

 x=setup();c=x.c();eng.issue(x.dir,c,{tick:100});
 const delayed=x.responses(c);
 check("revoking issuer after issue writes durable revocation state",()=>{
  const r=eng.change(x.dir,"ISSUER","REVOKE",{tick:101});
  assert.equal(r.revoked,true);assert.equal(eng.inspect(x.dir).roles.ISSUER.revoked,true);
 });
 reject("delayed pre-revocation signature cannot consume nonce",()=>eng.complete(x.dir,c,delayed,{tick:102,...allowed}),"ROLE_REVOKED");
 check("refused delayed request leaves nonce PENDING",()=>assert.equal(eng.inspect(x.dir).challenges[0].status,"PENDING"));
 reject("revoked issuer cannot issue fresh challenges",()=>eng.issue(x.dir,x.c("b",103),{tick:103}),"ROLE_REVOKED");
 reject("revoked issuer cannot be silently reinstated by rotation",()=>eng.change(x.dir,"ISSUER","ROTATE",{tick:104,newPublicKey:crypto.generateKeyPairSync("ed25519").publicKey}),"ROLE_ALREADY_REVOKED");
 reject("same revocation event cannot be issued twice",()=>eng.change(x.dir,"ISSUER","REVOKE",{tick:104}),"ROLE_ALREADY_REVOKED");

 x=setup();c=x.c();eng.issue(x.dir,c,{tick:100});
 const oldOperator=x.responses(c);
 check("revoking only operator also blocks both-signature acceptance",()=>assert.equal(eng.change(x.dir,"OPERATOR","REVOKE",{tick:105}).role,"OPERATOR"));
 reject("issuer signature cannot override operator revocation",()=>eng.complete(x.dir,c,oldOperator,{tick:106,...allowed}),"ROLE_REVOKED");

 x=setup();c=x.c();eng.issue(x.dir,c,{tick:100});
 const oldPair=x.responses(c),newIssuer=crypto.generateKeyPairSync("ed25519");
 check("issuer rotation raises authoritative generation",()=>assert.equal(eng.change(x.dir,"ISSUER","ROTATE",{tick:101,newPublicKey:newIssuer.publicKey}).generation,2));
 reject("pre-rotation issuer signature denied despite unchanged nonce",()=>eng.complete(x.dir,c,oldPair,{tick:102,...allowed}),"STALE_CREDENTIAL_GENERATION");
 reject("new issuer key cannot relabel stale challenge generation",()=>eng.complete(x.dir,c,x.responses(c,newIssuer.privateKey,x.o.privateKey,2,1),{tick:103,...allowed}),"STALE_CREDENTIAL_GENERATION");
 check("fresh post-rotation issuance binds new issuer generation",()=>{
  const next=x.c("b",104);assert.equal(eng.issue(x.dir,next,{tick:104}).issuer_generation,2);
  assert.equal(eng.complete(x.dir,next,x.responses(next,newIssuer.privateKey,x.o.privateKey,2,1),{tick:105,...allowed}).nonce_consumed,true);
 });

 x=setup();c=x.c();eng.issue(x.dir,c,{tick:100});
 const newOperator=crypto.generateKeyPairSync("ed25519");
 check("operator rotation raises the independent operator generation",()=>assert.equal(eng.change(x.dir,"OPERATOR","ROTATE",{tick:101,newPublicKey:newOperator.publicKey}).generation,2));
 reject("out-of-order operator signature fails on stale challenge",()=>eng.complete(x.dir,c,x.responses(c,x.i.privateKey,newOperator.privateKey,1,2),{tick:102,...allowed}),"STALE_CREDENTIAL_GENERATION");
 check("new challenge accepts issuer generation one and operator generation two",()=>{
  const fresh=x.c("b",103);eng.issue(x.dir,fresh,{tick:103});
  assert.equal(eng.complete(x.dir,fresh,x.responses(fresh,x.i.privateKey,newOperator.privateKey,1,2),{tick:104,...allowed}).decision,"HOLD");
 });
 reject("rotation cannot reuse the same public key",()=>eng.change(x.dir,"OPERATOR","ROTATE",{tick:105,newPublicKey:newOperator.publicKey}),"ROTATION_KEY_REUSED");

 x=setup();c=x.c();eng.issue(x.dir,c,{tick:100});
 reject("forged issuer role signature rejected",()=>{
  const rogue=crypto.generateKeyPairSync("ed25519");
  eng.complete(x.dir,c,x.responses(c,rogue.privateKey,x.o.privateKey),{tick:101,...allowed});
 },"RESPONSE_SIGNATURE");
 reject("forged operator role signature rejected",()=>{
  const rogue=crypto.generateKeyPairSync("ed25519");
  eng.complete(x.dir,c,x.responses(c,x.i.privateKey,rogue.privateKey),{tick:101,...allowed});
 },"RESPONSE_SIGNATURE");
 reject("issuer and operator signatures cannot be swapped",()=>{
  const p=x.responses(c);eng.complete(x.dir,c,{issuer:p.operator,operator:p.issuer},{tick:101,...allowed});
 },"RESPONSE_BINDING");
 reject("changed checkpoint digest invalidates pending challenge",()=>{
  const tampered={...c,checkpoint_sha256:"e".repeat(64)};
  eng.complete(x.dir,tampered,x.responses(tampered),{tick:101,...allowed});
 },"CHALLENGE_CONFLICT");
 reject("expired pending challenge cannot complete",()=>eng.complete(x.dir,c,x.responses(c),{tick:200,...allowed}),"CHALLENGE_EXPIRED");
 reject("source-controlled issuer root cannot satisfy role separation",()=>eng.complete(x.dir,c,x.responses(c),{tick:101,source_roots:["issuer-root"]}),"ROLE_CONTROL_CONVERGENCE");
 reject("source-controlled operator root cannot satisfy role separation",()=>eng.complete(x.dir,c,x.responses(c),{tick:101,source_roots:["operator-root"]}),"ROLE_CONTROL_CONVERGENCE");
 reject("caller cannot invent physical authority in response schema",()=>{
  const p=x.responses(c);eng.complete(x.dir,c,{issuer:{...p.issuer,utc_authority:true},operator:p.operator},{tick:101,...allowed});
 },"RESPONSE_BINDING");
 check("unconsumed nonce remains usable after failures when credentials current",()=>assert.equal(eng.complete(x.dir,c,x.responses(c),{tick:101,...allowed}).nonce_consumed,true));

 x=setup();c=x.c();eng.issue(x.dir,c,{tick:100});
 reject("out of order credential update tick fails closed",()=>eng.change(x.dir,"ISSUER","REVOKE",{tick:99}),"LOGICAL_TICK_ROLLBACK");
 reject("unknown role update rejected",()=>eng.change(x.dir,"CUSTODIAN","REVOKE",{tick:101}),"CHANGE_INVALID");
 reject("missing replacement key rejected",()=>eng.change(x.dir,"ISSUER","ROTATE",{tick:101}),"ROTATION_KEY_MISSING");
 reject("reuse of unchanged issuer key rejected",()=>eng.change(x.dir,"ISSUER","ROTATE",{tick:101,newPublicKey:x.i.publicKey}),"ROTATION_KEY_REUSED");
 reject("missing local credential store fails closed",()=>eng.inspect(path.join(root,"nonexistent")),"STATE_MISSING");
 reject("exclusive directory lock blocks admission",()=>{
  fs.mkdirSync(path.join(x.dir,"lock"));
  try{eng.complete(x.dir,c,x.responses(c),{tick:101,...allowed})}finally{fs.rmdirSync(path.join(x.dir,"lock"))}
 },"STATE_BUSY");
 reject("corrupt local state fails closed",()=>{
  const p=path.join(x.dir,"state.json"),previous=fs.readFileSync(p);
  try{fs.writeFileSync(p,"{broken");eng.inspect(x.dir)}finally{fs.writeFileSync(p,previous)}
 },"STATE_UNREADABLE");
 reject("forged authority metadata inside state fails closed",()=>{
  const p=path.join(x.dir,"state.json"),previous=fs.readFileSync(p);
  try{const state=JSON.parse(previous);state.external_authority=true;fs.writeFileSync(p,JSON.stringify(state));eng.inspect(x.dir)}
  finally{fs.writeFileSync(p,previous)}
 },"STATE_CORRUPT");
 check("synthetic qualification always returns external authority HOLD",()=>{
  const result=eng.complete(x.dir,c,x.responses(c),{tick:101,...allowed});
  assert.equal(result.decision,"HOLD");assert.equal(result.utc_authority,false);
 });
 console.log("SAPPHON-124:",n,"revocation propagation and delayed-credential checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
