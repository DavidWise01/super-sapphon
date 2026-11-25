"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto");
const fresh=require("./sapphon_126_freshness.cjs"),snap=require("./sapphon_125_replica.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon126-"));
const old=crypto.generateKeyPairSync("ed25519"),rot=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519");
const publisher="test-publisher",verifier="test-verifier",control="fixture-root";
const snapshot=(generation,privateKey=old.privateKey,previous_digest=null)=>{
 const payload={schema:"sapphon-125-revocation-snapshot-v1",publisher_id:publisher,control_root:control,
 generation,issuer_generation:1,operator_generation:1,issuer_revoked:generation>1,
 operator_revoked:false,previous_digest,mode:"synthetic-local-replica"};
 return snap.signForTest(payload,privateKey);
};
const p1=snapshot(1),digest=crypto.createHash("sha256").update(snap.bytes(p1.payload)).digest("hex");
const p2=snapshot(2,old.privateKey,digest);
const pins=key=>({[publisher]:{publicKey:key,control_root:control}});
let idx=0,n=0;
const create=()=>{const dir=path.join(root,"verifier-"+(++idx));fresh.init(dir,{verifier_id:verifier,publisher_id:publisher,publisher_public_key:old.publicKey});return dir};
const challenge=(digit="a",generation=1,issued_tick=100)=>({
 schema:"sapphon-126-freshness-challenge-v1",verifier_id:verifier,publisher_id:publisher,
 nonce:digit.repeat(64),minimum_generation:generation,issued_tick,expires_tick:issued_tick+30});
const response=(c,s=p1,privateKey=old.privateKey,keyGeneration=1)=>fresh.responseForTest(c,s,keyGeneration,privateKey);
const input=(c,s=p1,r=response(c,s),tick=c.issued_tick+1,connected=true,registry=pins(old.publicKey))=>({c,s,r,tick,connected,registry});
function consume(dir,x){return fresh.consume(dir,x.c,x.r,x.s,x.registry,{tick:x.tick,connected:x.connected})}
function test(label,fn){fn();console.log("PASS",++n,label)}
function reject(label,fn,code){test(label,()=>assert.throws(fn,e=>e.message===code))}
try{
 let dir=create(),c=challenge();
 test("fresh nonce is issued to one verifier",()=>assert.equal(fresh.issue(dir,c,{tick:100}).decision,"PENDING_FRESHNESS"));
 test("current signed publisher response consumes one nonce but returns HOLD",()=>{
  const x=consume(dir,input(c));assert.equal(x.nonce_consumed,true);assert.equal(x.decision,"HOLD");
  assert.equal(x.independent_publisher_authenticated,false);
 });
 reject("historical replay of consumed challenge denied",()=>consume(dir,input(c)),"CHALLENGE_REPLAY");
 test("consumed nonce survives new module read",()=>assert.equal(require("./sapphon_126_freshness.cjs").inspect(dir).challenges[0].status,"CONSUMED"));
 reject("same nonce cannot be reissued",()=>fresh.issue(dir,challenge("a",1,110),{tick:110}),"NONCE_REISSUE");
 reject("logical local clock cannot regress",()=>fresh.issue(dir,challenge("b",1,99),{tick:99}),"LOGICAL_TICK_ROLLBACK");
 reject("verifier initialization cannot overwrite its journal",()=>fresh.init(dir,{verifier_id:verifier,publisher_id:publisher,publisher_public_key:old.publicKey}),"VERIFIER_EXISTS");
 dir=create();c=challenge();fresh.issue(dir,c,{tick:100});
 reject("offline publisher denies freshness",()=>consume(dir,input(c,p1,response(c),101,false)),"PUBLISHER_UNAVAILABLE");
 reject("missing signed publisher proof denies freshness",()=>fresh.consume(dir,c,null,p1,pins(old.publicKey),{tick:101,connected:true}),"PUBLISHER_UNAVAILABLE");
 reject("delayed publisher response expires",()=>consume(dir,input(c,p1,response(c),130)),"FRESHNESS_EXPIRED");
 reject("wrong verifier ID cannot reuse response",()=>consume(dir,input(c,p1,{...response(c),payload:{...response(c).payload,verifier_id:"wrong-verifier"}})),"RESPONSE_BINDING");
 reject("wrong nonce is denied",()=>consume(dir,input(c,p1,{...response(c),payload:{...response(c).payload,nonce:"f".repeat(64)}})),"RESPONSE_BINDING");
 reject("forged response signer rejected",()=>consume(dir,input(c,p1,response(c,p1,rogue.privateKey))),"RESPONSE_SIGNATURE");
 reject("changed issued tick in response rejected",()=>consume(dir,input(c,p1,{...response(c),payload:{...response(c).payload,issued_tick:200}})),"RESPONSE_BINDING");
 reject("changed snapshot digest in response rejected",()=>consume(dir,input(c,p2,response(c,p1))),"SNAPSHOT_BINDING");
 reject("revoked signed snapshot publisher denied by current registry",()=>consume(dir,input(c,p1,response(c),101,true,{[publisher]:{...pins(old.publicKey)[publisher],revoked:true}})),"PUBLISHER_REVOKED");
 reject("unknown snapshot publisher cannot establish freshness",()=>consume(dir,input(c,p1,response(c),101,true,{})),"PUBLISHER_NOT_PINNED");
 const minimum=challenge("b",2,110);fresh.issue(dir,minimum,{tick:110});
 reject("historically signed snapshot fails newer minimum-generation challenge",()=>consume(dir,input(minimum,p1,response(minimum,p1),111)),"STALE_PUBLISHER_SNAPSHOT");
 test("newer snapshot matching a verifier nonce can be accepted synthetically",()=>{
  const x=consume(dir,input(minimum,p2,response(minimum,p2),111));
  assert.equal(x.response_generation,2);assert.equal(x.external_custody,false);
 });
 reject("replayed snapshot response from other challenge cannot consume new nonce",()=>{
  const next=challenge("c",2,112);fresh.issue(dir,next,{tick:112});
  consume(dir,input(next,p2,response(minimum,p2),113));
 },"RESPONSE_BINDING");
 dir=create();c=challenge();fresh.issue(dir,c,{tick:100});
 test("publisher rotation updates pinned public key and generation",()=>assert.equal(fresh.rotate(dir,{newPublicKey:rot.publicKey,tick:101}).generation,2));
 reject("pre-rotation response is fenced even with previously valid signature",()=>consume(dir,input(c,p1,response(c),102)),"PUBLISHER_ROTATION_FENCE");
 const freshResponse=response(c,p1,rot.privateKey,2);
 reject("rotated signing key cannot validate old snapshot signed by revoked fixture key",()=>consume(dir,input(c,p1,freshResponse,102,true,pins(rot.publicKey))),"SNAPSHOT_SIGNATURE");
 const newP1=snapshot(1,rot.privateKey);
 test("rotated publisher response with current snapshot can clear synthetic challenge",()=>{
  const current=response(c,newP1,rot.privateKey,2),x=consume(dir,input(c,newP1,current,102,true,pins(rot.publicKey)));
  assert.equal(x.decision,"HOLD");
 });
 reject("same rotated public key cannot rotate again",()=>fresh.rotate(dir,{newPublicKey:rot.publicKey,tick:103}),"ROTATION_KEY_REUSE");
 reject("publisher key generation cannot be forged inside signed response",()=>fresh.responseBytes({...freshResponse.payload,publisher_key_generation:0}),"RESPONSE_FIELDS");
 reject("challenge cannot contain unapproved physical authority field",()=>fresh.challengeBytes({...challenge(),utc_authority:true}),"CHALLENGE_FIELDS");
 dir=create();c=challenge();fresh.issue(dir,c,{tick:100});
 reject("nonce not locally issued is not accepted",()=>consume(dir,input(challenge("f"),p1,response(challenge("f")))),"CHALLENGE_UNKNOWN");
 reject("challenge fields cannot silently change after issuance",()=>{
  const changed={...c,minimum_generation:2};consume(dir,input(changed,p2,response(changed,p2)));
 },"CHALLENGE_CONFLICT");
 reject("same nonce from a different verifier fails binding",()=>{
  const changed={...c,verifier_id:"another-verifier"};consume(dir,input(changed,p1,response(changed)));
 },"CHALLENGE_CONFLICT");
 reject("mismatched response signature cannot be excused by fixture network delivery",()=>{
  consume(dir,input(c,p1,{...response(c),signature:response(c,p1,rogue.privateKey).signature}));
 },"RESPONSE_SIGNATURE");
 test("failed challenge remains pending and is recoverable",()=>assert.equal(fresh.inspect(dir).challenges[0].status,"PENDING"));
 test("correct response after transient failure can be consumed once",()=>assert.equal(consume(dir,input(c)).nonce_consumed,true));
 reject("missing verifier store fails closed",()=>fresh.inspect(path.join(root,"missing")),"VERIFIER_MISSING");
 reject("exclusive lock blocks competing verifier writer",()=>{
  fs.mkdirSync(path.join(dir,"lock"));try{fresh.inspect(dir)}finally{fs.rmdirSync(path.join(dir,"lock"))}
 },"VERIFIER_BUSY");
 reject("corrupted on-disk nonce state fails closed",()=>{
  const f=path.join(dir,"freshness.json"),old=fs.readFileSync(f);
  try{fs.writeFileSync(f,"{bad");fresh.inspect(dir)}finally{fs.writeFileSync(f,old)}
 },"VERIFIER_UNREADABLE");
 reject("fabricated UTC assertion in on-disk journal fails closed",()=>{
  const f=path.join(dir,"freshness.json"),old=fs.readFileSync(f);
  try{const d=JSON.parse(old);d.utc_authenticated=true;fs.writeFileSync(f,JSON.stringify(d));fresh.inspect(dir)}
  finally{fs.writeFileSync(f,old)}
 },"VERIFIER_CORRUPT");
 test("synthetic verifier has no independently authenticated monotonic outside history",()=>{
  const s=fresh.inspect(dir);assert.equal(s.challenges.length,1);assert.equal(s.challenges[0].status,"CONSUMED");
 });
 console.log("SAPPHON-126:",n,"fresh high-water and publication partition checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
