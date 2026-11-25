"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto");
const e=require("./sapphon_125_replica.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon125-"));
const issuer=crypto.generateKeyPairSync("ed25519"),rogue=crypto.generateKeyPairSync("ed25519");
const pins={"test-publisher":{publicKey:issuer.publicKey,control_root:"test-source-root"}};
const policy={schema:"sapphon-125-revocation-snapshot-v1",publisher_id:"test-publisher",
 control_root:"test-source-root",generation:1,issuer_generation:1,operator_generation:1,
 issuer_revoked:false,operator_revoked:false,previous_digest:null,mode:"synthetic-local-replica"};
const digest=b=>crypto.createHash("sha256").update(b).digest("hex");
const p1=e.signForTest(policy,issuer.privateKey);
const p2=e.signForTest({...policy,generation:2,issuer_revoked:true,previous_digest:digest(e.bytes(policy))},issuer.privateKey);
const p2op=e.signForTest({...policy,generation:2,operator_revoked:true,previous_digest:digest(e.bytes(policy))},issuer.privateKey);
const p3=e.signForTest({...p2.payload,generation:3,issuer_generation:2,previous_digest:digest(e.bytes(p2.payload))},issuer.privateKey);
let n=0;
function check(name,fn){fn();console.log("PASS",++n,name)}
function reject(name,fn,reason){check(name,()=>assert.throws(fn,err=>err.message===reason))}
function create(){const dir=path.join(root,"replica-"+n);e.init(dir);return dir}
function gate(dir,highWater=p1,nonce="a",extra={}){return e.gate(dir,{highWater,highWaterTrusted:true,pins,challenge_nonce:nonce.repeat(64),issuer_generation:1,operator_generation:1,...extra})}
try{
 const a=create(),b=create();
 reject("no replica state cannot authorize even with current high water",()=>gate(a),"NO_LOCAL_SNAPSHOT");
 check("pinned signed genesis installed at replica A",()=>assert.equal(e.update(a,p1,pins).generation,1));
 check("same signed genesis installed at replica B",()=>assert.equal(e.update(b,p1,pins).generation,1));
 check("duplicate publication is an idempotent no-op",()=>assert.equal(e.update(a,p1,pins).decision,"SAME_SNAPSHOT"));
 check("fresh equality with connected high water gives only test-local result",()=>{
  const x=gate(a);assert.equal(x.decision,"HOLD");assert.equal(x.external_authority,false);
 });
 reject("identical permission nonce cannot be authorized again",()=>gate(a),"PERMISSION_NONCE_REPLAY");
 reject("no high water while disconnected fails closed",()=>e.gate(a,{highWaterTrusted:false,pins,highWater:p1,challenge_nonce:"b".repeat(64),issuer_generation:1,operator_generation:1}),"HIGH_WATER_UNAVAILABLE");
 reject("missing high-water source fails closed",()=>e.gate(a,{highWaterTrusted:true,pins,challenge_nonce:"b".repeat(64),issuer_generation:1,operator_generation:1}),"HIGH_WATER_UNAVAILABLE");
 reject("forged snapshot with rogue publisher signature denied",()=>e.update(a,e.signForTest(policy,rogue.privateKey),pins),"SNAPSHOT_SIGNATURE");
 reject("revoked signing publisher cannot update replicas",()=>e.update(a,p2,{"test-publisher":{...pins["test-publisher"],revoked:true}}),"PUBLISHER_REVOKED");
 reject("unregistered publisher refused",()=>e.update(a,p2,{}),"PUBLISHER_NOT_PINNED");
 reject("wrong publisher root rejected",()=>e.update(a,p2,{"test-publisher":{...pins["test-publisher"],control_root:"wrong-root"}}),"PUBLISHER_IDENTITY");
 check("authority revocation snapshot reaches A while B remains stale",()=>{
  assert.equal(e.update(a,p2,pins).generation,2);assert.equal(e.inspect(b).snapshot.payload.generation,1);
 });
 reject("replica B cannot use stale state against current connected high water",()=>gate(b,p2,"b"),"STALE_REPLICA_HOLD");
 reject("replica A cannot authorize under issuer revocation",()=>gate(a,p2,"b"),"CURRENT_ROLE_REVOKED");
 reject("replica B cannot bootstrap authority from prior signed but stale state",()=>gate(b,p1,"b",{highWaterTrusted:false}),"HIGH_WATER_UNAVAILABLE");
 check("delayed revocation propagation reaches B and blocks local use",()=>{
  assert.equal(e.update(b,p2,pins).generation,2);
  assert.equal(e.inspect(b).snapshot.payload.issuer_revoked,true);
 });
 reject("delayed duplicate revocation cannot duplicate state",()=>gate(b,p2,"b"),"CURRENT_ROLE_REVOKED");
 reject("retrograde update to prior generation rejected",()=>e.update(a,p1,pins),"STALE_REPLICA_UPDATE");
 reject("stale signed high-water proof cannot authorize newer replica",()=>gate(a,p1,"b"),"UNTRUSTED_RETROGRADE_HIGH_WATER");
 reject("same generation conflicting signed state cannot overwrite publisher history",()=>e.update(a,p2op,pins),"GENERATION_FORK");
 reject("same generation conflicting connected high water cannot authorize",()=>gate(a,p2op,"b"),"HIGH_WATER_SNAPSHOT_CONFLICT");
 reject("generation skip refused despite signature",()=>e.update(a,e.signForTest({...p3.payload,generation:4},issuer.privateKey),pins),"SKIPPED_HIGH_WATER_GENERATION");
 const f=create();e.update(f,p1,pins);
 const fork=e.signForTest({...policy,generation:2,previous_digest:"f".repeat(64)},issuer.privateKey);
 reject("wrong predecessor chain cannot update current replica",()=>e.update(f,fork,pins),"BROKEN_PREDECESSOR");
 const staleGeneration=e.signForTest({...policy,generation:2,issuer_generation:1,operator_generation:1,previous_digest:digest(e.bytes(policy))},issuer.privateKey);
 check("valid generation two without revocation can be installed in separate fixture",()=>assert.equal(e.update(f,staleGeneration,pins).generation,2));
 reject("mismatched current credential generation cannot pass",()=>gate(f,staleGeneration,"c",{issuer_generation:2}),"CURRENT_CREDENTIAL_GENERATION_MISMATCH");
 reject("unissued future high water blocks lagging replica",()=>gate(f,p3,"c"),"STALE_REPLICA_HOLD");
 const badRevoke=e.signForTest({...staleGeneration.payload,generation:3,issuer_generation:2,previous_digest:digest(e.bytes(staleGeneration.payload)),operator_revoked:true},issuer.privateKey);
 check("operator-only revocation update is independently fenced",()=>assert.equal(e.update(f,badRevoke,pins).generation,3));
 reject("operator-only revocation blocks authority after propagation",()=>gate(f,badRevoke,"c",{issuer_generation:2}),"CURRENT_ROLE_REVOKED");
 const resurrect=e.signForTest({...badRevoke.payload,generation:4,operator_generation:2,operator_revoked:false,previous_digest:digest(e.bytes(badRevoke.payload))},issuer.privateKey);
 reject("revoked operator cannot be resurrected by newer signed snapshot",()=>e.update(f,resurrect,pins),"REVOCATION_RESURRECTION");
 reject("invalid zero credential generation cannot be signed",()=>e.bytes({...staleGeneration.payload,generation:3,issuer_generation:0,previous_digest:digest(e.bytes(staleGeneration.payload))}),"SNAPSHOT_FIELDS");
 const wrongRoot=e.signForTest({...policy,control_root:"unrelated-source-root"},issuer.privateKey);
 reject("changing control root cannot masquerade as original publisher",()=>e.update(a,wrongRoot,pins),"PUBLISHER_IDENTITY");
 reject("untrusted authority field in snapshot schema forbidden",()=>e.bytes({...policy,utc_valid:true}),"SNAPSHOT_FIELDS");
 reject("cannot silently reinitialize replica state",()=>e.init(a),"REPLICA_EXISTS");
 reject("missing replica path cannot admit permission",()=>gate(path.join(root,"absent")),"REPLICA_MISSING");
 reject("exclusive local lock blocks concurrent authority use",()=>{
  fs.mkdirSync(path.join(a,"lock"));try{e.inspect(a)}finally{fs.rmdirSync(path.join(a,"lock"))}
 },"REPLICA_BUSY");
 reject("truncated local replica state fails closed",()=>{
  const p=path.join(a,"replica.json"),previous=fs.readFileSync(p);
  try{fs.writeFileSync(p,"{broken");e.inspect(a)}finally{fs.writeFileSync(p,previous)}
 },"REPLICA_UNREADABLE");
 reject("fabricated external authority in persisted replica state fails closed",()=>{
  const p=path.join(a,"replica.json"),previous=fs.readFileSync(p);
  try{const d=JSON.parse(previous);d.outside_authenticated=true;fs.writeFileSync(p,JSON.stringify(d));e.inspect(a)}
  finally{fs.writeFileSync(p,previous)}
 },"REPLICA_CORRUPT");
 check("all local fixtures remain non-UTC and non-authoritative",()=>{
  assert.equal(e.inspect(a).snapshot.payload.mode,"synthetic-local-replica");
  assert.equal(e.inspect(a).permission_log.length,1);
 });
 console.log("SAPPHON-125:",n,"revocation lag, replica high-water and fail-closed checks passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
