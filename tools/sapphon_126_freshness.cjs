"use strict";
/* SAPPHON-126: local simulation of verifier-specific freshness handshake.
 * Signed nonce response proves possession of CURRENT PINNED fixture key, not
 * truth of a high-water claim or genuine remote freshness.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const snapshots=require("./sapphon_125_replica.cjs");
const H=/^[a-f0-9]{64}$/,ID=/^[a-z0-9-]{4,64}$/;
const fail=x=>{throw Error(x)};
const hash=b=>crypto.createHash("sha256").update(b).digest("hex");
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const fields=["schema","verifier_id","publisher_id","nonce","minimum_generation","issued_tick","expires_tick"];
const proofFields=["schema","verifier_id","publisher_id","nonce","publisher_key_generation","snapshot_sha256","snapshot_generation","issued_tick","expires_tick"];
function challengeBytes(c){
 if(!exact(c,fields)||c.schema!=="sapphon-126-freshness-challenge-v1"||
 ![c.verifier_id,c.publisher_id].every(v=>typeof v==="string"&&ID.test(v))||
 !H.test(c.nonce)||!Number.isSafeInteger(c.minimum_generation)||c.minimum_generation<1||
 !Number.isSafeInteger(c.issued_tick)||c.issued_tick<0||
 !Number.isSafeInteger(c.expires_tick)||c.expires_tick<=c.issued_tick||
 c.expires_tick-c.issued_tick>300000)fail("CHALLENGE_FIELDS");
 return Buffer.from(JSON.stringify(fields.map(k=>c[k])));
}
function responseBytes(r){
 if(!exact(r,proofFields)||r.schema!=="sapphon-126-freshness-response-v1"||
 ![r.verifier_id,r.publisher_id].every(v=>typeof v==="string"&&ID.test(v))||
 !H.test(r.nonce)||!H.test(r.snapshot_sha256)||
 ![r.publisher_key_generation,r.snapshot_generation].every(n=>Number.isSafeInteger(n)&&n>0)||
 !Number.isSafeInteger(r.issued_tick)||!Number.isSafeInteger(r.expires_tick))fail("RESPONSE_FIELDS");
 return Buffer.from(JSON.stringify(proofFields.map(k=>r[k])));
}
function responseForTest(challenge,snapshot,publisherKeyGeneration,privateKey){
 challengeBytes(challenge);
 const digest=snapshots.checkSigned(snapshot,{[snapshot.payload.publisher_id]:{publicKey:crypto.createPublicKey(privateKey),control_root:snapshot.payload.control_root}});
 const payload={schema:"sapphon-126-freshness-response-v1",verifier_id:challenge.verifier_id,
 publisher_id:challenge.publisher_id,nonce:challenge.nonce,publisher_key_generation:publisherKeyGeneration,
 snapshot_sha256:digest,snapshot_generation:snapshot.payload.generation,
 issued_tick:challenge.issued_tick,expires_tick:challenge.expires_tick};
 return {payload,signature:crypto.sign(null,responseBytes(payload),privateKey).toString("base64")};
}
function pem(k){return (k.type==="public"?k:crypto.createPublicKey(k)).export({type:"spki",format:"pem"}).toString()}
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("VERIFIER_MISSING");
 const p=path.join(dir,"lock");try{fs.mkdirSync(p)}catch{fail("VERIFIER_BUSY")}
 try{return fn()}finally{fs.rmdirSync(p)}
}
const SCHEMA="sapphon-126-verifier-v1";
function validate(d){
 if(!exact(d,["schema","revision","last_tick","verifier_id","publisher_id","publisher_key_generation","publisher_public_key_pem","challenges"])||
 d.schema!==SCHEMA||!Number.isSafeInteger(d.revision)||d.revision<0||
 !Number.isSafeInteger(d.last_tick)||d.last_tick<0||
 !ID.test(d.verifier_id)||!ID.test(d.publisher_id)||
 !Number.isSafeInteger(d.publisher_key_generation)||d.publisher_key_generation<1||
 typeof d.publisher_public_key_pem!=="string"||
 !Array.isArray(d.challenges)||d.challenges.length>1024)fail("VERIFIER_CORRUPT");
 try{crypto.createPublicKey(d.publisher_public_key_pem)}catch{fail("VERIFIER_CORRUPT")}
 const seen=new Set();
 for(const a of d.challenges){
  if(!exact(a,["challenge","status","response_sha256"])||
   !["PENDING","CONSUMED"].includes(a.status)||
   (a.status==="PENDING"&&a.response_sha256!==null)||
   (a.status==="CONSUMED"&&!H.test(a.response_sha256)))fail("VERIFIER_CORRUPT");
  try{challengeBytes(a.challenge)}catch{fail("VERIFIER_CORRUPT")}
  if(seen.has(a.challenge.nonce)||a.challenge.verifier_id!==d.verifier_id||
   a.challenge.publisher_id!==d.publisher_id)fail("VERIFIER_CORRUPT");
  seen.add(a.challenge.nonce);
 }
 return d;
}
function read(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"freshness.json"),"utf8"))}
 catch{fail("VERIFIER_UNREADABLE")}
 return validate(d);
}
function write(dir,d){
 const temp=path.join(dir,".fresh-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(temp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(temp,path.join(dir,"freshness.json"));
  const parent=fs.openSync(dir,"r");try{fs.fsyncSync(parent)}finally{fs.closeSync(parent)}
 }catch{try{fs.unlinkSync(temp)}catch{}fail("VERIFIER_WRITE_FAILED")}
}
function init(dir,{verifier_id,publisher_id,publisher_public_key}){
 if(![verifier_id,publisher_id].every(v=>typeof v==="string"&&ID.test(v))||!publisher_public_key)fail("VERIFIER_CONFIG");
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 lock(dir,()=>{
  if(fs.existsSync(path.join(dir,"freshness.json")))fail("VERIFIER_EXISTS");
  write(dir,{schema:SCHEMA,revision:0,last_tick:0,verifier_id,publisher_id,
   publisher_key_generation:1,publisher_public_key_pem:pem(publisher_public_key),challenges:[]});
 });
}
function tickCheck(d,tick){
 if(!Number.isSafeInteger(tick)||tick<0)fail("TICK_INVALID");
 if(tick<d.last_tick)fail("LOGICAL_TICK_ROLLBACK");
}
function issue(dir,c,{tick}={}){
 challengeBytes(c);
 return lock(dir,()=>{
  const d=read(dir);tickCheck(d,tick);
  if(tick!==c.issued_tick)fail("ISSUE_TICK_MISMATCH");
  if(c.verifier_id!==d.verifier_id||c.publisher_id!==d.publisher_id)fail("CHALLENGE_IDENTITY");
  if(d.challenges.some(a=>a.challenge.nonce===c.nonce))fail("NONCE_REISSUE");
  if(d.challenges.length>=1024)fail("CHALLENGE_CAPACITY_HOLD");
  d.challenges.push({challenge:c,status:"PENDING",response_sha256:null});
  d.last_tick=tick;d.revision++;write(dir,d);
  return {decision:"PENDING_FRESHNESS",nonce:c.nonce};
 });
}
function rotate(dir,{newPublicKey,tick}={}){
 if(!newPublicKey)fail("ROTATION_KEY_REQUIRED");
 return lock(dir,()=>{
  const d=read(dir);tickCheck(d,tick);
  const next=pem(newPublicKey);
  if(next===d.publisher_public_key_pem)fail("ROTATION_KEY_REUSE");
  d.publisher_public_key_pem=next;d.publisher_key_generation++;
  d.last_tick=tick;d.revision++;write(dir,d);
  return {decision:"PIN_ROTATED",generation:d.publisher_key_generation};
 });
}
function consume(dir,challenge,response,signedSnapshot,snapshotPins,{tick,connected}={}){
 challengeBytes(challenge);
 if(connected!==true||!signedSnapshot||!response)fail("PUBLISHER_UNAVAILABLE");
 if(!exact(response,["payload","signature"]))fail("RESPONSE_ENVELOPE");
 const proof=response.payload;
 responseBytes(proof);
 return lock(dir,()=>{
  const d=read(dir);tickCheck(d,tick);
  const entry=d.challenges.find(a=>a.challenge.nonce===challenge.nonce);
  if(!entry)fail("CHALLENGE_UNKNOWN");
  if(entry.status==="CONSUMED")fail("CHALLENGE_REPLAY");
  if(hash(challengeBytes(entry.challenge))!==hash(challengeBytes(challenge)))fail("CHALLENGE_CONFLICT");
  if(tick>=challenge.expires_tick)fail("FRESHNESS_EXPIRED");
  if(proof.verifier_id!==challenge.verifier_id||proof.publisher_id!==challenge.publisher_id||
   proof.nonce!==challenge.nonce||proof.issued_tick!==challenge.issued_tick||
   proof.expires_tick!==challenge.expires_tick)fail("RESPONSE_BINDING");
  if(proof.publisher_key_generation!==d.publisher_key_generation)fail("PUBLISHER_ROTATION_FENCE");
  if(typeof response.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(response.signature)||
   !crypto.verify(null,responseBytes(proof),crypto.createPublicKey(d.publisher_public_key_pem),
   Buffer.from(response.signature,"base64")))fail("RESPONSE_SIGNATURE");
  const digest=snapshots.checkSigned(signedSnapshot,snapshotPins);
  if(proof.snapshot_sha256!==digest||proof.snapshot_generation!==signedSnapshot.payload.generation)
   fail("SNAPSHOT_BINDING");
  if(proof.snapshot_generation<challenge.minimum_generation)fail("STALE_PUBLISHER_SNAPSHOT");
  entry.status="CONSUMED";entry.response_sha256=hash(responseBytes(proof));
  d.last_tick=tick;d.revision++;write(dir,d);
  return {decision:"HOLD",fixture_fresh_challenge_verified:true,
   response_generation:proof.snapshot_generation,nonce_consumed:true,
   independent_publisher_authenticated:false,external_custody:false,utc_authority:false};
 });
}
function inspect(dir){return lock(dir,()=>read(dir))}
module.exports={init,issue,rotate,consume,inspect,challengeBytes,responseBytes,responseForTest};
