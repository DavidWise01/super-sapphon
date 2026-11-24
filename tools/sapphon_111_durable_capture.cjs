"use strict";
/* SAPPHON-111 — durable capture session and signed synthetic retention receipt.
 * Local atomic journal != independent notarization. The registry is an explicit
 * local trust boundary. No recovery/reset without external operator verification.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {challengeFor,challengeBytes,verifyCapture,evidenceBytes}=require("./sapphon_110_capture.cjs");
const H=/^[a-f0-9]{64}$/,I=/^[a-z0-9-]{4,64}$/;
const SCHEMA="sapphon-111-session-registry-v1",MAX=1024,MAX_TTL=300000;
const fail=c=>{throw Error(c)};
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
const pubDer=k=>(k.type==="public"?k:crypto.createPublicKey(k)).export({format:"der",type:"spki"});
function exact(o,fields,error){if(!o||typeof o!=="object"||Array.isArray(o)||Object.keys(o).sort().join("|")!==fields.slice().sort().join("|"))fail(error)}
function time(now){if(!Number.isSafeInteger(now)||now<0)fail("INVALID_LOCAL_TIME")}
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("STORE_MISSING");
 const lk=path.join(dir,"lock");
 try{fs.mkdirSync(lk)}catch{fail("LOCK_UNAVAILABLE")}
 try{return fn(path.join(dir,"registry.json"))}finally{fs.rmdirSync(lk)}
}
function read(file){
 let d;try{d=JSON.parse(fs.readFileSync(file,"utf8"))}catch{fail("STORE_UNREADABLE")}
 exact(d,["schema","revision","max_seen_ms","records"],"STORE_CORRUPT");
 if(d.schema!==SCHEMA||!Number.isSafeInteger(d.revision)||d.revision<0||
 !Number.isSafeInteger(d.max_seen_ms)||d.max_seen_ms<0||!Array.isArray(d.records)||d.records.length>MAX)fail("STORE_CORRUPT");
 const nonces=new Set();
 for(const r of d.records){
  exact(r,["nonce","challenge_sha256","issued_ms","expires_ms","status","retention_sha256"],"STORE_CORRUPT");
  if(!H.test(r.nonce)||!H.test(r.challenge_sha256)||
   !Number.isSafeInteger(r.issued_ms)||!Number.isSafeInteger(r.expires_ms)||
   r.expires_ms<=r.issued_ms||r.expires_ms-r.issued_ms>MAX_TTL||
   !["ISSUED","CONSUMED"].includes(r.status)||
   (r.status==="ISSUED"&&r.retention_sha256!==null)||
   (r.status==="CONSUMED"&&!H.test(r.retention_sha256))||nonces.has(r.nonce))
   fail("STORE_CORRUPT");
  nonces.add(r.nonce);
 }
 return d;
}
function write(file,d){
 const dir=path.dirname(file),tmp=path.join(dir,".session-"+crypto.randomBytes(8).toString("hex")+".tmp");
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,file);
  const f=fs.openSync(dir,"r");try{fs.fsyncSync(f)}finally{fs.closeSync(f)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("STORE_WRITE_FAILED")}
}
function init(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 lock(dir,file=>{if(fs.existsSync(file))fail("STORE_ALREADY_EXISTS");
  write(file,{schema:SCHEMA,revision:0,max_seen_ms:0,records:[]})});
}
function tick(d,now){
 time(now);
 if(now<d.max_seen_ms)fail("LOCAL_CLOCK_ROLLBACK");
 d.max_seen_ms=now;
}
function issue(dir,identity,transcript,{now,ttl_ms=60000,nonce}={}){
 time(now);
 if(!Number.isSafeInteger(ttl_ms)||ttl_ms<1||ttl_ms>MAX_TTL)fail("TTL_INVALID");
 return lock(dir,file=>{
  const d=read(file);tick(d,now);
  if(d.records.length>=MAX)fail("REGISTRY_FULL");
  const c=challengeFor(identity.agent_id,identity.session_id,identity.acquisition_id,transcript,nonce);
  if(d.records.some(r=>r.nonce===c.nonce))fail("NONCE_ALREADY_ISSUED");
  const expires=now+ttl_ms;if(!Number.isSafeInteger(expires))fail("TIME_OVERFLOW");
  d.records.push({nonce:c.nonce,challenge_sha256:sha(challengeBytes(c)),issued_ms:now,
   expires_ms:expires,status:"ISSUED",retention_sha256:null});
  d.revision++;write(file,d);return {challenge:c,expires_ms:expires};
 });
}
function retentionBytes(p){
 const f=["schema","capture_sha256","challenge_sha256","agent_owner_root","custodian_id","custody_root","retention_id","retention_kind"];
 exact(p,f,"RETENTION_FIELDS");
 if(p.schema!=="sapphon-111-retention-v1"||![p.capture_sha256,p.challenge_sha256].every(x=>typeof x==="string"&&H.test(x))||
 ![p.agent_owner_root,p.custodian_id,p.custody_root,p.retention_id].every(x=>typeof x==="string"&&I.test(x))||
 p.retention_kind!=="synthetic-test-retention")fail("RETENTION_FIELDS");
 return Buffer.from(JSON.stringify(f.map(x=>p[x])),"utf8");
}
function signRetentionTest(payload,key){return {payload,signature:crypto.sign(null,retentionBytes(payload),key).toString("base64")}}
function verifyRetention(ack,registry,capture,challenge,ownerRoot){
 exact(ack,["payload","signature"],"RETENTION_ENVELOPE");
 const p=ack.payload,raw=retentionBytes(p);
 if(!registry||!Object.hasOwn(registry,p.custodian_id))fail("CUSTODIAN_NOT_ENROLLED");
 const r=registry[p.custodian_id];
 if(r.revoked===true)fail("REVOKED_CUSTODIAN");
 if(r.custody_root!==p.custody_root||r.custodian_id!==p.custodian_id)fail("CUSTODY_ROOT_MISMATCH");
 if(p.capture_sha256!==sha(evidenceBytes(capture.payload))||
    p.challenge_sha256!==sha(challengeBytes(challenge))||
    p.agent_owner_root!==ownerRoot)fail("RETENTION_BINDING");
 if(typeof ack.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(ack.signature)||
 !crypto.verify(null,raw,r.publicKey,Buffer.from(ack.signature,"base64")))fail("RETENTION_SIGNATURE");
 return {retention_sha256:sha(raw),custodian_root:p.custody_root,
  custody_independently_authenticated:false};
}
function consume(dir,args,{now,retention,retentionRegistry}={}){
 return lock(dir,file=>{
  const d=read(file);tick(d,now);
  const c=args.challenge;const raw=challengeBytes(c);
  const record=d.records.find(x=>x.nonce===c.nonce);
  if(!record)fail("NONCE_NOT_ISSUED");
  if(record.status!=="ISSUED")fail("DURABLE_CAPTURE_REPLAY");
  if(now>=record.expires_ms)fail("CHALLENGE_EXPIRED");
  if(now<record.issued_ms)fail("LOCAL_CLOCK_ROLLBACK");
  if(sha(raw)!==record.challenge_sha256)fail("ISSUED_CHALLENGE_MISMATCH");
  // In-memory sets are fresh for cryptographic checking; persistent registry
  // under exclusive lock is the authoritative issue/consume sequence.
  const verified=verifyCapture({...args,issuedChallenges:new Map([[c.nonce,record.challenge_sha256]]),
   consumedNonces:new Set()});
  const retained=verifyRetention(retention,retentionRegistry,args.capture,c,verified.agent_owner_root);
  record.status="CONSUMED";record.retention_sha256=retained.retention_sha256;
  d.revision++;write(file,d);
  return {...verified,retention:retained,durable_replay:true,
   independent_custody_confirmed:false,physical_clock_authorized:false,utc_authority:false,decision:"HOLD"};
 });
}
function inspect(dir){return lock(dir,file=>read(file))}
module.exports={init,issue,consume,inspect,retentionBytes,signRetentionTest,verifyRetention,MAX_TTL};
