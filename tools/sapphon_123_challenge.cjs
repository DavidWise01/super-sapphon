"use strict";
/* SAPPHON-123 — bounded local two-role challenge response; synthetic only.
 * Atomic local nonce consumption under an exclusive directory lock.
 * Caller-provided logical ticks are NOT physical time or UTC.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const H=/^[a-f0-9]{64}$/,ID=/^[a-z0-9-]{4,64}$/,MAX=1024;
const fail=x=>{throw Error(x)};
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const DIGEST=b=>crypto.createHash("sha256").update(b).digest("hex");
const F=["schema","nonce","issuer_id","operator_id","custodian_id","checkpoint_sha256","generation","issued_tick","expires_tick"];
function challengeBytes(c){
 if(!exact(c,F)||c.schema!=="sapphon-123-challenge-v1"||!H.test(c.nonce)||
 ![c.issuer_id,c.operator_id,c.custodian_id].every(x=>typeof x==="string"&&ID.test(x))||
 !H.test(c.checkpoint_sha256)||!Number.isSafeInteger(c.generation)||c.generation<1||
 !Number.isSafeInteger(c.issued_tick)||c.issued_tick<0||
 !Number.isSafeInteger(c.expires_tick)||c.expires_tick<=c.issued_tick||
 c.expires_tick-c.issued_tick>300000)fail("CHALLENGE_FIELDS");
 return Buffer.from(JSON.stringify(F.map(k=>c[k])),"utf8");
}
function signForTest(c,role,key){
 if(!["ISSUER","OPERATOR"].includes(role))fail("ROLE_INVALID");
 return {schema:"sapphon-123-response-v1",role,challenge_sha256:DIGEST(challengeBytes(c)),
  signature:crypto.sign(null,Buffer.from(JSON.stringify([role,DIGEST(challengeBytes(c))])),key).toString("base64")};
}
function verify(c,response,role,registry,originRoot){
 if(!exact(response,["schema","role","challenge_sha256","signature"])||
 response.schema!=="sapphon-123-response-v1"||response.role!==role||
 response.challenge_sha256!==DIGEST(challengeBytes(c)))fail("RESPONSE_BINDING");
 const id=role==="ISSUER"?c.issuer_id:c.operator_id;
 if(!registry||!Object.hasOwn(registry,id))fail("ROLE_NOT_PINNED");
 const r=registry[id];
 if(r.revoked===true)fail("ROLE_REVOKED");
 if(!r.publicKey||!ID.test(r.control_root)||r.control_root!==originRoot)fail("ROLE_ORIGIN_MISMATCH");
 if(typeof response.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(response.signature)||
 !crypto.verify(null,Buffer.from(JSON.stringify([role,response.challenge_sha256])),
 r.publicKey,Buffer.from(response.signature,"base64")))fail("RESPONSE_SIGNATURE");
 return r;
}
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("SESSION_STORE_MISSING");
 const p=path.join(dir,"lock");try{fs.mkdirSync(p)}catch{fail("SESSION_STORE_BUSY")}
 try{return fn()}finally{fs.rmdirSync(p)}
}
function validate(d){
 if(!exact(d,["schema","revision","last_tick","sessions"])||
 d.schema!=="sapphon-123-nonce-sessions-v1"||
 !Number.isSafeInteger(d.revision)||d.revision<0||
 !Number.isSafeInteger(d.last_tick)||d.last_tick<0||
 !Array.isArray(d.sessions)||d.sessions.length>MAX)fail("SESSION_STORE_CORRUPT");
 const unique=new Set();
 for(const s of d.sessions){
  if(!exact(s,["nonce","challenge_sha256","issued_tick","expires_tick","status","result_sha256"])||
  !H.test(s.nonce)||unique.has(s.nonce)||!H.test(s.challenge_sha256)||
  !Number.isSafeInteger(s.issued_tick)||s.issued_tick<0||
  !Number.isSafeInteger(s.expires_tick)||s.expires_tick<=s.issued_tick||
  !["ISSUED","USED"].includes(s.status)||
  (s.status==="ISSUED"&&s.result_sha256!==null)||
  (s.status==="USED"&&!H.test(s.result_sha256)))fail("SESSION_STORE_CORRUPT");
  unique.add(s.nonce);
 }
 return d;
}
function read(dir){
 try{return validate(JSON.parse(fs.readFileSync(path.join(dir,"sessions.json"),"utf8")))}
 catch(e){if(e.message==="SESSION_STORE_CORRUPT")throw e;fail("SESSION_STORE_UNREADABLE")}
}
function write(dir,d){
 const tmp=path.join(dir,".sapphon123-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,path.join(dir,"sessions.json"));
  const p=fs.openSync(dir,"r");try{fs.fsyncSync(p)}finally{fs.closeSync(p)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("SESSION_STORE_WRITE_FAILED")}
}
function init(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 return lock(dir,()=>{
  if(fs.existsSync(path.join(dir,"sessions.json")))fail("SESSION_STORE_EXISTS");
  write(dir,{schema:"sapphon-123-nonce-sessions-v1",revision:0,last_tick:0,sessions:[]});
 });
}
function issue(dir,c,{tick}){
 const digest=DIGEST(challengeBytes(c));
 if(!Number.isSafeInteger(tick)||tick<0||tick!==c.issued_tick)fail("ISSUE_TICK_MISMATCH");
 return lock(dir,()=>{
  const d=read(dir);
  if(tick<d.last_tick)fail("LOGICAL_TICK_ROLLBACK");
  if(d.sessions.some(s=>s.nonce===c.nonce))fail("NONCE_ALREADY_ISSUED");
  if(d.sessions.length>=MAX)fail("SESSION_CAPACITY_HOLD");
  d.sessions.push({nonce:c.nonce,challenge_sha256:digest,issued_tick:c.issued_tick,
   expires_tick:c.expires_tick,status:"ISSUED",result_sha256:null});
  d.last_tick=tick;d.revision++;write(dir,d);
  return {decision:"TEST_CHALLENGE_ISSUED",nonce:c.nonce,utc_authority:false};
 });
}
function resolve(dir,c,responses,registry,{issuer_root,operator_root,source_roots=[],custodian_root,tick}){
 const digest=DIGEST(challengeBytes(c));
 if(!Number.isSafeInteger(tick)||tick<0)fail("TICK_INVALID");
 if(!exact(responses,["issuer","operator"])||
 ![issuer_root,operator_root,custodian_root].every(x=>typeof x==="string"&&ID.test(x))||
 !Array.isArray(source_roots)||!source_roots.every(x=>typeof x==="string"&&ID.test(x)))
 fail("CONTROL_CONTEXT_INVALID");
 return lock(dir,()=>{
  const d=read(dir),s=d.sessions.find(x=>x.nonce===c.nonce);
  if(!s)fail("NONCE_NOT_ISSUED");
  if(s.status==="USED")fail("NONCE_REPLAY");
  if(s.challenge_sha256!==digest)fail("CHALLENGE_CONFLICT");
  if(tick<d.last_tick||tick<c.issued_tick)fail("LOGICAL_TICK_ROLLBACK");
  if(tick>=s.expires_tick)fail("CHALLENGE_EXPIRED");
  const i=verify(c,responses.issuer,"ISSUER",registry,issuer_root);
  const o=verify(c,responses.operator,"OPERATOR",registry,operator_root);
  const roots=[issuer_root,operator_root,custodian_root];
  if(new Set(roots).size!==3||roots.some(x=>source_roots.includes(x))||
     i.control_group===o.control_group)fail("ROLE_CONTROL_CONVERGENCE");
  s.status="USED";s.result_sha256=DIGEST(Buffer.from(JSON.stringify([digest,responses.issuer.signature,responses.operator.signature])));
  d.last_tick=tick;d.revision++;write(dir,d);
  return {schema:"sapphon-123-synthetic-challenge-result-v1",decision:"HOLD",
    nonce_consumed:true,issuer_signature_valid:true,operator_signature_valid:true,
    declared_role_separation:true,external_custody_authenticated:false,
    physical_clock_qualified:false,utc_authority:false};
 });
}
function inspect(dir){return lock(dir,()=>read(dir))}
module.exports={challengeBytes,signForTest,init,issue,resolve,inspect};
