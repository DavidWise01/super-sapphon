"use strict";
/* SAPPHON-124 — local delayed dual-role response admission.
 * Issuance and completion share ONE lock and durable state file; a revocation
 * or generation rotation between them fences the old signatures.
 * Synthetic ticks and pinned fixture identities: never real UTC/custody.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {challengeBytes}=require("./sapphon_123_challenge.cjs");
const ID=/^[a-z0-9-]{4,64}$/,H=/^[a-f0-9]{64}$/,LIMIT=1024;
const fail=x=>{throw Error(x)};
const hash=x=>crypto.createHash("sha256").update(x).digest("hex");
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const ROLES=["ISSUER","OPERATOR"],SCHEMA="sapphon-124-revocation-v1";
const proofBytes=(role,challengeHash,generation)=>Buffer.from(JSON.stringify(["sapphon-124-response-v1",role,challengeHash,generation]));
const pem=k=>(k.type==="public"?k:crypto.createPublicKey(k)).export({type:"spki",format:"pem"}).toString();
function signedForTest(challenge,role,generation,key){
 if(!ROLES.includes(role)||!Number.isSafeInteger(generation)||generation<1)fail("RESPONSE_FIELDS");
 const challenge_sha256=hash(challengeBytes(challenge));
 return {schema:"sapphon-124-role-response-v1",role,generation,challenge_sha256,
 signature:crypto.sign(null,proofBytes(role,challenge_sha256,generation),key).toString("base64")};
}
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("STATE_MISSING");
 const p=path.join(dir,"lock");try{fs.mkdirSync(p)}catch{fail("STATE_BUSY")}
 try{return fn()}finally{fs.rmdirSync(p)}
}
function validate(s){
 if(!exact(s,["schema","revision","tick","roles","challenges","events"])||s.schema!==SCHEMA||
 !Number.isSafeInteger(s.revision)||s.revision<0||
 !Number.isSafeInteger(s.tick)||s.tick<0||
 !exact(s.roles,ROLES)||!Array.isArray(s.challenges)||!Array.isArray(s.events)||
 s.challenges.length>LIMIT||s.events.length>LIMIT)fail("STATE_CORRUPT");
 for(const role of ROLES){
  const r=s.roles[role];
  if(!exact(r,["id","control_root","control_group","generation","public_key_pem","revoked"])||
  !ID.test(r.id)||!ID.test(r.control_root)||!ID.test(r.control_group)||
  !Number.isSafeInteger(r.generation)||r.generation<1||typeof r.public_key_pem!=="string"||
  typeof r.revoked!=="boolean")fail("STATE_CORRUPT");
  try{crypto.createPublicKey(r.public_key_pem)}catch{fail("STATE_CORRUPT")}
 }
 const nonces=new Set();
 for(const c of s.challenges){
  if(!exact(c,["challenge","digest","issuer_generation","operator_generation","status","result_sha256"])||
  !H.test(c.challenge.nonce)||nonces.has(c.challenge.nonce)||hash(challengeBytes(c.challenge))!==c.digest||
  !Number.isSafeInteger(c.issuer_generation)||c.issuer_generation<1||
  !Number.isSafeInteger(c.operator_generation)||c.operator_generation<1||
  !["PENDING","CONSUMED"].includes(c.status)||
  (c.status==="PENDING"&&c.result_sha256!==null)||
  (c.status==="CONSUMED"&&!H.test(c.result_sha256)))fail("STATE_CORRUPT");
  nonces.add(c.challenge.nonce);
 }
 for(const e of s.events){
  if(!exact(e,["type","role","generation","tick"])||
  !["ROTATE","REVOKE"].includes(e.type)||!ROLES.includes(e.role)||
  !Number.isSafeInteger(e.generation)||!Number.isSafeInteger(e.tick))fail("STATE_CORRUPT");
 }
 return s;
}
function read(dir){
 let o;try{o=JSON.parse(fs.readFileSync(path.join(dir,"state.json"),"utf8"))}catch{fail("STATE_UNREADABLE")}
 return validate(o);
}
function write(dir,s){
 const file=path.join(dir,"state.json"),tmp=path.join(dir,".state-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(s)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,file);
  const df=fs.openSync(dir,"r");try{fs.fsyncSync(df)}finally{fs.closeSync(df)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("STATE_WRITE_FAILED")}
}
function init(dir,roles){
 if(!exact(roles,ROLES))fail("ROLE_SET_INVALID");
 const assigned={};
 for(const role of ROLES){
  const r=roles[role];
  if(!exact(r,["id","control_root","control_group","publicKey"])||
  ![r.id,r.control_root,r.control_group].every(x=>typeof x==="string"&&ID.test(x)))fail("ROLE_SET_INVALID");
  assigned[role]={id:r.id,control_root:r.control_root,control_group:r.control_group,
   generation:1,public_key_pem:pem(r.publicKey),revoked:false};
 }
 if(assigned.ISSUER.id===assigned.OPERATOR.id)fail("ROLE_ID_COLLISION");
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 return lock(dir,()=>{
  if(fs.existsSync(path.join(dir,"state.json")))fail("STATE_EXISTS");
  write(dir,{schema:SCHEMA,revision:0,tick:0,roles:assigned,challenges:[],events:[]});
 });
}
function atTick(s,tick){
 if(!Number.isSafeInteger(tick)||tick<0)fail("TICK_INVALID");
 if(tick<s.tick)fail("LOGICAL_TICK_ROLLBACK");
}
function change(dir,role,action,{tick,newPublicKey=null}={}){
 if(!ROLES.includes(role)||!["ROTATE","REVOKE"].includes(action))fail("CHANGE_INVALID");
 return lock(dir,()=>{
  const s=read(dir);atTick(s,tick);
  const current=s.roles[role];
  if(current.revoked)fail("ROLE_ALREADY_REVOKED");
  if(action==="ROTATE"){
   if(!newPublicKey)fail("ROTATION_KEY_MISSING");
   const next=pem(newPublicKey);
   if(next===current.public_key_pem)fail("ROTATION_KEY_REUSED");
   current.generation++;current.public_key_pem=next;
  }else{
   if(newPublicKey!==null)fail("REVOKE_KEY_NOT_ALLOWED");
   current.revoked=true;
  }
  if(s.events.length>=LIMIT)fail("EVENT_CAPACITY_HOLD");
  s.events.push({type:action,role,generation:current.generation,tick});
  s.tick=tick;s.revision++;write(dir,s);
  return {decision:"TEST_ROLE_UPDATED",role,action,generation:current.generation,revoked:current.revoked};
 });
}
function issue(dir,c,{tick}={}){
 const digest=hash(challengeBytes(c));
 return lock(dir,()=>{
  const s=read(dir);atTick(s,tick);
  if(tick!==c.issued_tick)fail("ISSUANCE_TICK_MISMATCH");
  if(c.issuer_id!==s.roles.ISSUER.id||c.operator_id!==s.roles.OPERATOR.id)fail("ROLE_ID_MISMATCH");
  if(s.roles.ISSUER.revoked||s.roles.OPERATOR.revoked)fail("ROLE_REVOKED");
  if(s.challenges.some(x=>x.challenge.nonce===c.nonce))fail("NONCE_ALREADY_ISSUED");
  if(s.challenges.length>=LIMIT)fail("CHALLENGE_CAPACITY_HOLD");
  s.challenges.push({challenge:c,digest,issuer_generation:s.roles.ISSUER.generation,
   operator_generation:s.roles.OPERATOR.generation,status:"PENDING",result_sha256:null});
  s.tick=tick;s.revision++;write(dir,s);
  return {decision:"TEST_CHALLENGE_PENDING",issuer_generation:s.roles.ISSUER.generation,
   operator_generation:s.roles.OPERATOR.generation};
 });
}
function verify(response,role,entry,current){
 const expected=role==="ISSUER"?entry.issuer_generation:entry.operator_generation;
 if(!exact(response,["schema","role","generation","challenge_sha256","signature"])||
 response.schema!=="sapphon-124-role-response-v1"||response.role!==role||
 response.challenge_sha256!==entry.digest||response.generation!==expected)
  fail("RESPONSE_BINDING");
 if(current.revoked)fail("ROLE_REVOKED");
 if(current.generation!==expected)fail("STALE_CREDENTIAL_GENERATION");
 if(typeof response.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(response.signature)||
 !crypto.verify(null,proofBytes(role,entry.digest,expected),crypto.createPublicKey(current.public_key_pem),
 Buffer.from(response.signature,"base64")))fail("RESPONSE_SIGNATURE");
}
function complete(dir,c,responses,{tick,source_roots=[]}={}){
 const digest=hash(challengeBytes(c));
 if(!exact(responses,["issuer","operator"])||!Array.isArray(source_roots)||
 !source_roots.every(x=>typeof x==="string"&&ID.test(x)))fail("COMPLETION_CONTEXT_INVALID");
 return lock(dir,()=>{
  const s=read(dir);atTick(s,tick);
  const entry=s.challenges.find(x=>x.challenge.nonce===c.nonce);
  if(!entry)fail("NONCE_NOT_ISSUED");
  if(entry.status==="CONSUMED")fail("NONCE_REPLAY");
  if(entry.digest!==digest)fail("CHALLENGE_CONFLICT");
  if(tick>=c.expires_tick)fail("CHALLENGE_EXPIRED");
  for(const role of ROLES)if(s.roles[role].revoked)fail("ROLE_REVOKED");
  if(s.roles.ISSUER.generation!==entry.issuer_generation||
     s.roles.OPERATOR.generation!==entry.operator_generation)fail("STALE_CREDENTIAL_GENERATION");
  verify(responses.issuer,"ISSUER",entry,s.roles.ISSUER);
  verify(responses.operator,"OPERATOR",entry,s.roles.OPERATOR);
  if(s.roles.ISSUER.control_group===s.roles.OPERATOR.control_group||
     s.roles.ISSUER.control_root===s.roles.OPERATOR.control_root||
     ROLES.some(r=>source_roots.includes(s.roles[r].control_root)))fail("ROLE_CONTROL_CONVERGENCE");
  entry.status="CONSUMED";
  entry.result_sha256=hash(Buffer.from(JSON.stringify([digest,responses.issuer.signature,responses.operator.signature])));
  s.tick=tick;s.revision++;write(dir,s);
  return {decision:"HOLD",nonce_consumed:true,verified_test_signatures:2,
   externally_qualified:false,physical_clock_qualified:false,utc_authority:false};
 });
}
function inspect(dir){return lock(dir,()=>read(dir))}
module.exports={init,issue,change,complete,inspect,signedForTest};
