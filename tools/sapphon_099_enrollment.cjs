"use strict";
/* SAPPHON-099: append-only, governance-signed source identity lifecycle.
   Separates enrollment authority from observation signing keys. Not independent
   attestation and not authority to declare a clock reading correct. */
const crypto=require("node:crypto");
const {keyFingerprint}=require("./sapphon_098_chain.cjs");
const HASH=/^[0-9a-f]{64}$/;
const ID=/^[a-z0-9-]{4,64}$/;
const TYPES=new Set(["ENROLL","REVOKE","REENROLL"]);
function err(code){throw Error(code)}
function eventBytes(event){
 const keys=["type","source_id","ancestry_root","role","key_id","public_key_pem","reason","generation","index","prev_event_hash"];
 if(!event||typeof event!=="object"||Object.keys(event).sort().join("|")!==keys.slice().sort().join("|"))err("BAD_FIELDS");
 const {type,source_id,ancestry_root,role,key_id,public_key_pem,reason,generation,index,prev_event_hash}=event;
 if(!TYPES.has(type)||![source_id,ancestry_root,key_id].every(s=>typeof s==="string"&&ID.test(s)))err("BAD_IDENTITY");
 if(role!=="synthetic-test")err("ROLE_NOT_ENROLLED");
 if(!Number.isSafeInteger(index)||index<0||!Number.isSafeInteger(generation)||generation<0)err("BAD_ORDER");
 if(index===0 ? prev_event_hash!==null : typeof prev_event_hash!=="string"||!HASH.test(prev_event_hash))err("BAD_PREDECESSOR");
 if(type==="REVOKE"){
  if(public_key_pem!==null||typeof reason!=="string"||!reason.trim()||reason.length>256)err("REVOCATION_REASON");
 }else{
  if(reason!==null||typeof public_key_pem!=="string"||!public_key_pem.includes("BEGIN PUBLIC KEY"))err("KEY_MISSING");
  try{const pub=crypto.createPublicKey(public_key_pem);if(pub.asymmetricKeyType!=="ed25519")err("KEY_TYPE")}catch(e){if(e.message==="KEY_TYPE")throw e;err("KEY_TYPE")}
 }
 return Buffer.from(JSON.stringify(keys.map(k=>event[k])),"utf8");
}
function hashEvent(event,signature){
 return crypto.createHash("sha256").update("SAPPHON099\u0000").update(eventBytes(event)).update(Buffer.from(signature,"base64")).digest("hex");
}
function signedForTest(event,govPrivateKey){
 return {event,signature:crypto.sign(null,eventBytes(event),govPrivateKey).toString("base64")};
}
function parseEntries(entries,govPublicKey){
 if(!Array.isArray(entries)||entries.length>4096)err("LEDGER_SIZE");
 const ledger=[],sources=new Map(),usedKeys=new Set();
 let head=null;
 for(let i=0;i<entries.length;i++){
  const e=entries[i],body=e?.event;
  const bytes=eventBytes(body);
  if(body.index!==i||body.prev_event_hash!==head)err("BROKEN_LEDGER_CHAIN");
  if(typeof e.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(e.signature))err("BAD_SIGNATURE");
  if(!crypto.verify(null,bytes,govPublicKey,Buffer.from(e.signature,"base64")))err("GOVERNANCE_SIGNATURE");
  const current=sources.get(body.source_id);
  if(body.type==="ENROLL"){
   if(current||body.generation!==0||usedKeys.has(body.key_id))err("ENROLLMENT_CONFLICT");
   const pub=crypto.createPublicKey(body.public_key_pem);
   usedKeys.add(body.key_id);
   sources.set(body.source_id,{source_id:body.source_id,root:body.ancestry_root,role:body.role,
     key_id:body.key_id,generation:0,status:"ACTIVE",public_key:pub});
  }else if(body.type==="REVOKE"){
   if(!current||current.status!=="ACTIVE"||body.ancestry_root!==current.root||
      body.key_id!==current.key_id||body.generation!==current.generation)err("REVOCATION_CONFLICT");
   sources.set(body.source_id,{...current,status:"REVOKED"});
  }else{
   if(!current||current.status!=="REVOKED"||body.ancestry_root!==current.root||
      body.generation!==current.generation+1||usedKeys.has(body.key_id))err("REENROLLMENT_CONFLICT");
   const pub=crypto.createPublicKey(body.public_key_pem);
   if(keyFingerprint(pub)===keyFingerprint(current.public_key))err("REUSED_COMPROMISED_KEY");
   usedKeys.add(body.key_id);
   sources.set(body.source_id,{...current,key_id:body.key_id,generation:body.generation,
     status:"ACTIVE",public_key:pub});
  }
  const next=hashEvent(body,e.signature);
  ledger.push(Object.freeze({index:i,type:body.type,source_id:body.source_id,
    ancestry_root:body.ancestry_root,key_id:body.key_id,generation:body.generation,
    prev_event_hash:head,event_hash:next}));
  head=next;
 }
 return {head,ledger,sources};
}
function appendEvent(entries,signed,govPublicKey){
 const result=parseEntries([...entries,signed],govPublicKey);
 return {entries:[...entries,signed],...result};
}
function sourceTrust(state,id){
 const source=state.sources.get(id);
 if(!source||source.status!=="ACTIVE")err("SOURCE_NOT_ACTIVE");
 return {[source.key_id]:{source_id:id,role:source.role,publicKey:source.public_key,
   ancestry_root:source.root,revoked:false}};
}
module.exports={eventBytes,hashEvent,signedForTest,parseEntries,appendEvent,sourceTrust};
