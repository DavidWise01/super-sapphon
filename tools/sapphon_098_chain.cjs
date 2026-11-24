"use strict";
/* SAPPHON-098: chain continuity + signed key rotations + root-ancestry grouping.
   Offline synthetic verification, not independent source certification or UTC.
   Only append a new chain state after every preflight check succeeds. */
const crypto=require("node:crypto");
const {verifyEnvelope}=require("./sapphon_097_auth.cjs");
const HEX=/^[a-f0-9]{64}$/;
function fail(code){throw Error(code)}
function keyFingerprint(publicKey){
 return crypto.createHash("sha256").update((publicKey.type==="public"?publicKey:crypto.createPublicKey(publicKey)).export({type:"spki",format:"der"})).digest("hex");
}
function rotationMessage(r){
 if(!r||r.schema!=="sapphon-key-rotation-v1" ||
    !/^[a-z0-9-]{4,64}$/.test(r.source_id||"") ||
    !/^[a-z0-9-]{4,64}$/.test(r.from_key||"") ||
    !/^[a-z0-9-]{4,64}$/.test(r.to_key||"") ||
    !HEX.test(r.to_fingerprint||"") ||
    !Number.isSafeInteger(r.effective_seq)||r.effective_seq<1 ||
    !Number.isSafeInteger(r.generation)||r.generation<1 ||
    typeof r.ancestry_root!=="string" || !/^[a-z0-9-]{4,64}$/.test(r.ancestry_root))
     fail("BAD_ROTATION");
 return Buffer.from(JSON.stringify([r.schema,r.source_id,r.ancestry_root,r.from_key,r.to_key,
   r.to_fingerprint,r.effective_seq,r.generation]));
}
function rotate(state,certificate,nextPublicKey){
 const next=state.trust[certificate?.to_key];
 if(!next||!nextPublicKey||!state.trust[certificate.from_key])fail("UNKNOWN_ROTATION_KEY");
 if(certificate.from_key!==state.activeKey ||certificate.to_key===certificate.from_key)
   fail("ROTATION_ORDER");
 if(certificate.source_id!==state.sourceId||certificate.ancestry_root!==state.root)
   fail("ROTATION_ANCESTRY");
 if(certificate.effective_seq!==state.nextSeq ||certificate.generation!==state.generation+1)
   fail("ROTATION_BOUNDARY");
 const signer=state.trust[certificate.from_key];
 if(signer.revoked)fail("REVOKED_ROTATOR");
 if(next.role!==signer.role ||next.source_id!==state.sourceId||next.ancestry_root!==state.root)
   fail("ROTATION_ROLE");
 if(keyFingerprint(nextPublicKey)!==certificate.to_fingerprint ||
    keyFingerprint(next.publicKey)!==certificate.to_fingerprint)fail("KEY_SUBSTITUTION");
 if(typeof certificate.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(certificate.signature))
   fail("ROTATION_SIGNATURE");
 if(!crypto.verify(null,rotationMessage(certificate),signer.publicKey,
                  Buffer.from(certificate.signature,"base64")))fail("ROTATION_SIGNATURE");
 return {...state,activeKey:certificate.to_key,generation:certificate.generation,
   rotations:[...state.rotations,Object.freeze({...certificate})]};
}
function signRotationForTest(unsigned,privateKey){
 return {...unsigned,signature:crypto.sign(null,rotationMessage(unsigned),privateKey).toString("base64")};
}
function appendBatch(state,envelope){
 const result=verifyEnvelope(envelope,state.trust);
 const p=envelope.payload;
 if(envelope.key_id!==state.activeKey)fail("INACTIVE_KEY");
 if(p.source_id!==state.sourceId || p.generation!==state.generation)fail("WRONG_GENERATION");
 if(p.start_seq!==state.nextSeq)fail("SEQUENCE_GAP_OR_REPLAY");
 if(p.prev_hash!==state.lastHash)fail("PREDECESSOR_MISMATCH");
 if(p.record_hashes.some(h=>state.used.has(h)) ||
    new Set(p.record_hashes).size!==p.record_hashes.length)fail("DUPLICATE_IDENTITY");
 const used=new Set(state.used);p.record_hashes.forEach(h=>used.add(h));
 return {...state,nextSeq:state.nextSeq+p.record_hashes.length,
   lastHash:p.record_hashes.at(-1),used,
   batches:[...state.batches,{key:envelope.key_id,start:p.start_seq,
     end:p.start_seq+p.record_hashes.length-1,status:result.status,root:state.root}]};
}
function initialize({sourceId,root,activeKey,trust}){
 if(!trust[activeKey]||trust[activeKey].source_id!==sourceId||
    trust[activeKey].ancestry_root!==root||trust[activeKey].revoked)
   fail("INVALID_GENESIS");
 return {sourceId,root,activeKey,trust,generation:0,nextSeq:0,lastHash:null,
   used:new Set(),batches:[],rotations:[]};
}
function distinctAncestryRoots(states){
 return new Set(states.map(s=>s.root)).size;
}
module.exports={keyFingerprint,rotationMessage,rotate,signRotationForTest,appendBatch,initialize,distinctAncestryRoots};
