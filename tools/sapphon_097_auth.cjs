"use strict";
/* SAPPHON-097: Ed25519 envelope verifier, role separation, explicit trust-store.
   Verification proves possession of a signing key; never proves UTC, source
   independence, observation accuracy or permission to mint clock records. */
const crypto = require("node:crypto");
const HEX=/^[a-f0-9]{64}$/;
function canonical(payload){
  if(!payload || typeof payload!=="object" || Array.isArray(payload))throw Error("PAYLOAD_TYPE");
  const fields=["schema","source_role","source_id","generation","start_seq","prev_hash","record_hashes"];
  if(Object.keys(payload).sort().join("|")!==fields.slice().sort().join("|"))throw Error("PAYLOAD_FIELDS");
  if(payload.schema!=="sapphon-source-envelope-v1")throw Error("SCHEMA");
  if(!["synthetic-test","physical-source"].includes(payload.source_role))throw Error("ROLE");
  if(typeof payload.source_id!=="string" || !/^[a-z0-9-]{4,64}$/.test(payload.source_id))throw Error("SOURCE_ID");
  if(!Number.isSafeInteger(payload.generation)||payload.generation<0)throw Error("GENERATION");
  if(!Number.isSafeInteger(payload.start_seq)||payload.start_seq<0)throw Error("SEQUENCE");
  if(payload.start_seq===0 ? payload.prev_hash!==null : !HEX.test(payload.prev_hash))throw Error("PREDECESSOR");
  if(!Array.isArray(payload.record_hashes)||payload.record_hashes.length<1||payload.record_hashes.length>128||
    !payload.record_hashes.every(h=>typeof h==="string"&&HEX.test(h)))throw Error("HASH_LIST");
  return Buffer.from(JSON.stringify(fields.map(k=>payload[k])),"utf8");
}
function verifyEnvelope(envelope,trust){
  if(!envelope||typeof envelope!=="object"||envelope.schema!=="sapphon-signed-transport-v1")
    throw Error("ENVELOPE_SCHEMA");
  if(Object.keys(envelope).sort().join("|")!==["schema","key_id","payload","signature"].sort().join("|"))
    throw Error("ENVELOPE_FIELDS");
  if(typeof envelope.key_id!=="string"||!trust||!Object.hasOwn(trust,envelope.key_id))
    throw Error("UNKNOWN_SIGNER");
  const bound=trust[envelope.key_id];
  if(bound.revoked===true)throw Error("REVOKED_SIGNER");
  if(typeof envelope.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature))
    throw Error("SIGNATURE_ENCODING");
  const payload=envelope.payload, message=canonical(payload);
  if(bound.source_id!==payload.source_id || bound.role!==payload.source_role)
    throw Error("ROLE_OR_SOURCE_MISMATCH");
  if(!crypto.verify(null,message,bound.publicKey,Buffer.from(envelope.signature,"base64")))
    throw Error("SIGNATURE_INVALID");
  const status=payload.source_role==="physical-source"?"SIGNED_SOURCE_CLAIM_ONLY":"SIGNED_SYNTHETIC_TEST";
  return {status,key_id:envelope.key_id,source_id:payload.source_id,
    start_seq:payload.start_seq,count:payload.record_hashes.length,
    authorized_time:false,independent_witnesses_verified:false};
}
function signForTest(payload,privateKey,key_id){
  return {schema:"sapphon-signed-transport-v1",key_id,payload,
    signature:crypto.sign(null,canonical(payload),privateKey).toString("base64")};
}
module.exports={canonical,verifyEnvelope,signForTest};
