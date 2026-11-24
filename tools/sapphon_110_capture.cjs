"use strict";
/* SAPPHON-110: independently provisioned capture-agent contract.
   No live HTTPS capture is performed: test signatures and files demonstrate
   consistency only. External ownership, TLS and UTC remain HOLD. */
const crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path");
const {canonical:transcriptBytes,verifyTranscripts}=require("./sapphon_109_transcript.cjs");
const H=/^[a-f0-9]{64}$/,I=/^[a-z0-9-]{4,64}$/;
const fail=x=>{throw Error(x)};
const digest=b=>crypto.createHash("sha256").update(b).digest("hex");
const pubDer=k=>(k.type==="public"?k:crypto.createPublicKey(k)).export({type:"spki",format:"der"});
function exact(o,keys,error){if(!o||Array.isArray(o)||typeof o!=="object"||Object.keys(o).sort().join("|")!==keys.slice().sort().join("|"))fail(error)}
function enrollmentForTest(agent_id,owner_root,key_id,publicKey){
 return {schema:"sapphon-capture-agent-enrollment-v1",agent_id,owner_root,key_id,
  public_key_spki_sha256:digest(pubDer(publicKey)),enrollment_mode:"synthetic-fixture"};
}
function challengeFor(agent_id,session_id,acquisition_id,transcript,nonce=crypto.randomBytes(32).toString("hex")){
 const out={schema:"sapphon-capture-session-challenge-v1",agent_id,session_id,acquisition_id,
  transcript_sha256:digest(transcriptBytes(transcript)),nonce};
 challengeBytes(out);return out;
}
function challengeBytes(p){
 const k=["schema","agent_id","session_id","acquisition_id","transcript_sha256","nonce"];
 exact(p,k,"CHALLENGE_FIELDS");
 if(p.schema!=="sapphon-capture-session-challenge-v1"||
 ![p.agent_id,p.session_id,p.acquisition_id].every(x=>typeof x==="string"&&I.test(x))||
 !H.test(p.transcript_sha256)||!H.test(p.nonce))fail("CHALLENGE_FIELDS");
 return Buffer.from(JSON.stringify(k.map(x=>p[x])),"utf8");
}
function evidenceBytes(payload){
 const k=["schema","challenge_sha256","transcript_sha256","capture_sha256","capture_bytes",
 "agent_id","owner_root","key_id","retention_ref","peer_spki_sha256"];
 exact(payload,k,"CAPTURE_FIELDS");
 if(payload.schema!=="sapphon-capture-evidence-v1"||
 ![payload.agent_id,payload.owner_root,payload.key_id].every(x=>typeof x==="string"&&I.test(x))||
 ![payload.challenge_sha256,payload.transcript_sha256,payload.capture_sha256,payload.peer_spki_sha256].every(x=>typeof x==="string"&&H.test(x))||
 !Number.isSafeInteger(payload.capture_bytes)||payload.capture_bytes<1||payload.capture_bytes>262144||
 typeof payload.retention_ref!=="string"||!/^fixture:[a-z0-9-]{4,64}$/.test(payload.retention_ref))fail("CAPTURE_FIELDS");
 return Buffer.from(JSON.stringify(k.map(x=>payload[x])),"utf8");
}
function signForTest(payload,privateKey){return {payload,signature:crypto.sign(null,evidenceBytes(payload),privateKey).toString("base64")}}
function verifyCapture({bytes,transcript,acquisitionReceipt,transportRegistry,transportTranscript,
  challenge,capture,agentEnrollment,agentRegistry,issuedChallenges,consumedNonces}){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>262144)fail("CAPTURE_BYTES_INVALID");
 if(!(issuedChallenges instanceof Map)||!(consumedNonces instanceof Set))fail("TRUSTED_SESSION_STORE_REQUIRED");
 const transport=verifyTranscripts(bytes,[acquisitionReceipt],[transportTranscript],transportRegistry);
 if(transport.decision!=="HOLD")fail("UNEXPECTED_TRANSPORT_AUTHORITY");
 exact(agentEnrollment,["schema","agent_id","owner_root","key_id","public_key_spki_sha256","enrollment_mode"],"ENROLLMENT_FIELDS");
 if(agentEnrollment.schema!=="sapphon-capture-agent-enrollment-v1"||agentEnrollment.enrollment_mode!=="synthetic-fixture"||
 ![agentEnrollment.agent_id,agentEnrollment.owner_root,agentEnrollment.key_id].every(x=>typeof x==="string"&&I.test(x))||
 !H.test(agentEnrollment.public_key_spki_sha256))fail("ENROLLMENT_FIELDS");
 if(!agentRegistry||!Object.hasOwn(agentRegistry,agentEnrollment.key_id))fail("UNREGISTERED_AGENT");
 const r=agentRegistry[agentEnrollment.key_id];
 if(r.revoked===true)fail("REVOKED_AGENT");
 if(r.agent_id!==agentEnrollment.agent_id||r.owner_root!==agentEnrollment.owner_root||
 !r.publicKey||digest(pubDer(r.publicKey))!==agentEnrollment.public_key_spki_sha256)fail("AGENT_ENROLLMENT_MISMATCH");
 const challengeRaw=challengeBytes(challenge),challengeHash=digest(challengeRaw);
 if(challenge.agent_id!==agentEnrollment.agent_id||
 challenge.session_id!==transportTranscript.payload.session_id||
 challenge.acquisition_id!==acquisitionReceipt.payload.acquisition_id||
 challenge.transcript_sha256!==digest(transcriptBytes(transcript)))fail("SESSION_BINDING");
 if(consumedNonces.has(challenge.nonce))fail("CAPTURE_SESSION_REPLAY");
 if(issuedChallenges.get(challenge.nonce)!==challengeHash)fail("CHALLENGE_NOT_ISSUED");
 exact(capture,["payload","signature"],"CAPTURE_ENVELOPE");
 const p=capture.payload,raw=evidenceBytes(p);
 if(p.agent_id!==agentEnrollment.agent_id||p.owner_root!==agentEnrollment.owner_root||
 p.key_id!==agentEnrollment.key_id||p.challenge_sha256!==challengeHash||
 p.transcript_sha256!==challenge.transcript_sha256||
 p.peer_spki_sha256!==transcript.peer_spki_sha256)fail("CAPTURE_BINDING");
 if(p.capture_sha256!==digest(bytes)||p.capture_bytes!==bytes.length)fail("CAPTURE_BYTE_MISMATCH");
 if(typeof capture.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(capture.signature)||
 !crypto.verify(null,raw,r.publicKey,Buffer.from(capture.signature,"base64")))fail("CAPTURE_SIGNATURE");
 // An in-memory test store is not a durable external anchor: persistent custody
 // must be supplied by an authenticated outside organization.
 consumedNonces.add(challenge.nonce);
 return {schema:"sapphon-110-capture-assessment-v1",decision:"HOLD",
  cryptographic_test_passed:true,session_consumed_in_supplied_store:true,
  capture_bytes:bytes.length,capture_sha256:p.capture_sha256,
  agent_owner_root:p.owner_root,transport_source_root:acquisitionReceipt.payload.source_root,
  independent_capture_agent_verified:false,external_retention_verified:false,
  real_network_acquisition_verified:false,utc_authority:false};
}
module.exports={enrollmentForTest,challengeFor,challengeBytes,evidenceBytes,signForTest,verifyCapture};
