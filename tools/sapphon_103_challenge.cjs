"use strict";
/* SAPPHON-103 — out-of-band provisioned custodian root + challenge binding.
   A challenge proves access to a provisioned private key within a local
   verifier session. It does NOT establish independent organizational custody
   without separately authenticated provisioning and retention evidence. */
const crypto=require("node:crypto");
const {anchorDigest,verifyReceipts}=require("./sapphon_102_receipts.cjs");
const ID=/^[a-z0-9-]{4,64}$/;
const HEX=/^[a-f0-9]{64}$/;
function fail(code){throw Error(code)}
function keyHash(key){return crypto.createHash("sha256")
  .update((key.type==="public"?key:crypto.createPublicKey(key))
    .export({type:"spki",format:"der"})).digest("hex")}
function normalizeEnrollment(entry){
 const keys=["schema","custodian_id","custody_root","key_id","public_key_fingerprint","provisioning_channel","review_state"];
 if(!entry||Object.keys(entry).sort().join("|")!==keys.slice().sort().join("|")||
    entry.schema!=="sapphon-custodian-enrollment-v1"||
    ![entry.custodian_id,entry.custody_root,entry.key_id].every(x=>typeof x==="string"&&ID.test(x))||
    !HEX.test(entry.public_key_fingerprint)||
    entry.provisioning_channel!=="out-of-band"||
    !["test-fixture","externally-reviewed"].includes(entry.review_state))
    fail("ENROLLMENT_SCHEMA");
 return entry;
}
function enrollForTest({custodian_id,custody_root,key_id},publicKey){
 return {schema:"sapphon-custodian-enrollment-v1",custodian_id,custody_root,key_id,
   public_key_fingerprint:keyHash(publicKey),provisioning_channel:"out-of-band",
   review_state:"test-fixture"};
}
function challengeBytes(p){
 const keys=["schema","anchor_digest","custodian_id","key_id","nonce","purpose","session_id"];
 if(!p||Object.keys(p).sort().join("|")!==keys.slice().sort().join("|")||
    p.schema!=="sapphon-custody-challenge-v1"||
    !HEX.test(p.anchor_digest)||
    ![p.custodian_id,p.key_id,p.session_id].every(x=>typeof x==="string"&&ID.test(x))||
    typeof p.nonce!=="string"||!/^[a-f0-9]{64}$/.test(p.nonce)||
    p.purpose!=="prove-custody-key-possession")
   fail("CHALLENGE_FIELDS");
 return Buffer.from(JSON.stringify(keys.map(k=>p[k])),"utf8");
}
function challengeFor(anchor,{custodian_id,key_id,session_id},nonce=crypto.randomBytes(32).toString("hex")){
 const p={schema:"sapphon-custody-challenge-v1",anchor_digest:anchorDigest(anchor),
   custodian_id,key_id,nonce,purpose:"prove-custody-key-possession",session_id};
 challengeBytes(p);
 return p;
}
function responseForTest(challenge,privateKey){
 return {challenge,signature:crypto.sign(null,challengeBytes(challenge),privateKey).toString("base64")};
}
function verifySession({anchor,receipt,enrollment,response,publicKey,seenNonces,sessionId}){
 if(!(seenNonces instanceof Set))fail("REPLAY_STORE_MISSING");
 const e=normalizeEnrollment(enrollment);
 if(e.review_state!=="test-fixture"&&e.review_state!=="externally-reviewed")fail("REVIEW_STATE");
 if(keyHash(publicKey)!==e.public_key_fingerprint)fail("PROVISIONED_KEY_MISMATCH");
 if(!response||Object.keys(response).sort().join("|")!=="challenge|signature")
   fail("RESPONSE_SCHEMA");
 const p=response.challenge,bytes=challengeBytes(p);
 if(p.anchor_digest!==anchorDigest(anchor)||p.custodian_id!==e.custodian_id||
    p.key_id!==e.key_id||p.session_id!==sessionId)fail("CHALLENGE_BINDING");
 if(seenNonces.has(p.nonce))fail("CHALLENGE_REPLAY");
 if(typeof response.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(response.signature)||
    !crypto.verify(null,bytes,publicKey,Buffer.from(response.signature,"base64")))
     fail("CHALLENGE_SIGNATURE");
 const registry={[e.key_id]:{custodian_id:e.custodian_id,custody_root:e.custody_root,
   publicKey,revoked:false}};
 const checked=verifyReceipts(anchor,[receipt],registry);
 if(checked.receipt_count!==1)fail("MISSING_CUSTODY_RECEIPT");
 // The nonce is consumed only after the whole challenge+receipt transaction passes.
 seenNonces.add(p.nonce);
 return {status:"SIGNED_CHALLENGE_AND_RECEIPT",verified_key_possession:true,
   enrollment_review_state:e.review_state,declared_custody_root:e.custody_root,
   independently_authenticated_organizations:0,independent_custody_confirmed:false,
   external_retention_confirmed:false,utc_authority:false};
}
module.exports={keyHash,enrollForTest,challengeBytes,challengeFor,responseForTest,verifySession};
