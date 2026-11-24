"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {receiptForTest}=require("./sapphon_102_receipts.cjs");
const {enrollForTest,challengeFor,responseForTest,verifySession,keyHash}=require("./sapphon_103_challenge.cjs");
const a=crypto.generateKeyPairSync("ed25519"),b=crypto.generateKeyPairSync("ed25519");
const anchor={schema:"sapphon-external-anchor-v1",key_id:"test-governance-100",
 governance_spki_sha256:"1".repeat(64),head:"2".repeat(64),count:3,
 checkpoint_signature:"A".repeat(86)+"==",independently_retained:false,recorded_utc:null};
const identity={custodian_id:"test-custodian-a",custody_root:"owned-test-root",key_id:"test-custody-key-a"};
const enrollment=enrollForTest(identity,a.publicKey);
const receipt=receiptForTest(anchor,{...identity,receipt_serial:"test-receipt-one"},a.privateKey);
const sessionId="test-session-103";
const challenge=challengeFor(anchor,{...identity,session_id:sessionId},"3".repeat(64));
const response=responseForTest(challenge,a.privateKey);
const copy=x=>JSON.parse(JSON.stringify(x));
const run=(extras={})=>verifySession({anchor,receipt,enrollment,response,publicKey:a.publicKey,
 seenNonces:new Set(),sessionId,...extras});
let n=0;
function check(label,fn){fn();console.log("PASS",++n,label)}
function reject(label,fn,expected){check(label,()=>assert.throws(fn,e=>e.message===expected))}
check("correct provisioned key and bound receipt passes test challenge",()=>{
 const x=run();assert.equal(x.status,"SIGNED_CHALLENGE_AND_RECEIPT");assert.equal(x.verified_key_possession,true);
 assert.equal(x.independent_custody_confirmed,false);assert.equal(x.utc_authority,false);
});
check("enrollment records test fixture rather than independent authentication",()=>{
 assert.equal(enrollment.review_state,"test-fixture");
 assert.equal(keyHash(a.publicKey),enrollment.public_key_fingerprint);
});
check("fresh challenge uses nonempty cryptographic nonce",()=>{
 const x=challengeFor(anchor,{...identity,session_id:"another-session"});
 assert.match(x.nonce,/^[0-9a-f]{64}$/);assert.notEqual(x.nonce,challenge.nonce);
});
check("successful challenge consumes nonce exactly once",()=>{
 const seen=new Set();run({seenNonces:seen});assert.equal(seen.size,1);
});
reject("replayed challenge nonce rejected",()=>{
 const seen=new Set();run({seenNonces:seen});run({seenNonces:seen});
},"CHALLENGE_REPLAY");
reject("nonce store required",()=>run({seenNonces:null}),"REPLAY_STORE_MISSING");
reject("wrong session binding rejected",()=>run({sessionId:"other-session"}),"CHALLENGE_BINDING");
reject("wrong custodian ID rejected",()=>{
 const altered=copy(response);altered.challenge.custodian_id="impostor-name";
 run({response:altered});
},"CHALLENGE_BINDING");
reject("different anchor rejected",()=>{
 run({anchor:{...anchor,head:"f".repeat(64)}});
},"CHALLENGE_BINDING");
reject("wrong public key rejected before signature check",()=>run({publicKey:b.publicKey}),"PROVISIONED_KEY_MISMATCH");
reject("malformed signed challenge fails closed",()=>{
 const altered=copy(response);altered.challenge.nonce="short";
 run({response:altered});
},"CHALLENGE_FIELDS");
reject("forged challenge signature rejected",()=>{
 run({response:responseForTest(challenge,b.privateKey)});
},"CHALLENGE_SIGNATURE");
reject("tampered signed nonce fails cryptographic check",()=>{
 const altered=copy(response);altered.challenge.nonce="f".repeat(64);
 run({response:altered});
},"CHALLENGE_SIGNATURE");
reject("wrong registered key ID rejected",()=>{
 run({enrollment:{...enrollment,key_id:"another-custodian-key"}});
},"CHALLENGE_BINDING");
reject("wrong registered ancestry rejects signed receipt",()=>{
 run({enrollment:{...enrollment,custody_root:"pretend-independent-root"}});
},"CUSTODIAN_ROOT_MISMATCH");
reject("forged receipt rejected despite genuine challenge",()=>{
 run({receipt:receiptForTest(anchor,{...identity,receipt_serial:"other-receipt"},b.privateKey)});
},"BAD_CUSTODY_SIGNATURE");
reject("unknown receipt identity rejected",()=>{
 const forged=receiptForTest(anchor,{...identity,key_id:"other-custody-key",receipt_serial:"other-receipt"},a.privateKey);
 run({receipt:forged});
},"UNKNOWN_OR_REVOKED_CUSTODIAN");
reject("malformed enrollment provenance rejected",()=>{
 run({enrollment:{...enrollment,provisioning_channel:"same-repository"}});
},"ENROLLMENT_SCHEMA");
reject("false external enrollment status rejected",()=>{
 run({enrollment:{...enrollment,review_state:"independently-certified"}});
},"ENROLLMENT_SCHEMA");
check("invalid receipt does not consume valid nonce",()=>{
 const seen=new Set();try{run({seenNonces:seen,receipt:receiptForTest(anchor,{...identity,receipt_serial:"bogus-receipt"},b.privateKey)})}catch{}
 assert.equal(seen.size,0);
});
check("second synthetic signing key is not a second independent organization",()=>{
 const otherId={custodian_id:"test-custodian-b",custody_root:identity.custody_root,key_id:"test-custody-key-b"};
 const e2=enrollForTest(otherId,b.publicKey);
 const r2=receiptForTest(anchor,{...otherId,receipt_serial:"test-receipt-two"},b.privateKey);
 const c2=challengeFor(anchor,{...otherId,session_id:"second-session"},"4".repeat(64));
 const result=verifySession({anchor,enrollment:e2,receipt:r2,response:responseForTest(c2,b.privateKey),
    publicKey:b.publicKey,seenNonces:new Set(),sessionId:"second-session"});
 assert.equal(result.declared_custody_root,identity.custody_root);
 assert.equal(result.independently_authenticated_organizations,0);
});
console.log("SAPPHON-103:",n,"challenge and enrollment checks passed");