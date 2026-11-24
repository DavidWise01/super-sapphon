"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs");
const {signForTest}=require("./sapphon_097_auth.cjs");
const {keyFingerprint,rotate,signRotationForTest,appendBatch,initialize,distinctAncestryRoots}=require("./sapphon_098_chain.cjs");
const archive=JSON.parse(fs.readFileSync("docs/sapphon/live/clock.json","utf8")).records;
const old=crypto.generateKeyPairSync("ed25519"),next=crypto.generateKeyPairSync("ed25519"),outsider=crypto.generateKeyPairSync("ed25519");
const A="test-old-098",B="test-new-098",X="test-rogue-098",sourceId="sapphon-archive",root="single-source-ancestry";
const trust={
 [A]:{publicKey:old.publicKey,source_id:sourceId,role:"synthetic-test",ancestry_root:root,revoked:false},
 [B]:{publicKey:next.publicKey,source_id:sourceId,role:"synthetic-test",ancestry_root:root,revoked:false},
 [X]:{publicKey:outsider.publicKey,source_id:sourceId,role:"synthetic-test",ancestry_root:"separate-declared-root",revoked:false}
};
const payload=(key,generation,start,hashes,prev)=>({
 schema:"sapphon-source-envelope-v1",source_role:"synthetic-test",source_id:sourceId,generation,
 start_seq:start,prev_hash:prev,record_hashes:hashes
});
const genesis=signForTest(payload(A,0,0,archive.slice(0,4).map(r=>r.hash),null),old.privateKey,A);
const extension=signForTest(payload(A,0,4,archive.slice(4,6).map(r=>r.hash),archive[3].hash),old.privateKey,A);
const last=signForTest(payload(B,1,6,archive.slice(6,8).map(r=>r.hash),archive[5].hash),next.privateKey,B);
const from=()=>initialize({sourceId,root,activeKey:A,trust});
const state1=appendBatch(from(),genesis),state2=appendBatch(state1,extension);
const unsigned={
 schema:"sapphon-key-rotation-v1",source_id:sourceId,ancestry_root:root,
 from_key:A,to_key:B,to_fingerprint:keyFingerprint(next.publicKey),effective_seq:6,generation:1
};
const cert=signRotationForTest(unsigned,old.privateKey);
const rotated=rotate(state2,cert,next.publicKey);
let n=0;function check(name,fn){fn();n++;console.log("PASS",n,name)}
function rejects(name,fn,error){check(name,()=>assert.throws(fn,e=>e.message===error))}
check("two signed successive batches preserve exact ordinal boundary",()=>{
 assert.equal(state2.nextSeq,6);assert.equal(state2.lastHash,archive[5].hash);
});
check("old active key can sign effective key rotation",()=>{
 assert.equal(rotated.activeKey,B);assert.equal(rotated.generation,1);
});
check("rotated key continues historical signed chain",()=>{
 const state3=appendBatch(rotated,last);
 assert.equal(state3.nextSeq,8);assert.equal(state3.used.size,8);
 assert.equal(state3.batches.length,3);
 assert.equal(state3.batches[2].root,root);
});
check("same source root persists through rotation",()=>{
 assert.equal(distinctAncestryRoots([state1,state2,rotated]),1);
});
rejects("replayed batch rejected",()=>appendBatch(state2,extension),"SEQUENCE_GAP_OR_REPLAY");
rejects("skipped sequence rejected",()=>appendBatch(state1,signForTest(payload(A,0,5,[archive[6].hash],archive[3].hash),old.privateKey,A)),"SEQUENCE_GAP_OR_REPLAY");
rejects("wrong predecessor rejected",()=>appendBatch(state1,signForTest(payload(A,0,4,[archive[4].hash],"e".repeat(64)),old.privateKey,A)),"PREDECESSOR_MISMATCH");
rejects("reused event digest rejected",()=>appendBatch(state2,signForTest(payload(A,0,6,[archive[0].hash],archive[5].hash),old.privateKey,A)),"DUPLICATE_IDENTITY");
rejects("duplicate hash inside batch rejected",()=>appendBatch(state2,signForTest(payload(A,0,6,[archive[6].hash,archive[6].hash],archive[5].hash),old.privateKey,A)),"DUPLICATE_IDENTITY");
rejects("old key disabled after rotation",()=>appendBatch(rotated,signForTest(payload(A,1,6,[archive[6].hash],archive[5].hash),old.privateKey,A)),"INACTIVE_KEY");
rejects("incorrect generation rejected",()=>appendBatch(rotated,signForTest(payload(B,0,6,[archive[6].hash],archive[5].hash),next.privateKey,B)),"WRONG_GENERATION");
rejects("rotation from unknown key rejected",()=>rotate(state2,{...cert,from_key:X},next.publicKey),"ROTATION_ORDER");
rejects("wrong effective sequence rejected",()=>rotate(state2,{...cert,effective_seq:7},next.publicKey),"ROTATION_BOUNDARY");
rejects("altered ancestry root rejected",()=>rotate(state2,{...cert,ancestry_root:"fabricated-root"},next.publicKey),"ROTATION_ANCESTRY");
rejects("substituted public key rejected",()=>rotate(state2,cert,outsider.publicKey),"KEY_SUBSTITUTION");
rejects("forged rotation signature rejected",()=>{
 const forged=signRotationForTest(unsigned,outsider.privateKey);
 rotate(state2,forged,next.publicKey);
},"ROTATION_SIGNATURE");
rejects("revoked current key cannot rotate",()=>rotate({...state2,trust:{...trust,[A]:{...trust[A],revoked:true}}},cert,next.publicKey),"REVOKED_ROTATOR");
rejects("different role cannot be rotated into",()=>rotate({...state2,trust:{...trust,[B]:{...trust[B],role:"physical-source"}}},cert,next.publicKey),"ROTATION_ROLE");
rejects("shared root conflict blocks fake independent account",()=>rotate({...state2,trust:{...trust,[B]:{...trust[B],ancestry_root:"another-root"}}},cert,next.publicKey),"ROTATION_ROLE");
rejects("signed record tampering fails",()=>{
 const e=signForTest({...last.payload,record_hashes:[archive[0].hash]},outsider.privateKey,B);
 appendBatch(rotated,e);
},"SIGNATURE_INVALID");
check("failed rotation leaves previous state unchanged",()=>{
 const before=state2.activeKey;
 try{rotate(state2,{...cert,generation:4},next.publicKey)}catch{}
 assert.equal(state2.activeKey,before);
 assert.equal(state2.rotations.length,0);
});
check("no independent witness established",()=>assert.equal(distinctAncestryRoots([state1,rotated]),1));
console.log("SAPPHON-098:",n,"signed-chain, rotation and ancestry tests passed");