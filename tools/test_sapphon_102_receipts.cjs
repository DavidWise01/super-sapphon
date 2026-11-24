"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {anchorDigest,receiptForTest,verifyReceipts}=require("./sapphon_102_receipts.cjs");
const a=crypto.generateKeyPairSync("ed25519"),b=crypto.generateKeyPairSync("ed25519"),c=crypto.generateKeyPairSync("ed25519");
const anchor={schema:"sapphon-external-anchor-v1",key_id:"test-governance-100",
 governance_spki_sha256:"1".repeat(64),head:"2".repeat(64),count:3,
 checkpoint_signature:"A".repeat(86)+"==",independently_retained:false,recorded_utc:null};
const registry={
 "custodian-key-a":{custodian_id:"test-custodian-a",custody_root:"common-controlled-root",publicKey:a.publicKey,revoked:false},
 "custodian-key-b":{custodian_id:"test-custodian-b",custody_root:"common-controlled-root",publicKey:b.publicKey,revoked:false},
 "custodian-key-c":{custodian_id:"test-custodian-c",custody_root:"declared-other-root",publicKey:c.publicKey,revoked:false}
};
const meta=(id,root,key,serial)=>({custodian_id:id,custody_root:root,key_id:key,receipt_serial:serial});
const r1=receiptForTest(anchor,meta("test-custodian-a","common-controlled-root","custodian-key-a","receipt-one"),a.privateKey);
const r2=receiptForTest(anchor,meta("test-custodian-b","common-controlled-root","custodian-key-b","receipt-two"),b.privateKey);
const r3=receiptForTest(anchor,meta("test-custodian-c","declared-other-root","custodian-key-c","receipt-three"),c.privateKey);
const copy=x=>JSON.parse(JSON.stringify(x));
let n=0;function test(name,fn){fn();console.log("PASS",++n,name)}
function rejects(name,fn,error){test(name,()=>assert.throws(fn,e=>e.message===error))}
test("one Ed25519 custodian signature verifies but independent custody remains unproven",()=>{
 const result=verifyReceipts(anchor,[r1],registry);
 assert.equal(result.receipt_count,1);assert.equal(result.independent_custody_confirmed,false);
 assert.equal(result.clock_authority,false);
});
test("two different keypairs sharing one owner count as one declared root",()=>{
 const result=verifyReceipts(anchor,[r1,r2],registry);
 assert.equal(result.receipt_count,2);assert.equal(result.declared_custody_roots,1);
 assert.equal(result.independently_authenticated_custodians,0);
});
test("two declared roots still prove zero authenticated independent custodians",()=>{
 const result=verifyReceipts(anchor,[r1,r3],registry);
 assert.equal(result.declared_custody_roots,2);
 assert.equal(result.independently_authenticated_custodians,0);
});
test("anchor digest is stable and bound to complete contract",()=>{
 assert.match(anchorDigest(anchor),/^[0-9a-f]{64}$/);
 assert.notEqual(anchorDigest({...anchor,head:"3".repeat(64)}),anchorDigest(anchor));
});
rejects("altered anchor head invalidates binding",()=>verifyReceipts({...anchor,head:"3".repeat(64)},[r1],registry),"ANCHOR_BINDING");
rejects("altered anchor governance key invalidates binding",()=>verifyReceipts({...anchor,key_id:"another-governance"},[r1],registry),"ANCHOR_BINDING");
rejects("altered receipt source root fails governance trust registry",()=>{
 const x=copy(r1);x.payload.custody_root="fake-independent-root";
 verifyReceipts(anchor,[x],registry);
},"CUSTODIAN_ROOT_MISMATCH");
rejects("wrong signer cannot forge receipt",()=>{
 const forged=receiptForTest(anchor,meta("test-custodian-a","common-controlled-root","custodian-key-a","receipt-fake"),c.privateKey);
 verifyReceipts(anchor,[forged],registry);
},"BAD_CUSTODY_SIGNATURE");
rejects("changed signed receipt serial is rejected",()=>{
 const x=copy(r1);x.payload.receipt_serial="new-serial";
 verifyReceipts(anchor,[x],registry);
},"BAD_CUSTODY_SIGNATURE");
rejects("unknown custodian key rejected",()=>{
 const x=receiptForTest(anchor,meta("unknown-custodian","fake-root","unknown-key","unknown-receipt"),c.privateKey);
 verifyReceipts(anchor,[x],registry);
},"UNKNOWN_OR_REVOKED_CUSTODIAN");
rejects("revoked custodian rejected",()=>{
 verifyReceipts(anchor,[r1],{"custodian-key-a":{...registry["custodian-key-a"],revoked:true}});
},"UNKNOWN_OR_REVOKED_CUSTODIAN");
rejects("replayed receipt serial rejected",()=>verifyReceipts(anchor,[r1,r1],registry),"REPLAYED_RECEIPT");
rejects("one custodian key cannot inflate receipt counts",()=>{
 const repeat=receiptForTest(anchor,meta("test-custodian-a","common-controlled-root","custodian-key-a","second-serial"),a.privateKey);
 verifyReceipts(anchor,[r1,repeat],registry);
},"REPEATED_CUSTODIAN_KEY");
rejects("fake independently retained anchor must fail before receipt review",()=>{
 verifyReceipts({...anchor,independently_retained:true},[r1],registry);
},"INVALID_ANCHOR");
rejects("invented UTC timestamp must fail before receipt review",()=>{
 verifyReceipts({...anchor,recorded_utc:"2026-11-24T10:00:00Z"},[r1],registry);
},"INVALID_ANCHOR");
rejects("unexpected receipt field must fail closed",()=>{
 const x=copy(r1);x.payload.time_authorization=true;verifyReceipts(anchor,[x],registry);
},"RECEIPT_FIELDS");
rejects("incorrect registered custodian identity fails",()=>{
 verifyReceipts(anchor,[r1],{"custodian-key-a":{...registry["custodian-key-a"],custodian_id:"different-id"}});
},"CUSTODIAN_ROOT_MISMATCH");
test("unmodified synthetic receipt input is not rewritten",()=>{
 const before=JSON.stringify([r1,r2]);verifyReceipts(anchor,[r1,r2],registry);
 assert.equal(JSON.stringify([r1,r2]),before);
});
console.log("SAPPHON-102:",n,"custodian receipt acceptance tests passed");