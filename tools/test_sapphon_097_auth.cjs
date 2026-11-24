"use strict";
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const fs=require("node:fs");
const {canonical,verifyEnvelope,signForTest}=require("./sapphon_097_auth.cjs");
const source=JSON.parse(fs.readFileSync("docs/sapphon/live/clock.json","utf8"));
const pair=crypto.generateKeyPairSync("ed25519");
const other=crypto.generateKeyPairSync("ed25519");
const id="sapphon-test-root-097";
const trust={[id]:{role:"synthetic-test",source_id:"sapphon-archive",publicKey:pair.publicKey,revoked:false}};
const p={schema:"sapphon-source-envelope-v1",source_role:"synthetic-test",source_id:"sapphon-archive",generation:0,
 start_seq:0,prev_hash:null,record_hashes:source.records.map(r=>r.hash)};
const original=signForTest(p,pair.privateKey,id);
const copy=x=>JSON.parse(JSON.stringify(x));
let n=0;
function check(name,fn){fn();console.log("PASS",++n,name)}
function rejects(name,fn,pattern){check(name,()=>assert.throws(fn,e=>e.message===pattern))}
check("correctly signed synthetic source recognized but NOT authorized",()=>{
 const r=verifyEnvelope(original,trust);
 assert.equal(r.status,"SIGNED_SYNTHETIC_TEST");
 assert.equal(r.authorized_time,false);
 assert.equal(r.independent_witnesses_verified,false);
 assert.equal(r.count,8);
});
rejects("changed record hash rejects signature",()=>{const e=copy(original);e.payload.record_hashes[3]="f".repeat(64);verifyEnvelope(e,trust)},"SIGNATURE_INVALID");
rejects("changed authorization claim cannot sneak into canonical schema",()=>{const e=copy(original);e.payload.mint_authority=true;verifyEnvelope(e,trust)},"PAYLOAD_FIELDS");
rejects("wrong key rejected",()=>verifyEnvelope(signForTest(p,other.privateKey,id),trust),"SIGNATURE_INVALID");
rejects("unknown key rejected",()=>verifyEnvelope({...original,key_id:"outsider"},trust),"UNKNOWN_SIGNER");
rejects("revoked key rejected",()=>verifyEnvelope(original,{[id]:{...trust[id],revoked:true}}),"REVOKED_SIGNER");
rejects("physical role claim not accepted under synthetic key",()=>{const e=signForTest({...p,source_role:"physical-source"},pair.privateKey,id);verifyEnvelope(e,trust)},"ROLE_OR_SOURCE_MISMATCH");
rejects("source substitution rejected",()=>{const e=signForTest({...p,source_id:"other-origin"},pair.privateKey,id);verifyEnvelope(e,trust)},"ROLE_OR_SOURCE_MISMATCH");
rejects("invalid predecessor at genesis",()=>canonical({...p,prev_hash:"a".repeat(64)}),"PREDECESSOR");
rejects("gap or fractional sequence",()=>canonical({...p,start_seq:1.5}),"SEQUENCE");
rejects("empty batch",()=>canonical({...p,record_hashes:[]}),"HASH_LIST");
rejects("bad signature encoding",()=>verifyEnvelope({...original,signature:"abcd"},trust),"SIGNATURE_ENCODING");
rejects("wrong envelope schema",()=>verifyEnvelope({...original,schema:"time-authority"},trust),"ENVELOPE_SCHEMA");
check("two independent keypairs have distinct public keys",()=>assert.notEqual(
 pair.publicKey.export({type:"spki",format:"der"}).toString("hex"),
 other.publicKey.export({type:"spki",format:"der"}).toString("hex")));
check("canonical envelope stable under object key reordering",()=>{
 const reversed=Object.fromEntries(Object.entries(p).reverse());
 assert.deepEqual(canonical(p),canonical(reversed));
});
check("signed synthetic evidence remains separate from live clock",()=>{
 const x=verifyEnvelope(original,trust);
 assert.equal(x.authorized_time,false);
});
console.log("SAPPHON-097:",n,"Ed25519 verification and tamper checks passed");