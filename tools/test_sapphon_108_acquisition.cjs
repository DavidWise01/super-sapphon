"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {sha,canonical,knownOwnedRoot,receiptForTest,inspect,inspectFile}=require("./sapphon_108_acquisition.cjs");
const a=crypto.generateKeyPairSync("ed25519"),b=crypto.generateKeyPairSync("ed25519"),c=crypto.generateKeyPairSync("ed25519");
const bytes=Buffer.from('{"fixture":"synthetic evidence from one ancestry","observation":0}\n');
const root="davidwise01-owned-github",own1="https://github.com/DavidWise01/super-sapphon/blob/main/docs/sapphon/live/clock.json";
const own2="https://davidwise01.github.io/super-sapphon/docs/sapphon/live/clock.json";
const other="https://independent.example.org/evidence/clock.json";
const base=(id,url,key,source,parent=[])=>({schema:"sapphon-acquisition-receipt-v1",acquisition_id:id,
 source_url:url,source_root:source,transport_key_id:key,observed_sha256:sha(bytes),
 byte_count:bytes.length,collection_kind:"synthetic-local-fixture",declared_time:null,parent_roots:parent});
const p1=base("sample-one",own1,"test-transport-a",root),p2=base("sample-two",own2,"test-transport-b",root);
const p3=base("sample-three",other,"test-transport-c","declared-unverified-root",["common-parent"]);
const registry={
 "test-transport-a":{source_root:root,publicKey:a.publicKey,revoked:false},
 "test-transport-b":{source_root:root,publicKey:b.publicKey,revoked:false},
 "test-transport-c":{source_root:"declared-unverified-root",publicKey:c.publicKey,revoked:false}
};
const r1=receiptForTest(p1,a.privateKey),r2=receiptForTest(p2,b.privateKey),r3=receiptForTest(p3,c.privateKey);
const clone=x=>JSON.parse(JSON.stringify(x));let n=0;
function test(name,fn){fn();console.log("PASS",++n,name)}
function reject(name,fn,error){test(name,()=>assert.throws(fn,e=>e.message===error))}
test("GitHub and Pages collapse into one known origin",()=>{
 assert.equal(knownOwnedRoot(new URL(own1)),root);assert.equal(knownOwnedRoot(new URL(own2)),root);
});
test("two differently signed local acquisitions yield one root",()=>{
 const x=inspect(bytes,[r1,r2],registry);assert.equal(x.acquisitions_verified,2);
 assert.equal(x.claimed_direct_source_roots,1);assert.equal(x.root_ancestry_overlap,true);
 assert.equal(x.independently_authenticated_roots,0);assert.equal(x.decision,"HOLD");
});
test("unknown external hostname is only declared, not certified",()=>{
 const x=inspect(bytes,[r1,r3],registry);
 assert.equal(x.claimed_direct_source_roots,2);assert.equal(x.independently_authenticated_roots,0);
 assert.equal(x.external_acquisition_confirmed,false);
});
test("signed child lineage still establishes zero independent witnesses",()=>{
 const child=receiptForTest(base("child-capture",other,"test-transport-c","declared-unverified-root",[root]),c.privateKey);
 const x=inspect(bytes,[r1,child],registry);assert.equal(x.root_ancestry_overlap,true);
});
reject("one URL cannot fake a second root by declaring another",()=>{
 const p=base("fake-root",own2,"test-transport-c","declared-unverified-root");
 inspect(bytes,[receiptForTest(p,c.privateKey)],registry);
},"OWNED_MIRROR_ROOT_MISMATCH");
reject("corrupted downloaded bytes rejected",()=>inspect(Buffer.from("tampered"),[r1],registry),"BYTE_MISMATCH");
reject("wrong declared byte count rejected",()=>{
 const x=receiptForTest({...p1,byte_count:bytes.length+1},a.privateKey);
 inspect(bytes,[x],registry);
},"BYTE_MISMATCH");
reject("tampered signed URL rejected",()=>{
 const x=clone(r1);x.payload.source_url=own2;
 inspect(bytes,[x],registry);
},"ACQUISITION_SIGNATURE");
reject("rogue key cannot forge transport receipt",()=>{
 inspect(bytes,[receiptForTest(p1,c.privateKey)],registry);
},"ACQUISITION_SIGNATURE");
reject("replayed acquisition ID fails closed",()=>inspect(bytes,[r1,r1],registry),"REPLAYED_ACQUISITION");
reject("reused transport key under a fresh receipt ID rejected",()=>{
 const another=receiptForTest({...p1,acquisition_id:"sample-different"},a.privateKey);
 inspect(bytes,[r1,another],registry);
},"REPEATED_TRANSPORT_KEY");
reject("revoked transport signer rejected",()=>{
 inspect(bytes,[r1],{"test-transport-a":{...registry["test-transport-a"],revoked:true}});
},"REVOKED_TRANSPORT");
reject("unregistered signing key rejected",()=>{
 const p={...p1,transport_key_id:"unregistered-transport"};
 inspect(bytes,[receiptForTest(p,a.privateKey)],registry);
},"UNENROLLED_TRANSPORT");
reject("wrong registry ancestry cannot authorize receipt",()=>{
 inspect(bytes,[r1],{"test-transport-a":{...registry["test-transport-a"],source_root:"false-root"}});
},"TRUST_ROOT_MISMATCH");
reject("unsigned source URL rejected",()=>canonical({...p1,source_url:"http://github.com/DavidWise01/super-sapphon"}),"URL_UNTRUSTED");
reject("query-string source ambiguity rejected",()=>canonical({...p1,source_url:own1+"?version=2"}),"URL_UNTRUSTED");
reject("fragment source ambiguity rejected",()=>canonical({...p1,source_url:own1+"#section"}),"URL_UNTRUSTED");
reject("user info in URL rejected",()=>canonical({...p1,source_url:"https://actor@github.com/DavidWise01/super-sapphon"}),"URL_UNTRUSTED");
reject("non-canonical trailing URL rejected",()=>canonical({...p1,source_url:own1+"/../clock.json"}),"URL_NONCANONICAL");
reject("self-declared live timestamp excluded from fixture",()=>canonical({...p1,declared_time:"2026-11-24T11:00:00Z"}),"ACQUISITION_FIELDS");
reject("unsanctioned witness authority field excluded",()=>canonical({...p1,independent:true}),"ACQUISITION_FIELDS");
reject("repeated parent ancestry disallowed",()=>canonical({...p3,parent_roots:["one-root","one-root"]}),"ACQUISITION_FIELDS");
const directory=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon108-"));
try{
 const file=path.join(directory,"fixture.json");fs.writeFileSync(file,bytes);
 test("local evidence bytes are actually read from disk",()=>{
  assert.equal(inspectFile(file,[r1,r2],registry).acquisitions_verified,2);
 });
 reject("missing byte source rejected",()=>inspectFile(path.join(directory,"missing.json"),[r1],registry),"EVIDENCE_MISSING");
 reject("symlink cannot substitute byte evidence",()=>{
  const link=path.join(directory,"link.json");fs.symlinkSync(file,link);
  try{inspectFile(link,[r1],registry)}finally{fs.unlinkSync(link)}
 },"EVIDENCE_FILE_TYPE");
}finally{fs.rmSync(directory,{recursive:true,force:true})}
test("verification does not rewrite the receipt evidence",()=>{
 const saved=JSON.stringify([r1,r2]);inspect(bytes,[r1,r2],registry);assert.equal(JSON.stringify([r1,r2]),saved);
});
console.log("SAPPHON-108:",n,"acquisition byte provenance tests passed");
