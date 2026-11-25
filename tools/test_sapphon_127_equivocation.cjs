"use strict";
const fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto"),assert=require("node:assert/strict");
const e=require("./sapphon_127_equivocation.cjs"),s=require("./sapphon_125_replica.cjs");
const root=fs.mkdtempSync(path.join(os.tmpdir(),"sapphon127-")),dir=path.join(root,"audit");
const kp=crypto.generateKeyPairSync("ed25519"),other=crypto.generateKeyPairSync("ed25519");
const pins={"publisher-one":{publicKey:kp.publicKey,control_root:"owned-root"}};
const p={schema:"sapphon-125-revocation-snapshot-v1",publisher_id:"publisher-one",control_root:"owned-root",generation:1,issuer_generation:1,operator_generation:1,issuer_revoked:false,operator_revoked:false,previous_digest:null,mode:"synthetic-local-replica"};
const signed=x=>s.signForTest(x,kp.privateKey),a=signed(p),b=signed({...p,issuer_revoked:true}),c=signed({...p,operator_revoked:true});
const r=(signed,source_id,ancestry_roots=["owned-root"])=>({signed,source_id,ancestry_roots,pins});
const assess=(generation=1,publisher_id="publisher-one",source_ancestry=["owned-root"])=>e.assess(dir,{generation,publisher_id,source_ancestry,pins});
let n=0;const test=(name,fn)=>{fn();console.log("PASS",++n,name)},deny=(name,fn,error)=>test(name,()=>assert.throws(fn,e=>e.message===error));
try{
 e.init(dir);
 test("fresh empty journal initialized",()=>assert.equal(e.inspect(dir).observations.length,0));
 test("first signed observation persists with HOLD",()=>assert.equal(e.ingest(dir,r(a,"github-mirror")).decision,"HOLD"));
 test("same origin and digest re-observation idempotent",()=>assert.equal(e.ingest(dir,r(a,"github-mirror")).decision,"DUPLICATE_OBSERVATION"));
 test("public Pages mirror remains the SAME source ancestry",()=>{
  e.ingest(dir,r(a,"pages-mirror"));const out=assess();
  assert.equal(out.observed_snapshots,2);assert.equal(out.shared_ancestry_detected,true);
  assert.equal(out.independent_witnesses_authenticated,false);
 });
 test("first conflicting publisher signature is retained not silently selected",()=>{
  const out=e.ingest(dir,r(b,"publisher-reply"));assert.equal(out.equivocation,true);
  const state=e.inspect(dir);assert.equal(state.conflicts.length,1);assert.equal(state.observations.length,3);
 });
 test("same generation contradiction forces HOLD",()=>{
  const out=assess();assert.equal(out.decision,"HOLD");assert.equal(out.conflict_detected,true);
 });
 test("second divergent signed state is also retained",()=>{
  e.ingest(dir,r(c,"split-reply",["declared-independent-root"]));
  assert.equal(e.inspect(dir).conflicts.length,3);
 });
 test("multiple signed disagreements never trigger approval",()=>assert.equal(assess().external_finality,false));
 test("all observed signed fork digests remain recorded",()=>{
  const out=e.inspect(dir);assert.equal(new Set(out.observations.map(x=>x.digest)).size,3);
 });
 deny("cannot reinitialize without destroying history",()=>e.init(dir),"JOURNAL_EXISTS");
 deny("forged original publisher signature is rejected",()=>e.ingest(dir,r(s.signForTest(p,other.privateKey),"evil-source")),"SNAPSHOT_SIGNATURE");
 deny("unknown publisher root cannot enroll as evidence",()=>e.ingest(dir,{...r(a,"untrusted"),pins:{}}),"PUBLISHER_NOT_PINNED");
 deny("publisher pinned key substituted is rejected",()=>e.ingest(dir,{...r(a,"swapped-key"),pins:{"publisher-one":{publicKey:other.publicKey,control_root:"owned-root"}}}),"SNAPSHOT_SIGNATURE");
 deny("revoked publisher cannot newly be credited as signed source",()=>e.ingest(dir,{...r(a,"revoked"),pins:{"publisher-one":{...pins["publisher-one"],revoked:true}}}),"PUBLISHER_REVOKED");
 deny("wrong publisher control root fails pinned identity",()=>e.ingest(dir,{...r(a,"wrong-root"),pins:{"publisher-one":{...pins["publisher-one"],control_root:"different-root"}}}),"PUBLISHER_IDENTITY");
 deny("missing source ancestry fails closed",()=>e.ingest(dir,r(a,"empty-ancestry",[])),"PROVENANCE_FIELDS");
 deny("duplicated ancestry labels in observation fail closed",()=>e.ingest(dir,r(a,"double-root",["owned-root","owned-root"])),"PROVENANCE_FIELDS");
 deny("invalid source label denied",()=>e.ingest(dir,r(a,"bad source")),"PROVENANCE_FIELDS");
 deny("nonsensical requested generation denied",()=>e.assess(dir,{generation:0,publisher_id:"publisher-one",pins}),"ASSESSMENT_FIELDS");
 deny("missing publisher name denied",()=>e.assess(dir,{generation:1,publisher_id:"",pins}),"ASSESSMENT_FIELDS");
 test("no evidence at other generation cannot authorize",()=>{
  const out=assess(2);assert.equal(out.observed_snapshots,0);assert.equal(out.decision,"HOLD");
 });
 test("source owner overlap is explicitly exposed",()=>assert.equal(assess().source_owned_overlap,true));
 test("different declared root alone does not authenticate independent custody",()=>{
  const out=assess(1,"publisher-one",["unrelated-source"]);
  assert.equal(out.distinct_declared_first_roots,2);assert.equal(out.independent_witnesses_authenticated,false);
 });
 test("journal survives cold read",()=>assert.equal(require("./sapphon_127_equivocation.cjs").inspect(dir).conflicts.length,3));
 deny("local lock blocks concurrent ingestion",()=>{
  fs.mkdirSync(path.join(dir,"lock"));try{e.ingest(dir,r(a,"locked-source"))}finally{fs.rmdirSync(path.join(dir,"lock"))}
 },"JOURNAL_BUSY");
 deny("unreadable corrupt journal blocks evidence promotion",()=>{
  const f=path.join(dir,"journal.json"),before=fs.readFileSync(f);
  try{fs.writeFileSync(f,"{bad");e.inspect(dir)}finally{fs.writeFileSync(f,before)}
 },"JOURNAL_UNREADABLE");
 deny("malformed journal external authority injection fails",()=>{
  const f=path.join(dir,"journal.json"),before=fs.readFileSync(f);
  try{const state=JSON.parse(before);state.authoritative=true;fs.writeFileSync(f,JSON.stringify(state));e.inspect(dir)}
  finally{fs.writeFileSync(f,before)}
 },"JOURNAL_CORRUPT");
 deny("tampering retained signed snapshot digest fails integrity",()=>{
  const f=path.join(dir,"journal.json"),before=fs.readFileSync(f);
  try{const state=JSON.parse(before);state.observations[0].digest="f".repeat(64);fs.writeFileSync(f,JSON.stringify(state));e.inspect(dir)}
  finally{fs.writeFileSync(f,before)}
 },"JOURNAL_CORRUPT");
 deny("removing evidence of a recorded conflict fails integrity",()=>{
  const f=path.join(dir,"journal.json"),before=fs.readFileSync(f);
  try{const state=JSON.parse(before);state.observations.pop();fs.writeFileSync(f,JSON.stringify(state));e.inspect(dir)}
  finally{fs.writeFileSync(f,before)}
 },"JOURNAL_CORRUPT");
 deny("deleting conflict ledger while conflicting snapshots remain fails",()=>{
  const f=path.join(dir,"journal.json"),before=fs.readFileSync(f);
  try{const state=JSON.parse(before);state.conflicts=[];fs.writeFileSync(f,JSON.stringify(state));e.inspect(dir)}
  finally{fs.writeFileSync(f,before)}
 },"MISSING_EQUIVOCATION_RECORD");
 test("signed fork retains three immutable conflicting digests",()=>assert.equal(e.inspect(dir).conflicts.length,3));
 test("all asserted real-world qualifiers remain false",()=>{
  const out=assess();
  assert.equal(out.publication_freshness_authenticated,false);
  assert.equal(out.utc_authority,false);assert.equal(out.independent_witnesses_authenticated,false);
 });
 console.log("SAPPHON-127:",n,"fork detection, ancestry and no-authority tests passed");
}finally{fs.rmSync(root,{recursive:true,force:true})}
