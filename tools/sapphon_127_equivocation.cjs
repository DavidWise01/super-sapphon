"use strict";
/* SAPPHON-127 — synthetic publication equivocation audit.
 * Preserve BOTH signed forks instead of choosing a winner; source mirrors and
 * separately named witnesses with shared ancestry count as ONE origin.
 * Local journal and test keys are not independent custody or outside history.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const snap=require("./sapphon_125_replica.cjs");
const H=/^[a-f0-9]{64}$/,ID=/^[a-z0-9-]{4,64}$/;
const fail=x=>{throw Error(x)};
const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).sort().join("|")===k.slice().sort().join("|");
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
const schema="sapphon-127-equivocation-journal-v1";
function lock(dir,fn){
 if(!fs.existsSync(dir))fail("JOURNAL_MISSING");
 const f=path.join(dir,"lock");
 try{fs.mkdirSync(f)}catch{fail("JOURNAL_BUSY")}
 try{return fn()}finally{fs.rmdirSync(f)}
}
function validate(d){
 if(!exact(d,["schema","revision","observations","conflicts"])||
 d.schema!==schema||!Number.isSafeInteger(d.revision)||d.revision<0||
 !Array.isArray(d.observations)||!Array.isArray(d.conflicts)||
 d.observations.length>1024||d.conflicts.length>1024)fail("JOURNAL_CORRUPT");
 const unique=new Set(),conflicts=new Set();
 for(const item of d.observations){
  if(!exact(item,["publisher_id","generation","digest","snapshot","source_id","ancestry_roots"])||
   !ID.test(item.publisher_id)||!ID.test(item.source_id)||
   !Number.isSafeInteger(item.generation)||item.generation<1||
   !H.test(item.digest)||!Array.isArray(item.ancestry_roots)||
   item.ancestry_roots.length<1||item.ancestry_roots.some(x=>!ID.test(x))||
   new Set(item.ancestry_roots).size!==item.ancestry_roots.length||
   !exact(item.snapshot,["payload","signature"]))fail("JOURNAL_CORRUPT");
  const body=snap.bytes(item.snapshot.payload);
  if(sha(body)!==item.digest||item.publisher_id!==item.snapshot.payload.publisher_id||
    item.generation!==item.snapshot.payload.generation)fail("JOURNAL_CORRUPT");
  const k=JSON.stringify([item.source_id,item.digest]);
  if(unique.has(k))fail("JOURNAL_CORRUPT");unique.add(k);
 }
 for(const c of d.conflicts){
  if(!exact(c,["publisher_id","generation","digest_a","digest_b"])||
   !ID.test(c.publisher_id)||!Number.isSafeInteger(c.generation)||c.generation<1||
   !H.test(c.digest_a)||!H.test(c.digest_b)||c.digest_a===c.digest_b)fail("JOURNAL_CORRUPT");
  const key=JSON.stringify([c.publisher_id,c.generation,[c.digest_a,c.digest_b].sort()]);
  if(conflicts.has(key))fail("JOURNAL_CORRUPT");conflicts.add(key);
  if(!d.observations.some(o=>o.publisher_id===c.publisher_id&&o.generation===c.generation&&o.digest===c.digest_a)||
     !d.observations.some(o=>o.publisher_id===c.publisher_id&&o.generation===c.generation&&o.digest===c.digest_b))
    fail("JOURNAL_CORRUPT");
 }
 for(const a of d.observations)for(const b of d.observations){
  if(a.publisher_id===b.publisher_id&&a.generation===b.generation&&a.digest!==b.digest){
   if(!d.conflicts.some(c=>c.publisher_id===a.publisher_id&&c.generation===a.generation&&
    [c.digest_a,c.digest_b].includes(a.digest)&&[c.digest_a,c.digest_b].includes(b.digest)))
     fail("MISSING_EQUIVOCATION_RECORD");
  }
 }
 return d;
}
function read(dir){
 let d;try{d=JSON.parse(fs.readFileSync(path.join(dir,"journal.json"),"utf8"))}
 catch{fail("JOURNAL_UNREADABLE")}
 return validate(d);
}
function write(dir,d){
 const tmp=path.join(dir,".new-"+crypto.randomBytes(8).toString("hex"));
 try{
  const fd=fs.openSync(tmp,"wx",0o600);
  try{fs.writeFileSync(fd,JSON.stringify(d)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(tmp,path.join(dir,"journal.json"));
  const df=fs.openSync(dir,"r");try{fs.fsyncSync(df)}finally{fs.closeSync(df)}
 }catch{try{fs.unlinkSync(tmp)}catch{}fail("JOURNAL_WRITE_FAILED")}
}
function init(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 lock(dir,()=>{
  if(fs.existsSync(path.join(dir,"journal.json")))fail("JOURNAL_EXISTS");
  write(dir,{schema,revision:0,observations:[],conflicts:[]});
 });
}
function ingest(dir,{signed,source_id,ancestry_roots,pins}){
 const digest=snap.checkSigned(signed,pins),p=signed.payload;
 if(typeof source_id!=="string"||!ID.test(source_id)||
 !Array.isArray(ancestry_roots)||ancestry_roots.length<1||
 ancestry_roots.some(x=>typeof x!=="string"||!ID.test(x))||
 new Set(ancestry_roots).size!==ancestry_roots.length)fail("PROVENANCE_FIELDS");
 return lock(dir,()=>{
  const d=read(dir),found=d.observations.find(o=>o.source_id===source_id&&o.digest===digest);
  if(found)return {decision:"DUPLICATE_OBSERVATION",equivocation:d.conflicts.length>0};
  if(d.observations.length>=1024)fail("JOURNAL_CAPACITY_HOLD");
  const others=d.observations.filter(o=>o.publisher_id===p.publisher_id&&o.generation===p.generation&&o.digest!==digest);
  d.observations.push({publisher_id:p.publisher_id,generation:p.generation,digest,snapshot:signed,source_id,ancestry_roots});
  for(const o of others){
   const exists=d.conflicts.some(c=>c.publisher_id===p.publisher_id&&c.generation===p.generation&&
    [c.digest_a,c.digest_b].includes(digest)&&[c.digest_a,c.digest_b].includes(o.digest));
   if(!exists)d.conflicts.push({publisher_id:p.publisher_id,generation:p.generation,digest_a:o.digest,digest_b:digest});
  }
  d.revision++;write(dir,d);
  return {decision:"HOLD",equivocation:others.length>0,conflict_count:d.conflicts.length,
   external_custody_authenticated:false};
 });
}
function assess(dir,{publisher_id,generation,source_ancestry=[],pins}={}){
 if(!ID.test(publisher_id)||!Number.isSafeInteger(generation)||generation<1||
 !Array.isArray(source_ancestry)||source_ancestry.some(x=>!ID.test(x)))fail("ASSESSMENT_FIELDS");
 return lock(dir,()=>{
  const d=read(dir),records=d.observations.filter(o=>o.publisher_id===publisher_id&&o.generation===generation);
  const conflict=d.conflicts.some(c=>c.publisher_id===publisher_id&&c.generation===generation);
  const roots=new Set(),origins=new Set(),source=new Set(source_ancestry);
  for(const record of records){
   const actual=snap.checkSigned(record.snapshot,pins);
   if(actual!==record.digest)fail("OBSERVATION_SIGNATURE_MISMATCH");
   for(const ancestor of record.ancestry_roots)roots.add(ancestor);
   origins.add(record.ancestry_roots[0]);
  }
  const sharedAncestry=records.some((a,i)=>records.slice(i+1).some(b=>
   a.ancestry_roots.some(x=>b.ancestry_roots.includes(x))));
  const ownedOverlap=records.some(o=>o.ancestry_roots.some(x=>source.has(x)));
  return {schema:"sapphon-127-equivocation-assessment-v1",decision:"HOLD",
   observed_snapshots:records.length,declared_source_roots:roots.size,
   distinct_declared_first_roots:origins.size,conflict_detected:conflict,
   shared_ancestry_detected:sharedAncestry,source_owned_overlap:ownedOverlap,
   independent_witnesses_authenticated:false,publication_freshness_authenticated:false,
   external_finality:false,utc_authority:false};
 });
}
function inspect(dir){return lock(dir,()=>read(dir))}
module.exports={init,ingest,assess,inspect};
