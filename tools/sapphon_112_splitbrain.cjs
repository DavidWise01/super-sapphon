"use strict";
/* SAPPHON-112 — split-brain capture registry counterexample.
 * Local file journals are NOT globally authoritative. Comparing two copies
 * detects some forks; it cannot prevent acceptance during a partition. */
const fs=require("node:fs"),crypto=require("node:crypto"),path=require("node:path");
const HEX=/^[0-9a-f]{64}$/;
function fail(x){throw Error(x)}
function readJournal(directory){
 let d;
 try{d=JSON.parse(fs.readFileSync(path.join(directory,"registry.json"),"utf8"))}
 catch{fail("JOURNAL_UNAVAILABLE")}
 if(!d||d.schema!=="sapphon-111-session-registry-v1"||
   !Number.isSafeInteger(d.revision)||d.revision<0||
   !Number.isSafeInteger(d.max_seen_ms)||d.max_seen_ms<0||
   !Array.isArray(d.records)||d.records.length>1024)fail("JOURNAL_INVALID");
 const seen=new Set();
 for(const r of d.records){
  if(!r||Object.keys(r).sort().join("|")!=="challenge_sha256|expires_ms|issued_ms|nonce|retention_sha256|status"||
    !HEX.test(r.nonce)||!HEX.test(r.challenge_sha256)||
    !Number.isSafeInteger(r.issued_ms)||!Number.isSafeInteger(r.expires_ms)||
    r.issued_ms<0||r.expires_ms<=r.issued_ms||r.expires_ms-r.issued_ms>300000||
    !["ISSUED","CONSUMED"].includes(r.status)||
    (r.status==="ISSUED"&&r.retention_sha256!==null)||
    (r.status==="CONSUMED"&&!HEX.test(r.retention_sha256))||
    seen.has(r.nonce))fail("JOURNAL_INVALID");
  seen.add(r.nonce);
 }
 return d;
}
function hash(b){return crypto.createHash("sha256").update(b).digest("hex")}
function compareDirectories(a,b){
 const A=readJournal(a),B=readJournal(b);
 const left=new Map(A.records.map(x=>[x.nonce,x])),right=new Map(B.records.map(x=>[x.nonce,x]));
 const conflicts=[],duplicates=[],unilateral=[];
 for(const [nonce,l] of left){
  const r=right.get(nonce);
  if(!r){unilateral.push(nonce);continue}
  if(l.challenge_sha256!==r.challenge_sha256||l.issued_ms!==r.issued_ms||
     l.expires_ms!==r.expires_ms)conflicts.push({nonce,type:"ISSUANCE_FORK"});
  else if(l.status==="CONSUMED"&&r.status==="CONSUMED")
    duplicates.push({nonce,type:l.retention_sha256===r.retention_sha256?
      "DUAL_CONSUMPTION_SAME_CAPTURE":"DUAL_CONSUMPTION_DIFFERENT_RETENTION"});
  else if(l.status!==r.status)conflicts.push({nonce,type:"UNSYNCHRONIZED_CONSUMPTION"});
 }
 for(const nonce of right.keys())if(!left.has(nonce))unilateral.push(nonce);
 const sameState=JSON.stringify(A)===JSON.stringify(B);
 const status=(duplicates.length||conflicts.length||unilateral.length)?
   "SPLIT_BRAIN_OR_DIVERGENCE":"COPIES_CONSISTENT_ONLY";
 // Even byte-identical copies are not proof of a linearizable single authority.
 return {schema:"sapphon-112-journal-comparison-v1",status,
   duplicate_consumptions:duplicates,conflicts,unilateral_nonces:unilateral,
   exact_copy:sameState,revision_a:A.revision,revision_b:B.revision,
   independent_global_replay_protection:false,
   external_custody_qualified:false,utc_authority:false,decision:"HOLD"};
}
function reviewSnapshots(snapshots){
 if(!Array.isArray(snapshots)||snapshots.length<2||snapshots.length>16)
   fail("SNAPSHOT_SET");
 const names=new Set(),roots=new Set(),sameOwner=[];
 for(const s of snapshots){
  if(!s||Object.keys(s).sort().join("|")!=="custody_root|journal_dir|snapshot_id")
    fail("SNAPSHOT_FIELDS");
  if(typeof s.snapshot_id!=="string"||!/^[a-z0-9-]{4,64}$/.test(s.snapshot_id)||
     typeof s.custody_root!=="string"||!/^[a-z0-9-]{4,64}$/.test(s.custody_root)||
     typeof s.journal_dir!=="string"||!s.journal_dir)fail("SNAPSHOT_FIELDS");
  if(names.has(s.snapshot_id))fail("DUPLICATE_SNAPSHOT_ID");
  names.add(s.snapshot_id);roots.add(s.custody_root);
  readJournal(s.journal_dir);sameOwner.push(s.custody_root);
 }
 const comparison=[];
 for(let i=0;i<snapshots.length;i++)
   for(let j=i+1;j<snapshots.length;j++)
     comparison.push({left:snapshots[i].snapshot_id,right:snapshots[j].snapshot_id,
       ...compareDirectories(snapshots[i].journal_dir,snapshots[j].journal_dir)});
 return {schema:"sapphon-112-snapshot-audit-v1",status:"OBSERVATION_ONLY",
   snapshots_checked:snapshots.length,claimed_custody_roots:roots.size,
   repeated_owner_roots:roots.size<snapshots.length,
   comparisons:comparison,independently_authenticated_roots:0,
   physically_qualified:false,globally_linearizable:false,
   utc_authority:false,decision:"HOLD"};
}
module.exports={readJournal,compareDirectories,reviewSnapshots};
