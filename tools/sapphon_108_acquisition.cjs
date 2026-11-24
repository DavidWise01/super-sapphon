"use strict";
/* SAPPHON-108: acquisition receipts, byte witnesses and shared source ancestry.
   Acquisitions may be signed by multiple transport witnesses; neither signatures
   nor separate mirror URLs prove separate origin. No external retrieval is claimed.
*/
const crypto=require("node:crypto"),fs=require("node:fs");
const HEX=/^[0-9a-f]{64}$/;const ID=/^[a-z0-9-]{4,64}$/;
function fail(s){throw Error(s)}
function sha(b){return crypto.createHash("sha256").update(b).digest("hex")}
function spki(key){return (key.type==="public"?key:crypto.createPublicKey(key)).export({type:"spki",format:"der"})}
function normalizedUrl(value){
 let u;
 try{u=new URL(value)}catch{fail("URL_INVALID")}
 if(u.protocol!=="https:"||u.username||u.password||u.port||u.hash||u.search||!u.hostname||u.hostname.endsWith("."))
  fail("URL_UNTRUSTED");
 return u;
}
function knownOwnedRoot(u){
 const host=u.hostname.toLowerCase(),pieces=u.pathname.split("/").filter(Boolean).map(x=>x.toLowerCase());
 if((host==="github.com"||host==="raw.githubusercontent.com")&&
   pieces[0]==="davidwise01"&&pieces[1]==="super-sapphon")return "davidwise01-owned-github";
 if(host==="davidwise01.github.io"&&pieces[0]==="super-sapphon")return "davidwise01-owned-github";
 return null;
}
function canonical(p){
 const fields=["schema","acquisition_id","source_url","source_root","transport_key_id","observed_sha256","byte_count","collection_kind","declared_time","parent_roots"];
 if(!p||Object.keys(p).sort().join("|")!==fields.slice().sort().join("|")||
    p.schema!=="sapphon-acquisition-receipt-v1"||
    ![p.acquisition_id,p.source_root,p.transport_key_id].every(x=>typeof x==="string"&&ID.test(x))||
    !HEX.test(p.observed_sha256)||!Number.isSafeInteger(p.byte_count)||p.byte_count<1||p.byte_count>262144||
    p.collection_kind!=="synthetic-local-fixture"||p.declared_time!==null||
    !Array.isArray(p.parent_roots)||p.parent_roots.length>16||
    !p.parent_roots.every(x=>typeof x==="string"&&ID.test(x))||
    new Set(p.parent_roots).size!==p.parent_roots.length)fail("ACQUISITION_FIELDS");
 const u=normalizedUrl(p.source_url);
 if(u.toString()!==p.source_url)fail("URL_NONCANONICAL");
 return Buffer.from(JSON.stringify(fields.map(k=>p[k])),"utf8");
}
function receiptForTest(payload,privateKey){
 return {payload,signature:crypto.sign(null,canonical(payload),privateKey).toString("base64")};
}
function inspect(bytes,receipts,registry){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>262144)fail("BYTES_INVALID");
 if(!Array.isArray(receipts)||receipts.length<1||receipts.length>64)fail("RECEIPT_BATCH");
 const hash=sha(bytes),seenIds=new Set(),seenKeyIds=new Set(),sources=new Map(),audit=[];
 for(const item of receipts){
  if(!item||Object.keys(item).sort().join("|")!=="payload|signature")fail("RECEIPT_ENVELOPE");
  const p=item.payload,serialized=canonical(p),u=normalizedUrl(p.source_url);
  if(seenIds.has(p.acquisition_id))fail("REPLAYED_ACQUISITION");
  seenIds.add(p.acquisition_id);
  if(p.observed_sha256!==hash||p.byte_count!==bytes.length)fail("BYTE_MISMATCH");
  if(!registry||!Object.hasOwn(registry,p.transport_key_id))fail("UNENROLLED_TRANSPORT");
  const r=registry[p.transport_key_id];
  if(r.revoked===true)fail("REVOKED_TRANSPORT");
  if(r.source_root!==p.source_root)fail("TRUST_ROOT_MISMATCH");
  const owned=knownOwnedRoot(u);
  if(owned&&p.source_root!==owned)fail("OWNED_MIRROR_ROOT_MISMATCH");
  if(!r.publicKey||typeof item.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(item.signature)||
     !crypto.verify(null,serialized,r.publicKey,Buffer.from(item.signature,"base64")))fail("ACQUISITION_SIGNATURE");
  if(seenKeyIds.has(p.transport_key_id))fail("REPEATED_TRANSPORT_KEY");
  seenKeyIds.add(p.transport_key_id);
  const ancestry=new Set([p.source_root,...p.parent_roots]);
  for(const root of ancestry)sources.set(root,(sources.get(root)||0)+1);
  audit.push({acquisition_id:p.acquisition_id,root:p.source_root,sha256:hash,
    parent_roots:[...p.parent_roots],signed:true,known_owned_mirror:!!owned});
 }
 const directRoots=new Set(audit.map(a=>a.root));
 const shared=directRoots.size<receipts.length ||
  audit.some(a=>a.parent_roots.some(parent=>directRoots.has(parent)));
 return {schema:"sapphon-108-acquisition-assessment-v1",decision:"HOLD",
    byte_sha256:hash,acquisitions_verified:audit.length,
    claimed_direct_source_roots:directRoots.size,
    root_ancestry_overlap:shared,
    independently_authenticated_roots:0,external_acquisition_confirmed:false,
    physical_clock_authorized:false,utc_authority:false,audit};
}
function inspectFile(file,receipts,registry){
 let stat;try{stat=fs.lstatSync(file)}catch{fail("EVIDENCE_MISSING")}
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>262144)fail("EVIDENCE_FILE_TYPE");
 return inspect(fs.readFileSync(file),receipts,registry);
}
module.exports={sha,canonical,knownOwnedRoot,receiptForTest,inspect,inspectFile};
