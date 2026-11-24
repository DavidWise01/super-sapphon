"use strict";
/* SAPPHON-109: signed acquisition transcript contract.
 * This checks synthetic recorded request/response evidence; it DOES NOT prove
 * that HTTPS actually occurred. Independent peer pin provisioning and externally
 * retained network captures are prerequisites to real transport qualification.
 */
const crypto=require("node:crypto");
const {inspect:inspectReceipts,knownOwnedRoot,sha}=require("./sapphon_108_acquisition.cjs");
const HEX=/^[a-f0-9]{64}$/,ID=/^[a-z0-9-]{4,64}$/;
function bad(s){throw Error(s)}
function validURL(s){
 let u;try{u=new URL(s)}catch{bad("TRANSCRIPT_URL")}
 if(u.protocol!=="https:"||u.username||u.password||u.port||u.search||u.hash||
   !u.hostname||u.hostname.endsWith(".")||u.toString()!==s)bad("TRANSCRIPT_URL");
 return u;
}
function originRoot(url){const u=validURL(url);return knownOwnedRoot(u)||"unverified:"+u.hostname.toLowerCase()}
function canonical(p){
 const k=["schema","acquisition_id","session_id","request_method","request_url",
 "redirects","final_url","response_status","response_sha256","response_byte_count",
 "peer_spki_sha256","transport_key_id","claimed_source_root","collection_kind"];
 if(!p||Object.keys(p).sort().join("|")!==k.slice().sort().join("|")||
  p.schema!=="sapphon-transport-transcript-v1"||
  ![p.acquisition_id,p.session_id,p.transport_key_id,p.claimed_source_root].every(x=>typeof x==="string"&&ID.test(x))||
  p.request_method!=="GET"||p.response_status!==200||!HEX.test(p.response_sha256)||
  !HEX.test(p.peer_spki_sha256)||!Number.isSafeInteger(p.response_byte_count)||
  p.response_byte_count<1||p.response_byte_count>262144||
  p.collection_kind!=="synthetic-transcript-fixture"||
  !Array.isArray(p.redirects)||p.redirects.length>4)bad("TRANSCRIPT_FIELDS");
 validURL(p.request_url);validURL(p.final_url);
 let current=p.request_url;
 const seen=new Set([current]);
 for(const hop of p.redirects){
  if(!hop||Object.keys(hop).sort().join("|")!=="from|status|to"||
    hop.from!==current||![301,302,303,307,308].includes(hop.status))bad("REDIRECT_CHAIN");
  validURL(hop.to);
  if(seen.has(hop.to))bad("REDIRECT_LOOP");
  seen.add(hop.to);
  // Known owned GitHub/Pages paths may redirect but remain one root.
  // Unrecognized origin transfers cannot borrow the initial peer attestation.
  if(originRoot(hop.to)!==originRoot(current))bad("REDIRECT_ORIGIN_UNATTESTED");
  current=hop.to;
 }
 if(current!==p.final_url)bad("FINAL_URL_MISMATCH");
 return Buffer.from(JSON.stringify(k.map(x=>p[x])),"utf8");
}
function signedForTest(payload,privateKey){
 return {payload,signature:crypto.sign(null,canonical(payload),privateKey).toString("base64")};
}
function verifyTranscripts(bytes,acquisitionReceipts,transcripts,registry){
 const acquisition=inspectReceipts(bytes,acquisitionReceipts,registry);
 if(!Array.isArray(transcripts)||transcripts.length!==acquisitionReceipts.length)bad("TRANSCRIPT_COUNT");
 const accepted=[],ids=new Set(),sessions=new Set();
 for(const entry of transcripts){
  if(!entry||Object.keys(entry).sort().join("|")!=="payload|signature")bad("TRANSCRIPT_ENVELOPE");
  const p=entry.payload,raw=canonical(p);
  const receipt=acquisitionReceipts.find(x=>x.payload.acquisition_id===p.acquisition_id);
  if(!receipt)bad("UNBOUND_TRANSCRIPT");
  if(ids.has(p.acquisition_id))bad("DUPLICATE_TRANSCRIPT");
  if(sessions.has(p.session_id))bad("REPLAYED_SESSION");
  ids.add(p.acquisition_id);sessions.add(p.session_id);
  if(p.request_url!==receipt.payload.source_url||
      p.transport_key_id!==receipt.payload.transport_key_id||
      p.claimed_source_root!==receipt.payload.source_root)bad("ACQUISITION_BINDING");
  if(p.response_sha256!==sha(bytes)||p.response_byte_count!==bytes.length)bad("RESPONSE_BYTE_MISMATCH");
  const r=registry[p.transport_key_id];
  if(!r||r.revoked===true)bad("UNTRUSTED_TRANSPORT");
  if(!HEX.test(r.pinned_peer_spki_sha256||"")||r.pinned_peer_spki_sha256!==p.peer_spki_sha256)
    bad("PEER_PIN_MISMATCH");
  const originalRoot=originRoot(p.request_url),finalRoot=originRoot(p.final_url);
  if(originalRoot!==finalRoot)bad("REDIRECT_ORIGIN_UNATTESTED");
  const claimed=p.claimed_source_root;
  if(originalRoot!=="unverified:"+new URL(p.request_url).hostname.toLowerCase()&&originalRoot!==claimed)
    bad("SOURCE_ROOT_MISMATCH");
  if(typeof entry.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(entry.signature)||
      !crypto.verify(null,raw,r.publicKey,Buffer.from(entry.signature,"base64")))
    bad("TRANSCRIPT_SIGNATURE");
  accepted.push({acquisition_id:p.acquisition_id,session_id:p.session_id,source_root:claimed,
    peer_pin_checked:true,redirects_checked:p.redirects.length});
 }
 const roots=new Set(accepted.map(x=>x.source_root));
 return {schema:"sapphon-109-transcript-assessment-v1",decision:"HOLD",
  transcript_signatures_checked:accepted.length,declared_roots:roots.size,
  independently_authenticated_transport_sessions:0,external_https_capture_verified:false,
  physical_clock_authorized:false,utc_authority:false,
  root_ancestry_overlap:acquisition.root_ancestry_overlap,audit:accepted};
}
module.exports={canonical,signedForTest,verifyTranscripts,originRoot};
