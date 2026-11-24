"use strict";
/* SAPPHON-120 adversarial Phase IX closing audit.
 * Observation only. The check does not manufacture authority or validate
 * real-world clocks, outside custody, consensus or external transactions.
 */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const h=require("./sapphon_119_handshake.cjs"),a=require("./sapphon_118_anchor.cjs");
const {inspect:receiverInspect}=require("./sapphon_117_transaction.cjs");
const fail=x=>{throw Error(x)};
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
function evaluate(receiverDir,anchorDir,handshakeDir,keys){
 const receiver=receiverInspect(receiverDir),handshake=h.inspect(handshakeDir),anchors=a.inspect(anchorDir);
 const receiverHash=sha(Buffer.from(JSON.stringify(receiver)));
 const last=handshake.records.at(-1),checkpoint=anchors.entries.at(-1);
 if(!checkpoint)fail("NO_ANCHOR");
 const observations=[];
 if(receiver.revision>0&&(!last||last.receiver_revision!==receiver.revision))
  observations.push("UNTRACKED_RECEIVER_REVISION");
 if(last&&last.receiver_revision===receiver.revision&&last.receiver_state_sha256!==receiverHash)
  observations.push("HANDSHAKE_STATE_CONFLICT");
 if(last&&last.status!=="LOCAL_ANCHOR_CONFIRMED")observations.push("PENDING_ANCHOR");
 const latest=checkpoint.checkpoint.payload;
 if(latest.revision<receiver.revision)observations.push("UNANCHORED_ADVANCE");
 if(latest.revision>receiver.revision)observations.push("RECEIVER_ROLLBACK");
 if(latest.revision===receiver.revision&&latest.state_sha256!==receiverHash)
  observations.push("RECEIVER_DIGEST_CONFLICT");
 try{a.compare(receiverDir,anchorDir,keys)}catch(e){
  if(!observations.includes(e.message))observations.push(e.message);
 }
 const consistent=observations.length===0&&last&&last.status==="LOCAL_ANCHOR_CONFIRMED"&&
  last.checkpoint_sha256===checkpoint.checkpoint_sha256;
 if(last&&last.status==="LOCAL_ANCHOR_CONFIRMED"&&
    last.checkpoint_sha256!==checkpoint.checkpoint_sha256)observations.push("ACK_LINK_MISMATCH");
 return {schema:"sapphon-120-final-recovery-audit-v1",
  status:consistent?"LOCAL_CONSISTENCY_ONLY":"HOLD_UNRESOLVED",
  receiver_revision:receiver.revision,receiver_effects:receiver.effects.length,
  handshake_records:handshake.records.length,checkpoint_entries:anchors.entries.length,
  observations,external_finalized:false,independent_custody:false,
  globally_linearizable:false,physical_clock_authorized:false,utc_authority:false,
  decision:"HOLD"};
}
function provePreserved(base){
 const manifests=["docs/sapphon/SAPPHON-096-FREEZE.json",
 "docs/sapphon/phase-vii/SAPPHON-104-FREEZE.json",
 "docs/sapphon/phase-viii/SAPPHON-112-FREEZE.json"];
 const roots=[],seen=new Set();
 for(const p of manifests){
  const manifest=JSON.parse(fs.readFileSync(path.join(base,p),"utf8"));
  for(const [file,meta] of Object.entries(manifest.files)){
   const bytes=fs.readFileSync(path.join(base,file));
   if(sha(bytes)!==meta.sha256||bytes.length!==meta.bytes)fail("FROZEN_HASH_MISMATCH");
   if(seen.has(file))fail("OVERLAPPING_FREEZE_FILES");seen.add(file);
  }
  roots.push({manifest:p,files:Object.keys(manifest.files).length,
   sha256:sha(fs.readFileSync(path.join(base,p)))});
 }
 if(roots.reduce((n,r)=>n+r.files,0)!==98)fail("PARENT_FREEZE_COUNT");
 return {schema:"sapphon-120-preservation-v1",roots,total_files:98,verified:true};
}
module.exports={evaluate,provePreserved};
