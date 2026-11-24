"use strict";
/* Export signed checkpoint pin for custody OUTSIDE this repository.
 * Example: node tools/sapphon_101_export.cjs audit.json trusted-public.pem governance-key-id /tmp/anchor.json
 * The key is an explicit verifier input; never read it from the untrusted audit itself.
 * The output is a custody-request artifact; do NOT mark it independently retained.
 */
const fs=require("node:fs"),crypto=require("node:crypto");
const {anchorFrom,compare}=require("./sapphon_101_anchor.cjs");
function run(args){
 if(args.length!==4&&args.length!==6)
   throw Error("Usage: audit.json trusted-public.pem governance-key-id anchor.json [previous-audit.json previous-anchor.json]");
 const [auditFile,pubFile,keyId,output,previousAudit,previousAnchor]=args;
 const audit=JSON.parse(fs.readFileSync(auditFile,"utf8"));
 const pub=crypto.createPublicKey(fs.readFileSync(pubFile,"utf8"));
 if(pub.asymmetricKeyType!=="ed25519")throw Error("TRUST_ROOT_MUST_BE_ED25519");
 const anchor=anchorFrom(audit.entries,audit.checkpoint,pub,keyId);
 if(previousAudit){
  const former=JSON.parse(fs.readFileSync(previousAudit,"utf8"));
  const oldPin=JSON.parse(fs.readFileSync(previousAnchor,"utf8"));
  const result=compare(oldPin,former.entries,former.checkpoint,audit.entries,audit.checkpoint,pub,keyId);
  if(!["ANCHOR_MATCH","APPEND_ONLY_CONTINUATION"].includes(result.status))throw Error("CHAIN_NOT_ANCHORED");
  process.stdout.write("PREVIOUS PIN "+result.status+"\n");
 }
 fs.writeFileSync(output,JSON.stringify(anchor,null,2)+"\n",{flag:"wx",mode:0o644});
 console.log("EXPORTED custody-request anchor to",output,"head",anchor.head,"records",anchor.count);
 console.log("NOT INDEPENDENTLY REGISTERED: deliver and verify via separately trusted channel.");
}
try{run(process.argv.slice(2))}catch(e){console.error("ANCHOR EXPORT FAILED:",e.message);process.exitCode=1}
