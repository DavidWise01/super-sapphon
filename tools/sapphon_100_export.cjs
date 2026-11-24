"use strict";
/* SAPPHON-100 export: explicit private key stays outside Git and exported JSON.
 * Usage:
 * node tools/sapphon_100_export.cjs ledger.json governance-private.pem key-id audit.json governance-public.pem
 * A synthetic ephemeral fixture may be built with --test-fixture OUTDIR.
 */
const crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path");
const {signedForTest}=require("./sapphon_099_enrollment.cjs");
const {createCheckpoint,verifyCheckpoint}=require("./sapphon_100_checkpoint.cjs");
function save(outdir,entries,privateKey,publicKey,keyId){
 fs.mkdirSync(outdir,{recursive:true});
 const checkpoint=createCheckpoint(entries,privateKey,publicKey,keyId);
 verifyCheckpoint(entries,checkpoint,publicKey,keyId);
 const doc={entries,checkpoint};
 fs.writeFileSync(path.join(outdir,"audit.json"),JSON.stringify(doc,null,2)+"\n",{mode:0o644});
 fs.writeFileSync(path.join(outdir,"governance-public.pem"),publicKey.export({type:"spki",format:"pem"}));
 return doc;
}
function fixture(outdir){
 const gov=crypto.generateKeyPairSync("ed25519");
 const a=crypto.generateKeyPairSync("ed25519");
 const b=crypto.generateKeyPairSync("ed25519");
 const {appendEvent}=require("./sapphon_099_enrollment.cjs");
 let entries=[],head=null;
 function add(type,key,generation,pub,reason){
  const event={type,source_id:"synthetic-archive",ancestry_root:"one-owned-root",
    role:"synthetic-test",key_id:key,public_key_pem:type==="REVOKE"?null:pub.export({type:"spki",format:"pem"}),
    reason:type==="REVOKE"?reason:null,generation,index:entries.length,prev_event_hash:head};
  const next=appendEvent(entries,signedForTest(event,gov.privateKey),gov.publicKey);
  entries=next.entries;head=next.head;
 }
 add("ENROLL","test-key-a",0,a.publicKey);
 add("REVOKE","test-key-a",0,a.publicKey,"Synthetic compromise test");
 add("REENROLL","test-key-b",1,b.publicKey);
 const doc=save(outdir,entries,gov.privateKey,gov.publicKey,"test-governance-100");
 console.log("EXPORTED synthetic audit checkpoint",doc.checkpoint.payload.head,"with",doc.entries.length,"events");
}
function main(argv){
 if(argv[0]==="--test-fixture"&&argv.length===2){fixture(argv[1]);return}
 if(argv.length!==5)throw Error("Usage: ledger.json private-key.pem key-id audit.json public-key.pem");
 const [ledgerFile,privateFile,keyId,auditFile,pubFile]=argv;
 const entries=JSON.parse(fs.readFileSync(ledgerFile,"utf8")).entries;
 const priv=crypto.createPrivateKey(fs.readFileSync(privateFile));
 if(priv.asymmetricKeyType!=="ed25519")throw Error("ED25519_REQUIRED");
 const pub=crypto.createPublicKey(priv);
 const checkpoint=createCheckpoint(entries,priv,pub,keyId);
 verifyCheckpoint(entries,checkpoint,pub,keyId);
 fs.writeFileSync(auditFile,JSON.stringify({entries,checkpoint},null,2)+"\n");
 fs.writeFileSync(pubFile,pub.export({type:"spki",format:"pem"}));
 console.log("EXPORTED governance-signed checkpoint",checkpoint.payload.head,"governance identity",keyId);
}
try{main(process.argv.slice(2))}catch(e){console.error("EXPORT FAILED:",e.message);process.exitCode=1}
