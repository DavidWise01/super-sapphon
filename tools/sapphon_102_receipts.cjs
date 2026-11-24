"use strict";
/* SAPPHON-102: cryptographic custody receipts with explicitly supplied custodian
 * registry. Signature proves key possession, NOT independent legal or operational
 * custody. Never converts same-owner GitHub/Pages mirrors into separate roots. */
const crypto=require("node:crypto");
const HEX=/^[a-f0-9]{64}$/;
const ID=/^[a-z0-9-]{4,64}$/;
function fail(code){throw Error(code)}
function anchorDigest(anchor){
 const keys=["schema","key_id","governance_spki_sha256","head","count","checkpoint_signature","independently_retained","recorded_utc"];
 if(!anchor||Object.keys(anchor).sort().join("|")!==keys.slice().sort().join("|")||
    anchor.schema!=="sapphon-external-anchor-v1"||
    anchor.independently_retained!==false||anchor.recorded_utc!==null||
    !HEX.test(anchor.head)||!HEX.test(anchor.governance_spki_sha256)||
    !Number.isSafeInteger(anchor.count)||anchor.count<1)fail("INVALID_ANCHOR");
 return crypto.createHash("sha256").update("SAPPHON102-ANCHOR\u0000")
   .update(JSON.stringify(keys.map(k=>anchor[k]))).digest("hex");
}
function receiptBytes(payload){
 const keys=["schema","anchor_digest","anchor_head","anchor_count","custodian_id","custody_root","key_id","receipt_serial","custody_claim"];
 if(!payload||Object.keys(payload).sort().join("|")!==keys.slice().sort().join("|")||
    payload.schema!=="sapphon-custody-receipt-v1"||
    !HEX.test(payload.anchor_digest)||!HEX.test(payload.anchor_head)||
    !Number.isSafeInteger(payload.anchor_count)||payload.anchor_count<1||
    ![payload.custodian_id,payload.custody_root,payload.key_id,payload.receipt_serial].every(x=>typeof x==="string"&&ID.test(x))||
    payload.custody_claim!=="synthetic-test-custody")fail("RECEIPT_FIELDS");
 return Buffer.from(JSON.stringify(keys.map(k=>payload[k])),"utf8");
}
function receiptForTest(anchor,{custodian_id,custody_root,key_id,receipt_serial},privateKey){
 const payload={schema:"sapphon-custody-receipt-v1",anchor_digest:anchorDigest(anchor),
    anchor_head:anchor.head,anchor_count:anchor.count,custodian_id,custody_root,key_id,
    receipt_serial,custody_claim:"synthetic-test-custody"};
 return {payload,signature:crypto.sign(null,receiptBytes(payload),privateKey).toString("base64")};
}
function verifyReceipts(anchor,receipts,registry,options={}){
 const digest=anchorDigest(anchor);
 if(!Array.isArray(receipts)||receipts.length>128)fail("RECEIPT_BATCH");
 if(!registry||typeof registry!=="object"||Array.isArray(registry))fail("NO_TRUST_REGISTRY");
 const seenSerial=new Set(),seenKeys=new Set(),claimedRoots=new Set(),accepted=[];
 for(const entry of receipts){
  if(!entry||Object.keys(entry).sort().join("|")!=="payload|signature")fail("RECEIPT_ENVELOPE");
  const p=entry.payload,bytes=receiptBytes(p);
  if(p.anchor_digest!==digest||p.anchor_head!==anchor.head||p.anchor_count!==anchor.count)fail("ANCHOR_BINDING");
  if(seenSerial.has(p.receipt_serial))fail("REPLAYED_RECEIPT");
  seenSerial.add(p.receipt_serial);
  const r=Object.hasOwn(registry,p.key_id)?registry[p.key_id]:null;
  if(!r||r.revoked===true)fail("UNKNOWN_OR_REVOKED_CUSTODIAN");
  if(r.custodian_id!==p.custodian_id||r.custody_root!==p.custody_root)fail("CUSTODIAN_ROOT_MISMATCH");
  if(typeof entry.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(entry.signature)||
     !crypto.verify(null,bytes,r.publicKey,Buffer.from(entry.signature,"base64")))fail("BAD_CUSTODY_SIGNATURE");
  if(seenKeys.has(p.key_id))fail("REPEATED_CUSTODIAN_KEY");
  seenKeys.add(p.key_id);
  claimedRoots.add(p.custody_root);
  accepted.push({custodian_id:p.custodian_id,custody_root:p.custody_root,receipt_serial:p.receipt_serial});
 }
 // Deliberately decline to convert self-described custodian-root strings into
 // independently validated organizations. External custody remains unconfirmed.
 return {status:"CRYPTOGRAPHIC_RECEIPTS_VERIFIED",receipt_count:accepted.length,
   declared_custody_roots:claimedRoots.size,independently_authenticated_custodians:0,
   independent_custody_confirmed:false,clock_authority:false,accepted};
}
module.exports={anchorDigest,receiptBytes,receiptForTest,verifyReceipts};
