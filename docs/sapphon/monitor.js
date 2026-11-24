/* SAPPHON-093: pure read-only monitor, shared by browser and Node tests.
 * Not a clock, a signer, or an authorization engine.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SapphonMonitor = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const keys = ["ymd", "hms", "degree_arcminute_arcsecond", "arc_arc_arc"];
  const permissions = ["second", "minute", "day"];
  function fail(code, message) { const err = new Error(message); err.code = code; throw err; }
  function digest(r) {
    return JSON.stringify([
      r.seq, r.sector, r.hash, r.estimate, r.uncertainty,
      ...permissions.map(k => r[k]), ...keys.map(k => r.address[k])
    ]);
  }
  function valid(r, seq) {
    if (!r || typeof r !== "object" || !Number.isSafeInteger(r.seq) || r.seq !== seq)
      fail("GAP", "Missing or out-of-order phase, expected " + seq);
    if (!Number.isSafeInteger(r.sector) || r.sector !== seq % 8)
      fail("PHASE", "Eight-phase mismatch at " + seq);
    if (typeof r.hash !== "string" || !/^[0-9a-f]{64}$/.test(r.hash))
      fail("IDENTITY", "Invalid record digest at " + seq);
    if (!r.address || keys.some(k => !Array.isArray(r.address[k]) ||
        r.address[k].length !== 3 || r.address[k].some(v => !Number.isSafeInteger(v))))
      fail("REGISTER", "Invalid four-register address at " + seq);
    if (!Number.isFinite(r.estimate) || !(r.uncertainty === null ||
        Number.isFinite(r.uncertainty) && r.uncertainty >= 0))
      fail("UNCERTAINTY", "Invalid time estimate/uncertainty at " + seq);
    if (permissions.some(k => typeof r[k] !== "boolean"))
      fail("AUTHORIZATION", "Nonrecorded authorization value at " + seq);
  }
  function scan(history, incoming) {
    if (!Array.isArray(history) || !Array.isArray(incoming))
      fail("FORMAT", "Expected record arrays");
    const append = [], knownHashes = new Set(history.map(r => r.hash));
    let duplicate = 0;
    for (const record of incoming) {
      if (!record || !Number.isSafeInteger(record.seq) || record.seq < 0)
        fail("FORMAT", "Invalid sequence identity");
      const seq = record.seq;
      const expected = history.length + append.length;
      if (seq < history.length) {
        valid(record, seq);
        if (digest(record) !== digest(history[seq]))
          fail("CONFLICT", "Immutable record rewritten at " + seq);
        duplicate++;
      } else if (seq === expected) {
        valid(record, seq);
        if (knownHashes.has(record.hash)) fail("IDENTITY", "Record identity reused");
        knownHashes.add(record.hash);
        append.push(record);
      } else fail("GAP", "Expected phase " + expected + ", received " + seq);
    }
    return { append, duplicate, lastSequence: history.length + append.length - 1 };
  }
  function validateEnvelope(o, pin) {
    if (!o || o.schema !== "sapphon-clock-records-v1" ||
        !["static-archive", "recorded-stream"].includes(o.mode))
      fail("FORMAT", "Unrecognized feed contract");
    if (o.source_root !== pin || o.clock_origin !== "synthetic-export")
      fail("PROVENANCE", "Source route mismatch");
    if (!Array.isArray(o.records) || !Number.isSafeInteger(o.record_count) ||
        o.record_count !== o.records.length || !o.records.length ||
        o.records[0].seq !== 0)
      fail("GAP", "Incomplete published feed");
    return true;
  }
  function fixtureFault(history, kind) {
    const batch = structuredClone(history);
    if (!batch.length) fail("EMPTY", "No recorded phases available");
    if (kind === "duplicate") return [...batch, structuredClone(batch.at(-1))];
    if (kind === "gap") { batch[batch.length - 1].seq += 2; return batch; }
    if (kind === "conflict") { batch[0].day = !batch[0].day; return batch; }
    if (kind === "bad-sector") { batch[0].sector = 7; return batch; }
    if (kind === "bad-hash") { batch[0].hash = "invalid"; return batch; }
    fail("FAULT", "Unknown synthetic test");
  }
  /* Checkpoint covers every displayed field, including authorization, not merely
     the producer's claimed record identity. Browser WebCrypto and Node 22 compatible. */
  function checkpointText(rows) {
    if (!Array.isArray(rows)) fail("CHECKPOINT","Invalid checkpoint history");
    scan([],rows);
    return JSON.stringify(rows.map(r => [
      r.seq,r.sector,r.hash,r.estimate,r.uncertainty,
      ...permissions.map(k => r[k]),...keys.map(k => r.address[k])
    ]));
  }
  async function fingerprint(rows) {
    const cryptoApi = globalThis.crypto;
    if (!cryptoApi || !cryptoApi.subtle) fail("CRYPTO", "SHA-256 unavailable");
    const input = new TextEncoder().encode(checkpointText(rows));
    const bytes = new Uint8Array(await cryptoApi.subtle.digest("SHA-256",input));
    return Array.from(bytes,b => b.toString(16).padStart(2,"0")).join("");
  }
  async function makeCheckpoint(rows) {
    if (!rows.length) fail("CHECKPOINT","No records to persist");
    const records = JSON.parse(JSON.stringify(rows));
    return {schema:"sapphon-browser-checkpoint-v1",last_seq:records.length-1,
      digest:await fingerprint(records),records};
  }
  async function recoverCheckpoint(saved) {
    if (!saved || saved.schema!=="sapphon-browser-checkpoint-v1" ||
        !Array.isArray(saved.records) || !saved.records.length ||
        saved.records.length>100000 || saved.last_seq!==saved.records.length-1 ||
        typeof saved.digest!=="string" || !/^[a-f0-9]{64}$/.test(saved.digest))
      fail("CHECKPOINT","Unusable checkpoint manifest");
    let computed;
    try { computed=await fingerprint(saved.records); }
    catch(e) { if(e.code)throw e;fail("CHECKPOINT","Malformed persisted clock history"); }
    if(computed!==saved.digest)fail("CHECKPOINT","Persisted record data differs from checkpoint fingerprint");
    return saved.records;
  }
  return Object.freeze({scan, validateEnvelope, fixtureFault,
    fingerprint, makeCheckpoint, recoverCheckpoint});
});
