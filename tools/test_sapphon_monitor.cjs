"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const monitor=require("../docs/sapphon/monitor.js");
const archive=JSON.parse(fs.readFileSync("docs/sapphon/live/clock.json","utf8"));
const PIN="sapphon-082-frozen-synthetic-export";
const rows=archive.records;
let passed=0;
function test(name,fn){fn();passed++;console.log("PASS",name)}
function rejects(name,fn,code){test(name,()=>assert.throws(fn,e=>e.code===code))}
const clone=x=>JSON.parse(JSON.stringify(x));
test("publisher envelope accepted",()=>assert.equal(monitor.validateEnvelope(archive,PIN),true));
test("record set accepted",()=>assert.equal(monitor.scan([],rows).append.length,8));
test("identical replay idempotent",()=>assert.equal(monitor.scan(rows,rows).duplicate,8));
test("duplicate existing record counted",()=>assert.equal(monitor.scan(rows,[rows[0],rows[0]]).duplicate,2));
rejects("sequence gap blocked",()=>monitor.scan(rows,monitor.fixtureFault(rows,"gap")),"GAP");
rejects("authorization mutation despite same hash blocked",()=>monitor.scan(rows,monitor.fixtureFault(rows,"conflict")),"CONFLICT");
rejects("sector mismatch rejected",()=>monitor.scan(rows,monitor.fixtureFault(rows,"bad-sector")),"PHASE");
rejects("invalid digest rejected",()=>monitor.scan(rows,monitor.fixtureFault(rows,"bad-hash")),"IDENTITY");
rejects("source provenance mismatch rejected",()=>monitor.validateEnvelope({...archive,source_root:"other-root"},PIN),"PROVENANCE");
rejects("same-hash conflicting registered values rejected",()=>{const v=clone(rows);v[0].uncertainty+=3;monitor.scan(rows,v)},"CONFLICT");
rejects("gap at append rejected",()=>{const v=clone(rows.at(-1));v.seq=10;monitor.scan(rows,[v])},"GAP");
test("valid append from synthetic recorded output",()=>{const v=clone(rows.at(-1));v.seq=8;v.sector=0;v.hash="a".repeat(64);v.day=false;assert.equal(monitor.scan(rows,[v]).append.length,1)});
test("append from untouched evidence is non-mutating",()=>{const before=JSON.stringify(rows);monitor.scan(rows,rows);assert.equal(JSON.stringify(rows),before)});
rejects("unknown feed mode rejected",()=>monitor.validateEnvelope({...archive,mode:"hardware-live"},PIN),"FORMAT");
console.log("SAPPHON-093:",passed,"tests passed");