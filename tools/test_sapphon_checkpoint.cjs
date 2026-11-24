"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const crypto=require("node:crypto");
globalThis.crypto ??= crypto.webcrypto;
const mon=require("../docs/sapphon/monitor.js");
const archive=JSON.parse(fs.readFileSync("docs/sapphon/live/clock.json","utf8"));
const history=archive.records;
const copy=x=>JSON.parse(JSON.stringify(x));
let passed=0;
async function test(name,fn){await fn();passed++;console.log("PASS",name)}
async function rejects(name,fn,code){await test(name,async()=>await assert.rejects(fn,e=>e.code===code))}
(async()=>{
  await test("complete checkpoint roundtrip",async()=>{
    const cp=await mon.makeCheckpoint(history);
    assert.equal(cp.schema,"sapphon-browser-checkpoint-v1");
    assert.equal(cp.last_seq,history.length-1);
    assert.deepEqual(await mon.recoverCheckpoint(cp),history);
  });
  await test("stable digest independent of object-key ordering",async()=>{
    const reshuffled=history.map(r=>({
      day:r.day,minute:r.minute,second:r.second,
      uncertainty:r.uncertainty,address:{hms:r.address.hms,ymd:r.address.ymd,
      arc_arc_arc:r.address.arc_arc_arc,degree_arcminute_arcsecond:r.address.degree_arcminute_arcsecond},
      hash:r.hash,sector:r.sector,seq:r.seq,estimate:r.estimate
    }));
    assert.equal(await mon.fingerprint(reshuffled),await mon.fingerprint(history));
  });
  const cp=await mon.makeCheckpoint(history);
  await rejects("altered authorization fails restore",async()=>{
    const x=copy(cp);x.records[0].day=!x.records[0].day;await mon.recoverCheckpoint(x)
  },"CHECKPOINT");
  await rejects("altered uncertainty fails restore",async()=>{
    const x=copy(cp);x.records[2].uncertainty+=1;await mon.recoverCheckpoint(x)
  },"CHECKPOINT");
  await rejects("altered clock register fails restore",async()=>{
    const x=copy(cp);x.records[3].address.hms[1]=11;await mon.recoverCheckpoint(x)
  },"CHECKPOINT");
  await rejects("altered identity fails restore",async()=>{
    const x=copy(cp);x.records[4].hash="b".repeat(64);await mon.recoverCheckpoint(x)
  },"CHECKPOINT");
  await rejects("truncated checkpoint fails manifest",async()=>{
    const x=copy(cp);x.records.pop();await mon.recoverCheckpoint(x)
  },"CHECKPOINT");
  await test("legitimate reconnect replay is duplicate-only",async()=>{
    const persisted=await mon.recoverCheckpoint(cp);
    const result=mon.scan(persisted,history);
    assert.equal(result.append.length,0);assert.equal(result.duplicate,history.length);
  });
  await test("legitimate next recorded phase extends recovered history",async()=>{
    const nxt=copy(history.at(-1));nxt.seq=history.length;nxt.sector=history.length%8;
    nxt.hash="a".repeat(64);nxt.second=false;
    const result=mon.scan(await mon.recoverCheckpoint(cp),[...history,nxt]);
    assert.equal(result.append.length,1);
    const newcp=await mon.makeCheckpoint([...history,...result.append]);
    assert.deepEqual(await mon.recoverCheckpoint(newcp).then(r=>r.at(-1)),nxt);
  });
  await test("non-mutating rejection on conflicting prefix",async()=>{
    const old=copy(history),t=copy(history);t[2].minute=!t[2].minute;
    assert.throws(()=>mon.scan(history,t),e=>e.code==="CONFLICT");
    assert.deepEqual(history,old);
  });
  await test("syntactic HTML script validation with Node",async()=>{
    const html=fs.readFileSync("docs/sapphon/index.html","utf8");
    const m=html.match(/<script>\s*([\s\S]*?)<\/script>/);
    assert.ok(m);
    new (require("node:vm").Script)(m[1],{filename:"sapphon-ui.js"});
  });
  console.log("SAPPHON-094:",passed,"checkpoint/reconnect tests passed");
})().catch(e=>{console.error(e);process.exitCode=1});
