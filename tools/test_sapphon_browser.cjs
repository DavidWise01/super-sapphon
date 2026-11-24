"use strict";
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const ROOT = "http://127.0.0.1:8765/docs/sapphon/";
const archived = JSON.parse(fs.readFileSync("docs/sapphon/live/clock.json","utf8"));
let passed=0;
async function check(name, fn) {
  await fn();passed++;process.stdout.write("PASS browser "+passed+" "+name+"\n");
}
async function ready(page) {
  await page.goto(ROOT,{waitUntil:"load"});
  await page.waitForFunction(()=>document.getElementById("health-accepted").textContent==="8",{timeout:15000});
}
async function main(){
const browser=await chromium.launch({headless:true});
try{
 const context=await browser.newContext({acceptDownloads:true});
 const page=await context.newPage(); const errs=[];
 page.on("pageerror",e=>errs.push(e.message));
 await ready(page);
 await check("three neon pump rings and nonempty canvas",async()=>{
  assert.equal(await page.locator("canvas#clock").count(),1);
  assert.equal(await page.locator("#phase").textContent(),"7");
  const px=await page.locator("canvas#clock").evaluate(c=>{
    const d=c.getContext("2d").getImageData(0,0,c.width,c.height).data;
    let bright=0;for(let i=0;i<d.length;i+=4)if(d[i]+d[i+1]+d[i+2]>400)bright++;
    return bright;
  });
  assert.ok(px>100,"Three-pump canvas not drawn");
 });
 await check("four clock registers populated from export",async()=>{
  for (const id of ["ymd","hms","angle","arcs"]) {
   const text=await page.locator("#"+id).textContent();
   assert.ok(text.includes("/"),id+" missing");
  }
 });
 await check("static source explicitly distinguished from live feed",async()=>{
  assert.match(await page.locator("#source-status").textContent(),/STATIC ARCHIVE/);
 });
 await check("checkpoint fingerprint and local persistence",async()=>{
  const digest=await page.locator("#ck-digest").textContent();
  assert.match(digest,/^[a-f0-9]{64}$/);
  const stored=await page.evaluate(()=>localStorage.getItem("sapphon094.readonly.checkpoint.v1"));
  assert.ok(stored&&JSON.parse(stored).records.length===8);
 });
 await check("downloaded checkpoint independently structured",async()=>{
  const wait=page.waitForEvent("download");
  await page.click("#export-checkpoint");
  const download=await wait;
  assert.match(download.suggestedFilename(),/sapphon-095-checkpoint-phase-7\.json/);
  const content=JSON.parse(fs.readFileSync(await download.path(),"utf8"));
  assert.equal(content.records.length,8);
  assert.match(content.digest,/^[a-f0-9]{64}$/);
 });
 await check("source-prefix verification does not append or reauthorize",async()=>{
  await page.click("#verify-prefix");
  await page.locator("#ck-prefix").getByText("PUBLISHED MATCH").waitFor();
  assert.equal(await page.locator("#health-accepted").textContent(),"8");
 });
 await check("isolated fault buttons do not mutate the ledger",async()=>{
  const before=await page.evaluate(()=>JSON.stringify(JSON.parse(localStorage.getItem("sapphon094.readonly.checkpoint.v1")).records));
  for(const kind of ["duplicate","gap","conflict","bad-sector","bad-hash"])await page.click('[data-fault="'+kind+'"]');
  await page.click("#ck-test");
  const after=await page.evaluate(()=>JSON.stringify(JSON.parse(localStorage.getItem("sapphon094.readonly.checkpoint.v1")).records));
  assert.equal(after,before);
  assert.equal(await page.locator("#health-accepted").textContent(),"8");
 });
 await page.reload({waitUntil:"load"});
 await check("reconnect restores checkpoint then matches published prefix",async()=>{
  await page.waitForFunction(()=>document.querySelector("#ck-prefix").textContent==="PUBLISHED MATCH");
  assert.match(await page.locator("#ck-source").textContent(),/RECOVERED LOCAL/);
  assert.equal(await page.locator("#health-accepted").textContent(),"8");
 });
 await check("browser recovery timeline shows historical segment",async()=>{
  assert.ok(await page.locator(".recovery-node").count()>=1);
 });
 await check("browser produced no uncaught JavaScript errors",async()=>{
  assert.deepEqual(errs,[]);
 });
 await context.close();
 const damaged=await browser.newContext();
 const tamperPage=await damaged.newPage();
 await ready(tamperPage);
 await tamperPage.evaluate(()=>{
  const key="sapphon094.readonly.checkpoint.v1";
  const ck=JSON.parse(localStorage.getItem(key));
  ck.records[0].day=!ck.records[0].day;
  localStorage.setItem(key,JSON.stringify(ck));
 });
 await tamperPage.reload({waitUntil:"load"});
 await check("corrupt persisted checkpoint halts restart",async()=>{
  await tamperPage.waitForFunction(()=>document.querySelector("#ck-prefix").textContent.includes("HALTED"));
  assert.match(await tamperPage.locator("#source-status").textContent(),/HALTED/);
  assert.equal(await tamperPage.locator("#health-accepted").textContent(),"0");
 });
 await damaged.close();
 const rewritten=await browser.newContext();
 const conflictPage=await rewritten.newPage();
 await ready(conflictPage);
 await conflictPage.route("**/docs/sapphon/live/clock.json",route=>{
  const forged=structuredClone(archived);
  forged.records[2].minute=!forged.records[2].minute;
  return route.fulfill({status:200,contentType:"application/json",body:JSON.stringify(forged)});
 });
 await conflictPage.reload({waitUntil:"load"});
 await check("changed published historical prefix halts reconnect",async()=>{
  await conflictPage.waitForFunction(()=>document.querySelector("#ck-prefix").textContent==="REJECTED PREFIX");
  assert.match(await conflictPage.locator("#health-state").textContent(),/HALTED/);
 });
 await rewritten.close();
 console.log("SAPPHON-096 CHROMIUM PASS",passed,"tests");
}finally{await browser.close()}
}
main().catch(e=>{console.error("FAIL browser",e);process.exitCode=1});
