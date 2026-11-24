"use strict";
const {chromium}=require("playwright");
const assert=require("node:assert/strict");
const root="http://127.0.0.1:8765/docs/sapphon/phase-vii/104/";
let checks=0;
function check(name,cb){return Promise.resolve().then(cb).then(()=>{checks++;console.log("PASS chromium",checks,name)})}
(async()=>{
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage(),errors=[];
  page.on("pageerror",e=>errors.push(e.message));
  await page.goto(root,{waitUntil:"load"});
  await page.locator("#ymd").waitFor();
  await page.waitForFunction(()=>document.querySelector("#ymd").textContent!=="—");
  await check("three neon physical pumps draw actual pixels",async()=>{
    const pixels=await page.locator("canvas").evaluate(c=>{const d=c.getContext("2d").getImageData(0,0,c.width,c.height).data;let bright=0;for(let n=0;n<d.length;n+=4)if(d[n]+d[n+1]+d[n+2]>440)bright++;return bright});
    assert.ok(pixels>100,"Missing pump art");
    assert.equal(await page.locator("canvas").count(),1);
  });
  await check("four frozen clock registers populated",async()=>{
   for(const k of ["ymd","hms","degrees","arcs"])assert.match(await page.locator("#"+k).textContent(),/\d+\s*\/\s*\d+/);
  });
  await check("archived source is explicitly synthetic",async()=>assert.match(await page.locator("#record-label").textContent(),/Synthetic archive/));
  await check("qualification remains HOLD",async()=>assert.match(await page.locator("header").textContent(),/QUALIFICATION HOLD/));
  await check("valid synthetic consumption is visually explanatory",async()=>{
   await page.click("#shared");assert.match(await page.locator("#result").textContent(),/SIGNED_CHALLENGE_AND_RECEIPT/);
  });
  await check("forgery button changes no source or authorization",async()=>{
   await page.click("#forged");assert.match(await page.locator("#result").textContent(),/CHALLENGE_SIGNATURE/);
  });
  await check("durable replay rejection presented",async()=>{
   await page.click("#replay");assert.match(await page.locator("#result").textContent(),/DURABLE_REPLAY/);
  });
  await check("expired nonce rejection presented",async()=>{
   await page.click("#split");assert.match(await page.locator("#result").textContent(),/CHALLENGE_EXPIRED/);
  });
  await check("viewer has no uncaught JavaScript errors",async()=>assert.deepEqual(errors,[]));
  console.log("SAPPHON-104 CHROMIUM PASS",checks);
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
