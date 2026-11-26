#!/usr/bin/env node
"use strict";
/* SAPPHON-162 browser assertions. Real DOM interactions, canvas frames,
 * page errors, and a screenshot. Source mirrors are not independent witnesses.
 */
const {chromium}=require("playwright");
const fs=require("node:fs");
const crypto=require("node:crypto");
const assert=require("node:assert/strict");
const path=require("node:path");

const ORIGIN="https://davidwise01.github.io/super-sapphon/";
const CASES=[
  {path:"docs/sapphon/phase-xiv/160/",title:"SAPPHON-160",
   buttons:[
    ["#ci","#status","CI NOT INDEPENDENTLY VERIFIED"],
    ["#fork","#status","SIGNED HISTORIES DIVERGE"],
    ["#custody","#status","ONE SHARED SOURCE ANCESTRY"],
    ["#normal","#status","DESIGN COMPLETE"]
   ]},
  {path:"docs/sapphon/phase-xv/161/",title:"SAPPHON-161",
   buttons:[
    ["#compile","#finding","RUST-CHECK:FAILED"],
    ["#hash","#finding","HISTORICAL-FREEZE:FAILED"],
    ["#browser","#finding","BROWSER-SMOKE:FAILED"],
    ["#neutral","#finding","OBSERVATIONS PENDING"]
   ]}
];
function sha(b){return crypto.createHash("sha256").update(b).digest("hex")}
async function main(){
  const dir=path.resolve("qualification-artifact");
  fs.mkdirSync(dir,{recursive:true});
  const browser=await chromium.launch({headless:true});
  const reports=[];
  try{
    for(const c of CASES){
      const page=await browser.newPage({viewport:{width:1280,height:900},deviceScaleFactor:1});
      const errors=[];
      page.on("pageerror",e=>errors.push(String(e)));
      page.on("console",e=>{if(e.type()==="error")errors.push(e.text())});
      const url=ORIGIN+c.path;
      const response=await page.goto(url,{waitUntil:"domcontentloaded",timeout:30000});
      assert.ok(response&&response.status()===200, "HTTP 200 required: "+url);
      assert.match(await page.title(),new RegExp(c.title));
      assert.equal(await page.locator("canvas").count(),1,"one 4D canvas expected");
      await page.waitForTimeout(400);
      const canvasBefore=await page.locator("canvas").evaluate(el=>{
        return {w:el.width,h:el.height,
          data:Array.from(el.getContext("2d").getImageData(
            Math.floor(el.width/2),Math.floor(el.height/2),1,1).data)};
      });
      assert.ok(canvasBefore.w>300&&canvasBefore.h>200,"canvas pixel dimensions");
      const transitions=[];
      for(const [button,target,expected] of c.buttons){
        await page.locator(button).click();
        await page.waitForFunction(([selector,value])=>
          document.querySelector(selector)?.textContent.trim()===value,
          [target,expected],{timeout:3000});
        transitions.push({button,observed:await page.locator(target).innerText()});
      }
      const hold=await page.locator(".hold").innerText();
      assert.equal(hold.trim(),"HOLD","operational authority must remain HOLD");
      await page.waitForTimeout(100);
      assert.deepEqual(errors,[],"no browser console/page exceptions");
      const shot=path.join(dir,c.title.toLowerCase()+"-chromium.png");
      await page.screenshot({path:shot,fullPage:true});
      const bytes=fs.readFileSync(shot);
      assert.ok(bytes.length>10000,"real nonempty Chromium capture");
      reports.push({url,title:c.title,http_status:response.status(),
        canvas:canvasBefore,transitions,hold,
        screenshot:shot,screenshot_sha256:sha(bytes),
        errors,statement:"BROWSER_OBSERVATION_ONLY_NOT_EXTERNAL_CUSTODY"});
      await page.close();
    }
  }finally{await browser.close()}
  const out=path.join(dir,"162-browser-acceptance.json");
  fs.writeFileSync(out,JSON.stringify({schema:"sapphon-162-browser-v1",
    decision:"BROWSER_DIAGNOSTIC_HOLD",reports},null,2)+"\n");
  console.log("SAPPHON-162 PASS interactive DOM scenarios:",reports.reduce((n,x)=>n+x.transitions.length,0));
  console.log("Source-owned Chromium evidence; independent custody HOLD");
}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1});
