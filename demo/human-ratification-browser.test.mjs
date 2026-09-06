import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import puppeteer from 'puppeteer-core';

const source = readFileSync(new URL('../src/server.rs', import.meta.url), 'utf8');
function rustConstant(name) {
  const marker = `const ${name}: &str = r`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1);
  const quote = source.indexOf('"', start + marker.length);
  const hashes = source.slice(start + marker.length, quote);
  const end = source.indexOf(`"${hashes};`, quote + 1);
  return source.slice(quote + 1, end);
}
const html = rustConstant('RATIFICATION_CONSOLE');
const script = rustConstant('RATIFICATION_CONSOLE_SCRIPT');
const packageJson = JSON.parse(readFileSync(new URL('package.json', import.meta.url), 'utf8'));
const digest = `sha256:${'a'.repeat(64)}`;

test('canonical demo test builds the gateway before browser execution', () => {
  assert.match(packageJson.scripts.test, /^cargo build --locked --bin smesh-a2a-gateway && node --test /);
});
const hostile = '<img src=x onerror="window.pwned=1"><script>window.pwned=2</script>';
const canonicalArtifact = JSON.stringify({artifactId:'artifact-1',name:hostile,description:hostile,parts:[{text:hostile,mediaType:'text/html',metadata:{hostile}}],metadata:{hostile},extensions:[hostile]});

test('debug binary exposes the repository-owned authentic packet seed hook', () => {
  const result = spawnSync(new URL('../target/debug/smesh-a2a-gateway', import.meta.url).pathname, ['test-seed-ratification'], {
    env: { PATH: process.env.PATH ?? '' }, encoding: 'utf8', timeout: 5000,
  });
  assert.match(result.stderr, /SMESH_TEST_RATIFICATION_SEED_SQLITE_PATH is required/);
});
function packet(revision = 1, reviewed = false, terminalDecision = null) {
  return { packet: { taskId: 'task-1', generation: 1, taskRevision: 4, packetHash: digest,
    checkpoint: hostile, checkpointHash: digest, completionPolicyId: hostile,
    completionPolicyVersion: 1, completionPolicyHash: digest,
    evidence: [hostile, 'plain'], evidenceHashes: [digest, `sha256:${'b'.repeat(64)}`],
    artifactSetDigest: `sha256:${'d'.repeat(64)}`,
    artifacts: [{ name: hostile, mediaType: 'text/html', digest: `sha256:${'c'.repeat(64)}`, canonicalJson: canonicalArtifact }],
    uncertaintySummary: hostile, createdAtMillis: 1 }, history: [], phase: terminalDecision ? 'decided' : 'pending',
    revision, etag: `"ratification-v1:${String(revision).padStart(64, '0')}"`, reviewedByCurrentActor: reviewed, terminalDecision };
}
async function fixture() {
  const requests = []; let view = packet(); let releaseReview;
  const reviewBarrier = new Promise(r => { releaseReview = r; });
  const server = createServer(async (req, res) => {
    const recorded={ method: req.method, url: req.url, headers: req.headers, body:'' }; requests.push(recorded);
    res.setHeader('cache-control', 'private, no-store');
    res.setHeader('content-security-policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.setHeader('x-content-type-options', 'nosniff'); res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    if (req.url === '/ratification/console') { res.setHeader('content-type','text/html'); return res.end(html); }
    if (req.url === '/ratification/console.js') { res.setHeader('content-type','text/javascript'); return res.end(script); }
    if (req.method === 'GET') { res.setHeader('content-type','application/json'); res.setHeader('etag',view.etag); return res.end(JSON.stringify(view)); }
    let body=''; for await (const chunk of req) body += chunk; recorded.body=body;
    if (req.headers['if-match'] !== view.etag) { res.statusCode=412; return res.end(); }
    if (req.url.endsWith('/review')) { await reviewBarrier; view = packet(2, true); }
    else view = packet(3, true, JSON.parse(body).decision);
    res.setHeader('content-type','application/json'); res.setHeader('etag',view.etag); res.end(JSON.stringify(view));
  });
  await new Promise((resolve,reject) => { server.once('error',reject); server.listen(0,'127.0.0.1',resolve); });
  return { server, requests, releaseReview, url:`http://127.0.0.1:${server.address().port}` };
}

async function close(server) { server.closeAllConnections?.(); await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve())); }

test('production console enforces exact review and decision gates in Chromium', { timeout: 30_000 }, async () => {
  const f = await fixture(); let browser; const errors=[]; const credential=`test-${randomUUID()}`;
  try {
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless:true,
      args:['--no-sandbox','--disable-dev-shm-usage'] });
    const page = await browser.newPage(); page.on('console', m => { if (m.type()==='error') errors.push(m.text()); }); page.on('pageerror',e=>errors.push(e.message));
    await page.goto(`${f.url}/ratification/console`, {waitUntil:'domcontentloaded', timeout:5000});
    assert.equal(await page.$eval('#review-submit', e=>e.disabled), true);
    await page.type('#task','task-1'); await page.type('#tenant','tenant-a'); await page.type('#token',credential);
    await page.click('#load'); await page.waitForSelector('#ack-evidence-1',{timeout:5000});
    assert.equal(await page.$eval('#token',e=>e.value),'');
    const residue = await page.evaluate(()=>({url:location.href,html:document.documentElement.outerHTML,local:Object.keys(localStorage),session:Object.keys(sessionStorage),pwned:window.pwned||0}));
    assert.equal(residue.url,`${f.url}/ratification/console`); assert.equal(residue.html.includes(credential),false);
    assert.deepEqual(residue.local,[]); assert.deepEqual(residue.session,[]); assert.equal(residue.pwned,0);
    assert.ok((await page.$eval('#packet',e=>e.textContent)).includes(canonicalArtifact));
    assert.equal((await page.$$('img')).length,0); assert.equal((await page.$$('#review-items input[type=checkbox]')).length,5);
    assert.equal(await page.$eval('#review-submit',e=>e.disabled),true);
    for (const box of await page.$$('#review-items input[type=checkbox]')) await box.click();
    assert.equal(await page.$eval('#review-submit',e=>e.disabled),false);
    await page.evaluate(()=>{ document.querySelector('#review-submit').click(); document.querySelector('#review-submit').click(); });
    assert.equal(await page.$eval('#review-submit',e=>e.disabled),true); f.releaseReview();
    await page.waitForFunction(()=>!document.querySelector('#approve').disabled,{timeout:5000});
    await page.type('#rationale','ship it'); await page.click('#approve'); await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='TERMINAL',{timeout:5000});
    assert.equal(await page.$eval('#approve',e=>e.disabled),true);
    assert.equal(f.requests.filter(r=>r.url.endsWith('/review')).length,1);
    assert.equal(f.requests.filter(r=>r.url.endsWith('/decision')).length,1);
    assert.ok(f.requests.every(r=>!r.url.includes(credential))); assert.equal(errors.length,0);
    const mutation=f.requests.find(r=>r.method==='POST'); assert.equal(mutation.headers.authorization,`Bearer ${credential}`);
    assert.equal(mutation.headers['x-smesh-tenant'],'tenant-a'); assert.ok(mutation.headers['idempotency-key']);
    assert.equal(JSON.parse(mutation.body).artifactManifestDigest,packet().packet.artifactSetDigest);
  } finally { if(browser) await browser.close(); await close(f.server); }
});

test('auth, server failure, retry, and stale refetch remain locked', { timeout: 30_000 }, async () => {
  const f = await fixture(); let browser; let getCount=0; let postCount=0; let terminalMode=false;
  try {
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless:true, args:['--no-sandbox','--disable-dev-shm-usage'] });
    const page=await browser.newPage(); await page.setRequestInterception(true);
    page.on('request', request=>{
      if (!request.url().includes('/ratification/v1/')) return request.continue();
      if (request.method()==='GET') {
        getCount++;
        if(getCount===1)return request.respond({status:401,body:''});
        if(getCount===2)return request.respond({status:503,body:''});
        return request.respond({status:200,contentType:'application/json',body:JSON.stringify(terminalMode?packet(3,true,'Approve'):packet())});
      }
      postCount++;
      return request.respond({status:412,body:''});
    });
    await page.goto(`${f.url}/ratification/console`,{waitUntil:'domcontentloaded',timeout:5000});
    await page.type('#task','task-1'); await page.click('#load');
    await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='AUTH_LOCKED',{timeout:5000});
    assert.equal(await page.$eval('#review-submit',e=>e.disabled),true);
    await page.click('#load'); await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='ERROR_LOCKED',{timeout:5000});
    assert.equal(await page.$eval('#retry',e=>e.hidden),false); await page.click('#retry');
    await page.waitForSelector('#ack-uncertainty',{timeout:5000});
    for(const box of await page.$$('#review-items input'))await box.click();
    await page.click('#review-submit');
    await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='AWAITING_REVIEW',{timeout:5000});
    assert.equal(await page.$$eval('#review-items input',boxes=>boxes.every(box=>!box.checked)),true);
    assert.equal(postCount,1); assert.equal(getCount,4);
    terminalMode=true; await page.reload({waitUntil:'domcontentloaded',timeout:5000}); await page.type('#task','task-1'); await page.click('#load');
    await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='TERMINAL',{timeout:5000});
    assert.equal(await page.$$eval('#review-submit,#approve,#reject,#amend',buttons=>buttons.every(button=>button.disabled)),true);
  } finally { if(browser)await browser.close(); await close(f.server); }
});

test('reject and amend use their exact semantic decisions', { timeout: 30_000 }, async () => {
  let browser;
  try {
    browser=await puppeteer.launch({executablePath:process.env.CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
    for(const choice of ['reject','amend']){
      const f=await fixture(); const page=await browser.newPage();
      try{
        await page.goto(`${f.url}/ratification/console`,{waitUntil:'domcontentloaded',timeout:5000}); await page.type('#task','task-1'); await page.click('#load'); await page.waitForSelector('#ack-uncertainty',{timeout:5000});
        for(const box of await page.$$('#review-items input'))await box.click(); await page.click('#review-submit'); f.releaseReview(); await page.waitForFunction(()=>!document.querySelector('#reject').disabled,{timeout:5000});
        await page.click(`#${choice}`); await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='TERMINAL',{timeout:5000});
        const request=f.requests.find(r=>r.url.endsWith('/decision')); assert.ok(request); assert.equal(request.headers['idempotency-key'].length>0,true); assert.equal(JSON.parse(request.body).decision,choice);
      }finally{await page.close();await close(f.server);}
    }
  }finally{if(browser)await browser.close();}
});

test('production script never uses innerHTML or persistent credential stores', () => {
  for (const forbidden of ['innerHTML','localStorage','sessionStorage','indexedDB','document.cookie','location.hash']) assert.equal(script.includes(forbidden),false,forbidden);
});

test('nonce identity binds exact body, task, generation, and action while 409 never stale-reloads', { timeout: 30_000 }, async () => {
  const f = await fixture(); let browser; const posts=[]; let generation=1; let gets=0;
  try {
    browser=await puppeteer.launch({executablePath:process.env.CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
    const page=await browser.newPage(); await page.setRequestInterception(true);
    page.on('request',request=>{
      if(!request.url().includes('/ratification/v1/'))return request.continue();
      if(request.method()==='GET'){
        gets++; const value=packet(1,true); value.packet.taskId=decodeURIComponent(request.url().split('/').pop()); value.packet.generation=generation;
        return request.respond({status:200,contentType:'application/json',body:JSON.stringify(value)});
      }
      posts.push({url:request.url(),nonce:request.headers()['idempotency-key'],body:request.postData()});
      return request.respond({status:409,body:''});
    });
    await page.goto(`${f.url}/ratification/console`,{waitUntil:'domcontentloaded',timeout:5000});
    await page.type('#task','task-1'); await page.click('#load'); await page.waitForFunction(()=>!document.querySelector('#approve').disabled);
    await page.type('#rationale','first rationale'); await page.click('#approve');
    await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='ERROR_LOCKED');
    assert.equal(gets,1); await page.click('#retry'); await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='ERROR_LOCKED');
    assert.equal(posts[1].nonce,posts[0].nonce); assert.equal(posts[1].body,posts[0].body); assert.equal(gets,1);
    await page.click('#load'); await page.waitForFunction(()=>!document.querySelector('#approve').disabled);
    await page.type('#rationale',' changed'); await page.click('#approve'); await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='ERROR_LOCKED');
    assert.notEqual(posts[2].nonce,posts[0].nonce);
    await page.$eval('#task',node=>{node.value='task-2';}); await page.click('#load'); await page.waitForFunction(()=>!document.querySelector('#approve').disabled);
    await page.click('#approve'); await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='ERROR_LOCKED');
    assert.notEqual(posts[3].nonce,posts[2].nonce);
    generation=2; await page.click('#load'); await page.waitForFunction(()=>!document.querySelector('#approve').disabled);
    await page.click('#approve'); await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='ERROR_LOCKED');
    assert.notEqual(posts[4].nonce,posts[3].nonce);
  } finally { if(browser)await browser.close(); await close(f.server); }
});

test('canceled and superseded views remain terminally locked', { timeout: 30_000 }, async () => {
  const f=await fixture(); let browser;
  try {
    browser=await puppeteer.launch({executablePath:process.env.CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
    for(const phase of ['canceled','superseded']){
      const page=await browser.newPage(); await page.setRequestInterception(true);
      page.on('request',request=>{
        if(request.method()!=='GET'||!request.url().includes('/ratification/v1/'))return request.continue();
        const value=packet(3,true); value.phase=phase; return request.respond({status:200,contentType:'application/json',body:JSON.stringify(value)});
      });
      await page.goto(`${f.url}/ratification/console`,{waitUntil:'domcontentloaded',timeout:5000}); await page.type('#task','task-1'); await page.click('#load');
      await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='TERMINAL');
      assert.equal(await page.$$eval('#review-submit,#approve,#reject,#amend',buttons=>buttons.every(button=>button.disabled)),true);
      await page.close();
    }
  } finally { if(browser)await browser.close(); await close(f.server); }
});

test('empty bearer submission switches the production script to mTLS for GET review and decision', { timeout: 30_000 }, async () => {
  const f=await fixture(); let browser;
  try {
    browser=await puppeteer.launch({executablePath:process.env.CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
    const page=await browser.newPage();
    await page.goto(`${f.url}/ratification/console`,{waitUntil:'domcontentloaded',timeout:5000});
    await page.type('#task','task-1'); await page.type('#tenant','tenant-a'); await page.type('#token','prior-bearer'); await page.click('#load');
    await page.waitForSelector('#ack-uncertainty',{timeout:5000});
    const boundary=f.requests.length;
    const nextGet=page.waitForResponse(response=>response.request().method()==='GET'&&response.url().endsWith('/tasks/task-1'),{timeout:5000});
    await page.$eval('#bootstrap',form=>form.requestSubmit()); await nextGet;
    for(const box of await page.$$('#review-items input'))await box.click();
    await page.click('#review-submit'); f.releaseReview();
    await page.waitForFunction(()=>!document.querySelector('#approve').disabled,{timeout:5000});
    await page.type('#rationale','mTLS-only decision'); await page.click('#approve');
    await page.waitForFunction(()=>document.querySelector('#status').dataset.state==='TERMINAL',{timeout:5000});
    const switched=f.requests.slice(boundary).filter(request=>request.url.includes('/ratification/v1/'));
    assert.deepEqual(switched.map(request=>request.method),['GET','POST','POST']);
    assert.ok(switched.every(request=>!Object.hasOwn(request.headers,'authorization')));
  } finally { if(browser)await browser.close(); await close(f.server); }
});

test('principal inputs and request locks erase the private packet surface', { timeout: 30_000 }, async () => {
  const f=await fixture(); let browser;
  try {
    browser=await puppeteer.launch({executablePath:process.env.CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
    const page=await browser.newPage();
    await page.goto(`${f.url}/ratification/console`,{waitUntil:'domcontentloaded',timeout:5000});
    await page.type('#task','task-1'); await page.type('#token','actor-a'); await page.click('#load');
    await page.waitForSelector('#ack-uncertainty',{timeout:5000}); await page.type('#rationale','private rationale');
    for(const selector of ['#task','#tenant','#token']){
      if(selector==='#task') await page.$eval(selector,node=>{node.value='task-1';});
      await page.type(selector,'x');
      assert.deepEqual(await page.evaluate(()=>({hidden:document.querySelector('#review-surface').hidden,packet:document.querySelector('#packet').textContent,boxes:document.querySelectorAll('#review-items input').length,rationale:document.querySelector('#rationale').value})),{hidden:true,packet:'',boxes:0,rationale:''});
      await page.$eval(selector,node=>{node.value='';}); await page.type('#task','task-1'); await page.click('#load'); await page.waitForSelector('#ack-uncertainty',{timeout:5000});
    }
    await page.setRequestInterception(true); let mode='auth';
    page.on('request',request=>request.url().includes('/ratification/v1/')?request.respond({status:mode==='auth'?401:503,body:''}):request.continue());
    for(const expected of ['AUTH_LOCKED','ERROR_LOCKED']){
      await page.click('#load'); await page.waitForFunction(value=>document.querySelector('#status').dataset.state===value,{},expected);
      assert.deepEqual(await page.evaluate(()=>({hidden:document.querySelector('#review-surface').hidden,packet:document.querySelector('#packet').textContent,boxes:document.querySelectorAll('#review-items input').length,rationale:document.querySelector('#rationale').value})),{hidden:true,packet:'',boxes:0,rationale:''});
      mode='error';
    }
  } finally { if(browser)await browser.close(); await close(f.server); }
});

test('delayed actor response cannot render after identity changes', { timeout: 30_000 }, async () => {
  const f=await fixture(); let browser; let release;
  try {
    browser=await puppeteer.launch({executablePath:process.env.CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
    const page=await browser.newPage(); await page.setRequestInterception(true);
    const barrier=new Promise(resolve=>{release=resolve;});
    page.on('request',async request=>{
      if(!request.url().includes('/ratification/v1/'))return request.continue();
      await barrier; const value=packet(); value.packet.checkpoint='actor-a-private';
      return request.respond({status:200,contentType:'application/json',body:JSON.stringify(value)}).catch(()=>{});
    });
    await page.goto(`${f.url}/ratification/console`,{waitUntil:'domcontentloaded',timeout:5000});
    await page.type('#task','task-1'); await page.type('#token','actor-a'); await page.click('#load');
    await page.type('#token','actor-b'); release(); await new Promise(resolve=>setTimeout(resolve,100));
    assert.deepEqual(await page.evaluate(()=>({hidden:document.querySelector('#review-surface').hidden,packet:document.querySelector('#packet').textContent,state:document.querySelector('#status').dataset.state})),{hidden:true,packet:'',state:'BOOTSTRAP_LOCKED'});
  } finally { release?.(); if(browser)await browser.close(); await close(f.server); }
});
