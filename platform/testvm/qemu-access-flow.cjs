// Run only inside the retained QEMU guest, after reserving the browser slot.
// Uses candidate UI assets against the real installed gateway/core/executor.
const {chromium}=require('/home/harness/ui-smoke-tools/node_modules/playwright');
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
(async()=>{
 const account=JSON.parse(fs.readFileSync('/home/harness/qemu-owner-login.json','utf8'));
 const tenant=JSON.parse(fs.readFileSync('/home/harness/qemu-fresh-tenant-46.json','utf8'));
 const browser=await chromium.launch({headless:true});
 const prefix='qemu-access-'+Date.now();
 const bytes=Buffer.from('exact browser upload\r\nUTF-8: café\n');
 try {
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000},acceptDownloads:true});
  await context.addInitScript(id=>localStorage.setItem('panel.tenant',id),tenant.id);
  await context.route('https://localhost:8090/**',async route=>{
   const request=route.request(),url=new URL(request.url());
   if(request.method()!=='GET'||url.pathname.startsWith('/api/')||url.pathname.startsWith('/health/'))return route.continue();
   const file=path.join(__dirname,'../ui/dist',/^\/assets\/[a-zA-Z0-9._-]+$/.test(url.pathname)?url.pathname.slice(1):'index.html');
   const original=await route.fetch();const headers={...original.headers(),'cache-control':'no-store'};
   delete headers['content-length'];delete headers['content-encoding'];delete headers.etag;
   await route.fulfill({status:200,headers,contentType:file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':file.endsWith('.woff2')?'font/woff2':'text/html',body:fs.readFileSync(file)});
  });
  const page=await context.newPage();
  page.on('pageerror',e=>{throw e});
  let csrf='';
  page.on('response',async response=>{if(response.url().endsWith('/api/v1/operations')){const token=await response.headerValue('x-csrf-token');if(token)csrf=token}});
  await page.goto('https://localhost:8090/',{waitUntil:'networkidle'});
  await page.getByLabel('Username',{exact:true}).fill(account.username);
  await page.getByLabel('Password',{exact:true}).fill(account.password);
  await page.locator('button.auth-submit').click();
  await page.getByLabel('Username',{exact:true}).waitFor({state:'hidden'});
  const pending=page.waitForResponse(r=>r.url().endsWith('/api/v1/operations')&&r.request().postDataJSON()?.operation==='access.files.list');
  await page.locator('a[href="/files"]').click();assert.equal((await pending).status(),200);
  const siteID=await page.locator('.scope-bar select').first().inputValue();
  const otherTenant=JSON.parse(fs.readFileSync('/home/harness/qemu-created-tenant.json','utf8'));
  assert.notEqual(otherTenant.id,tenant.id);
  const denial=await page.evaluate(async ({siteID,tenantID})=>{
   const requestID='req_'+crypto.randomUUID().replaceAll('-','');
   const response=await fetch('/api/v1/operations',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Request-ID':requestID},body:JSON.stringify({api_version:'panel.cyberpanel.io/v1',request_id:requestID,operation:'access.files.list',tenant_id:tenantID,resource_id:siteID,payload:{root:{site_id:siteID,kind:'public'},directory:'',page:{limit:10}}})});
   return response.status;
  },{siteID,tenantID:otherTenant.id});
  assert.equal(denial,403,'cross-tenant file listing must be denied');
  const row=name=>page.locator('.file-table > button').filter({has:page.getByText(name,{exact:true})});
  const responseFor=operation=>page.waitForResponse(r=>r.url().endsWith('/api/v1/operations')&&r.request().postDataJSON()?.operation===operation);
  let mutations=0;page.on('request',r=>{if(r.url().endsWith('/api/v1/operations')&&r.postDataJSON()?.operation==='access.files.mutate')mutations++});
  await page.locator('input[type=file]').setInputFiles({name:prefix+'-too-large.bin',mimeType:'application/octet-stream',buffer:Buffer.alloc((4<<20)+1)});
  await page.getByRole('alert').filter({hasText:'direct 4 MiB editor-upload limit'}).waitFor();assert.equal(mutations,0,'oversized upload must be rejected before mutation');
  const name=prefix+'.txt',renamed=prefix+'-renamed.txt';
  let mutation=responseFor('access.files.mutate');
  await page.locator('input[type=file]').setInputFiles({name,mimeType:'text/plain',buffer:bytes});
  assert.equal((await mutation).status(),200);await row(name).waitFor();const editorResponse=responseFor('access.files.read_editor');await row(name).dblclick();
  const editor=await editorResponse;assert.equal(editor.status(),200);assert.deepEqual(Buffer.from((await editor.json()).result.content,'base64'),bytes);
  await page.locator('.editor-modal textarea').waitFor();assert.equal(await page.locator('.editor-modal textarea').inputValue(),bytes.toString().replaceAll('\r\n','\n'));
  await page.locator('.editor-modal').getByRole('button',{name:'Cancel',exact:true}).click();
  await row(name).click();const downloaded=page.waitForEvent('download');
  await page.locator('.inspector').getByRole('button',{name:'Download',exact:true}).click();
  const download=await downloaded;assert.deepEqual(fs.readFileSync(await download.path()),bytes);
  await page.getByRole('button',{name:'Rename',exact:true}).click();await page.getByLabel('New name',{exact:true}).fill(renamed);
  mutation=responseFor('access.files.mutate');await page.getByRole('button',{name:'Rename entry',exact:true}).click();assert.equal((await mutation).status(),200);await row(renamed).waitFor();
  await row(renamed).click();mutation=responseFor('access.trash.move');await page.locator('.inspector').getByRole('button',{name:'Trash',exact:true}).click();assert.equal((await mutation).status(),201);await row(renamed).waitFor({state:'hidden'});
  mutation=responseFor('access.trash.restore');await page.getByRole('button',{name:'Restore '+renamed,exact:true}).click();assert.equal((await mutation).status(),200);await row(renamed).waitFor();
  await row(renamed).click();const restoredDownload=page.waitForEvent('download');await page.locator('.inspector').getByRole('button',{name:'Download',exact:true}).click();assert.deepEqual(fs.readFileSync(await (await restoredDownload).path()),bytes);
  // Native HTTP verifies the uploaded/restored inode through the real OLS vhost.
  const getPublic=(filename)=>execFileSync('/usr/bin/curl',['--fail','--silent','--show-error','--header','Host: qemu-fresh46.example.invalid','http://127.0.0.1/'+filename]);
  assert.deepEqual(getPublic(renamed),bytes);
  await row(renamed).click();mutation=responseFor('access.trash.move');await page.locator('.inspector').getByRole('button',{name:'Trash',exact:true}).click();assert.equal((await mutation).status(),201);await row(renamed).waitFor({state:'hidden'});
  const phpName=prefix+'.php';mutation=responseFor('access.files.mutate');await page.locator('input[type=file]').setInputFiles({name:phpName,mimeType:'application/x-httpd-php',buffer:Buffer.from('<?php header("Content-Type: text/plain"); echo "access-php-ok";')});assert.equal((await mutation).status(),200);await row(phpName).waitFor();assert.equal(getPublic(phpName).toString(),'access-php-ok');
  await row(phpName).click();mutation=responseFor('access.trash.move');await page.locator('.inspector').getByRole('button',{name:'Trash',exact:true}).click();assert.equal((await mutation).status(),201);await row(phpName).waitFor({state:'hidden'});
  const boundaryName=prefix+'-boundary.bin',boundary=Buffer.alloc(4<<20,0xa5);
  mutation=responseFor('access.files.mutate');await page.locator('input[type=file]').setInputFiles({name:boundaryName,mimeType:'application/octet-stream',buffer:boundary});assert.equal((await mutation).status(),200);await row(boundaryName).waitFor();await row(boundaryName).click();
  const boundaryDownload=page.waitForEvent('download');await page.locator('.inspector').getByRole('button',{name:'Download',exact:true}).click();assert.deepEqual(fs.readFileSync(await (await boundaryDownload).path()),boundary);
  mutation=responseFor('access.trash.move');await page.locator('.inspector').getByRole('button',{name:'Trash',exact:true}).click();assert.equal((await mutation).status(),201);await row(boundaryName).waitFor({state:'hidden'});
  assert(csrf);console.log('PASS candidate UI + installed APIs: upload/read/download/rename/trash/restore exact bytes, native static/PHP; only unique fixtures moved to recoverable trash');
 } finally {await browser.close()}
})().catch(error=>{console.error(error.message);process.exitCode=1});
