// QEMU only. Requires exclusive browser/passkey AND native access lease.
// Installed assets/APIs/native sshd only; no response or asset interception.
const {chromium}=require('/home/harness/ui-smoke-tools/node_modules/playwright');
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {execFileSync,spawnSync}=require('node:child_process');

(async()=>{
 assert(process.argv.includes('--installed')&&process.argv.includes('--leased'),'reserve exclusive browser/native lease before --installed --leased');
 const account=JSON.parse(fs.readFileSync('/home/harness/qemu-owner-login.json','utf8'));
 const tenant=JSON.parse(fs.readFileSync('/home/harness/qemu-fresh-tenant-46.json','utf8'));
 const passkeyPath='/home/harness/qemu-virtual-passkey.json';
 const workspace=fs.mkdtempSync('/home/harness/lanes/access/sftp-installed-');
 const prefix='qemu-sftp-'+Date.now();
 const receipt={stage:'prepared',workspace,tenant:tenant.id,filename:prefix+'.bin',symlink:prefix+'-escape',grant:null,username:null};
 const save=()=>fs.writeFileSync(path.join(workspace,'receipt.json'),JSON.stringify(receipt,null,2),{mode:0o600});
 save();
 execFileSync('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',path.join(workspace,'client')]);
 const publicKey=fs.readFileSync(path.join(workspace,'client.pub'),'utf8').trim();
 const bytes=Buffer.from('installed-sftp-exact-bytes\x00\xff\r\n','latin1');
 fs.writeFileSync(path.join(workspace,'source.bin'),bytes,{mode:0o600});
 const browser=await chromium.launch({headless:true});
 let cdp,authenticatorId;
 try{
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000}});
  await context.addInitScript(id=>localStorage.setItem('panel.tenant',id),tenant.id);
  const page=await context.newPage();page.setDefaultTimeout(12000);
  cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
  ({authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}}));
  await cdp.send('WebAuthn.addCredential',{authenticatorId,credential:JSON.parse(fs.readFileSync(passkeyPath,'utf8'))});
  page.on('response',response=>{if(response.url().endsWith('/api/v1/operations'))console.log(response.request().postDataJSON()?.operation+' HTTP '+response.status())});
  const responseFor=operation=>page.waitForResponse(response=>response.url().endsWith('/api/v1/operations')&&response.request().postDataJSON()?.operation===operation);
  await page.goto('https://localhost:8090/',{waitUntil:'networkidle'});
  await page.getByLabel('Username',{exact:true}).fill(account.username);
  const login=responseFor('identity.session.webauthn.finish');
  await page.getByRole('button',{name:'Use a passkey',exact:true}).click();
  const loginResponse=await login;
  const updated=await cdp.send('WebAuthn.getCredentials',{authenticatorId});
  fs.writeFileSync(passkeyPath,JSON.stringify(updated.credentials[0]),{mode:0o600});
  assert.equal(loginResponse.status(),200);await page.getByLabel('Username',{exact:true}).waitFor({state:'hidden'});
  receipt.stage='authenticated';save();

  await page.locator('a[href="/files"]').click();
  const siteSelect=page.locator('.scope-bar select').first();
  await siteSelect.locator('option').filter({hasText:'qemu-fresh46.example.invalid'}).waitFor();
  await siteSelect.selectOption({label:'qemu-fresh46.example.invalid'});
  receipt.site=await siteSelect.inputValue();assert(receipt.site);save();
  await page.locator('a[href="/access"]').click();
  await page.locator('.head-actions').getByRole('button',{name:'Add access',exact:true}).click();
  const drawer=page.getByRole('dialog',{name:'Add access',exact:true});
  await drawer.getByLabel('Access kind',{exact:true}).selectOption('ftps');
  await drawer.getByLabel('FTPS password',{exact:true}).waitFor();assert.equal(await drawer.getByLabel('SSH public key for SFTP',{exact:true}).count(),0);
  await drawer.getByLabel('Access kind',{exact:true}).selectOption('terminal');assert.equal(await drawer.getByLabel('FTPS password',{exact:true}).count(),0);
  await drawer.getByLabel('Access kind',{exact:true}).selectOption('ssh_key');assert.equal(await drawer.getByLabel('FTPS password',{exact:true}).count(),0);
  await drawer.getByLabel('Site',{exact:true}).fill(receipt.site);
  await drawer.getByLabel('Label',{exact:true}).fill(prefix);
  await drawer.getByLabel('SSH public key for SFTP',{exact:true}).fill(publicKey);
  await drawer.getByLabel('File access',{exact:true}).selectOption('read_write');
  await drawer.getByLabel('Expires after (seconds)',{exact:true}).fill('900');
  const created=responseFor('access.credential.create');
  await drawer.getByRole('button',{name:'Add access',exact:true}).click();
  const createdResponse=await created;const creation=await createdResponse.json();
  receipt.create_request=createdResponse.request().postDataJSON().request_id;
  receipt.create_status=createdResponse.status();save();
  assert.equal(createdResponse.status(),201,JSON.stringify({code:creation.code,title:creation.title}));
  receipt.grant=creation.result.resource.id;receipt.generation=creation.result.resource.generation;receipt.stage='granted';save();
  await drawer.getByRole('button',{name:'Close',exact:true}).last().click();
  const listed=responseFor('access.credential.list');await page.getByRole('button',{name:'Refresh',exact:true}).click();
  const listing=await (await listed).json();const resource=listing.result.items.find(row=>row.id===receipt.grant);assert(resource);
  receipt.username=resource.username;assert.match(receipt.username,/^cpsftp_[0-9a-f]{20}$/);save();
  const row=page.locator('tbody tr').filter({hasText:receipt.username});await row.waitFor();
  const cell=row.locator('td').filter({hasText:receipt.username});
  assert.equal(await cell.evaluate(element=>{const selection=window.getSelection();selection.removeAllRanges();const range=document.createRange();range.selectNodeContents(element);selection.addRange(range);return selection.toString()}),receipt.username);
  console.log('PASS installed Add access protocol-specific fields, create201, dedicated SFTP login displayed/selectable');

  const hostKey=fs.readFileSync('/etc/ssh/ssh_host_ed25519_key.pub','utf8').trim();
  fs.writeFileSync(path.join(workspace,'known_hosts'),'127.0.0.1 '+hostKey+'\n',{mode:0o600});
  const runSFTP=(commands,success=true)=>{
   const batch=path.join(workspace,'batch');fs.writeFileSync(batch,commands+'\n',{mode:0o600});
   const result=spawnSync('/usr/bin/sftp',['-b',batch,'-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+path.join(workspace,'known_hosts'),'-o','IdentitiesOnly=yes','-i',path.join(workspace,'client'),receipt.username+'@127.0.0.1'],{encoding:'utf8',timeout:12000});
   if(success)assert.equal(result.status,0,result.stderr);else assert.notEqual(result.status,0,'unexpected SFTP authorization');
   return result;
  };
  runSFTP('put '+path.join(workspace,'source.bin')+' public/'+receipt.filename+'\nget public/'+receipt.filename+' '+path.join(workspace,'received.bin'));
  assert.deepEqual(fs.readFileSync(path.join(workspace,'received.bin')),bytes);receipt.stage='transferred';save();
  for(const target of ['/etc/passwd','../../etc/passwd'])runSFTP('get '+target+' '+path.join(workspace,'forbidden.bin'),false);
  const crossSite=process.argv.find(arg=>arg.startsWith('--cross-site-file='))?.slice('--cross-site-file='.length);
  if(crossSite){assert(/^\/var\/lib\/cyberpanel\/sites\/s-[a-z0-9]+\/roots\/g[0-9]+\/releases\/current\/public\/[a-zA-Z0-9._-]+$/.test(crossSite));assert(fs.statSync(crossSite).isFile(),'cross-site proof requires an actual known regular file');runSFTP('get '+crossSite+' '+path.join(workspace,'forbidden.bin'),false);receipt.cross_site_denied=crossSite;save()}
  runSFTP('ln -s /etc/passwd public/'+receipt.symlink);
  runSFTP('get public/'+receipt.symlink+' '+path.join(workspace,'forbidden.bin'),false);
  console.log('PASS installed native SFTP exact-byte upload/download and absolute/traversal/symlink escape denial');
  runSFTP('rm public/'+receipt.filename+'\nrm public/'+receipt.symlink);receipt.files_removed=true;save();

  await row.locator('summary').click();await row.getByRole('button',{name:'Revoke',exact:true}).click();
  const revoked=responseFor('access.credential.revoke');await page.getByRole('dialog').getByRole('button',{name:'Revoke',exact:true}).click();
  const revokedResponse=await revoked;const revocation=await revokedResponse.json();assert.equal(revokedResponse.status(),200,JSON.stringify({code:revocation.code,title:revocation.title}));
  runSFTP('ls',false);receipt.stage='revoked';receipt.revoked=true;save();
  console.log('PASS installed UI revoke200 and native reauthentication denied');
  fs.unlinkSync(path.join(workspace,'client'));receipt.private_key_removed=true;save();
  console.log('Receipt '+path.join(workspace,'receipt.json'));
 }catch(error){console.error('Stage '+receipt.stage+'; receipt '+path.join(workspace,'receipt.json'));throw error}
 finally{
  if(cdp&&authenticatorId){const saved=await cdp.send('WebAuthn.getCredentials',{authenticatorId}).catch(()=>null);if(saved?.credentials?.length===1)fs.writeFileSync(passkeyPath,JSON.stringify(saved.credentials[0]),{mode:0o600})}
  await browser.close();
 }
})().catch(error=>{console.error(error.stack);process.exitCode=1});
