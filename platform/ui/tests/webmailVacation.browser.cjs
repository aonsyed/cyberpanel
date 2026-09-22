// Isolated Vue UI/contract regression. Requires installed Playwright on NODE_PATH.
const {chromium}=require('playwright');
const {createRequire}=require('node:module');
const path=require('node:path');
const assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),requireUI=createRequire(path.join(root,'package.json'));
(async()=>{
 const {createServer}=await import(requireUI.resolve('vite'));
 const calls=[],rules=new Map();let epoch=7,denyList=false,denyUpdate=false,delayedList;
 const entry=`import {createApp} from 'vue';import WebmailPage from '/src/components/WebmailPage.vue';import {sessionStore} from '/src/store.ts';import {APIClient} from '/src/api.ts';import '/src/styles.css';sessionStore.setTenant('tenant-one');const api=new APIClient('/fixture');await api.loadCatalog();const app=createApp(WebmailPage);app.provide('api',api);app.mount('#app');`;
 const server=await createServer({root,server:{host:'127.0.0.1',port:0},plugins:[{name:'vacation-fixture',resolveId(id){if(id==='/fixture-entry.js')return root+'/fixture-entry.js'},load(id){if(id===root+'/fixture-entry.js')return entry},configureServer(instance){instance.middlewares.use(async(req,res,next)=>{
  if(req.url==='/fixture'){res.setHeader('Content-Type','text/html');res.end('<!doctype html><html><body><div id="app"></div><script type="module" src="/fixture-entry.js"></script></body></html>');return}
  if(req.url==='/fixture/api/v1/catalog'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({api_version:'panel.cyberpanel.io/v1',operations:['webmail.account.list','webmail.account.switch','webmail.folder.list','webmail.message.list',...['list','get','create','update','enabled','delete'].map(action=>'webmail.data.vacation.'+action)].map(name=>({name,auth:'required',mutating:!name.endsWith('.list')&&!name.endsWith('.get')}))}));return}
  if(req.url!=='/fixture/api/v1/operations')return next();let body='';for await(const chunk of req)body+=chunk;const envelope=JSON.parse(body),operation=envelope.operation,options={tenantId:envelope.tenant_id,resourceId:envelope.resource_id,expectedGeneration:envelope.expected_generation||0,payload:envelope.payload};calls.push({operation,options});res.setHeader('Content-Type','application/json');
  const result=value=>res.end(JSON.stringify({api_version:'panel.cyberpanel.io/v1',request_id:envelope.request_id,operation,result:value}));const fail=(status,detail)=>{res.statusCode=status;res.end(JSON.stringify({status,title:detail,detail,code:'fixture'}))};
  if(operation==='webmail.account.list')return result({items:[{id:'mailbox-one',address:'one@example.test',authorization_epoch:epoch},{id:'mailbox-two',address:'two@example.test',authorization_epoch:9}]});
  if(operation==='webmail.account.switch')return result({});
  if(operation==='webmail.folder.list')return result({items:[{name:'INBOX',role:'inbox'}]});
  if(operation==='webmail.message.list')return result({items:[]});
  if(!operation.startsWith('webmail.data.vacation.'))return fail(400,'Unexpected fixture operation');
  const {payload}=options,id=payload.mailbox_id,currentEpoch=id==='mailbox-one'?epoch:9;assert.equal(payload.authorization_epoch,currentEpoch);
  if(operation.endsWith('.list')){if(denyList)return fail(403,'Mailbox access revoked');const value={mailbox_id:id,domain_id:'domain-one',mailbox_generation:3,rules:[...rules.values()].filter(rule=>rule.mailbox_id===id)};if(delayedList){delayedList.resolve=()=>result(value);return}return result(value)}
  const request=payload.request;assert.equal(request.domain_id,'domain-one');assert.equal(request.mailbox_generation,3);assert.equal(options.resourceId,request.rule_id);assert.equal(options.expectedGeneration,request.expected_generation);
  const previous=rules.get(request.rule_id);
  if(operation.endsWith('.create')){assert.equal(request.expected_generation,0);const rule={id:request.rule_id,tenant_id:'tenant-one',domain_id:'domain-one',mailbox_id:id,mailbox_generation:3,generation:1,enabled:false,state:'suspended',settings:request.settings};rules.set(rule.id,rule);return result(rule)}
  assert(previous);assert.equal(previous.mailbox_id,id);assert.equal(request.expected_generation,previous.generation);
  if(operation.endsWith('.get'))return result(previous);
  if(operation.endsWith('.delete')){rules.delete(previous.id);res.statusCode=204;res.end();return}
  if(denyUpdate)return fail(409,'Vacation generation changed; reload required');
  const rule={...previous,generation:previous.generation+1,mailbox_generation:request.mailbox_generation};if(operation.endsWith('.update'))rule.settings=request.settings;else{assert.equal(typeof payload.enabled,'boolean');rule.enabled=payload.enabled;rule.state=payload.enabled?'active':'suspended'}rules.set(rule.id,rule);return result(rule);
 })}}]});await server.listen();const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1366,height:900}});const errors=[];page.on('pageerror',error=>errors.push(error.message));await page.goto(server.resolvedUrls.local[0]+'fixture');
  await page.getByRole('button',{name:'Vacation reply',exact:true}).click();const panel=page.getByRole('region',{name:'Vacation reply',exact:true});await panel.getByLabel('Vacation subject',{exact:true}).fill('Away');await panel.getByLabel('Vacation message',{exact:true}).fill('Back soon');await panel.getByRole('button',{name:'Create vacation reply',exact:true}).click();await panel.getByText('Vacation reply created.',{exact:true}).waitFor();
  const created=calls.find(call=>call.operation.endsWith('.create'));assert.equal(created.options.payload.request.settings.repeat_interval,86400000000000);assert.equal(created.options.payload.request.settings.timezone,'UTC');
  rules.get(created.options.resourceId).mailbox_generation=2;rules.get(created.options.resourceId).settings.senders={allow:['trusted@example.test'],deny:[],excluded_domains:['excluded.example.test']};await panel.getByRole('button',{name:'Read vacation reply',exact:true}).click();await panel.getByText('Vacation reply loaded.',{exact:true}).waitFor();
  await panel.getByLabel('Vacation subject',{exact:true}).fill('Updated');await panel.getByRole('button',{name:'Save vacation changes',exact:true}).click();await panel.getByText('Vacation reply updated.',{exact:true}).waitFor();
  assert.deepEqual(calls.find(call=>call.operation.endsWith('.update')).options.payload.request.settings.senders,{allow:['trusted@example.test'],deny:[],excluded_domains:['excluded.example.test']});
  await panel.getByRole('button',{name:'Enable vacation reply',exact:true}).click();await panel.getByText('Vacation reply enabled.',{exact:true}).waitFor();await panel.getByRole('button',{name:'Disable vacation reply',exact:true}).click();await panel.getByText('Vacation reply disabled.',{exact:true}).waitFor();
  await panel.getByRole('button',{name:'Reload vacation replies',exact:true}).click();await panel.getByLabel('Vacation subject',{exact:true}).waitFor();assert.equal(await panel.getByLabel('Vacation subject',{exact:true}).inputValue(),'Updated');
  denyUpdate=true;await panel.getByRole('button',{name:'Save vacation changes',exact:true}).click();await panel.getByRole('alert').getByText('Vacation generation changed; reload required',{exact:true}).waitFor();denyUpdate=false;await panel.getByRole('button',{name:'Reload vacation replies',exact:true}).click();await panel.getByLabel('Vacation subject',{exact:true}).waitFor();
  const remove=panel.getByRole('button',{name:'Delete vacation reply',exact:true});assert(await remove.isDisabled());await panel.getByLabel('Confirm permanent deletion of this vacation reply',{exact:true}).check();await remove.click();await panel.getByText('Vacation reply deleted.',{exact:true}).waitFor();assert.equal(rules.size,0);
  await panel.getByLabel('Vacation subject',{exact:true}).fill('Must not cross accounts');await page.locator('.account-picker select').selectOption('mailbox-two');await panel.waitFor({state:'hidden'});await page.getByRole('button',{name:'Vacation reply',exact:true}).click();assert.equal(await panel.getByLabel('Vacation subject',{exact:true}).inputValue(),'');
  await panel.getByRole('button',{name:'Close vacation reply',exact:true}).click();denyList=true;await page.getByRole('button',{name:'Vacation reply',exact:true}).click();await panel.getByRole('alert').getByText('Mailbox access revoked',{exact:true}).waitFor();assert.equal(await panel.getByLabel('Vacation subject',{exact:true}).count(),0);denyList=false;
  delayedList={};await panel.getByRole('button',{name:'Reload vacation replies',exact:true}).click();await page.waitForTimeout(50);await page.locator('.account-picker select').selectOption('mailbox-one');await panel.waitFor({state:'hidden'});if(delayedList.resolve)delayedList.resolve();delayedList=null;
  await page.getByRole('button',{name:'Vacation reply',exact:true}).click();await panel.getByLabel('Vacation subject',{exact:true}).fill('Epoch stale');epoch=8;await page.getByRole('button',{name:'Refresh',exact:true}).click();await panel.waitFor({state:'hidden'});await page.getByRole('button',{name:'Vacation reply',exact:true}).click();assert.equal(await panel.getByLabel('Vacation subject',{exact:true}).inputValue(),'');
  assert.deepEqual(errors,[]);console.log('PASS vacation lifecycle payloads, generation failure, explicit delete, mailbox switch, denied discovery, late reply, epoch refresh');
 }finally{await browser.close();await server.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
