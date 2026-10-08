const {test:baseTest, expect}=require('@playwright/test');
const fs=require('node:fs/promises');
const path=require('node:path');
const test=baseTest.extend({page:async({page},use,testInfo)=>{
 await page.coverage.startJSCoverage({resetOnNavigation:false});
 await use(page);
 const entries=await page.coverage.stopJSCoverage();
 const directory=path.resolve('_tmp/evidence/js-v8');await fs.mkdir(directory,{recursive:true});
 await fs.writeFile(path.join(directory,testInfo.testId.replace(/[^a-zA-Z0-9_-]/g,'_')+'-'+testInfo.retry+'.json'),JSON.stringify(entries.filter(entry=>entry.url.endsWith('/app.js'))));
}});
test.setTimeout(10000);
const prefix='/api/hassio_ingress/example/';
const rev='a'.repeat(64), newer='b'.repeat(64);
async function fixture(page,mode='ingress',initialized=true){
 await page.route('https://shared.fastly.steamstatic.com/**',r=>r.fulfill({contentType:'image/svg+xml',body:'<svg xmlns="http://www.w3.org/2000/svg" width="600" height="900"><rect width="600" height="900" fill="#22382d"/><text x="50" y="400" fill="#8de7bb" font-size="48">Fixture cover</text></svg>'}));
 const calls=[]; let authenticated=mode==='ingress'; let desired=rev;
 const pcs=[{pc_id:'desk',display_name:'Desk <img onerror=alert(1)>',ssh_host:'192.0.2.1',ssh_port:22,ssh_user:'wolf-manager',trust_state:'unenrolled'}, {pc_id:'lounge',display_name:'Lounge',ssh_host:'192.0.2.2',ssh_port:22,ssh_user:'wolf-manager',trust_state:'enrolled'}];
 await page.route('http://wolf.test/**',async route=>{
  const req=route.request(), u=new URL(req.url()); const p=u.pathname.slice(prefix.length); const method=req.method(); const body=req.postDataJSON();
  if(p.startsWith('api/v1/')){
   const endpoint=p.slice(7); calls.push({endpoint,method,body,headers:req.headers()});
   const reply=(data,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});
   if(endpoint==='bootstrap/status')return reply({initialized});
   if(endpoint.startsWith('auth/login-challenge'))return reply({challenge:'challenge-secret',expires_at:999999999});
   if(endpoint==='auth/login'||endpoint==='bootstrap'){authenticated=true;return reply({csrf_token:'session-csrf',expires_at:999999999},endpoint==='bootstrap'?201:200);}
   if(!authenticated)return reply({error:{code:'unauthenticated',message:'Sign in required'}},401);
   if(endpoint==='auth/session')return reply({authenticated:true,expires_at:999999999});
   if(endpoint==='auth/csrf')return reply({csrf_token:'bound-csrf',expires_at:999999999});
   if(endpoint==='auth/logout'||endpoint==='auth/password'){authenticated=false;return route.fulfill({status:204});}
   if(endpoint==='pcs'&&method==='GET')return reply({pcs});
   if(endpoint==='pcs'&&method==='POST'){pcs.push({...body,trust_state:'unenrolled'});return reply(pcs.at(-1),201);}
   if(/^pcs\/[^/]+$/.test(endpoint))return method==='DELETE'?route.fulfill({status:204}):reply({...pcs[0],...body});
   if(endpoint.endsWith('/status'))return reply({status:{systemd_state:'active',container_state:'running',restart_count:0,exit_code:null,staged_revision:rev,running_revision:rev,recovery_pending:false},capabilities:{version:1,pc_id:endpoint.split('/')[1],ready:true,proton_cachyos:false,reasons:[]},availability:'online',observed_at:1});
   if(endpoint.endsWith('/settings')&&method==='GET')return reply({settings:{debug:{test_ball:false},parameters:{fsr4:{label:'FSR4',launch_options:'PROTON_FSR4_UPGRADE=1 %command%',description:'FSR4'}},games:{'570':{direct_launch:false,proton_cachyos:false,parameters:[]}}},desired_revision:desired,staged_revision:rev,running_revision:rev});
   if(endpoint.includes('/games/570/settings')){desired=newer;return reply({desired_revision:desired});}
   if(endpoint.endsWith('/games'))return reply({games:[{version:1,pc_id:endpoint.split('/')[1],app_id:'570',name:endpoint.includes('/lounge/')?'Lounge game':'Dota 2',cover_url:'https://shared.fastly.steamstatic.com/store_item_assets/steam/apps/570/library_600x900.jpg',library_id:'main',catalog_generation:2,observed_at_ms:1}],catalog_generation:2,observed_at:1,availability:endpoint.includes('/lounge/')?'offline':'online'});
   if(endpoint==='parameters')return reply({parameters:{fsr4:{label:'FSR4',launch_options:'PROTON_FSR4_UPGRADE=1 %command%',description:'FSR4'}}});
   if(endpoint.startsWith('parameters/')||endpoint==='settings/debug')return reply({});
   if(endpoint.endsWith('/ssh/public-key'))return reply({public_key:'ssh-ed25519 AAAATEST fixture-only'});
   if(endpoint.endsWith('/ssh/probe'))return reply({probe_id:'fixture-probe',algorithm:'ssh-ed25519',fingerprint:'SHA256:fixture',expires_at:999999999});
   if(endpoint.endsWith('/ssh/enroll'))return reply({trust_state:'enrolled'});
   if(endpoint.endsWith('/logs'))return reply({lines:['bounded fixture log'],truncated:true});
   if(endpoint.endsWith('/operations'))return reply({operations:[{operation_id:'11111111-1111-4111-8111-111111111111',pc_id:'desk',kind:'restart',state:'unknown_interrupted',desired_revision:rev,submitted_at:1,started_at:2,completed_at:null,sanitized_result:null}],next_cursor:null});
   if(endpoint.endsWith('/reconcile'))return reply({operation:{operation_id:'11111111-1111-4111-8111-111111111111',state:'unknown_interrupted'},state:'unknown_interrupted',resolution:{children:[]}});
   if(endpoint.endsWith('/apply')||endpoint.includes('/service/')||endpoint.endsWith('/ssh/test'))return reply({operation_id:'22222222-2222-4222-8222-222222222222',state:'queued'},202);
   return reply({error:{code:'not_found',message:'Fixture route undefined'}},404);
  }
  if(!u.pathname.startsWith(prefix))return route.fulfill({status:404,body:'outside prefix'});
  let file=p||'index.html'; try{let data=await fs.readFile(path.join(__dirname,'..',file),'utf8');data=data.replaceAll('__WOLF_BASE__',prefix).replaceAll('__WOLF_MODE__',mode);return route.fulfill({contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',body:data});}catch{return route.fulfill({contentType:'text/html',body:'<html><body>UI not implemented</body></html>'});}
 });
 await page.goto('http://wolf.test'+prefix);
 return calls;
}
test('Ingress nonce uses browser origin and prefix-safe PC requests, with escaped names',async({page})=>{
 const calls=await fixture(page); await expect(page.getByRole('heading',{name:'Wolf Manager'})).toBeVisible();
 await expect(page.getByRole('button',{name:'Desk <img onerror=alert(1)>'})).toBeVisible(); expect(await page.locator('img[onerror]').count()).toBe(0);
 expect(calls.find(c=>c.endpoint==='auth/csrf').headers['x-wolf-origin']).toBe('http://wolf.test');
});
test('saved desired revision stages separately and unsupported Proton stays disabled',async({page})=>{
 const calls=await fixture(page);await page.getByText('Game settings',{exact:true}).click(); await page.getByRole('checkbox',{name:'Direct launch'}).check();await expect(page.getByRole('checkbox',{name:'Proton-CachyOS'})).toBeDisabled();
 await page.getByRole('button',{name:'Save game settings'}).click();await page.getByText('Configuration revisions',{exact:true}).click();await expect(page.getByText('Desired: '+newer)).toBeVisible();await expect(page.getByText('Running: '+rev)).toBeVisible();
 await page.getByRole('button',{name:'Stage settings',exact:true}).click();await expect.poll(()=>calls.find(c=>c.endpoint==='pcs/desk/apply')?.body).toEqual({expected_desired_revision:newer});
 expect(calls.find(c=>c.endpoint==='pcs/desk/apply').headers['x-wolf-csrf']).toBe('bound-csrf');await expect(page.getByText('Service: running', {exact:true})).toBeVisible();
});
test('fingerprint enrollment requires explicit confirmation and logs are bounded',async({page})=>{
 const calls=await fixture(page);await page.getByRole('button',{name:'SSH setup'}).click();await page.getByRole('button',{name:'Probe host key'}).click();
 await expect(page.getByRole('button',{name:'Trust fingerprint'})).toBeDisabled();await page.getByRole('checkbox',{name:'I verified this fingerprint independently'}).check();await page.getByRole('button',{name:'Trust fingerprint'}).click();
 expect(calls.find(c=>c.endpoint.endsWith('/ssh/enroll')).body).toEqual({probe_id:'fixture-probe',fingerprint:'SHA256:fixture'});
 await page.getByRole('button',{name:'Cancel'}).click();await page.getByText('Diagnostics',{exact:true}).click();await page.getByRole('button',{name:'Read logs'}).click();await expect(page.getByText('bounded fixture log')).toBeVisible();expect(calls.find(c=>c.endpoint.endsWith('/logs')).endpoint).toBe('pcs/desk/logs');
});
test('PC identity isolates identical app IDs and unavailable catalog remains visible',async({page})=>{
 await fixture(page);await page.getByRole('button',{name:'Lounge',exact:true}).click();await expect(page.getByRole('heading',{name:'Lounge game'})).toBeVisible();await expect(page.getByText('Catalog is stale; last known games are preserved.')).toBeVisible();
});
test('standalone login uses single-use challenge and forgets password, logout removes dashboard',async({page})=>{
 const calls=await fixture(page,'standalone');await page.getByLabel('Password',{exact:true}).fill('fixture-password-only');await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('button',{name:'Sign out'})).toBeVisible();
 const login=calls.find(c=>c.endpoint==='auth/login');expect(login.body).toEqual({password:'fixture-password-only',challenge:'challenge-secret'});expect(login.headers['x-wolf-csrf']).toBe('challenge-secret');
 expect(await page.evaluate(()=>localStorage.length)).toBe(0);await page.getByRole('button',{name:'Sign out'}).click();await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Stage settings'})).toHaveCount(0);
});
test('bootstrap bearer token stays in memory and new PC onboarding uses closed endpoint DTO',async({page})=>{
 const calls=await fixture(page,'standalone',false);await page.getByLabel('Bootstrap token').fill('fixture-bootstrap-only');await page.getByLabel('Password',{exact:true}).fill('fixture-password-only');await page.getByRole('button',{name:'Create administrator'}).click();await expect(page.getByRole('button',{name:'Add PC'})).toBeVisible();
 expect(calls.find(c=>c.endpoint==='bootstrap').headers.authorization).toBe('Bearer fixture-bootstrap-only');await page.getByRole('button',{name:'Add PC'}).click();await page.getByLabel('PC ID').fill('study');await page.getByLabel('Display name').fill('Study');await page.getByLabel('SSH host').fill('192.0.2.3');await page.getByRole('button',{name:'Save PC',exact:true}).click();
 expect(calls.find(c=>c.endpoint==='pcs'&&c.method==='POST').body).toEqual({pc_id:'study',display_name:'Study',ssh_host:'192.0.2.3',ssh_port:22,ssh_user:'wolf-manager'});
});
test('uncertain operation reconciliation remains uncertain and log failure is recoverable',async({page})=>{
 const calls=await fixture(page);await page.getByText('Operation history',{exact:true}).click();await page.getByRole('button',{name:'Reconcile operation'}).click();await expect(page.getByText('Resolution: unknown_interrupted')).toBeVisible();
 await page.route('**/api/v1/pcs/desk/logs?lines=100',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'host_unavailable',message:'Host unavailable'}})}));
 await page.getByText('Diagnostics',{exact:true}).click();await page.getByRole('button',{name:'Read logs'}).click();await expect(page.getByRole('alert')).toContainText('Host unavailable');await expect(page.getByRole('button',{name:'Read logs'})).toBeEnabled();
 expect(calls.find(c=>c.endpoint.endsWith('/reconcile')).body).toEqual({});
});
test('expired CSRF renews protection without automatically replaying a mutation',async({page})=>{
 const calls=await fixture(page);let refused=0;
 await page.route('**/api/v1/pcs/desk/apply',route=>{refused++;return route.fulfill({status:403,contentType:'application/json',body:JSON.stringify({error:{code:'csrf_failed',message:'Session protection expired'}})});});
 await page.getByRole('button',{name:'Stage settings',exact:true}).click();await expect(page.getByRole('alert')).toBeVisible();
 await expect.poll(()=>calls.filter(c=>c.endpoint==='auth/csrf').length).toBe(2);expect(refused).toBe(1);
});
test('SSH public-key failure keeps an accessible escape from the setup dialog',async({page})=>{
 await fixture(page);await page.route('**/api/v1/pcs/desk/ssh/public-key',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'host_unavailable',message:'Key unavailable'}})}));
 await page.getByRole('button',{name:'SSH setup'}).click();await expect(page.getByRole('dialog').getByRole('alert')).toContainText('Key unavailable');await page.getByRole('button',{name:'Cancel'}).click();await expect(page.getByRole('dialog')).toHaveCount(0);
});
test('parameter editor accepts shared-contract uppercase and dot identifiers',async({page})=>{
 const calls=await fixture(page);await page.getByRole('button',{name:'Add parameter'}).click();await page.getByLabel('Parameter ID').fill('Compatibility.Layer');await page.getByLabel('Label',{exact:true}).fill('Compatibility');await page.getByLabel('Launch options').fill('FOO=1 %command%');await page.getByRole('button',{name:'Save parameter'}).click();
 await expect.poll(()=>calls.find(c=>c.endpoint==='parameters/Compatibility.Layer')?.body).toEqual({label:'Compatibility',launch_options:'FOO=1 %command%',description:''});
});
test('invalid parameter and PC identifiers are blocked before any submitted request',async({page})=>{
 const calls=await fixture(page);await page.getByRole('button',{name:'Add parameter'}).click();await page.getByLabel('Parameter ID').fill('bad/../id');await page.getByLabel('Label',{exact:true}).fill('Bad');await page.getByLabel('Launch options').fill('%command%');await page.getByRole('button',{name:'Save parameter'}).click();
 expect(await page.getByLabel('Parameter ID').evaluate(n=>n.checkValidity())).toBe(false);expect(calls.some(c=>c.endpoint.startsWith('parameters/')&&c.method==='PUT')).toBe(false);
});
test('mobile dashboard preserves keyboard access without horizontal overflow',async({page})=>{
 await page.setViewportSize({width:375,height:812});await fixture(page);await expect(page.getByRole('heading',{name:'Dota 2'})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
 await page.getByRole('button',{name:'Add PC'}).focus();await page.keyboard.press('Enter');await expect(page.getByLabel('PC ID')).toBeFocused();await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).toHaveCount(0);
 await page.screenshot({path:'_tmp/ui-evidence/dashboard-mobile.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:'_tmp/ui-evidence/dashboard-desktop.png',fullPage:true});
});
test('service commands bind desired revision but stop remains independent of it',async({page})=>{
 const calls=await fixture(page);await page.getByRole('button',{name:'Start',exact:true}).click();await page.getByRole('button',{name:'Restart',exact:true}).click();await page.getByRole('button',{name:'Stop',exact:true}).click();
 expect(calls.find(c=>c.endpoint==='pcs/desk/service/start').body).toEqual({expected_desired_revision:rev});expect(calls.find(c=>c.endpoint==='pcs/desk/service/restart').body).toEqual({expected_desired_revision:rev});expect(calls.find(c=>c.endpoint==='pcs/desk/service/stop').body).toEqual({});await expect(page.getByText('Service: running',{exact:true})).toBeVisible();
});
test('password change uses current session protection and returns to login',async({page})=>{
 const calls=await fixture(page,'standalone');await page.getByLabel('Password',{exact:true}).fill('fixture-password-only');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('button',{name:'Change password'}).click();await page.getByLabel('Current password').fill('fixture-current-only');await page.getByLabel('New password').fill('fixture-new-only');await page.getByRole('button',{name:'Update password'}).click();await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeVisible();
 expect(calls.find(c=>c.endpoint==='auth/password').body).toEqual({current_password:'fixture-current-only',new_password:'fixture-new-only'});expect(calls.find(c=>c.endpoint==='auth/password').headers['x-wolf-csrf']).toBe('session-csrf');expect(await page.evaluate(()=>localStorage.length)).toBe(0);
});
test('debug setting and parameter deletion use canonical routes and surface reference conflicts',async({page})=>{
 const calls=await fixture(page);await page.getByRole('checkbox',{name:'Diagnostic test ball'}).check();await page.getByRole('button',{name:'Save diagnostic setting'}).click();expect(calls.find(c=>c.endpoint==='settings/debug').body).toEqual({test_ball:true});
 await page.route('**/api/v1/parameters/fsr4',route=>route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:{code:'parameter_in_use',message:'Parameter still referenced'}})}));await page.getByRole('button',{name:'Delete FSR4'}).click();await expect(page.getByRole('alert')).toContainText('Parameter still referenced');await page.getByText('Game settings',{exact:true}).click();await expect(page.getByRole('checkbox',{name:'FSR4',exact:true})).toBeVisible();
});
test('Ingress denial never falls back to standalone password authentication',async({page})=>{
 await page.route('http://wolf.test/**',async route=>{
  const u=new URL(route.request().url());if(u.pathname.includes('/api/v1/'))return route.fulfill({status:403,contentType:'application/json',body:JSON.stringify({error:{code:'ingress_peer_forbidden',message:'Ingress access denied'}})});
  const file=u.pathname.endsWith('/')?'index.html':u.pathname.split('/').at(-1);let data=await fs.readFile(path.join(__dirname,'..',file),'utf8');return route.fulfill({contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',body:data.replaceAll('__WOLF_BASE__',prefix).replaceAll('__WOLF_MODE__','ingress')});
 });await page.goto('http://wolf.test'+prefix);await expect(page.getByRole('alert')).toContainText('Ingress access denied');await expect(page.getByLabel('Password',{exact:true})).toHaveCount(0);await expect(page.getByRole('button',{name:'Retry connection'})).toBeVisible();
});
test('explicit refresh renews expiring CSRF protection as well as observations',async({page})=>{
 const calls=await fixture(page);await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect.poll(()=>calls.filter(c=>c.endpoint==='auth/csrf').length).toBe(2);
});
test('unread global debug state cannot be changed through a fabricated false default',async({page})=>{
 const calls=await fixture(page);await page.route('**/api/v1/pcs/desk/settings',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'host_unavailable',message:'Settings unavailable'}})}));await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(page.getByText('Diagnostic setting unavailable until settings can be read.')).toBeVisible();await expect(page.getByRole('checkbox',{name:'Diagnostic test ball'})).toBeDisabled();await expect(page.getByRole('button',{name:'Save diagnostic setting'})).toBeDisabled();expect(calls.some(c=>c.endpoint==='settings/debug')).toBe(false);
});
test('offline host status explicitly preserves last-known service and revision observations',async({page})=>{
 await fixture(page);await page.route('**/api/v1/pcs/desk/status',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({status:{systemd_state:'active',container_state:'running',restart_count:0,exit_code:null,staged_revision:rev,running_revision:rev,recovery_pending:false},capabilities:{version:1,pc_id:'desk',ready:true,proton_cachyos:false,reasons:[]},availability:'offline',observed_at:1})}));await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(page.getByText('Host availability: offline', {exact:true})).toBeVisible();await expect(page.getByText('Last known service: running',{exact:true})).toBeVisible();await expect(page.getByText('Service: running',{exact:true})).toHaveCount(0);await page.getByText('Configuration revisions',{exact:true}).click();await expect(page.getByText('Last known running: '+rev,{exact:true})).toBeVisible();await expect(page.getByText('Observed at:',{exact:false})).toBeVisible();
});
test('compact library expands settings by keyboard and preserves parameter removal',async({page})=>{
 const calls=await fixture(page);const disclosure=page.getByText('Game settings',{exact:true});
 await expect(page.getByRole('checkbox',{name:'Direct launch'})).not.toBeVisible();await disclosure.focus();await page.keyboard.press('Enter');
 await page.getByRole('checkbox',{name:'FSR4',exact:true}).check();await page.getByRole('checkbox',{name:'FSR4',exact:true}).uncheck();await page.getByRole('button',{name:'Save game settings'}).click();
 expect(calls.find(c=>c.endpoint==='pcs/desk/games/570/settings').body.parameters).toEqual([]);
 await expect(page.getByRole('checkbox',{name:'Direct launch'})).not.toBeVisible();
});
test('PC edit retains immutable identity and archive requires confirmation',async({page})=>{
 const calls=await fixture(page);await page.getByRole('button',{name:'Edit PC'}).click();await expect(page.getByLabel('PC ID')).toBeDisabled();
 await page.getByLabel('Display name').fill('Renamed desktop');await page.getByLabel('SSH host').fill('192.0.2.42');await page.getByRole('button',{name:'Save PC',exact:true}).click();
 expect(calls.find(c=>c.endpoint==='pcs/desk'&&c.method==='PATCH').body).toEqual({display_name:'Renamed desktop',ssh_host:'192.0.2.42',ssh_port:22,ssh_user:'wolf-manager'});
 await page.getByRole('button',{name:'Edit PC'}).click();page.once('dialog',dialog=>dialog.dismiss());await page.getByRole('button',{name:'Archive PC'}).click();expect(calls.some(c=>c.method==='DELETE')).toBe(false);
 page.once('dialog',dialog=>dialog.accept());await page.getByRole('button',{name:'Archive PC'}).click();expect(calls.find(c=>c.method==='DELETE').endpoint).toBe('pcs/desk');await expect(page.getByRole('dialog')).toHaveCount(0);
});
test('parameter edit retains ID and successful deletion refreshes configuration',async({page})=>{
 const calls=await fixture(page);await page.getByRole('button',{name:'Edit FSR4'}).click();await expect(page.getByLabel('Parameter ID')).toBeDisabled();await page.getByLabel('Description').fill('Updated compatibility preset');await page.getByRole('button',{name:'Save parameter'}).click();
 expect(calls.find(c=>c.endpoint==='parameters/fsr4'&&c.method==='PUT').body.description).toBe('Updated compatibility preset');await page.getByRole('button',{name:'Delete FSR4'}).click();expect(calls.some(c=>c.endpoint==='parameters/fsr4'&&c.method==='DELETE')).toBe(true);
});
test('diagnostic line bounds refuse network submission and valid snapshot stays readable',async({page})=>{
 const calls=await fixture(page);await page.getByText('Diagnostics',{exact:true}).click();await page.getByLabel('Log lines').fill('501');await page.getByRole('button',{name:'Read logs'}).click();await expect(page.getByRole('alert')).toContainText('Choose 1 to 500 log lines.');expect(calls.some(c=>c.endpoint.endsWith('/logs'))).toBe(false);
 await page.getByLabel('Log lines').fill('25');await page.route('**/api/v1/pcs/desk/logs?lines=25',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({lines:'plain bounded snapshot',truncated:false})}));await page.getByRole('button',{name:'Read logs'}).click();await expect(page.getByText('plain bounded snapshot')).toBeVisible();await expect(page.getByText('Bounded snapshot; refresh explicitly for newer logs.')).toBeVisible();
});
test('recovery observation disables revision-sensitive controls while diagnostics remain available',async({page})=>{
 await fixture(page);await page.route('**/api/v1/pcs/desk/status',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({status:{container_state:'stopped',recovery_pending:true},capabilities:{ready:true,proton_cachyos:true},availability:'online',observed_at:null})}));await page.getByRole('button',{name:'Refresh',exact:true}).click();
 for(const name of ['Start','Restart','Stage settings'])await expect(page.getByRole('button',{name,exact:true})).toBeDisabled();await expect(page.getByRole('button',{name:'Stop',exact:true})).toBeEnabled();await expect(page.getByText('Recovery pending.',{exact:false})).toBeVisible();await expect(page.getByText('Observed at: unknown')).toBeVisible();
});
test('missing host and catalog observations never imply an empty current host',async({page})=>{
 await fixture(page);await page.route('**/api/v1/pcs/desk/status',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'host_unavailable',message:'Host unavailable'}})}));await page.route('**/api/v1/pcs/desk/games',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'host_unavailable',message:'Host unavailable'}})}));await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(page.getByText('No current host observation. Controls require a verified host.')).toBeVisible();await expect(page.getByText('Catalog unavailable. No empty catalog is inferred.')).toBeVisible();await expect(page.getByRole('button',{name:'Stop',exact:true})).toBeDisabled();
});
test('operation pagination is explicit and exposes empty history without replay',async({page})=>{
 const calls=await fixture(page);await page.route('**/api/v1/pcs/desk/operations?limit=20',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({operations:[{operation_id:'test-complete',kind:'start',state:'completed',submitted_at:1,sanitized_result:{ok:true}}],next_cursor:'older cursor'})}));await page.route('**/api/v1/pcs/desk/operations?limit=20&cursor=older%20cursor',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({operations:[],next_cursor:null})}));await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByText('Operation history',{exact:true}).click();await expect(page.getByText('start · completed')).toBeVisible();await page.getByRole('button',{name:'Next operations'}).click();await expect(page.getByText('No operations yet.')).toBeVisible();expect(calls.some(c=>c.endpoint.includes('/service/'))).toBe(false);
});
test('empty host list gives an actionable onboarding screen and unavailable history is disclosed',async({page})=>{
 await fixture(page);await page.route('**/api/v1/pcs',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({pcs:[]})}));await page.reload();await expect(page.getByText('Add a PC to get started.')).toBeVisible();await page.getByRole('button',{name:'Add PC'}).click();await expect(page.getByLabel('PC ID')).toBeFocused();await page.keyboard.press('Escape');
});
test('reduced motion and narrow viewport keep operational and dialog controls reachable',async({page})=>{
 await page.emulateMedia({reducedMotion:'reduce'});await page.setViewportSize({width:320,height:640});await fixture(page);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.getByRole('button',{name:'SSH setup'}).click();await expect(page.getByRole('dialog')).toBeVisible();expect(await page.getByRole('dialog').evaluate(n=>n.scrollWidth<=n.clientWidth)).toBe(true);await page.keyboard.press('Escape');await expect(page.getByRole('button',{name:'SSH setup'})).toBeFocused();
});
test('rejected settings and onboarding mutations surface errors and keep drafts editable',async({page})=>{
 await fixture(page);await page.getByText('Game settings',{exact:true}).click();await page.route('**/api/v1/pcs/desk/games/570/settings',route=>route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:{code:'stale_revision',message:'Refresh settings before saving'}})}));await page.getByRole('button',{name:'Save game settings'}).click();await expect(page.getByRole('alert')).toContainText('Refresh settings before saving');await expect(page.getByRole('button',{name:'Save game settings'})).toBeEnabled();
 await page.getByRole('button',{name:'Add PC'}).click();await page.getByLabel('PC ID').fill('new-host');await page.getByLabel('Display name').fill('New host');await page.getByLabel('SSH host').fill('192.0.2.9');await page.route('**/api/v1/pcs',route=>route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:{code:'conflict',message:'PC already exists'}})}));await page.getByRole('button',{name:'Save PC',exact:true}).click();await expect(page.getByRole('dialog').getByRole('alert')).toContainText('PC already exists');await expect(page.getByLabel('Display name')).toHaveValue('New host');await page.keyboard.press('Escape');
});
test('failed login clears submitted password and remains on the sign-in screen',async({page})=>{
 await fixture(page,'standalone');await page.route('**/api/v1/auth/login',route=>route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:{code:'invalid_credentials',message:'Password was not accepted'}})}));await page.getByLabel('Password',{exact:true}).fill('invalid-test-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Password was not accepted');await expect(page.getByLabel('Password',{exact:true})).toHaveValue('');await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeEnabled();
});
test('expired standalone session returns to authentication without resubmitting service control',async({page})=>{
 await fixture(page,'standalone');await page.getByLabel('Password',{exact:true}).fill('test-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();let submissions=0;await page.route('**/api/v1/pcs/desk/service/start',route=>{submissions++;return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:{code:'unauthenticated',message:'Session expired'}})});});await page.getByRole('button',{name:'Start',exact:true}).click();await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeVisible();expect(submissions).toBe(1);await expect(page.getByRole('button',{name:'Start',exact:true})).toHaveCount(0);
});
test('history failure remains visible within its disclosure and empty catalog is explicit',async({page})=>{
 await fixture(page);await page.route('**/api/v1/pcs/desk/operations?limit=20',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'storage_unavailable',message:'History unavailable'}})}));await page.route('**/api/v1/pcs/desk/games',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({games:[],availability:'online',catalog_generation:3})}));await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.getByText('No games in the last complete catalog.')).toBeVisible();await page.getByText('Operation history',{exact:true}).click();await expect(page.getByText('Operation history unavailable.')).toBeVisible();
});
