/* Embedded vanilla client. Authentication and authorization remain server-owned. */
'use strict';
(() => {
  const mode = document.querySelector('meta[name="wolf-mode"]').content;
  const base = new URL(document.querySelector('base').href);
  const apiBase = new URL('api/v1/', base);
  const main = document.getElementById('main');
  const account = document.getElementById('account');
  let csrf = null, selected = null, pcs = [], epoch = 0, desired = null, dialogSequence = 0;
  let settings = null, status = null, parameters = {};

  function node(tag, text, attrs = {}) {
    const n = document.createElement(tag);
    if (text !== null && text !== undefined) n.textContent = String(text);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') n.className = v;
      else if (k === 'checked' || k === 'disabled') n[k] = Boolean(v);
      else n.setAttribute(k, v);
    }
    return n;
  }
  function append(parent, ...children) { parent.append(...children); return parent; }
  function notice(message, error = false) {
    const n = document.getElementById(error ? 'error' : 'notice');
    n.textContent = message; n.hidden = !message;
    if (error) {
      document.getElementById('notice').hidden = true;
      const dialog = document.querySelector('dialog[open]');
      if (dialog) {
        let alert = dialog.querySelector('[role=alert]');
        if (!alert) { alert = node('div', null, {role:'alert',class:'notice danger'}); dialog.append(alert); }
        alert.textContent = message; alert.hidden = !message;
      }
    }
  }
  function button(label, action, attrs = {}) {
    const b = node('button', label, {type:'button', ...attrs});
    b.addEventListener('click', async () => {
      b.disabled = true; notice('', true);
      try { await action(); } catch (e) { notice(e.message, true); }
      finally { b.disabled = Boolean(attrs.disabled); }
    }); return b;
  }
  function field(label, type = 'text', value = '', attrs = {}) {
    const input = node(type === 'textarea' ? 'textarea' : 'input', null,
      type === 'textarea' ? attrs : {type, ...attrs});
    input.value = value;
    return {input, label: append(node('label', label), input)};
  }
  function check(label, checked = false, disabled = false) {
    const input = node('input', null, {type:'checkbox', checked, disabled});
    return {input, label: append(node('label', null, {class:'check'}), input, node('span', label))};
  }
  async function api(path, options = {}) {
    const method = options.method || 'GET';
    const headers = {...options.headers};
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && csrf && !headers['X-Wolf-CSRF']) headers['X-Wolf-CSRF'] = csrf;
    const response = await fetch(new URL(path, apiBase), {
      method, headers, credentials:'same-origin', cache:'no-store',
      body:options.body === undefined ? undefined : JSON.stringify(options.body)
    });
    const data = response.status === 204 ? null : await response.json();
    if (!response.ok) {
      if (response.status === 401 && !path.startsWith('auth/') && path !== 'bootstrap') {
        csrf = null; epoch++; await authScreen();
      }
      const error = new Error(data?.error?.message || 'Request failed. Please retry.');
      error.code = data?.error?.code;
      if (error.code === 'csrf_failed' && csrf && method !== 'GET') {
        // Renew only the nonce. A rejected mutation is never silently replayed.
        try { await issueCsrf(); error.message = 'Session protection refreshed. Retry the action explicitly.'; } catch { csrf = null; }
      }
      throw error;
    }
    return data;
  }
  async function issueCsrf() {
    const data = await api('auth/csrf', {headers: mode === 'ingress' ? {'X-Wolf-Origin':window.location.origin} : {}});
    csrf = data.csrf_token;
  }
  async function authScreen() {
    main.replaceChildren(); account.replaceChildren(); main.setAttribute('aria-busy','false');
    if (mode === 'ingress') {
      append(main, node('p','Home Assistant admission failed. Reopen the add-on through Home Assistant.'));
      return;
    }
    const bootstrap = !(await api('bootstrap/status')).initialized;
    const panel = node('section', null, {class:'panel auth'});
    const form = node('form', null, {class:'stack'});
    append(panel, node('h2', bootstrap ? 'Create administrator' : 'Sign in'), form);
    const token = bootstrap ? field('Bootstrap token','password','',{required:'',autocomplete:'off'}) : null;
    const password = field('Password','password','',{required:'',autocomplete:bootstrap?'new-password':'current-password'});
    if (token) form.append(token.label);
    form.append(password.label);
    const submit = node('button',bootstrap?'Create administrator':'Sign in',{type:'submit',class:'primary'});
    form.append(submit);
    form.addEventListener('submit',async e=>{
      e.preventDefault(); submit.disabled=true;notice('',true);
      try {
        const challenge = await api('auth/login-challenge?purpose='+(bootstrap?'bootstrap':'login'));
        const value = password.input.value; const bearer = token?.input.value;
        password.input.value=''; if(token)token.input.value='';
        const response = await api(bootstrap?'bootstrap':'auth/login',{
          method:'POST', body:{password:value,challenge:challenge.challenge},
          headers:{'X-Wolf-CSRF':challenge.challenge,...(bootstrap?{'Authorization':'Bearer '+bearer}:{})}
        });
        csrf=response.csrf_token;await dashboard();
      }catch(error){notice(error.message,true);}finally{submit.disabled=false;}
    });
    main.append(panel);
  }
  function modal(title) {
    const headingId = 'dialog-title-' + (++dialogSequence);
    const dialog = node('dialog', null, {'aria-labelledby':headingId});
    append(dialog,node('h2',title,{id:headingId}));document.body.append(dialog);
    const close = button('Cancel',()=>dialog.close());
    dialog.addEventListener('close',()=>dialog.remove());
    dialog.showModal();
    queueMicrotask(() => dialog.querySelector('input:not(:disabled),textarea,button')?.focus());
    return {dialog,close};
  }
  function passwordDialog() {
    const {dialog,close}=modal('Change password');
    const current=field('Current password','password','',{required:'',autocomplete:'current-password'});
    const next=field('New password','password','',{required:'',autocomplete:'new-password'});
    const form=node('form',null,{class:'stack'});const submit=node('button','Update password',{type:'submit',class:'primary'});
    append(form,current.label,next.label,append(node('div',null,{class:'row'}),submit,close));dialog.append(form);
    form.addEventListener('submit',async e=>{e.preventDefault();submit.disabled=true;try{
      await api('auth/password',{method:'POST',body:{current_password:current.input.value,new_password:next.input.value}});
      current.input.value='';next.input.value='';dialog.close();csrf=null;await authScreen();notice('Password changed. Sign in again.');
    }catch(e){notice(e.message,true);}finally{submit.disabled=false;}});
  }
  async function dashboard() {
    account.replaceChildren();
    if(mode==='standalone')append(account,button('Change password',passwordDialog),button('Sign out',async()=>{
      await api('auth/logout',{method:'POST',body:{}});csrf=null;epoch++;await authScreen();
    }));
    else account.append(node('span','Home Assistant Ingress',{class:'badge'}));
    pcs=(await api('pcs')).pcs;
    if(!pcs.some(pc=>pc.pc_id===selected))selected=pcs[0]?.pc_id||null;
    await loadPc();
  }
  async function loadPc() {
    const generation=++epoch;main.setAttribute('aria-busy','true');
    const layout=node('div',null,{class:'layout'}),side=node('aside',null,{class:'host-rail'}),content=node('section');
    append(side,node('h2','Your PCs'));
    const list=node('nav',null,{class:'pc-list','aria-label':'PC selection'});
    for(const pc of pcs)list.append(button(pc.display_name,async()=>{selected=pc.pc_id;await loadPc();},{class:pc.pc_id===selected?'selected':'','aria-pressed':String(pc.pc_id===selected)}));
    append(side,list,button('Add PC',()=>pcDialog(),{class:'add-host'}),node('p','Choose a host to manage its service and Steam library.',{class:'rail-hint'}));append(layout,side,content);main.replaceChildren(layout);
    if(!selected){append(content,node('p','Add a PC to get started.',{class:'panel empty'}));main.setAttribute('aria-busy','false');return;}
    const pc=pcs.find(p=>p.pc_id===selected), root='pcs/'+encodeURIComponent(selected)+'/';
    const results=await Promise.allSettled([api(root+'status'),api(root+'games'),api(root+'settings'),api('parameters'),api(root+'operations?limit=20')]);
    if(generation!==epoch)return;
    if(results.some(r=>r.status==='rejected'&&r.reason.code==='unauthenticated'))return;
    const [statusResult,gamesResult,settingsResult,paramsResult,opsResult]=results;
    status=statusResult.status==='fulfilled'?statusResult.value:null;
    settings=settingsResult.status==='fulfilled'?settingsResult.value:null;desired=settings?.desired_revision||null;
    parameters=paramsResult.status==='fulfilled'?paramsResult.value.parameters:{};
    content.append(servicePanel(pc,root),catalogPanel(gamesResult,root),configurationPanel(),operationsPanel(opsResult),logsPanel(root));
    main.setAttribute('aria-busy','false');
  }
  function servicePanel(pc,root){
    const service=node('section',null,{class:'panel service-panel'});
    append(service,append(node('div',null,{class:'row spread'}),node('h2',pc.display_name),append(node('div',null,{class:'row'}),button('Edit PC',()=>pcDialog(pc)),button('SSH setup',()=>sshDialog(pc)),button('Refresh',async()=>{await issueCsrf();await loadPc();}))));
    const observed=status?.status;
    const availability=status?.availability||'unknown';
    const lastKnown=availability!=='online';
    appendServiceObservation(service,observed,availability,lastKnown);
    if(lastKnown)service.append(node('p','Service state and observed revisions are last known; current host state is unavailable.',{class:'warning'}));
    if(!status)service.append(node('p','No current host observation. Controls require a verified host.',{class:'warning'}));
    if(observed?.recovery_pending)service.append(node('p','Recovery pending. Preserve current files and backups; inspect diagnostics before retrying.',{class:'warning'}));
    const revisions=node('div',null,{class:'revisions'});
    append(revisions,node('p','Desired: '+(desired||'unknown')),node('p',(lastKnown?'Last known staged: ':'Staged: ')+(settings?.staged_revision||'unknown')),node('p',(lastKnown?'Last known running: ':'Running: ')+(settings?.running_revision||'unknown')));const revisionDetails=append(node('details',null,{class:'revision-details'}),node('summary','Configuration revisions'),revisions);service.append(revisionDetails);
    const unavailable=!desired||!status?.capabilities?.ready||Boolean(observed?.recovery_pending);
    append(service,append(node('div',null,{class:'row lifecycle'}),
      button('Stage settings',()=>queue(root+'apply',{expected_desired_revision:desired}),{disabled:unavailable}),
      button('Start',()=>queue(root+'service/start',{expected_desired_revision:desired}),{disabled:unavailable,class:'primary'}),
      button('Stop',()=>queue(root+'service/stop',{}),{disabled:!status,class:'stop-service'}),
      button('Restart',()=>queue(root+'service/restart',{expected_desired_revision:desired}),{disabled:unavailable})));
    return service;
  }
  function serviceLabel(observed){
    // Match the confirmed MQTT OFF observation; a missing container alone is ambiguous.
    const container=observed?.container_state||'unknown';
    if(observed?.systemd_state==='inactive'&&['stopped','exited','absent','not_found','missing'].includes(container))return 'stopped';
    return container;
  }
  function appendServiceObservation(service,observed,availability,lastKnown){
    const observation=node('div',null,{class:'service-observation'});
    let stateClass='';
    if(lastKnown)stateClass='is-stale';
    else if(observed?.container_state==='running')stateClass='is-running';
    append(observation,node('p',(lastKnown?'Last known service: ':'Service: ')+serviceLabel(observed),{class:'service-state '+stateClass}),node('p','Host availability: '+availability,{class:'availability'}));
    service.append(observation);
    const observedTime=status?.observed_at;
    const date=Number.isFinite(observedTime)?new Date(observedTime):null;
    service.append(node('p','Observed at: '+(date&&!Number.isNaN(date.getTime())?date.toISOString():'unknown'),{class:'muted'}));
  }
  function catalogPanel(gamesResult,root){
    const gamesPanel=node('section',null,{class:'panel'});gamesPanel.append(node('h2','Steam games'));
    if(gamesResult.status==='fulfilled'){
      const catalog=gamesResult.value;
      gamesPanel.append(node('p','Generation '+catalog.catalog_generation+' / '+catalog.availability,{class:'catalog-meta muted'}));
      if(catalog.availability!=='online')gamesPanel.append(node('p','Catalog is stale; last known games are preserved.',{class:'warning'}));
      const grid=node('div',null,{class:'games'});
      for(const game of catalog.games)if(game.pc_id===selected)grid.append(gameCard(game,root));
      gamesPanel.append(grid);if(!catalog.games.length)gamesPanel.append(node('p','No games in the last complete catalog.'));
    }else gamesPanel.append(node('p','Catalog unavailable. No empty catalog is inferred.',{class:'warning'}));
    return gamesPanel;
  }
  async function queue(path,body){
    const result=await api(path,{method:'POST',body});
    notice('Operation '+result.operation_id+': '+result.state+'. Refresh to observe its outcome.');
    // Admission is not execution: do not speculate about service state or revisions.
  }
  function gameCard(game,root){
    const card=node('article',null,{class:'game'}),content=node('div',null,{class:'content'});
    const heading=node('div',null,{class:'game-heading'});
    if(/^\d{1,12}$/.test(game.app_id))heading.append(node('img',null,{src:'https://shared.fastly.steamstatic.com/store_item_assets/steam/apps/'+game.app_id+'/header.jpg',alt:'',loading:'lazy',referrerpolicy:'no-referrer'}));
    append(heading,append(node('div'),node('h3',game.name),node('small','Steam '+game.app_id+' / '+game.library_id)));content.append(heading);
    const value=settings?.settings?.games?.[game.app_id]||{direct_launch:false,proton_cachyos:false,parameters:[]};
    const direct=check('Direct launch',value.direct_launch),proton=check('Proton-CachyOS',value.proton_cachyos,!status?.capabilities?.proton_cachyos);
    const form=node('form',null,{class:'stack'});append(form,append(node('div',null,{class:'row game-options'}),direct.label,proton.label));
    if(!status?.capabilities?.proton_cachyos)form.append(node('small','Proton-CachyOS is unavailable on this PC.'));
    const choices=append(node('fieldset'),node('legend','Reusable parameters'));
    const selection=[...value.parameters];
    for(const [id,definition]of Object.entries(parameters)){
      const c=check(definition.label,selection.includes(id));c.input.addEventListener('change',()=>{
        const at=selection.indexOf(id);if(c.input.checked&&at<0)selection.push(id);else if(!c.input.checked&&at>=0)selection.splice(at,1);
      });choices.append(c.label);
    }form.append(choices);
    const save=node('button','Save game settings',{type:'submit',disabled:!desired,class:'primary'});form.append(save);
    form.addEventListener('submit',async event=>{event.preventDefault();save.disabled=true;try{
      await api(root+'games/'+encodeURIComponent(game.app_id)+'/settings',{method:'PUT',body:{expected_desired_revision:desired,direct_launch:direct.input.checked,proton_cachyos:proton.input.checked,parameters:selection}});
      notice('Desired settings saved. Stage or start explicitly to apply them.');await loadPc();
    }catch(e){notice(e.message,true);}finally{save.disabled=false;}});
    append(content,append(node('details',null,{class:'game-settings'}),node('summary','Game settings'),form));card.append(content);return card;
  }
  function pcDialog(pc=null){
    const {dialog,close}=modal(pc?'Edit PC':'Add PC');const form=node('form',null,{class:'stack'});
    const id=field('PC ID','text',pc?.pc_id||'',{required:'',pattern:String.raw`[a-z0-9][a-z0-9_\-]{0,63}`,disabled:!!pc});
    const name=field('Display name','text',pc?.display_name||'',{required:'',maxlength:'256'});
    const host=field('SSH host','text',pc?.ssh_host||'',{required:''});
    const port=field('SSH port','number',pc?.ssh_port||22,{required:'',min:'1',max:'65535'});
    const user=field('SSH user','text',pc?.ssh_user||'wolf-manager',{required:''});
    const save=node('button','Save PC',{type:'submit',class:'primary'});
    append(form,id.label,name.label,host.label,port.label,user.label,node('small','Endpoint changes require a new fingerprint enrollment.'),append(node('div',null,{class:'row'}),save,close));
    if(pc)form.append(button('Archive PC',async()=>{if(!window.confirm('Archive this PC? Host data is preserved.')){return;}await api('pcs/'+encodeURIComponent(pc.pc_id),{method:'DELETE'});dialog.close();await dashboard();}));
    dialog.append(form);form.addEventListener('submit',async e=>{e.preventDefault();save.disabled=true;try{
      const endpoint={display_name:name.input.value,ssh_host:host.input.value,ssh_port:Number(port.input.value),ssh_user:user.input.value};
      await api(pc?'pcs/'+encodeURIComponent(pc.pc_id):'pcs',{method:pc?'PATCH':'POST',body:pc?endpoint:{pc_id:id.input.value,...endpoint}});
      dialog.close();selected=pc?.pc_id||id.input.value;await dashboard();notice('PC saved. Verify SSH enrollment before control.');
    }catch(e){notice(e.message,true);}finally{save.disabled=false;}});
  }
  async function sshDialog(pc){
    const {dialog,close}=modal('SSH setup — '+pc.display_name),root='pcs/'+encodeURIComponent(pc.pc_id)+'/ssh/';
    append(dialog,close,node('p','Install this public key using the restricted host installer. Never grant an unrestricted shell or Docker access.'));
    const key=await api(root+'public-key');dialog.append(node('pre',key.public_key));
    const evidence=node('div'),verified=check('I verified this fingerprint independently');let probe=null;
    const enroll=button('Trust fingerprint',async()=>{if(!probe||!verified.input.checked){return;}await api(root+'enroll',{method:'POST',body:{probe_id:probe.probe_id,fingerprint:probe.fingerprint}});notice('Fingerprint enrolled. Run the connection test.');},{disabled:true});
    verified.input.addEventListener('change',()=>enroll.disabled=!verified.input.checked||!probe);
    append(dialog,button('Probe host key',async()=>{probe=await api(root+'probe',{method:'POST'});verified.input.checked=false;enroll.disabled=true;evidence.replaceChildren(node('p',probe.algorithm),node('code',probe.fingerprint),node('small','Compare with the host console before trusting.'));}),evidence,verified.label,
      append(node('div',null,{class:'row'}),enroll,button('Test connection',()=>queue(root+'test',{})),close));
  }
  function configurationPanel(){
    const panel=node('section',null,{class:'panel'});append(panel,node('h2','Shared configuration'));
    const debugAvailable=typeof settings?.settings?.debug?.test_ball==='boolean';
    const debug=check('Diagnostic test ball',debugAvailable?settings.settings.debug.test_ball:false,!debugAvailable);
    if(!debugAvailable)panel.append(node('p','Diagnostic setting unavailable until settings can be read.',{class:'warning'}));
    append(panel,append(node('div',null,{class:'row debug-setting'}),debug.label,button('Save diagnostic setting',async()=>{await api('settings/debug',{method:'PUT',body:{test_ball:debug.input.checked}});notice('Diagnostic setting saved as desired configuration.');await loadPc();},{disabled:!debugAvailable})));
    const defs=node('div');for(const [id,d]of Object.entries(parameters)){
      const row=node('div',null,{class:'operation'});append(row,node('h3',d.label),node('p',d.description,{class:'muted'}),node('code',d.launch_options),append(node('div',null,{class:'row'}),button('Edit '+d.label,()=>parameterDialog(id,d)),button('Delete '+d.label,async()=>{await api('parameters/'+encodeURIComponent(id),{method:'DELETE'});await loadPc();})));
      defs.append(row);
    }append(panel,defs,button('Add parameter',()=>parameterDialog()));return panel;
  }
  function parameterDialog(id=null,definition={}){
    const {dialog,close}=modal(id?'Edit parameter':'Add parameter');const form=node('form',null,{class:'stack'});
    const key=field('Parameter ID','text',id||'',{required:'',disabled:!!id,pattern:String.raw`[A-Za-z0-9_.\-]{1,64}`}),label=field('Label','text',definition.label||'',{required:'',maxlength:'256'});
    const options=field('Launch options','textarea',definition.launch_options||'',{required:'',maxlength:'4096'}),description=field('Description','textarea',definition.description||'',{maxlength:'4096'});
    const save=node('button','Save parameter',{type:'submit',class:'primary'});append(form,key.label,label.label,options.label,description.label,append(node('div',null,{class:'row'}),save,close));dialog.append(form);
    form.addEventListener('submit',async e=>{e.preventDefault();save.disabled=true;try{await api('parameters/'+encodeURIComponent(key.input.value),{method:'PUT',body:{label:label.input.value,launch_options:options.input.value,description:description.input.value}});dialog.close();await loadPc();notice('Reusable parameter saved. Affected desired revisions changed.');}catch(e){notice(e.message,true);}finally{save.disabled=false;}});
  }
  function operationsPanel(result){
    const panel=node('details',null,{class:'panel disclosure'});panel.append(node('summary','Operation history'));
    const list=node('div');panel.append(list);
    const render=data=>{list.replaceChildren();for(const op of data.operations){
      const entry=node('article',null,{class:'operation'});append(entry,node('p',op.kind+' · '+op.state),node('code',op.operation_id));
      if(op.submitted_at)entry.append(node('small',new Date(op.submitted_at).toLocaleString()));
      if(op.sanitized_result)entry.append(node('pre',JSON.stringify(op.sanitized_result,null,2)));
      const resolution=node('div');entry.append(resolution);
      if(op.state==='unknown_interrupted'){entry.append(button('Reconcile operation',async()=>{
        const value=await api('operations/'+encodeURIComponent(op.operation_id)+'/reconcile',{method:'POST',body:{}});
        resolution.replaceChildren(node('p','Resolution: '+value.state),node('pre',JSON.stringify(value.resolution,null,2)));
      }));}
      list.append(entry);
    }
    if(data.next_cursor)list.append(button('Next operations',async()=>render(await api('pcs/'+encodeURIComponent(selected)+'/operations?limit=20&cursor='+encodeURIComponent(data.next_cursor)))));
    if(!data.operations.length)list.append(node('p','No operations yet.'));};
    if(result.status==='fulfilled'){render(result.value);}else{panel.append(node('p','Operation history unavailable.',{class:'warning'}));}
    return panel;
  }
  function logsPanel(root){
    const panel=node('details',null,{class:'panel disclosure'}),lines=field('Log lines','number',100,{min:'1',max:'500'}),output=node('div');
    append(panel,node('summary','Diagnostics'),lines.label,button('Read logs',async()=>{
      const count=Number(lines.input.value);if(!Number.isInteger(count)||count<1||count>500){throw new Error('Choose 1 to 500 log lines.');}
      const response=await api(root+'logs?lines='+count);const content=Array.isArray(response.lines)?response.lines.join('\n'):String(response.lines||'');
      output.replaceChildren(node('pre',content),node('small',response.truncated?'Output truncated to the diagnostic limit.':'Bounded snapshot; refresh explicitly for newer logs.'));
    }),output);return panel;
  }
  async function start(){
    try{
      if(mode==='ingress'){await issueCsrf();await dashboard();}
      else if(mode==='standalone'){
        try{await api('auth/session');await issueCsrf();await dashboard();}catch(e){if(e.code==='unauthenticated')await authScreen();else throw e;}
      }else throw new Error('Invalid deployment mode.');
    }catch(e){main.setAttribute('aria-busy','false');notice(e.message,true);main.replaceChildren(button('Retry connection',start));}
  }
  start();
})();
