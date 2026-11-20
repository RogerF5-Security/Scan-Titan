// Execute the generated Daily's JavaScript with a minimal in-memory DOM.
// This checks interaction/state logic; it does not claim browser/layout coverage.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(process.argv[2], 'utf8');
const dataText = html.match(/<script type="application\/json" id="dashboardData">([\s\S]*?)<\/script>/)[1];
const scripts = [...html.matchAll(/<script(?![^>]*type="application\/json")[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const storage = new Map();

function runtime() {
  const elements = new Map(), listeners = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {id, textContent:id==='dashboardData'?dataText:'', innerHTML:'', value:id==='historyMetric'?'active':'',
      classList:{add(){},remove(){}},style:{},dataset:{},addEventListener(event,fn){this[event]=fn;},insertAdjacentHTML(_position,value){this.innerHTML+=value;},
      showModal(){this.open=true;},close(){this.open=false;},select(){},click(){},remove(){}});
    return elements.get(id);
  };
  const state = {reloads:0};
  const ctx = {
    document:{getElementById:element,querySelectorAll(){return [];},createElement(){return element('temporary');},body:{appendChild(){}},execCommand(){},
      addEventListener(event,fn){if(!listeners.has(event))listeners.set(event,[]);listeners.get(event).push(fn);}},
    localStorage:{getItem:key=>storage.get(key)||null,setItem:(key,value)=>storage.set(key,value)},
    window:{},navigator:{clipboard:{writeText:async()=>{}}},location:{reload(){state.reloads++;}},
    prompt:()=> 'Fixture false positive',alert:m=>{throw Error(m);},print(){},console,URL,Blob,
    setTimeout:()=>0,clearTimeout(){},Date,fetch:()=>{throw Error('Unexpected network request in static report');}
  };
  vm.createContext(ctx);
  scripts.forEach(script=>vm.runInContext(script,ctx,{timeout:3000}));
  return {element,state,click(selector,dataset){const event={target:{closest:s=>s===selector?{dataset}:null}};for(const fn of listeners.get('click')||[])fn(event);}};
}

(async()=>{
  const model = JSON.parse(dataText);
  const active=model.rows.find(r=>r.state==='ACTIVE');
  assert(active,'Fixture report must contain an active finding');
  let app=runtime();
  assert(app.element('summary').textContent.includes('alertas pendientes'));
  app.click('[data-inspect]',{inspect:active.id,asset:active.asset});
  assert(app.element('detailBody').innerHTML.includes('Descartar falso positivo'));
  app.click('[data-discard]',{discard:active.triage_key});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(app.state.reloads,1);
  assert.equal(JSON.parse(storage.get('scanTitanAnalystTriageV1'))[active.triage_key].decision,'discarded');
  app=runtime();
  app.element('viewTabs').onclick({target:{closest:()=>({dataset:{view:'DISCARDED'},classList:{add(){}}})}});
  assert(app.element('findingRows').innerHTML.includes(active.title.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')));
  app.click('[data-inspect]',{inspect:active.id,asset:active.asset});
  assert(app.element('detailBody').innerHTML.includes('Restaurar hallazgo'));
  app.click('[data-discard]',{discard:active.triage_key});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(JSON.parse(storage.get('scanTitanAnalystTriageV1'))[active.triage_key].decision,'restored');
  app=runtime();
  assert(app.element('findingRows').innerHTML.length>0);
  console.log('Daily JS: render, inspect, discard, reload, discarded view and restore passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
