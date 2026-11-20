"""Add analyst triage and evidence-led reconnaissance to the standalone Daily."""
from __future__ import annotations

import json
from pathlib import Path

from finding_triage import load_decisions


def intelligence_model(reports: Path):
    items = []
    for path in sorted(reports.glob("recon_intelligence_*.json")):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(item, dict):
                items.append(item)
        except (OSError, ValueError):
            continue
    return items


TRIAGE_JS = r'''
const triageStorage='scanTitanAnalystTriageV1';
let decisions={...(data.triage||{})};
try{const local=JSON.parse(localStorage.getItem(triageStorage)||'{}');for(const [k,v]of Object.entries(local)){if(v&&v.updated_at>=(decisions[k]?.updated_at||''))decisions[k]=v}}catch(_){}
const discarded=r=>decisions[r.triage_key]?.decision==='discarded';
function updateTriageCounts(){
 const active=data.rows.filter(r=>r.state==='ACTIVE'&&!discarded(r));
 meta.active=active.length;meta.high_critical=active.filter(r=>['CRITICAL','HIGH'].includes(r.severity)).length;
 meta.new=active.filter(r=>r.status==='NEW').length;meta.regressions=active.filter(r=>r.status==='REGRESSION').length;
 meta.not_seen=data.rows.filter(r=>r.state==='NOT_SEEN'&&!discarded(r)).length;
 meta.exact_delta=false;meta.severity=Object.fromEntries(Object.keys(severityRank).map(s=>[s,active.filter(r=>r.severity===s).length]));
 data.active_snapshot=[{date:meta.cutoff.slice(0,10)||meta.generated_at.slice(0,10),total:active.length,...meta.severity}];
 data.priority=[...active].sort((a,b)=>b.risk-a.risk).slice(0,8);
 data.assets=[...new Set(active.map(r=>r.target))].map(target=>{const rows=active.filter(r=>r.target===target),scores=rows.map(r=>r.risk).sort((a,b)=>b-a);return {target,total:rows.length,risk:Math.min(100,Math.round((scores[0]+.05*scores.slice(1).reduce((a,b)=>a+b,0))*10)/10)}}).sort((a,b)=>b.risk-a.risk);
 meta.summary=`${active.length} hallazgos activos con evidencia disponible. ${data.rows.filter(r=>r.state==='PENDING'&&!discarded(r)).length} alertas pendientes de validación y ${Object.values(decisions).filter(v=>v.decision==='discarded').length} descartes del analista. Las alertas de inyección requieren validación diferencial independiente.`;
}
updateTriageCounts();
async function saveTriage(){
 localStorage.setItem(triageStorage,JSON.stringify(decisions));
 if(window.SCAN_TITAN_TRIAGE_TOKEN){const response=await fetch('/api/triage',{method:'POST',headers:{'Content-Type':'application/json','X-ScanTitan-Token':window.SCAN_TITAN_TRIAGE_TOKEN},body:JSON.stringify({schema:'scan_titan_triage_v1',decisions})});if(!response.ok)throw Error('No se pudo guardar el descarte en el motor');const saved=await response.json();decisions=saved.decisions;localStorage.setItem(triageStorage,JSON.stringify(decisions))}
}
async function toggleDiscard(key){
 const r=data.rows.find(r=>r.triage_key===key);if(!r)return;
 const restoring=discarded(r);const reason=restoring?'Restaurado por el analista':prompt('Motivo del falso positivo (solo afecta este origen, ruta, método, parámetro y tipo):','Sin evidencia reproducible');
 if(reason===null)return;
 const previous=decisions[key];decisions[key]={decision:restoring?'restored':'discarded',reason:reason||'Descartado por el analista',updated_at:new Date().toISOString(),url:r.url,title:r.title};
 try{await saveTriage();location.reload()}catch(error){if(previous)decisions[key]=previous;else delete decisions[key];try{localStorage.setItem(triageStorage,JSON.stringify(decisions))}catch(_){}alert(error.message+'. El descarte no se confirmó; vuelve a intentarlo.')}
}
function exportTriage(){const blob=new Blob([JSON.stringify({schema:'scan_titan_triage_v1',decisions},null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='finding_triage.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),500)}
document.addEventListener('click',e=>{const button=e.target.closest('[data-discard]');if(button){toggleDiscard(button.dataset.discard);return}if(e.target.id==='exportTriage')exportTriage()});
document.getElementById('importTriage').addEventListener('change',async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>2000000)throw Error('Archivo demasiado grande');const parsed=JSON.parse(await file.text());if(parsed.schema!=='scan_titan_triage_v1'||!parsed.decisions||typeof parsed.decisions!=='object')throw Error('Formato inválido');for(const [k,v]of Object.entries(parsed.decisions)){if(!/^[a-f0-9]{64}$/.test(k)||!v||!['discarded','restored'].includes(v.decision))throw Error('Decisión inválida');if((v.updated_at||'')>=(decisions[k]?.updated_at||''))decisions[k]=v}await saveTriage();location.reload()}catch(error){alert(error.message)}});
document.getElementById('triageMode').textContent=window.SCAN_TITAN_TRIAGE_TOKEN?'Descartes sincronizados con el motor. Se aplican a futuros escaneos y pueden restaurarse.':'Vista de archivo: descartes en este navegador. Abre Abrir_Daily.cmd para guardarlos también en el motor, o exporta finding_triage.json a audit_reports.';
function intelligenceSection(){
 const panel=document.getElementById('intelligenceBody');const items=data.intelligence||[];
 if(!items.length){panel.textContent='El próximo escaneo generará el inventario JavaScript y el registro de validación diferencial.';return}
 const table=(headers,rows)=>`<div class="table-wrap"><table class="hit-table"><thead><tr>${headers.map(x=>`<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows.length?rows.map(row=>`<tr>${row.map(x=>`<td>${esc(x)}</td>`).join('')}</tr>`).join(''):'<tr><td>Sin observaciones</td></tr>'}</tbody></table></div>`;
 panel.innerHTML=items.map(item=>{const js=item.javascript||{},triage=item.injection_triage||[];return `<article class="recon-card"><h4>${esc(item.target)} · ${esc(item.timestamp)}</h4><p>${(js.scripts||[]).length} scripts · ${(js.endpoints||[]).length} endpoints estáticos · ${(js.source_maps||[]).filter(x=>x.state==='valid_source_map').length} source maps válidos · ${triage.length} alertas revisadas</p><p class="muted">Las rutas y flujos estáticos son candidatos. No prueban acceso sin autenticación, explotación DOM ni validez de credenciales.</p><details><summary>Endpoints extraídos de JavaScript</summary>${table(['URL','Fuente','Línea','Alcance'],(js.endpoints||[]).slice(0,200).map(x=>[x.url,x.source,x.line,x.in_scope?'Mismo origen':'Externo, sin consultar']))}</details><details><summary>Source maps</summary>${table(['URL','Estado','Archivos','Fuentes embebidas'],(js.source_maps||[]).map(x=>[x.url,x.state,(x.files||[]).join('\n'),x.embedded_sources||0]))}</details><details><summary>Flujos DOM candidatos</summary>${table(['Fuente','Línea','Código','Estado'],(js.dom_flows||[]).map(x=>[x.source,x.line,x.snippet,x.state]))}</details><details><summary>Posibles credenciales (valores ocultos)</summary>${table(['Tipo','Fuente','Línea','Valor','Estado'],(js.secret_candidates||[]).map(x=>[x.type,x.source,x.line,x.redacted,x.state]))}</details><details><summary>Validación de alertas de inyección</summary>${table(['Alerta','URL','Resultado','Motivo','Similitud DOM'],triage.slice(0,200).map(x=>[x.title,x.url,x.state,x.reason,x.similarity!==undefined?`${(x.similarity*100).toFixed(2)}%`:'N/D']))}</details><details><summary>Scripts y cobertura</summary>${table(['Script','Caracteres','Truncado','SHA-256'],(js.scripts||[]).map(x=>[x.url,x.characters,x.truncated,x.sha256]))}${table(['Fuente','Estado'],(js.coverage||[]).map(x=>[x.source||'',x.state]))}</details></article>`}).join('');
}
intelligenceSection();
'''


def enhance_daily_html(page: str) -> str:
    panel = '''<section class="panel operations"><header class="panel-head"><h3>Decisiones del analista</h3></header><div class="panel-body"><p id="triageMode" class="muted"></p><button class="btn" id="exportTriage">Exportar descartes</button> <label class="btn">Importar descartes<input type="file" id="importTriage" accept="application/json" hidden></label></div></section><section class="panel operations"><header class="panel-head"><h3>Inteligencia JavaScript y validación diferencial</h3></header><div class="panel-body" id="intelligenceBody"></div></section>'''
    page = page.replace('<section class="panel table-panel">', panel + '<section class="panel table-panel">', 1)
    page = page.replace('<button class="tab" data-view="ALL">', '<button class="tab" data-view="PENDING">Por validar</button><button class="tab" data-view="DISCARDED">Descartados</button><button class="tab" data-view="ALL">', 1)
    page = page.replace("$('summary').textContent=meta.summary;", TRIAGE_JS + "\n$('summary').textContent=meta.summary;", 1)
    page = page.replace("function matchView(r){", "function matchView(r){if(state.view==='DISCARDED')return discarded(r);if(discarded(r))return false;if(state.view==='PENDING')return r.state==='PENDING';", 1)
    page = page.replace("const links=[`<button", "const links=[`<button class=\"btn small\" data-discard=\"${esc(r.triage_key)}\">${discarded(r)?'Restaurar hallazgo':'Descartar falso positivo'}</button>`,`<button", 1)
    page = page.replace("statusLabel=v=>({NEW:", "statusLabel=v=>({PENDING:'POR VALIDAR',DISCARDED:'DESCARTADO',NEW:", 1)
    page = page.replace('vigentes en el estado local. Coincide con el resumen de consola.', 'vigentes tras filtros y descartes de esta vista.')
    page = page.replace('statusLabel(r.status)', "statusLabel(discarded(r)?'DISCARDED':r.status)")
    page = page.replace("${section('Evidencia técnica',r.evidence,r.evidence)}", "${section('Evidencia técnica',r.evidence,r.evidence)}${section('Validación diferencial',Object.keys(r.validation||{}).length?JSON.stringify(r.validation,null,2):(r.state==='PENDING'?'Pendiente de validación independiente para alertas históricas de inyección.':''))}${decisions[r.triage_key]?section('Decisión del analista',[decisions[r.triage_key].decision,decisions[r.triage_key].reason,decisions[r.triage_key].updated_at].join(' · ')):''}", 1)
    return page
