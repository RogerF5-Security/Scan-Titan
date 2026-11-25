"""Daily vulnerability report: one self-contained HTML page organized in tabs.

The page reads the model produced by ``Dashboard.construir_modelo`` from an
embedded JSON block, works offline (no external scripts, strict CSP) and keeps
the analyst triage contract used by ``daily_server``
(``window.SCAN_TITAN_TRIAGE_TOKEN``, ``POST /api/triage``) and the browser
fallback (localStorage). Historical views use ``model.timeline``
(``daily_history.build_timeline``): carry-forward state per target and date.
"""
from __future__ import annotations

DAILY_TEMPLATE = r'''<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'self' data:;img-src 'self' data:;style-src 'unsafe-inline';script-src 'unsafe-inline';connect-src 'none';object-src 'none';base-uri 'none'">
<title>Scan Titan — Centro operativo de vulnerabilidades</title>
<style>
:root{
  --bg-l:#f3f5f9;--bg-d:#0b0e13;--panel-l:#ffffff;--panel-d:#141920;--line-l:#d9dee7;--line-d:#2a313b;
  --text-l:#18202b;--text-d:#e6edf3;--muted-l:#5b6676;--muted-d:#97a3af;--accent-l:#c4161c;--accent-d:#ff4d55;
  --bg:var(--bg-l);--panel:var(--panel-l);--line:var(--line-l);--text:var(--text-l);--muted:var(--muted-l);--accent:var(--accent-l);
  --crit:#9b1c1c;--high:#e0592a;--med:#c99400;--low:#2f7dd1;--info:#6b7785;--ok:#2e8b57;--cyan:#1fb6d6;
  color-scheme:light dark;accent-color:var(--accent);
  @media (prefers-color-scheme:dark){--bg:var(--bg-d);--panel:var(--panel-d);--line:var(--line-d);--text:var(--text-d);--muted:var(--muted-d);--accent:var(--accent-d);}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
header.top{display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--line);background:linear-gradient(90deg,#0b0e13,#1b1f27 60%,#2a0d10);color:#f2f4f7}
.brand{display:flex;gap:14px;align-items:center}
.brand img{width:64px;height:64px;filter:drop-shadow(0 0 8px rgb(255 40 50 / .45))}
header.top h1{font-size:20px;margin:0;letter-spacing:.02em}
header.top .meta{color:#b9c2cc}
.meta{font-size:12px;display:flex;flex-wrap:wrap;gap:4px 14px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor}
.badge.FINAL{color:#5fd38d}.badge.PROVISIONAL{color:#f0c040}
.actions{display:flex;gap:8px;flex-wrap:wrap}
button,.btn{font:inherit;cursor:pointer;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:8px;padding:6px 12px;min-height:32px}
header.top button,header.top .btn{background:rgb(255 255 255 / .06);color:#f2f4f7;border-color:rgb(255 255 255 / .2)}
button:hover,.btn:hover{border-color:var(--accent)}
button:focus-visible,.btn:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
nav.tabs{display:flex;gap:2px;padding:0 24px;border-bottom:1px solid var(--line);background:var(--panel);overflow-x:auto;position:sticky;top:0;z-index:2}
nav.tabs button{border:0;border-bottom:3px solid transparent;border-radius:0;background:none;padding:12px 13px;color:var(--muted);white-space:nowrap}
nav.tabs button[aria-selected="true"]{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.count{display:inline-block;min-width:20px;padding:0 6px;margin-left:6px;border-radius:999px;background:var(--line);font-size:11px;text-align:center}
main{padding:20px 24px;max-width:1560px;margin:0 auto}
section.panel-tab[hidden]{display:none}
.grid{display:grid;gap:16px}
.kpis{grid-template-columns:repeat(auto-fit,minmax(160px,1fr))}
.two{grid-template-columns:repeat(auto-fit,minmax(min(440px,100%),1fr));align-items:start}
.three{grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));align-items:start}
.span-all{grid-column:1/-1}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card h2{font-size:15px;margin:0 0 4px}.card .desc{color:var(--muted);font-size:12px;margin:0 0 12px}
.card h3{font-size:13px;margin:14px 0 6px}
.kpi .label{color:var(--muted);font-size:12px}.kpi .value{font-size:28px;font-weight:700;line-height:1.2}
.kpi .hint{color:var(--muted);font-size:11px}
.kpi.crit .value{color:var(--crit)}.kpi.high .value{color:var(--high)}.kpi.ok .value{color:var(--ok)}
.delta{font-size:12px;font-weight:700;margin-left:6px}.delta.up{color:var(--high)}.delta.down{color:var(--ok)}.delta.flat{color:var(--muted)}
.summary{color:var(--muted);margin:0 0 16px}
.bars .row{display:grid;grid-template-columns:160px 1fr 48px;gap:8px;align-items:center;margin:5px 0;font-size:12px}
.bars .track{display:block;background:var(--line);border-radius:4px;height:12px;overflow:hidden}
.bars .fill{display:block;height:100%;border-radius:4px;background:var(--accent)}
.bars .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sev-CRITICAL{background:var(--crit)!important}.sev-HIGH{background:var(--high)!important}.sev-MEDIUM{background:var(--med)!important}.sev-LOW{background:var(--low)!important}.sev-INFO{background:var(--info)!important}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:11px;font-weight:700;white-space:nowrap}
.stack{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--line)}.stack span{display:block;height:100%}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:center}
.filters input,.filters select{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text);min-height:32px}
.filters input{flex:1 1 260px}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.seg button{border:0;border-radius:0;border-right:1px solid var(--line)}.seg button:last-child{border-right:0}
.seg button.active,.subtabs button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.subtabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;min-inline-size:760px}
table.compact{min-inline-size:0}
caption{text-align:left;padding:10px 12px;font-weight:600}
th,td{padding:8px 10px;border-top:1px solid var(--line);text-align:left;vertical-align:top}
thead th{background:var(--bg);font-size:12px;color:var(--muted);position:sticky;top:0}
th:has(> button){padding:0}
th button{width:100%;border:0;border-radius:0;background:none;text-align:left;padding:8px 10px;color:inherit;font-weight:600}
th[aria-sort="ascending"] button::after{content:" ▲"}th[aria-sort="descending"] button::after{content:" ▼"}
tbody tr:hover{background:color-mix(in srgb,var(--accent) 6%,transparent)}
tr.clickable{cursor:pointer}tr.selected{background:color-mix(in srgb,var(--accent) 12%,transparent)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.title{max-width:440px}td.title .sub{color:var(--muted);font-size:11px;word-break:break-all}
.empty{padding:24px;text-align:center;color:var(--muted)}
.muted{color:var(--muted)}.small{font-size:12px}
svg text{fill:var(--muted);font-size:11px}
svg .grid-line{stroke:var(--line)}
svg .bar:hover{opacity:.8}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted);margin-top:6px}
.legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;background:var(--c)}
.asset-card .risk{font-size:22px;font-weight:700}
.heat td{padding:4px;text-align:center;font-size:11px;border:1px solid var(--line);min-width:30px}
.heat th{font-size:11px;padding:4px;white-space:nowrap}
.heat td.name{text-align:left;white-space:nowrap;font-size:12px}
details{border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0}
summary{cursor:pointer;font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;font:12px/1.5 Consolas,"Cascadia Mono",monospace;max-height:360px;overflow:auto}
dialog{max-width:min(980px,96vw);width:100%;border:1px solid var(--line);border-radius:14px;padding:0;background:var(--panel);color:var(--text)}
dialog:modal{overscroll-behavior:contain}
dialog::backdrop{background:rgb(0 0 0 / .5);overflow:hidden;overscroll-behavior:contain}
dialog .dlg-head{display:flex;justify-content:space-between;gap:12px;align-items:start;padding:16px 18px;border-bottom:1px solid var(--line)}
dialog .dlg-head h1{font-size:17px;margin:0}
dialog .dlg-body{padding:16px 18px;max-height:72vh;overflow:auto}
.section{margin-bottom:14px}.section h3{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 6px}
.kv{display:grid;grid-template-columns:160px 1fr;gap:4px 12px;font-size:13px}.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-word}
.cmp-cols{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr))}
.list{max-height:420px;overflow:auto}
.list .item{display:flex;gap:8px;align-items:flex-start;padding:6px 0;border-top:1px solid var(--line);font-size:13px}
.toast{position:fixed;right:20px;bottom:20px;background:var(--text);color:var(--bg);padding:8px 14px;border-radius:8px;opacity:0;transition:opacity .2s}
.toast.show{opacity:1}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
@media print{nav.tabs,.actions,.filters,.subtabs{display:none}section.panel-tab[hidden]{display:block}}
@media (prefers-reduced-motion:reduce){.toast{transition:none}}
</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <img id="logo" alt="Scan Titan" width="64" height="64" hidden>
    <div>
      <h1>Scan Titan — Centro operativo de vulnerabilidades</h1>
      <div class="meta"><span id="scanner"></span><span>Generado: <b id="generated"></b></span><span>Corte: <b id="cutoff"></b></span><span id="snapshotStatus" class="badge"></span><span id="stateSource"></span></div>
    </div>
  </div>
  <div class="actions">
    <button type="button" id="exportBtn">Exportar CSV</button>
    <button type="button" id="exportTriage">Exportar descartes</button>
    <label class="btn">Importar descartes<input type="file" id="importTriage" accept="application/json" hidden></label>
    <button type="button" id="printBtn">Imprimir</button>
  </div>
</header>
<nav class="tabs" id="mainTabs" role="tablist" aria-label="Secciones del reporte">
  <button type="button" role="tab" id="tab-resumen" aria-controls="panel-resumen" aria-selected="true" data-tab="resumen">Resumen</button>
  <button type="button" role="tab" id="tab-evolucion" aria-controls="panel-evolucion" aria-selected="false" tabindex="-1" data-tab="evolucion">Evolución</button>
  <button type="button" role="tab" id="tab-comparar" aria-controls="panel-comparar" aria-selected="false" tabindex="-1" data-tab="comparar">Comparar fechas</button>
  <button type="button" role="tab" id="tab-vulnerabilidades" aria-controls="panel-vulnerabilidades" aria-selected="false" tabindex="-1" data-tab="vulnerabilidades">Vulnerabilidades<span class="count" id="countTypes"></span></button>
  <button type="button" role="tab" id="tab-hallazgos" aria-controls="panel-hallazgos" aria-selected="false" tabindex="-1" data-tab="hallazgos">Hallazgos<span class="count" id="countActive"></span></button>
  <button type="button" role="tab" id="tab-validar" aria-controls="panel-hallazgos" aria-selected="false" tabindex="-1" data-tab="validar">Por validar<span class="count" id="countPending"></span></button>
  <button type="button" role="tab" id="tab-objetivos" aria-controls="panel-objetivos" aria-selected="false" tabindex="-1" data-tab="objetivos">Objetivos<span class="count" id="countTargets"></span></button>
  <button type="button" role="tab" id="tab-cobertura" aria-controls="panel-cobertura" aria-selected="false" tabindex="-1" data-tab="cobertura">Cobertura</button>
  <button type="button" role="tab" id="tab-recon" aria-controls="panel-recon" aria-selected="false" tabindex="-1" data-tab="recon">Reconocimiento</button>
</nav>
<main>
<section class="panel-tab" id="panel-resumen" role="tabpanel" aria-labelledby="tab-resumen">
  <p class="summary" id="summary"></p>
  <div class="grid kpis" id="kpis"></div>
  <div class="grid two" style="margin-top:16px">
    <div class="card span-all"><h2>Vulnerabilidades vigentes a lo largo del tiempo</h2><p class="desc">Últimas 30 fechas con escaneo. Cada objetivo aporta el resultado de su último escaneo en esa fecha. Detalle completo en la pestaña Evolución.</p><div id="miniTrend"></div><div class="legend" id="sevLegend"></div></div>
    <div class="card"><h2>Severidad de hallazgos vigentes</h2><div class="bars" id="sevBars"></div></div>
    <div class="card"><h2>Calidad de la evidencia</h2><div class="bars" id="qualityBars"></div><p class="small muted">Validado: prueba diferencial o contenido probatorio. Observado: configuración verificable en la respuesta. Por validar: correlación o heurística sin prueba.</p></div>
    <div class="card"><h2>Prioridad (riesgo combinado)</h2><div id="priority"></div><p class="small muted" id="riskFormula"></p></div>
    <div class="card"><h2>Tipos de vulnerabilidad más extendidos</h2><div class="bars" id="topTypes"></div></div>
    <div class="card"><h2>Por motor de detección</h2><div class="bars" id="engineBars"></div></div>
    <div class="card"><h2>OWASP Top 10 2025</h2><div class="bars" id="owaspBars"></div></div>
  </div>
</section>

<section class="panel-tab" id="panel-evolucion" role="tabpanel" aria-labelledby="tab-evolucion" hidden>
  <div class="filters"><span class="small muted">Periodo:</span>
    <div class="seg" id="rangeSeg" role="group" aria-label="Periodo"><button type="button" data-range="7">7 días</button><button type="button" data-range="30" class="active">30 días</button><button type="button" data-range="90">90 días</button><button type="button" data-range="0">Todo</button></div>
    <select id="evoTarget" aria-label="Objetivo"></select>
  </div>
  <div class="grid kpis" id="evoKpis"></div>
  <div class="grid two" style="margin-top:16px">
    <div class="card span-all"><h2>Vulnerabilidades vigentes por severidad</h2><p class="desc">Barras apiladas por fecha: si suben hay más exposición, si bajan se corrigió. Pasa el cursor sobre una barra para ver el detalle.</p><div id="stackChart"></div><div class="legend" id="sevLegend2"></div></div>
    <div class="card span-all"><h2>Nuevas y resueltas por fecha</h2><p class="desc">Barras hacia arriba: vulnerabilidades que aparecen. Hacia abajo: las que dejan de observarse. La línea es el cambio neto.</p><div id="flowChart"></div><div class="legend"><span style="--c:var(--high)">Nuevas</span><span style="--c:var(--ok)">Resueltas</span><span style="--c:var(--text)">Neto</span></div></div>
    <div class="card span-all"><h2>Registro por fecha</h2><p class="desc">Selecciona una fecha para ver qué apareció y qué se resolvió.</p>
      <div class="table-wrap"><table class="compact" id="dayTable"><thead><tr><th>Fecha</th><th>Vigentes</th><th>Crítica</th><th>Alta</th><th>Media</th><th>Baja</th><th>Nuevas</th><th>Resueltas</th><th>Variación</th><th>Objetivos escaneados</th></tr></thead><tbody id="dayRows"></tbody></table></div>
      <div id="dayDetail"></div></div>
    <div class="card span-all"><h2>Evolución por objetivo</h2><p class="desc">Tendencia de cada objetivo y variación frente a su escaneo anterior.</p><div class="table-wrap"><table class="compact"><thead><tr><th>Objetivo</th><th>Tendencia</th><th>Vigentes</th><th>Variación</th><th>Desde el inicio</th><th>Último escaneo</th></tr></thead><tbody id="targetTrend"></tbody></table></div></div>
    <div class="card span-all"><h2>Mapa de calor objetivo × fecha</h2><p class="desc">Número de vulnerabilidades vigentes; más intenso = más vulnerabilidades.</p><div class="table-wrap" id="heatmap"></div></div>
    <div class="card"><h2>Antigüedad de los hallazgos vigentes</h2><div class="bars" id="aging"></div></div>
    <div class="card"><h2>Reincidencia</h2><div class="bars" id="recurrence"></div></div>
  </div>
</section>

<section class="panel-tab" id="panel-comparar" role="tabpanel" aria-labelledby="tab-comparar" hidden>
  <div class="card">
    <h2>Comparar dos fechas</h2><p class="desc">Elige una fecha de referencia y otra posterior para ver qué vulnerabilidades aparecieron, cuáles se resolvieron y cuáles persisten.</p>
    <div class="filters"><label class="small">Desde <select id="cmpA" aria-label="Fecha de referencia"></select></label><label class="small">Hasta <select id="cmpB" aria-label="Fecha a comparar"></select></label><select id="cmpTarget" aria-label="Objetivo"></select></div>
    <div class="grid kpis" id="cmpKpis"></div>
    <div class="grid two" style="margin-top:16px"><div class="card"><h3 style="margin-top:0">Por severidad</h3><div id="cmpSev"></div><div class="legend"><span style="--c:var(--info)" id="cmpLegendA">Desde</span><span style="--c:var(--med)" id="cmpLegendB">Hasta (color de su severidad)</span></div></div><div class="card"><h3 style="margin-top:0">Por objetivo</h3><div id="cmpTargets"></div></div></div>
    <div class="cmp-cols" style="margin-top:16px"><div class="card"><h3 style="margin-top:0">Nuevas <span class="count" id="cmpNewN"></span></h3><div class="list" id="cmpNew"></div></div><div class="card"><h3 style="margin-top:0">Resueltas <span class="count" id="cmpGoneN"></span></h3><div class="list" id="cmpGone"></div></div><div class="card"><h3 style="margin-top:0">Persisten <span class="count" id="cmpKeepN"></span></h3><div class="list" id="cmpKeep"></div></div></div>
  </div>
</section>

<section class="panel-tab" id="panel-vulnerabilidades" role="tabpanel" aria-labelledby="tab-vulnerabilidades" hidden>
  <div class="card">
    <h2>Vulnerabilidades detectadas por Scan Titan</h2><p class="desc">Cada fila es un tipo de vulnerabilidad vigente, agrupando todos los objetivos y ubicaciones donde se detectó. Despliega una fila para ver cada caso.</p>
    <div class="filters"><input type="search" id="typeSearch" placeholder="Buscar tipo, CWE, objetivo…" aria-label="Buscar tipo"><select id="typeSeverity" aria-label="Severidad"></select></div>
    <div id="typeList"></div>
  </div>
</section>

<section class="panel-tab" id="panel-hallazgos" role="tabpanel" aria-labelledby="tab-hallazgos" hidden>
  <div class="card">
    <p id="triageMode" class="small muted"></p>
    <div class="subtabs" id="viewTabs" role="group" aria-label="Estado">
      <button type="button" class="active" data-view="ACTIVE">Vigentes</button>
      <button type="button" data-view="PENDING">Por validar</button>
      <button type="button" data-view="NEW">Nuevos</button>
      <button type="button" data-view="REGRESSION">Regresiones</button>
      <button type="button" data-view="NOT_SEEN">No vistos</button>
      <button type="button" data-view="DISCARDED">Descartados</button>
      <button type="button" data-view="ALL">Todos</button>
    </div>
    <div class="filters">
      <input type="search" id="search" placeholder="Buscar título, URL, parámetro, CWE, ID…" aria-label="Buscar">
      <select id="severityFilter" aria-label="Severidad"></select>
      <select id="targetFilter" aria-label="Objetivo"></select>
      <select id="categoryFilter" aria-label="Categoría"></select>
      <select id="sourceFilter" aria-label="Motor"></select>
      <select id="confidenceFilter" aria-label="Confianza"></select>
      <button type="button" id="clearFilters">Limpiar filtros</button>
    </div>
    <p class="small muted"><span id="rowCount"></span></p>
    <div class="table-wrap" role="region" aria-labelledby="findingsCaption" tabindex="0">
      <table id="findingTable">
        <caption id="findingsCaption">Registro operativo de hallazgos</caption>
        <thead><tr>
          <th scope="col" data-key="severity"><button type="button" data-sort="severity">Severidad</button></th>
          <th scope="col" data-key="title"><button type="button" data-sort="title">Hallazgo</button></th>
          <th scope="col" data-key="target"><button type="button" data-sort="target">Objetivo</button></th>
          <th scope="col" data-key="category"><button type="button" data-sort="category">Categoría</button></th>
          <th scope="col" data-key="quality"><button type="button" data-sort="quality">Evidencia</button></th>
          <th scope="col" data-key="risk"><button type="button" data-sort="risk">Riesgo</button></th>
          <th scope="col" data-key="first_seen"><button type="button" data-sort="first_seen">Primera vez</button></th>
          <th scope="col" data-key="last_seen"><button type="button" data-sort="last_seen">Última vez</button></th>
          <th scope="col">Detalle</th>
        </tr></thead>
        <tbody id="findingRows"></tbody>
      </table>
    </div>
    <div role="status" class="visually-hidden" id="sortStatus"></div>
  </div>
</section>

<section class="panel-tab" id="panel-objetivos" role="tabpanel" aria-labelledby="tab-objetivos" hidden>
  <div class="grid three" id="assets"></div>
</section>

<section class="panel-tab" id="panel-cobertura" role="tabpanel" aria-labelledby="tab-cobertura" hidden>
  <div class="grid two">
    <div class="card" id="snapshotCard"><h2>Ejecución</h2><dl class="kv" id="runtimeDetail"></dl><p id="runtimeAlert" class="small"></p><p class="small muted" id="runtimeStatus"></p></div>
    <div class="card"><h2>Motores externos</h2><div class="bars" id="toolHealth"></div><div id="toolWarnings"></div></div>
    <div class="card"><h2>Confianza</h2><div class="bars" id="confidenceBars"></div></div>
    <div class="card"><h2>Por categoría</h2><div class="bars" id="categoryBars"></div></div>
    <div class="card span-all"><h2>Inteligencia JavaScript y validación diferencial</h2><div id="intelligenceBody"></div></div>
  </div>
</section>

<section class="panel-tab" id="panel-recon" role="tabpanel" aria-labelledby="tab-recon" hidden>
  <div class="card">
    <p class="small muted">Reconocimiento solamente: las rutas, tecnologías y puertos no se contabilizan como vulnerabilidades.</p>
    <div class="filters"><input type="search" id="reconSearch" placeholder="Filtrar objetivo, tecnología, ruta…" aria-label="Filtrar reconocimiento"></div>
    <div id="reconBody"></div>
  </div>
</section>
</main>

<dialog id="detailDialog" aria-labelledby="detailTitle" closedby="any">
  <div class="dlg-head"><div><h1 id="detailTitle"></h1><div class="small muted" id="detailId"></div></div>
    <form method="dialog"><button type="submit" id="closeDialog" autofocus>Cerrar</button></form></div>
  <div class="dlg-body" id="detailBody"></div>
</dialog>
<div class="toast" id="toast" role="status"></div>

<script type="application/json" id="dashboardData">__DASHBOARD_DATA__</script>
<script>
const $=id=>document.getElementById(id);
const data=JSON.parse($('dashboardData').textContent);
const meta=data.meta||{};
const timeline=data.timeline||{dates:[],series:[],targets:{},items:[],snapshots:{}};
const SEV=['CRITICAL','HIGH','MEDIUM','LOW'];
const severityRank={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
const sevLabel={CRITICAL:'Crítica',HIGH:'Alta',MEDIUM:'Media',LOW:'Baja',INFO:'Info'};
const sevVar={CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)',INFO:'var(--info)'};
const confLabel={high:'Alta',medium:'Media',low:'Baja'};
const qualityLabel={VALIDATED:'Validado',OBSERVED:'Observado',CANDIDATE:'Por validar',INFORMATIONAL:'Informativo'};
const esc=v=>String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
const attr=(el,k,v)=>{if(el&&el.setAttribute)el.setAttribute(k,v)};
const collator=new Intl.Collator('es',{numeric:true,sensitivity:'base'});
const fmtDate=d=>{const p=String(d||'').slice(0,10).split('-');return p.length===3?`${p[2]}/${p[1]}`:d};

/* ---- Analyst triage (shared contract with daily_server) ---- */
const triageStorage='scanTitanAnalystTriageV1';
let decisions={...(data.triage||{})};
try{const local=JSON.parse(localStorage.getItem(triageStorage)||'{}');for(const [k,v] of Object.entries(local)){if(v&&v.updated_at>=(decisions[k]?.updated_at||''))decisions[k]=v}}catch(_){}
const discarded=r=>decisions[r.triage_key]?.decision==='discarded';
let active=[],pending=[];
function recount(){
  data.rows=data.rows||[];
  active=data.rows.filter(r=>r.state==='ACTIVE'&&!discarded(r));
  pending=data.rows.filter(r=>r.state==='PENDING'&&!discarded(r));
  meta.active=active.length;
  meta.high_critical=active.filter(r=>['CRITICAL','HIGH'].includes(r.severity)).length;
  meta.severity=Object.fromEntries(Object.keys(severityRank).map(s=>[s,active.filter(r=>r.severity===s).length]));
  const assetsMap=new Map();
  for(const r of active){if(!assetsMap.has(r.target))assetsMap.set(r.target,[]);assetsMap.get(r.target).push(r)}
  data.assets=[...assetsMap].map(([target,rows])=>{const s=rows.map(r=>r.risk).sort((a,b)=>b-a);return {target,total:rows.length,rows,risk:Math.min(100,Math.round((s[0]+.05*s.slice(1).reduce((a,b)=>a+b,0))*10)/10),severity:Object.fromEntries(Object.keys(severityRank).map(k=>[k,rows.filter(r=>r.severity===k).length]))}}).sort((a,b)=>b.risk-a.risk);
  data.priority=[...active].sort((a,b)=>b.risk-a.risk).slice(0,8);
  const discards=Object.values(decisions).filter(v=>v.decision==='discarded').length;
  meta.summary=`${active.length} hallazgos activos con evidencia disponible en ${data.assets.length} objetivo(s); ${meta.high_critical} de prioridad crítica o alta. ${pending.length} alertas pendientes de validación y ${discards} descartes del analista. Las alertas sin prueba reproducible (correlación de versiones, heurísticas, inyecciones sin validación diferencial) se muestran en "Por validar" y no cuentan como vulnerabilidades.`;
}
async function saveTriage(){
  localStorage.setItem(triageStorage,JSON.stringify(decisions));
  if(window.SCAN_TITAN_TRIAGE_TOKEN){const response=await fetch('/api/triage',{method:'POST',headers:{'Content-Type':'application/json','X-ScanTitan-Token':window.SCAN_TITAN_TRIAGE_TOKEN},body:JSON.stringify({schema:'scan_titan_triage_v1',decisions})});if(!response.ok)throw Error('No se pudo guardar el descarte en el motor');const saved=await response.json();decisions=saved.decisions;localStorage.setItem(triageStorage,JSON.stringify(decisions))}
}
async function toggleDiscard(key){
  const r=data.rows.find(x=>x.triage_key===key);if(!r)return;
  const restoring=discarded(r);
  const reason=restoring?'Restaurado por el analista':prompt('Motivo del falso positivo (solo afecta este origen, ruta, método, parámetro y tipo):','Sin evidencia reproducible');
  if(reason===null)return;
  const previous=decisions[key];
  decisions[key]={decision:restoring?'restored':'discarded',reason:reason||'Descartado por el analista',updated_at:new Date().toISOString(),url:r.url,title:r.title};
  try{await saveTriage();location.reload()}catch(error){if(previous)decisions[key]=previous;else delete decisions[key];try{localStorage.setItem(triageStorage,JSON.stringify(decisions))}catch(_){}alert(error.message+'. El descarte no se confirmó; vuelve a intentarlo.')}
}
function exportTriage(){const blob=new Blob([JSON.stringify({schema:'scan_titan_triage_v1',decisions},null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='finding_triage.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),500)}

/* ---- Chart helpers (inline SVG, no external libraries) ---- */
function bars(id,entries,{sev=false,limit=12}={}){
  const el=$(id);const list=entries.filter(e=>e[1]>0).slice(0,limit);
  if(!list.length){el.innerHTML='<p class="small muted">Sin datos.</p>';return}
  const max=Math.max(...list.map(e=>e[1]));
  el.innerHTML=list.map(([name,value,cls])=>`<div class="row"><span class="name" title="${esc(name)}">${esc(sev?(sevLabel[name]||name):name)}</span><span class="track"><span class="fill ${sev?'sev-'+esc(name):esc(cls||'')}" style="width:${Math.max(2,value/max*100)}%"></span></span><b>${value}</b></div>`).join('');
}
const countBy=(rows,fn)=>{const m=new Map();for(const r of rows){for(const k of [].concat(fn(r)||[])){if(k)m.set(k,(m.get(k)||0)+1)}}return [...m].sort((a,b)=>b[1]-a[1])};
const niceMax=v=>{if(v<=5)return 5;const p=Math.pow(10,Math.floor(Math.log10(v)));const n=v/p;return [1.2,1.5,2,2.5,3,4,5,6,8,10].find(x=>n<=x)*p};
function axes(w,h,pad,max,ticks=4){let g='';for(let i=0;i<=ticks;i++){const y=h-pad.b-(i/ticks)*(h-pad.t-pad.b),v=Math.round(max*i/ticks);g+=`<line class="grid-line" x1="${pad.l}" y1="${y}" x2="${w-pad.r}" y2="${y}"/><text x="${pad.l-6}" y="${y+4}" text-anchor="end">${v}</text>`}return g}
function xLabels(points,x,h,pad){const step=Math.max(1,Math.ceil(points.length/10));return points.map((p,i)=>i%step===0||i===points.length-1?`<text x="${x(i)}" y="${h-pad.b+16}" text-anchor="middle">${esc(fmtDate(p.date))}</text>`:'').join('')}
function stackChart(series,{h=300}={}){
  if(!series.length)return '<p class="empty">Aún no hay historial de escaneos.</p>';
  const w=960,pad={l:44,r:12,t:12,b:28},max=niceMax(Math.max(1,...series.map(s=>s.total)));
  const band=(w-pad.l-pad.r)/series.length,bw=Math.max(4,Math.min(40,band*.7)),x=i=>pad.l+band*i+band/2;
  const y=v=>(v/max)*(h-pad.t-pad.b);
  let bars='';series.forEach((s,i)=>{let acc=0;const tip=`${s.date}: ${s.total} vigentes · `+SEV.map(k=>`${sevLabel[k]} ${s[k]||0}`).join(' · ')+(s.new||s.resolved?` · +${s.new||0} / -${s.resolved||0}`:'');
    for(const k of [...SEV].reverse()){const v=s[k]||0;if(!v)continue;const top=h-pad.b-y(acc+v);bars+=`<rect class="bar" x="${x(i)-bw/2}" y="${top}" width="${bw}" height="${y(v)}" fill="${sevVar[k]}"><title>${esc(tip)}</title></rect>`;acc+=v}
    if(series.length<=40)bars+=`<text x="${x(i)}" y="${h-pad.b-y(s.total)-4}" text-anchor="middle">${s.total}</text>`});
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" role="img" aria-label="Vulnerabilidades vigentes por severidad y fecha">${axes(w,h,pad,max)}${bars}${xLabels(series,x,h,pad)}</svg>`;
}
function flowChart(series,{h=240}={}){
  if(!series.length)return '<p class="empty">Aún no hay historial de escaneos.</p>';
  const w=960,pad={l:44,r:12,t:12,b:28},mid=(h-pad.b+pad.t)/2,maxv=niceMax(Math.max(1,...series.map(s=>Math.max(s.new||0,s.resolved||0))));
  const band=(w-pad.l-pad.r)/series.length,bw=Math.max(4,Math.min(30,band*.6)),x=i=>pad.l+band*i+band/2,sc=v=>v/maxv*(mid-pad.t);
  let g=`<line class="grid-line" x1="${pad.l}" y1="${mid}" x2="${w-pad.r}" y2="${mid}"/><text x="${pad.l-6}" y="${pad.t+8}" text-anchor="end">+${maxv}</text><text x="${pad.l-6}" y="${h-pad.b}" text-anchor="end">-${maxv}</text>`;
  const net=[];series.forEach((s,i)=>{const n=s.new||0,r=s.resolved||0;
    if(n)g+=`<rect class="bar" x="${x(i)-bw/2}" y="${mid-sc(n)}" width="${bw}" height="${sc(n)}" fill="var(--high)"><title>${esc(s.date)}: ${n} nuevas</title></rect>`;
    if(r)g+=`<rect class="bar" x="${x(i)-bw/2}" y="${mid}" width="${bw}" height="${sc(r)}" fill="var(--ok)"><title>${esc(s.date)}: ${r} resueltas</title></rect>`;
    net.push([x(i),mid-sc(Math.max(-maxv,Math.min(maxv,n-r)))])});
  g+=`<polyline points="${net.map(p=>p.join(',')).join(' ')}" fill="none" stroke="var(--text)" stroke-width="1.5" stroke-dasharray="4 3"/>`;
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" role="img" aria-label="Nuevas y resueltas por fecha">${g}${xLabels(series,x,h,pad)}</svg>`;
}
function sparkline(values,{w=140,h=34,color='var(--accent)'}={}){
  if(values.length<2)return '<span class="small muted">—</span>';
  const max=Math.max(1,...values),min=Math.min(...values),span=Math.max(1,max-min),step=(w-4)/(values.length-1);
  const pts=values.map((v,i)=>`${(2+i*step).toFixed(1)},${(h-3-(v-min)/span*(h-6)).toFixed(1)}`).join(' ');
  const last=pts.split(' ').pop().split(',');
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Tendencia"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2"/><circle cx="${last[0]}" cy="${last[1]}" r="2.5" fill="${color}"/></svg>`;
}
function delta(cur,prev,{invert=false}={}){
  if(prev===undefined||prev===null)return '<span class="delta flat">—</span>';
  const d=cur-prev;if(!d)return '<span class="delta flat">= sin cambio</span>';
  const worse=invert?d<0:d>0,pct=prev?` (${d>0?'+':''}${Math.round(d/prev*100)}%)`:'';
  return `<span class="delta ${worse?'up':'down'}">${d>0?'▲':'▼'} ${d>0?'+':''}${d}${pct}</span>`;
}
const sevPill=s=>`<span class="pill sev-${esc(s)}">${esc(sevLabel[s]||s)}</span>`;
const sevStack=counts=>{const total=Object.values(counts).reduce((a,b)=>a+b,0)||1;return `<div class="stack">${Object.keys(severityRank).map(s=>counts[s]?`<span class="sev-${s}" style="width:${counts[s]/total*100}%" title="${sevLabel[s]}: ${counts[s]}"></span>`:'').join('')}</div>`};
const engine=r=>(String(r.sources||'').split(/[,;|]/).map(x=>x.trim().split(':')[0]).filter(Boolean));
const legendHtml=()=>SEV.map(k=>`<span style="--c:${sevVar[k]}">${sevLabel[k]}</span>`).join('');

/* ---- Header and summary ---- */
function renderHeader(){
  if(data.logo){const img=$('logo');img.src=data.logo;img.hidden=false}
  $('scanner').textContent=meta.scanner||'';$('generated').textContent=(meta.generated_at||'').replace('T',' ').slice(0,19);
  $('cutoff').textContent=(meta.cutoff||'').replace('T',' ').slice(0,19)||'N/D';
  $('snapshotStatus').textContent=meta.snapshot_status||'';$('snapshotStatus').classList.add(meta.snapshot_status||'');
  $('stateSource').textContent=meta.state_source==='SCAN_TITAN_STATE'?'Fuente: estado del motor':'Fuente: reportes históricos';
  $('triageMode').textContent=window.SCAN_TITAN_TRIAGE_TOKEN?'Descartes sincronizados con el motor: se aplican a futuros escaneos y pueden restaurarse.':'Vista de archivo: los descartes se guardan en este navegador. Abre Abrir_Daily.cmd para guardarlos también en el motor, o exporta finding_triage.json a audit_reports.';
}
function seriesFor(target){
  if(!target)return timeline.series||[];
  return (timeline.targets?.[target]||[]).map(p=>({...p}));
}
function renderSummary(){
  $('summary').textContent=meta.summary;
  const s=timeline.series||[],last=s[s.length-1],prev=s[s.length-2];
  const notSeen=data.rows.filter(r=>r.state==='NOT_SEEN'&&!discarded(r)).length;
  const fresh=active.filter(r=>r.status==='NEW').length,reg=active.filter(r=>r.status==='REGRESSION').length;
  const validated=active.filter(r=>r.quality==='VALIDATED').length;
  const cards=[['Hallazgos vigentes',active.length,'',last&&prev?delta(last.total,prev.total)+' vs escaneo anterior':`${validated} con prueba diferencial`],
    ['Crítica + alta',meta.high_critical,'crit',last&&prev?delta((last.CRITICAL||0)+(last.HIGH||0),(prev.CRITICAL||0)+(prev.HIGH||0)):'Prioridad inmediata'],
    ['Nuevas en el último escaneo',last?.new??fresh,'high',`${reg} regresiones`],['Resueltas en el último escaneo',last?.resolved??0,'ok','Dejaron de observarse'],
    ['Por validar',pending.length,'','Sin prueba reproducible'],['Ya no vistos',notSeen,'ok','Resueltos o fuera de cobertura'],
    ['Objetivos afectados',data.assets.length,'',`${meta.targets||data.assets.length} en el corte`]];
  $('kpis').innerHTML=cards.map(([l,v,c,h])=>`<div class="card kpi ${c}"><div class="label">${esc(l)}</div><div class="value">${v}</div><div class="hint">${h}</div></div>`).join('');
  $('miniTrend').innerHTML=stackChart(s.slice(-30),{h:220});$('sevLegend').innerHTML=legendHtml();
  bars('sevBars',Object.keys(severityRank).map(k=>[k,meta.severity[k]||0]),{sev:true});
  bars('qualityBars',countBy([...active,...pending],r=>qualityLabel[r.quality]||r.quality));
  bars('topTypes',groupTypes().map(g=>[g.title,g.targets.size]),{limit:10});
  bars('engineBars',countBy(active,engine));
  bars('owaspBars',countBy(active,r=>String(r.owasp||'').split(' - ')[0]||'Sin clasificar'));
  bars('categoryBars',countBy(active,r=>r.category));
  bars('confidenceBars',countBy(active,r=>confLabel[r.confidence]||'Sin dato'));
  $('priority').innerHTML=data.priority.length?`<table class="compact"><tbody>${data.priority.map(r=>`<tr><td>${sevPill(r.severity)}</td><td>${esc(r.title)}<div class="small muted">${esc(r.target)}</div></td><td class="num"><b>${r.risk}</b></td><td><button type="button" data-inspect="${esc(r.id)}" data-asset="${esc(r.asset)}">Ver</button></td></tr>`).join('')}</tbody></table>`:'<p class="empty">No hay hallazgos activos en este corte.</p>';
  $('riskFormula').textContent='Riesgo = '+(meta.risk_formula||'');
  $('countActive').textContent=active.length;$('countPending').textContent=pending.length;$('countTargets').textContent=data.assets.length;
}

/* ---- Evolution (history) ---- */
const evo={range:30,target:''};
function rangeSlice(series){if(!evo.range||!series.length)return series;const end=Date.parse(series[series.length-1].date);return series.filter(s=>end-Date.parse(s.date)<=evo.range*864e5)}
function renderEvolution(){
  const full=seriesFor(evo.target),series=rangeSlice(full);
  const last=series[series.length-1],first=series[0],prev=series[series.length-2];
  const peak=series.reduce((m,s)=>s.total>(m?.total??-1)?s:m,null);
  const sumNew=series.reduce((a,s)=>a+(s.new||0),0),sumRes=series.reduce((a,s)=>a+(s.resolved||0),0);
  const cards=last?[['Vigentes ahora',last.total,'',delta(last.total,prev?.total)+' vs anterior'],['Al inicio del periodo',first.total,'',`${fmtDate(first.date)} · ${delta(last.total,first.total)} desde entonces`],
    ['Máximo del periodo',peak.total,'high',`el ${fmtDate(peak.date)}`],['Nuevas en el periodo',evo.target?'—':sumNew,'high','aparecieron'],['Resueltas en el periodo',evo.target?'—':sumRes,'ok','dejaron de observarse'],
    ['Crítica + alta ahora',(last.CRITICAL||0)+(last.HIGH||0),'crit',delta((last.CRITICAL||0)+(last.HIGH||0),(prev?.CRITICAL||0)+(prev?.HIGH||0))]]:[];
  $('evoKpis').innerHTML=cards.map(([l,v,c,h])=>`<div class="card kpi ${c}"><div class="label">${esc(l)}</div><div class="value">${v}</div><div class="hint">${h}</div></div>`).join('')||'<p class="empty">Aún no hay historial de escaneos.</p>';
  $('stackChart').innerHTML=stackChart(series);$('sevLegend2').innerHTML=legendHtml();
  $('flowChart').innerHTML=evo.target?'<p class="small muted">Las altas y cierres se muestran para todos los objetivos; elige "Todos los objetivos".</p>':flowChart(series);
  const rows=[...series].reverse();
  $('dayRows').innerHTML=rows.map((s,i)=>{const p=rows[i+1];return `<tr class="clickable" data-day="${esc(s.date)}" tabindex="0"><td><b>${esc(s.date)}</b></td><td class="num"><b>${s.total}</b></td>${SEV.map(k=>`<td class="num">${s[k]||0}</td>`).join('')}<td class="num" style="color:var(--high)">${s.new===undefined?'—':s.new?'+'+s.new:'0'}</td><td class="num" style="color:var(--ok)">${s.resolved===undefined?'—':s.resolved?'-'+s.resolved:'0'}</td><td>${delta(s.total,p?.total)}</td><td class="num">${s.targets_scanned??(s.last_scan===s.date?'sí':'no')}${s.targets_unreachable?` <span class="small" style="color:var(--high)" title="Objetivos sin respuesta HTTP: se conserva su último estado observado">(${s.targets_unreachable} sin respuesta)</span>`:''}</td></tr>`}).join('')||'<tr><td colspan="10" class="empty">Sin datos.</td></tr>';
  $('dayDetail').innerHTML='';
  renderTargetTrends();renderHeatmap();
  const now=Date.parse(meta.cutoff||meta.generated_at)||Date.now(),age=r=>Math.floor((now-Date.parse(r.first_seen||meta.generated_at))/864e5);
  bars('aging',[['< 7 días',active.filter(r=>age(r)<7).length],['7-30 días',active.filter(r=>age(r)>=7&&age(r)<30).length],['30-90 días',active.filter(r=>age(r)>=30&&age(r)<90).length],['> 90 días',active.filter(r=>age(r)>=90).length]],{limit:4});
  bars('recurrence',[['Primera observación',active.filter(r=>r.occurrences<=1).length],['2-5 observaciones',active.filter(r=>r.occurrences>1&&r.occurrences<=5).length],['> 5 observaciones',active.filter(r=>r.occurrences>5).length],['Regresiones',active.filter(r=>r.regression_count>0).length]],{limit:4});
}
function itemRow(i){const it=timeline.items[i]||[];return `<div class="item">${sevPill(it[1])}<div><div>${esc(it[2])}</div><div class="small muted">${esc(it[0])}</div></div></div>`}
function showDay(date){
  const s=(timeline.series||[]).find(x=>x.date===date);if(!s)return;
  for(const tr of document.querySelectorAll('#dayRows tr'))tr.classList.toggle('selected',tr.dataset.day===date);
  $('dayDetail').innerHTML=`<div class="cmp-cols" style="margin-top:12px"><div class="card"><h3 style="margin-top:0">Nuevas el ${esc(date)} <span class="count">${(s.new_ids||[]).length}</span></h3><div class="list">${(s.new_ids||[]).map(itemRow).join('')||'<p class="small muted">Ninguna.</p>'}</div></div><div class="card"><h3 style="margin-top:0">Resueltas el ${esc(date)} <span class="count">${(s.resolved_ids||[]).length}</span></h3><div class="list">${(s.resolved_ids||[]).map(itemRow).join('')||'<p class="small muted">Ninguna.</p>'}</div></div></div>`;
}
function renderTargetTrends(){
  const entries=Object.entries(timeline.targets||{}).map(([t,pts])=>{const sl=rangeSlice(pts),last=sl[sl.length-1],prev=sl[sl.length-2],first=sl[0];return {t,sl,last,prev,first}}).filter(e=>e.last).sort((a,b)=>b.last.total-a.last.total);
  $('targetTrend').innerHTML=entries.map(e=>`<tr><td><b>${esc(e.t)}</b></td><td>${sparkline(e.sl.map(p=>p.total))}</td><td class="num"><b>${e.last.total}</b></td><td>${delta(e.last.total,e.prev?.total)}</td><td>${delta(e.last.total,e.first.total)}</td><td>${esc(e.last.last_scan||'')}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">Sin datos.</td></tr>';
}
function renderHeatmap(){
  const dates=rangeSlice((timeline.series||[]).map(s=>({date:s.date}))).map(s=>s.date);
  const targets=Object.keys(timeline.targets||{}).sort(collator.compare);
  if(!dates.length||!targets.length){$('heatmap').innerHTML='<p class="empty">Sin datos.</p>';return}
  const val=(t,d)=>(timeline.targets[t].find(p=>p.date===d)||{}).total;
  const max=Math.max(1,...targets.flatMap(t=>dates.map(d=>val(t,d)||0)));
  $('heatmap').innerHTML=`<table class="heat compact"><thead><tr><th>Objetivo</th>${dates.map(d=>`<th>${esc(fmtDate(d))}</th>`).join('')}</tr></thead><tbody>${targets.map(t=>`<tr><td class="name">${esc(t)}</td>${dates.map(d=>{const v=val(t,d);return v===undefined?'<td class="muted">·</td>':`<td style="background:color-mix(in srgb,var(--accent) ${Math.round(8+v/max*72)}%,transparent);color:${v/max>.55?'#fff':'inherit'}" title="${esc(t)} ${esc(d)}: ${v}">${v}</td>`}).join('')}</tr>`).join('')}</tbody></table>`;
}

/* ---- Compare two dates ---- */
function fillDates(){
  const dates=timeline.dates||[];const opts=dates.map(d=>`<option value="${esc(d)}">${esc(d)}</option>`).join('');
  $('cmpA').innerHTML=opts;$('cmpB').innerHTML=opts;
  $('cmpA').value=dates[Math.max(0,dates.length-2)]||'';$('cmpB').value=dates[dates.length-1]||'';
  const targets=Object.keys(timeline.targets||{}).sort(collator.compare).map(t=>`<option value="${esc(t)}">${esc(t)}</option>`).join('');
  $('cmpTarget').innerHTML='<option value="">Todos los objetivos</option>'+targets;
  $('evoTarget').innerHTML='<option value="">Todos los objetivos</option>'+targets;
}
function renderCompare(){
  const a=$('cmpA').value,b=$('cmpB').value,t=$('cmpTarget').value,dates=timeline.dates||[];
  if(!dates.length||!a||!b){$('cmpKpis').innerHTML='<p class="empty">Se necesitan al menos dos fechas de escaneo.</p>';return}
  const keep=i=>!t||(timeline.items[i]||[])[0]===t;
  const A=new Set((timeline.snapshots[a]||[]).filter(keep)),B=new Set((timeline.snapshots[b]||[]).filter(keep));
  const added=[...B].filter(i=>!A.has(i)),gone=[...A].filter(i=>!B.has(i)),both=[...B].filter(i=>A.has(i));
  const bySev=set=>Object.fromEntries(SEV.map(k=>[k,[...set].filter(i=>timeline.items[i][1]===k).length]));
  const sa=bySev(A),sb=bySev(B);
  $('cmpKpis').innerHTML=[[`Vigentes el ${fmtDate(a)}`,A.size,'',''],[`Vigentes el ${fmtDate(b)}`,B.size,'',delta(B.size,A.size)],['Nuevas',added.length,'high','no estaban antes'],['Resueltas',gone.length,'ok','ya no se observan'],['Persisten',both.length,'','sin corregir']]
    .map(([l,v,c,h])=>`<div class="card kpi ${c}"><div class="label">${esc(l)}</div><div class="value">${v}</div><div class="hint">${h}</div></div>`).join('');
  const max=Math.max(1,...SEV.map(k=>Math.max(sa[k],sb[k])));
  $('cmpLegendA').textContent=`Desde ${a}`;$('cmpLegendB').textContent=`Hasta ${b} (color de su severidad)`;
  const twin=(v,color)=>`<span class="track" style="display:block;background:var(--line);border-radius:4px;height:10px;overflow:hidden;min-width:120px"><span style="display:block;height:100%;width:${v/max*100}%;background:${color}"></span></span>`;
  $('cmpSev').innerHTML=`<table class="compact"><thead><tr><th>Severidad</th><th>Desde</th><th></th><th>Hasta</th><th></th><th>Variación</th></tr></thead><tbody>${SEV.map(k=>`<tr><td>${sevPill(k)}</td><td class="num">${sa[k]}</td><td>${twin(sa[k],'var(--info)')}</td><td class="num"><b>${sb[k]}</b></td><td>${twin(sb[k],sevVar[k])}</td><td>${delta(sb[k],sa[k])}</td></tr>`).join('')}</tbody></table>`;
  const per=new Map();for(const i of A){const n=timeline.items[i][0];per.set(n,{a:(per.get(n)?.a||0)+1,b:per.get(n)?.b||0})}for(const i of B){const n=timeline.items[i][0];per.set(n,{a:per.get(n)?.a||0,b:(per.get(n)?.b||0)+1})}
  $('cmpTargets').innerHTML=`<table class="compact"><thead><tr><th>Objetivo</th><th>Desde</th><th>Hasta</th><th>Variación</th></tr></thead><tbody>${[...per].sort((x,y)=>y[1].b-x[1].b).map(([n,v])=>`<tr><td>${esc(n)}</td><td class="num">${v.a}</td><td class="num">${v.b}</td><td>${delta(v.b,v.a)}</td></tr>`).join('')}</tbody></table>`;
  const sortIds=ids=>ids.sort((x,y)=>severityRank[timeline.items[x][1]]-severityRank[timeline.items[y][1]]);
  $('cmpNew').innerHTML=sortIds(added).map(itemRow).join('')||'<p class="small muted">Ninguna.</p>';$('cmpNewN').textContent=added.length;
  $('cmpGone').innerHTML=sortIds(gone).map(itemRow).join('')||'<p class="small muted">Ninguna.</p>';$('cmpGoneN').textContent=gone.length;
  $('cmpKeep').innerHTML=sortIds(both).map(itemRow).join('')||'<p class="small muted">Ninguna.</p>';$('cmpKeepN').textContent=both.length;
}

/* ---- Vulnerability catalog (grouped by type) ---- */
function groupTypes(){
  const groups=new Map();
  for(const r of active){const key=r.rule||r.title;if(!groups.has(key))groups.set(key,{key,rows:[],targets:new Set(),titles:new Map()});const g=groups.get(key);g.rows.push(r);g.targets.add(r.target);g.titles.set(r.title,(g.titles.get(r.title)||0)+1)}
  return [...groups.values()].map(g=>{g.title=[...g.titles].sort((a,b)=>b[1]-a[1])[0][0];g.severity=g.rows.map(r=>r.severity).sort((a,b)=>severityRank[a]-severityRank[b])[0];g.first=g.rows.map(r=>r.first_seen||'').sort()[0];g.cwe=[...new Set(g.rows.map(r=>r.cwe).filter(Boolean))].join(', ');g.validated=g.rows.filter(r=>r.quality==='VALIDATED').length;return g})
    .sort((a,b)=>severityRank[a.severity]-severityRank[b.severity]||b.targets.size-a.targets.size||b.rows.length-a.rows.length);
}
function typeTrend(rule){
  const ids=new Set();(timeline.items||[]).forEach((it,i)=>{if(it[4]===rule)ids.add(i)});
  return (timeline.series||[]).slice(-30).map(s=>(timeline.snapshots[s.date]||[]).filter(i=>ids.has(i)).length);
}
function renderCatalog(){
  const q=($('typeSearch').value||'').toLowerCase(),sev=$('typeSeverity').value;
  const groups=groupTypes();$('countTypes').textContent=groups.length;
  const list=groups.filter(g=>(!sev||g.severity===sev)&&(!q||[g.title,g.cwe,...g.targets].join(' ').toLowerCase().includes(q)));
  $('typeList').innerHTML=list.length?`<div class="table-wrap"><table class="compact"><thead><tr><th>Severidad</th><th>Vulnerabilidad</th><th>Objetivos</th><th>Casos</th><th>Con prueba</th><th>Tendencia (30 fechas)</th><th>Desde</th></tr></thead><tbody>${list.map((g,n)=>`<tr class="clickable" data-type="${n}" tabindex="0"><td>${sevPill(g.severity)}</td><td><b>${esc(g.title)}</b><div class="small muted">${esc(g.cwe)}</div></td><td class="num">${g.targets.size}</td><td class="num">${g.rows.length}</td><td class="num">${g.validated}</td><td>${sparkline(typeTrend(g.key),{w:120,h:28,color:sevVar[g.severity]})}</td><td>${esc((g.first||'').slice(0,10))}</td></tr><tr id="type-${n}" hidden><td colspan="7"><table class="compact"><tbody>${g.rows.sort((a,b)=>b.risk-a.risk).map(r=>`<tr><td>${esc(r.target)}</td><td class="small" style="word-break:break-all">${esc(r.url||r.endpoint)}${r.param?' · '+esc(r.param):''}</td><td>${esc(qualityLabel[r.quality]||r.quality)}</td><td><button type="button" data-inspect="${esc(r.id)}" data-asset="${esc(r.asset)}">Ver</button></td></tr>`).join('')}</tbody></table></td></tr>`).join('')}</tbody></table></div>`:'<p class="empty">No hay hallazgos activos en este corte.</p>';
}

/* ---- Findings table ---- */
const state={view:'ACTIVE',sort:{key:'severity',dir:'ascending'}};
function matchView(r){
  if(state.view==='DISCARDED')return discarded(r);
  if(discarded(r))return false;
  if(state.view==='PENDING')return r.state==='PENDING';
  if(state.view==='ACTIVE')return r.state==='ACTIVE';
  if(state.view==='NEW')return r.state==='ACTIVE'&&r.status==='NEW';
  if(state.view==='REGRESSION')return r.state==='ACTIVE'&&r.status==='REGRESSION';
  if(state.view==='NOT_SEEN')return r.state==='NOT_SEEN';
  return true;
}
function fillSelect(id,label,values,labels={}){const el=$(id);el.innerHTML=`<option value="">${esc(label)}</option>`+values.map(v=>`<option value="${esc(v)}">${esc(labels[v]||v)}</option>`).join('')}
function filters(){
  fillSelect('severityFilter','Todas las severidades',Object.keys(severityRank),sevLabel);
  fillSelect('typeSeverity','Todas las severidades',Object.keys(severityRank),sevLabel);
  fillSelect('targetFilter','Todos los objetivos',[...new Set(data.rows.map(r=>r.target))].sort(collator.compare));
  fillSelect('categoryFilter','Todas las categorías',[...new Set(data.rows.map(r=>r.category))].sort(collator.compare));
  fillSelect('sourceFilter','Todos los motores',[...new Set(data.rows.flatMap(engine))].sort(collator.compare));
  fillSelect('confidenceFilter','Toda confianza',['high','medium','low'],confLabel);
}
function visibleRows(){
  const q=($('search').value||'').toLowerCase(),sev=$('severityFilter').value,t=$('targetFilter').value,c=$('categoryFilter').value,s=$('sourceFilter').value,cf=$('confidenceFilter').value;
  const rows=data.rows.filter(r=>matchView(r)&&(!sev||r.severity===sev)&&(!t||r.target===t)&&(!c||r.category===c)&&(!s||engine(r).includes(s))&&(!cf||r.confidence===cf)
    &&(!q||[r.title,r.url,r.param,r.cwe,r.owasp,r.id,r.target,r.evidence].join(' ').toLowerCase().includes(q)));
  const {key,dir}=state.sort,f=dir==='ascending'?1:-1;
  return rows.sort((a,b)=>f*(key==='severity'?(severityRank[a.severity]-severityRank[b.severity])||(b.risk-a.risk):key==='risk'?a.risk-b.risk:collator.compare(String(a[key]||''),String(b[key]||''))));
}
const viewName={ACTIVE:'Vigentes',PENDING:'Por validar',NEW:'Nuevos',REGRESSION:'Regresiones',NOT_SEEN:'No vistos',DISCARDED:'Descartados',ALL:'Todos'};
function renderRows(){
  const rows=visibleRows();
  $('rowCount').textContent=`${rows.length} hallazgo(s) en la vista "${viewName[state.view]||state.view}".`;
  $('findingRows').innerHTML=rows.length?rows.map(r=>`<tr><td>${sevPill(r.severity)}</td><td class="title"><b>${esc(r.title)}</b><div class="sub">${esc(r.url||r.endpoint)}${r.param?' · parámetro '+esc(r.param):''}</div></td><td>${esc(r.target)}</td><td>${esc(r.category)}</td><td>${esc(qualityLabel[r.quality]||r.quality)}<div class="small muted">confianza ${esc(confLabel[r.confidence]||r.confidence)}</div></td><td class="num"><b>${r.risk}</b></td><td>${esc((r.first_seen||'').slice(0,10))}</td><td>${esc((r.last_seen||'').slice(0,10))}</td><td><button type="button" data-inspect="${esc(r.id)}" data-asset="${esc(r.asset)}">Ver</button></td></tr>`).join('')
    :`<tr><td colspan="9" class="empty">${state.view==='ACTIVE'?'No hay hallazgos activos con los filtros actuales.':'Sin registros en esta vista.'}</td></tr>`;
}
function setView(view){state.view=view;for(const b of document.querySelectorAll('#viewTabs [data-view]'))b.classList.toggle('active',b.dataset.view===view);renderRows()}
$('viewTabs').onclick=e=>{const b=e.target.closest('[data-view]');if(!b)return;setView(b.dataset.view);b.classList.add('active')};
for(const id of ['search','severityFilter','targetFilter','categoryFilter','sourceFilter','confidenceFilter'])$(id).addEventListener(id==='search'?'input':'change',renderRows);
$('clearFilters').addEventListener('click',()=>{for(const id of ['search','severityFilter','targetFilter','categoryFilter','sourceFilter','confidenceFilter'])$(id).value='';renderRows()});
function sortBy(button){
  const th=button.closest('th');const key=th.dataset.key;
  const dir=state.sort.key===key&&state.sort.dir==='ascending'?'descending':'ascending';
  for(const h of document.querySelectorAll('#findingTable thead th'))h.removeAttribute('aria-sort');
  th.setAttribute('aria-sort',dir);state.sort={key,dir};renderRows();
  $('sortStatus').textContent=`Ordenado por ${button.textContent.trim()}, ${dir==='ascending'?'ascendente':'descendente'}`;
}

/* ---- Detail dialog ---- */
function section(title,body,pre=false){return body?`<div class="section"><h3>${esc(title)}</h3>${pre?`<pre>${esc(body)}</pre>`:`<div>${esc(body)}</div>`}</div>`:''}
function inspect(id,asset){
  const r=data.rows.find(x=>x.id===id&&(!asset||x.asset===asset))||data.rows.find(x=>x.id===id);if(!r)return;
  $('detailTitle').textContent=r.title;$('detailId').textContent=`${r.id} · ${r.target}`;
  const kv=[['Severidad',sevLabel[r.severity]||r.severity],['Estado',r.state==='PENDING'?'Por validar':r.state],['Evidencia',qualityLabel[r.quality]||r.quality],['Confianza',confLabel[r.confidence]||r.confidence],['Riesgo',r.risk],['CVSS',r.cvss||''],['CWE',r.cwe],['OWASP',r.owasp],['URL',r.url],['Parámetro',r.param],['Método',r.method],['Motores',r.sources],['Primera vez',r.first_seen],['Última vez',r.last_seen],['Ocurrencias',r.occurrences]]
    .filter(x=>x[1]!==''&&x[1]!==undefined&&x[1]!==null).map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
  const validation=Object.keys(r.validation||{}).length?JSON.stringify(r.validation,null,2):(r.state==='PENDING'?'Sin prueba reproducible todavía: correlación de versión, heurística o alerta de inyección pendiente de validación diferencial.':'');
  const decision=decisions[r.triage_key];
  $('detailBody').innerHTML=`<div class="section"><dl class="kv">${kv}</dl></div>${section('Evidencia técnica',r.evidence,true)}`
    +(r.manual_command?`<div class="section"><h3>Prueba manual (PowerShell)</h3><pre>${esc(r.manual_command)}</pre><button type="button" data-copy="${esc(r.triage_key)}">Copiar comando</button></div>`:'')
    +section('Validación diferencial',validation,true)+section('Impacto',r.impact)+section('Remediación',r.remediation||r.recommendation)
    +(r.evidence_href?`<p><a href="${esc(r.evidence_href)}">Evidencia HTTP</a></p>`:'')+(r.browser_href?`<p><a href="${esc(r.browser_href)}">Captura del navegador</a></p>`:'')
    +(decision?section('Decisión del analista',[decision.decision,decision.reason,decision.updated_at].join(' · ')):'')
    +`<p><button type="button" class="primary" data-discard="${esc(r.triage_key)}">${discarded(r)?'Restaurar hallazgo':'Descartar falso positivo'}</button></p>`;
  $('detailDialog').showModal();
}

/* ---- Assets, coverage, recon ---- */
function renderAssets(){
  $('assets').innerHTML=data.assets.length?data.assets.map(a=>{const pts=timeline.targets?.[a.target]||[],last=pts[pts.length-1],prev=pts[pts.length-2];
    return `<div class="card asset-card"><h2>${esc(a.target)}</h2><div class="risk">${a.risk}<span class="small muted"> riesgo combinado · ${a.total} hallazgo(s)</span></div><div style="margin:6px 0">${sparkline(pts.slice(-30).map(p=>p.total),{w:260,h:40})} ${last?delta(last.total,prev?.total):''}</div>${sevStack(a.severity)}<div class="legend" style="margin:8px 0">${Object.keys(severityRank).filter(s=>a.severity[s]).map(s=>`<span style="--c:${sevVar[s]}">${sevLabel[s]} ${a.severity[s]}</span>`).join('')}</div><table class="compact"><tbody>${[...a.rows].sort((x,y)=>y.risk-x.risk).slice(0,5).map(r=>`<tr><td>${sevPill(r.severity)}</td><td>${esc(r.title)}</td><td><button type="button" data-inspect="${esc(r.id)}" data-asset="${esc(r.asset)}">Ver</button></td></tr>`).join('')}</tbody></table></div>`}).join('')
    :'<p class="empty">No hay hallazgos activos en este corte.</p>';
}
function renderCoverage(){
  const rt=meta.runtime||{};
  $('runtimeDetail').innerHTML=[['Estado',rt.status],['Fase',rt.phase],['Progreso',(rt.percent??'')+'%'],['Objetivos',`${rt.targets_completed||0}/${rt.target_total||0}`],['Actualizado',rt.updated_at],['Fuente de datos',meta.state_source],['Versión del reporte',meta.dashboard_version]].map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v??'')}</dd>`).join('');
  $('runtimeAlert').textContent=rt.error?('Error: '+rt.error):(rt.warning&&rt.status!=='finished'?'Aviso: '+rt.warning:'');
  $('runtimeStatus').textContent=meta.snapshot_status==='PROVISIONAL'?'Corte provisional: el escaneo sigue en curso.':'Corte final del último escaneo.';
  const tools=meta.tools||{};bars('toolHealth',Object.entries(tools.counts||{}));
  $('toolWarnings').innerHTML=(tools.degraded||[]).length?`<h3>Ejecuciones degradadas</h3><table class="compact"><tbody>${tools.degraded.map(t=>`<tr><td>${esc(t.tool)} ${esc(t.profile)}</td><td>${esc(t.status)}</td><td class="small">${esc(t.error)}</td></tr>`).join('')}</tbody></table>`:'<p class="small muted">Sin ejecuciones degradadas.</p>';
  const items=data.intelligence||[],panel=$('intelligenceBody');
  if(!items.length){panel.textContent='El próximo escaneo generará el inventario JavaScript y el registro de validación diferencial.';return}
  const table=(h,rows)=>`<div class="table-wrap"><table class="compact"><thead><tr>${h.map(x=>`<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows.length?rows.map(r=>`<tr>${r.map(x=>`<td>${esc(x)}</td>`).join('')}</tr>`).join(''):'<tr><td>Sin observaciones</td></tr>'}</tbody></table></div>`;
  panel.innerHTML=items.map(item=>{const js=item.javascript||{},tri=item.injection_triage||[];return `<details><summary>${esc(item.target)} · ${(js.scripts||[]).length} scripts · ${tri.length} alertas revisadas</summary>${table(['Alerta','URL','Resultado','Motivo'],tri.slice(0,200).map(x=>[x.title,x.url,x.state,x.reason]))}${table(['Endpoint JS','Fuente','Alcance'],(js.endpoints||[]).slice(0,200).map(x=>[x.url,x.source,x.in_scope?'Mismo origen':'Externo']))}${table(['Posible credencial','Fuente','Valor','Estado'],(js.secret_candidates||[]).map(x=>[x.type,x.source,x.redacted,x.state]))}</details>`}).join('');
}
function renderRecon(){
  const recon=data.recon||{},q=($('reconSearch').value||'').toLowerCase();
  if(!recon.available){$('reconBody').innerHTML='<p class="empty">Recon Matrix no disponible todavía.</p>';return}
  const list=(label,items)=>items&&items.length?`<h3>${esc(label)} (${items.length})</h3><div class="small">${items.slice(0,120).map(esc).join(' · ')}</div>`:'';
  const targets=recon.targets.filter(t=>!q||JSON.stringify(t).toLowerCase().includes(q));
  $('reconBody').innerHTML=targets.length?targets.map(t=>`<details><summary>${esc(t.target)} <span class="small muted">${esc(t.ip)} · ${esc(t.ultima)}</span></summary>${list('Tecnologías',[...(t.tecnologias||[]),...(t.whatweb||[])])}${list('Puertos',t.puertos)}${list('Servicios',t.servicios)}${list('Rutas',t.rutas)}${list('Formularios de login',t.login)}${list('Librerías JS',t.js)}${list('WAF/CDN',[...(t.waf||[]),t.wafw00f,t.perfil_waf].filter(Boolean))}${list('Subdominios',t.subdominios)}</details>`).join(''):'<p class="empty">Sin coincidencias.</p>';
}

/* ---- Tabs (ARIA tablist with arrow keys) ---- */
function selectTab(name){
  for(const b of document.querySelectorAll('#mainTabs [role="tab"]')){const on=b.dataset.tab===name;attr(b,'aria-selected',String(on));b.tabIndex=on?0:-1}
  const panel=name==='validar'?'hallazgos':name;
  for(const p of document.querySelectorAll('section.panel-tab'))p.hidden=p.id!=='panel-'+panel;
  if(name==='validar')setView('PENDING');else if(name==='hallazgos'&&state.view==='PENDING')setView('ACTIVE');
}
$('mainTabs').onclick=e=>{const b=e.target.closest('[data-tab]');if(b)selectTab(b.dataset.tab)};
$('mainTabs').addEventListener('keydown',e=>{const tabs=[...document.querySelectorAll('#mainTabs [role="tab"]')];const i=tabs.indexOf(document.activeElement);if(i<0)return;
  const next=e.key==='ArrowRight'?(i+1)%tabs.length:e.key==='ArrowLeft'?(i-1+tabs.length)%tabs.length:e.key==='Home'?0:e.key==='End'?tabs.length-1:-1;
  if(next<0)return;e.preventDefault();tabs[next].focus();selectTab(tabs[next].dataset.tab)});

/* ---- Global actions ---- */
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1800)}
function exportCsv(){const rows=visibleRows(),cols=['id','severity','title','target','url','param','category','quality','confidence','risk','cwe','owasp','first_seen','last_seen','state'];
  const csv=[cols.join(',')].concat(rows.map(r=>cols.map(c=>'"'+String(r[c]??'').replaceAll('"','""')+'"').join(','))).join('\r\n');
  const url=URL.createObjectURL(new Blob(['﻿'+csv],{type:'text/csv'})),a=document.createElement('a');a.href=url;a.download='scan_titan_hallazgos.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),500)}
document.addEventListener('click',e=>{
  const inspectBtn=e.target.closest('[data-inspect]');if(inspectBtn){inspect(inspectBtn.dataset.inspect,inspectBtn.dataset.asset);return}
  const discardBtn=e.target.closest('[data-discard]');if(discardBtn){toggleDiscard(discardBtn.dataset.discard);return}
  const copyBtn=e.target.closest('[data-copy]');if(copyBtn){const r=data.rows.find(x=>x.triage_key===copyBtn.dataset.copy);if(r)navigator.clipboard.writeText(r.manual_command).then(()=>toast('Comando copiado'));return}
  const sortBtn=e.target.closest('[data-sort]');if(sortBtn){sortBy(sortBtn);return}
  const rangeBtn=e.target.closest('[data-range]');if(rangeBtn){evo.range=Number(rangeBtn.dataset.range);for(const b of document.querySelectorAll('#rangeSeg [data-range]'))b.classList.toggle('active',b===rangeBtn);renderEvolution();return}
  const dayRow=e.target.closest('[data-day]');if(dayRow){showDay(dayRow.dataset.day);return}
  const typeRow=e.target.closest('[data-type]');if(typeRow){const det=$('type-'+typeRow.dataset.type);if(det)det.hidden=!det.hidden;return}
  if(e.target.id==='exportTriage')exportTriage();else if(e.target.id==='exportBtn')exportCsv();else if(e.target.id==='printBtn')print();
});
document.addEventListener('keydown',e=>{if(e.key!=='Enter'||!e.target.closest)return;const row=e.target.closest('[data-day],[data-type]');if(row)row.click()});
$('importTriage').addEventListener('change',async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>2000000)throw Error('Archivo demasiado grande');const parsed=JSON.parse(await file.text());if(parsed.schema!=='scan_titan_triage_v1'||!parsed.decisions||typeof parsed.decisions!=='object')throw Error('Formato inválido');for(const [k,v] of Object.entries(parsed.decisions)){if(!/^[a-f0-9]{64}$/.test(k)||!v||!['discarded','restored'].includes(v.decision))throw Error('Decisión inválida');if((v.updated_at||'')>=(decisions[k]?.updated_at||''))decisions[k]=v}await saveTriage();location.reload()}catch(error){alert(error.message)}});
$('evoTarget').addEventListener('change',()=>{evo.target=$('evoTarget').value;renderEvolution()});
for(const id of ['cmpA','cmpB','cmpTarget'])$(id).addEventListener('change',renderCompare);
$('typeSearch').addEventListener('input',renderCatalog);$('typeSeverity').addEventListener('change',renderCatalog);
$('reconSearch').addEventListener('input',renderRecon);

recount();renderHeader();filters();fillDates();renderSummary();renderRows();renderCatalog();renderAssets();renderEvolution();renderCompare();renderCoverage();renderRecon();
</script>
</body>
</html>
'''


def render_daily(model_json: str) -> str:
    """Return the Daily HTML for an already HTML-safe JSON model string."""
    return DAILY_TEMPLATE.replace("__DASHBOARD_DATA__", model_json)
