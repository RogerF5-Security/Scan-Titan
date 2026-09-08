# Scan Titan Community Edition

Scan Titan es un motor zero-touch de reconocimiento y orquestacion de vulnerabilidades para auditorias autorizadas. Lee objetivos, ejecuta modulos asincronos internos, integra motores externos cuando estan disponibles, deduplica hallazgos y genera evidencia operativa sin preguntas interactivas.

La ejecucion estandar mantiene un piso minimo de 10,000 pruebas en modulos basados en wordlists, genera tarjetas PNG de evidencia para hallazgos reportables y captura evidencia de navegador cuando Playwright esta disponible.

## Estructura

```text
Plantilla0/
  main.py                 # lanzador unico en la raiz
  config/                 # configuracion y dependencias Python
  data/                   # base publica de conocimiento
  install/                # instaladores Windows y Linux
  audit_reports/          # salidas, dashboards y estado del lanzador
  reports/                # compatibilidad con herramientas y pruebas
  src/scan_titan/         # motor del escaner
  targets/targets.txt     # un objetivo por linea
  templates/              # plantillas publicas de reporte
  tools/                  # health-check y utilidades
  wordlists/              # diccionarios de fuzzing
```

## Uso Rapido

Windows:

```powershell
cd C:\Ruta\A\Plantilla0
python .\main.py --health-check
python .\main.py
```

Linux:

```bash
cd /ruta/a/Plantilla0
python3 main.py --health-check
python3 main.py
```

Agrega objetivos autorizados en:

```text
targets/targets.txt
```

El escaner ignora lineas vacias y lineas iniciadas con `#`.

## Modo Full

Modo de maxima cobertura:

```powershell
python .\main.py --full
```

Alias compatibles:

```powershell
python .\main.py -Full
python .\main.py -full
```

El modo full activa perfil profundo, motores externos, auditoria de navegador, tarjetas de evidencia y wordlists completas. Nmap, Nuclei, ZAP y los modulos internos no tienen limite duro de tiempo cuando su timeout esta en `0`; Scan Titan mantiene heartbeat y telemetria para confirmar actividad.

## Control de Ejecucion

En Windows, mientras Scan Titan esta corriendo:

```text
P       pausar
R       reanudar
F       finalizar ordenadamente y generar reportes/dashboard con lo encontrado
Ctrl+C  detener de forma inmediata
```

## Monitor

El monitor es de solo lectura y puede abrirse mientras el escaneo esta activo:

```powershell
python .\main.py --monitor
```

Para monitorear otra carpeta copiada:

```powershell
python .\main.py --monitor --path C:\Ruta\A\OtroEscaneo
```

El monitor detecta la telemetria en `audit_reports/` o `reports/` y respeta las rutas de entorno del escaneo. Si pasan mas de 60 segundos sin actualizacion, muestra `SIN ACTUALIZAR`; un porcentaje antiguo no confirma que el proceso siga avanzando.

LFI, XSS, SSRF y fuzzing de rutas usan un grupo de hasta 20 trabajadores. Los contadores avanzan al terminar cada intento, y cada 15 segundos se informa de peticiones HTTP terminadas, activas y en espera. Se conserva el jitter configurado: 10.000 peticiones a 1-2 segundos entre inicios pueden requerir unas cuatro horas. `F` evita consumir toda la cola pendiente antes de finalizar. Las mejoras requieren reiniciar las ejecuciones iniciadas con versiones anteriores.

## Salidas

El lanzador `main.py` incluido escribe por defecto en:

```text
audit_reports/
```

Las copias antiguas pueden usar `reports/`. Revisa la ruta que imprime el lanzador al finalizar. Para elegir otra salida, define `SCAN_TITAN_REPORTS_DIR` antes de ejecutar el proceso.

Salidas principales:

```text
<salida>/<target>_<YYYY-MM-DD>.txt
<salida>/<target>_<YYYY-MM-DD>.json
<salida>/scan_titan_state.json
<salida>/scan_titan_runtime.json
<salida>/Recon_Matrix.xlsx
<salida>/Recon_Dashboard.html
<salida>/Recon_Sitemap.json
<salida>/Recon_Sitemap.html
<salida>/Daily_vulns_report.html
<salida>/Formal_Audit_Report_<YYYY-MM-DD>.html
<salida>/Formal_Audit_Report_Latest.html
<salida>/external_tools.log
<salida>/external_tools_observability.jsonl
<salida>/External_Tools_Observability.html
<salida>/evidence_screenshots/
<salida>/browser_evidence/
```

El reporte formal incluye portada, resumen ejecutivo, objetivos evaluados, totales por severidad, detalle tecnico de hallazgos, comando de validacion manual, datos First Seen / Last Seen, enlaces a tarjetas de evidencia y capturas de navegador cuando existan.

## Reconocimiento

La inteligencia de superficie no se mezcla con vulnerabilidades. Se guarda en:

```text
<salida>/Recon_Matrix.xlsx
<salida>/Recon_Dashboard.html
<salida>/Recon_Sitemap.html
<salida>/Daily_vulns_report.html
```

El dashboard diario incluye una seccion propia de Reconocimiento por objetivo con tecnologias, puertos, rutas, headers, cookies, subdominios, WhatWeb y perfil WAF/CDN.

`Recon_Sitemap.html` presenta un mapa jerarquico tipo Burp/ZAP por objetivo. Agrupa rutas internas, endpoints, rutas SPA, redirects, estados HTTP, parametros y fuente de descubrimiento para revisar la estructura de la aplicacion sin mezclar inteligencia de superficie con vulnerabilidades.

## Herramientas Externas

Scan Titan usa estas herramientas cuando estan disponibles en `PATH`:

```text
nmap
nuclei
ffuf
whatweb
subfinder
wafw00f
OWASP ZAP
```

Si una herramienta falta, Scan Titan lo reporta en consola, `tool_inventory.json` y observabilidad externa. El motor Python interno continua ejecutandose.

Por defecto, los procesos largos de Nmap, Nuclei y OWASP ZAP no tienen limite duro de tiempo (`0 = sin limite`). Cada proceso emite heartbeat con duracion, salida observada y ultimo mensaje util; si necesitas cerrar la jornada, usa `F` para finalizar ordenadamente y generar dashboard con lo encontrado.

### WhatWeb

Para fingerprinting de tecnologias web, Scan Titan prefiere el motor oficial WhatWeb de Urbanadventurer/Kali. Cuando el binario soporta `--log-json` y `--aggression`, Scan Titan lo ejecuta en modo JSON estructurado y guarda tecnologias, frameworks, servidores, categorias y evidencia en la matriz de Recon.

Validacion recomendada:

```powershell
whatweb --help
```

La ayuda debe incluir `--log-json` y `--aggression`. Si existe un wrapper limitado llamado `whatweb`, Scan Titan usa modo de compatibilidad, pero la identificacion JSON de mayor calidad requiere el binario oficial.

### wafw00f y WAF

Scan Titan integra `wafw00f` para reconocimiento de WAF/CDN y complementa esa salida con un modulo interno de resiliencia WAF. El modulo propio prueba senales de bloqueo, rate-limit, headers alternos, codificaciones, doble codificacion, comentarios, saltos de linea, tabs, mayusculas alternas y variantes Unicode.

Estas pruebas se tratan como reconocimiento defensivo y perfilado de filtros; no se reportan como vulnerabilidad salvo que otro modulo confirme un fallo real.

## Ritmo de Payloads

Los modulos activos usan jitter aleatorio para evitar saturacion local y reducir bloqueos por automatizacion:

```text
payloads: 1.0s a 2.0s por peticion
rutas:    0.5s a 1.5s por bloque
```

Estos valores pueden ajustarse en `config/config.yaml`.

## Instalacion

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\install\install.ps1
```

Linux:

```bash
bash ./install/install.sh
```

Los instaladores actualizan dependencias Python y validan Nmap, Nuclei, WhatWeb, wafw00f y OWASP ZAP.

## Politica de Reporte Publico

La plantilla comunitaria excluye el exportador privado de detalle tecnico. Las salidas publicas son TXT, JSON, Excel de Recon y dashboards HTML con estilo operativo tipo Nessus, enfocados en hallazgos confirmados, confianza, fuerza de evidencia, riesgo de falso positivo, CWE, OWASP Top 10:2025, CVSS estimado y comando de validacion manual.

## Presentacion Web

La presentacion esta en [rogerf5-security.github.io/Scan-Titan](https://rogerf5-security.github.io/Scan-Titan/). Explica el proceso de auditoria, los motores, los reportes y la operacion en Windows y Linux. Los ejemplos son ficticios y no ejecutan escaneos.

La copia local es [web/index.html](web/index.html). Consulta [WEB_PUBLICA.md](WEB_PUBLICA.md) para publicar solo la presentacion desde el propio repositorio Scan-Titan, sin empaquetar el motor ni los datos locales.
