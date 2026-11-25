## Unreleased — Web informativa, README y comandos del Daily (2026-11-24)

- Web pública reescrita como sitio informativo: qué hace, pipeline en seis etapas, control de falsos positivos, Daily Report con galería por pestañas y ampliación de capturas, motores y módulos, instalación, salidas y límites. Se retiran las secciones de llamada a la comunidad y de proyectos futuros.
- README reorganizado con el funcionamiento por etapas, criterios de precisión, Daily histórico y comandos de verificación; capturas nuevas en `assets/daily/` generadas con datos ficticios (`*.example`, 198.51.100.0/24).
- Daily: en inyecciones confirmadas el comando de verificación conserva la prueba literal (`Select-String`) y ya no se rotula como "pendiente de validación"; las alertas históricas sin validación mantienen la comparación control/prueba.

## Unreleased — Daily histórico y comparativo (2026-11-24)

- Daily: pestañas Evolución (vigentes por severidad, nuevas/resueltas con cambio neto, registro por fecha con variación y detalle de qué apareció y qué se resolvió, tendencia y variación por objetivo, mapa de calor objetivo × fecha, antigüedad y reincidencia; periodos 7/30/90 días o todo), Comparar fechas (dos fechas cualesquiera: vigentes, nuevas, resueltas y persistentes por severidad y objetivo) y Vulnerabilidades (catálogo agrupado por tipo con objetivos, casos, prueba y tendencia). Logo de Scan Titan embebido (PNG reducido, sin dependencias externas).
- Histórico fiable (`daily_history.py`): cada fecha usa el último escaneo de cada objetivo (un objetivo no escaneado no cuenta como resuelto), conserva el último estado observado cuando el objetivo no responde HTTP, recalcula la identidad canónica y aplica las reglas de calidad a reportes antiguos.
- Identidad: las cookies se identifican por servicio y nombre de cookie, no por la URL donde el crawler las vio; elimina la rotación falsa de nuevas/resueltas entre escaneos.

## Unreleased — Cobertura medida, identidad estable y Daily por pestañas (2026-11-23)

- Laboratorio de verdad base `tools/vuln_lab.py` (solo 127.0.0.1): aplicación con 12 vulnerabilidades reales, controles negativos (misma funcionalidad segura) y señuelos de falso positivo (catch-all, WAF 403); ejecuta el pipeline completo aislado, mide cobertura y falsos positivos y ejecuta cada `manual_command` en PowerShell comprobando la prueba. Resultado: 12/12, 0 falsos positivos, 17/17 comandos reproducen la prueba (antes 5/11).
- Rutas: `path_discovery` prueba primero ~90 rutas de alto valor (`.env`, `.git`, backups, actuator, phpinfo, swagger...) y luego entradas con marcadores sensibles; antes la wordlist alfabética de 1,6 M líneas se truncaba al presupuesto y esas rutas no se probaban. Se descartan líneas basura de listas públicas.
- Listados de directorio: detección genérica (Apache, Nginx, IIS, Python, Tomcat) en directorios descubiertos y comunes, con firma de índice y oráculo soft-404.
- Redirección abierta: módulo nuevo `open_redirect` con control del mismo sitio, host externo único, `Location`/`Refresh`/meta refresh y repetición 2/2.
- XSS: si el payload del detector no corresponde al contexto (atributo reflejado como texto), el validador prueba payloads por contexto y confirma solo con un elemento ejecutable parseado y repetido.
- CORS: también sobre endpoints de API descubiertos (incluido JavaScript) con origen único por ejecución; `*` con credenciales pasa a Low (los navegadores lo rechazan).
- Cabeceras: CSP ausente y similares ya no se tratan como inyecciones (antes se ocultaban como candidatos por su CWE-79).
- Identidad y deduplicación: familias canónicas en español/inglés, sin acentos ni mojibake, con título antes que evidencia; vulners agrupado por producto CPE y resumen de versiones estable ante actualizaciones del catálogo; migración del estado que fusiona duplicados conservando la observación más reciente y guarda `rule_id` y `legacy_ids`. ZAP se decodifica UTF-8/cp1252 (antes "Exploraci�n").
- OWASP 2025: el CWE del hallazgo prevalece sobre etiquetas persistidas (CWE-601 → A01, no A04) y se añadieron CWE frecuentes.
- Comandos de verificación: Nmap relanza el script NSE exacto en su puerto; Nuclei usa `host:puerto` y `-pt` en plantillas de red; rutas/logs/listados incluyen una ruta inexistente de control; las inyecciones imprimen estado, líneas con la prueba y tiempo en lugar de solo guardar archivos.
- Daily: plantilla única `daily_report.py` (sustituye la plantilla en línea y dos capas de parches) con pestañas Resumen, Hallazgos, Por validar, Objetivos, Tendencias, Cobertura y Reconocimiento; estadísticas por severidad, calidad de evidencia, categoría, motor, OWASP, antigüedad, reincidencia y altas/cierres; tabla ordenable y filtrable, detalle en `<dialog>` con copia del comando, tema claro/oscuro, móvil y CSP estricta.
- Publicación: `tools/leak_gate.py` bloquea hosts de clientes (de `targets.txt`, nombres en `audit_reports` y `config/leak_denylist.local.txt`), claves, tokens, rutas de usuario y correos antes de publicar.

## Unreleased — Control de falsos positivos (2026-11-20)

- Rutas: oraculo soft-404 compartido (`modules/soft_not_found.py`) por origen, directorio padre y extension; compara estado, redireccion y cuerpo normalizado (sin reflejos de la ruta ni tokens volatiles). Antes habia una sola linea base sin extension y comparada solo por titulo, por lo que SPA catch-all, paginas de debug 404 y bloqueos WAF 403 por extension se reportaban como rutas.
- Rutas: un hallazgo exige contenido probatorio en el cuerpo (`.env`, `.git`, claves, actuator, phpinfo, listado). Un 401/403 o un nombre "sensible" sin contenido queda en recon; manifiestos de dependencias/API como Low. El bypass 403 tambien debe distinguirse de una ruta inexistente.
- Logs expuestos: se exige estructura real de log (access/error log de Apache/Nginx, Laravel/Monolog, log4j/logging ISO, traceback completo o listado con `.log`) y respuesta distinta de ruta inexistente; antes bastaba la palabra `error` o `warning` en una respuesta 200 (7 High falsos por objetivo con SPA). Ahora tambien se detectan logs reales sin esas palabras.
- Versiones: un hallazgo por componente y version con todos los avisos (IDs, desglose por severidad, referencias) en lugar de uno por CVE; severidad limitada a Medium por ser correlacion de version sin validacion funcional.
- Calidad (retroactivo sobre estado y Daily, quedan en "Por validar"): avisos por CVE sustituidos por el resumen, logs/rutas antiguos sin prueba de contenido, `http-slowloris-check` "probablemente vulnerable", `http-vuln-cve2011-3192`, CVE inferidos por version con `nmap:vulners`, y reglas activas de ZAP sin evidencia en la respuesta ni confianza alta. La regla de calidad ya lee `last_evidence` de los registros de estado.
- Candidatos: lo excluido por calidad en un escaneo nuevo se guarda en el estado (Daily, "Por validar") en lugar de descartarse; no entra en reportes, totales de consola ni captura de evidencias. La cobertura registra `quality_candidates`.
- Ciclo de vida: en escaneos parciales, un hallazgo ausente pasa a NOT_SEEN si todos los modulos/herramientas que lo produjeron terminaron completos (sin timeout ni error); antes cualquier timeout lo mantenia ACTIVE indefinidamente (52 de 60 ejecuciones recientes eran parciales). La cobertura registra `completed_sources`.
- Pruebas: `tests/test_false_positive_controls.py` y validacion en loopback `tools/validate_false_positives.py` (SPA catch-all, debug 404, WAF por extension y archivos reales).

## Unreleased — Potencia de motores externos (2026-11-20)

- ZAP: alertas paginadas por riesgo (High→Info) y tope por defecto 2000; antes el tope de 250 se llenaba con instancias pasivas/informativas y descartaba las alertas del escaneo activo (IDs mas altos).
- ZAP: escaneo activo sobre todo el contexto del origen; antes solo atacaba el subarbol de la URL objetivo (p. ej. `/app/login`), dejando `/api` y rutas hermanas sin cobertura activa.
- ZAP: AJAX Spider (Firefox headless, limite de tiempo) e importacion de definiciones OpenAPI/GraphQL descubiertas por `api_dast`.
- Nmap: superficie TCP ampliada (1-1024 + ~150 puertos de bases de datos, brokers, Docker/Kubernetes, Java y administracion); `-p-` con `--min-rate` en `--full`; deteccion de version completa (sin `--version-light`); `--script-timeout`.
- Nmap: scripts seguros adicionales (NFS, Redis, Memcached, MongoDB, CouchDB, rsync, RDP) y clasificador `service_exposure.py` con firmas exactas NSE (VNC sin auth, X11 abierto, Redis/Mongo/Couch sin auth, FTP anonimo escribible, RDP sin NLA, proxy abierto, metodos HTTP riesgosos, NTLM info, clave TLS comprometida, Docker API).
- Nmap: perfil `udp_services` (DNS recursivo, SNMP `public`, IPMI, NTP, IKE, NetBIOS, UPnP); estado `unavailable` explicito si faltan privilegios de captura.
- Nmap: `vulners` solo en su perfil dedicado `--version-all` (evita CVE duplicados con dos titulos).
- SSH: Terrapin CVE-2023-48795 por algoritmos negociados y ausencia de strict kex; SSHv1; correlacion de version OpenSSH (CVE-2024-6387 con builds corregidos Ubuntu/Debian, CVE-2025-26466, CVE-2018-15473) con confianza reducida si hay sufijo de proveedor.
- Nuclei: perfil `network_services_scan` (plantillas network/javascript/ssl contra cada `host:puerto` abierto de Nmap, tambien en hosts sin HTTP) y `dast_scan` (`-dast` sobre URLs con parametros, una por ruta y conjunto de parametros).
- Nuclei: `javascript/cves` en `cve_scan`; `severity`, `retries` y `request_timeout_seconds` de config.yaml ahora se aplican; exclusion de `brute` cuando `allow_bruteforce=false`; actualizacion de plantillas si superan `templates_max_age_days`.
- Pruebas: `tests/test_engine_power.py` y validacion real en loopback `tools/validate_engine_power.py`.
- Telemetria: el heartbeat de un submodulo (p. ej. `xss_reflected`) se atribuye al modulo padre activo de su objetivo; antes creaba filas fantasma y desplazaba el modulo y su progreso en el monitor.
- FFUF: se registran `ffuf_raw_results` y `ffuf_results_truncated` cuando los resultados superan `MAX_FFUF_RECON_HITS`; antes el recorte era silencioso.
- Suite de pruebas en verde (236): tests alineados con contratos vigentes (SSRF diferencial con control, CVSS localizado, topes de recon de 10000, perfiles multiples de Nmap/Nuclei con listas `-l`, `ScanLimits` real); la comprobacion del exportador privado se omite de forma explicita solo en el workspace privado.

## Unreleased — DAST precision and analyst triage

- Independent baseline replay for internal and external XSS, SQLi and traversal alerts; retain inconclusive results outside confirmed findings.
- Replace generic ODBC/database keyword evidence with repeatable explicit SQL error signatures; paired boolean and time controls.
- Bounded same-origin JavaScript/source-map reconnaissance with redacted credential candidates in Daily.
- Endpoint-scoped discard/restore decisions persisted by the local Daily viewer, import/export and browser fallback.
- Preserve historical unvalidated alerts for revalidation instead of labelling every alert validated.

# Changelog de Scan Titan

Este archivo registra los cambios funcionales verificables de cada version.

Las versiones `21.3.2` y `21.3.3` documentan iteraciones locales verificadas que se consolidaron en `22.0.0`; no se publicaron como tags independientes.

## [22.5.0] - 2026-11-05

- Daily: grafica inicial de hallazgos vigentes, con selector independiente de observaciones diarias.
- Catalogo local con rangos de RetireJS, avisos oficiales de PHP y Apache, y ciclos de soporte de endoflife.date.
- Auditoria de componentes con version exacta en headers, JS, WhatWeb/Wappy y Nmap; hallazgos separados del recon.
- Actualizacion semanal acotada, cache offline, hashes y referencias; distincion entre EOL, correlacion de version y validacion funcional.

## [22.4.1] - 2026-10-23

- Resultados de rutas compartidos por objetivo; FFUF prueba entradas aun pendientes y registra ahorro de peticiones.
- Dos objetivos HTTP simultaneos con 20 solicitudes globales y herramientas externas serializadas.
- Nuclei sin limite total por defecto, con corte por ausencia de progreso y parser de estadisticas fragmentadas.
- Perfiles Nuclei de vulnerabilidades/CVE antes del conservador; menos URLs semilla en modo normal.
- Nmap evita repetir `http-slowloris-check` cuando el perfil base lo cubrio correctamente.
- Telemetria por objetivo y correccion de parametros descubiertos en auditoria de roles.

## [22.4.0] - 2026-10-23

- Wrappers asincronos y acotados para Katana y httpx de ProjectDiscovery.
- Rutas y tecnologias de recon filtradas al origen exacto y disponibles antes de las pruebas web.
- Deteccion del conflicto con el comando `httpx` del paquete Python en Windows.
- Salida y cobertura de cada herramienta en la observabilidad existente, sin promover recon a vulnerabilidades.
- Guia de validacion manual basica con sqlmap y XSSer, sin automatizar pruebas intrusivas.

## Actualizaciones del monitor - 2026-10-16

- Monitor modernizado con CustomTkinter, iconos vectoriales, tarjetas y distribucion adaptable con desplazamiento.
- Graficas en tiempo real de actividad HTTP interna y CPU/RAM del arbol de Scan Titan; distribucion de severidades.
- Historial acotado por ejecucion, deduplicacion de muestras y reinicio del calculo de ritmo al cambiar de contexto; indicadores de telemetria antigua y reportes anteriores.
- Tablas con seleccion y desplazamiento persistentes, detalle por fila y navegacion lateral adaptativa.
- Deteccion de carpeta compatible con paquetes actuales y copias antiguas con archivos en la raiz.

## [22.3.0] - 2026-10-02

- FTP/SMB: evidencia de acceso anonimo a directorios/recursos, servidor/SO y autenticacion.
- SMB NSE: MS17-010, protocolos y firma; alternativa nativa SMB1 sin Impacket.
- IDOR por propietario; RCE con dos pruebas aritmeticas y SSRF con respuesta controlada.
- Correccion de parametros duplicados y falsos positivos de autenticacion por HTTP 200.
- Pipeline para objetivos sin HTTP; cobertura parcial explicita y procesos acotados.
- Configuracion y limites documentados en docs/SERVICE_ACCESS.md.

## [22.2.0] - 2026-09-29

- SessionManager con identidades aisladas, login multipaso/CSRF, extraccion de tokens, renovacion y comprobacion de identidad/MFA.
- Nuevos auditores de roles/IDOR, XSS almacenado validado en Chromium, rafagas concurrentes de 20–64 operaciones, WebSockets y revocacion tras logout.
- SSH NSE: metodos de autenticacion, algoritmos ofrecidos y claves; contrasta configuracion efectiva sin basarse solo en banners.
- Nuclei: perfiles acotados, menos repeticion de semillas, vigilancia de progreso, parser de estadisticas/JSONL parcial y logs completos.
- ZAP: contexto propio, paginacion/checkpoints, recuperacion de alertas ante fallos, tiempos por etapa y daemon con estado/log separado.
- Cobertura en reportes TXT/JSON y evidencia separada; un scan incompleto conserva el estado de hallazgos historicos no observados.
- Documentacion de los 55 puntos, configuracion de ejemplo y pruebas locales positivas/negativas con motores externos reales.

## [22.1.1] - 2026-09-21

- El cargador cuenta solo entradas reales y unicas, aplica el limite despues de deduplicar y deja de generar relleno hasta 10 000.
- XSS utiliza una sola wordlist canonica (`wordlists/xss.txt`); se retira `xss_payloads.txt` porque sus 297 entradas ya estaban incluidas en ella.
- El arranque oculta por defecto los conteos de wordlists y la configuracion de red, politica y ZAP; `--verbose-startup` permite consultarlos.
- Se agregan pruebas de regresion para conteo exacto, limite tras deduplicacion, XSS unico y modo de arranque optativo.

## [22.1.0] - 2026-09-18

### Estabilidad y observabilidad

- Las pruebas inteligentes usan pools concurrentes acotados y timeouts estrictos por prueba y por modulo; un timeout se registra y no bloquea la ejecucion global.
- Se elimina el modulo de site map y se sustituye por un filtro concurrente que entrega rutas crudas del mismo origen con estado HTTP 200 o 403.
- La telemetria agrega CPU, RAM, E/S y numero de procesos del proceso principal y todos sus hijos mediante `psutil`, tanto en CLI como en el monitor grafico.

### Evidencia y publicacion

- Los artefactos crudos de Nmap, Nuclei, OWASP ZAP y wafw00f se centralizan en el directorio externo configurado.
- La presentacion publica incorpora un emblema original, flujo interactivo para charlas tecnicas y ejemplos alineados con el filtro de rutas 200/403.

### Validacion

- Se agregan regresiones para aislamiento de timeouts, cancelacion limpia, filtro de rutas, arbol de procesos, enrutamiento de salidas externas y contrato de la web publica.

## [22.0.1] - 2026-09-09

### Cobertura de herramientas externas

- Nuclei aplica resolucion de sistema, deshabilita el abandono temprano por errores del host y sigue redirecciones del mismo origen en todos sus perfiles.
- Los endpoints reales reunidos por reconocimiento y FFUF se normalizan, deduplican, limitan y entregan a Nuclei mediante una lista reproducible.
- El perfil rapido incorpora severidad informativa y plantillas de headers, misconfiguraciones, exposiciones y tecnologia; los tres perfiles conservan evidencia JSONL.
- La observabilidad distingue cero coincidencias, abandono del host, ausencia de plantillas, errores de salida y errores de parser.
- Nmap fusiona rangos para eliminar puertos duplicados y el perfil Vulners usa deteccion exhaustiva de versiones para mejorar la obtencion de producto, version y CPE.
- FFUF mide varias rutas inexistentes y combina tamano, palabras, lineas y destino de redireccion para suprimir respuestas soft-404/catch-all.
- Subfinder deriva el dominio registrable del objetivo y SSRF documenta explicitamente cuando no existen parametros candidatos.

### Validacion

- Se agregan regresiones para perfiles y JSONL de Nuclei, clasificacion de errores, semillas del mismo origen, puertos Nmap, dominio base, soft-404 de FFUF y omision observable de SSRF.

## [22.0.0] - 2026-09-09

### Identidad y comunidad

- La documentacion deja de depender de una campaña o actividad puntual y presenta Scan Titan como proyecto comunitario global.
- Se incorpora la extension complementaria Scan Titan para Google Chrome al README, manual y presentacion publica.
- Se formaliza este changelog con la trazabilidad de las iteraciones previas.

### Motor

- Se consolidan los presupuestos adaptativos de LFI y XSS, el descarte previo por reflexion y el cortacircuito ante bloqueos WAF equivalentes.
- La telemetria y la matriz de reconocimiento conservan la razon de cada corte adaptativo.

### Versionado

- Motor, paquete, dashboard, fallback, banner y documentacion avanzan juntos a `22.0.0`.
- Se agrega una fuente de version legible por herramientas y una prueba automatizada de consistencia.

### Justificacion del salto mayor

- `22.0.0` conserva la continuidad desde `21.3.3` y representa un cambio conjunto de posicionamiento, ecosistema y politica de ejecucion; usar v2 o v3 seria una regresion numerica.

## [21.3.3] - 2026-09-08

### Motor adaptativo WAF

- Nuevo cortacircuito compartido para LFI y XSS basado en codigo HTTP, tamano, tipo de contenido, huella normalizada, cabeceras y marcadores de bloqueo.
- Seis respuestas WAF equivalentes detienen el modulo antes de consumir el resto del presupuesto.
- Ocho respuestas negativas equivalentes detienen solamente el endpoint/parametro afectado; los demas candidatos conservan cobertura.
- Las firmas eliminan payloads reflejados e identificadores dinamicos antes de comparar el cuerpo, evitando que un Ray ID o Incident ID diferente oculte una pagina de bloqueo repetida.
- La concurrencia de LFI/XSS se limita a ocho trabajadores para reducir solicitudes que ya estaban en vuelo al activarse el cortacircuito.
- Los umbrales son configurables mediante `adaptive_waf_block_threshold` y `adaptive_plateau_threshold`.
- La razon del corte se conserva en telemetria, contexto de reconocimiento y la nueva columna `Cortes Adaptativos`.

### Validacion

- Regresiones para WAF repetido en XSS y LFI, pagina estable equivalente al control, proveedor WAF y limites de solicitudes en vuelo.

## [21.3.2] - 2026-09-08

### Rendimiento

- LFI deja de completar 10,000 combinaciones ciegas en el perfil zero-touch. Prioriza parametros observados relacionados con archivos y rutas; si no existen, usa una muestra de alta senal.
- XSS incorpora dos etapas: marcador inocuo de reflexion y escalamiento de payloads solo sobre entradas reflejadas.
- El presupuesto zero-touch queda limitado a 1,200 pruebas para LFI, 1,200 para XSS y 240 para `client_side`.
- LFI y XSS tienen un limite de 45 minutos por modulo; `client_side`, 20 minutos. El modo `--full` conserva sus limites exhaustivos y sin timeout duro.
- `client_side` reutiliza el resultado del modulo XSS y evita repetir una segunda corrida reflejada de hasta 10,000 payloads.
- Los casos de prueba se distribuyen round-robin entre parametros para impedir que el primer parametro consuma todo el presupuesto.

### Calidad y observabilidad

- LFI registra modo, entradas, pruebas planeadas, pruebas terminadas y hallazgos en el contexto de reconocimiento.
- XSS registra entradas evaluadas, entradas reflejadas, payloads enviados, pruebas terminadas y hallazgos.
- Se agregaron regresiones para descarte XSS sin reflexion, escalamiento XSS reflejado, fallback LFI de alta senal y presupuestos zero-touch/deep.

### Compatibilidad

- Se mantienen los esquemas de runtime y reportes existentes.
- Las ejecuciones ya iniciadas conservan el codigo cargado en memoria; deben finalizarse y reiniciarse para usar esta version.

## [21.3.1] - 2026-09-07

### Observabilidad

- Los modulos asincronos usan un grupo fijo de hasta 20 trabajadores en lugar de crear una tarea por payload.
- La telemetria informa solicitudes terminadas, activas, en espera y tiempo desde la ultima respuesta.
- El monitor marca como desactualizado un estado `running` sin actividad reciente y resuelve correctamente la carpeta de runtime de cada copia.
- La finalizacion ordenada interrumpe colas y pausas pendientes antes de generar los reportes disponibles.

[22.1.1]: https://github.com/RogerF5-Security/Scan-Titan/releases/tag/v22.1.1
[22.1.0]: https://github.com/RogerF5-Security/Scan-Titan/releases/tag/v22.1.0
[22.0.1]: https://github.com/RogerF5-Security/Scan-Titan/releases/tag/v22.0.1
[22.0.0]: https://github.com/RogerF5-Security/Scan-Titan/releases/tag/v22.0.0
