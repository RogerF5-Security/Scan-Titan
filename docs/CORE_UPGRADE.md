# Scan Titan 22.2.0 — sesiones, estado y motores externos

## Resultado

El pipeline incorpora `SessionManager`, `RoleAuditor`, `StoredXSS_Auditor`,
`RaceCondition_Tester`, `WebSocket_Analyzer`, `SessionLifecycleAuditor` y
`NmapSSHAuditor`. Los resultados se integran como `Finding` y pasan por los
filtros, correlación, evidencia y reportes existentes.

La cobertura de la metodología se documenta en [METODOLOGIA_55.md](METODOLOGIA_55.md).
El inventario de emisores de hallazgos está en [FINDING_CATALOG.csv](FINDING_CATALOG.csv).
No equivale a una lista cerrada de CVEs: las plantillas instaladas de Nuclei y
las reglas de ZAP/Nmap amplían el catálogo y cambian con sus versiones.

## Configuración y ejecución

1. Fusionar las secciones necesarias de `config/stateful.example.yaml` en
   `config/config.local.yaml`. El archivo local sobreescribe el general; las
   listas de perfiles/casos se reemplazan completas.
2. Establecer las variables de entorno referenciadas por `${VARIABLE}`.
3. Configurar `origins`, login, extracción de token y una comprobación de identidad
   (`check`). Un HTTP 200 de login no prueba autenticación.
4. Definir recursos y propietarios esperados, operaciones de negocio de prueba
   y mensajes privados de WebSocket según la aplicación.
5. Ejecutar el lanzador habitual `python main.py` con los targets configurados.

El archivo de ejemplo contiene dominios reservados, sin credenciales reales.
`auth_profiles: []` conserva el reconocimiento anónimo. No habilita pruebas
autenticadas hasta que existan perfiles válidos. Un desafío MFA se registra
como `mfa_required`; no se considera autenticación ni se omite el segundo factor.
Los pasos de login pueden representar un flujo MFA ya configurado; no se implementó
un motor universal de TOTP, WebAuthn, recuperación ni aprobación push.

## Arquitectura y criterio de evidencia

| Componente | Ejecución | Criterio para reportar |
|---|---|---|
| SessionManager | Un cliente y cookies por identidad; Unauth no almacena cookies. Login JSON/formulario, CSRF, JWT/header/cookies, multipaso, renovación por TTL o 401. | Identidad comprobada por contenido/JSON. Los secretos de perfil no se escriben en el resumen. |
| Roles/IDOR | Repite URL, método, parámetros y cuerpo entre identidades; almacena código, tamaño, hash y similitud. | Perfil no permitido obtiene contenido protegido del control válido. Requiere propietario/rol esperado y campos o marcadores sensibles. |
| Stored XSS | Descubre formularios POST, conserva campos ocultos, introduce un UUID con payload SVG y vuelve a visitar rutas. | Dos GET independientes conservan el canario y Chromium observa el diálogo exacto. Un reflejo POST o contenido escapado no confirma XSS. |
| Race conditions | Barrera asyncio; 20–64 solicitudes concurrentes, sin el jitter del motor general ni reintento de escrituras. | IDs de operaciones distintos por encima del máximo o incremento de estado que viola el límite configurado. |
| WebSockets | Descubre ws/wss y compara handshakes con cookies/token y sin credenciales; permite mensaje de prueba. | Conexión anónima entrega el marcador privado esperado, con un control autenticado que conecta. Un 101 público no constituye fallo. |
| Ciclo de sesión | Tras las pruebas autenticadas, ejecuta el logout configurado y reproduce credenciales previas. | Tras un logout exitoso la credencial anterior todavía satisface la comprobación de identidad. La revocación no observable se marca inconclusa. |
| SSH | Nmap NSE enumera algoritmos, claves y métodos por puerto SSH, incluidos los descubiertos fuera del 22. | Algoritmos heredados/débiles o claves RSA cortas/DSA. Soportar password no es por sí mismo vulnerabilidad. |

Las peticiones de identidad están limitadas al origen configurado. Los redirects
no se siguen; para SSO entre varios orígenes se necesita un adaptador explícito.
ZAP/Nuclei mantienen su propia ejecución; los perfiles de SessionManager se usan
en los nuevos módulos y no se transfieren automáticamente a esos motores externos.
Los GET/HEAD pueden repetirse una vez después de renovar; las operaciones de
negocio nunca se repiten automáticamente por un 401. Las sesiones fallidas no
provocan reintentos de login en cada petición.

La ventana `dispatch_window_ms` es la medición local del inicio de cada solicitud,
no una garantía de llegada simultánea al servidor. Una violación bajo concurrencia
no identifica por sí sola la línea de código vulnerable: debe contrastarse con
transacciones, idempotencia y controles secuenciales específicos de la aplicación.
Los formularios pueden conservar datos canario; su limpieza depende del entorno
de prueba. Las operaciones de negocio necesitan fixtures consumibles y límites
de éxito conocidos; no se inventan transferencias, cupones ni propietarios.

## Correcciones de Nuclei y ZAP

- **Nuclei:** primero el perfil conservador; hasta 12 semillas descubiertas y
  perfiles amplios sobre una URL base, evitando multiplicar miles de plantillas
  por todas las rutas. Se separan etiquetas solapadas y se desactivan comprobaciones
  de actualización durante el análisis (`-duc`). Presupuestos 300/600/600 s;
  vigilancia de progreso 180 s. Los timeouts conservan JSONL parcial.
- **Parser:** estadísticas JSON y `matcher-status=false` no crean vulnerabilidades.
  Se distinguen fallo de plantillas, conexión, parser, timeout y cero hallazgos.
- **Subprocesos:** stdout/stderr completos en archivos; en memoria se conservan
  principio y final. Se termina el árbol de procesos al cancelar o agotar tiempo.
- **ZAP:** contexto de origen propio, ID de scan obligatorio, ejecución serializada,
  progreso por etapa y detención del scan propio ante bloqueo. Spider 180 s,
  activo 900 s y pasivo 120 s por espera; startup 90 s. Estos son presupuestos por
  fase, no una promesa de duración total exacta.
- **Evidencia ZAP:** alertas paginadas, checkpoints durante el scan y recuperación
  de alertas al fallar una etapa. El límite de alertas se informa como parcial.
  El daemon usa directorio separado, `-silent` y log de arranque conservado.
  Se comprueban las reglas pasivas base 10010/10020/10021: complementos ausentes,
  desactivados o incompletos impiden declarar cobertura completa.
- **Timeout cero:** configuración 0 utiliza el valor finito de respaldo. No significa
  un segundo ni ejecución ilimitada. Los overrides de módulo no positivos se ignoran.
- **Reporte:** `coverage_*.json` y la sección `coverage` del JSON del objetivo
  incluyen perfiles, pruebas de estado, etapas externas y conteos antes/después
  de filtros. Con errores/timeout no se marca `NOT_SEEN` un hallazgo histórico
  ausente. Info puede estar en evidencia y omitirse del reporte por `min_severity`.

Reducir semillas y presupuestos reduce repetición, pero puede dejar plantillas
sin ejecutar. La cobertura parcial queda explícita. No se afirma un porcentaje
de mejora de rendimiento sin comparar el mismo sitio y versiones de plantillas.

## Verificación reproducible

```powershell
python -m unittest discover -s tests -v
python main.py --help
python main.py --health-check
python main.py --monitor --self-test
python tools/validate_core_engines.py
```

La suite usa un servidor aiohttp local con casos vulnerables y controles negativos:
aislamiento de cookies/token, CSRF, renovación, MFA, autorización, persistencia,
ejecución Chromium, 20 operaciones concurrentes, WebSockets y logout. SSH usa XML
representativo. Las pruebas externas cubren paginación, error de etapa, falta de
ID, bloqueo de progreso, JSONL truncado y terminación de un proceso real.

Validación local del 29-09-2026: 74 pruebas automatizadas, Nuclei con un hallazgo
de fixture y ZAP con 61 reglas pasivas, 22 alertas y 9 hallazgos consolidados.
La prueba de ZAP usó presupuestos reducidos: el activo se detuvo al 37% por
vigilancia de progreso y las alertas se conservaron con estado `partial`.
Antes de repetir desde un directorio limpio se detectaron complementos incompletos
en el runtime de prueba tras interrumpir una actualización. Esa evidencia se
conservó separada; no demuestra que la instalación histórica del usuario tenga
el mismo daño. El arranque final con `-silent` evitó esa actualización durante el scan.

`validate_core_engines.py` utiliza Nuclei y ZAP instalados contra su propio servidor
127.0.0.1 con tiempos cortos; deja evidencia en `version_backups/core_upgrade_20260929/engine_smoke`.
No realiza una auditoría de los targets corporativos del archivo de configuración.

## Referencias de integración

- [ZAP API](https://www.zaproxy.org/docs/api/)
- [ZAP opciones CLI y -silent](https://www.zaproxy.org/docs/desktop/cmdline/)
- [Nmap ssh-auth-methods](https://nmap.org/nsedoc/scripts/ssh-auth-methods.html)
- [Nmap ssh2-enum-algos](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html)
- [Nmap ssh-hostkey](https://nmap.org/nsedoc/scripts/ssh-hostkey.html)
