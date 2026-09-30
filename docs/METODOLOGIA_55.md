# Cobertura frente a Metodologia.xlsx — 22.2.0

Fuente: hoja `Metodologia`, A2:A56, 55 actividades. La columna «Ejecutado» del
Excel describe la auditoría del documento; no demuestra capacidad de Scan Titan.
El original se leyó sin modificarlo. Esta matriz evalúa el código y sus límites;
no certifica una auditoría de una aplicación real.

**Automatizada:** existe prueba concreta del aspecto descrito. **Parcial:** existen
pruebas o indicios, pero faltan casos o validación integral. **Configurable:** el
motor existe y necesita identidades, datos o reglas del negocio. **No cubierta:**
no existe una comprobación suficiente del punto completo.

| # | Actividad del Excel | Cobertura | Implementación / límite |
|---|---|---|---|
| 1 | Tecnologías web vulnerables | Parcial | WhatWeb, recon, Nuclei; banner y correlación CVE no prueban explotabilidad. |
| 2 | Subdominios que no deben ser públicos | Parcial | Subfinder descubre; la intención de exposición requiere inventario del propietario. |
| 3 | Endpoints y rutas | Automatizada | Recon, JS/OpenAPI, rutas, ZAP spider. Sujeta a alcance y acceso. |
| 4 | Fuzzing de rutas/directorios | Automatizada | Paths/FFUF, filtros soft-404 y wordlists. |
| 5 | Certificados SSL/TLS | Automatizada | crypto_tls y NSE; validación, nombres y vigencia. |
| 6 | Puertos expuestos | Automatizada | Nmap, puertos configurados y servicios. |
| 7 | Mapeo funcional | Parcial | Crawl y formularios; no infiere toda la lógica del negocio. |
| 8 | Rutas sin autenticación | Automatizada | unauthenticated_map; exposición intencional requiere política. |
| 9 | Tokens en frontend | Parcial | client_side y patrones; no toda cadena encontrada es un secreto utilizable. |
| 10 | Políticas CORS | Automatizada | cors, client_side, origen y credenciales. |
| 11 | Headers de seguridad | Automatizada | headers, crypto_tls, reglas externas. |
| 12 | XSS reflejado | Parcial | xss/client_side y navegador; contextos/payloads acotados. |
| 13 | XSS almacenado | Configurable | stored_xss: POST, dos recargas, ejecución Chromium; formas accesibles y flujos compatibles. |
| 14 | DOM-XSS | Parcial | Indicadores de sinks y browser_audit; no rastreo universal origen→sink. |
| 15 | Sanitización del cliente | Parcial | Canarios y probes; no inspección completa de todas las funciones JS. |
| 16 | Autenticación | Configurable | SessionManager, auth_session; login/cookies/JWT con comprobación de identidad. |
| 17 | Bypass lógico de login | Parcial | Probes y controles; flujos especiales necesitan adaptación. |
| 18 | Recuperación de contraseña | Parcial | auth_session detecta superficies; no completa email/token/reuso/cambio entre cuentas. |
| 19 | Cookies y flags | Automatizada | auth_session/client_side sobre cookies observadas. |
| 20 | JWT | Parcial | Decodificación, claims y probes existentes; validación universal de firma/JWKS no cubierta. |
| 21 | MFA | Parcial | Descubrimiento y desafío configurado; bypass, factores alternos, enrolamiento y recuperación no automatizados integralmente. |
| 22 | Sesiones | Configurable | Aislamiento, renovación, identidad y reproducción tras logout configurado. |
| 23 | Roles/IDOR | Configurable | role_audit compara identidades; requiere propietarios/roles y marcadores de contenido protegido. |
| 24 | Manipulación de parámetros | Parcial | authorization, injection, api_dast; significado de negocio no inferido. |
| 25 | Fuerza bruta controlada | Configurable | auth_session; deshabilitada por defecto, necesita política/datos. |
| 26 | SQL Injection | Parcial | sqli: errores, diferenciales y tiempo; no cubre todos los DBMS/canales/segundo orden. |
| 27 | LDAP Injection | Parcial | injection y señales de respuesta; no todas las consultas LDAP. |
| 28 | Command Injection | Parcial | injection y verificaciones acotadas; sin garantía universal de ejecución/OOB. |
| 29 | Path Traversal | Automatizada | lfi y rutas/lecturas reconocibles. |
| 30 | File Upload | Parcial | api_dast y pruebas de subida; ejecución, conversión y pipelines específicos requieren adaptación. |
| 31 | Rate limit / anti-automation | Parcial | Ráfagas acotadas y respuestas; no confirma bloqueo silencioso ni controles distribuidos. |
| 32 | Configuración del servidor | Parcial | infra_network, Nmap/Nuclei/ZAP; no revisión completa del host autenticado. |
| 33 | Archivos .git/.env expuestos | Automatizada | paths/unauthenticated_map, comprobación de contenido. |
| 34 | Versiones vulnerables | Parcial | Correlación y plantillas; backports y explotación necesitan evidencia adicional. |
| 35 | WebSockets | Configurable | Handshake anónimo/autenticado y mensaje privado; no toda lógica por mensaje. |
| 36 | Race conditions | Configurable | race_conditions, 20–64 peticiones y oráculo explícito de estado/IDs. |
| 37 | Revisión de logs | No cubierta | advanced_logic detecta logs expuestos por HTTP; no audita logs internos del servidor/SIEM. |
| 38 | Secure/HttpOnly/SameSite | Automatizada | Revisión de cookies recibidas; puede depender de la ruta autenticada. |
| 39 | Expiración/regeneración de cookies | Parcial | Renovación de sesión y logout; no medición exhaustiva de TTL, idle timeout y fijación pre/post-login. |
| 40 | Fuga de cookies vía JS | Parcial | HttpOnly y patrones de acceso; no prueba universal de extracción/exfiltración. |
| 41 | CSP/HSTS/X-Frame/X-Content-Type | Automatizada | headers y crypto_tls; contexto funcional importa. |
| 42 | Política CSP | Parcial | Directivas débiles/ausentes; no análisis completo de todos los recursos permitidos. |
| 43 | Bypass de CSP | Parcial | Probes XSS/browser; gadgets y confianza transitiva no cubiertos integralmente. |
| 44 | HSTS | Automatizada | Presencia y políticas observadas; no simula todos los navegadores. |
| 45 | HTTP→HTTPS | Automatizada | crypto_tls evalúa redirección. |
| 46 | Downgrade SSL/TLS | Parcial | Versiones/cifrados aceptados; no implementación universal de ataques de downgrade. |
| 47 | Protocolos/cifrados inseguros | Automatizada | crypto_tls y Nmap ssl-enum-ciphers. |
| 48 | Vigencia/cadena/CN certificado | Automatizada | crypto_tls y NSE. |
| 49 | Clickjacking | Parcial | Headers/frame policy y señales; flujos UI sensibles requieren validación visual. |
| 50 | Evasión WAF | Parcial | waf_resilience y payloads alternativos; no garantiza bypass. |
| 51 | Bloqueo de IP | Parcial | Respuestas/bloqueos observados; no demuestra bloqueo persistente ni reglas internas. |
| 52 | Bypass de rate limit | Parcial | Probes de cabeceras; no rotación de IP distribuida ni agotamiento real de cuotas. |
| 53 | CORS | Automatizada | Repite el punto 10 del Excel. |
| 54 | Cache-Control de datos sensibles | Parcial | headers; caché autenticada entre cuentas/CDN requiere pruebas específicas. |
| 55 | Expect-CT | Parcial | Se registra ausencia informativa; no equivale a demostrar incumplimiento de transparencia. |

## SSH y brechas comunes adicionales

SSH no aparece como actividad independiente en el Excel. Ahora se ejecutan
`ssh-auth-methods`, `ssh2-enum-algos` y `ssh-hostkey`: KEX SHA-1 heredados,
ssh-dss/ssh-rsa como algoritmos ofrecidos, CBC/3DES/RC4, MAC heredados y claves
cortas. Un servidor que ofrece esos algoritmos puede mantener clientes modernos;
el hallazgo documenta la opción débil ofrecida. Password/publickey se inventarían.
La enumeración de métodos depende del usuario de prueba. No se implementaron
fuerza bruta SSH, login remoto ni explotación de CVEs específicas de OpenSSH.

Siguen sin cobertura integral: SSRF ciego con callbacks verificables, XSS ciego
fuera de rutas rastreables, SQLi de segundo orden, OAuth/OIDC/SAML multiproveedor,
enrolamiento/recuperación MFA, lógica financiera o de descuentos desconocida,
cache poisoning/deception entre usuarios, request smuggling con validación de
desincronización, deserialización específica del framework y revisión interna
de permisos de sistema/AD/Kubernetes/cloud. Puede haber plantillas externas o
probes parciales para algunas familias; su presencia no confirma cobertura total.

El upgrade mejora los puntos 13, 16, 22, 23, 35, 36 y la inspección SSH. **No permite
declarar los 55 puntos auditados de extremo a extremo sin configuración y revisión
específica de la aplicación.**
