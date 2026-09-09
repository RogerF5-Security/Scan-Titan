from __future__ import annotations

import asyncio
import hashlib
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, TypeVar

import aiohttp

from quality_rules import finding_quality_exclusion


SEVERITY_ORDER = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Info": 5,
}


def normalize_severity(value: str) -> str:
    mapping = {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "media": "Medium",
        "medio": "Medium",
        "low": "Low",
        "baja": "Low",
        "bajo": "Low",
        "info": "Info",
        "informational": "Info",
        "informativo": "Info",
        "critica": "Critical",
        "crítica": "Critical",
        "alto": "High",
        "alta": "High",
    }
    return mapping.get(str(value or "Info").strip().lower(), "Info")


def clean_text(value: Any, limit: int = 900) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


TEXT_TRANSLATIONS_ES = {
    "(Critical)": "(Critica)",
    "(High)": "(Alta)",
    "(Medium)": "(Media)",
    "(Low)": "(Baja)",
    "(Info)": "(Info)",
    "Vulnerability": "Vulnerabilidad",
    "VULNERABLE: Slowloris DOS attack": "VULNERABLE: ataque DoS Slowloris",
    "State: LIKELY VULNERABLE": "Estado: PROBABLEMENTE VULNERABLE",
    "Self Signed SSL Certificate": "Certificado SSL autofirmado",
    "Potential CVEs inferred from service version": "CVEs potenciales inferidos por la version del servicio",
    "CSP contains bypass/evasion primitives": "CSP contiene primitivas debiles o permisivas",
    "CSP bypass/evasion primitives present": "CSP contiene primitivas debiles o permisivas",
    "CSP missing hardening directives": "CSP sin directivas de endurecimiento",
    "CSP object-src is not locked down": "CSP object-src no esta restringido",
    "CSP missing": "CSP ausente",
    "HSTS missing": "HSTS ausente",
    "HSTS max-age is weak": "HSTS con max-age debil",
    "HSTS does not include subdomains": "HSTS no incluye subdominios",
    "X-Frame-Options missing": "X-Frame-Options ausente",
    "X-Content-Type-Options missing": "X-Content-Type-Options ausente",
    "Referrer-Policy missing": "Referrer-Policy ausente",
    "Permissions-Policy missing": "Permissions-Policy ausente",
    "Clickjacking protection missing": "Proteccion contra clickjacking ausente",
    "Cache-Control not restrictive": "Cache-Control no restrictivo",
    "Cache-Control may allow sensitive response caching": "Cache-Control podria permitir cache de respuestas sensibles",
    "Information disclosure header": "Cabecera de divulgacion de informacion",
    "Initial HTTP request failed": "Fallo en la peticion HTTP inicial",
    "The target did not answer the initial HTTP probe.": "El objetivo no respondio la prueba HTTP inicial.",
    "HTTPS is not explicitly enforced by HSTS.": "HTTPS no se fuerza explicitamente mediante HSTS.",
    "Strict-Transport-Security header not observed.": "No se observo la cabecera Strict-Transport-Security.",
    "XSS mitigation is weakened by a missing CSP.": "La mitigacion contra XSS queda debilitada por ausencia de CSP.",
    "Content-Security-Policy not observed.": "No se observo la cabecera Content-Security-Policy.",
    "Clickjacking protection is not declared.": "No se declara proteccion contra clickjacking.",
    "Browser MIME sniffing is not explicitly disabled.": "El sniffing MIME del navegador no esta deshabilitado explicitamente.",
    "Sensitive URLs may leak through the Referer header.": "URLs sensibles podrian filtrarse mediante la cabecera Referer.",
    "Browser feature access is not explicitly constrained.": "El acceso a capacidades del navegador no esta limitado explicitamente.",
    "No X-Frame-Options or CSP frame-ancestors.": "No se observo X-Frame-Options ni CSP frame-ancestors.",
    "nosniff not observed.": "No se observo nosniff.",
    "Weak transport security can enable downgrade attacks or reduce confidentiality guarantees.": "Una seguridad de transporte debil puede permitir ataques de downgrade o reducir las garantias de confidencialidad.",
    "Allow only TLS 1.2/1.3, prioritize AEAD/ECDHE suites and remove NULL, anonymous, export, RC4, DES/3DES and CBC legacy ciphers.": "Permitir unicamente TLS 1.2/1.3, priorizar suites AEAD/ECDHE y retirar cifrados NULL, anonimos, export, RC4, DES/3DES y CBC heredados.",
    "Users may remain exposed to downgrade or stripping attacks on first or repeated visits.": "Los usuarios pueden quedar expuestos a ataques de downgrade o stripping en visitas iniciales o recurrentes.",
    "Set Strict-Transport-Security with an appropriate max-age and includeSubDomains after confirming HTTPS coverage.": "Configurar Strict-Transport-Security con max-age adecuado e includeSubDomains despues de confirmar cobertura HTTPS completa.",
    "Successful exploitation can execute JavaScript in a victim session, steal tokens available to JavaScript or manipulate user actions.": "Una explotacion exitosa puede ejecutar JavaScript en la sesion de la victima, robar tokens accesibles a JavaScript o manipular acciones del usuario.",
    "Apply context-aware output encoding, sanitize HTML with a proven allowlist sanitizer, enforce CSP and avoid unsafe DOM sinks.": "Aplicar codificacion de salida contextual, sanear HTML con un sanitizador por lista permitida, reforzar CSP y evitar sinks DOM inseguros.",
    "User-controlled content is rendered in the browser without context-aware output encoding or sanitization.": "Contenido controlado por el usuario se renderiza en el navegador sin codificacion contextual ni sanitizacion adecuada.",
    "User-controlled input reaches a SQL query without robust parameterization or query isolation.": "Entrada controlada por el usuario alcanza consultas SQL sin parametrizacion robusta ni aislamiento de consultas.",
    "An attacker can alter database queries, bypass logic, read sensitive records or modify application data depending on privileges.": "Un atacante puede alterar consultas, evadir logica, leer registros sensibles o modificar datos segun los privilegios disponibles.",
    "Use parameterized queries, typed ORM bindings, strict input normalization and least-privilege database accounts.": "Usar consultas parametrizadas, bindings ORM tipados, normalizacion estricta de entrada y cuentas de base de datos con minimo privilegio.",
    "Impact can include internal service discovery, cloud metadata exposure, credential retrieval or pivoting to restricted networks.": "El impacto puede incluir descubrimiento de servicios internos, exposicion de metadatos cloud, recuperacion de credenciales o pivote hacia redes restringidas.",
    "Use strict outbound allowlists, block private/link-local ranges, disable redirects to disallowed hosts and isolate request brokers.": "Usar allowlists estrictas de salida, bloquear rangos privados/link-local, deshabilitar redirecciones a hosts no permitidos y aislar brokers de peticiones.",
    "Attackers may read application secrets, source code, configuration files or operating system artifacts.": "Un atacante podria leer secretos de aplicacion, codigo fuente, archivos de configuracion o artefactos del sistema operativo.",
    "Normalize paths, enforce fixed base directories, reject traversal tokens and use opaque file identifiers instead of raw paths.": "Normalizar rutas, forzar directorios base fijos, rechazar tokens de traversal y usar identificadores opacos en lugar de rutas crudas.",
    "Depending on the template engine and sandbox, exploitation can lead to remote code execution or sensitive data exposure.": "Segun el motor de plantillas y su sandbox, la explotacion puede derivar en ejecucion remota de codigo o exposicion de datos sensibles.",
    "Never render user input as templates, disable dangerous template features and isolate rendering in a hardened sandbox.": "No renderizar entradas de usuario como plantillas, deshabilitar funciones peligrosas y aislar el render en un sandbox endurecido.",
    "An attacker can execute arbitrary commands in the application runtime context.": "Un atacante puede ejecutar comandos arbitrarios en el contexto de ejecucion de la aplicacion.",
    "Avoid shell execution, pass arguments as arrays, validate strict allowlists and run services with least privilege.": "Evitar ejecucion por shell, pasar argumentos como listas, validar allowlists estrictas y ejecutar servicios con minimo privilegio.",
    "A malicious website may read authenticated API responses when credentials are allowed and origin validation is weak.": "Un sitio malicioso podria leer respuestas autenticadas de API cuando se permiten credenciales y la validacion de origen es debil.",
    "Use an exact allowlist of trusted origins, avoid wildcard origins with credentials and validate CORS per endpoint sensitivity.": "Usar una allowlist exacta de origenes confiables, evitar wildcard con credenciales y validar CORS segun la sensibilidad de cada endpoint.",
    "Weak CSP can increase the exploitability and impact of client-side injection flaws.": "Una CSP debil puede aumentar la explotabilidad e impacto de fallos de inyeccion del lado cliente.",
    "Define restrictive default-src, script-src, object-src, base-uri, frame-ancestors and form-action directives using nonces or hashes where needed.": "Definir directivas restrictivas default-src, script-src, object-src, base-uri, frame-ancestors y form-action usando nonces o hashes cuando aplique.",
    "Missing flags can increase exposure to session theft, cross-site request abuse or accidental transmission over cleartext.": "La ausencia de flags aumenta la exposicion a robo de sesion, abuso cross-site o transmision accidental en claro.",
    "Use Secure, HttpOnly and SameSite=Lax or Strict for sensitive cookies, and rotate sessions after authentication.": "Usar Secure, HttpOnly y SameSite=Lax o Strict para cookies sensibles, y rotar sesiones tras autenticacion.",
    "An attacker can trick users into interacting with hidden or overlaid application controls.": "Un atacante puede inducir al usuario a interactuar con controles ocultos o superpuestos.",
    "Use CSP frame-ancestors and, where compatible, X-Frame-Options DENY or SAMEORIGIN for sensitive pages.": "Usar CSP frame-ancestors y, donde sea compatible, X-Frame-Options DENY o SAMEORIGIN en paginas sensibles.",
    "Exposure can reveal credentials, source code, internal endpoints or deployment secrets.": "La exposicion puede revelar credenciales, codigo fuente, endpoints internos o secretos de despliegue.",
    "Remove sensitive files from web-accessible paths, block dotfiles and backups at the web server, and rotate any exposed secrets.": "Retirar archivos sensibles de rutas web, bloquear dotfiles y respaldos en el servidor, y rotar cualquier secreto expuesto.",
    "Attackers may forge tokens, escalate privileges or impersonate users.": "Un atacante podria falsificar tokens, escalar privilegios o suplantar usuarios.",
    "Pin accepted algorithms, validate issuer/audience/expiration, protect signing keys and reject unsigned or weakly signed tokens.": "Fijar algoritmos aceptados, validar issuer/audience/expiracion, proteger claves de firma y rechazar tokens sin firma o con firma debil.",
    "An authenticated or unauthenticated attacker may access or modify another user's records.": "Un atacante autenticado o no autenticado podria acceder o modificar registros de otro usuario.",
    "Enforce object-level authorization server-side for every request and use indirect references where practical.": "Aplicar autorizacion por objeto en servidor para cada peticion y usar referencias indirectas cuando sea viable.",
    "Validate the condition manually, capture supporting evidence, and remediate the affected control.": "Validar la condicion manualmente, capturar evidencia de soporte y corregir el control afectado.",
    "Disable directory listing and expose only required static assets.": "Deshabilitar el listado de directorios y exponer solo activos estaticos requeridos.",
    "Align SAML metadata entityID, ACS and SLO URLs with the deployed host, scheme and port.": "Alinear entityID, ACS y SLO de metadata SAML con el host, esquema y puerto desplegados.",
    "Review exposed routes, require authentication where needed and remove debug/admin/static listings.": "Revisar rutas expuestas, exigir autenticacion donde aplique y retirar listados debug/admin/static.",
    "Use parameterized queries and server-side input validation.": "Usar consultas parametrizadas y validacion de entrada en servidor.",
    "Deploy browser security headers consistently across all responses.": "Desplegar cabeceras de seguridad del navegador de forma consistente en todas las respuestas.",
    "Apply contextual output encoding and enforce a restrictive CSP.": "Aplicar codificacion contextual de salida y reforzar una CSP restrictiva.",
    "Validate outbound URLs, block internal ranges, and use egress allowlists.": "Validar URLs de salida, bloquear rangos internos y usar allowlists de egreso.",
    "Normalize paths and restrict file access to approved directories.": "Normalizar rutas y restringir acceso a directorios aprobados.",
    "Avoid shell execution with user input and use strict command allowlists.": "Evitar ejecucion shell con entrada de usuario y usar allowlists estrictas de comandos.",
    "Escape LDAP filters and use parameterized directory queries.": "Escapar filtros LDAP y usar consultas parametrizadas contra directorios.",
    "Avoid rendering user input as templates and sandbox template engines.": "Evitar renderizar entrada de usuario como plantilla y aislar motores de plantillas en sandbox.",
    "Enforce server-side authentication checks and harden login workflows.": "Aplicar validaciones de autenticacion en servidor y endurecer los flujos de login.",
    "Perform object-level authorization checks for every sensitive request.": "Ejecutar controles de autorizacion por objeto en cada peticion sensible.",
    "Restrict CORS origins and never allow credentials with wildcard origins.": "Restringir origenes CORS y nunca permitir credenciales con origen wildcard.",
    "Use strong JWT algorithms, verify signatures, and enforce exp/iat claims.": "Usar algoritmos JWT fuertes, verificar firmas y exigir claims exp/iat.",
    "Use modern TLS, valid certificates, HSTS, and strong cipher suites.": "Usar TLS moderno, certificados validos, HSTS y suites criptograficas fuertes.",
    "Restrict exposed metadata and remove sensitive operational details.": "Restringir metadatos expuestos y retirar detalles operativos sensibles.",
    "Validate affected software versions and apply vendor remediation.": "Validar versiones de software afectadas y aplicar correcciones del proveedor.",
    "Version/CPE correlation; vendor patch state unverified": "Correlacion Version/CPE; estado de parche del proveedor no verificado",
    "Nmap NSE script output": "Salida del script NSE de Nmap",
    "NSE cipher enumeration": "Enumeracion de cifrados con NSE",
    "NSE protocol support check": "Validacion de soporte de protocolo con NSE",
    "Specific NSE CVE check": "Validacion CVE especifica con NSE",
    "Specific NSE TLS vulnerability check": "Validacion TLS especifica con NSE",
    "NSE protocol downgrade check": "Validacion de downgrade de protocolo con NSE",
    "NSE DH parameter analysis": "Analisis de parametros DH con NSE",
    "Specific SMB NSE check": "Validacion SMB especifica con NSE",
    "Nmap http-git exposure check": "Validacion http-git con Nmap",
    "WAF or perimeter protection detected by wafw00f": "WAF o proteccion perimetral identificado por wafw00f",
    "Application WAF and filter resilience profile observed": "Perfil de WAF y filtros de aplicacion observado",
    "Browser audit skipped: Playwright not installed": "Auditoria de navegador omitida: Playwright no instalado",
    "Install with: pip install playwright && python -m playwright install chromium": "Instalar con: pip install playwright && python -m playwright install chromium",
    "Browser audit skipped: Playwright import failed": "Auditoria de navegador omitida: fallo al importar Playwright",
    "Browser audit skipped or failed": "Auditoria de navegador omitida o fallida",
    "Validated DOM XSS dialog execution": "Ejecucion de dialogo DOM XSS validada",
    "Browser crawl identified login/auth routes": "Crawl de navegador identifico rutas de login/autenticacion",
    "CORS wildcard with credentials": "CORS wildcard con credenciales",
    "CORS reflects arbitrary origin": "CORS refleja origen arbitrario",
    "Payload reflected without HTML escaping.": "Payload reflejado sin escape HTML.",
    "Stored/reflected form input candidate": "Candidato de entrada de formulario almacenada/reflejada",
    "Benign marker was reflected after form submission.": "Marcador benigno reflejado despues del envio del formulario.",
    "DOM XSS sink indicators detected": "Indicadores de sinks DOM XSS detectados",
    "Front-end storage/cookie access pattern": "Patron de acceso a storage/cookies desde front-end",
    "No WAF/filtering signal on encoded probes": "Sin senal de WAF/filtro en pruebas codificadas",
    "Weak credential accepted": "Credencial debil aceptada",
    "Protected-looking route returned 200 without login challenge.": "Ruta aparentemente protegida respondio 200 sin desafio de login.",
    "Login bypass signal with injection payload": "Senal de bypass de login con payload de inyeccion",
    "Recovery surface identified for manual workflow review.": "Superficie de recuperacion identificada para revision manual del flujo.",
    "Browsers require Secure for SameSite=None; session transport guarantees are weakened.": "Los navegadores requieren Secure con SameSite=None; se debilitan las garantias de transporte de sesion.",
    "No Expires/Max-Age observed.": "No se observo Expires/Max-Age.",
    "JavaScript references document.cookie": "JavaScript referencia document.cookie",
    "document.cookie found in page source; verify cookie exposure and HttpOnly coverage.": "document.cookie encontrado en el codigo de la pagina; verificar exposicion de cookies y cobertura HttpOnly.",
    "Session regeneration not observed for auth profile": "No se observo regeneracion de sesion para el perfil autenticado",
    "JWT uses unsigned/null algorithm": "JWT usa algoritmo sin firma/null",
    "JWT temporal claim weakness": "Debilidad en claims temporales JWT",
    "JWT contains sensitive-looking claims": "JWT contiene claims con apariencia sensible",
    "JWT contains privileged boolean claim": "JWT contiene claim booleano privilegiado",
    "JWT contains privileged role claim": "JWT contiene claim de rol privilegiado",
    "JWT signed with weak HMAC secret": "JWT firmado con secreto HMAC debil",
    "State-changing form without visible CSRF token": "Formulario con cambio de estado sin token CSRF visible",
    "Login form without visible MFA field": "Formulario de login sin campo MFA visible",
    "No OTP/MFA/TOTP/2FA field identified in login form markup.": "No se identifico campo OTP/MFA/TOTP/2FA en el markup del formulario de login.",
    "File upload surface discovered": "Superficie de carga de archivos descubierta",
    "File input exists. Verify extension/MIME/content validation.": "Existe input de archivo. Verificar validacion de extension/MIME/contenido.",
    "Benign file upload probe accepted": "Prueba benigna de carga de archivo aceptada",
    "Route may require authorization review.": "La ruta puede requerir revision de autorizacion.",
    "Response body changed significantly after parameter manipulation.": "El cuerpo de respuesta cambio significativamente tras manipular parametros.",
    "Anonymous response closely matches authenticated profile response.": "La respuesta anonima coincide estrechamente con la respuesta del perfil autenticado.",
    "WAF/CDN signal detected": "Senal de WAF/CDN detectada",
    "Server configuration headers exposed": "Cabeceras de configuracion del servidor expuestas",
    "Potentially dangerous HTTP methods advertised": "Metodos HTTP potencialmente peligrosos anunciados",
    "HTTP TRACE method enabled": "Metodo HTTP TRACE habilitado",
    "TRACE reflected the request marker.": "TRACE reflejo el marcador de solicitud.",
    "IP restriction bypass via forwarding header": "Bypass de restriccion IP mediante cabecera de reenvio",
    "No rate-limit / anti-automation signal observed": "Sin senal de rate-limit / anti-automatizacion",
    "HTTP to HTTPS redirect not enforced": "Redireccion HTTP a HTTPS no forzada",
    "Expect-CT header not present": "Cabecera Expect-CT no presente",
    "Expect-CT is deprecated in modern browsers but retained as audit evidence.": "Expect-CT esta deprecada en navegadores modernos, pero se conserva como evidencia de auditoria.",
    "Weak TLS cipher negotiated": "Cifrado TLS debil negociado",
    "TLS certificate validation failed": "Validacion de certificado TLS fallida",
    "TLS certificate inspection failed": "Inspeccion de certificado TLS fallida",
    "Certificate CN/SAN mismatch": "Inconsistencia CN/SAN del certificado",
    "TLS certificate not yet valid": "Certificado TLS aun no valido",
    "TLS certificate near expiration": "Certificado TLS proximo a expirar",
    "Modern TLS protocol support not confirmed": "Soporte de protocolo TLS moderno no confirmado",
    "TLSv1.2/TLSv1.3 handshakes did not succeed during protocol validation.": "Los handshakes TLSv1.2/TLSv1.3 no tuvieron exito durante la validacion de protocolo.",
    "Weak Referrer-Policy": "Referrer-Policy debil",
    "SAML metadata endpoint is publicly reachable": "Endpoint de metadata SAML accesible publicamente",
    "SAML metadata appears inconsistent with scanned target": "La metadata SAML parece inconsistente con el objetivo analizado",
    "Unauthenticated route audit generated": "Auditoria de rutas sin autenticacion generada",
    "Directory listing enabled on unauthenticated paths": "Listado de directorios habilitado en rutas sin autenticacion",
    "Disable Apache autoindex/Options Indexes and publish only required static artifacts.": "Deshabilitar Apache autoindex/Options Indexes y publicar solo artefactos estaticos requeridos.",
    "Backup or editor residue files exposed in static tree": "Archivos de respaldo o residuos de editor expuestos en arbol estatico",
    "Remove backup/editor files from web roots and block risky extensions at the web server.": "Eliminar archivos de respaldo/editor del webroot y bloquear extensiones riesgosas en el servidor web.",
    "Functional site map generated": "Mapa funcional del sitio generado",
    "Sensitive-looking functionality exposed in site map": "Funcionalidad con apariencia sensible expuesta en el mapa del sitio",
    "Public OpenAPI/Swagger specification exposed": "Especificacion OpenAPI/Swagger publica expuesta",
    "GraphQL introspection enabled": "Introspeccion GraphQL habilitada",
    "JavaScript source map exposed": "Source map JavaScript expuesto",
    "JSON body reflection candidate": "Candidato de reflexion en cuerpo JSON",
    "JSON marker reflected in response body.": "Marcador JSON reflejado en el cuerpo de respuesta.",
    "WebSocket endpoint discovered": "Endpoint WebSocket descubierto",
    "WebSocket security requires origin/authentication validation.": "La seguridad WebSocket requiere validacion de origen/autenticacion.",
    "Race/concurrency response variance": "Variacion de respuesta por concurrencia/race condition",
    "Log/debug markers observed in response.": "Marcadores de log/debug observados en la respuesta.",
    "Public directory listing exposed: /ftp": "Listado publico de directorio expuesto: /ftp",
    "Prometheus metrics endpoint exposed": "Endpoint de metricas Prometheus expuesto",
    "Application version endpoint exposed": "Endpoint de version de aplicacion expuesto",
    "Challenge/catalog API exposed": "API de catalogo/challenges expuesta",
    "OWASP Juice Shop challenge metadata is publicly readable.": "La metadata de challenges de OWASP Juice Shop es publicamente legible.",
    "Authentication bypass via SQL injection on JSON login API": "Bypass de autenticacion por SQL Injection en API JSON de login",
    "Login API response exposes sensitive user fields": "La respuesta de la API de login expone campos sensibles de usuario",
    "SQL Injection error-based": "SQL Injection basada en errores",
    "Differential database error signature observed only after payload": "Firma diferencial de error de base de datos observada solo despues del payload",
    "Differential LDAP error signature observed": "Firma diferencial de error LDAP observada",
    "Tool not found in PATH": "Herramienta no encontrada en PATH",
    "No useful output": "Sin salida util",
    "Timeout": "Tiempo agotado",
    "Timed out": "Tiempo agotado",
    "Module timeout": "Tiempo agotado en modulo",
    "Module failed": "Modulo fallido",
    "Graceful finish requested": "Finalizacion ordenada solicitada",
    "ACTIVE": "ACTIVO",
    "NOT_SEEN": "NO VISTO",
    "NEW": "NUEVO",
    "RECURRING": "RECURRENTE",
    "REGRESSION": "REGRESION",
}


FIELD_LABELS_ES = {
    "Vulnerability ID": "ID de Vulnerabilidad",
    "Category": "Categoria",
    "Target": "Objetivo",
    "URL": "URL",
    "Endpoint": "Endpoint",
    "Param": "Parametro",
    "Method": "Metodo",
    "Payload": "Payload",
    "HTTP": "HTTP",
    "Size": "Tamano",
    "Time": "Tiempo",
    "Evidence": "Evidencia",
    "Detected By": "Detectado por",
    "CWE": "CWE",
    "OWASP": "OWASP",
    "CVSS": "CVSS",
    "Impact": "Impacto",
    "Remediation": "Remediacion",
    "Recommendation": "Recomendacion",
    "Manual Test": "Prueba Manual",
    "Browser Evidence": "Evidencia Browser",
    "Evidence Artifact": "Artefacto de Evidencia",
    "Console Artifact": "Artefacto de Consola",
    "Affected Locations": "Ubicaciones Afectadas",
    "Confidence": "Confianza",
    "Evidence Strength": "Fuerza de Evidencia",
    "False Positive Risk": "Riesgo de Falso Positivo",
    "Source": "Fuente",
    "Fingerprint": "Huella",
    "First Seen": "Primera Deteccion",
    "Last Seen": "Ultima Deteccion",
    "Occurrences": "Ocurrencias",
    "State": "Estado",
}


SEVERITY_LABELS_ES = {
    "Critical": "Critica",
    "High": "Alta",
    "Medium": "Media",
    "Low": "Baja",
    "Info": "Info",
}


CATEGORY_LABELS_ES = {
    "availability": "Disponibilidad",
    "client-side": "Cliente",
    "discovery": "Descubrimiento",
    "external": "Externo",
    "external/ffuf": "Externo/FFUF",
    "external/nmap": "Externo/Nmap",
    "external/nuclei": "Externo/Nuclei",
    "external/subfinder": "Externo/Subfinder",
    "external/waf": "Externo/WAF",
    "external/wafw00f": "Externo/WAFW00F",
    "external/whatweb": "Externo/WhatWeb",
    "external/zap": "Externo/ZAP",
    "headers": "Cabeceras",
    "pipeline": "Pipeline",
    "recon": "Reconocimiento",
    "recon/waf": "Reconocimiento/WAF",
}


def translate_visible_text(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    for source, replacement in sorted(TEXT_TRANSLATIONS_ES.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(source, replacement)
    text = re.sub(r"\bTemplate=", "Plantilla=", text)
    text = re.sub(r"\bMatcher=", "Matcher=", text)
    text = re.sub(r"\bType=", "Tipo=", text)
    text = re.sub(r"\bHost=", "Host=", text)
    text = re.sub(r"\bMatchedAt=", "Coincidencia=", text)
    text = re.sub(r"\bAffectedLocations=", "UbicacionesAfectadas=", text)
    text = re.sub(r"\bExtracted=", "Extraido=", text)
    text = re.sub(r"\bRisk=", "Riesgo=", text)
    text = re.sub(r"\bConfidence=", "Confianza=", text)
    text = re.sub(r"\bEvidence=", "Evidencia=", text)
    text = re.sub(r"\bParam=", "Parametro=", text)
    text = re.sub(r"\bAttack=", "Ataque=", text)
    text = re.sub(r"\bPlugin=", "Plugin=", text)
    text = re.sub(r"\bProfile=", "Perfil=", text)
    text = re.sub(r"\bStatuses=", "Estados=", text)
    text = re.sub(r"\bReusedCookies=", "CookiesReutilizadas=", text)
    text = re.sub(r"\bWeakTokens=", "TokensDebiles=", text)
    text = re.sub(r"\bMissing=", "Faltantes=", text)
    text = re.sub(r"\bDetected=", "Detectado=", text)
    text = re.sub(r"\bVendor=", "Fabricante=", text)
    text = re.sub(r"\bFirewall=", "Firewall=", text)
    text = re.sub(r"\bWAF=", "WAF=", text)
    text = re.sub(r"\bStatus=", "Estado=", text)
    text = re.sub(r"\bBlocked=", "Bloqueados=", text)
    text = re.sub(r"\bPassed=", "Permitidos=", text)
    text = re.sub(r"\bRateLimit=", "RateLimit=", text)
    return text


def field_label_es(value: str) -> str:
    return FIELD_LABELS_ES.get(value, value)


def severity_label_es(value: Any) -> str:
    return SEVERITY_LABELS_ES.get(normalize_severity(str(value or "")), str(value or "Info"))


def category_label_es(value: Any) -> str:
    raw = str(value or "").strip()
    return CATEGORY_LABELS_ES.get(raw.casefold(), raw)


def confidence_label_es(value: Any) -> str:
    return {
        "high": "alta",
        "medium": "media",
        "low": "baja",
        "unknown": "desconocida",
    }.get(str(value or "").strip().lower(), str(value or ""))


def evidence_strength_label_es(value: Any) -> str:
    return {
        "strong": "fuerte",
        "moderate": "moderada",
        "medium": "moderada",
        "weak": "debil",
        "unknown": "desconocida",
    }.get(str(value or "").strip().lower(), translate_visible_text(value))


def false_positive_risk_label_es(value: Any) -> str:
    return {
        "high": "alto",
        "medium": "medio",
        "low": "bajo",
        "unknown": "desconocido",
    }.get(str(value or "").strip().lower(), translate_visible_text(value))


def url_with_params(url: str, params: dict[str, Any]) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urllib.parse.urlencode(params, doseq=True)}"


def stable_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value or "")
    return parsed._replace(query="", fragment="").geturl()


def _finding_value(finding: Any, name: str, default: Any = "") -> Any:
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _identity_text(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"https?://[^\s|]+", " ", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def finding_cves(finding: Any) -> list[str]:
    text = " ".join(
        str(_finding_value(finding, key, "") or "")
        for key in ("title", "evidence", "details", "cvss", "source", "endpoint")
    )
    return sorted({match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)})


def canonical_vulnerability_family(finding: Any) -> str:
    """Return a source-independent vulnerability family for correlation."""
    cves = finding_cves(finding)
    if cves:
        return "cve:" + ",".join(cves)

    haystack = _identity_text(
        " ".join(
            str(_finding_value(finding, key, "") or "")
            for key in ("title", "category", "source", "evidence", "details", "cwe")
        )
    )
    rules: list[tuple[str, tuple[str, ...]]] = [
        ("cors-arbitrary-origin", ("cors reflects arbitrary", "arbitrary origin", "origin reflejado", "wildcard origin", "cross-domain misconfiguration", "cors misconfiguration")),
        ("hsts-missing", ("hsts missing", "strict-transport-security header no", "strict transport security missing", "strict-transport-security header not set", "hsts ausente")),
        ("csp-missing", ("csp missing", "content security policy (csp) no configurada", "content-security-policy missing", "content security policy (csp) header not set", "cabecera content security policy")),
        ("csp-weak", ("csp: style-src unsafe-inline", "unsafe-inline", "unsafe-eval", "csp weak", "csp debil")),
        ("clickjacking-protection-missing", ("clickjacking", "x-frame-options missing", "x-frame-options header not set", "frame-ancestors missing")),
        ("x-content-type-options-missing", ("x-content-type-options", "mime sniffing")),
        ("referrer-policy-missing", ("referrer-policy", "referrer policy")),
        ("permissions-policy-missing", ("permissions-policy", "feature-policy")),
        ("cookie-secure-missing", ("cookie secure", "secure flag missing", "cookie without secure")),
        ("cookie-httponly-missing", ("cookie httponly", "httponly flag missing", "cookie without httponly")),
        ("cookie-samesite-missing", ("cookie samesite", "samesite attribute", "missing-cookie-samesite")),
        ("sql-injection", ("sql injection", "sqli", "inyeccion sql", "inyección sql")),
        ("command-injection", ("command injection", "os command", "inyeccion de comandos", "inyección de comandos")),
        ("server-side-template-injection", ("ssti", "template injection")),
        ("cross-site-scripting", ("cross-site scripting", "cross site scripting", " xss", "xss ")),
        ("server-side-request-forgery", ("server-side request forgery", " ssrf", "ssrf ")),
        ("path-traversal-lfi", ("path traversal", "directory traversal", "local file inclusion", " lfi", "lfi ")),
        ("open-redirect", ("open redirect", "external redirect", "redireccion abierta", "redirección abierta")),
        ("authentication-bypass", ("authentication bypass", "auth bypass", "bypass de autenticacion", "bypass de autenticación")),
        ("broken-object-authorization", ("idor", "bola", "object authorization", "autorizacion por objeto", "autorización por objeto")),
        ("csrf", ("cross-site request forgery", "csrf")),
        ("rate-limit-missing", ("rate limit", "rate-limit", "unlimited requests")),
        ("directory-listing", ("directory listing", "directory index", "listado de directorio")),
        ("git-exposure", ("/.git", "http-git", "git repository exposure")),
        ("environment-file-exposure", ("/.env", "environment file exposure")),
        ("backup-file-exposure", ("backup file", "backup exposure", "archivo de respaldo")),
        ("weak-tls-protocol", ("sslv2", "sslv3", "tls 1.0", "tls 1.1", "weak tls protocol")),
        ("weak-tls-cipher", ("weak cipher", "cifrados debiles", "cifrados débiles", "anonymous cipher", "export cipher")),
        ("heartbleed", ("heartbleed",)),
        ("poodle", ("poodle",)),
        ("ms17-010", ("ms17-010", "eternalblue")),
    ]
    for family, markers in rules:
        if any(marker in haystack for marker in markers):
            return family

    title = _identity_text(_finding_value(finding, "title", "finding"))
    title = re.sub(r"^(?:nuclei|zap|scan titan)\s*:\s*", "", title)
    title = re.sub(r"^nmap\s+[^:]+:\s*", "", title)
    title = re.sub(r"\bon\s+\d{1,5}/(?:tcp|udp)\b", "", title)
    title = re.sub(r"\s+", " ", title).strip(" :-")
    cwe = str(_finding_value(finding, "cwe", "") or "").strip().lower()
    return f"{cwe}:{title}" if cwe else title or "unclassified-vulnerability"


SERVICE_SCOPED_FAMILIES = {
    "cors-arbitrary-origin",
    "hsts-missing",
    "csp-missing",
    "csp-weak",
    "clickjacking-protection-missing",
    "x-content-type-options-missing",
    "referrer-policy-missing",
    "permissions-policy-missing",
    "weak-tls-protocol",
    "weak-tls-cipher",
    "heartbleed",
    "poodle",
    "ms17-010",
}


def canonical_vulnerability_id(finding: Any) -> str:
    """Stable ID shared by equivalent detections from different engines."""
    family = canonical_vulnerability_family(finding)
    url = str(_finding_value(finding, "url", "") or "")
    endpoint = str(_finding_value(finding, "endpoint", "") or "")
    parsed = urllib.parse.urlparse(url if "://" in url else "")
    port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else "")
    if not port:
        endpoint_port = re.search(r"\b(\d{1,5})(?:/(?:tcp|udp))?\b", endpoint, flags=re.IGNORECASE)
        port = endpoint_port.group(1) if endpoint_port else ""
    path = parsed.path or (endpoint if endpoint.startswith("/") else "")
    if family in SERVICE_SCOPED_FAMILIES or family.startswith("cve:"):
        location = f"port:{port or endpoint or 'service'}"
    else:
        location = path.rstrip("/") or endpoint or "/"
    method = str(_finding_value(finding, "method", "") or "").upper()
    param = str(_finding_value(finding, "param", "") or "").strip().lower()
    if family in SERVICE_SCOPED_FAMILIES or family.startswith("cve:"):
        method = ""
        param = ""
    material = "|".join([family, str(location).lower(), method, param])
    return "STV-" + hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()[:12].upper()


def vulnerability_occurrence_key(finding: Any, asset: str = "") -> str:
    canonical_id = str(_finding_value(finding, "canonical_id", "") or canonical_vulnerability_id(finding))
    asset_key = str(asset or _finding_value(finding, "asset", "") or _finding_value(finding, "target", "")).strip().lower()
    return hashlib.sha256(f"{asset_key}|{canonical_id}".encode("utf-8", errors="ignore")).hexdigest()


AUTH_ROUTE_RE = re.compile(
    r"(^|/)(login|logon|signin|sign-in|sign_in|auth|sso|saml|oauth|oidc|cas|session)(/|$)"
)


def _header_value(headers: dict[str, str], name: str) -> str:
    expected = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == expected:
            return str(value or "")
    return ""


def is_authentication_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(str(value or "").strip())
    path = parsed.path.lower()
    query = parsed.query.lower()
    if not path:
        return False
    if AUTH_ROUTE_RE.search(path):
        return True
    auth_fragments = (
        "/accounts/login",
        "/user/login",
        "/users/login",
        "/admin/login",
        "/auth/login",
        "/password/reset",
        "/password_reset",
        "/reset-password",
        "/forgot-password",
        "/realms/",
        "/protocol/openid-connect",
    )
    if any(fragment in path for fragment in auth_fragments):
        return True
    return bool(
        any(token in query for token in ("next=", "returnurl=", "redirect_uri=", "relaystate="))
        and any(token in path for token in ("login", "auth", "sso", "saml", "oauth", "cas"))
    )


def is_login_response(body: str) -> bool:
    lower = (body or "").lower()
    if not lower:
        return False
    has_secret_field = any(token in lower for token in ("type=\"password\"", "name=\"password", "id=\"password"))
    has_login_word = any(
        token in lower
        for token in (
            "login",
            "sign in",
            "signin",
            "username",
            "correo",
            "contraseña",
            "password",
            "csrfmiddlewaretoken",
            "otp",
            "mfa",
            "2fa",
        )
    )
    return has_secret_field and has_login_word


def auth_destination(result: Any) -> str:
    location = _header_value(getattr(result, "headers", {}), "Location")
    if location and is_authentication_url(location):
        return urllib.parse.urljoin(getattr(result, "url", "") or getattr(result, "final_url", ""), location)
    request_url = getattr(result, "url", "") or ""
    final_url = getattr(result, "final_url", "") or ""
    if final_url and stable_url(final_url).lower() != stable_url(request_url).lower() and is_authentication_url(final_url):
        return final_url
    if getattr(result, "status", 0) == 200 and is_login_response(getattr(result, "text", "")):
        return final_url or request_url
    return ""


def soft_auth_redirect_reason(result: Any, baseline: Any | None = None, request_path: str | None = None) -> str:
    request_value = request_path or getattr(result, "url", "") or getattr(result, "final_url", "")
    if is_authentication_url(request_value):
        return ""
    destination = auth_destination(result)
    if not destination:
        return ""
    if baseline is not None:
        baseline_destination = auth_destination(baseline)
        if baseline_destination:
            dest_path = urllib.parse.urlparse(destination).path.lower()
            base_path = urllib.parse.urlparse(baseline_destination).path.lower()
            if dest_path and base_path and dest_path == base_path:
                return f"soft-auth redirect catch-all -> {dest_path}"
            if is_login_response(getattr(result, "text", "")) and is_login_response(getattr(baseline, "text", "")):
                return "soft-auth login body matches catch-all baseline"
        if getattr(result, "status", None) == getattr(baseline, "status", None):
            result_title = html_title(getattr(result, "text", ""))
            baseline_title = html_title(getattr(baseline, "text", ""))
            if result_title and result_title == baseline_title and is_authentication_url(destination):
                return f"soft-auth title match -> {result_title}"
    return "soft-auth redirect/login response"


def is_soft_auth_redirect(result: Any, baseline: Any | None = None, request_path: str | None = None) -> bool:
    return bool(soft_auth_redirect_reason(result, baseline, request_path))


def html_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip().lower() if match else ""


def powershell_quote(value: Any) -> str:
    text = str(value or "")
    text = text.replace("`", "``").replace("$", "`$").replace('"', '`"')
    return f'"{text}"'


def build_manual_command(finding: Any) -> str:
    url = str(getattr(finding, "url", "") or "").strip()
    target = str(getattr(finding, "target", "") or "").strip()
    endpoint = str(getattr(finding, "endpoint", "") or "").strip()
    method = str(getattr(finding, "method", "") or "GET").upper()
    param = str(getattr(finding, "param", "") or "").strip()
    payload = str(getattr(finding, "payload", "") or "").strip()
    title = str(getattr(finding, "title", "") or "")
    category = str(getattr(finding, "category", "") or "")
    source = str(getattr(finding, "source", "") or "")
    haystack = " ".join([title, category, source, str(getattr(finding, "evidence", "") or "")]).lower()
    if not url and endpoint.startswith(("http://", "https://")):
        url = endpoint
    if not url and target.startswith(("http://", "https://")):
        url = target

    if source.startswith("nmap") or "external/nmap" in category.lower():
        host = urllib.parse.urlparse(url).hostname if url else ""
        host = host or target
        script = "vuln and safe"
        if "slowloris" in haystack:
            script = "http-slowloris-check"
        elif "heartbleed" in haystack:
            script = "ssl-heartbleed"
        elif "poodle" in haystack:
            script = "ssl-poodle"
        elif "ms17-010" in haystack:
            script = "smb-vuln-ms17-010"
        elif "vulners" in haystack or "cve-" in haystack:
            script = "vulners"
        port_match = re.search(r"\b(\d{1,5})/(?:tcp|udp)\b", f"{endpoint} {title}", re.IGNORECASE)
        port_arg = f" -p {port_match.group(1)}" if port_match else ""
        script_args = " --script-args mincvss=4.0" if script == "vulners" else ""
        return (
            f"nmap -sV -Pn{port_arg} --script {powershell_quote(script)}{script_args} "
            f"{powershell_quote(host)}"
        )

    if source.startswith("nuclei"):
        template = source.split(":", 1)[1] if ":" in source else ""
        if not template and re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,120}", endpoint, re.IGNORECASE):
            template = endpoint
        base = url or target
        if base and not base.startswith(("http://", "https://")):
            base = f"https://{base}"
        cmd = f"nuclei -u {powershell_quote(base)} -jsonl"
        if template:
            cmd += f" -id {powershell_quote(template)}"
        return cmd

    if not url:
        return ""

    if method in {"", "GET"}:
        method = "GET"

    def curl_get(value: str, *, headers: list[str] | None = None, metadata_only: bool = False) -> str:
        parts = ["curl.exe", "-k", "-sS", "--max-time", "20"]
        if metadata_only:
            parts.extend(["-D", "-", "-o", "NUL"])
        else:
            parts.append("-i")
        for header in headers or []:
            parts.extend(["-H", powershell_quote(header)])
        parts.append(powershell_quote(value))
        return " ".join(parts)

    if "cors" in haystack:
        simple = curl_get(url, headers=["Origin: https://example.com"], metadata_only=True)
        preflight = (
            "curl.exe -k -sS --max-time 20 -D - -o NUL -X OPTIONS "
            f"-H {powershell_quote('Origin: https://example.com')} "
            f"-H {powershell_quote('Access-Control-Request-Method: GET')} {powershell_quote(url)}"
        )
        return f"Write-Host '[CORS simple]'; {simple}; Write-Host '[CORS preflight]'; {preflight}"

    if source == "zap:20019" and param.strip().lower() in {"host", "host header", "http host"}:
        original_host = urllib.parse.urlsplit(url).netloc or target
        attack_host = payload or "scan-titan-control.invalid"
        control = curl_get(url, headers=[f"Host: {original_host}"], metadata_only=True)
        probe = curl_get(url, headers=[f"Host: {attack_host}"], metadata_only=True)
        return f"Write-Host '[Host control]'; {control}; Write-Host '[Host probe]'; {probe}"

    if method == "GET" and param and payload and any(token in haystack for token in ("sql injection", "inyeccion sql", "inyección sql")):
        control_value = re.split(r"\s+(?:and|or)\s+", payload, maxsplit=1, flags=re.IGNORECASE)[0].strip()
        control_value = control_value or "scan_titan_control"
        false_payload = re.sub(r"(?i)1\s*=\s*1", "1=2", payload, count=1)
        if false_payload == payload:
            false_payload = f"{control_value} AND 1=2"
        control_url = _url_with_replaced_param(url, param, control_value)
        true_url = _url_with_replaced_param(url, param, payload)
        false_url = _url_with_replaced_param(url, param, false_payload)
        return (
            f"Write-Host '[SQLi control]'; {curl_get(control_url)}; "
            f"Write-Host '[SQLi true]'; {curl_get(true_url)}; "
            f"Write-Host '[SQLi false]'; {curl_get(false_url)}"
        )

    if method == "GET" and param and payload and any(
        token in haystack for token in ("command injection", "template injection", "ssti", "ssrf")
    ):
        control_url = _url_with_replaced_param(url, param, "scan_titan_control")
        probe_url = _url_with_replaced_param(url, param, payload)
        return (
            f"Write-Host '[control]'; {curl_get(control_url)}; "
            f"Write-Host '[probe]'; {curl_get(probe_url)}"
        )

    if method == "GET" and param and payload and any(
        token in haystack for token in ("redirect", "redireccion", "redirección")
    ):
        control_url = _url_with_replaced_param(url, param, "scan-titan-control.invalid")
        probe_url = _url_with_replaced_param(url, param, payload)
        return (
            f"Write-Host '[redirect control]'; {curl_get(control_url, metadata_only=True)}; "
            f"Write-Host '[redirect probe]'; {curl_get(probe_url, metadata_only=True)}"
        )

    if any(token in haystack for token in ("header", "hsts", "clickjacking", "cache-control", "cookie")) and not payload:
        return curl_get(url, metadata_only=True)

    if any(token in haystack for token in ("tls", "certificate", "cipher", "ssl")) and not payload:
        return f"curl.exe -k -v --max-time 20 -o NUL {powershell_quote(url)}"

    command_parts = ["curl.exe", "-k", "-i", "--max-time", "20"]
    if method not in {"GET", "HEAD"}:
        command_parts.extend(["-X", method])

    request_url = url
    if method == "GET" and param and payload:
        request_url = _url_with_replaced_param(url, param, payload)
    command_parts.append(powershell_quote(request_url))

    if method not in {"GET", "HEAD"} and payload:
        if "json" in haystack or payload.lstrip().startswith(("{", "[")):
            command_parts.extend(["-H", powershell_quote("Content-Type: application/json"), "--data", powershell_quote(payload)])
        elif param:
            command_parts.extend(["--data-urlencode", powershell_quote(f"{param}={payload}")])
        else:
            command_parts.extend(["--data", powershell_quote(payload)])
    return " ".join(command_parts)


def _url_with_replaced_param(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    return parsed._replace(query=urllib.parse.urlencode(query, doseq=True)).geturl()


@dataclass
class Target:
    raw: str
    url: str
    host: str
    ip: str
    scheme: str
    port: int
    is_ip: bool = False

    @property
    def display(self) -> str:
        return self.host or self.url


@dataclass
class HttpResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    text: str
    body_len: int
    elapsed: float
    content_type: str = ""
    raw_headers: dict[str, list[str]] = field(default_factory=dict)
    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    target: str
    category: str
    severity: str
    title: str
    url: str = ""
    endpoint: str = ""
    param: str = ""
    method: str = ""
    payload: str = ""
    status: str = ""
    size: str = ""
    elapsed: str = ""
    evidence: str = ""
    source: str = ""
    asset: str = ""
    canonical_id: str = ""
    correlated_sources: list[str] = field(default_factory=list)
    confidence: str = "medium"
    details: str = ""
    fingerprint: str = ""
    evidence_strength: str = ""
    false_positive_risk: str = ""
    cwe: str = ""
    owasp: str = ""
    cvss: str = ""
    impact: str = ""
    remediation: str = ""
    recommendation: str = ""
    manual_command: str = ""
    evidence_artifact: str = ""
    console_artifact: str = ""
    browser_artifact: str = ""
    first_seen: str = ""
    last_seen: str = ""
    occurrences: int = 1
    state: str = "ACTIVE"

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if self.source and self.source not in self.correlated_sources:
            self.correlated_sources.append(self.source)
        if not self.canonical_id:
            self.canonical_id = canonical_vulnerability_id(self)
        if not self.fingerprint:
            self.fingerprint = self.build_fingerprint()
        if not self.manual_command:
            self.manual_command = build_manual_command(self)

    def build_fingerprint(self) -> str:
        return vulnerability_occurrence_key(self)

    def refresh_identity(self, asset: str = "") -> None:
        if asset:
            self.asset = str(asset).strip()
        self.canonical_id = canonical_vulnerability_id(self)
        self.fingerprint = vulnerability_occurrence_key(self, self.asset)

    def report_lines(self) -> list[str]:
        lines = [
            f"  {field_label_es('Category')}: {category_label_es(self.category)}",
            f"  {field_label_es('First Seen')}: {self.first_seen}",
            f"  {field_label_es('Last Seen')}: {self.last_seen}",
            f"  {field_label_es('Occurrences')}: {self.occurrences}",
            f"  {field_label_es('State')}: {self.state}",
        ]
        values = [
            ("URL", self.url),
            ("Endpoint", self.endpoint),
            ("Param", self.param),
            ("Method", self.method),
            ("Payload", self.payload),
            ("HTTP", self.status),
            ("Size", self.size),
            ("Time", self.elapsed),
            ("Source", self.source),
            ("Confidence", self.confidence),
            ("Evidence Strength", self.evidence_strength),
            ("False Positive Risk", self.false_positive_risk),
            ("CWE", self.cwe),
            ("OWASP", self.owasp),
            ("CVSS", self.cvss),
            ("Impact", self.impact),
            ("Remediation", self.remediation or self.recommendation),
            ("Manual Test", self.manual_command),
            ("Browser Evidence", self.browser_artifact),
            ("Evidence", self.evidence),
            ("Vulnerability ID", self.canonical_id),
            ("Detected By", ", ".join(self.correlated_sources)),
            ("Fingerprint", self.fingerprint[:16]),
        ]
        for key, value in values:
            if value not in ("", None):
                if key == "Manual Test":
                    display = clean_text(value, 1100)
                elif key == "Category":
                    display = category_label_es(value)
                elif key == "Confidence":
                    display = confidence_label_es(value)
                elif key == "Evidence Strength":
                    display = evidence_strength_label_es(value)
                elif key == "False Positive Risk":
                    display = false_positive_risk_label_es(value)
                else:
                    display = translate_visible_text(value)
                lines.append(f"  {field_label_es(key)}: {clean_text(display, 1100)}")
        if self.details:
            for part in self.details.split("|"):
                if part.strip():
                    lines.append(f"  {clean_text(translate_visible_text(part), 1000)}")
        return lines


def correlate_findings(findings: list[Finding], asset: str = "") -> list[Finding]:
    """Merge semantically equivalent findings while retaining all useful evidence."""
    grouped: dict[str, Finding] = {}
    confidence_rank = {"low": 1, "medium": 2, "high": 3}
    for finding in findings:
        finding.refresh_identity(asset)
        key = finding.canonical_id
        current = grouped.get(key)
        if current is None:
            grouped[key] = finding
            continue

        sources = [*current.correlated_sources, *finding.correlated_sources]
        current.correlated_sources = list(dict.fromkeys(source for source in sources if source))
        if SEVERITY_ORDER.get(finding.severity, 99) < SEVERITY_ORDER.get(current.severity, 99):
            current.severity = finding.severity
        if confidence_rank.get(str(finding.confidence).lower(), 0) > confidence_rank.get(str(current.confidence).lower(), 0):
            current.confidence = finding.confidence
        for name in (
            "cwe",
            "owasp",
            "cvss",
            "impact",
            "remediation",
            "recommendation",
            "evidence_strength",
            "manual_command",
            "status",
            "payload",
            "evidence_artifact",
            "browser_artifact",
        ):
            if not getattr(current, name, "") and getattr(finding, name, ""):
                setattr(current, name, getattr(finding, name))

        evidence_items: list[str] = []
        for source, value in (
            (current.source, current.evidence),
            (finding.source, finding.evidence),
        ):
            cleaned = clean_text(value, 1800)
            if not cleaned:
                continue
            labelled = (
                cleaned
                if source == current.source and " :: " in cleaned
                else f"{source or 'scanner'} :: {cleaned}"
            )
            if labelled.lower() not in {item.lower() for item in evidence_items}:
                evidence_items.append(labelled)
        current.evidence = clean_text(" | ".join(evidence_items), 5000)

        detail_parts = [current.details, finding.details]
        merged_details = []
        for value in detail_parts:
            cleaned = clean_text(value, 2500)
            if cleaned and cleaned.lower() not in {item.lower() for item in merged_details}:
                merged_details.append(cleaned)
        detected_by = ", ".join(current.correlated_sources)
        if detected_by:
            merged_details.append(f"Fuentes correlacionadas: {detected_by}")
        current.details = clean_text(" | ".join(merged_details), 6000)
        current.refresh_identity(asset)

    return sorted(
        grouped.values(),
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.category, item.title, item.canonical_id),
    )


@dataclass
class ScanPolicy:
    profile: str = "balanced"
    enabled_modules: set[str] = field(default_factory=set)
    disabled_modules: set[str] = field(default_factory=set)
    skip_external: bool = False
    enable_nmap: bool = True
    enable_nuclei: bool = True
    enable_ffuf: bool = True
    enable_whatweb: bool = True
    enable_subfinder: bool = True
    enable_wafw00f: bool = True
    enable_zap: bool = False
    external_observability: bool = True
    allow_cloud_ssrf: bool = False
    allow_state_changing_api_tests: bool = False
    perform_upload_attempts: bool = False
    allow_bruteforce: bool = False
    allow_rate_limit_probes: bool = True
    rate_limit_probe_requests: int = 12
    api_openapi: bool = True
    api_graphql: bool = True
    api_sourcemaps: bool = True
    api_json_body_tests: bool = False
    enable_browser: bool = False
    browser_max_pages: int = 12
    browser_timeout_seconds: int = 20
    evidence_cards: bool = False
    console_screenshots: bool = False
    browser_evidence: bool = True
    browser_evidence_max_per_target: int = 150
    auth_profiles: list[dict[str, Any]] = field(default_factory=list)

    def module_enabled(self, module_name: str) -> bool:
        normalized = str(module_name or "").strip().lower()
        if not normalized:
            return False
        if normalized in self.disabled_modules:
            return False
        if self.enabled_modules and normalized not in self.enabled_modules:
            return False
        return True


@dataclass
class ScanLimits:
    timeout: float = 10.0
    max_tests_per_module: int = 160
    max_body_bytes: int = 600_000
    delay_seconds: float = 0.0
    jitter_min_seconds: float = 0.5
    jitter_max_seconds: float = 1.5
    throttle_batch_size: int = 25
    adaptive_waf_block_threshold: int = 6
    adaptive_plateau_threshold: int = 8
    allow_cloud_ssrf: bool = False
    allow_state_changing_api_tests: bool = False
    perform_upload_attempts: bool = False
    allow_bruteforce: bool = False
    allow_rate_limit_probes: bool = True
    rate_limit_probe_requests: int = 12
    policy: ScanPolicy = field(default_factory=ScanPolicy)
    runtime_control: Any = None


@dataclass
class ScanContext:
    target: Target
    http: "AsyncHttpClient"
    wordlists: dict[str, list[str]]
    limits: ScanLimits
    recon: dict[str, Any]
    heartbeat: Callable[[str, str, int, int], None]
    policy: ScanPolicy = field(default_factory=ScanPolicy)

    def should_stop(self) -> bool:
        control = self.limits.runtime_control
        return bool(
            getattr(self.http, "circuit_open", False)
            or (control and control.finish_requested)
        )


_Item = TypeVar("_Item")


async def run_bounded(
    items: Iterable[_Item],
    probe: Callable[[_Item], Awaitable[None]],
    *,
    limit: int = 20,
    should_stop: Callable[[], bool] | None = None,
) -> None:
    """Consume probes with a fixed worker pool, without queuing a task per payload."""
    iterator = iter(items)

    async def worker() -> None:
        while not (should_stop and should_stop()):
            try:
                item = next(iterator)
            except StopIteration:
                return
            await probe(item)

    workers = [asyncio.create_task(worker()) for _ in range(max(1, min(20, limit)))]
    try:
        await asyncio.gather(*workers)
    finally:
        for task in workers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


class AsyncHttpClient:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        limits: ScanLimits,
        verify_tls: bool = False,
        circuit_after: int = 20,
    ) -> None:
        self.session = session
        self.semaphore = semaphore
        self.limits = limits
        self.verify_tls = verify_tls
        self.circuit_after = circuit_after
        self.failure_streak = 0
        self.circuit_open = False
        self.circuit_reason = ""
        self._start_lock = asyncio.Lock()
        self._request_starts = 0
        self.requests_started = 0
        self.requests_completed = 0
        self.requests_waiting = 0
        self.requests_active = 0
        self.last_completed_at = time.monotonic()

    def _stop_requested(self) -> bool:
        control = self.limits.runtime_control
        return self.circuit_open or bool(control and control.finish_requested)

    def open_circuit(self, reason: str) -> None:
        self.circuit_open = True
        self.circuit_reason = reason

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = False,
        timeout: float | None = None,
    ) -> HttpResult | None:
        if self._stop_requested():
            return None
        if self.limits.runtime_control:
            await self.limits.runtime_control.wait_if_paused()
            if self.limits.runtime_control.finish_requested:
                return None
        self.requests_waiting += 1
        try:
            await self._throttle_request_start()
            if self._stop_requested():
                return None
            return await self._perform_request(
                method, url, params=params, data=data, headers=headers,
                allow_redirects=allow_redirects, timeout=timeout,
            )
        finally:
            self.requests_waiting -= 1

    async def _perform_request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> HttpResult | None:
        async with self.semaphore:
            if self.limits.runtime_control:
                await self.limits.runtime_control.wait_if_paused()
            if self._stop_requested():
                return None
            start = time.monotonic()
            self.requests_started += 1
            self.requests_active += 1
            cancelled = False
            try:
                timeout = kwargs.pop("timeout", None)
                req_timeout = aiohttp.ClientTimeout(total=timeout or self.limits.timeout)
                async with self.session.request(
                    method.upper(),
                    url,
                    timeout=req_timeout,
                    ssl=None if self.verify_tls else False,
                    **kwargs,
                ) as response:
                    raw = await response.content.read(self.limits.max_body_bytes)
                    charset = response.charset or "utf-8"
                    text = raw.decode(charset, errors="replace")
                    headers_dict: dict[str, str] = {}
                    raw_headers: dict[str, list[str]] = {}
                    for key in response.headers.keys():
                        values = [str(v) for v in response.headers.getall(key, [])]
                        raw_headers[str(key)] = values
                        if str(key).lower() == "set-cookie":
                            headers_dict[str(key)] = values[-1] if values else ""
                        else:
                            headers_dict[str(key)] = ", ".join(values)
                    self.failure_streak = 0
                    content_type = next(
                        (value for key, value in headers_dict.items() if key.lower() == "content-type"),
                        "",
                    )
                    return HttpResult(
                        url=url,
                        final_url=str(response.url),
                        status=response.status,
                        headers=headers_dict,
                        text=text,
                        body_len=len(raw),
                        elapsed=time.monotonic() - start,
                        content_type=content_type,
                        raw_headers=raw_headers,
                        request_method=method.upper(),
                        request_url=str(response.url),
                        request_headers={str(k): str(v) for k, v in response.request_info.headers.items()},
                    )
            except asyncio.CancelledError:
                cancelled = True
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                self.failure_streak += 1
                if self.failure_streak >= self.circuit_after:
                    self.open_circuit(f"{self.failure_streak} HTTP failures/timeouts")
                return None
            finally:
                self.requests_active -= 1
                if not cancelled:
                    self.requests_completed += 1
                    self.last_completed_at = time.monotonic()

    async def _throttle_request_start(self) -> None:
        base_delay = max(0.0, float(self.limits.delay_seconds or 0.0))
        jitter_min = max(0.0, float(self.limits.jitter_min_seconds or 0.0))
        jitter_max = max(jitter_min, float(self.limits.jitter_max_seconds or jitter_min))
        batch_size = max(1, int(self.limits.throttle_batch_size or 1))
        if base_delay <= 0 and jitter_max <= 0:
            return
        async with self._start_lock:
            if self._stop_requested():
                return
            self._request_starts += 1
            if self._request_starts % batch_size == 0:
                remaining = base_delay + random.uniform(jitter_min, jitter_max)
                while remaining > 0 and not self._stop_requested():
                    step = min(0.2, remaining)
                    await asyncio.sleep(step)
                    remaining -= step


class VulnerabilityModule:
    name = "base"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError
