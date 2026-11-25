# Validación con laboratorio de verdad base

`tools/vuln_lab.py` mide qué detecta Scan Titan y si sus comandos de verificación
funcionan, sin escanear ningún sistema real. Todo ocurre en `127.0.0.1`.

## Qué contiene

| Tipo | Elementos |
|---|---|
| Vulnerabilidades esperadas (12) | XSS reflejado, SQLi por error, path traversal, redirección abierta, SSTI, `.env` expuesto, log de acceso expuesto, listado de directorio, CORS reflejado con credenciales en una API, CSP ausente, X-Frame-Options ausente, cookie sin atributos de seguridad |
| Controles negativos | Búsqueda con salida escapada (`/safe`), consulta parametrizada (`/item2`) |
| Señuelos de falso positivo | Rutas inexistentes con 200 (SPA catch-all con las palabras "error"/"warning"), WAF que responde 403 a `*.jsp` |

## Uso

```powershell
python -B tools/vuln_lab.py
```

```powershell
python -B tools/vuln_lab.py --with-external --keep --report lab.json
```

El script ejecuta `main.py` contra el laboratorio con un workspace temporal
(estado, reportes y objetivos aislados; no toca `audit_reports`), compara los
hallazgos con la verdad base y ejecuta cada `manual_command` en PowerShell,
comprobando que la salida contiene la prueba del hallazgo.

Sale con código 0 solo si la cobertura es completa, no hay falsos positivos y
todos los comandos reproducen su prueba. `--with-external` incluye Nmap,
Nuclei y ZAP (más lento).

## Límites

El laboratorio cubre las clases anteriores; no demuestra cobertura de lógica de
negocio, IDOR con identidades reales, SSRF ciego ni vulnerabilidades que
requieran autenticación. Un resultado 100 % aquí no garantiza el 100 % en
aplicaciones reales; sirve para detectar regresiones de detección y de falsos
positivos entre versiones.

## Puerta contra fugas

Antes de publicar código o reportes:

```powershell
python -B tools/leak_gate.py src tests tools docs config wordlists README.md CHANGELOG.md
```

La lista de bloqueo se construye en memoria con los hosts de
`targets/targets.txt`, los nombres de archivo de `audit_reports` y
`config/leak_denylist.local.txt` (opcional). Además busca claves privadas,
tokens, rutas de usuario de Windows y correos. Los valores se muestran
enmascarados.
