# Scan Titan

Motor de auditoria automatizada en Python: reconocimiento, pruebas web, orquestacion de herramientas externas y reportes de vulnerabilidades. Preparacion de la edicion comunitaria para Pwn3d!.

**Version del motor:** 21.3.1. **Estado:** preparacion privada; la publicacion se realizara el dia del evento.

## Inicio rapido

Requiere Python 3.11 o posterior. Clona este repositorio y ejecuta el instalador de tu plataforma dentro de la carpeta del proyecto.

Windows, PowerShell:

```powershell
git clone https://github.com/RogerF5-Security/Scan-Titan.git
cd Scan-Titan
python -m venv .venv
.\.venv\Scripts\Activate.ps1
powershell -ExecutionPolicy Bypass -File .\install\install.ps1
```

Linux:

```bash
git clone https://github.com/RogerF5-Security/Scan-Titan.git
cd Scan-Titan
python3 -m venv .venv
source .venv/bin/activate
bash install/install.sh
```

Agrega un objetivo por linea en `targets/targets.txt`, revisa `config/config.yaml` y ejecuta:

```text
python main.py --health-check
python main.py
```

La plantilla contiene ejemplos comentados. Una vez definidos los objetivos, el escaneo se ejecuta sin confirmaciones interactivas. El instalador puede requerir permisos del sistema; revisa sus avisos sobre herramientas faltantes.

## Capacidades

- Reconocimiento de tecnologias, puertos, rutas, APIs y aplicaciones SPA.
- Integracion de Nmap, Nuclei, OWASP ZAP, WhatWeb, wafw00f, ffuf y subfinder cuando estan instalados.
- Modulos de auditoria HTTP, TLS, autenticacion, autorizacion e inyecciones.
- Matriz Excel, mapa del sitio desplegable y reconocimiento organizado por objetivo.
- Deduplicacion de hallazgos, comandos de validacion manual y evidencias de navegador.
- Dashboard diario e informe formal HTML con portada y detalle de hallazgos.

Los resultados requieren valorar su evidencia y confianza. Una prueba automatizada no garantiza encontrar todas las vulnerabilidades ni demostrar por si sola su explotabilidad.

## Comandos

| Comando | Funcion |
| --- | --- |
| `python main.py` | Ejecucion zero-touch |
| `python main.py --full` | Mayor cobertura y wordlists completas |
| `python main.py --monitor` | Monitor independiente |
| `python main.py --dashboard` | Regenerar dashboard con resultados existentes |
| `python main.py --health-check` | Comprobar estructura, dependencias y herramientas |
| `python main.py --help` | Opciones disponibles |

En Windows: `P` pausa, `R` reanuda, `F` finaliza y genera los reportes con lo encontrado; `Ctrl+C` interrumpe. Los procesos configurados con timeout `0` no tienen limite global de duracion y muestran actividad periodica. Las peticiones individuales conservan sus limites.

## Reportes

El lanzador incluido escribe por defecto en `audit_reports/`:

- `Daily_vulns_report.html`: dashboard de vulnerabilidades.
- `Formal_Audit_Report_Latest.html`: informe formal mas reciente.
- `Recon_Matrix.xlsx`: matriz de reconocimiento.
- `Recon_Sitemap.html`: arbol de rutas por objetivo.
- `External_Tools_Observability.html`: estado de herramientas externas.

Los reportes, sesiones y evidencias permanecen locales y estan excluidos de Git. El archivo versionado `targets/targets.txt` debe conservarse sin objetivos reales en los commits; `.gitignore` no oculta cambios de archivos que ya estan versionados.

## Documentacion y desarrollo

- [Manual completo](docs/README.md).
- [Presentacion web local](docs/web/index.html): abre el archivo en tu navegador.
- [Preparacion para el evento](docs/PUBLICACION.md).
- [Licencia MIT](LICENSE).

```text
python -B -m unittest discover -s tests -v
```

Las comprobaciones de GitHub validan el paquete y sus pruebas en Windows y Linux. No ejecutan escaneos contra objetivos externos ni acreditan una instalacion completa de todos los motores.
