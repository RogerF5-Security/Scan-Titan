# Publicacion comunitaria

El propietario autorizo la publicacion de este repositorio el 8 de septiembre de 2026. La web se despliega en GitHub Pages desde `docs/web/`. Ninguna accion modifica automaticamente la visibilidad del repositorio.

## Contenido de la distribucion

Se incluyen el motor, configuracion de ejemplo sin credenciales, instaladores, pruebas, documentacion, plantilla publica, conocimiento general y las doce wordlists del proyecto. Nmap, Nuclei, ZAP, WhatWeb y sus recursos se instalan por separado; no se distribuyen sus binarios locales.

Las carpetas `reports/` y `audit_reports/` solo contienen marcadores vacios. Los objetivos del archivo versionado son ejemplos comentados. Los reportes internos, estado, evidencia, copias de seguridad y el exportador privado de detalle tecnico quedan fuera del paquete.

## Revision continua antes de una release

- Revisar la procedencia y condiciones de redistribucion de las wordlists y del recurso grafico incluido. La licencia MIT del proyecto no sustituye las licencias de terceros.
- Revisar el historial completo: retirar un archivo del ultimo commit no lo elimina de commits anteriores. La subida manual inicial incluyo archivos `.pyc`, que pueden contener rutas locales; se retiraron del seguimiento sin reescribir el historial.
- Mantener sin objetivos reales, tokens ni sesiones los archivos versionados. Para otra salida se puede definir `SCAN_TITAN_REPORTS_DIR` antes de iniciar el proceso.
- Completar pruebas de instalacion desde cero y escaneos de laboratorio con cada motor externo en ambos sistemas. Las pruebas automatizadas actuales son locales y no sustituyen esta validacion.
- Revisar los textos todavia no traducidos, la calidad de hallazgos y el informe de demostracion antes de preparar una release.

La publicacion del repositorio no equivale a certificar todos los escenarios de auditoria. Cada release publica requiere completar las verificaciones pendientes de esta lista.
