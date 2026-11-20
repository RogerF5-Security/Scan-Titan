# Versiones vulnerables y soporte

`python main.py` ejecuta `component_versions` despues de las herramientas externas. Los hallazgos usan el flujo normal de vulnerabilidades: consola, TXT/JSON diarios, estado local y Daily. No se atribuye un CVE solo porque un producto sea antiguo.

## Fuentes del catalogo local

Archivo: `data/version_catalog.json`. Cada fuente incluye URL, fecha de descarga y SHA-256 del JSON normalizado.

- [RetireJS](https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository-v4.json): rangos de versiones afectadas de librerias JavaScript, identificadores y referencias. Fuente bajo Apache-2.0; atribucion y licencia en `data/catalog_licenses/`.
- [PHP](https://api.github.com/repos/php/php-src/security-advisories?per_page=100): avisos publicos del proyecto, con rangos y versiones corregidas por rama. La paginacion no se trunca silenciosamente.
- [Apache HTTP Server](https://httpd.apache.org/security/vulnerabilities-httpd.json): avisos oficiales en formato CVE 4/5. Se respetan los rangos y las versiones exactas publicadas; no se infieren rangos ausentes ni cambios de estado no soportados.
- [endoflife.date](https://endoflife.date/docs/api): ciclos de PHP, Python, Django, Node.js, OpenSSL, Apache, nginx, Tomcat, jQuery y .NET. Datos bajo MIT; se conserva la licencia. Para PHP, [politica oficial de soporte](https://www.php.net/supported-versions.php).

No es una copia completa de NVD ni una garantia de cobertura universal. Nmap/Vulners y Nuclei siguen aportando sus propios avisos al pipeline existente. La ausencia de coincidencia en este catalogo no demuestra que una version sea segura.

## Evidencia y precision

Se recopilan marcadores explicitos de headers y servicios; versiones estructuradas de WhatWeb/Wappy; nombres de scripts versionados y comentarios de librerias JS. Se leen como maximo 12 scripts del mismo origen, sin ejecutar su contenido ni visitar CDN externos. La informacion detectada sin version precisa permanece en reconocimiento.

- `Software sin soporte de seguridad`: la rama observada supero su fecha de soporte upstream; puede existir soporte extendido o de una distribucion que debe verificarse.
- `Componente con aviso de seguridad`: version numerica exacta dentro de un rango publicado. Se reporta como correlacion por version, no como explotacion confirmada. Las extensiones, modulos, plataforma y configuracion indicados por el aviso pueden ser requisitos adicionales.
- Los sufijos de paquetes (por ejemplo Ubuntu/Debian) no se eliminan para atribuir CVE: requieren comprobar la revision del proveedor y posibles backports.
- CVSS se etiqueta como estimado por severidad del aviso, no como puntuacion medida del activo.

Los hallazgos incluyen version, fuente, rango o entrada afectada, referencia, recomendacion, comando de comprobacion e identificador estable. El Daily los presenta como candidatos a validar, separados del reconocimiento.

## Actualizacion

Por defecto se revisan fuentes cada 7 dias, una sola vez por ejecucion, con TLS, hasta 3 descargas simultaneas, 12 segundos por peticion y 35 segundos globales. Una fuente fallida no reemplaza su cache previa. Se descargan catalogos publicos; no se envian objetivos ni inventarios.

Forzar actualizacion sin escanear objetivos:

```text
python src/scan_titan/version_intelligence.py
```

`version_intelligence.enabled`, `auto_update` y `refresh_days` se configuran en `config/config.yaml`. Con `auto_update: false`, la correlacion sigue funcionando con la base local.

## Conteos del Daily

`Vigentes al corte` cuenta los registros ACTIVE de `scan_titan_state.json`. `Observados por dia` cuenta lo encontrado en los reportes de cada dia. Por ejemplo, 12 observaciones del dia pueden coexistir con 82 hallazgos vigentes acumulados; no son 70 hallazgos perdidos. No se reconstruye un historial de vigentes que no haya sido registrado.
