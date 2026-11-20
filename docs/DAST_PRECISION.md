# Validación diferencial y descartes del Daily

El reporte exige validación independiente para XSS, SQLi y LFI/traversal, tanto de módulos internos como de ZAP/Nuclei. La confianza declarada por otro escáner no sustituye esta validación. Las alertas históricas sin prueba independiente pasan a **Por validar**; no se borran del historial ni se declaran corregidas.

## Criterios

- Se consulta la misma ruta sin el parámetro atacado y se preservan los demás parámetros. La URL enviada por la herramienta externa se reproduce sin decodificarla dos veces.
- HTTP 200 con similitud de DOM superior al 98%, sin evidencia específica de inyección, se registra como falso positivo de tolerancia de ruteo para ese payload. No se concluye que el parámetro sea siempre ignorado. Una prueba específica de XSS o contenido de archivo prevalece sobre la similitud: una inyección real puede ocupar menos del 2% de la página.
- XSS reflejado requiere el payload exacto en HTML, formando un elemento ejecutable fuera de comentarios, textarea, template, JSON y otros contextos inertes. El resultado acredita reflexión HTML insegura; la ejecución efectiva puede depender de CSP y condiciones del navegador. Los flujos estáticos source/sink son candidatos de recon. El XSS almacenado conserva su validación mediante diálogo canario exacto tras recargas independientes.
- SQLi por error requiere una firma explícita de error SQL nueva frente al baseline, repetida. `odbc`, `mysql`, `postgresql` o `syntax error` aislados no bastan. Tampoco bastan un HTTP 500 genérico o el eco del payload.
- SQLi booleana requiere baseline estable, dos pares TRUE/FALSE reproducibles y cambio de contenido/DOM. Se eliminan reflejos de los propios payloads antes de comparar. No se confirma únicamente por tamaños diferentes.
- SQLi temporal requiere tres series secuenciales con baseline, payload y control equivalente de demora cero. Se admiten retardos conocidos de 5 a 10 segundos. Se exige delta de al menos 5 segundos, controles estables y repetibilidad; un timeout o una demora aislada son inconclusos.
- Traversal requiere contenido estructurado de archivo ausente del baseline y repetido. `localhost` o `root:x:` aislados no bastan.
- Las rutas inexistentes se contrastan con otra ruta aleatoria. Catch-all, login por defecto y 404 equivalentes sin evidencia quedan fuera de vulnerabilidades.
- Bloqueos, errores de red, métodos que no pueden reproducirse con seguridad, límites y respuestas inestables son **INCONCLUSIVE**. No equivalen a ausencia de vulnerabilidad. El replay automático independiente está limitado a GET del mismo origen; POST, cabeceras y otros contextos requieren validación específica antes de reportarse.

Los resultados independientes incluyen estados, tamaños, hashes de cuerpo, similitud y URLs de control. Las pruebas manuales son comandos PowerShell con `curl.exe` que guardan cuerpos y cabeceras por separado y muestran estado, bytes y tiempo. No convierten una pareja TRUE/FALSE completa en un único payload.

## Descartar y restaurar

1. Ejecutar **Abrir_Daily.cmd**, o `python main.py --daily-live`.
2. Abrir **Inspeccionar → Descartar falso positivo** y registrar el motivo.
3. Consultar **Descartados → Inspeccionar → Restaurar hallazgo** para revertirlo.

El visor escucha solo en `127.0.0.1`, usa un puerto dinámico y valida Host, Origin y token contra escrituras de otros sitios. Guarda las decisiones mediante reemplazo atómico en `audit_reports/finding_triage.json`. El motor y el Daily las leen en ejecuciones posteriores. Cerrar el visor no borra decisiones. Las reglas se limitan a origen, ruta, método, parámetro y familia; cambiar el payload o el motor detector no resucita el mismo falso positivo. Otra ruta, parámetro, método u origen conserva su evaluación.

Al abrir directamente el HTML, el descarte permanece en ese navegador y se aplica al regenerar el mismo reporte. Para aplicarlo también al motor se debe abrir el visor local o exportar `finding_triage.json` a la carpeta `audit_reports`. Los controles de importar/exportar permiten trasladar las decisiones. Un fallo de almacenamiento se muestra al usuario; no se anuncia un descarte persistido si falló.

Los contadores vigentes, prioridades, activos y exportación CSV de la vista excluyen descartes. El histórico por día conserva las observaciones originales; no representa el total vigente. Restaurar una alerta histórica sin validación no la convierte en confirmada.

## Reconocimiento JavaScript

El reconocimiento analiza scripts inline y hasta 40 recursos/imports del mismo origen, con hasta 500.000 caracteres por recurso. Inspecciona hasta cuatro source maps referenciados y válidos (JSON v3), incluyendo fuentes embebidas con límites. No descarga scripts de terceros ni sigue redirecciones a otros orígenes. Conserva límites, truncamientos y recursos no consultados.

El Daily presenta endpoints y parámetros literales, ubicación/línea, source maps, flujos DOM directos candidatos, claves de almacenamiento y posibles credenciales con valores ocultos y hashes. No se prueban credenciales contra proveedores. Esos indicadores no se suman como vulnerabilidades. Las rutas del mismo origen alimentan el análisis posterior. El inventario actualizado se genera durante el próximo escaneo y se conserva en `recon_intelligence_<target>.json` y en cobertura.

## Comprobaciones

`python -B -m unittest discover -s tests -p test_injection_precision.py -v`

Las pruebas de precisión usan respuestas y transporte simulados; no envían tráfico a objetivos. Incluyen falsos positivos, controles positivos, persistencia de decisiones, restricciones de origen del visor y extracción de JS. No acreditan conectividad real ni ejecución en un navegador.

Referencias: [OWASP WSTG: SQL Injection](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/) y [ZAP: Active Scan Rules](https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/).
