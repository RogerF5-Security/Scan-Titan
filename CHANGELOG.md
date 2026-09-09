# Changelog de Scan Titan

Este archivo registra los cambios funcionales verificables de cada version.

Las versiones `21.3.2` y `21.3.3` documentan iteraciones locales verificadas que se consolidaron en `22.0.0`; no se publicaron como tags independientes.

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

[22.0.0]: https://github.com/RogerF5-Security/Scan-Titan/releases/tag/v22.0.0
