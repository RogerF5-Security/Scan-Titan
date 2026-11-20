# Reconocimiento externo controlado

Scan Titan ejecuta Katana y httpx de ProjectDiscovery como wrappers de recon cuando
estan instalados y habilitados en `config/config.yaml`. La ejecucion es asincrona,
con una cola de dos pendientes, un proceso externo activo por objetivo, salida
stdout/stderr capturada, cancelacion y tiempos maximos de 90/30 segundos.

El resultado de Katana se filtra por esquema, host y puerto exactos antes de
agregar rutas al mapa. El resultado de httpx se usa para estado, servidor y
tecnologias. Ambos son inteligencia de superficie: una respuesta o una ruta
descubierta no constituye una vulnerabilidad confirmada.

Los binarios se buscan en `tools/bin`, `~/go/bin` y `PATH`. El instalador puede
instalarlos con Go. En Windows, un ejecutable llamado `httpx.exe` puede pertenecer
al paquete Python `httpx`; Scan Titan comprueba las opciones del CLI oficial y
omite el binario equivocado. Tambien puede indicarse un binario explicitamente en
la configuracion de cada herramienta.

La salida cruda y los eventos de duracion, codigo de salida y error se guardan en
`audit_reports/external reports` y en la observabilidad externa existente. Para
deshabilitar una herramienta, establece `tools.katana.enabled` o
`tools.httpx.enabled` en `false`.

## Validacion manual basica

sqlmap y XSSer no se lanzan automaticamente. Antes de una validacion manual,
selecciona una URL y un parametro observados, limita el numero de solicitudes,
usa solo metodos de lectura, define un tiempo maximo y compara la respuesta con
una peticion base. Interrumpe la prueba si aparecen errores repetidos, bloqueo o
cambios inesperados de estado. No uses funciones de extraccion de datos, acceso al
sistema, alteracion de registros ni fuerza bruta como parte de esta fase basica.

Un indicador de cualquiera de estas herramientas es una pista que requiere
confirmacion independiente. Solo los hallazgos con evidencia suficiente deben
entrar en el reporte TITAN.
