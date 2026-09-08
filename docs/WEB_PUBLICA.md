# Web publica de Scan Titan

La presentacion se mantiene en `docs/web/index.html`. Incluye CSS, JavaScript e imagenes locales; no requiere compilacion ni dependencias del escaner para visualizarse.

## Mismo repositorio, artefacto separado

- Repositorio del motor y la web: `https://github.com/RogerF5-Security/Scan-Titan`.
- Carpeta publicada: `docs/web/`, exclusivamente.
- URL: `https://rogerf5-security.github.io/Scan-Titan/`.

El propietario autorizo hacer publico Scan-Titan el 8 de septiembre de 2026. Pages se publica desde ese mismo repositorio, sin depender de un repositorio de usuario separado.

La publicacion separada creada inicialmente en el repositorio de usuario fue retirada; no se utiliza como origen de esta web.

## Activacion

En Settings > Pages > Source se utiliza GitHub Actions. El flujo "Publicar web de Scan Titan" se ejecuta cuando cambian la web, sus pruebas o el propio flujo en la rama main. Tambien permite ejecucion manual desde Actions.

Las acciones estan fijadas a commits concretos y el artefacto incluye solo `docs/web/`. El flujo no cambia la visibilidad del repositorio. Los cambios de visibilidad son decisiones separadas del propietario.

## Mantenimiento

1. Editar los archivos en `docs/web/` y mantener el idioma espanol.
2. Ejecutar `python -B -m unittest discover -s tests -p test_web_presentation.py -v`.
3. Revisar las vistas movil/escritorio, las pestanas, el mapa y la copia de comandos.
4. Sincronizar `docs/web/` y sus pruebas al repositorio Scan-Titan y publicar el commit.
5. Comprobar el flujo de Pages en GitHub Actions y la URL publica antes de dar el despliegue por terminado.

El flujo de Pages empaqueta exclusivamente `docs/web/`. Nunca ampliar el artefacto a la raiz del escaner, reportes, diccionarios, configuraciones privadas ni objetivos. Las imagenes de esta web son ejemplos sinteticos con dominios reservados, no evidencias reales.

La guia incluye descarga y preparacion para Windows y Linux. Los cambios del instalador o de los comandos deben reflejarse tambien en la web.

Las modificaciones de la web tambien se conservan en ambas copias de Plantilla0. No se cambian datos locales ni el comportamiento del escaner al actualizar esta presentacion.
