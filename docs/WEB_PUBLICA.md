# Web publica de Scan Titan

La presentacion se mantiene en `docs/web/index.html`. Incluye CSS, JavaScript e imagenes locales; no requiere compilacion ni dependencias del escaner para visualizarse.

## Mismo repositorio, artefacto separado

- Repositorio del motor y la web: `https://github.com/RogerF5-Security/Scan-Titan`.
- Carpeta publicada: `docs/web/`, exclusivamente.
- URL prevista: `https://rogerf5-security.github.io/Scan-Titan/`.

El repositorio sigue privado. El 8 de septiembre de 2026 GitHub rechazo la activacion de Pages: el plan actual no permite publicarlo desde este repositorio privado (HTTP 422). La web queda preparada, no publicada desde Scan-Titan. Se requiere habilitar un plan compatible o autorizar por separado que el repositorio sea publico.

La publicacion separada creada inicialmente en el repositorio de usuario fue retirada; no se utiliza como origen de esta web.

## Activacion

Una vez resuelto el requisito del plan o de visibilidad, activar Settings > Pages > Source > GitHub Actions en Scan-Titan. Ejecutar el flujo "Publicar web de Scan Titan" desde Actions. El flujo es manual hasta la activacion de Pages para no generar despliegues fallidos mientras exista el bloqueo.

Las acciones estan fijadas a commits concretos y el artefacto incluye solo `docs/web/`. Publicar Pages no debe cambiar la visibilidad del repositorio. Si se decide abrir el repositorio, revisar previamente el historial, licencias y contenido del motor; esa decision no forma parte de la publicacion de la web.

## Mantenimiento

1. Editar los archivos en `docs/web/` y mantener el idioma espanol.
2. Ejecutar `python -B -m unittest discover -s tests -p test_web_presentation.py -v`.
3. Revisar las vistas movil/escritorio, las pestanas, el mapa y la copia de comandos.
4. Sincronizar `docs/web/` y sus pruebas al repositorio Scan-Titan y publicar el commit.
5. Ejecutar el flujo de Pages y comprobar GitHub Actions y la URL publica, una vez habilitado el servicio.

El flujo de Pages empaqueta exclusivamente `docs/web/`. Nunca ampliar el artefacto a la raiz del escaner, reportes, diccionarios, configuraciones privadas ni objetivos. Las imagenes de esta web son ejemplos sinteticos con dominios reservados, no evidencias reales.

La guia muestra comandos para usuarios que ya disponen del proyecto e indica que el codigo permanece privado. Actualizar ese aviso cuando se apruebe el lanzamiento publico del motor.

Las modificaciones de la web tambien se conservan en ambas copias de Plantilla0. No se cambian datos locales ni el comportamiento del escaner al actualizar esta presentacion.
