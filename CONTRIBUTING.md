# Cómo contribuir a Scan Titan

Gracias por tu interés en mejorar Scan Titan. Este documento describe cómo
proponer cambios, reportar problemas y mantener la calidad del proyecto.

## Antes de empezar

- Scan Titan es una herramienta de **auditoría de seguridad autorizada**. Úsala
  solo contra objetivos para los que tengas permiso explícito por escrito.
- Requiere **Python 3.11+** en Windows o Linux.

## Entorno de desarrollo

```bash
git clone https://github.com/RogerF5-Security/Scan-Titan.git
cd Scan-Titan
python -m venv .venv
# Windows: .venv\Scripts\activate | Linux: source .venv/bin/activate
pip install -e .
```

Coloca tus objetivos autorizados en `targets/targets.txt` (está en `.gitignore`;
versiona solo `targets/targets.txt.example`).

## Ejecutar las pruebas

```bash
pip install pytest
pytest tests/
```

Toda contribución que cambie comportamiento debe incluir o actualizar pruebas en
`tests/`. No se aceptan cambios que rompan la batería existente.

## Flujo de contribución

1. Abre primero un *issue* describiendo el problema o la mejora.
2. Crea una rama desde `main`: `git checkout -b tipo/descripcion-corta`.
3. Haz commits pequeños y descriptivos (prefijos `feat:`, `fix:`, `docs:`,
   `ci:`, `chore:`). El repositorio usa un hook que bloquea el commit de
   objetivos reales y secretos.
4. Asegúrate de que `pytest` pasa y de que no subes datos de cliente,
   credenciales ni resultados de escaneos reales.
5. Abre un *Pull Request* hacia `main` explicando el cambio y cómo se probó.
   El workflow de validación (`.github/workflows/validacion.yml`) debe quedar en
   verde antes de mergear.

## Estilo de código

- Python 3.11+, tipado donde aporte claridad, funciones con responsabilidad única.
- Líneas de hasta 100 caracteres; nombres descriptivos.
- Docstrings en las clases y métodos públicos.

## Reporte de errores de seguridad

Las vulnerabilidades **no** se reportan como *issues* públicos. Sigue el proceso
de [SECURITY.md](SECURITY.md).

## Licencia

Al contribuir aceptas que tu aporte se publique bajo la licencia
[MIT](LICENSE) del proyecto.
