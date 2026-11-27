# Política de seguridad

## Versiones con soporte

Se da soporte de seguridad a la última versión publicada del motor. Consulta la
versión vigente en [`VERSION`](VERSION) y el [CHANGELOG](CHANGELOG.md).

| Versión | Soporte |
| --- | --- |
| 22.x (última) | ✅ |
| Anteriores | ❌ |

## Cómo reportar una vulnerabilidad

**No abras un issue público** para reportar vulnerabilidades.

Usa el reporte privado de GitHub: pestaña **Security → Report a vulnerability**
del repositorio ([Private Vulnerability Reporting](https://github.com/RogerF5-Security/Scan-Titan/security/advisories/new)).
Si no tienes acceso, contacta por los canales del perfil
[RogerF5-Security](https://github.com/RogerF5-Security).

Incluye en tu reporte:

- Versión del motor afectada y entorno (SO, Python).
- Descripción del fallo y su impacto.
- Pasos de reproducción o prueba de concepto mínima.
- Cualquier mitigación conocida.

## Qué esperar

- **Acuse de recibo:** en un plazo de 5 días hábiles.
- **Evaluación y triaje:** se confirma o descarta y se asigna severidad.
- **Divulgación coordinada:** se corrige y se publica un aviso (GitHub Security
  Advisory) acreditando a quien reporta, salvo que prefiera el anonimato.

Se agradece la **divulgación responsable**: da un plazo razonable para corregir
antes de hacer público el detalle.

## Alcance y uso responsable

Scan Titan es una herramienta de auditoría ofensiva para **entornos
autorizados**. El reporte de seguridad cubre fallos en el propio código de Scan
Titan (p. ej. ejecución no intencionada, fuga de datos en reportes, inyección en
la generación de salidas), no el uso de la herramienta contra terceros sin
permiso.
