# Scan Titan 22.3.0: acceso sin credenciales y pruebas web

## Qué comprueba

| Familia | Evidencia requerida | Cobertura y límites |
|---|---|---|
| SMB sin credenciales | Sesión nula o Guest con contraseña vacía y listado de raíz de un recurso de disco | Automático en 445/139. SMB1/2/3 con Impacket; alternativa Nmap para SMB1. IPC$ por sí solo no demuestra acceso a archivos. |
| Windows XP/2000/2003 | SO anunciado mediante SMB, separado del acceso comprobado | Identificación del servicio, no certificación del sistema instalado ni de una CVE. Windows 5.0/5.1 se reconocen como identificaciones heredadas. |
| SMB vulnerable | Dialecto SMB1, firma no obligatoria, autenticación heredada y estado positivo de MS17-010 NSE | No ejecuta EternalBlue ni código remoto. Un script ausente/error deja cobertura parcial. |
| FTP | Login anonymous aceptado; prueba LIST independiente y negociación AUTH TLS | No descarga archivos ni prueba escritura, FTP bounce o explotación de CVEs FTP. Un FTP público previsto requiere revisar la política de exposición. |
| IDOR/roles | Mismo objeto y contenido protegido accesibles por un perfil no autorizado | Requiere perfiles, objetos conocidos y marcadores/campos privados. No se infiere propiedad por números consecutivos. |
| RCE | Dos resultados aritméticos diferentes que no aparecen en el control | Command injection GET para POSIX/Windows. No cubre toda deserialización, carga de webshells, RCE ciego o vulnerabilidades específicas de producto. |
| SSRF | Cuerpo del servidor de prueba repetido dos veces, ausente del control y del payload reflejado | GET y respuesta visible; requiere URL controlada con marcador exclusivo. SSRF ciego/OAST no implementado. |
| Autenticación | Recurso protegido accesible por Unauth y referencia autenticada válida | SessionManager, cookies/JWT, roles y logout existentes. HTTP 200 o login page pública no bastan. MFA/SSO siguen siendo parciales. |

## Ejemplo de hallazgo

Ejemplo ilustrativo, no resultado de una auditoría real:

```text
High — SMB: recurso SharedDocs accesible sin credenciales
Servidor=LEGACY-LAB; SO anunciado=Windows XP SP3; identidad=null;
guest_mapping=True; recurso=SharedDocs; listado de raiz aceptado;
entradas=5; lectura de contenido y escritura no probadas.
```

El SO, SMBv1 y la firma se reportan también por separado. Una sesión nula aceptada
sin listado confirmado queda como inventario informativo, no como acceso a archivos.
No se afirma que toda la máquina carezca de autenticación: la evidencia identifica
el servicio, la identidad usada y el recurso concreto.

## Uso

```powershell
python main.py --target 192.0.2.10
```

Sustituir la dirección de ejemplo por el objetivo. `service_access` se ejecuta al
principio del pipeline. Si la URL no responde en dos solicitudes HTTP, se revisan
servicios y Nmap; los módulos y herramientas web quedan pendientes con razón explícita.
Eso no demuestra que no existan sitios web en otros puertos o nombres virtuales.

La configuración está en `stateful.services`. Puertos y recursos adicionales:

```yaml
stateful:
  services:
    enabled: true
    ftp_ports: [21, 2121]
    smb_ports: [445, 139]
    smb_shares: [SharedDocs, Public, Finanzas, 'C$', 'ADMIN$']
```

Las operaciones tienen límites de tiempo y cantidad. La alternativa Nmap prueba
solo los recursos configurados y hasta 8 por identidad; usa SMB1 y exige una
respuesta de listado válida, con límites y longitudes comprobados.
Impacket enumera recursos y admite SMB2/3. Los resultados conservan backend y estado.

### Dependencias

- FTP usa la biblioteca estándar de Python.
- Nmap debe estar instalado para `smb_security` y la alternativa SMB1.
- Linux instala Impacket con los requisitos generales.
- En Windows Impacket es opcional: `python -m pip install -r config/requirements-smb.txt`.
  Si no está disponible, se usa Nmap y se marca el alcance SMB1 como parcial.
- `--skip-external` y deshabilitar Nmap también desactivan esa alternativa.

### IDOR y SSRF

Adaptar `config/stateful.example.yaml`. Para IDOR, crear UserA/UserB, verificar su
identidad y declarar objetos de cada propietario mediante `stateful.roles.objects`.
`allowed_profiles` debe incluir los perfiles realmente autorizados; los campos
de `sensitive_json_paths` deben ser privados y propios del objeto.

Para SSRF, alojar un cuerpo con un marcador aleatorio de al menos 16 caracteres
en una URL controlada y declararla en `stateful.ssrf.probes`. El marcador no debe
estar en la URL ni en páginas normales de la aplicación. El escáner no sigue
redirecciones durante la comprobación, evitando confundir una redirección abierta
con una solicitud efectuada por el servidor.

## Evidencia y referencias

Los reportes TXT/JSON conservan `service_access`, `smb_nse`, `role_audit`,
`rce_checks`, `ssrf_status` y `http_availability`. Errores, timeouts o dependencia
ausente no equivalen a "sin vulnerabilidades" y conservan el historial anterior.

- [Nmap: descubrimiento del sistema SMB](https://nmap.org/nsedoc/scripts/smb-os-discovery.html)
- [Nmap: comprobación MS17-010](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html)
- [Nmap: modos de firma SMB2](https://nmap.org/nsedoc/scripts/smb2-security-mode.html)
- [Impacket: implementación SMBConnection](https://github.com/fortra/impacket/blob/master/impacket/smbconnection.py)
