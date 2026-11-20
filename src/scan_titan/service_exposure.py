"""Classify safe Nmap NSE output and open services into evidence-bound findings.

Every rule keys on an exact, documented NSE output signature (or on the
service name Nmap identified on an open port). A rule never infers a
vulnerability from a related banner: when the evidence is only exposure of a
service, the finding says exposure and keeps a low severity.

Mitigation guidance in each rule follows secure-configuration practice:
require authentication, bind management/database services to private
interfaces, and replace cleartext protocols with authenticated encryption.
"""
from __future__ import annotations

import re
from typing import Any, Callable

OWASP_MISCONFIG = "A02:2025 - Configuración de seguridad incorrecta"
OWASP_CRYPTO = "A04:2025 - Fallos criptográficos"
OWASP_AUTH = "A07:2025 - Fallos de autenticación"

Rule = Callable[[str], "dict[str, str] | None"]


def _meta(title: str, severity: str, cwe: str, cvss: str, impact: str, remediation: str,
          *, owasp: str = OWASP_MISCONFIG, confidence: str = "high",
          strength: str = "Exact NSE output signature", fp_risk: str = "Low") -> dict[str, str]:
    return {
        "title": title, "severity": severity, "cwe": cwe, "cvss": cvss, "impact": impact,
        "remediation": remediation, "owasp": owasp, "confidence": confidence,
        "evidence_strength": strength, "false_positive_risk": fp_risk,
    }


def _ftp_anon(output: str) -> dict[str, str] | None:
    # Plain anonymous login is reported natively by service_access; NSE adds
    # the write-permission evidence that module deliberately never tests.
    if "Anonymous FTP login allowed" in output and "[NSE: writeable]" in output:
        return _meta(
            "FTP anonimo con directorio escribible", "High", "CWE-732", "8.2 (High)",
            "Un usuario sin credenciales puede subir archivos: alojamiento de malware, "
            "sustitucion de contenido servido o agotamiento de disco.",
            "Deshabilitar escritura anonima (anon_upload_enable=NO / permisos del directorio), "
            "o retirar el acceso anonimo y exigir SFTP/FTPS autenticado.", owasp=OWASP_AUTH)
    return None


def _http_methods(output: str) -> dict[str, str] | None:
    match = re.search(r"Potentially risky methods:\s*([A-Z ]+)", output)
    if not match:
        return None
    methods = sorted(set(match.group(1).split()))
    if not methods:
        return None
    write = [m for m in methods if m in {"PUT", "DELETE", "MOVE", "COPY", "PROPPATCH", "MKCOL"}]
    severity = "Medium" if write else "Low"
    return _meta(
        f"Metodos HTTP riesgosos anunciados: {', '.join(methods)}", severity, "CWE-650",
        "5.3 (Medium)" if write else "3.7 (Low)",
        "El servidor anuncia metodos que, si estan implementados sin control de acceso, "
        "permiten modificar recursos (PUT/DELETE/WebDAV) o reflejar cabeceras (TRACE).",
        "Restringir los verbos al minimo necesario en el servidor/proxy y validar que PUT/DELETE "
        "requieran autenticacion. Confirmar con una peticion controlada antes de elevar severidad.",
        confidence="medium", strength="OPTIONS response; implementation not proven",
        fp_risk="Medium")


def _nfs_showmount(output: str) -> dict[str, str] | None:
    exports = [line.strip(" |_") for line in output.splitlines() if line.strip(" |_").startswith("/")]
    if not exports:
        return None
    world = any(re.search(r"(\s\*\s*$|\s\*\s|everyone|0\.0\.0\.0/0)", item) for item in exports)
    return _meta(
        "NFS exporta recursos" + (" a cualquier cliente" if world else " visibles sin autenticacion"),
        "High" if world else "Medium", "CWE-284", "7.5 (High)" if world else "5.3 (Medium)",
        "Las exportaciones NFS pueden montarse desde la red; con exportacion abierta se exponen "
        "o modifican archivos con la identidad UID del cliente.",
        "Restringir /etc/exports a hosts concretos, usar root_squash, NFSv4 con Kerberos (sec=krb5p) "
        "y filtrar 111/2049 en el perimetro.", owasp=OWASP_AUTH)


def _vnc_info(output: str) -> dict[str, str] | None:
    if re.search(r"(?im)^\s*\|?\s*None \(1\)\s*$", output) or "Security types:\n|     None" in output:
        return _meta(
            "VNC acepta conexiones sin autenticacion (security type None)", "Critical", "CWE-306",
            "9.8 (Critical)",
            "Cualquier cliente obtiene control interactivo del escritorio remoto sin credenciales.",
            "Deshabilitar el tipo de seguridad None, exigir autenticacion fuerte y publicar VNC solo "
            "por tunel cifrado/VPN.", owasp=OWASP_AUTH)
    return None


def _x11_access(output: str) -> dict[str, str] | None:
    if "X server access is granted" in output:
        return _meta(
            "Servidor X11 accesible sin control de acceso", "High", "CWE-284", "8.1 (High)",
            "Permite capturar pantalla y pulsaciones e inyectar eventos de teclado en la sesion grafica.",
            "Habilitar xhost/xauth restrictivo, deshabilitar escucha TCP (-nolisten tcp) y filtrar 6000-6063.",
            owasp=OWASP_AUTH)
    return None


def _redis_info(output: str) -> dict[str, str] | None:
    upper = output.upper()
    if (re.search(r"(?im)^\s*\|?\s*Version:\s*\S+", output)
            and "NOAUTH" not in upper and "ERROR" not in upper):
        return _meta(
            "Redis responde comandos sin autenticacion", "High", "CWE-306", "8.6 (High)",
            "Lectura/escritura de datos en cache y, segun la version, escritura de archivos o "
            "ejecucion de codigo mediante CONFIG/MODULE LOAD.",
            "Exigir requirepass/ACL, protected-mode yes, bind a interfaces privadas y renombrar comandos "
            "administrativos.", owasp=OWASP_AUTH)
    return None


def _memcached_info(output: str) -> dict[str, str] | None:
    if re.search(r"(?im)^\s*\|?\s*(Version|Uptime|Process ID):", output):
        return _meta(
            "Memcached accesible sin autenticacion", "Medium", "CWE-306", "6.5 (Medium)",
            "Lectura y modificacion de objetos en cache; con UDP habilitado es amplificador de DDoS.",
            "Bind a 127.0.0.1/red privada, deshabilitar UDP (-U 0) y habilitar SASL si la red no es de confianza.",
            owasp=OWASP_AUTH)
    return None


def _mongodb(output: str) -> dict[str, str] | None:
    lowered = output.lower()
    if any(marker in lowered for marker in ("unauthorized", "requires authentication", "auth failed")):
        return None
    if re.search(r"(?im)\b(databases|totalSize|sizeOnDisk|version\s*=)", output):
        return _meta(
            "MongoDB responde consultas sin autenticacion", "High", "CWE-306", "8.6 (High)",
            "Enumeracion y posible extraccion o borrado de bases de datos completas.",
            "Habilitar security.authorization, bind a interfaces privadas y filtrar 27017.",
            owasp=OWASP_AUTH)
    return None


def _couchdb(output: str) -> dict[str, str] | None:
    if re.search(r"(?m)^\s*\|?\s*\d+\s*[:=]\s*\S+", output) or "_users" in output:
        return _meta(
            "CouchDB lista bases de datos sin autenticacion", "High", "CWE-306", "7.5 (High)",
            "Lectura de documentos y, en modo admin party, control administrativo de la instancia.",
            "Configurar administradores, require_valid_user=true y filtrar 5984.", owasp=OWASP_AUTH)
    return None


def _rsync(output: str) -> dict[str, str] | None:
    modules = [line for line in output.splitlines() if re.match(r"^\s*\|?\s*\S+\s+\S", line)]
    if modules and "ERROR" not in output.upper():
        return _meta(
            "rsync lista modulos sin autenticacion", "Medium", "CWE-306", "5.3 (Medium)",
            "Los modulos listados pueden permitir descarga (o subida) de archivos sin credenciales.",
            "Definir auth users/secrets file por modulo, read only = yes y filtrar 873.", owasp=OWASP_AUTH,
            confidence="medium", strength="Module listing; per-module read access not proven", fp_risk="Medium")
    return None


def _rdp_encryption(output: str) -> dict[str, str] | None:
    # The NSE example reports 40/56-bit SUCCESS even at "Encryption level: High",
    # so weak RC4 is only claimed when the server-declared level allows it.
    weak_rc4 = (re.search(r"(40|56)-bit RC4:\s*SUCCESS", output)
                and re.search(r"RDP Encryption level:\s*(Low|Client Compatible)", output, re.I))
    native = re.search(r"Native RDP:\s*SUCCESS", output)
    if native:
        return _meta(
            "RDP no exige Network Level Authentication (NLA)", "Medium", "CWE-287", "5.9 (Medium)",
            "La sesion grafica se negocia antes de autenticar: expone la pantalla de inicio a "
            "fuerza bruta/MitM y amplia la superficie de fallos pre-autenticacion (p. ej. BlueKeep).",
            "Exigir NLA (SecurityLayer=2, UserAuthentication=1), TLS 1.2+ y publicar RDP solo por VPN/RD Gateway.",
            owasp=OWASP_AUTH)
    if weak_rc4:
        return _meta(
            "RDP acepta cifrado RC4 de 40/56 bits", "Medium", "CWE-327", "5.9 (Medium)",
            "El canal RDP puede negociarse con cifrado debil y descifrarse por un atacante en ruta.",
            "Fijar MinEncryptionLevel=3 (High) o FIPS y forzar capa TLS/NLA.", owasp=OWASP_CRYPTO)
    return None


def _open_proxy(output: str) -> dict[str, str] | None:
    if re.search(r"Potentially OPEN proxy", output, re.I):
        return _meta(
            "Proxy abierto potencial", "High", "CWE-441", "7.2 (High)",
            "Terceros pueden encaminar trafico a traves del host (anonimizacion, abuso, acceso a red interna).",
            "Exigir autenticacion en el proxy y restringir los origenes y destinos permitidos.",
            confidence="medium", strength="NSE proxy request through target", fp_risk="Medium")
    return None


def _docker(output: str) -> dict[str, str] | None:
    if re.search(r"(?im)\b(ApiVersion|Version|GoVersion)\b", output):
        return _meta(
            "API de Docker expuesta sin TLS", "Critical", "CWE-306", "9.8 (Critical)",
            "El control de la API Docker equivale a root en el host (contenedores privilegiados, montaje del FS).",
            "Desactivar el socket TCP o protegerlo con TLS mutuo (--tlsverify) y filtrar 2375/2376.",
            owasp=OWASP_AUTH)
    return None


def _ntlm_info(output: str) -> dict[str, str] | None:
    if re.search(r"(?im)(NetBIOS_Domain_Name|DNS_Domain_Name|Target_Name):", output):
        return _meta(
            "Divulgacion de informacion interna via NTLM", "Low", "CWE-200", "3.7 (Low)",
            "El desafio NTLM revela nombres de dominio, host y version de Windows utiles para ataques dirigidos.",
            "Deshabilitar autenticacion NTLM en el servicio expuesto o publicarlo solo tras VPN/proxy.",
            confidence="high", strength="NTLM challenge fields")
    return None


def _ssl_known_key(output: str) -> dict[str, str] | None:
    if re.search(r"Found in .+", output):
        return _meta(
            "Certificado TLS con clave privada publicamente comprometida", "High", "CWE-321", "7.4 (High)",
            "La clave privada figura en bases publicas: el trafico puede descifrarse o suplantarse.",
            "Generar un nuevo par de claves, reemitir el certificado y revocar el anterior.",
            owasp=OWASP_CRYPTO)
    return None


def _snmp_info(output: str) -> dict[str, str] | None:
    # snmp-info performs unauthenticated SNMPv3 engine discovery (by protocol
    # design). It proves exposure only, never a default community.
    if re.search(r"(?im)(engineIDFormat|snmpEngineTime|snmpEngineBoots)", output):
        return _meta(
            "SNMP expuesto a la red (responde descubrimiento SNMPv3)", "Low", "CWE-668", "3.7 (Low)",
            "El agente SNMP es alcanzable y revela fabricante y tiempo de actividad; habilita ataques "
            "de diccionario de comunidades/usuarios.",
            "Filtrar 161/UDP a las estaciones de gestion y usar SNMPv3 authPriv.",
            strength="SNMPv3 engine discovery response")
    return None


def _snmp_sysdescr(output: str) -> dict[str, str] | None:
    # snmp-sysdescr queries sysDescr with the community 'public' (NSE default).
    text = output.strip()
    if text and "ERROR" not in text.upper() and not text.lower().startswith("timeout"):
        return _meta(
            "SNMP responde con la comunidad por defecto 'public'", "Medium", "CWE-1392", "5.3 (Medium)",
            "Cualquiera puede leer el MIB: inventario, interfaces, rutas, procesos y software instalado.",
            "Eliminar las comunidades public/private, migrar a SNMPv3 authPriv y filtrar 161/UDP.",
            owasp=OWASP_AUTH, strength="sysDescr returned for community 'public'")
    return None


def _dns_recursion(output: str) -> dict[str, str] | None:
    if "Recursion appears to be enabled" in output:
        return _meta(
            "Servidor DNS con recursion abierta", "Medium", "CWE-406", "5.8 (Medium)",
            "El resolver atiende consultas de terceros: amplificacion DDoS y envenenamiento de cache.",
            "Limitar allow-recursion a redes internas o deshabilitar recursion en servidores autoritativos.")
    return None


def _ipmi_version(output: str) -> dict[str, str] | None:
    if re.search(r"(?im)Version:\s*IPMI-2\.0", output) or "PassAuth" in output:
        return _meta(
            "Interfaz IPMI/BMC expuesta", "Medium", "CWE-668", "5.3 (Medium)",
            "IPMI 2.0 entrega hashes RAKP de usuarios validos a cualquiera (diseno del protocolo), "
            "permitiendo descifrado offline de credenciales del BMC.",
            "Aislar los BMC en una VLAN de gestion, deshabilitar IPMI sobre LAN si no se usa y "
            "usar contrasenas largas unicas.", confidence="high",
            strength="IPMI Get Channel Auth Capabilities response")
    return None


SCRIPT_RULES: dict[str, Rule] = {
    "ftp-anon": _ftp_anon,
    "http-methods": _http_methods,
    "nfs-showmount": _nfs_showmount,
    "vnc-info": _vnc_info,
    "x11-access": _x11_access,
    "redis-info": _redis_info,
    "memcached-info": _memcached_info,
    "mongodb-info": _mongodb,
    "mongodb-databases": _mongodb,
    "couchdb-databases": _couchdb,
    "rsync-list-modules": _rsync,
    "rdp-enum-encryption": _rdp_encryption,
    "http-open-proxy": _open_proxy,
    "socks-open-proxy": _open_proxy,
    "docker-version": _docker,
    "http-ntlm-info": _ntlm_info,
    "rdp-ntlm-info": _ntlm_info,
    "ms-sql-ntlm-info": _ntlm_info,
    "smtp-ntlm-info": _ntlm_info,
    "telnet-ntlm-info": _ntlm_info,
    "imap-ntlm-info": _ntlm_info,
    "pop3-ntlm-info": _ntlm_info,
    "ssl-known-key": _ssl_known_key,
    # sshv1 is reported by the dedicated ssh_security profile (ssh_audit.py).
    "snmp-info": _snmp_info,
    "snmp-sysdescr": _snmp_sysdescr,
    "dns-recursion": _dns_recursion,
    "ipmi-version": _ipmi_version,
}

# Safe, non-default discovery scripts that produce the evidence above. They are
# appended to the base Nmap script expression; none brute-forces or writes.
EXTRA_SAFE_SCRIPTS = (
    "nfs-showmount", "redis-info", "memcached-info", "mongodb-databases", "couchdb-databases",
    "rsync-list-modules", "rdp-enum-encryption",
)

# UDP services worth one probe each; scripts are safe/default category only.
UDP_PORTS = "53,69,111,123,137,161,500,623,1434,1900,5353,11211"
UDP_SCRIPTS = ("dns-recursion,ntp-info,snmp-info,snmp-sysdescr,ipmi-version,ipmi-cipher-zero,"
               "ike-version,nbstat,ms-sql-info,upnp-info")


def classify_script(script_id: str, output: str) -> dict[str, str] | None:
    """Return finding metadata for an exact exposure signature, else None."""
    rule = SCRIPT_RULES.get(str(script_id or "").lower().strip())
    if rule is None or not output:
        return None
    try:
        return rule(output)
    except re.error:
        return None


# Service names as reported by Nmap -sV (service@name) on an open port.
CLEARTEXT_SERVICES: dict[str, tuple[str, str]] = {
    "telnet": ("Telnet", "High"),
    "login": ("rlogin", "High"),
    "shell": ("rsh", "High"),
    "exec": ("rexec", "High"),
    "tftp": ("TFTP", "Medium"),
    "finger": ("finger", "Low"),
}

DATA_SERVICES = {
    "mysql", "postgresql", "ms-sql-s", "oracle-tns", "mongodb", "mongod", "redis", "memcache",
    "memcached", "elasticsearch", "cassandra", "couchdb", "docker", "kubernetes", "etcd-client",
    "zookeeper", "amqp", "rabbitmq", "kafka", "ldap", "vnc", "ms-wbt-server", "rdp", "x11",
    "java-rmi", "rmiregistry", "ajp13", "nfs", "rpcbind", "winrm", "wsman", "ipmi",
}


def classify_service(port: str, protocol: str, service_name: str, product: str = "",
                     tunnel: str = "") -> dict[str, str] | None:
    """Classify an open port by its identified service (exposure, not exploitability)."""
    name = str(service_name or "").lower().strip()
    if not name or name in {"?", "unknown", "tcpwrapped"}:
        return None
    if name in CLEARTEXT_SERVICES and tunnel != "ssl":
        label, severity = CLEARTEXT_SERVICES[name]
        return _meta(
            f"Servicio de administracion en texto claro expuesto: {label}", severity, "CWE-319",
            "7.4 (High)" if severity == "High" else ("5.9 (Medium)" if severity == "Medium" else "3.7 (Low)"),
            "Credenciales y sesion viajan sin cifrar y pueden capturarse o secuestrarse en la ruta.",
            "Deshabilitar el servicio y sustituirlo por SSH/SFTP; si es imprescindible, limitarlo a una red de gestion.",
            owasp=OWASP_CRYPTO, strength="Nmap -sV service identification")
    if name == "ftp":
        return None  # service_access verifies AUTH TLS directly; avoid a banner-only duplicate.
    if name == "docker" and "docker" in str(product).lower():
        # docker-version (run by -sV) only fills product/version after an
        # unauthenticated GET /version succeeded against the Engine API.
        return _meta(
            f"API de Docker responde sin autenticacion ({port}/{protocol})", "Critical", "CWE-306",
            "9.8 (Critical)",
            "El control de la API Docker equivale a root en el host (contenedores privilegiados, montaje del FS).",
            "Desactivar el socket TCP o protegerlo con TLS mutuo (--tlsverify) y filtrar 2375/2376.",
            owasp=OWASP_AUTH, strength="Unauthenticated Docker Engine /version response (docker-version NSE)")
    if name in DATA_SERVICES:
        return _meta(
            f"Servicio de datos/administracion accesible desde el origen del escaneo: {name} ({port}/{protocol})",
            "Low", "CWE-668", "3.7 (Low)",
            "La exposicion de bases de datos, colas o interfaces de administracion amplia la superficie "
            "para fuerza bruta y explotacion de CVE del servicio. No prueba acceso sin credenciales.",
            "Restringir el puerto con firewall/ACL a los clientes necesarios o publicarlo solo por VPN.",
            confidence="high", strength="Open port with Nmap service identification", fp_risk="Low")
    return None


def finding_kwargs(meta: dict[str, Any]) -> dict[str, Any]:
    """Map rule metadata onto Finding keyword arguments."""
    return {
        "severity": meta["severity"], "cwe": meta["cwe"], "cvss": meta["cvss"], "impact": meta["impact"],
        "remediation": meta["remediation"], "recommendation": meta["remediation"], "owasp": meta["owasp"],
        "confidence": meta["confidence"], "evidence_strength": meta["evidence_strength"],
        "false_positive_risk": meta["false_positive_risk"],
    }
