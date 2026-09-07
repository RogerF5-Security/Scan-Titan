#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
REQUIREMENTS="$PROJECT_ROOT/config/requirements.txt"

step() { printf '[*] %s\n' "$1"; }
ok() { printf '[+] %s\n' "$1"; }
warn() { printf '[!] %s\n' "$1"; }

have() {
  command -v "$1" >/dev/null 2>&1
}

install_apt() {
  local package="$1"
  if have apt-get; then
    step "Installing $package with apt"
    sudo apt-get update
    sudo apt-get install -y "$package" || warn "apt install failed for $package"
  else
    warn "apt-get unavailable; install $package manually if required"
  fi
}

step "Instalador Scan Titan Community"
step "Raiz del proyecto: $PROJECT_ROOT"

if ! have "$PYTHON_BIN"; then
  warn "$PYTHON_BIN no encontrado; probando python"
  PYTHON_BIN="python"
fi
if ! have "$PYTHON_BIN"; then
  printf '[x] Python 3.11+ es requerido\n' >&2
  exit 1
fi

step "Actualizando dependencias Python"
"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r "$REQUIREMENTS"

if "$PYTHON_BIN" -m playwright install chromium; then
  ok "Playwright Chromium listo"
else
  warn "Instalacion de Playwright Chromium fallida"
fi

if ! have nmap; then
  install_apt nmap
else
  ok "nmap encontrado: $(command -v nmap)"
fi

if ! have nuclei; then
  if have go; then
    step "Instalando Nuclei con go"
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || warn "Instalacion de nuclei con go fallida"
    export PATH="$PATH:$HOME/go/bin"
  else
    warn "nuclei no encontrado y go no disponible; instala Nuclei manualmente"
  fi
else
  ok "nuclei encontrado: $(command -v nuclei)"
fi

if ! have zaproxy && ! have zap && ! have zap.sh; then
  install_apt zaproxy
else
  ok "OWASP ZAP encontrado"
fi

whatweb_official() {
  local cmd="${1:-whatweb}"
  have "$cmd" && "$cmd" --help 2>&1 | grep -q -- '--log-json' && "$cmd" --help 2>&1 | grep -q -- '--aggression'
}

install_project_whatweb() {
  local tool_root="$PROJECT_ROOT/tools"
  local whatweb_dir="$tool_root/whatweb"
  local bin_dir="$tool_root/bin"
  local wrapper="$bin_dir/whatweb"
  if ! have git || ! have ruby; then
    warn "git/ruby no disponibles; instala WhatWeb oficial manualmente desde https://github.com/urbanadventurer/WhatWeb"
    return
  fi
  mkdir -p "$tool_root" "$bin_dir"
  if [ -d "$whatweb_dir/.git" ]; then
    step "Actualizando repositorio oficial de WhatWeb"
    git -C "$whatweb_dir" pull --ff-only || warn "Actualizacion de WhatWeb fallida"
  elif [ -f "$whatweb_dir/whatweb" ]; then
    ok "Fuente local de WhatWeb ya presente: $whatweb_dir"
  elif [ -d "$whatweb_dir" ]; then
    warn "El directorio de WhatWeb existe pero no parece completo: $whatweb_dir"
  else
    step "Clonando repositorio oficial de WhatWeb"
    git clone https://github.com/urbanadventurer/WhatWeb "$whatweb_dir" || warn "Clonado de WhatWeb fallido"
  fi
  cat >"$wrapper" <<'EOF'
#!/usr/bin/env sh
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec ruby "$SCRIPT_DIR/../whatweb/whatweb" "$@"
EOF
  chmod +x "$wrapper"
  ok "Wrapper local de WhatWeb listo: $wrapper"
}

if ! whatweb_official whatweb; then
  if ! have whatweb; then
    install_apt whatweb
  fi
fi
if whatweb_official whatweb; then
  ok "WhatWeb oficial encontrado: $(command -v whatweb)"
else
  warn "whatweb no existe o no expone soporte oficial --log-json"
  install_project_whatweb
fi

if ! have wafw00f; then
  step "Instalando wafw00f con pip"
  "$PYTHON_BIN" -m pip install --upgrade wafw00f || warn "Instalacion de wafw00f fallida"
else
  ok "wafw00f encontrado: $(command -v wafw00f)"
fi

if have nuclei; then
  step "Actualizando plantillas Nuclei"
  nuclei -update || warn "Autoactualizacion de nuclei fallida"
  nuclei -ut || warn "Actualizacion de plantillas nuclei fallida"
fi

step "Validacion final"
"$PYTHON_BIN" "$PROJECT_ROOT/main.py" --health-check
