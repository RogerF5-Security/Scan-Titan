param(
    [switch]$SkipSystemTools
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$Requirements = Join-Path $ProjectRoot "config\requirements.txt"

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Test-Command {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Ok "$Name encontrado: $($cmd.Source)"
        return $true
    }
    Write-Warn "$Name no encontrado en PATH"
    return $false
}

function Test-WhatWebOfficial {
    param([string]$Command = "whatweb")
    $cmd = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return $false
    }
    try {
        $help = & $cmd.Source --help 2>&1 | Out-String
        if (($help -match "--log-json") -and ($help -match "--aggression")) {
            Write-Ok "Official WhatWeb detected: $($cmd.Source)"
            return $true
        }
        Write-Warn "A command named whatweb exists, but it does not expose official --log-json support: $($cmd.Source)"
        return $false
    } catch {
        Write-Warn "WhatWeb validation failed: $($_.Exception.Message)"
        return $false
    }
}

function Install-ProjectWhatWeb {
    $ToolRoot = Join-Path $ProjectRoot "tools"
    $WhatWebDir = Join-Path $ToolRoot "whatweb"
    $BinDir = Join-Path $ToolRoot "bin"
    $Wrapper = Join-Path $BinDir "whatweb.cmd"
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Warn "git unavailable; install official WhatWeb manually from https://github.com/urbanadventurer/WhatWeb"
        return
    }
    if (-not (Get-Command ruby -ErrorAction SilentlyContinue)) {
        Write-Warn "Ruby unavailable; install Ruby first to run official WhatWeb on Windows"
        return
    }
    New-Item -ItemType Directory -Force -Path $ToolRoot, $BinDir | Out-Null
    if (Test-Path (Join-Path $WhatWebDir ".git")) {
        Write-Step "Updating official WhatWeb repository"
        git -C $WhatWebDir pull --ff-only
    } elseif (Test-Path (Join-Path $WhatWebDir "whatweb")) {
        Write-Ok "Project-local WhatWeb source already present: $WhatWebDir"
    } elseif (Test-Path $WhatWebDir) {
        Write-Warn "WhatWeb directory exists but does not look complete: $WhatWebDir"
    } else {
        Write-Step "Cloning official WhatWeb repository"
        git clone https://github.com/urbanadventurer/WhatWeb $WhatWebDir
    }
    Set-Content -LiteralPath $Wrapper -Encoding ASCII -Value '@echo off
ruby "%~dp0..\whatweb\whatweb" %*'
    Write-Ok "Project-local WhatWeb wrapper ready: $Wrapper"
}

function Install-WingetPackage {
    param(
        [string]$PackageId,
        [string]$Label
    )
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warn "winget unavailable; install $Label manually if required"
        return
    }
    Write-Step "Installing/updating $Label with winget"
    try {
        winget install --id $PackageId --silent --accept-package-agreements --accept-source-agreements
    } catch {
        Write-Warn "winget install failed for ${Label}: $($_.Exception.Message)"
    }
}

function Test-ProjectDiscoveryHttpx {
    param([string]$Binary)
    if (-not $Binary -or -not (Test-Path -LiteralPath $Binary)) { return $false }
    try {
        $help = & $Binary -h 2>&1 | Out-String
        return ($LASTEXITCODE -eq 0 -and $help.Contains('-tech-detect') -and $help.Contains('-status-code'))
    } catch { return $false }
}

function Install-ProjectDiscoveryRecon {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Warn "Go no encontrado; instala Katana y httpx desde ProjectDiscovery para habilitar el recon adicional"
        return
    }
    $goBin = (& go env GOBIN 2>$null | Out-String).Trim()
    if (-not $goBin) {
        $goPath = (& go env GOPATH 2>$null | Out-String).Trim()
        $goBin = Join-Path $goPath 'bin'
    }
    $katanaBin = Join-Path $goBin 'katana.exe'
    $httpxBin = Join-Path $goBin 'httpx.exe'
    if (-not (Test-Path -LiteralPath $katanaBin)) {
        Write-Step 'Instalando Katana de ProjectDiscovery'
        & go install github.com/projectdiscovery/katana/cmd/katana@latest
        if ($LASTEXITCODE -ne 0) { Write-Warn 'Instalacion de Katana fallida' }
    }
    if (-not (Test-ProjectDiscoveryHttpx $httpxBin)) {
        Write-Step 'Instalando httpx de ProjectDiscovery'
        & go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        if ($LASTEXITCODE -ne 0) { Write-Warn 'Instalacion de httpx fallida' }
    }
    if (Test-Path -LiteralPath $katanaBin) { Write-Ok "Katana disponible: $katanaBin" }
    else { Write-Warn 'Katana no disponible tras instalacion' }
    if (Test-ProjectDiscoveryHttpx $httpxBin) { Write-Ok "httpx oficial disponible: $httpxBin" }
    else { Write-Warn 'httpx oficial no disponible tras instalacion' }
}

Write-Step "Scan Titan Community installer"
Write-Step "Raiz del proyecto: $ProjectRoot"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python no fue encontrado en PATH. Instala Python 3.11+ y ejecuta este instalador nuevamente."
}

Write-Step "Actualizando dependencias Python"
python -m pip install --upgrade pip
python -m pip install -r $Requirements

try {
    python -m playwright install chromium
} catch {
    Write-Warn "Instalacion de Playwright Chromium fallida: $($_.Exception.Message)"
}

if (-not $SkipSystemTools) {
    Install-ProjectDiscoveryRecon
    if (-not (Test-Command "nmap")) {
        Install-WingetPackage -PackageId "Insecure.Nmap" -Label "Nmap"
    }
    if (-not (Test-Command "nuclei")) {
        Install-WingetPackage -PackageId "ProjectDiscovery.Nuclei" -Label "Nuclei"
    }
    if (-not ((Test-Command "zap") -or (Test-Command "zap.bat") -or (Test-Command "zaproxy"))) {
        Install-WingetPackage -PackageId "ZAP.ZAP" -Label "OWASP ZAP"
    }
    if (-not (Test-WhatWebOfficial "whatweb")) {
        Install-ProjectWhatWeb
    }
    if (-not (Test-Command "wafw00f")) {
        Write-Step "Instalando wafw00f con pip"
        python -m pip install --upgrade wafw00f
    }
}

Write-Step "Actualizando plantillas Nuclei cuando este disponible"
if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    try {
        nuclei -update
        nuclei -ut
    } catch {
        Write-Warn "Actualizacion de Nuclei fallida: $($_.Exception.Message)"
    }
}

Write-Step "Validacion final"
python (Join-Path $ProjectRoot "main.py") --health-check
