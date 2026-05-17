@echo off
setlocal enabledelayedexpansion

:: ==================================================================
:: DoBotShield - Download de Ferramentas de Teste de Seguranca
:: ==================================================================
:: Instala 8 ferramentas na pasta ferramentas\:
::   1. testssl.sh   (git clone + Docker image)
::   2. OWASP ZAP    (Docker image)
::   3. SQLMap       (git clone)
::   4. XSStrike     (git clone + pip)
::   5. Commix       (git clone)
::   6. wrk          (Docker build local)
::   7. nuclei       (binary download)
::
:: Pre-requisitos: git, python 3.x, docker, conexao com internet.
:: ==================================================================

set "TOOLS_DIR=%~dp0"
set "PROJECT_DIR=%TOOLS_DIR%.."
set "SQLMAP_DIR=%TOOLS_DIR%sqlmap"
set "XSSTRIKE_DIR=%TOOLS_DIR%XSStrike"
set "COMMIX_DIR=%TOOLS_DIR%commix"
set "TESTSSL_DIR=%TOOLS_DIR%testssl"
set "NUCLEI_DIR=%TOOLS_DIR%nuclei"

echo.
echo ==================================================================
echo   DoBotShield - Download de Ferramentas de Seguranca
echo   8 ferramentas para testes comparativos de WAF
echo ==================================================================
echo.

:: ---- Verificar pre-requisitos ----

echo [PRE] Verificando pre-requisitos...

where git >nul 2>&1
if errorlevel 1 (
    echo [ERRO] git nao encontrado. Instale via https://git-scm.com
    pause & exit /b 1
)
echo       git ............ OK

where python >nul 2>&1
if errorlevel 1 (
    echo [ERRO] python nao encontrado. Instale via https://python.org
    pause & exit /b 1
)
echo       python ......... OK

where docker >nul 2>&1
if errorlevel 1 (
    echo [ERRO] docker nao encontrado. Instale Docker Desktop.
    pause & exit /b 1
)
echo       docker ......... OK
echo.

:: ==================================================================
:: [1/8] testssl.sh
:: ==================================================================
echo [1/8] testssl.sh (Analise TLS/SSL)...
if exist "%TESTSSL_DIR%\testssl.sh" (
    echo       ja existe, atualizando...
    git -C "%TESTSSL_DIR%" pull --quiet
) else (
    echo       Clonando repositorio...
    git clone --depth 1 --quiet "https://github.com/drwetter/testssl.sh.git" "%TESTSSL_DIR%"
    if errorlevel 1 (
        echo [ERRO] Falha ao clonar testssl.sh.
        pause & exit /b 1
    )
)
echo       Baixando imagem Docker (drwetter/testssl.sh)...
docker pull drwetter/testssl.sh --quiet 2>nul
echo       OK.

:: ==================================================================
:: [2/8] OWASP ZAP
:: ==================================================================
echo.
echo [2/8] OWASP ZAP (Scanner DAST)...
echo       Baixando imagem Docker (ghcr.io/zaproxy/zaproxy:stable)...
docker pull ghcr.io/zaproxy/zaproxy:stable --quiet 2>nul
if errorlevel 1 (
    echo [AVISO] Falha ao baixar ZAP via ghcr.io, tentando Docker Hub...
    docker pull zaproxy/zap-stable --quiet 2>nul
)
echo       OK.

:: ==================================================================
:: [3/8] SQLMap
:: ==================================================================
echo.
echo [3/8] SQLMap (SQL Injection)...
if exist "%SQLMAP_DIR%\sqlmap.py" (
    echo       ja existe, atualizando...
    git -C "%SQLMAP_DIR%" pull --quiet
) else (
    echo       Clonando repositorio...
    git clone --depth 1 --quiet "https://github.com/sqlmapproject/sqlmap.git" "%SQLMAP_DIR%"
    if errorlevel 1 (
        echo [ERRO] Falha ao clonar sqlmap.
        pause & exit /b 1
    )
)
echo       OK.

:: ==================================================================
:: [4/8] XSStrike
:: ==================================================================
echo.
echo [4/8] XSStrike (XSS Fuzzing)...
if exist "%XSSTRIKE_DIR%\xsstrike.py" (
    echo       ja existe, atualizando...
    git -C "%XSSTRIKE_DIR%" pull --quiet
) else (
    echo       Clonando repositorio...
    git clone --depth 1 --quiet "https://github.com/s0md3v/XSStrike.git" "%XSSTRIKE_DIR%"
    if errorlevel 1 (
        echo [ERRO] Falha ao clonar XSStrike.
        pause & exit /b 1
    )
)
echo       Instalando dependencias Python...
python -m pip install -r "%XSSTRIKE_DIR%\requirements.txt" --quiet --disable-pip-version-check 2>nul
echo       OK.

:: ==================================================================
:: [5/8] Commix
:: ==================================================================
echo.
echo [5/8] Commix (Command Injection)...
if exist "%COMMIX_DIR%\commix.py" (
    echo       ja existe, atualizando...
    git -C "%COMMIX_DIR%" pull --quiet
) else (
    echo       Clonando repositorio...
    git clone --depth 1 --quiet "https://github.com/commixproject/commix.git" "%COMMIX_DIR%"
    if errorlevel 1 (
        echo [ERRO] Falha ao clonar commix.
        pause & exit /b 1
    )
)
echo       OK.

:: ==================================================================
:: [6/8] wrk (via Docker build)
:: ==================================================================
echo.
echo [6/8] wrk (Gerador de Carga HTTP)...
echo       Compilando imagem Docker a partir do source...
docker build -t lab_wrk "%PROJECT_DIR%\docker\wrk" --quiet 2>nul
if errorlevel 1 (
    echo [AVISO] Build do wrk falhou. Tentando sem --quiet...
    docker build -t lab_wrk "%PROJECT_DIR%\docker\wrk"
    if errorlevel 1 (
        echo [ERRO] Falha ao compilar imagem wrk.
        pause & exit /b 1
    )
)
echo       OK.

:: ==================================================================
:: [7/8] nuclei
:: ==================================================================
echo.
echo [7/8] nuclei (Vulnerability Scanner)...
if exist "%NUCLEI_DIR%\nuclei.exe" (
    echo       ja existe. Atualizando templates...
    "%NUCLEI_DIR%\nuclei.exe" -update-templates -silent 2>nul
) else (
    echo       Baixando binario Windows (via PowerShell)...
    if not exist "%NUCLEI_DIR%" mkdir "%NUCLEI_DIR%"

    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " ^
        "try { " ^
        "  $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/projectdiscovery/nuclei/releases/latest' -UseBasicParsing; " ^
        "  $asset = $rel.assets | Where-Object { $_.name -match 'windows.*amd64.*zip$' } | Select-Object -First 1; " ^
        "  if (-not $asset) { throw 'Asset nao encontrado' }; " ^
        "  Write-Host ('       Versao: ' + $rel.tag_name); " ^
        "  Write-Host ('       Arquivo: ' + $asset.name); " ^
        "  $out = '%NUCLEI_DIR%\nuclei.zip'; " ^
        "  Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $out -UseBasicParsing; " ^
        "  Expand-Archive -Path $out -DestinationPath '%NUCLEI_DIR%' -Force; " ^
        "  Remove-Item $out -Force; " ^
        "  Write-Host '       Download concluido.' " ^
        "} catch { " ^
        "  Write-Error $_.Exception.Message; exit 1 " ^
        "}"

    if not exist "%NUCLEI_DIR%\nuclei.exe" (
        echo [ERRO] nuclei.exe nao encontrado apos download.
        echo       Verifique sua conexao e tente novamente.
        pause & exit /b 1
    )
    echo       Baixando templates...
    "%NUCLEI_DIR%\nuclei.exe" -update-templates -silent 2>nul
)
echo       OK.

:: ==================================================================
:: Sumario
:: ==================================================================
echo.
echo ==================================================================
echo   Todas as ferramentas instaladas com sucesso!
echo ==================================================================
echo.
echo   LOCAL (ferramentas\):
echo     [1] testssl.sh : %TESTSSL_DIR%\testssl.sh
echo     [3] sqlmap     : %SQLMAP_DIR%\sqlmap.py
echo     [4] XSStrike   : %XSSTRIKE_DIR%\xsstrike.py
echo     [5] commix     : %COMMIX_DIR%\commix.py
echo     [7] nuclei     : %NUCLEI_DIR%\nuclei.exe
echo.
echo   DOCKER:
echo     [1] testssl    : drwetter/testssl.sh
echo     [2] OWASP ZAP  : ghcr.io/zaproxy/zaproxy:stable
echo     [6] wrk        : lab_wrk (build local)
echo.
echo ==================================================================
echo.
pause
