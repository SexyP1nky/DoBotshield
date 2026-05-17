@echo off
setlocal enabledelayedexpansion

:: ==================================================================
:: DoBotShield - Download das Ferramentas de Teste
:: ==================================================================
:: Baixa sqlmap, XSStrike e nuclei para a pasta ferramentas\.
:: Pre-requisitos: git, python 3.x, conexao com internet.
:: ==================================================================

set "TOOLS_DIR=%~dp0"
set "SQLMAP_DIR=%TOOLS_DIR%sqlmap"
set "XSSTRIKE_DIR=%TOOLS_DIR%XSStrike"
set "NUCLEI_DIR=%TOOLS_DIR%nuclei"

echo.
echo ==================================================================
echo   DoBotShield - Download de Ferramentas de Seguranca
echo ==================================================================
echo.

:: ---- Verificar pre-requisitos ----

where git >nul 2>&1
if errorlevel 1 (
    echo [ERRO] git nao encontrado. Instale via https://git-scm.com
    pause & exit /b 1
)

where python >nul 2>&1
if errorlevel 1 (
    echo [ERRO] python nao encontrado. Instale via https://python.org
    pause & exit /b 1
)

:: ---- sqlmap ----
echo [1/3] Verificando sqlmap...
if exist "%SQLMAP_DIR%\sqlmap.py" (
    echo       sqlmap ja existe, atualizando...
    git -C "%SQLMAP_DIR%" pull --quiet
) else (
    echo       Clonando sqlmap...
    git clone --depth 1 --quiet "https://github.com/sqlmapproject/sqlmap.git" "%SQLMAP_DIR%"
    if errorlevel 1 (
        echo [ERRO] Falha ao clonar sqlmap.
        pause & exit /b 1
    )
)
echo       OK.

:: ---- XSStrike ----
echo.
echo [2/3] Verificando XSStrike...
if exist "%XSSTRIKE_DIR%\xsstrike.py" (
    echo       XSStrike ja existe, atualizando...
    git -C "%XSSTRIKE_DIR%" pull --quiet
) else (
    echo       Clonando XSStrike...
    git clone --depth 1 --quiet "https://github.com/s0md3v/XSStrike.git" "%XSSTRIKE_DIR%"
    if errorlevel 1 (
        echo [ERRO] Falha ao clonar XSStrike.
        pause & exit /b 1
    )
)
echo       Instalando dependencias do XSStrike...
python -m pip install -r "%XSSTRIKE_DIR%\requirements.txt" --quiet --disable-pip-version-check
echo       OK.

:: ---- nuclei ----
echo.
echo [3/3] Verificando nuclei...
if exist "%NUCLEI_DIR%\nuclei.exe" (
    echo       nuclei ja existe. Atualizando templates...
    "%NUCLEI_DIR%\nuclei.exe" -update-templates -silent 2>nul
) else (
    echo       Baixando nuclei (via PowerShell)...
    if not exist "%NUCLEI_DIR%" mkdir "%NUCLEI_DIR%"

    powershell -NoProfile -Command ^
        "$releases = Invoke-RestMethod 'https://api.github.com/repos/projectdiscovery/nuclei/releases/latest'; " ^
        "$asset = $releases.assets | Where-Object { $_.name -like '*windows_amd64.zip' } | Select-Object -First 1; " ^
        "if (-not $asset) { Write-Error 'Asset nao encontrado'; exit 1 }; " ^
        "Invoke-WebRequest -Uri $asset.browser_download_url -OutFile '%NUCLEI_DIR%\nuclei.zip' -UseBasicParsing; " ^
        "Expand-Archive -Path '%NUCLEI_DIR%\nuclei.zip' -DestinationPath '%NUCLEI_DIR%' -Force; " ^
        "Remove-Item '%NUCLEI_DIR%\nuclei.zip' -Force"

    if not exist "%NUCLEI_DIR%\nuclei.exe" (
        echo [ERRO] nuclei.exe nao encontrado apos download.
        pause & exit /b 1
    )
    echo       Baixando templates do nuclei...
    "%NUCLEI_DIR%\nuclei.exe" -update-templates -silent 2>nul
)
echo       OK.

echo.
echo ==================================================================
echo   Ferramentas prontas em: %TOOLS_DIR%
echo ==================================================================
echo.
echo   sqlmap    : %SQLMAP_DIR%\sqlmap.py
echo   XSStrike  : %XSSTRIKE_DIR%\xsstrike.py
echo   nuclei    : %NUCLEI_DIR%\nuclei.exe
echo.
pause
