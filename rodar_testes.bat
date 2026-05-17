@echo off
setlocal enabledelayedexpansion

:: ==================================================================
:: DoBotShield - Suite de Testes Comparativos de WAF
:: ==================================================================
::
:: Executa 8 ferramentas contra 8 alvos (2 apps x 4 configs):
::
::   ALVOS:
::     DVWA        sem WAF       (porta 8080)
::     DVWA        DoBotShield   (porta 9080)
::     DVWA        ModSecurity   (porta 9180)
::     DVWA        Coraza        (porta 9280)
::     Mutillidae  sem WAF       (porta 8081)
::     Mutillidae  DoBotShield   (porta 9081)
::     Mutillidae  ModSecurity   (porta 9181)
::     Mutillidae  Coraza        (porta 9281)
::
::   FERRAMENTAS:
::     1. testssl.sh  - Analise TLS/SSL
::     2. OWASP ZAP   - Scanner DAST
::     3. SQLMap       - SQL Injection
::     4. XSStrike     - XSS Fuzzing
::     5. Commix       - Command Injection
::     6. wrk          - Carga HTTP (DoS)
::     7. nuclei       - Vulnerability Scanner
::
:: PADRONIZACAO: parametros IDENTICOS para todos os alvos.
:: Apenas a URL de destino muda entre os testes.
::
:: Logs: logs\[ferramenta]\[ferramenta]_[app]_[waf].txt
:: Total: 7 ferramentas x 8 alvos = 56 arquivos de log
::
:: Pre-requisitos:
::   - Docker Desktop em execucao
::   - ferramentas\ populada (execute ferramentas\baixar_ferramentas.bat)
::   - Python 3.x no PATH
:: ==================================================================

set "SCRIPT_DIR=%~dp0"
set "TOOLS_DIR=%SCRIPT_DIR%ferramentas"
set "LOG_DIR=%SCRIPT_DIR%logs"
set "COOKIES_DIR=%LOG_DIR%\cookies"
set "PYTHON=python"
set "SQLMAP=%TOOLS_DIR%\sqlmap\sqlmap.py"
set "XSSTRIKE=%TOOLS_DIR%\XSStrike\xsstrike.py"
set "COMMIX=%TOOLS_DIR%\commix\commix.py"
set "NUCLEI=%TOOLS_DIR%\nuclei\nuclei.exe"

:: ================================================================
:: Portas do laboratorio
:: ================================================================
set P_DVWA_NOWAF=8080
set P_MUTT_NOWAF=8081
set P_DVWA_DOBOT=9080
set P_MUTT_DOBOT=9081
set P_DVWA_MODSEC=9180
set P_MUTT_MODSEC=9181
set P_DVWA_CORAZA=9280
set P_MUTT_CORAZA=9281

:: ================================================================
:: URLs vulneraveis por tipo de ataque
:: ================================================================
:: SQLi
set "DVWA_SQLI_PATH=/vulnerabilities/sqli/?id=1&Submit=Submit"
set "MUTT_SQLI_PATH=/index.php?page=user-info.php&username=admin&password=&user-info-php-submit-button=View+Account+Details"

:: XSS
set "DVWA_XSS_PATH=/vulnerabilities/xss_r/?name=test"
set "MUTT_XSS_PATH=/index.php?page=dns-lookup.php&target_host=test&dns-lookup-php-submit-button=Lookup+DNS"

:: Command Injection
set "DVWA_CMDI_PATH=/vulnerabilities/exec/"
set "DVWA_CMDI_DATA=ip=127.0.0.1&Submit=Submit"
set "MUTT_CMDI_PATH=/index.php?page=dns-lookup.php&target_host=127.0.0.1&dns-lookup-php-submit-button=Lookup+DNS"

:: ================================================================
echo.
echo ==================================================================
echo   DoBotShield - Suite Completa de Testes de Seguranca
echo   Inicio: %date% %time%
echo ==================================================================
echo.
echo   7 ferramentas x 8 alvos = 56 testes
echo.

:: ================================================================
:: ETAPA 0 - Verificar pre-requisitos
:: ================================================================
echo [0/8] Verificando pre-requisitos...

if not exist "%SQLMAP%" (
    echo [ERRO] sqlmap nao encontrado em: %SQLMAP%
    echo        Execute ferramentas\baixar_ferramentas.bat primeiro.
    pause & exit /b 1
)
if not exist "%XSSTRIKE%" (
    echo [ERRO] XSStrike nao encontrado em: %XSSTRIKE%
    echo        Execute ferramentas\baixar_ferramentas.bat primeiro.
    pause & exit /b 1
)
if not exist "%COMMIX%" (
    echo [ERRO] Commix nao encontrado em: %COMMIX%
    echo        Execute ferramentas\baixar_ferramentas.bat primeiro.
    pause & exit /b 1
)
if not exist "%NUCLEI%" (
    echo [ERRO] nuclei nao encontrado em: %NUCLEI%
    echo        Execute ferramentas\baixar_ferramentas.bat primeiro.
    pause & exit /b 1
)

where docker >nul 2>&1
if errorlevel 1 (
    echo [ERRO] docker nao encontrado no PATH.
    pause & exit /b 1
)

:: Verificar imagens Docker necessarias
docker image inspect drwetter/testssl.sh >nul 2>&1
if errorlevel 1 (
    echo [AVISO] Imagem testssl.sh nao encontrada, baixando...
    docker pull drwetter/testssl.sh --quiet 2>nul
)
docker image inspect ghcr.io/zaproxy/zaproxy:stable >nul 2>&1
if errorlevel 1 (
    echo [AVISO] Imagem ZAP nao encontrada, baixando...
    docker pull ghcr.io/zaproxy/zaproxy:stable --quiet 2>nul
)
docker image inspect lab_wrk >nul 2>&1
if errorlevel 1 (
    echo [AVISO] Imagem wrk nao encontrada, compilando...
    docker build -t lab_wrk "%SCRIPT_DIR%docker\wrk" --quiet 2>nul
)

echo       Todos os pre-requisitos verificados.
echo.

:: ================================================================
:: ETAPA 1 - Criar diretorios de log
:: ================================================================
echo [1/8] Criando diretorios de log...
for %%d in (testssl zap sqlmap xsstrike commix wrk nuclei cookies) do (
    if not exist "%LOG_DIR%\%%d" mkdir "%LOG_DIR%\%%d"
)
echo       OK.

:: ================================================================
:: ETAPA 2 - Subir ambiente Docker
:: ================================================================
echo.
echo [2/8] Iniciando laboratorio Docker...
docker compose -f "%SCRIPT_DIR%docker-compose.yml" up -d --build
if errorlevel 1 (
    echo [ERRO] Falha ao iniciar Docker Compose.
    pause & exit /b 1
)

echo       Aguardando servicos (60s)...
timeout /t 60 /nobreak >nul

:: Aguarda DVWA
echo       Verificando DVWA (porta %P_DVWA_NOWAF%)...
set /a WAIT_TRIES=0
:wait_dvwa
set /a WAIT_TRIES+=1
if !WAIT_TRIES! gtr 24 (
    echo [ERRO] DVWA nao respondeu em tempo habil.
    pause & exit /b 1
)
curl -s -o nul -w "%%{http_code}" "http://localhost:%P_DVWA_NOWAF%/login.php" 2>nul | findstr /r "^[23]" >nul
if errorlevel 1 (
    timeout /t 5 /nobreak >nul
    goto wait_dvwa
)
echo       DVWA respondendo.

:: Aguarda Mutillidae
echo       Verificando Mutillidae (porta %P_MUTT_NOWAF%)...
set /a WAIT_TRIES=0
:wait_mutillidae
set /a WAIT_TRIES+=1
if !WAIT_TRIES! gtr 24 (
    echo [AVISO] Mutillidae nao respondeu, continuando...
    goto setup_dvwa
)
curl -s -o nul -w "%%{http_code}" "http://localhost:%P_MUTT_NOWAF%/" 2>nul | findstr /r "^[23]" >nul
if errorlevel 1 (
    timeout /t 5 /nobreak >nul
    goto wait_mutillidae
)
echo       Mutillidae respondendo.

:: ================================================================
:: ETAPA 3 - Configurar aplicacoes
:: ================================================================
:setup_dvwa
echo.
echo [3/8] Configurando DVWA...

set "DVWA_COOKIE_FILE=%COOKIES_DIR%\dvwa.txt"

:: Obter pagina de login para extrair CSRF token
curl -s -c "!DVWA_COOKIE_FILE!" ^
     -o "%TEMP%\dvwa_login_page.html" ^
     "http://localhost:%P_DVWA_NOWAF%/login.php"

for /f "usebackq delims=" %%t in (`powershell -NoProfile -Command ^
    "try { (Select-String -Path '%TEMP%\dvwa_login_page.html' -Pattern 'user_token').Line -replace '.*value=.([^'']+).*','$1' } catch { '' }"`) do set "DVWA_CSRF=%%t"

:: Login com CSRF token
curl -s -b "!DVWA_COOKIE_FILE!" -c "!DVWA_COOKIE_FILE!" ^
     -d "username=admin&password=password&Login=Login&user_token=!DVWA_CSRF!" ^
     -L -o nul ^
     "http://localhost:%P_DVWA_NOWAF%/login.php"

:: Setar seguranca baixa
curl -s -b "!DVWA_COOKIE_FILE!" -c "!DVWA_COOKIE_FILE!" ^
     -d "security=low&seclev_submit=Submit" ^
     -o nul ^
     "http://localhost:%P_DVWA_NOWAF%/security.php"

:: Extrair PHPSESSID
for /f "usebackq delims=" %%s in (`powershell -NoProfile -Command ^
    "(Get-Content '!DVWA_COOKIE_FILE!' | Where-Object {$_ -match 'PHPSESSID'} | Select-Object -First 1) -replace '.*\t',''"`) do set "DVWA_PHPSESSID=%%s"

if "!DVWA_PHPSESSID!"=="" (
    echo [AVISO] Sessao DVWA nao obtida. Testes DVWA podem falhar.
    set "DVWA_COOKIE=security=low"
) else (
    set "DVWA_COOKIE=PHPSESSID=!DVWA_PHPSESSID!; security=low"
    echo       Sessao: !DVWA_PHPSESSID!
)
echo       DVWA configurado (security=low).

echo.
echo       Configurando Mutillidae...

set "MUTT_COOKIE_FILE=%COOKIES_DIR%\mutillidae.txt"

:: Inicializar banco
curl -s -c "!MUTT_COOKIE_FILE!" -o nul ^
     "http://localhost:%P_MUTT_NOWAF%/set-up-database.php" 2>nul
timeout /t 3 /nobreak >nul

:: Nivel 0 (mais vulneravel)
curl -s -b "!MUTT_COOKIE_FILE!" -c "!MUTT_COOKIE_FILE!" ^
     -d "security-level=0" -o nul ^
     "http://localhost:%P_MUTT_NOWAF%/index.php?page=home.php"

echo       Mutillidae configurado (security-level=0).

:: ================================================================
:: PARAMETROS PADRONIZADOS
:: ================================================================
:: Identicos para todos os alvos. Apenas URL muda.
::
:: testssl  : via Docker, analise TLS basica
:: ZAP      : baseline scan, 2 minutos max, sem falha por alertas
:: sqlmap   : level 1, risk 1, delay 1s (seguranca)
:: XSStrike : sem DOM scan, timeout 10s
:: commix   : batch mode, delay 1s (seguranca)
:: wrk      : 2 threads, 10 conexoes, 30 segundos
:: nuclei   : 10 req/s, timeout 10s, sem cores

set "SQLMAP_OPTS=--level=1 --risk=1 --batch --delay=1 --timeout=30 --retries=1 --no-cast"
set "XSSTRIKE_OPTS=--skip-dom --timeout 10"
set "COMMIX_OPTS=--batch --output-dir=%TEMP%\commix_out"
set "WRK_OPTS=-t2 -c10 -d30s"
set "NUCLEI_OPTS=-rate-limit 10 -timeout 10 -nc -silent"
set "ZAP_OPTS=-I -m 2"

:: ================================================================
:: Funcoes auxiliares
:: ================================================================
goto skip_functions

:log_header
(
    echo ==================================================================
    echo   %~2
    echo   Alvo: %~3
    echo   Data: %date% %time%
    echo   Parametros padronizados (identicos para todos os alvos)
    echo ==================================================================
    echo.
) > "%~1"
goto :eof

:skip_functions

:: ================================================================
:: ETAPA 4 - TESTSSL.SH
:: ================================================================
echo.
echo [4/8] testssl.sh - Analise TLS/SSL
echo ------------------------------------------------------------------

:: DVWA - sem WAF
echo   [testssl] DVWA sem WAF (porta !P_DVWA_NOWAF!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "TESTSSL - DVWA sem WAF" "host.docker.internal:!P_DVWA_NOWAF!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_DVWA_NOWAF! >> "!LOG_FILE!" 2>&1
echo       OK.

:: DVWA - DoBotShield
echo   [testssl] DVWA com DoBotShield (porta !P_DVWA_DOBOT!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "TESTSSL - DVWA com DoBotShield" "host.docker.internal:!P_DVWA_DOBOT!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_DVWA_DOBOT! >> "!LOG_FILE!" 2>&1
echo       OK.

:: DVWA - ModSecurity
echo   [testssl] DVWA com ModSecurity (porta !P_DVWA_MODSEC!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "TESTSSL - DVWA com ModSecurity" "host.docker.internal:!P_DVWA_MODSEC!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_DVWA_MODSEC! >> "!LOG_FILE!" 2>&1
echo       OK.

:: DVWA - Coraza
echo   [testssl] DVWA com Coraza (porta !P_DVWA_CORAZA!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "TESTSSL - DVWA com Coraza" "host.docker.internal:!P_DVWA_CORAZA!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_DVWA_CORAZA! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - sem WAF
echo   [testssl] Mutillidae sem WAF (porta !P_MUTT_NOWAF!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "TESTSSL - Mutillidae sem WAF" "host.docker.internal:!P_MUTT_NOWAF!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_MUTT_NOWAF! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - DoBotShield
echo   [testssl] Mutillidae com DoBotShield (porta !P_MUTT_DOBOT!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "TESTSSL - Mutillidae com DoBotShield" "host.docker.internal:!P_MUTT_DOBOT!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_MUTT_DOBOT! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - ModSecurity
echo   [testssl] Mutillidae com ModSecurity (porta !P_MUTT_MODSEC!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "TESTSSL - Mutillidae com ModSecurity" "host.docker.internal:!P_MUTT_MODSEC!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_MUTT_MODSEC! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - Coraza
echo   [testssl] Mutillidae com Coraza (porta !P_MUTT_CORAZA!)...
set "LOG_FILE=!LOG_DIR!\testssl\testssl_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "TESTSSL - Mutillidae com Coraza" "host.docker.internal:!P_MUTT_CORAZA!"
docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:!P_MUTT_CORAZA! >> "!LOG_FILE!" 2>&1
echo       OK.

:: ================================================================
:: ETAPA 5 - OWASP ZAP (Baseline Scan)
:: ================================================================
echo.
echo [5/8] OWASP ZAP - Scanner DAST (Baseline)
echo ------------------------------------------------------------------

:: DVWA - sem WAF
echo   [ZAP] DVWA sem WAF (porta !P_DVWA_NOWAF!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - DVWA sem WAF" "http://host.docker.internal:!P_DVWA_NOWAF!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_DVWA_NOWAF!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: DVWA - DoBotShield
echo   [ZAP] DVWA com DoBotShield (porta !P_DVWA_DOBOT!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - DVWA com DoBotShield" "http://host.docker.internal:!P_DVWA_DOBOT!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_DVWA_DOBOT!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: DVWA - ModSecurity
echo   [ZAP] DVWA com ModSecurity (porta !P_DVWA_MODSEC!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - DVWA com ModSecurity" "http://host.docker.internal:!P_DVWA_MODSEC!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_DVWA_MODSEC!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: DVWA - Coraza
echo   [ZAP] DVWA com Coraza (porta !P_DVWA_CORAZA!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - DVWA com Coraza" "http://host.docker.internal:!P_DVWA_CORAZA!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_DVWA_CORAZA!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - sem WAF
echo   [ZAP] Mutillidae sem WAF (porta !P_MUTT_NOWAF!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - Mutillidae sem WAF" "http://host.docker.internal:!P_MUTT_NOWAF!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_MUTT_NOWAF!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - DoBotShield
echo   [ZAP] Mutillidae com DoBotShield (porta !P_MUTT_DOBOT!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - Mutillidae com DoBotShield" "http://host.docker.internal:!P_MUTT_DOBOT!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_MUTT_DOBOT!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - ModSecurity
echo   [ZAP] Mutillidae com ModSecurity (porta !P_MUTT_MODSEC!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - Mutillidae com ModSecurity" "http://host.docker.internal:!P_MUTT_MODSEC!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_MUTT_MODSEC!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae - Coraza
echo   [ZAP] Mutillidae com Coraza (porta !P_MUTT_CORAZA!)...
set "LOG_FILE=!LOG_DIR!\zap\zap_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "ZAP BASELINE - Mutillidae com Coraza" "http://host.docker.internal:!P_MUTT_CORAZA!/"
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://host.docker.internal:!P_MUTT_CORAZA!/" !ZAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: ================================================================
:: ETAPA 6 - SQLMAP + XSSTRIKE + COMMIX (ferramentas direcionadas)
:: ================================================================
echo.
echo [6/8] SQLMap + XSStrike + Commix - Ataques Direcionados
echo ------------------------------------------------------------------

:: ---- SQLMAP (SQL Injection) ----
echo.
echo   --- SQLMap (SQL Injection) ---

:: DVWA
echo   [sqlmap] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA sem WAF" "http://localhost:!P_DVWA_NOWAF!!DVWA_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_NOWAF!!DVWA_SQLI_PATH!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [sqlmap] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA com DoBotShield" "http://localhost:!P_DVWA_DOBOT!!DVWA_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_DOBOT!!DVWA_SQLI_PATH!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [sqlmap] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA com ModSecurity" "http://localhost:!P_DVWA_MODSEC!!DVWA_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_MODSEC!!DVWA_SQLI_PATH!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [sqlmap] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA com Coraza" "http://localhost:!P_DVWA_CORAZA!!DVWA_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_CORAZA!!DVWA_SQLI_PATH!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae
echo   [sqlmap] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae sem WAF" "http://localhost:!P_MUTT_NOWAF!!MUTT_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_NOWAF!!MUTT_SQLI_PATH!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [sqlmap] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae com DoBotShield" "http://localhost:!P_MUTT_DOBOT!!MUTT_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_DOBOT!!MUTT_SQLI_PATH!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [sqlmap] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae com ModSecurity" "http://localhost:!P_MUTT_MODSEC!!MUTT_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_MODSEC!!MUTT_SQLI_PATH!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [sqlmap] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae com Coraza" "http://localhost:!P_MUTT_CORAZA!!MUTT_SQLI_PATH!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_CORAZA!!MUTT_SQLI_PATH!" !SQLMAP_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: ---- XSSTRIKE (XSS) ----
echo.
echo   --- XSStrike (XSS Fuzzing) ---

:: DVWA
echo   [XSStrike] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA sem WAF" "http://localhost:!P_DVWA_NOWAF!!DVWA_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_NOWAF!!DVWA_XSS_PATH!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [XSStrike] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA com DoBotShield" "http://localhost:!P_DVWA_DOBOT!!DVWA_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_DOBOT!!DVWA_XSS_PATH!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [XSStrike] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA com ModSecurity" "http://localhost:!P_DVWA_MODSEC!!DVWA_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_MODSEC!!DVWA_XSS_PATH!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [XSStrike] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA com Coraza" "http://localhost:!P_DVWA_CORAZA!!DVWA_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_CORAZA!!DVWA_XSS_PATH!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae
echo   [XSStrike] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae sem WAF" "http://localhost:!P_MUTT_NOWAF!!MUTT_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_NOWAF!!MUTT_XSS_PATH!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [XSStrike] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae com DoBotShield" "http://localhost:!P_MUTT_DOBOT!!MUTT_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_DOBOT!!MUTT_XSS_PATH!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [XSStrike] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae com ModSecurity" "http://localhost:!P_MUTT_MODSEC!!MUTT_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_MODSEC!!MUTT_XSS_PATH!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [XSStrike] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae com Coraza" "http://localhost:!P_MUTT_CORAZA!!MUTT_XSS_PATH!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_CORAZA!!MUTT_XSS_PATH!" !XSSTRIKE_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: ---- COMMIX (Command Injection) ----
echo.
echo   --- Commix (Command Injection) ---

:: DVWA (POST-based: usa --data)
echo   [commix] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\commix\commix_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "COMMIX - DVWA sem WAF" "http://localhost:!P_DVWA_NOWAF!!DVWA_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_NOWAF!!DVWA_CMDI_PATH!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [commix] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\commix\commix_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "COMMIX - DVWA com DoBotShield" "http://localhost:!P_DVWA_DOBOT!!DVWA_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_DOBOT!!DVWA_CMDI_PATH!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [commix] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\commix\commix_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "COMMIX - DVWA com ModSecurity" "http://localhost:!P_DVWA_MODSEC!!DVWA_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_MODSEC!!DVWA_CMDI_PATH!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [commix] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\commix\commix_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "COMMIX - DVWA com Coraza" "http://localhost:!P_DVWA_CORAZA!!DVWA_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_CORAZA!!DVWA_CMDI_PATH!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae (GET-based: params na URL)
echo   [commix] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\commix\commix_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "COMMIX - Mutillidae sem WAF" "http://localhost:!P_MUTT_NOWAF!!MUTT_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_NOWAF!!MUTT_CMDI_PATH!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [commix] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\commix\commix_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "COMMIX - Mutillidae com DoBotShield" "http://localhost:!P_MUTT_DOBOT!!MUTT_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_DOBOT!!MUTT_CMDI_PATH!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [commix] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\commix\commix_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "COMMIX - Mutillidae com ModSecurity" "http://localhost:!P_MUTT_MODSEC!!MUTT_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_MODSEC!!MUTT_CMDI_PATH!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [commix] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\commix\commix_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "COMMIX - Mutillidae com Coraza" "http://localhost:!P_MUTT_CORAZA!!MUTT_CMDI_PATH!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_CORAZA!!MUTT_CMDI_PATH!" !COMMIX_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: ================================================================
:: ETAPA 7 - WRK (Teste de Carga)
:: ================================================================
echo.
echo [7/8] wrk - Teste de Carga HTTP
echo ------------------------------------------------------------------
echo       Parametros: %WRK_OPTS% (2 threads, 10 conexoes, 30s)

:: DVWA
echo   [wrk] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "WRK - DVWA sem WAF" "http://host.docker.internal:!P_DVWA_NOWAF!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_NOWAF!/" >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [wrk] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "WRK - DVWA com DoBotShield" "http://host.docker.internal:!P_DVWA_DOBOT!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_DOBOT!/" >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [wrk] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "WRK - DVWA com ModSecurity" "http://host.docker.internal:!P_DVWA_MODSEC!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_MODSEC!/" >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [wrk] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "WRK - DVWA com Coraza" "http://host.docker.internal:!P_DVWA_CORAZA!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_CORAZA!/" >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae
echo   [wrk] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "WRK - Mutillidae sem WAF" "http://host.docker.internal:!P_MUTT_NOWAF!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_NOWAF!/" >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [wrk] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "WRK - Mutillidae com DoBotShield" "http://host.docker.internal:!P_MUTT_DOBOT!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_DOBOT!/" >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [wrk] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "WRK - Mutillidae com ModSecurity" "http://host.docker.internal:!P_MUTT_MODSEC!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_MODSEC!/" >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [wrk] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\wrk\wrk_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "WRK - Mutillidae com Coraza" "http://host.docker.internal:!P_MUTT_CORAZA!/"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_CORAZA!/" >> "!LOG_FILE!" 2>&1
echo       OK.

:: ================================================================
:: ETAPA 8 - NUCLEI (Vulnerability Scanner)
:: ================================================================
echo.
echo [8/8] nuclei - Scanner de Vulnerabilidades
echo ------------------------------------------------------------------

:: DVWA
echo   [nuclei] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA sem WAF" "http://localhost:!P_DVWA_NOWAF!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_NOWAF!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [nuclei] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA com DoBotShield" "http://localhost:!P_DVWA_DOBOT!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_DOBOT!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [nuclei] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA com ModSecurity" "http://localhost:!P_DVWA_MODSEC!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_MODSEC!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [nuclei] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA com Coraza" "http://localhost:!P_DVWA_CORAZA!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_CORAZA!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: Mutillidae
echo   [nuclei] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae sem WAF" "http://localhost:!P_MUTT_NOWAF!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_NOWAF!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [nuclei] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae com DoBotShield" "http://localhost:!P_MUTT_DOBOT!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_DOBOT!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [nuclei] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae com ModSecurity" "http://localhost:!P_MUTT_MODSEC!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_MODSEC!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

echo   [nuclei] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae com Coraza" "http://localhost:!P_MUTT_CORAZA!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_CORAZA!" !NUCLEI_OPTS! >> "!LOG_FILE!" 2>&1
echo       OK.

:: ================================================================
:: SUMARIO FINAL
:: ================================================================
echo.
echo ==================================================================
echo   TESTES CONCLUIDOS
echo   Fim: %date% %time%
echo ==================================================================
echo.
echo   56 logs gerados em: %LOG_DIR%\
echo.
echo   Estrutura:
echo   logs\
echo   +-- testssl\    (8 arquivos) - Analise TLS/SSL
echo   +-- zap\        (8 arquivos) - Scanner DAST
echo   +-- sqlmap\     (8 arquivos) - SQL Injection
echo   +-- xsstrike\   (8 arquivos) - XSS Fuzzing
echo   +-- commix\     (8 arquivos) - Command Injection
echo   +-- wrk\        (8 arquivos) - Teste de Carga
echo   +-- nuclei\     (8 arquivos) - Vulnerabilidades
echo.
echo   Nomenclatura: [ferramenta]_[app]_[waf].txt
echo   Exemplo: sqlmap_dvwa_dobotshield.txt
echo.
echo   PARAMETROS USADOS (identicos para todos os alvos):
echo     testssl  : --quiet --color 0
echo     ZAP      : baseline scan, max 2 min, sem falha por alertas
echo     sqlmap   : --level=1 --risk=1 --delay=1 --batch
echo     XSStrike : --skip-dom --timeout 10
echo     commix   : --batch
echo     wrk      : -t2 -c10 -d30s
echo     nuclei   : -rate-limit 10 -timeout 10
echo.
echo ==================================================================
echo.
pause
