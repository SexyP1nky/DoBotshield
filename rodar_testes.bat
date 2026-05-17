@echo off
setlocal enabledelayedexpansion

:: ==================================================================
:: DoBotShield - Suite de Testes Comparativos de WAF
:: ==================================================================
::
:: Executa sqlmap, XSStrike e nuclei contra 8 alvos:
::   - DVWA        sem WAF  (porta 8080)
::   - DVWA        DoBotShield (porta 9080)
::   - DVWA        ModSecurity (porta 9180)
::   - DVWA        Coraza      (porta 9280)
::   - Mutillidae  sem WAF  (porta 8081)
::   - Mutillidae  DoBotShield (porta 9081)
::   - Mutillidae  ModSecurity (porta 9181)
::   - Mutillidae  Coraza      (porta 9281)
::
:: PADRONIZACAO: os parametros de cada ferramenta sao IDENTICOS para
:: todos os alvos — apenas a URL de destino muda. Isso garante que
:: a comparacao reflita a eficacia dos WAFs, nao variacoes de entrada.
::
:: Logs gerados em: logs\[ferramenta]\[ferramenta]_[app]_[waf].txt
::
:: Pre-requisitos:
::   - Docker Desktop em execucao
::   - ferramentas\ populada (execute ferramentas\baixar_ferramentas.bat)
::   - Python 3.x no PATH (para sqlmap e XSStrike)
:: ==================================================================

set "SCRIPT_DIR=%~dp0"
set "TOOLS_DIR=%SCRIPT_DIR%ferramentas"
set "LOG_DIR=%SCRIPT_DIR%logs"
set "COOKIES_DIR=%SCRIPT_DIR%logs\cookies"
set "PYTHON=python"
set "SQLMAP=%TOOLS_DIR%\sqlmap\sqlmap.py"
set "XSSTRIKE=%TOOLS_DIR%\XSStrike\xsstrike.py"
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
:: Sufixos SQLi e XSS
:: Nota: & dentro de SET entre aspas e seguro; use aspas nos comandos
:: ================================================================
set "DVWA_SQLI_SUFFIX=/vulnerabilities/sqli/?id=1&Submit=Submit"
set "DVWA_XSS_SUFFIX=/vulnerabilities/xss_r/?name=test"
set "MUTT_SQLI_SUFFIX=/index.php?page=user-info.php&username=1&password=&user-info-php-submit-button=View+Account+Details"
set "MUTT_XSS_SUFFIX=/index.php?page=dns-lookup.php&target_host=test&dns-lookup-php-submit-button=Lookup+DNS"

:: ================================================================
echo.
echo ==================================================================
echo   DoBotShield - Suite de Testes de Seguranca
echo   Inicio: %date% %time%
echo ==================================================================
echo.

:: ================================================================
:: ETAPA 0 - Verificar pre-requisitos
:: ================================================================
echo [0/6] Verificando pre-requisitos...

if not exist "%SQLMAP%" (
    echo [ERRO] sqlmap nao encontrado. Execute ferramentas\baixar_ferramentas.bat primeiro.
    pause & exit /b 1
)
if not exist "%XSSTRIKE%" (
    echo [ERRO] XSStrike nao encontrado. Execute ferramentas\baixar_ferramentas.bat primeiro.
    pause & exit /b 1
)
if not exist "%NUCLEI%" (
    echo [ERRO] nuclei nao encontrado. Execute ferramentas\baixar_ferramentas.bat primeiro.
    pause & exit /b 1
)

where docker >nul 2>&1
if errorlevel 1 (
    echo [ERRO] docker nao encontrado no PATH.
    pause & exit /b 1
)

:: ================================================================
:: ETAPA 1 - Criar diretorios de log
:: ================================================================
echo [1/6] Criando diretorios de log...
for %%d in (sqlmap xsstrike nuclei cookies) do (
    if not exist "%LOG_DIR%\%%d" mkdir "%LOG_DIR%\%%d"
)
echo       OK.

:: ================================================================
:: ETAPA 2 - Subir ambiente Docker
:: ================================================================
echo.
echo [2/6] Iniciando laboratorio Docker...
docker compose -f "%SCRIPT_DIR%docker-compose.yml" up -d --build
if errorlevel 1 (
    echo [ERRO] Falha ao iniciar o Docker Compose.
    pause & exit /b 1
)

echo       Aguardando servicos ficarem prontos (60s)...
timeout /t 60 /nobreak > nul

:: Aguarda DVWA responder (ate 120s adicionais)
echo       Aguardando DVWA (http://localhost:%P_DVWA_NOWAF%)...
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
echo       DVWA OK.

:: Aguarda Mutillidae
echo       Aguardando Mutillidae (http://localhost:%P_MUTT_NOWAF%)...
set /a WAIT_TRIES=0
:wait_mutillidae
set /a WAIT_TRIES+=1
if !WAIT_TRIES! gtr 24 (
    echo [AVISO] Mutillidae nao respondeu, continuando mesmo assim...
    goto setup_dvwa
)
curl -s -o nul -w "%%{http_code}" "http://localhost:%P_MUTT_NOWAF%/" 2>nul | findstr /r "^[23]" >nul
if errorlevel 1 (
    timeout /t 5 /nobreak >nul
    goto wait_mutillidae
)
echo       Mutillidae OK.

:: ================================================================
:: ETAPA 3 - Configurar DVWA
:: ================================================================
:setup_dvwa
echo.
echo [3/6] Configurando DVWA...

set "DVWA_COOKIE_FILE=%COOKIES_DIR%\dvwa.txt"

:: Login
curl -s -c "!DVWA_COOKIE_FILE!" ^
     -d "username=admin&password=password&Login=Login" ^
     -L -o nul ^
     "http://localhost:%P_DVWA_NOWAF%/login.php"

:: Inicializar banco de dados
curl -s -b "!DVWA_COOKIE_FILE!" -c "!DVWA_COOKIE_FILE!" ^
     -d "create_db=Create+/+Reset+Database" ^
     -L -o nul ^
     "http://localhost:%P_DVWA_NOWAF%/setup.php"

timeout /t 5 /nobreak >nul

:: Login novamente apos reset do banco
curl -s -c "!DVWA_COOKIE_FILE!" ^
     -d "username=admin&password=password&Login=Login" ^
     -L -o nul ^
     "http://localhost:%P_DVWA_NOWAF%/login.php"

:: Definir nivel de seguranca como baixo (vulneravel)
curl -s -b "!DVWA_COOKIE_FILE!" -c "!DVWA_COOKIE_FILE!" ^
     -d "security=low&seclev_submit=Submit" ^
     -o nul ^
     "http://localhost:%P_DVWA_NOWAF%/security.php"

:: Extrair PHPSESSID do arquivo de cookies
for /f "usebackq delims=" %%s in (`powershell -NoProfile -Command ^
    "(Get-Content '!DVWA_COOKIE_FILE!' | Where-Object {$_ -match 'PHPSESSID'} | Select-Object -First 1) -replace '.*\t',''"`
) do set "DVWA_PHPSESSID=%%s"

if "!DVWA_PHPSESSID!"=="" (
    echo [AVISO] PHPSESSID nao encontrado, tentando continuar sem cookie.
    set "DVWA_COOKIE=security=low"
) else (
    set "DVWA_COOKIE=PHPSESSID=!DVWA_PHPSESSID!; security=low"
    echo       Sessao DVWA obtida: !DVWA_PHPSESSID!
)
echo       DVWA configurado com security=low.

:: ================================================================
:: ETAPA 4 - Configurar Mutillidae
:: ================================================================
echo.
echo [4/6] Configurando Mutillidae...

set "MUTT_COOKIE_FILE=%COOKIES_DIR%\mutillidae.txt"

:: Inicializar banco Mutillidae
curl -s -c "!MUTT_COOKIE_FILE!" ^
     -o nul ^
     "http://localhost:%P_MUTT_NOWAF%/index.php?page=set-up-database.php"

timeout /t 3 /nobreak >nul

:: Definir nivel de seguranca 0 (Shovelware - mais vulneravel)
curl -s -b "!MUTT_COOKIE_FILE!" -c "!MUTT_COOKIE_FILE!" ^
     -d "security-level=0" ^
     -o nul ^
     "http://localhost:%P_MUTT_NOWAF%/index.php?page=home.php"

:: Extrair cookie de sessao
for /f "usebackq delims=" %%s in (`powershell -NoProfile -Command ^
    "$lines = Get-Content '!MUTT_COOKIE_FILE!' -ErrorAction SilentlyContinue; " ^
    "$line = $lines | Where-Object {$_ -notmatch '^#' -and $_ -match '\S'} | Select-Object -First 1; " ^
    "if ($line) { ($line -split '\t')[-1] } else { '' }"`) do set "MUTT_SESS=%%s"

echo       Mutillidae configurado.

:: ================================================================
:: ETAPA 5 - EXECUTAR TESTES
:: ================================================================
echo.
echo [5/6] Executando testes de seguranca...
echo.
echo   Atencao: os mesmos parametros sao usados em todos os alvos.
echo   Apenas a URL de destino muda entre os testes.
echo   sqlmap: --level=1 --risk=1 --delay=1
echo   XSStrike: --skip-dom --timeout=10
echo   nuclei: -rate-limit=10 -timeout=10
echo.

:: ================================================================
:: Parametros padronizados (identicos para todos os alvos)
:: ================================================================
:: sqlmap: delay de 1s entre requests (evita sobrecarregar a app)
set "SQLMAP_OPTS=--level=1 --risk=1 --batch --delay=1 --timeout=30 --retries=1 --no-cast"
:: XSStrike: sem DOM (mais rapido), timeout de 10s por request
set "XSSTRIKE_OPTS=--skip-dom --timeout 10"
:: nuclei: limite de 10 req/s (evita DoS), timeout 10s, sem cores
set "NUCLEI_OPTS=-rate-limit 10 -timeout 10 -nc -silent"

:: ================================================================
:: Funcao auxiliar: escreve cabecalho no arquivo de log
:: ================================================================
:: (chamado como: call :log_header <arquivo> <titulo> <url>)
goto skip_functions

:log_header
(
    echo ==================================================================
    echo   %~2
    echo   URL: %~3
    echo   Data/Hora: %date% %time%
    echo ==================================================================
    echo.
) > "%~1"
goto :eof

:log_separator
(
    echo.
    echo ==================================================================
    echo.
) >> "%~1"
goto :eof

:skip_functions

:: ================================================================
:: === SQLMAP ===
:: ================================================================
echo ------------------------------------------------------------------
echo  SQLMAP - Injecao de SQL
echo ------------------------------------------------------------------

:: DVWA - sem WAF
echo   [sqlmap] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA sem WAF (porta !P_DVWA_NOWAF!)" "http://localhost:!P_DVWA_NOWAF!!DVWA_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_DVWA_NOWAF!!DVWA_SQLI_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - DoBotShield
echo   [sqlmap] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA com DoBotShield (porta !P_DVWA_DOBOT!)" "http://localhost:!P_DVWA_DOBOT!!DVWA_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_DVWA_DOBOT!!DVWA_SQLI_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - ModSecurity
echo   [sqlmap] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA com ModSecurity (porta !P_DVWA_MODSEC!)" "http://localhost:!P_DVWA_MODSEC!!DVWA_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_DVWA_MODSEC!!DVWA_SQLI_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - Coraza
echo   [sqlmap] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "SQLMAP - DVWA com Coraza (porta !P_DVWA_CORAZA!)" "http://localhost:!P_DVWA_CORAZA!!DVWA_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_DVWA_CORAZA!!DVWA_SQLI_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - sem WAF
echo   [sqlmap] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae sem WAF (porta !P_MUTT_NOWAF!)" "http://localhost:!P_MUTT_NOWAF!!MUTT_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_MUTT_NOWAF!!MUTT_SQLI_SUFFIX!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - DoBotShield
echo   [sqlmap] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae com DoBotShield (porta !P_MUTT_DOBOT!)" "http://localhost:!P_MUTT_DOBOT!!MUTT_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_MUTT_DOBOT!!MUTT_SQLI_SUFFIX!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - ModSecurity
echo   [sqlmap] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae com ModSecurity (porta !P_MUTT_MODSEC!)" "http://localhost:!P_MUTT_MODSEC!!MUTT_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_MUTT_MODSEC!!MUTT_SQLI_SUFFIX!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - Coraza
echo   [sqlmap] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\sqlmap\sqlmap_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "SQLMAP - Mutillidae com Coraza (porta !P_MUTT_CORAZA!)" "http://localhost:!P_MUTT_CORAZA!!MUTT_SQLI_SUFFIX!"
%PYTHON% "!SQLMAP!" ^
    -u "http://localhost:!P_MUTT_CORAZA!!MUTT_SQLI_SUFFIX!" ^
    !SQLMAP_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: ================================================================
:: === XSSTRIKE ===
:: ================================================================
echo.
echo ------------------------------------------------------------------
echo  XSSTRIKE - Cross-Site Scripting (XSS)
echo ------------------------------------------------------------------

:: DVWA - sem WAF
echo   [XSStrike] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA sem WAF (porta !P_DVWA_NOWAF!)" "http://localhost:!P_DVWA_NOWAF!!DVWA_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_DVWA_NOWAF!!DVWA_XSS_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - DoBotShield
echo   [XSStrike] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA com DoBotShield (porta !P_DVWA_DOBOT!)" "http://localhost:!P_DVWA_DOBOT!!DVWA_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_DVWA_DOBOT!!DVWA_XSS_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - ModSecurity
echo   [XSStrike] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA com ModSecurity (porta !P_DVWA_MODSEC!)" "http://localhost:!P_DVWA_MODSEC!!DVWA_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_DVWA_MODSEC!!DVWA_XSS_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - Coraza
echo   [XSStrike] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - DVWA com Coraza (porta !P_DVWA_CORAZA!)" "http://localhost:!P_DVWA_CORAZA!!DVWA_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_DVWA_CORAZA!!DVWA_XSS_SUFFIX!" ^
    --cookie "!DVWA_COOKIE!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - sem WAF
echo   [XSStrike] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae sem WAF (porta !P_MUTT_NOWAF!)" "http://localhost:!P_MUTT_NOWAF!!MUTT_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_MUTT_NOWAF!!MUTT_XSS_SUFFIX!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - DoBotShield
echo   [XSStrike] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae com DoBotShield (porta !P_MUTT_DOBOT!)" "http://localhost:!P_MUTT_DOBOT!!MUTT_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_MUTT_DOBOT!!MUTT_XSS_SUFFIX!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - ModSecurity
echo   [XSStrike] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae com ModSecurity (porta !P_MUTT_MODSEC!)" "http://localhost:!P_MUTT_MODSEC!!MUTT_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_MUTT_MODSEC!!MUTT_XSS_SUFFIX!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - Coraza
echo   [XSStrike] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\xsstrike\xsstrike_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "XSSTRIKE - Mutillidae com Coraza (porta !P_MUTT_CORAZA!)" "http://localhost:!P_MUTT_CORAZA!!MUTT_XSS_SUFFIX!"
%PYTHON% "!XSSTRIKE!" ^
    -u "http://localhost:!P_MUTT_CORAZA!!MUTT_XSS_SUFFIX!" ^
    !XSSTRIKE_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: ================================================================
:: === NUCLEI ===
:: ================================================================
echo.
echo ------------------------------------------------------------------
echo  NUCLEI - Varredura de Vulnerabilidades
echo ------------------------------------------------------------------

:: DVWA - sem WAF
echo   [nuclei] DVWA sem WAF...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_semwaf.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA sem WAF (porta !P_DVWA_NOWAF!)" "http://localhost:!P_DVWA_NOWAF!"
"!NUCLEI!" ^
    -u "http://localhost:!P_DVWA_NOWAF!" ^
    -H "Cookie: !DVWA_COOKIE!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - DoBotShield
echo   [nuclei] DVWA com DoBotShield...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_dobotshield.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA com DoBotShield (porta !P_DVWA_DOBOT!)" "http://localhost:!P_DVWA_DOBOT!"
"!NUCLEI!" ^
    -u "http://localhost:!P_DVWA_DOBOT!" ^
    -H "Cookie: !DVWA_COOKIE!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - ModSecurity
echo   [nuclei] DVWA com ModSecurity...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_modsecurity.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA com ModSecurity (porta !P_DVWA_MODSEC!)" "http://localhost:!P_DVWA_MODSEC!"
"!NUCLEI!" ^
    -u "http://localhost:!P_DVWA_MODSEC!" ^
    -H "Cookie: !DVWA_COOKIE!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: DVWA - Coraza
echo   [nuclei] DVWA com Coraza...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_dvwa_coraza.txt"
call :log_header "!LOG_FILE!" "NUCLEI - DVWA com Coraza (porta !P_DVWA_CORAZA!)" "http://localhost:!P_DVWA_CORAZA!"
"!NUCLEI!" ^
    -u "http://localhost:!P_DVWA_CORAZA!" ^
    -H "Cookie: !DVWA_COOKIE!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - sem WAF
echo   [nuclei] Mutillidae sem WAF...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_semwaf.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae sem WAF (porta !P_MUTT_NOWAF!)" "http://localhost:!P_MUTT_NOWAF!"
"!NUCLEI!" ^
    -u "http://localhost:!P_MUTT_NOWAF!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - DoBotShield
echo   [nuclei] Mutillidae com DoBotShield...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_dobotshield.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae com DoBotShield (porta !P_MUTT_DOBOT!)" "http://localhost:!P_MUTT_DOBOT!"
"!NUCLEI!" ^
    -u "http://localhost:!P_MUTT_DOBOT!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - ModSecurity
echo   [nuclei] Mutillidae com ModSecurity...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_modsecurity.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae com ModSecurity (porta !P_MUTT_MODSEC!)" "http://localhost:!P_MUTT_MODSEC!"
"!NUCLEI!" ^
    -u "http://localhost:!P_MUTT_MODSEC!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: Mutillidae - Coraza
echo   [nuclei] Mutillidae com Coraza...
set "LOG_FILE=!LOG_DIR!\nuclei\nuclei_mutillidae_coraza.txt"
call :log_header "!LOG_FILE!" "NUCLEI - Mutillidae com Coraza (porta !P_MUTT_CORAZA!)" "http://localhost:!P_MUTT_CORAZA!"
"!NUCLEI!" ^
    -u "http://localhost:!P_MUTT_CORAZA!" ^
    !NUCLEI_OPTS! ^
    >> "!LOG_FILE!" 2>&1
echo      Concluido.

:: ================================================================
:: ETAPA 6 - Sumario
:: ================================================================
echo.
echo [6/6] Testes concluidos.
echo.
echo ==================================================================
echo   SUMARIO DOS LOGS
echo ==================================================================
echo.
echo   Todos os logs foram salvos em: %LOG_DIR%\
echo.
echo   Estrutura:
echo   logs\
echo   +-- sqlmap\        (24 arquivos: 8 alvos x 3 apps)
echo   ^|   +-- sqlmap_dvwa_semwaf.txt
echo   ^|   +-- sqlmap_dvwa_dobotshield.txt
echo   ^|   +-- sqlmap_dvwa_modsecurity.txt
echo   ^|   +-- sqlmap_dvwa_coraza.txt
echo   ^|   +-- sqlmap_mutillidae_semwaf.txt
echo   ^|   +-- sqlmap_mutillidae_dobotshield.txt
echo   ^|   +-- sqlmap_mutillidae_modsecurity.txt
echo   ^|   +-- sqlmap_mutillidae_coraza.txt
echo   +-- xsstrike\      (mesma estrutura)
echo   +-- nuclei\        (mesma estrutura)
echo.
echo   Fim: %date% %time%
echo ==================================================================
echo.
pause
