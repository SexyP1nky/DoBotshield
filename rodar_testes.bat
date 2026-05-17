@echo off
setlocal enabledelayedexpansion

:: ==================================================================
:: DoBotShield - Suite de Testes Comparativos de WAF
:: ==================================================================
:: 7 ferramentas x 8 alvos = 56 logs
:: Parametros IDENTICOS por ferramenta — so a URL muda.
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

:: Portas
set P_DVWA_NOWAF=8080
set P_MUTT_NOWAF=8081
set P_DVWA_DOBOT=9080
set P_MUTT_DOBOT=9081
set P_DVWA_MODSEC=9180
set P_MUTT_MODSEC=9181
set P_DVWA_CORAZA=9280
set P_MUTT_CORAZA=9281

:: URLs vulneraveis
set "DVWA_SQLI=/vulnerabilities/sqli/?id=1&Submit=Submit"
set "MUTT_SQLI=/index.php?page=user-info.php&username=admin&password=&user-info-php-submit-button=View+Account+Details"
set "DVWA_XSS=/vulnerabilities/xss_r/?name=test"
set "MUTT_XSS=/index.php?page=dns-lookup.php&target_host=test&dns-lookup-php-submit-button=Lookup+DNS"
set "DVWA_CMDI=/vulnerabilities/exec/"
set "DVWA_CMDI_DATA=ip=127.0.0.1&Submit=Submit"
set "MUTT_CMDI=/index.php?page=dns-lookup.php&target_host=127.0.0.1&dns-lookup-php-submit-button=Lookup+DNS"

:: Parametros padronizados
set "SQLMAP_OPTS=--level=1 --risk=1 --batch --delay=1 --timeout=30 --retries=1 --no-cast"
set "XSSTRIKE_OPTS=--skip-dom --timeout 10"
set "COMMIX_OPTS=--batch --output-dir=%TEMP%\commix_out"
set "WRK_OPTS=-t2 -c10 -d30s"
set "NUCLEI_OPTS=-rate-limit 10 -timeout 10 -nc -silent"
set "ZAP_OPTS=-I -m 2"
set "TESTSSL_OPTS=--quiet --warnings batch --color 0"

echo ==================================================================
echo   DoBotShield - Suite de Testes de Seguranca
echo   Inicio: %date% %time%
echo ==================================================================
echo.

:: ==================================================================
:: PRE-REQUISITOS
:: ==================================================================
if not exist "%SQLMAP%" (
    echo [ERRO] sqlmap nao encontrado. Execute ferramentas\baixar_ferramentas.bat
    exit /b 1
)
if not exist "%XSSTRIKE%" (
    echo [ERRO] XSStrike nao encontrado. Execute ferramentas\baixar_ferramentas.bat
    exit /b 1
)
if not exist "%COMMIX%" (
    echo [ERRO] commix nao encontrado. Execute ferramentas\baixar_ferramentas.bat
    exit /b 1
)
if not exist "%NUCLEI%" (
    echo [ERRO] nuclei nao encontrado. Execute ferramentas\baixar_ferramentas.bat
    exit /b 1
)
where docker >nul 2>&1 || (
    echo [ERRO] docker nao encontrado.
    exit /b 1
)

docker image inspect drwetter/testssl.sh >nul 2>&1 || docker pull drwetter/testssl.sh
docker image inspect ghcr.io/zaproxy/zaproxy:stable >nul 2>&1 || docker pull ghcr.io/zaproxy/zaproxy:stable
docker image inspect lab_wrk >nul 2>&1 || docker build -t lab_wrk "%SCRIPT_DIR%docker\wrk"

:: ==================================================================
:: LIMPAR LOGS ANTIGOS (evita duplicacao)
:: ==================================================================
echo [1] Limpando logs antigos...
for %%d in (testssl zap sqlmap xsstrike commix wrk nuclei) do (
    if exist "%LOG_DIR%\%%d" rd /s /q "%LOG_DIR%\%%d"
    mkdir "%LOG_DIR%\%%d"
)
if not exist "%COOKIES_DIR%" mkdir "%COOKIES_DIR%"
echo     OK.

:: ==================================================================
:: SUBIR DOCKER
:: ==================================================================
echo.
echo [2] Subindo laboratorio Docker...
docker compose -f "%SCRIPT_DIR%docker-compose.yml" up -d --build
if errorlevel 1 (
    echo [ERRO] Docker Compose falhou.
    exit /b 1
)
echo     Aguardando 60s...
timeout /t 60 /nobreak >nul

set /a W=0
:w1
set /a W+=1
if !W! gtr 24 ( echo [ERRO] DVWA timeout. & exit /b 1 )
curl -s -o nul -w "%%{http_code}" "http://localhost:%P_DVWA_NOWAF%/login.php" 2>nul | findstr /r "^[23]" >nul
if errorlevel 1 ( timeout /t 5 /nobreak >nul & goto w1 )
echo     DVWA OK.

set /a W=0
:w2
set /a W+=1
if !W! gtr 24 ( echo [AVISO] Mutillidae timeout, continuando... & goto cfg )
curl -s -o nul -w "%%{http_code}" "http://localhost:%P_MUTT_NOWAF%/" 2>nul | findstr /r "^[23]" >nul
if errorlevel 1 ( timeout /t 5 /nobreak >nul & goto w2 )
echo     Mutillidae OK.

:: ==================================================================
:: CONFIGURAR APPS
:: ==================================================================
:cfg
echo.
echo [3] Configurando aplicacoes...
set "DVWA_COOKIE_FILE=%COOKIES_DIR%\dvwa.txt"

curl -s -c "!DVWA_COOKIE_FILE!" -o "%TEMP%\dvwa_login.html" "http://localhost:%P_DVWA_NOWAF%/login.php"
for /f "usebackq delims=" %%t in (`powershell -NoProfile -Command "try { (Select-String -Path '%TEMP%\dvwa_login.html' -Pattern 'user_token').Line -replace '.*value=.([^'']+).*','$1' } catch { '' }"`) do set "DVWA_CSRF=%%t"
curl -s -b "!DVWA_COOKIE_FILE!" -c "!DVWA_COOKIE_FILE!" -d "username=admin&password=password&Login=Login&user_token=!DVWA_CSRF!" -L -o nul "http://localhost:%P_DVWA_NOWAF%/login.php"
curl -s -b "!DVWA_COOKIE_FILE!" -c "!DVWA_COOKIE_FILE!" -d "security=low&seclev_submit=Submit" -o nul "http://localhost:%P_DVWA_NOWAF%/security.php"

for /f "usebackq delims=" %%s in (`powershell -NoProfile -Command "(Get-Content '!DVWA_COOKIE_FILE!' | Where-Object {$_ -match 'PHPSESSID'} | Select-Object -First 1) -replace '.*\t',''"`) do set "DVWA_PHPSESSID=%%s"
if "!DVWA_PHPSESSID!"=="" (
    set "DVWA_COOKIE=security=low"
) else (
    set "DVWA_COOKIE=PHPSESSID=!DVWA_PHPSESSID!; security=low"
)
echo     DVWA: security=low, sessao=!DVWA_PHPSESSID!

set "MUTT_COOKIE_FILE=%COOKIES_DIR%\mutillidae.txt"
curl -s -c "!MUTT_COOKIE_FILE!" -o nul "http://localhost:%P_MUTT_NOWAF%/set-up-database.php" 2>nul
timeout /t 3 /nobreak >nul
curl -s -b "!MUTT_COOKIE_FILE!" -c "!MUTT_COOKIE_FILE!" -d "security-level=0" -o nul "http://localhost:%P_MUTT_NOWAF%/index.php?page=home.php"
echo     Mutillidae: security-level=0

:: ==================================================================
:: TESTSSL
:: ==================================================================
echo.
echo [4] testssl.sh - Analise TLS/SSL
echo ------------------------------------------------------------------

set "L=!LOG_DIR!\testssl\testssl_dvwa_semwaf.txt"
echo   DVWA sem WAF...
( echo [testssl] DVWA sem WAF - host.docker.internal:!P_DVWA_NOWAF! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_DVWA_NOWAF! >> "!L!" 2>&1

set "L=!LOG_DIR!\testssl\testssl_dvwa_dobotshield.txt"
echo   DVWA DoBotShield...
( echo [testssl] DVWA DoBotShield - host.docker.internal:!P_DVWA_DOBOT! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_DVWA_DOBOT! >> "!L!" 2>&1

set "L=!LOG_DIR!\testssl\testssl_dvwa_modsecurity.txt"
echo   DVWA ModSecurity...
( echo [testssl] DVWA ModSecurity - host.docker.internal:!P_DVWA_MODSEC! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_DVWA_MODSEC! >> "!L!" 2>&1

set "L=!LOG_DIR!\testssl\testssl_dvwa_coraza.txt"
echo   DVWA Coraza...
( echo [testssl] DVWA Coraza - host.docker.internal:!P_DVWA_CORAZA! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_DVWA_CORAZA! >> "!L!" 2>&1

set "L=!LOG_DIR!\testssl\testssl_mutillidae_semwaf.txt"
echo   Mutillidae sem WAF...
( echo [testssl] Mutillidae sem WAF - host.docker.internal:!P_MUTT_NOWAF! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_MUTT_NOWAF! >> "!L!" 2>&1

set "L=!LOG_DIR!\testssl\testssl_mutillidae_dobotshield.txt"
echo   Mutillidae DoBotShield...
( echo [testssl] Mutillidae DoBotShield - host.docker.internal:!P_MUTT_DOBOT! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_MUTT_DOBOT! >> "!L!" 2>&1

set "L=!LOG_DIR!\testssl\testssl_mutillidae_modsecurity.txt"
echo   Mutillidae ModSecurity...
( echo [testssl] Mutillidae ModSecurity - host.docker.internal:!P_MUTT_MODSEC! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_MUTT_MODSEC! >> "!L!" 2>&1

set "L=!LOG_DIR!\testssl\testssl_mutillidae_coraza.txt"
echo   Mutillidae Coraza...
( echo [testssl] Mutillidae Coraza - host.docker.internal:!P_MUTT_CORAZA! - !date! !time! ) > "!L!"
docker run --rm drwetter/testssl.sh !TESTSSL_OPTS! host.docker.internal:!P_MUTT_CORAZA! >> "!L!" 2>&1

:: ==================================================================
:: OWASP ZAP (relatorios HTML em logs\zap\)
:: ==================================================================
echo.
echo [5] OWASP ZAP - Baseline Scan (HTML reports)
echo ------------------------------------------------------------------

set "ZAP_VOL=!LOG_DIR!\zap"
set "ZAP_CMD=docker run --rm -v "!ZAP_VOL!:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py"

echo   DVWA sem WAF...
!ZAP_CMD! -t "http://host.docker.internal:!P_DVWA_NOWAF!/" !ZAP_OPTS! -r zap_dvwa_semwaf.html >nul 2>&1

echo   DVWA DoBotShield...
!ZAP_CMD! -t "http://host.docker.internal:!P_DVWA_DOBOT!/" !ZAP_OPTS! -r zap_dvwa_dobotshield.html >nul 2>&1

echo   DVWA ModSecurity...
!ZAP_CMD! -t "http://host.docker.internal:!P_DVWA_MODSEC!/" !ZAP_OPTS! -r zap_dvwa_modsecurity.html >nul 2>&1

echo   DVWA Coraza...
!ZAP_CMD! -t "http://host.docker.internal:!P_DVWA_CORAZA!/" !ZAP_OPTS! -r zap_dvwa_coraza.html >nul 2>&1

echo   Mutillidae sem WAF...
!ZAP_CMD! -t "http://host.docker.internal:!P_MUTT_NOWAF!/" !ZAP_OPTS! -r zap_mutillidae_semwaf.html >nul 2>&1

echo   Mutillidae DoBotShield...
!ZAP_CMD! -t "http://host.docker.internal:!P_MUTT_DOBOT!/" !ZAP_OPTS! -r zap_mutillidae_dobotshield.html >nul 2>&1

echo   Mutillidae ModSecurity...
!ZAP_CMD! -t "http://host.docker.internal:!P_MUTT_MODSEC!/" !ZAP_OPTS! -r zap_mutillidae_modsecurity.html >nul 2>&1

echo   Mutillidae Coraza...
!ZAP_CMD! -t "http://host.docker.internal:!P_MUTT_CORAZA!/" !ZAP_OPTS! -r zap_mutillidae_coraza.html >nul 2>&1

:: ==================================================================
:: SQLMAP
:: ==================================================================
echo.
echo [6] SQLMap - SQL Injection
echo ------------------------------------------------------------------

set "L=!LOG_DIR!\sqlmap\sqlmap_dvwa_semwaf.txt"
echo   DVWA sem WAF...
( echo [sqlmap] DVWA sem WAF - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_NOWAF!!DVWA_SQLI!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\sqlmap\sqlmap_dvwa_dobotshield.txt"
echo   DVWA DoBotShield...
( echo [sqlmap] DVWA DoBotShield - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_DOBOT!!DVWA_SQLI!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\sqlmap\sqlmap_dvwa_modsecurity.txt"
echo   DVWA ModSecurity...
( echo [sqlmap] DVWA ModSecurity - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_MODSEC!!DVWA_SQLI!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\sqlmap\sqlmap_dvwa_coraza.txt"
echo   DVWA Coraza...
( echo [sqlmap] DVWA Coraza - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_DVWA_CORAZA!!DVWA_SQLI!" --cookie="!DVWA_COOKIE!" !SQLMAP_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\sqlmap\sqlmap_mutillidae_semwaf.txt"
echo   Mutillidae sem WAF...
( echo [sqlmap] Mutillidae sem WAF - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_NOWAF!!MUTT_SQLI!" !SQLMAP_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\sqlmap\sqlmap_mutillidae_dobotshield.txt"
echo   Mutillidae DoBotShield...
( echo [sqlmap] Mutillidae DoBotShield - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_DOBOT!!MUTT_SQLI!" !SQLMAP_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\sqlmap\sqlmap_mutillidae_modsecurity.txt"
echo   Mutillidae ModSecurity...
( echo [sqlmap] Mutillidae ModSecurity - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_MODSEC!!MUTT_SQLI!" !SQLMAP_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\sqlmap\sqlmap_mutillidae_coraza.txt"
echo   Mutillidae Coraza...
( echo [sqlmap] Mutillidae Coraza - !date! !time! ) > "!L!"
%PYTHON% "!SQLMAP!" -u "http://localhost:!P_MUTT_CORAZA!!MUTT_SQLI!" !SQLMAP_OPTS! >> "!L!" 2>&1

:: ==================================================================
:: XSSTRIKE
:: ==================================================================
echo.
echo [7] XSStrike - XSS Fuzzing
echo ------------------------------------------------------------------

set "L=!LOG_DIR!\xsstrike\xsstrike_dvwa_semwaf.txt"
echo   DVWA sem WAF...
( echo [xsstrike] DVWA sem WAF - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_NOWAF!!DVWA_XSS!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\xsstrike\xsstrike_dvwa_dobotshield.txt"
echo   DVWA DoBotShield...
( echo [xsstrike] DVWA DoBotShield - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_DOBOT!!DVWA_XSS!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\xsstrike\xsstrike_dvwa_modsecurity.txt"
echo   DVWA ModSecurity...
( echo [xsstrike] DVWA ModSecurity - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_MODSEC!!DVWA_XSS!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\xsstrike\xsstrike_dvwa_coraza.txt"
echo   DVWA Coraza...
( echo [xsstrike] DVWA Coraza - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_DVWA_CORAZA!!DVWA_XSS!" --headers "Cookie: !DVWA_COOKIE!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\xsstrike\xsstrike_mutillidae_semwaf.txt"
echo   Mutillidae sem WAF...
( echo [xsstrike] Mutillidae sem WAF - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_NOWAF!!MUTT_XSS!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\xsstrike\xsstrike_mutillidae_dobotshield.txt"
echo   Mutillidae DoBotShield...
( echo [xsstrike] Mutillidae DoBotShield - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_DOBOT!!MUTT_XSS!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\xsstrike\xsstrike_mutillidae_modsecurity.txt"
echo   Mutillidae ModSecurity...
( echo [xsstrike] Mutillidae ModSecurity - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_MODSEC!!MUTT_XSS!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\xsstrike\xsstrike_mutillidae_coraza.txt"
echo   Mutillidae Coraza...
( echo [xsstrike] Mutillidae Coraza - !date! !time! ) > "!L!"
%PYTHON% "!XSSTRIKE!" -u "http://localhost:!P_MUTT_CORAZA!!MUTT_XSS!" !XSSTRIKE_OPTS! >> "!L!" 2>&1

:: ==================================================================
:: COMMIX
:: ==================================================================
echo.
echo [8] Commix - Command Injection
echo ------------------------------------------------------------------

set "L=!LOG_DIR!\commix\commix_dvwa_semwaf.txt"
echo   DVWA sem WAF...
( echo [commix] DVWA sem WAF - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_NOWAF!!DVWA_CMDI!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\commix\commix_dvwa_dobotshield.txt"
echo   DVWA DoBotShield...
( echo [commix] DVWA DoBotShield - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_DOBOT!!DVWA_CMDI!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\commix\commix_dvwa_modsecurity.txt"
echo   DVWA ModSecurity...
( echo [commix] DVWA ModSecurity - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_MODSEC!!DVWA_CMDI!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\commix\commix_dvwa_coraza.txt"
echo   DVWA Coraza...
( echo [commix] DVWA Coraza - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_DVWA_CORAZA!!DVWA_CMDI!" --data="!DVWA_CMDI_DATA!" --cookie="!DVWA_COOKIE!" !COMMIX_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\commix\commix_mutillidae_semwaf.txt"
echo   Mutillidae sem WAF...
( echo [commix] Mutillidae sem WAF - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_NOWAF!!MUTT_CMDI!" !COMMIX_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\commix\commix_mutillidae_dobotshield.txt"
echo   Mutillidae DoBotShield...
( echo [commix] Mutillidae DoBotShield - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_DOBOT!!MUTT_CMDI!" !COMMIX_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\commix\commix_mutillidae_modsecurity.txt"
echo   Mutillidae ModSecurity...
( echo [commix] Mutillidae ModSecurity - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_MODSEC!!MUTT_CMDI!" !COMMIX_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\commix\commix_mutillidae_coraza.txt"
echo   Mutillidae Coraza...
( echo [commix] Mutillidae Coraza - !date! !time! ) > "!L!"
%PYTHON% "!COMMIX!" --url="http://localhost:!P_MUTT_CORAZA!!MUTT_CMDI!" !COMMIX_OPTS! >> "!L!" 2>&1

:: ==================================================================
:: WRK
:: ==================================================================
echo.
echo [9] wrk - Teste de Carga HTTP
echo ------------------------------------------------------------------

set "L=!LOG_DIR!\wrk\wrk_dvwa_semwaf.txt"
echo   DVWA sem WAF...
( echo [wrk] DVWA sem WAF - http://host.docker.internal:!P_DVWA_NOWAF!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_NOWAF!/" >> "!L!" 2>&1

set "L=!LOG_DIR!\wrk\wrk_dvwa_dobotshield.txt"
echo   DVWA DoBotShield...
( echo [wrk] DVWA DoBotShield - http://host.docker.internal:!P_DVWA_DOBOT!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_DOBOT!/" >> "!L!" 2>&1

set "L=!LOG_DIR!\wrk\wrk_dvwa_modsecurity.txt"
echo   DVWA ModSecurity...
( echo [wrk] DVWA ModSecurity - http://host.docker.internal:!P_DVWA_MODSEC!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_MODSEC!/" >> "!L!" 2>&1

set "L=!LOG_DIR!\wrk\wrk_dvwa_coraza.txt"
echo   DVWA Coraza...
( echo [wrk] DVWA Coraza - http://host.docker.internal:!P_DVWA_CORAZA!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_DVWA_CORAZA!/" >> "!L!" 2>&1

set "L=!LOG_DIR!\wrk\wrk_mutillidae_semwaf.txt"
echo   Mutillidae sem WAF...
( echo [wrk] Mutillidae sem WAF - http://host.docker.internal:!P_MUTT_NOWAF!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_NOWAF!/" >> "!L!" 2>&1

set "L=!LOG_DIR!\wrk\wrk_mutillidae_dobotshield.txt"
echo   Mutillidae DoBotShield...
( echo [wrk] Mutillidae DoBotShield - http://host.docker.internal:!P_MUTT_DOBOT!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_DOBOT!/" >> "!L!" 2>&1

set "L=!LOG_DIR!\wrk\wrk_mutillidae_modsecurity.txt"
echo   Mutillidae ModSecurity...
( echo [wrk] Mutillidae ModSecurity - http://host.docker.internal:!P_MUTT_MODSEC!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_MODSEC!/" >> "!L!" 2>&1

set "L=!LOG_DIR!\wrk\wrk_mutillidae_coraza.txt"
echo   Mutillidae Coraza...
( echo [wrk] Mutillidae Coraza - http://host.docker.internal:!P_MUTT_CORAZA!/ - !date! !time! ) > "!L!"
docker run --rm lab_wrk !WRK_OPTS! "http://host.docker.internal:!P_MUTT_CORAZA!/" >> "!L!" 2>&1

:: ==================================================================
:: NUCLEI
:: ==================================================================
echo.
echo [10] nuclei - Vulnerability Scanner
echo ------------------------------------------------------------------

set "L=!LOG_DIR!\nuclei\nuclei_dvwa_semwaf.txt"
echo   DVWA sem WAF...
( echo [nuclei] DVWA sem WAF - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_NOWAF!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\nuclei\nuclei_dvwa_dobotshield.txt"
echo   DVWA DoBotShield...
( echo [nuclei] DVWA DoBotShield - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_DOBOT!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\nuclei\nuclei_dvwa_modsecurity.txt"
echo   DVWA ModSecurity...
( echo [nuclei] DVWA ModSecurity - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_MODSEC!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\nuclei\nuclei_dvwa_coraza.txt"
echo   DVWA Coraza...
( echo [nuclei] DVWA Coraza - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_DVWA_CORAZA!" -H "Cookie: !DVWA_COOKIE!" !NUCLEI_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\nuclei\nuclei_mutillidae_semwaf.txt"
echo   Mutillidae sem WAF...
( echo [nuclei] Mutillidae sem WAF - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_NOWAF!" !NUCLEI_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\nuclei\nuclei_mutillidae_dobotshield.txt"
echo   Mutillidae DoBotShield...
( echo [nuclei] Mutillidae DoBotShield - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_DOBOT!" !NUCLEI_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\nuclei\nuclei_mutillidae_modsecurity.txt"
echo   Mutillidae ModSecurity...
( echo [nuclei] Mutillidae ModSecurity - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_MODSEC!" !NUCLEI_OPTS! >> "!L!" 2>&1

set "L=!LOG_DIR!\nuclei\nuclei_mutillidae_coraza.txt"
echo   Mutillidae Coraza...
( echo [nuclei] Mutillidae Coraza - !date! !time! ) > "!L!"
"!NUCLEI!" -u "http://localhost:!P_MUTT_CORAZA!" !NUCLEI_OPTS! >> "!L!" 2>&1

:: ==================================================================
:: FIM
:: ==================================================================
echo.
echo ==================================================================
echo   CONCLUIDO - %date% %time%
echo   56 logs em: %LOG_DIR%\
echo ==================================================================
