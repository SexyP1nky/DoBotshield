# DoBot Shield - Configuracao administrativa

Esta pasta contem uma tela estatica para montar as variaveis de ambiente usadas pelo DoBot Shield.

A tela nao altera arquivos do proxy, nao inicia o servico e nao grava segredos. Ela apenas gera comandos para PowerShell, Bash ou `.env`.

## Abrir

Abra no navegador:

```text
admin-config/index.html
```

Nao e necessario servidor web.

## Campos principais

- `TARGET_URL`: URL interna do sistema legado.
- `PROXY_PORT`: porta HTTPS publica do Shield.
- `ENABLE_WAF`: liga/desliga inspecao de requisicoes.
- `WAF_MODE`: `block`, `monitor` ou `off`.
- `ENABLE_RESPONSE_INSPECTION`: liga/desliga inspecao de respostas do backend.
- `ENABLE_RATE_LIMIT`: liga/desliga rate limit.
- `RATE_LIMIT`, `BURST_LIMIT`, `MAX_CONNS`, `MAX_TRACKED_IPS`: limites por IP.
- `MAX_BODY_SIZE`: limite de body de requisicao.
- `RESPONSE_INSPECTION_LIMIT`: limite de bytes por resposta inspecionada.
- `CERT_FILE` e `KEY_FILE`: certificado e chave local do Shield.
- `TRUSTED_PROXIES`: proxies confiaveis para IP real.
- `INSECURE_SKIP_VERIFY`: aceita certificado TLS invalido do backend HTTPS.
- `WAF_ALLOWLIST`: excecoes por categoria e rota.
- `RATE_LIMIT_STATE_FILE`: arquivo opcional para persistir tokens do rate limiter.

## Modo WAF

Use `monitor` em homologacao ou no primeiro periodo de producao assistida. Ele registra deteccoes, mas nao bloqueia usuarios.

Use `block` depois de revisar falsos positivos.

Use `off` apenas para diagnostico controlado.

## Allowlist

Formato:

```text
SQLi:/api/search,XSS:/content-editor,/health
```

- `SQLi:/api/search` libera somente SQLi no prefixo `/api/search`.
- `XSS:/content-editor` libera somente XSS nesse prefixo.
- `/health` libera qualquer categoria nesse prefixo.

Prefira regras por categoria. Uma allowlist ampla demais reduz muito a protecao.

## TLS

`CERT_FILE` e `KEY_FILE` sao do Shield, nao do backend. Eles precisam existir antes da execucao.

Para laboratorio:

```powershell
cd certificado
go run .\gerar_cert.go
Move-Item .\server.crt ..\server.crt -Force
Move-Item .\server.key ..\server.key -Force
cd ..
```

Nao commite `server.crt` nem `server.key`.

`INSECURE_SKIP_VERIFY=true` afeta somente a conexao do Shield ate um `TARGET_URL=https://...`. O padrao seguro e `false`.

## Abas de saida

### PowerShell

Gera comandos `$env:...` e finaliza com:

```powershell
.\dobotshield.exe
```

### Bash

Gera comandos `export ...` e finaliza com:

```bash
./dobotshield
```

### .env

Gera um arquivo auxiliar. O binario atual nao carrega `.env` automaticamente; ele le as variaveis do processo.

## Variaveis avancadas nao exibidas

`CONTENT_SECURITY_POLICY` continua manual para evitar quebrar sistemas legados por acidente:

```powershell
$env:CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
```

Quando vazia, o Shield nao envia `Content-Security-Policy`.
