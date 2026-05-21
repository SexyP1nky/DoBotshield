# DoBot Shield

Proxy reverso de seguranca com WAF integrado, desenvolvido como Trabalho de Conclusao de Curso em Ciencia da Computacao. Atua na frente de aplicacoes web legadas sem exigir modificacao no codigo da aplicacao protegida.

---

## Arquitetura (modelo C4)

### Nivel 1 — Contexto do sistema

```
                    Internet
                       |
                  [ Usuario ]
                  (navegador,
                   ferramenta
                   de ataque)
                       |
                       | HTTPS (producao) / HTTP (laboratorio)
                       v
              +------------------+
              |   DoBot Shield   |  <- sistema analisado
              |  (proxy reverso  |
              |   com WAF)       |
              +------------------+
                       |
                       | HTTP interno
                       v
              +------------------+
              |  Aplicacao Web   |
              |  (legado: DVWA,  |
              |   Mutillidae...  |
              +------------------+
```

**DoBot Shield** recebe todo o trafego externo, aplica as politicas de seguranca e encaminha apenas as requisicoes validas para o sistema legado. A aplicacao protegida nao precisa ser alterada.

---

### Nivel 2 — Containers

```
+------------------------------------------------------------------------+
|                           DoBot Shield                                  |
|                                                                         |
|   +----------------+   +------------------+   +--------------------+   |
|   |   WAF          |   |  Rate Limiter    |   |  Reverse Proxy     |   |
|   | (waf/)         |   | (ratelimit/)     |   | (middleware/)      |   |
|   |                |   |                  |   |                    |   |
|   | Inspecao de    |   | Token bucket     |   | httputil.Reverse   |   |
|   | requisicoes e  |   | por IP com LRU   |   | Proxy com TLS      |   |
|   | respostas por  |   | e persistencia   |   | e headers de       |   |
|   | regex          |   | opcional         |   | seguranca          |   |
|   +----------------+   +------------------+   +--------------------+   |
|                                                                         |
|   +----------------+   +------------------+   +--------------------+   |
|   |  Blocklist     |   |  Config          |   |  Admin UI          |   |
|   | (blocklist/)   |   | (config/)        |   | (admin-config/)    |   |
|   |                |   |                  |   |                    |   |
|   | IPs/CIDRs      |   | Leitura de env   |   | Interface HTML     |   |
|   | bloqueados     |   | vars com         |   | estatica para      |   |
|   | antes do WAF   |   | defaults         |   | gerar comandos     |   |
|   +----------------+   +------------------+   +--------------------+   |
+------------------------------------------------------------------------+
            |                                           |
            v                                           v
     Aplicacao legada                            Operador humano
     (HTTP/HTTPS)                                (configura via .env)
```

---

### Nivel 3 — Componentes do WAF

```
+--------------------------------------------------+
|                   waf/                            |
|                                                   |
|  CheckRequest(r, body)                            |
|    |                                              |
|    +-- analyzePayload(path)                       |
|    +-- analyzePayload(query)                      |
|    +-- analyzePayload(headers selecionados)       |
|    +-- analyzePayload(body)                       |
|    +-- inspectMultipart(r, body)                  |
|         |                                         |
|         v                                         |
|    buildInspectionVariants(input)                 |
|    - original                                     |
|    - URL decode (ate 5 passes)                    |
|    - HTML decode (ate 3 passes)                   |
|    - unicode/hex escape decode                    |
|    - remocao de block comments                    |
|    - normalizacao de separadores                  |
|    - compactacao de payload                       |
|         |                                         |
|         v                                         |
|    patterns.go: 12 categorias de ataque           |
|    XSS | SQLi | CMD_INJ | PATH_TRAVERSAL          |
|    SSRF | XXE | JNDI | NoSQLi | SSTI              |
|    PROTOTYPE_POLLUTION | OPEN_REDIRECT            |
|    HTTP_HEADER_INJECTION                          |
|                                                   |
|  CheckResponse(resp, body)                        |
|    - RESPONSE_SQL_ERROR                           |
|    - RESPONSE_STACK_TRACE                         |
|    - RESPONSE_XSS_REFLECTION                      |
|    - RESPONSE_FILE_LEAK                           |
+--------------------------------------------------+
```

---

### Fluxo de uma requisicao

```
Requisicao HTTP/S chegando
        |
        v
[1] Gerar request_id (X-Request-ID)
        |
        v
[2] Extrair IP real (X-Forwarded-For com proxies confiaveis)
        |
        v
[3] Blocklist — IP bloqueado?
        | sim -> 403 Forbidden
        | nao
        v
[4] Metodo proibido? (TRACE/TRACK)
        | sim -> 405 Method Not Allowed
        | nao
        v
[5] Rate limit — tokens disponiveis?
        | nao -> 429 Too Many Requests
        | sim
        v
[6] WAF — inspecao de path, query, headers, body, multipart
        | ameaca detectada (modo block) -> 400 Bad Request
        | ameaca detectada (modo monitor) -> log e continua
        | limpo
        v
[7] Injetar X-Forwarded-For, X-Real-IP, X-Forwarded-Proto
        |
        v
[8] Encaminhar ao backend (httputil.ReverseProxy)
        |
        v
[9] ModifyResponse: remover headers de versao, injetar headers de seguranca
        |
        v
[10] Inspecao de resposta (SQL errors, stack traces, file leaks, XSS)
        | ameaca (modo block) -> 502 + JSON
        | limpo
        v
Resposta ao cliente
```

---

## Funcionalidades

| Camada | Recurso | Configuracao |
|---|---|---|
| Rede | Terminacao TLS (TLS 1.2+, ECDHE, AES-256-GCM) | `CERT_FILE`, `KEY_FILE` |
| Acesso | Blocklist por IP e CIDR | `BLOCKED_IPS` |
| Acesso | Rate limiting (token bucket por IP) | `RATE_LIMIT`, `BURST_LIMIT`, `MAX_CONNS` |
| WAF | Inspecao de requisicao (12 categorias) | `ENABLE_WAF`, `WAF_MODE` |
| WAF | Inspecao de resposta (4 categorias) | `ENABLE_RESPONSE_INSPECTION` |
| WAF | Allowlist por categoria e rota | `WAF_ALLOWLIST` |
| Headers | Remocao de headers de versao (Server, X-Powered-By) | automatico |
| Headers | Injecao de headers defensivos (HSTS, X-Frame, CSP...) | automatico |
| Proxy | IP real de clientes atras de proxy confiavel | `TRUSTED_PROXIES` |
| Proxy | Suporte a WebSocket (inspeciona handshake) | automatico |

---

## Estrutura do projeto

```
DoBotShield_v2/
|
|-- main.go                    Ponto de entrada, TLS e HTTP_MODE
|-- go.mod
|-- Dockerfile                 Imagem Docker para laboratorio
|-- docker-compose.yml         Lab completo: apps + 3 WAFs
|
|-- admin-config/              Interface web de configuracao (HTML puro)
|   |-- index.html
|   |-- scripts/               Logica de geracao de comandos (JS)
|   `-- styles/                Design tokens e componentes (CSS)
|
|-- blocklist/
|   `-- blocklist.go           Bloqueio por IP e CIDR
|
|-- config/
|   |-- config.go              Leitura de variaveis de ambiente
|   `-- config_test.go
|
|-- middleware/
|   |-- middleware.go          Proxy reverso, handlers, integracao WAF
|   `-- middleware_test.go
|
|-- ratelimit/
|   |-- ratelimit.go           Token bucket com LRU e persistencia
|   `-- ratelimit_test.go
|
|-- utils/
|   |-- utils.go               IP, request ID, logging
|   `-- utils_test.go
|
|-- waf/
|   |-- waf.go                 Inspecao de requisicao e resposta
|   |-- patterns.go            Padroes regex por categoria de ataque
|   `-- waf_test.go
|
|-- certificado/
|   `-- gerar_cert.go          Gerador de cert autoassinado (laboratorio)
|
|-- docker/
|   `-- coraza/                WAF Coraza + Caddy (terceiro WAF)
|       |-- Dockerfile
|       `-- Caddyfile
|
|-- ferramentas/               Ferramentas de teste (baixadas localmente)
|   `-- baixar_ferramentas.bat Download de sqlmap, XSStrike, nuclei
|
|-- logs/                      Resultados dos testes (gerados pelo .bat)
|   |-- sqlmap/
|   |-- xsstrike/
|   `-- nuclei/
|
`-- rodar_testes.bat           Suite de testes automatizada
```

Arquivos que existem apenas localmente (nao versionados):

```
server.crt, server.key         Certificado TLS
dobotshield, dobotshield.exe   Binario compilado
.env                           Variaveis de ambiente locais
state/ratelimit.json           Estado do rate limiter
ferramentas/sqlmap/            Ferramentas de teste (git clone)
ferramentas/XSStrike/
ferramentas/nuclei/
logs/                          Resultados de testes
```

---

## Variaveis de ambiente

| Variavel | Padrao | Descricao |
|---|---|---|
| `TARGET_URL` | `http://localhost:4280` | URL da aplicacao protegida |
| `PROXY_PORT` | `:443` | Porta de escuta do Shield |
| `HTTP_MODE` | `false` | `true` = HTTP puro (laboratorio); `false` = HTTPS (producao) |
| `ENABLE_WAF` | `true` | Liga/desliga WAF |
| `WAF_MODE` | `block` | `block`, `monitor` ou `off` |
| `ENABLE_RESPONSE_INSPECTION` | `true` | Inspecao de respostas do backend |
| `RESPONSE_INSPECTION_LIMIT` | `1048576` | Limite de bytes por resposta inspecionada |
| `WAF_ALLOWLIST` | vazio | Excecoes: `SQLi:/api/search,/health` |
| `BLOCKED_IPS` | vazio | IPs/CIDRs bloqueados antes do WAF: `1.2.3.4,10.0.0.0/8` |
| `ENABLE_RATE_LIMIT` | `true` | Liga/desliga rate limiting |
| `RATE_LIMIT` | `10.0` | Requisicoes por segundo por IP |
| `BURST_LIMIT` | `20` | Pico permitido (token bucket) |
| `MAX_CONNS` | `10` | Conexoes simultaneas por IP |
| `MAX_TRACKED_IPS` | `10000` | IPs monitorados em memoria |
| `RATE_LIMIT_STATE_FILE` | vazio | Arquivo de persistencia do rate limiter |
| `MAX_BODY_SIZE` | `1048576` | Limite do body de requisicao em bytes |
| `CERT_FILE` | `server.crt` | Certificado TLS |
| `KEY_FILE` | `server.key` | Chave privada TLS |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Proxies confiaveis (CSV de IPs/CIDRs) |
| `INSECURE_SKIP_VERIFY` | `false` | Ignora TLS do backend (apenas em laboratorio) |
| `CONTENT_SECURITY_POLICY` | vazio | Header CSP opcional |

Valores booleanos aceitos: `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off`, `enabled`, `disabled`.

---

## Execucao em producao (HTTPS)

**Requisito:** Go 1.21+

```powershell
# Windows
cd certificado
go run .\gerar_cert.go
Move-Item .\server.crt ..\server.crt -Force
Move-Item .\server.key ..\server.key -Force
cd ..

$env:TARGET_URL = 'http://localhost:4280'
$env:PROXY_PORT = ':443'
$env:WAF_MODE = 'block'
go build -o dobotshield.exe .
.\dobotshield.exe
```

```bash
# Linux/macOS
cd certificado && go run gerar_cert.go && mv server.crt ../ && mv server.key ../ && cd ..

export TARGET_URL='http://localhost:4280'
export PROXY_PORT=':443'
export WAF_MODE='block'
go build -o dobotshield .
./dobotshield
```

---

## Laboratorio Docker (comparacao de WAFs)

O `docker-compose.yml` sobe oito endpoints para comparacao:

| Porta | Configuracao |
|---|---|
| 8080 | DVWA sem WAF (referencia) |
| 8081 | Mutillidae sem WAF (referencia) |
| 9080 | DoBotShield protegendo DVWA (HTTPS) |
| 9081 | DoBotShield protegendo Mutillidae (HTTPS) |
| 9180 | ModSecurity + OWASP CRS protegendo DVWA (HTTPS) |
| 9181 | ModSecurity + OWASP CRS protegendo Mutillidae (HTTPS) |
| 9280 | Coraza + OWASP CRS protegendo DVWA (HTTPS) |
| 9281 | Coraza + OWASP CRS protegendo Mutillidae (HTTPS) |

**Coraza** e um motor WAF escrito em Go, compativel com as regras OWASP CRS, mais recente e menos consolidado que o ModSecurity — escolhido como terceiro ponto de comparacao academica.

```powershell
# Subir todo o laboratorio
docker compose up -d --build

# Derrubar
docker compose down
```

---

## Ferramentas de teste

```powershell
# 1. Baixar sqlmap, XSStrike e nuclei
ferramentas\baixar_ferramentas.bat

# 2. Executar suite de testes (requer Docker rodando)
rodar_testes.bat
```

A suite executa cada ferramenta contra os 8 endpoints com **parametros identicos** — apenas a URL muda. Isso garante que os resultados reflitam a eficacia de cada WAF e nao variacoes de configuracao do teste.

Logs gerados em `logs\`:

```
logs\
+-- sqlmap\
|   +-- sqlmap_dvwa_semwaf.txt
|   +-- sqlmap_dvwa_dobotshield.txt
|   +-- sqlmap_dvwa_modsecurity.txt
|   +-- sqlmap_dvwa_coraza.txt
|   +-- sqlmap_mutillidae_semwaf.txt
|   ... (8 arquivos por ferramenta)
+-- xsstrike\  (mesma estrutura)
`-- nuclei\    (mesma estrutura)
```

---

## Interface de configuracao

Abra `admin-config/index.html` em qualquer navegador. A interface gera o comando de inicializacao nos formatos PowerShell, Bash ou `.env` sem precisar de servidor backend.

---

## Compilar e testar

```powershell
# Compilar
go build -o dobotshield.exe .
Get-FileHash .\dobotshield.exe -Algorithm SHA256

# Testes automatizados
$env:GOCACHE = Join-Path (Get-Location) '.gocache'
go test ./...
```

---

## Modo monitor

Use `WAF_MODE=monitor` para registrar deteccoes sem bloquear. Recomendado antes de ativar `block` em producao.

```
WAF_DETECT     -> requisicao suspeita registrada, encaminhada
WAF_BLOCK      -> requisicao bloqueada (modo block)
RESPONSE_WAF_DETECT -> resposta suspeita registrada, encaminhada
RESPONSE_WAF_BLOCK  -> resposta bloqueada (modo block)
IP_BLOCK       -> IP na blocklist, bloqueado antes do WAF
DoS_BLOCK      -> rate limit excedido
```

---

## Allowlist WAF

Excecoes cirurgicas para evitar falsos positivos em rotas especificas:

```
WAF_ALLOWLIST=SQLi:/api/search,XSS:/editor,/health
```

- `SQLi:/api/search` — libera apenas SQLi nessa rota
- `/health` — libera qualquer categoria em /health

---

## Categorias de ataque detectadas

**Requisicao:** XSS, SQLi, CMD_INJ, PATH_TRAVERSAL, SSRF, XXE, JNDI, NoSQLi, SSTI, PROTOTYPE_POLLUTION, OPEN_REDIRECT, HTTP_HEADER_INJECTION

**Resposta:** RESPONSE_SQL_ERROR, RESPONSE_STACK_TRACE, RESPONSE_XSS_REFLECTION, RESPONSE_FILE_LEAK

---

## Limitacoes conhecidas

- WAF por regex nao substitui validacao no backend. Reduz superficie de ataque, nao garante cobertura total.
- Respostas comprimidas, binarias ou acima do limite nao sao inspecionadas.
- Frames WebSocket pos-upgrade nao sao analisados.
- Rate limiter e por processo; clusters precisam de solucao externa (Redis, gateway).
- `INSECURE_SKIP_VERIFY=true` aceita qualquer certificado do backend. Usar apenas em redes controladas.

---

## Checklist de implantacao

- [ ] Gerar ou importar certificado TLS de CA confiavel
- [ ] Garantir que `server.crt` e `server.key` nao estao versionados
- [ ] Definir `TARGET_URL` com a URL interna da aplicacao
- [ ] Configurar `TRUSTED_PROXIES` apenas com proxies reais
- [ ] Iniciar com `WAF_MODE=monitor` e revisar logs
- [ ] Criar allowlists minimas para falsos positivos identificados
- [ ] Ativar `WAF_MODE=block`
- [ ] Executar `go test ./...`
- [ ] Rodar suite de comparacao em ambiente de laboratorio
