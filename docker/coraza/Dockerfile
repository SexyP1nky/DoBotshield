# Coraza WAF via Caddy
# Terceiro WAF usado na comparacao academica.
# Coraza e uma implementacao moderna em Go do motor WAF compativel com OWASP CRS,
# menos madura que o ModSecurity mas com arquitetura mais simples.

FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 443

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
