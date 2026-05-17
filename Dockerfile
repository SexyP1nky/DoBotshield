FROM golang:1.21-alpine AS builder

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o dobotshield .

# ----

FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/dobotshield ./dobotshield

EXPOSE 80

# HTTP_MODE=true: desativa TLS para uso em laboratorio Docker.
# Para producao, remova esta variavel e monte server.crt e server.key.
ENV HTTP_MODE=true

CMD ["./dobotshield"]
