FROM alpine:3.19 AS builder
RUN apk add --no-cache build-base git openssl-dev linux-headers
RUN git clone --depth 1 https://github.com/wg/wrk.git /src \
    && cd /src && make -j$(nproc)

FROM alpine:3.19
RUN apk add --no-cache libgcc openssl
COPY --from=builder /src/wrk /usr/local/bin/wrk
ENTRYPOINT ["wrk"]
