FROM alpine:3.19 AS builder
RUN apk add --no-cache build-base git openssl-dev linux-headers perl
RUN git clone --depth 1 https://github.com/wg/wrk.git /src \
    && cd /src && make WITH_OPENSSL=/usr -j$(nproc)

FROM alpine:3.19
RUN apk add --no-cache libgcc libssl3 libcrypto3
COPY --from=builder /src/wrk /usr/local/bin/wrk
ENTRYPOINT ["wrk"]
