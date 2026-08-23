FROM alpine:3.22 AS build
RUN apk add --no-cache build-base cmake openssl-dev
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build build --parallel

FROM alpine:3.22
RUN apk add --no-cache libcrypto3 \
    && addgroup -S skyvault \
    && adduser -S -G skyvault -h /vault skyvault \
    && mkdir -p /vault/data \
    && chown -R skyvault:skyvault /vault
COPY --from=build /src/build/sky-secret-vault /usr/local/bin/sky-secret-vault
USER skyvault
WORKDIR /vault
VOLUME ["/vault/data"]
ENV SKY_VAULT_DATA=/vault/data/vault.db \
    SKY_VAULT_AUDIT=/vault/data/vault.audit.log
ENTRYPOINT ["/usr/local/bin/sky-secret-vault"]
