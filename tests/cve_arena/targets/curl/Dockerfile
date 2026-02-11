# CVE-2024-6197: curl/libcurl ASN1 parser stack use-after-free
# CVSS 7.5 — Remote code execution via crafted TLS certificate
#
# The vulnerability exists in libcurl's ASN.1 certificate parsing code
# where a stack-allocated buffer's address is passed to free() due to
# incorrect pointer tracking in the UTF-8 conversion path. A malicious
# server can send a crafted TLS certificate that triggers this path,
# causing free() to be called on a stack address.
#
# Build vulnerable curl 8.6.0 from source with OpenSSL.

FROM debian:bookworm-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        wget \
        pkg-config \
        autoconf \
        automake \
        libtool \
        libssl-dev \
        zlib1g-dev \
        libnghttp2-dev && \
    rm -rf /var/lib/apt/lists/*

# Pin to vulnerable version 8.6.0 (fixed in 8.8.0)
RUN wget -q https://curl.se/download/curl-8.6.0.tar.gz && \
    tar xzf curl-8.6.0.tar.gz && \
    rm curl-8.6.0.tar.gz

# Build curl with OpenSSL backend (the vulnerable code path)
RUN cd curl-8.6.0 && \
    autoreconf -fi && \
    ./configure \
        --prefix=/opt/curl \
        --with-openssl \
        --with-nghttp2 \
        --without-libpsl \
        --without-brotli \
        --without-zstd \
        --disable-ldap \
        --disable-ldaps \
        --disable-rtsp && \
    make -j"$(nproc)" && \
    make install

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-cryptography \
        jq \
        procps \
        libssl3 \
        zlib1g \
        libnghttp2-14 \
        openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/curl /opt/curl
RUN ldconfig /opt/curl/lib && \
    ln -sf /opt/curl/bin/curl /usr/local/bin/curl

# Copy CVE arena artifacts
COPY trigger.sh         /cve_arena/
COPY mock_tls_server.py /cve_arena/
COPY manifest.json      /cve_arena/

RUN chmod +x /cve_arena/trigger.sh

WORKDIR /cve_arena

ENTRYPOINT ["/cve_arena/trigger.sh"]
