# CVE-2025-49844: Redis "RediShell" use-after-free in Lua GC userdata
# CVSS 10.0 — Remote code execution via crafted Lua script
#
# The vulnerability exists in Redis's embedded Lua interpreter where
# Lua garbage collection can free userdata objects that are still
# referenced by the Lua stack, leading to use-after-free when the
# freed userdata is subsequently accessed.
#
# Build vulnerable Redis version with system allocator (not jemalloc)
# so LD_PRELOAD of our glibc_rust libc.so intercepts all allocations.

FROM debian:bookworm-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        wget \
        pkg-config \
        tcl && \
    rm -rf /var/lib/apt/lists/*

# Pin to vulnerable version 7.4.0 (before the fix in 7.4.1)
RUN wget -q https://github.com/redis/redis/archive/refs/tags/7.4.0.tar.gz && \
    tar xzf 7.4.0.tar.gz && \
    rm 7.4.0.tar.gz

# Build WITHOUT jemalloc so our LD_PRELOAD libc.so handles all allocations.
# Also disable protected mode for easier testing in container.
RUN cd redis-7.4.0 && \
    make USE_JEMALLOC=no MALLOC=libc -j"$(nproc)" && \
    make install PREFIX=/opt/redis

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-redis \
        jq \
        procps && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/redis/bin/redis-server /usr/local/bin/
COPY --from=builder /opt/redis/bin/redis-cli /usr/local/bin/

# Copy CVE arena artifacts
COPY trigger.sh   /cve_arena/
COPY trigger.py   /cve_arena/
COPY manifest.json /cve_arena/

RUN chmod +x /cve_arena/trigger.sh

WORKDIR /cve_arena

# Default entrypoint runs the trigger
ENTRYPOINT ["/cve_arena/trigger.sh"]
