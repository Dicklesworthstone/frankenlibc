# CVE-2021-3156: sudo "Baron Samedit" heap-based buffer overflow
# CVSS 7.8 — Local privilege escalation via sudoedit -s
#
# The vulnerability exists in sudo's command-line argument parsing
# for sudoedit (sudo -e) when backslash-escaped characters are
# improperly handled. A heap-based buffer overflow occurs when
# set_cmnd() copies the escaped arguments without properly
# accounting for the backslash escaping, writing past the end
# of the heap buffer.
#
# Build vulnerable sudo 1.9.5p1 from source with system allocator.

FROM debian:bookworm-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        wget \
        libpam0g-dev \
        zlib1g-dev \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Pin to vulnerable version 1.9.5p1 (fixed in 1.9.5p2)
RUN wget -q https://www.sudo.ws/dist/sudo-1.9.5p1.tar.gz && \
    tar xzf sudo-1.9.5p1.tar.gz && \
    rm sudo-1.9.5p1.tar.gz

# Build sudo with system malloc (no hardening flags)
RUN cd sudo-1.9.5p1 && \
    ./configure \
        --prefix=/opt/sudo \
        --with-pam \
        --without-sendmail \
        --without-lecture \
        --disable-hardening && \
    make -j"$(nproc)" && \
    make install

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        jq \
        procps \
        libpam0g && \
    rm -rf /var/lib/apt/lists/*

# Install vulnerable sudo, preserving setuid bit for realistic testing
COPY --from=builder /opt/sudo /opt/sudo
RUN ln -sf /opt/sudo/bin/sudo /usr/local/bin/sudo && \
    ln -sf /opt/sudo/bin/sudo /usr/local/bin/sudoedit && \
    ln -sf /opt/sudo/sbin/visudo /usr/local/sbin/visudo && \
    chmod 4755 /opt/sudo/bin/sudo

# Create a sudoers file
RUN mkdir -p /opt/sudo/etc && \
    echo "root ALL=(ALL:ALL) ALL" > /opt/sudo/etc/sudoers && \
    chmod 0440 /opt/sudo/etc/sudoers

# Create unprivileged test user
RUN useradd -m -s /bin/bash cve_tester

# Copy CVE arena artifacts
COPY trigger.sh    /cve_arena/
COPY manifest.json /cve_arena/

RUN chmod +x /cve_arena/trigger.sh

WORKDIR /cve_arena

ENTRYPOINT ["/cve_arena/trigger.sh"]
