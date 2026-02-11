# CVE-2024-56406: Perl tr/// transliteration heap buffer overflow
# CVSS 8.6 — Remote code execution via crafted Perl input
#
# The vulnerability exists in Perl's transliteration operator (tr///)
# when processing strings containing characters above \x{FF} (wide
# Unicode) combined with byte-range transliterations (\x80-\xff).
# The tr/// implementation miscalculates the output buffer size
# when the string undergoes UTF-8 encoding changes during the
# transliteration, leading to a heap buffer overflow.
#
# Build vulnerable Perl 5.38.2 from source.

FROM debian:bookworm-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        wget \
        libssl-dev \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Pin to vulnerable version 5.38.2 (fixed in 5.38.4 / 5.40.1)
RUN wget -q https://www.cpan.org/src/5.0/perl-5.38.2.tar.gz && \
    tar xzf perl-5.38.2.tar.gz && \
    rm perl-5.38.2.tar.gz

# Build Perl with system malloc (no Perl's internal malloc)
# -Dusedevel allows building development configurations
# -Uusemymalloc forces use of system malloc for LD_PRELOAD testing
RUN cd perl-5.38.2 && \
    ./Configure \
        -des \
        -Dprefix=/opt/perl \
        -Dusethreads \
        -Uusemymalloc \
        -Doptimize="-O2 -g" \
        -Dusedevel && \
    make -j"$(nproc)" && \
    make install

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        jq \
        procps && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/perl /opt/perl
RUN ln -sf /opt/perl/bin/perl /usr/local/bin/perl

# Copy CVE arena artifacts
COPY trigger.sh    /cve_arena/
COPY trigger.pl    /cve_arena/
COPY manifest.json /cve_arena/

RUN chmod +x /cve_arena/trigger.sh

WORKDIR /cve_arena

ENTRYPOINT ["/cve_arena/trigger.sh"]
