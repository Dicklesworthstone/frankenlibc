# =============================================================================
# CVE Arena Docker Image
# =============================================================================
#
# Minimal Debian-based container for running CVE reproduction tests.
# Provides a stock glibc environment for the "stock" mode and the necessary
# build tools to compile C trigger programs. The glibc_rust library is
# mounted at runtime via docker run -v, not baked into the image.
#
# Build:
#   docker build -t glibc-rust-cve-arena -f Dockerfile .
#
# Run (example):
#   docker run --rm --network=none \
#       -v /path/to/cve_test:/cve_arena/test:ro \
#       -v /path/to/signal_wrapper.sh:/cve_arena/signal_wrapper.sh:ro \
#       glibc-rust-cve-arena \
#       bash -c "cd /cve_arena/test && ./trigger"
# =============================================================================

FROM debian:bookworm-slim

LABEL maintainer="glibc_rust CVE Arena"
LABEL description="Sandboxed environment for CVE reproduction testing"

# Avoid interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install build tools and diagnostic utilities.
# - build-essential, gcc, libc6-dev: compile C trigger programs
# - python3: needed by some CVE reproduction scripts
# - jq: JSON processing for result aggregation
# - strace: syscall tracing for debugging test behavior
# - gdb: post-mortem analysis of crashes
# - file, binutils: binary inspection utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libc6-dev \
        python3 \
        jq \
        strace \
        gdb \
        file \
        binutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create the working directory structure.
RUN mkdir -p /cve_arena/test /cve_arena/build /cve_arena/results

# Copy the signal-catching wrapper into the image.
COPY signal_wrapper.sh /cve_arena/signal_wrapper.sh
RUN chmod +x /cve_arena/signal_wrapper.sh

# Set the working directory to the test mount point.
WORKDIR /cve_arena/test

# Run as a non-root user for realistic testing conditions.
# CVE triggers should not require root unless explicitly noted.
RUN useradd --create-home --shell /bin/bash cve_runner
USER cve_runner

# Default: drop into a shell. The runner.sh script overrides this with
# the actual test command via docker run ... bash -c "...".
CMD ["bash"]
