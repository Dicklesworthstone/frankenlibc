# CVE-2024-46461: VLC MMS stream integer overflow
# CVSS 7.5 — Remote code execution via crafted MMS stream
#
# The vulnerability exists in VLC's MMS (Microsoft Media Server) protocol
# access module. When parsing MMS stream headers, an integer overflow in
# the length field calculation causes a heap buffer to be allocated with
# a size much smaller than the data that will be written to it. The
# subsequent memcpy overflows the undersized buffer.
#
# Build VLC 3.0.20 from source with minimal plugins.

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
        gettext \
        cmake \
        flex \
        bison \
        lua5.2 \
        liblua5.2-dev \
        libavcodec-dev \
        libavformat-dev \
        libswscale-dev \
        libxcb1-dev \
        libxcb-shm0-dev \
        libxcb-xfixes0-dev \
        libxcb-randr0-dev \
        libgcrypt20-dev \
        libgpg-error-dev \
        libprotobuf-dev \
        protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

# Pin to vulnerable version 3.0.20 (before the fix in 3.0.21)
RUN wget -q https://get.videolan.org/vlc/3.0.20/vlc-3.0.20.tar.xz && \
    tar xJf vlc-3.0.20.tar.xz && \
    rm vlc-3.0.20.tar.xz

# Build VLC with minimal plugins - we only need the MMS access module
# Disable most features to speed up the build
RUN cd vlc-3.0.20 && \
    ./bootstrap && \
    ./configure \
        --prefix=/opt/vlc \
        --disable-a52 \
        --disable-alsa \
        --disable-avahi \
        --disable-dbus \
        --disable-fontconfig \
        --disable-freetype \
        --disable-fribidi \
        --disable-gles2 \
        --disable-glx \
        --disable-gnutls \
        --disable-harfbuzz \
        --disable-jack \
        --disable-jpeg \
        --disable-libass \
        --disable-libplacebo \
        --disable-libva \
        --disable-nls \
        --disable-notify \
        --disable-ogg \
        --disable-opus \
        --disable-png \
        --disable-pulse \
        --disable-qt \
        --disable-samplerate \
        --disable-sdl-image \
        --disable-skins2 \
        --disable-sndio \
        --disable-soxr \
        --disable-speex \
        --disable-svg \
        --disable-taglib \
        --disable-theora \
        --disable-vdpau \
        --disable-vlm \
        --disable-vorbis \
        --disable-wayland \
        --disable-x264 \
        --disable-x265 \
        --disable-xcb \
        --disable-xml \
        --enable-mms \
        --enable-run-as-root \
        --with-pic && \
    make -j"$(nproc)" || make -j1 && \
    make install

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        jq \
        procps \
        libavcodec59 \
        libavformat59 \
        libswscale6 \
        libgcrypt20 \
        liblua5.2-0 \
        libprotobuf32 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/vlc /opt/vlc
RUN ldconfig /opt/vlc/lib && \
    ln -sf /opt/vlc/bin/vlc /usr/local/bin/vlc && \
    ln -sf /opt/vlc/bin/cvlc /usr/local/bin/cvlc

# Copy CVE arena artifacts
COPY trigger.sh     /cve_arena/
COPY craft_mms.py   /cve_arena/
COPY manifest.json  /cve_arena/

RUN chmod +x /cve_arena/trigger.sh

WORKDIR /cve_arena

ENTRYPOINT ["/cve_arena/trigger.sh"]
