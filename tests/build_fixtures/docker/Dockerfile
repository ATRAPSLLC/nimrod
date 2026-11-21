# One image per Nim release, all on the same C toolchain, so differences
# between fixture sets come from the Nim compiler rather than from gcc.
#
# bookworm ships gcc 12: gcc 14 turns several warnings that older Nim
# releases trigger in their generated C into hard errors.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils \
      gcc libc6-dev \
      gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      gcc-powerpc64-linux-gnu libc6-dev-ppc64-cross \
      gcc-mips-linux-gnu libc6-dev-mips-cross \
 && rm -rf /var/lib/apt/lists/*

ARG NIM_VERSION
COPY nim-sha256.txt /tmp/nim-sha256.txt
RUN set -eu; \
    tarball="nim-${NIM_VERSION}-linux_x64.tar.xz"; \
    grep -q "  ${tarball}\$" /tmp/nim-sha256.txt \
      || { echo "no pinned checksum for ${tarball}; add it to nim-sha256.txt" >&2; exit 1; }; \
    cd /tmp; \
    curl -fsSLO "https://nim-lang.org/download/${tarball}"; \
    grep "  ${tarball}\$" nim-sha256.txt | sha256sum -c -; \
    tar -xJf "${tarball}" -C /opt; \
    ln -s "/opt/nim-${NIM_VERSION}" /opt/nim; \
    rm "${tarball}"

ENV PATH=/opt/nim/bin:$PATH
WORKDIR /src
