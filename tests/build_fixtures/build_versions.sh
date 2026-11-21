#!/usr/bin/env bash
# Build fixture sets for several Nim releases in Docker.
#
#   ./build_versions.sh                 # every version in docker/nim-sha256.txt
#   ./build_versions.sh 2.4.2 2.2.14    # just these
#   PLATFORMS=linux_arm64 ./build_versions.sh 1.6.20   # one platform
#   ONLY_SOURCES=dispatch ./build_versions.sh          # one program
#
# Each release gets its own image (nimrod-fixtures:<version>) built from
# docker/Dockerfile, which downloads the official linux_x64 tarball and checks
# it against the pinned checksum. The fixture sources are mounted read-only;
# binaries land in ../fixtures/nim-<version>/ owned by the calling user.
set -euo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
OUT="$(cd .. && pwd)/fixtures"

if [ "$#" -gt 0 ]; then
  VERSIONS=("$@")
else
  mapfile -t VERSIONS < <(sed -E 's/.*nim-([0-9.]+)-linux_x64.*/\1/' docker/nim-sha256.txt)
fi

for v in "${VERSIONS[@]}"; do
  echo "#### nim $v"
  docker build -q --build-arg "NIM_VERSION=$v" -t "nimrod-fixtures:$v" docker >/dev/null
  mkdir -p "$OUT/nim-$v"
  # Copy the sources into the container so nimcache and outputs never touch
  # the mounted checkout; only /out is writable.
  docker run --rm --network none \
    --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -e ONLY_SOURCES="${ONLY_SOURCES:-}" \
    -e PLATFORMS="${PLATFORMS:-linux_x64 mingw mingw_i686 linux_arm64 linux_ppc64 linux_mips}" \
    -v "$HERE:/fixture-src:ro" -v "$OUT/nim-$v:/out" \
    "nimrod-fixtures:$v" \
    bash -c 'cp -r /fixture-src /tmp/src && /tmp/src/build_matrix.sh /out'
done
