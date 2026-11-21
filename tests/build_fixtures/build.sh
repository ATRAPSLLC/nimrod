#!/usr/bin/env bash
# Build Nim fixture binaries covering a matrix of compilation modes.
#
# Each source file is compiled with several flag combinations so that
# the parser can be tested against:
#   - refc vs arc vs orc memory management
#   - debug vs release vs danger
#   - stackTrace on vs off (determines presence of proc/file/line strings)
#   - --opt:size vs --opt:speed
#
# Outputs go to ../fixtures/native/ for host-platform binaries and
# ../fixtures/mingw/ for Windows PE cross-compiled binaries.
#
# Requirements:
#   - nim (brew install nim)
#   - mingw-w64 (brew install mingw-w64) for -d:mingw cross-builds
set -euo pipefail

cd "$(dirname "$0")"

OUT_NATIVE="../fixtures/native"
OUT_MINGW="../fixtures/mingw"
mkdir -p "$OUT_NATIVE" "$OUT_MINGW"

SOURCES=(hello_basic strings_and_seqs exceptions stdlib_mix fileio_json)

# (suffix, flags) — kept short to avoid a 30+ binary explosion.
MODES=(
  "refc_debug|--mm:refc --stackTrace:on --lineTrace:on"
  "refc_release|--mm:refc -d:release"
  "orc_debug|--mm:orc --stackTrace:on --lineTrace:on"
  "orc_release|--mm:orc -d:release"
  "orc_danger_size|--mm:orc -d:danger --opt:size"
  "arc_release|--mm:arc -d:release"
)

echo "==> native ($(uname -s) $(uname -m))"
for src in "${SOURCES[@]}"; do
  for mode in "${MODES[@]}"; do
    suffix="${mode%%|*}"
    flags="${mode#*|}"
    out="$OUT_NATIVE/${src}_${suffix}"
    echo "  -> $out"
    # shellcheck disable=SC2086
    nim c $flags --hints:off --warnings:off -o:"$out" "${src}.nim" >/dev/null
  done
done

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  echo "==> windows cross (mingw-w64)"
  for src in "${SOURCES[@]}"; do
    for mode in orc_release orc_danger_size; do
      case "$mode" in
        orc_release) flags="--mm:orc -d:release" ;;
        orc_danger_size) flags="--mm:orc -d:danger --opt:size" ;;
      esac
      out="$OUT_MINGW/${src}_${mode}.exe"
      echo "  -> $out"
      # shellcheck disable=SC2086
      nim c -d:mingw --cpu:amd64 $flags --hints:off --warnings:off -o:"$out" "${src}.nim" >/dev/null
    done
  done
else
  echo "==> skipping windows cross (install mingw-w64 and rerun)"
fi

echo "done."
