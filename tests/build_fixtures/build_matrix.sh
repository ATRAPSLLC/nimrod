#!/usr/bin/env bash
# Build the fixture matrix with whatever `nim` is on PATH (or $NIM).
#
# Normally run inside the per-version Docker image by build_versions.sh, but
# works on a host too:  NIM=/path/to/bin/nim ./build_matrix.sh [outdir]
#
# Output: <outdir>/{linux_x64,mingw,mingw_i686,linux_arm64,linux_ppc64,linux_mips}/
#         <source>_<mode>[.exe]
# (default outdir: ../fixtures/nim-<version>). Modes are gated on the compiler
# version so each release builds everything it supports:
#   --gc:X before 2.0, --mm:X from 2.0; arc >= 1.2, orc >= 1.4;
#   atomicArc >= 2.0; --mangle when the compiler accepts it (2.2.x);
#   yrc, --strings:sso, sum types >= 2.4.
set -euo pipefail

cd "$(dirname "$0")"

NIM="${NIM:-nim}"
# `sed` reads all of `nim -v`: with `head -1` the compiler could hit a closed
# pipe, fail with EPIPE and, under `pipefail`, abort the build at random.
VERSION="$("$NIM" -v | sed -nE '1s/.*Version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
ROOT="${1:-../fixtures/nim-${VERSION}}"
CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT
mkdir -p "$ROOT/linux_x64" "$ROOT/mingw" "$ROOT/linux_arm64"

# Platforms to build (env PLATFORMS, default all). linux_ppc64 and
# linux_mips are the big-endian targets (64- and 32-bit); mingw_i686 is
# 32-bit Windows.
PLATFORMS="${PLATFORMS:-linux_x64 mingw mingw_i686 linux_arm64 linux_ppc64 linux_mips}"
want() { [[ " $PLATFORMS " == *" $1 "* ]]; }

# ge A B: version A >= version B
ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | sed -n 1p)" = "$2" ]; }
if ge "$VERSION" 2.0.0; then MM="--mm"; else MM="--gc"; fi

# The fixture programs (their line numbers are baked into the binaries'
# raise sites and stack traces, so edit them only together with a rebuild):
#   hello_basic       the runtime alone: entry shims, system, baseline detection
#   strings_and_seqs  literals "alpha" .. "delta" and seq[string] / seq[int]
#   exceptions        MyError (CatchableError) and OtherError (ValueError),
#                     raised in `inner`, caught in `outer`: raise sites, RTTI
#   stdlib_mix        strutils, tables, sequtils, algorithm: generic instances
#   fileio_json       std/json and std/os: a larger stdlib footprint
#   sumtypes          (2.4+) sum types next to a classic object variant
#   dispatch          methods (Shape / Circle / Square), a closure, two async
#                     procs, a generic proc used twice, a `new` finalizer
SOURCES=(hello_basic strings_and_seqs exceptions stdlib_mix fileio_json dispatch)
ge "$VERSION" 2.4.0 && SOURCES+=(sumtypes)

# ONLY_SOURCES (space-separated) builds just those programs, so a new source
# can be added without rebuilding, and so changing, the existing fixtures.
if [ -n "${ONLY_SOURCES:-}" ]; then
  selected=()
  for src in "${SOURCES[@]}"; do
    [[ " $ONLY_SOURCES " == *" $src "* ]] && selected+=("$src")
  done
  SOURCES=("${selected[@]}")
fi
# The shared-library builds use hello_basic.
has_source() { [[ " ${SOURCES[*]} " == *" $1 "* ]]; }

MODES=(
  "refc_debug|$MM:refc --stackTrace:on --lineTrace:on"
  "refc_release|$MM:refc -d:release"
  "refc_danger_size|$MM:refc -d:danger --opt:size"
  "refc_debuginfo|$MM:refc -d:release --debugger:native"
)
if ge "$VERSION" 1.2.0; then
  MODES+=("arc_release|$MM:arc -d:release")
fi
if ge "$VERSION" 1.4.0; then
  MODES+=(
    "orc_debug|$MM:orc --stackTrace:on --lineTrace:on"
    "orc_release|$MM:orc -d:release"
    "orc_danger_size|$MM:orc -d:danger --opt:size"
    "orc_debuginfo|$MM:orc -d:release --debugger:native"
    "orc_threads_release|$MM:orc -d:release --threads:on"
    "orc_nothreads_release|$MM:orc -d:release --threads:off"
    "orc_setjmp_release|$MM:orc -d:release --exceptions:setjmp"
  )
fi
if ge "$VERSION" 2.0.0; then
  MODES+=("atomicarc_release|--mm:atomicArc -d:release")
fi
# `--mangle` appeared during the 2.2 series; probe for it.
if "$NIM" --mangle:nim --version >/dev/null 2>&1; then
  MODES+=("orc_debuginfo_nimmangle|--mm:orc -d:release --debugger:native --mangle:nim")
fi
if ge "$VERSION" 2.4.0; then
  MODES+=(
    "yrc_release|--mm:yrc -d:release"
    "yrc_debug|--mm:yrc --stackTrace:on --lineTrace:on"
    "orc_sso_release|--mm:orc --strings:sso -d:release"
    "orc_sso_debug|--mm:orc --strings:sso --stackTrace:on --lineTrace:on"
  )
fi
# Default memory manager of the release (refc before 2.0, orc after).
if ge "$VERSION" 2.0.0; then DEFMM=orc; else DEFMM=refc; fi

failures=0
build() { # out, source, nim options...
  local out="$1" src="$2"; shift 2
  local name; name="$(basename "$out")"
  # One nimcache per output: platforms share binary names (every Linux
  # target has a `<src>_refc_release`), and a cache reused across targets
  # links one target's objects into another's binary.
  local cache; cache="$CACHE/$(basename "$(dirname "$out")")/$name"
  mkdir -p "$(dirname "$cache")"
  # Options must precede the source file: anything after it is passed to
  # the program (and rejected without --run).
  if "$NIM" c "$@" --hints:off --warnings:off --nimcache:"$cache" -o:"$out" "$src" \
      >"$cache.log" 2>&1; then
    printf '  ok   %s\n' "$name"
  else
    printf '  FAIL %s\n' "$name"; tail -5 "$cache.log" | sed 's/^/       /'
    failures=$((failures + 1))
  fi
}

want linux_x64 && echo "==> nim $VERSION: linux x64"
want linux_x64 && for src in "${SOURCES[@]}"; do
  for mode in "${MODES[@]}"; do
    # shellcheck disable=SC2086
    build "$ROOT/linux_x64/${src}_${mode%%|*}" "${src}.nim" ${mode#*|}
  done
done
want linux_x64 && has_source hello_basic && build "$ROOT/linux_x64/libhello_${DEFMM}_release.so" hello_basic.nim "$MM:$DEFMM" -d:release --app:lib

# Name the cross toolchain explicitly: in 2.2.14 neither the `@if mingw`
# block in nim.cfg nor `--amd64.windows.gcc.exe` takes effect and the host
# gcc is used; the unqualified `--gcc.exe` works in every release.
MINGW=(-d:mingw --os:windows --cpu:amd64 --cc:gcc
  --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc)

if want mingw && command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  echo "==> nim $VERSION: windows x64 (mingw-w64)"
  for src in "${SOURCES[@]}"; do
    build "$ROOT/mingw/${src}_${DEFMM}_release.exe" "${src}.nim" "${MINGW[@]}" "$MM:$DEFMM" -d:release
    build "$ROOT/mingw/${src}_${DEFMM}_danger_size.exe" "${src}.nim" "${MINGW[@]}" "$MM:$DEFMM" -d:danger --opt:size
    if ge "$VERSION" 2.4.0; then
      build "$ROOT/mingw/${src}_yrc_release.exe" "${src}.nim" "${MINGW[@]}" --mm:yrc -d:release
    fi
  done
  has_source hello_basic && build "$ROOT/mingw/hello_${DEFMM}_release.dll" hello_basic.nim "${MINGW[@]}" "$MM:$DEFMM" -d:release --app:lib
fi

# 32-bit Windows: C-level names carry the i386 COFF decoration (`_name`,
# and `@name@N` for Nim's fastcall procs), which 64-bit PE does not.
MINGW32=(-d:mingw --os:windows --cpu:i386 --cc:gcc
  --gcc.exe:i686-w64-mingw32-gcc --gcc.linkerexe:i686-w64-mingw32-gcc
  --i386.windows.gcc.exe:i686-w64-mingw32-gcc --i386.windows.gcc.linkerexe:i686-w64-mingw32-gcc)

if want mingw_i686 && command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
  echo "==> nim $VERSION: windows x86 (mingw-w64 i686)"
  for src in "${SOURCES[@]}"; do
    build "$ROOT/mingw_i686/${src}_${DEFMM}_release.exe" "${src}.nim" "${MINGW32[@]}" "$MM:$DEFMM" -d:release
    if [ "$DEFMM" != refc ]; then
      build "$ROOT/mingw_i686/${src}_refc_release.exe" "${src}.nim" "${MINGW32[@]}" "$MM:refc" -d:release
    fi
  done
fi

# As for mingw: name the cross compiler explicitly. Without it, Nim 1.x and
# 2.2.14 silently compile `--cpu:arm64` with the host x86-64 gcc.
ARM64=(--cpu:arm64 --os:linux --cc:gcc
  --gcc.exe:aarch64-linux-gnu-gcc --gcc.linkerexe:aarch64-linux-gnu-gcc)

if want linux_arm64 && command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  echo "==> nim $VERSION: linux arm64"
  for src in "${SOURCES[@]}"; do
    build "$ROOT/linux_arm64/${src}_${DEFMM}_release" "${src}.nim" "${ARM64[@]}" "$MM:$DEFMM" -d:release
    if ge "$VERSION" 2.4.0; then
      build "$ROOT/linux_arm64/${src}_orc_sso_release" "${src}.nim" "${ARM64[@]}" --mm:orc --strings:sso -d:release
    fi
  done
fi

# Big-endian targets: release builds in the default memory manager, plus
# refc where that is not the default (V1 RTTI and string layouts).
big_endian() {
  local dir="$1" cc="$2" cpu="$3"; shift 3
  # Nim's own config names a toolchain per CPU (`mips.linux.gcc.exe =
  # "mips-openwrt-linux-gcc"`), which overrides plain `--gcc.exe`.
  local flags=("--cpu:$cpu" --os:linux --cc:gcc "--gcc.exe:$cc" "--gcc.linkerexe:$cc"
    "--$cpu.linux.gcc.exe:$cc" "--$cpu.linux.gcc.linkerexe:$cc")
  if want "$dir" && command -v "$cc" >/dev/null 2>&1; then
    echo "==> nim $VERSION: $dir"
    for src in "${SOURCES[@]}"; do
      build "$ROOT/$dir/${src}_${DEFMM}_release" "${src}.nim" "${flags[@]}" "$MM:$DEFMM" -d:release
      if [ "$DEFMM" != refc ]; then
        build "$ROOT/$dir/${src}_refc_release" "${src}.nim" "${flags[@]}" "$MM:refc" -d:release
      fi
    done
  fi
}
big_endian linux_ppc64 powerpc64-linux-gnu-gcc powerpc64
big_endian linux_mips mips-linux-gnu-gcc mips

echo "done: $ROOT ($failures failed)"
