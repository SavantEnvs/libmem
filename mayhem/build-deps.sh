#!/usr/bin/env bash
# Builds libmem's capstone + keystone submodules (pinned to the commits upstream's gitlinks name)
# into $MAYHEM_DEPS/{san,plain}/{lib,include}. Run as root by mayhem/Dockerfile; needs network.
#   san   — $SANITIZER_FLAGS + SanCov (fuzzer-no-link) + DWARF<=3: linked into the fuzz targets
#   plain — default flags, no sanitizer: linked into the functional-test oracle
set -euo pipefail

DEPS="${MAYHEM_DEPS:-/opt/mayhem-deps}"
CAPSTONE_URL=https://github.com/rdbo/capstone
CAPSTONE_SHA=929d0ff8daf599d6a7f81487651477580e7876f0
KEYSTONE_URL=https://github.com/rdbo/keystone
KEYSTONE_SHA=d5c265e60c786f44bb606975aa751d4d5f3d7999

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
JOBS="${MAYHEM_JOBS:-$(nproc)}"

if [ -f "$DEPS/.built" ]; then echo "deps already built in $DEPS"; exit 0; fi

mkdir -p "$DEPS/src" && cd "$DEPS/src"
fetch() { # name url sha
  rm -rf "$1" && mkdir "$1" && git -C "$1" init -q
  git -C "$1" fetch -q --depth 1 "$2" "$3" && git -C "$1" checkout -q FETCH_HEAD
}
fetch capstone "$CAPSTONE_URL" "$CAPSTONE_SHA"
fetch keystone "$KEYSTONE_URL" "$KEYSTONE_SHA"

build_variant() { # variant cflags
  local v="$1" flags="$2" out="$DEPS/$1"
  mkdir -p "$out/lib" "$out/include"
  cmake -S capstone -B "capstone-build-$v" -G Ninja \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags" -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_INSTALL=OFF \
    -DCAPSTONE_BUILD_SHARED=OFF -DCAPSTONE_BUILD_STATIC_RUNTIME=OFF \
    -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_ARM_SUPPORT=ON -DCAPSTONE_ARM64_SUPPORT=ON \
    -DCAPSTONE_MIPS_SUPPORT=ON -DCAPSTONE_X86_SUPPORT=ON -DCAPSTONE_PPC_SUPPORT=ON \
    -DCAPSTONE_SPARC_SUPPORT=ON -DCAPSTONE_SYSZ_SUPPORT=ON
  ninja -C "capstone-build-$v" -j"$JOBS"
  cp "$(find "capstone-build-$v" -name libcapstone.a | head -n1)" "$out/lib/"

  cmake -S keystone -B "keystone-build-$v" -G Ninja \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags" -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_LIBS_ONLY=1 -DKEYSTONE_BUILD_STATIC_RUNTIME=OFF \
    -DLLVM_TARGETS_TO_BUILD="AArch64 ARM Mips PowerPC Sparc SystemZ X86"
  ninja -C "keystone-build-$v" -j"$JOBS" keystone
  cp "$(find "keystone-build-$v" -name libkeystone.a | head -n1)" "$out/lib/"
}

build_variant san "$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
build_variant plain ""

for v in san plain; do
  cp -r capstone/include/capstone "$DEPS/$v/include/"
  cp -r keystone/include/keystone "$DEPS/$v/include/"
done
rm -rf "$DEPS"/src/*-build-*
touch "$DEPS/.built"
