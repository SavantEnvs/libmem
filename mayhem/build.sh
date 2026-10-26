#!/usr/bin/env bash
#
# mayhem/build.sh — build libmem's fuzz harnesses and its functional-test oracle.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# libmem's CMake build fetches capstone + keystone through ExternalProject from git submodules that a plain
# checkout leaves empty, and that would need the network. mayhem/build-deps.sh (run by the Dockerfile as
# root) already built both, pinned to the submodule commits, into /opt/mayhem-deps. This script compiles
# libmem's own sources itself — the same Linux file set as CMakeLists.txt, globbed so source edits are picked up.
DEPS="${MAYHEM_DEPS:-/opt/mayhem-deps}"
[ -f "$DEPS/.built" ] || { echo "build.sh: $DEPS/.built missing — mayhem/build-deps.sh must run in the Dockerfile" >&2; exit 1; }

case "$(uname -m)" in
  x86_64)  ARCH_SRC=(src/common/arch/x86.c src/linux/ptrace/x64/*.c) ;;
  aarch64) ARCH_SRC=(src/common/arch/aarch64.c src/linux/ptrace/aarch64/*.c) ;;
  *)       ARCH_SRC=(src/common/arch/generic.c src/linux/ptrace/generic/*.c) ;;
esac
LIBMEM_SRC=("${ARCH_SRC[@]}" src/linux/*.c src/linux/ptrace/*.c src/common/*.c src/common/*.cpp
            internal/posixutils/*.c internal/elfutils/*.c internal/demangler/*.cpp external/llvm/lib/Demangle/*.cpp)
INC=(-Isrc -Iinternal -Isrc/common -Iinclude -Iexternal/llvm/include)

# compile_lib <variant> <outdir> <flags...>: every libmem source -> <outdir>/<flattened path>.o, then <outdir>/libmem.a
compile_lib() {
  local variant="$1" out="$2"; shift 2
  local flags=("$@") f o objs=() pids=() cmd p
  mkdir -p "$out"
  for f in "${LIBMEM_SRC[@]}"; do
    o="$out/$(echo "${f%.*}" | tr / _).o"
    objs+=("$o")
    case "$f" in *.cpp) cmd=("$CXX" -std=c++17) ;; *) cmd=("$CC") ;; esac
    "${cmd[@]}" "${flags[@]}" -fPIC -DLM_EXPORT "${INC[@]}" -I"$DEPS/$variant/include" -c "$f" -o "$o" &
    pids+=($!)
    while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do sleep 0.05; done
  done
  for p in "${pids[@]}"; do wait "$p"; done
  rm -f "$out/libmem.a"
  ar rcs "$out/libmem.a" "${objs[@]}"
}

# 1) Sanitized + SanCov + DWARF<=3 libmem and the fuzz targets --------------------------------------------
SAN_OUT="$SRC/build-mayhem/san"
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
compile_lib san "$SAN_OUT" $FUZZ_CFLAGS

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SAN_OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SAN_OUT/standalone_main.o"

SAN_LIBS=("$SAN_OUT/libmem.a" "$DEPS/san/lib/libcapstone.a" "$DEPS/san/lib/libkeystone.a" -ldl -lm)
TARGETS=(fuzz_disasm fuzz_asm fuzz_demangle fuzz_scan fuzz_elfsyms)
for t in "${TARGETS[@]}"; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -Iinclude -c "mayhem/$t.c" -o "$SAN_OUT/$t.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SAN_OUT/$t.o" "$SAN_OUT/lsan_off.o" "${SAN_LIBS[@]}" -o "/mayhem/$t"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$SAN_OUT/$t.o" "$SAN_OUT/standalone_main.o" "$SAN_OUT/lsan_off.o" "${SAN_LIBS[@]}" -o "/mayhem/$t-standalone"
done

# 2) Test oracle: the project's NORMAL flags (no sanitizer, no DWARF pin), as upstream's CMake builds it -----
PLAIN_OUT="$SRC/build-tests"
compile_lib plain "$PLAIN_OUT/obj" $COVERAGE_FLAGS
mkdir -p "$PLAIN_OUT/tests"
$CXX -shared $COVERAGE_FLAGS "$PLAIN_OUT/obj"/*.o "$DEPS/plain/lib/libcapstone.a" "$DEPS/plain/lib/libkeystone.a" \
     -ldl -lm -o "$PLAIN_OUT/liblibmem.so"
$CC -shared -fPIC $COVERAGE_FLAGS -Iinclude tests/libtest.c -o "$PLAIN_OUT/tests/libtest.so"
$CC $COVERAGE_FLAGS -Iinclude tests/target.c "$PLAIN_OUT/liblibmem.so" -ldl -Wl,-rpath,"$PLAIN_OUT" -o "$PLAIN_OUT/tests/target"
$CC $COVERAGE_FLAGS -Iinclude -DLIBTEST_PATH="\"$PLAIN_OUT/tests/libtest.so\"" -DTARGET_NAME='"target"' \
    tests/unit/*.c "$PLAIN_OUT/liblibmem.so" -ldl -Wl,-rpath,"$PLAIN_OUT" -o "$PLAIN_OUT/tests/unit"
$CC $COVERAGE_FLAGS -Iinclude mayhem/kat.c "$PLAIN_OUT/liblibmem.so" -Wl,-rpath,"$PLAIN_OUT" -o "$PLAIN_OUT/kat"

for t in "${TARGETS[@]}"; do
  [ -x "/mayhem/$t" ] && [ -x "/mayhem/$t-standalone" ] || { echo "build.sh: missing $t" >&2; exit 1; }
done
[ -x "$PLAIN_OUT/tests/unit" ] && [ -x "$PLAIN_OUT/tests/target" ] && [ -x "$PLAIN_OUT/kat" ]
