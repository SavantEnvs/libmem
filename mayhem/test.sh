#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

B="$SRC/build-tests"
for exe in "$B/kat" "$B/tests/unit" "$B/tests/target" "$B/liblibmem.so"; do
  [ -e "$exe" ] || { echo "test.sh: $exe missing — mayhem/build.sh must build it" >&2; emit_ctrf "libmem-kat+unit" 0 1 0; exit 1; }
done

passed=0; failed=0

# 1) Known-answer probe, run by this script through the dynamically linked libmem.so. Golden values come
#    from libmem's own unit fixtures (tests/unit/asm.c, scan.c) and the Itanium ABI; the symbol address
#    is cross-checked against `nm`, so the comparison happens in bash/coreutils, outside the program under test.
kat_out="$("$B/kat" "$B/liblibmem.so" 2>&1)" || true
nm_addr="$(nm -D --defined-only "$B/liblibmem.so" | awk '$3=="LM_AssembleEx"{print $1}' | sed 's/^0*//')"
expected="$(cat <<EXP
asm_x64_size=5
asm_x64_bytes=b839050000
asm_arm_size=8
asm_arm_bytes=0110a0e31eff2fe1
disasm_x64_count=7
disasm_x64_0=1000:push rbp
disasm_x64_1=1001:mov rbp, rsp
disasm_x64_2=1004:mov eax, dword ptr [rip + 0x539]
disasm_x64_3=100a:call rax
disasm_x64_4=100c:mov rsp, rbp
disasm_x64_5=100f:pop rbp
disasm_x64_6=1010:ret 
disasm_arm_count=2
disasm_arm_0=mov r1, #1
disasm_arm_1=bx lr
demangle=foo::bar(int)
demangle_stl=std::vector<int, std::allocator<int>>::push_back(int const&)
sigscan_offset=2
datascan_offset=4
patternscan_offset=1
elf_sym_LM_AssembleEx=$nm_addr
EXP
)"
if [ -n "$nm_addr" ] && [ "$kat_out" = "$expected" ]; then
  passed=$((passed + 1)); echo "KAT probe: OK"
else
  failed=$((failed + 1)); echo "KAT probe: FAILED — diff (expected vs actual):" >&2
  diff <(printf '%s\n' "$expected") <(printf '%s\n' "$kat_out") >&2 || true
fi

# 2) Upstream's own unit suite (tests/unit). It tests a separate `target` process, so run that alongside.
#    Each case prints "<name>... OK"; the first failure prints "ERROR:" and exits 1.
"$B/tests/target" >/dev/null 2>&1 &
target_pid=$!
sleep 1
unit_out="$(cd "$B/tests" && timeout 300 ./unit 2>&1)"; unit_rc=$?
kill "$target_pid" 2>/dev/null; wait "$target_pid" 2>/dev/null
echo "$unit_out" | tail -n 25
unit_ok="$(echo "$unit_out" | grep -c -E '^[A-Za-z_]+\.\.\. .*OK$' || true)"
# The first 27 cases are in-process and must all pass. The remote-process (*MemoryEx) cases need ptrace, which
# the container build sandbox denies; a stop there ("LM_*MemoryEx... ERROR") is tolerated, any other failure is not.
UNIT_EXPECTED=27
passed=$((passed + unit_ok))
if [ "$unit_ok" -lt "$UNIT_EXPECTED" ]; then
  failed=$((failed + 1)); echo "unit suite: rc=$unit_rc, only $unit_ok/$UNIT_EXPECTED in-process cases OK" >&2
elif [ "$unit_rc" -ne 0 ] && ! echo "$unit_out" | grep -q -E '^LM_[A-Za-z]*MemoryEx\.\.\. ERROR'; then
  failed=$((failed + 1)); echo "unit suite: unexpected failure rc=$unit_rc" >&2
fi

emit_ctrf "libmem-kat+unit" "$passed" "$failed" 0
