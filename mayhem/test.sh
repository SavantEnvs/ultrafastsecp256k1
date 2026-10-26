#!/usr/bin/env bash
#
# mayhem/test.sh — runs the upstream known-answer test binaries that build.sh built (mayhem/build-tests/kat/*).
# Each prints "Result: P passed, F failed"; a run that exits early or prints no summary counts as a failure.
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


KATDIR="$SRC/mayhem/build-tests/kat"
# minimum pass count per KAT binary, so a patch cannot "pass" by deleting vectors
declare -A MIN=(
  [test_exploit_schnorr_bip340_kat]=19 [test_exploit_sha256_kat]=22 [test_exploit_ecdsa_rfc6979_kat]=28
  [test_exploit_chacha20_kat]=18 [test_exploit_hkdf_kat]=23 [test_exploit_keccak256_kat]=21
  [test_exploit_ripemd160_kat]=17
)

passed=0; failed=0
for t in $(cat "$SRC/mayhem/kat_tests.txt"); do
  bin="$KATDIR/$t"
  if [ ! -x "$bin" ]; then echo "missing $bin (build.sh bug)" >&2; failed=$((failed + 1)); continue; fi
  out=$("$bin" 2>&1); rc=$?
  printf '%s\n' "$out" | tail -n 3
  if [[ "$out" =~ Result:\ ([0-9]+)\ passed,\ ([0-9]+)\ failed ]]; then
    p=${BASH_REMATCH[1]}; f=${BASH_REMATCH[2]}
  else
    echo "$t: no result summary" >&2; failed=$((failed + 1)); continue
  fi
  if [ "$rc" -ne 0 ] || [ "$f" -ne 0 ] || [ "$p" -lt "${MIN[$t]:-1}" ]; then
    echo "$t: rc=$rc passed=$p failed=$f (min ${MIN[$t]:-1})" >&2
    failed=$((failed + 1)); continue
  fi
  passed=$((passed + p))
done

# Unconditional known-input -> known-output checks on the printed vectors (BIP-340 vector 4: pubkey not
# on curve must verify FALSE; vector 0: the reference signature must verify).
sch=$("$KATDIR/test_exploit_schnorr_bip340_kat" 2>&1)
if grep -q 'verify vector 4 (public key not on curve): result=FALSE (expected=FALSE)' <<<"$sch"; then
  passed=$((passed + 1))
else
  echo "BIP-340 vector 4 line missing" >&2; failed=$((failed + 1))
fi
if grep -q 'sign vector 0: reference sig verifies' <<<"$sch"; then
  passed=$((passed + 1))
else
  echo "BIP-340 vector 0 verify line missing" >&2; failed=$((failed + 1))
fi

emit_ctrf "ufsecp-kat" "$passed" "$failed" 0
