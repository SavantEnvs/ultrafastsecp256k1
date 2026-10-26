#!/usr/bin/env bash
# Builds every fuzz harness (sanitized, + a -standalone run-once twin) and the KAT oracle binaries.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Library-level SanCov (-fsanitize=fuzzer-no-link) is required or Mayhem sees 0 edges in the fuzzed code.
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
# SECP256K1_BIP324 is only defined directory-scoped upstream, so libufsecp would silently omit the
# ufsecp_bip324_* C ABI; define it globally. -march=native would bake the build host's ISA into the image.
BIP324_DEF="-DSECP256K1_BIP324=1"

CMAKE_COMMON=(
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
  -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_BENCH=OFF -DSECP256K1_BUILD_EXAMPLES=OFF
  -DSECP256K1_BUILD_METAL=OFF -DSECP256K1_BUILD_JAVA=OFF -DSECP256K1_USE_LTO=OFF
  -DSECP256K1_INSTALL=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DSECP256K1_MARCH=x86-64-v2
)

# 1) sanitized + SanCov-instrumented libraries
rm -rf mayhem/build-fuzz
cmake -S . -B mayhem/build-fuzz -G Ninja "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS $BIP324_DEF" \
  -DCMAKE_C_FLAGS_RELEASE="-DNDEBUG" -DCMAKE_CXX_FLAGS_RELEASE="-DNDEBUG" \
  -DSECP256K1_USE_ASM=OFF
cmake --build mayhem/build-fuzz -j"$MAYHEM_JOBS" --target fastsecp256k1 ufsecp_static

LIB_FAST=$(find mayhem/build-fuzz -name libfastsecp256k1.a | head -n1)
LIB_C=$(find mayhem/build-fuzz -name 'libufsecp*.a' | head -n1)
[ -n "$LIB_FAST" ] && [ -n "$LIB_C" ]
# feature macros (SECP256K1_BIP324, ...) the C ABI headers key off must match how the library was built
read -r -a LIBDEFS <<< "$(python3 - mayhem/build-fuzz/compile_commands.json <<'PY'
import json, shlex, sys
for e in json.load(open(sys.argv[1])):
    if e["file"].endswith("src/cpu/src/ufsecp_impl.cpp"):
        cmd = e.get("command") or " ".join(e["arguments"])
        print(" ".join(t for t in shlex.split(cmd) if t.startswith("-D") and not t.startswith("-DUFSECP_BUILDING")))
        break
PY
)"
INCS=(-I"$SRC/include" -I"$SRC/src/cpu/include" -I"$SRC/mayhem/build-fuzz/include/ufsecp" -I"$SRC/mayhem/build-fuzz/include")

# 2) harnesses: one object each, linked once with libFuzzer and once with the run-once driver
mkdir -p mayhem/build-fuzz/obj
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/build-fuzz/obj/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o mayhem/build-fuzz/obj/lsan_off.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/cache_env.cc -o mayhem/build-fuzz/obj/cache_env.o

HARNESSES=(
  src/cpu/fuzz/fuzz_field.cpp src/cpu/fuzz/fuzz_scalar.cpp src/cpu/fuzz/fuzz_point.cpp
  src/cpu/fuzz/fuzz_ecdsa.cpp src/cpu/fuzz/fuzz_schnorr.cpp
  audit/fuzz_der_parse.cpp mayhem/harness/fuzz_pubkey_parse.cpp mayhem/harness/fuzz_schnorr_verify.cpp
  mayhem/harness/fuzz_ecdsa_verify.cpp audit/fuzz_bip32_path.cpp audit/fuzz_bip324_frame.cpp
)
for src in "${HARNESSES[@]}"; do
  name=$(basename "$src" .cpp)
  $CXX $FUZZ_FLAGS -std=c++20 -DUFSECP_API= "${LIBDEFS[@]}" "${INCS[@]}" -c "$src" -o "mayhem/build-fuzz/obj/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "mayhem/build-fuzz/obj/$name.o" mayhem/build-fuzz/obj/lsan_off.o mayhem/build-fuzz/obj/cache_env.o \
    "$LIB_C" "$LIB_FAST" -o "/mayhem/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "mayhem/build-fuzz/obj/$name.o" mayhem/build-fuzz/obj/standalone_main.o mayhem/build-fuzz/obj/lsan_off.o mayhem/build-fuzz/obj/cache_env.o \
    "$LIB_C" "$LIB_FAST" -o "/mayhem/$name-standalone"
done

# Pre-generate the fixed-base precompute table where cache_env.cc points the harnesses at it.
rm -rf mayhem/build-fuzz/xdg
head -c 32 /dev/zero | tr '\0' '\1' > mayhem/build-fuzz/obj/warm_input
XDG_CACHE_HOME="$SRC/mayhem/build-fuzz/xdg" "/mayhem/fuzz_point-standalone" mayhem/build-fuzz/obj/warm_input
[ -s mayhem/build-fuzz/xdg/secp256k1/cache_w18.bin ]
chmod -R a+rX mayhem/build-fuzz/xdg

# 3) oracle: upstream's own known-answer tests, normal flags, no sanitizers
rm -rf mayhem/build-tests
cmake -S . -B mayhem/build-tests -G Ninja "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS $BIP324_DEF"
cmake --build mayhem/build-tests -j"$MAYHEM_JOBS" --target fastsecp256k1 ufsecp_static
T_FAST=$(find mayhem/build-tests -name libfastsecp256k1.a | head -n1)
T_C=$(find mayhem/build-tests -name 'libufsecp*.a' | head -n1)
read -r -a TLIBDEFS <<< "$(python3 - mayhem/build-tests/compile_commands.json <<'PY'
import json, shlex, sys
for e in json.load(open(sys.argv[1])):
    if e["file"].endswith("src/cpu/src/ufsecp_impl.cpp"):
        cmd = e.get("command") or " ".join(e["arguments"])
        print(" ".join(t for t in shlex.split(cmd) if t.startswith("-D") and not t.startswith("-DUFSECP_BUILDING")))
        break
PY
)"
TINCS=(-I"$SRC/include" -I"$SRC/src/cpu/include" -I"$SRC/include/ufsecp" -I"$SRC/audit" -I"$SRC/mayhem/build-tests/include/ufsecp" -I"$SRC/mayhem/build-tests/include")
mkdir -p mayhem/build-tests/kat
KATS=$(cat mayhem/kat_tests.txt)
for t in $KATS; do
  $CXX -O2 -std=c++20 $COVERAGE_FLAGS -DSTANDALONE_TEST -DUFSECP_API= "${TLIBDEFS[@]}" "${TINCS[@]}" "audit/$t.cpp" \
    "$T_C" "$T_FAST" -o "mayhem/build-tests/kat/$t"
done
