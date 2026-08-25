#!/usr/bin/env bash
# Build the real-binary test matrix into tests/binaries/output/.
# Ported from checksec's tests/binaries/build_binaries.sh (gcc/clang matrix,
# minus the CFI/SafeStack variants scc does not implement, and minus 32-bit
# which needs gcc-multilib).
#
# Toolchain defaults are normalized explicitly because Ubuntu's gcc enables
# stack protection and _FORTIFY_SOURCE=2 by default while clang enables
# neither; without normalization the two toolchains would emit different
# binaries for the same flags and the assertions could not be shared.

set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
OUT="${DIR}/output"
mkdir -p "${OUT}"

for cc in gcc clang; do
  # All hardening on (full RELRO, canary, NX, PIE, fortify, stripped)
  $cc -o "${OUT}/all_${cc}" test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
      -fpie -O2 -z relro -z now -z noexecstack -pie -s
  # Partial RELRO (lazy binding)
  $cc -o "${OUT}/partial_${cc}" test.c -w -D_FORTIFY_SOURCE=1 -fstack-protector-strong \
      -fpie -O2 -z relro -z lazy -z noexecstack -s
  # RPATH (old-style DT_RPATH tag)
  $cc -o "${OUT}/rpath_${cc}" test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
      -fpie -O2 -z relro -z now -z noexecstack -pie -s \
      -Wl,-rpath,/nonexistent/libdir -Wl,--disable-new-dtags
  # RUNPATH (new-style DT_RUNPATH tag)
  $cc -o "${OUT}/runpath_${cc}" test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
      -fpie -O2 -z relro -z now -z noexecstack -pie -s \
      -Wl,-rpath,/nonexistent/libdir -Wl,--enable-new-dtags
  # No hardening at all (exec stack, no canary, no PIE, no RELRO, symbols kept)
  $cc -o "${OUT}/none_${cc}" test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector \
      -no-pie -O2 -z norelro -z lazy -z execstack
  # Relocatable object → REL classification. Explicit -fno-stack-protector:
  # Ubuntu's gcc enables stack protection by default (--enable-default-ssp)
  # while clang does not; normalize so both toolchains emit the same thing.
  $cc -c test.c -o "${OUT}/rel_${cc}.o" -w -fno-stack-protector -U_FORTIFY_SOURCE
  # Shared object → DSO classification
  $cc -shared -fPIC -o "${OUT}/dso_${cc}.so" test.c -w -D_FORTIFY_SOURCE=2 \
      -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s
  # Fortify variant: hardened build with fortify explicitly off. Ubuntu's
  # gcc injects _FORTIFY_SOURCE=2 by default at -O1+, clang does not;
  # -D_FORTIFY_SOURCE=0 normalizes both.
  $cc -o "${OUT}/nofortify_${cc}" test.c -w -D_FORTIFY_SOURCE=0 -fstack-protector-strong \
      -fpie -O2 -z relro -z now -z noexecstack -pie -s
done

echo "built $(ls "${OUT}" | wc -l) test binaries in ${OUT}"
