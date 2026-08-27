#!/usr/bin/env bash
# Assert scc's classifications against the compiled test matrix in
# tests/binaries/output/. The parallel of checksec's hardening-checks.sh,
# but data-driven: one table row per binary, expectations support fnmatch
# patterns. Run tests/binaries/build_binaries.sh first.

set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${DIR}/.." && pwd)
SCC="${SCC:-${REPO_ROOT}/scc}"
OUT="${DIR}/binaries/output"

if [[ ! -x "${SCC}" ]]; then
  echo "scc binary not found at ${SCC} (build it or set SCC=<path>)" >&2
  exit 255
fi

# file:expected relro:canary:nx:pie:pic:bind_now:rpath:runpath:fortify
MATRIX='
all_gcc:Full RELRO:Canary found:NX enabled:PIE enabled:PIC enabled*:Bind now:No RPATH:No RUNPATH:Yes
all_clang:Full RELRO:Canary found:NX enabled:PIE enabled:PIC enabled*:Bind now:No RPATH:No RUNPATH:Yes
partial_gcc:Partial RELRO:Canary found:NX enabled:PIE enabled:PIC enabled*:Lazy binding:No RPATH:No RUNPATH:Yes
partial_clang:Partial RELRO:Canary found:NX enabled:PIE enabled:PIC enabled*:Lazy binding:No RPATH:No RUNPATH:Yes
rpath_gcc:*:Canary found:*:PIE enabled:PIC enabled*:*:RPATH*:No RUNPATH:*
rpath_clang:*:Canary found:*:PIE enabled:PIC enabled*:*:RPATH*:No RUNPATH:*
runpath_gcc:*:Canary found:*:PIE enabled:PIC enabled*:Bind now:No RPATH:RUNPATH*:*
runpath_clang:*:Canary found:*:PIE enabled:PIC enabled*:Bind now:No RPATH:RUNPATH*:*
none_gcc:No RELRO:No canary found:NX disabled:PIE disabled:N/A:Lazy binding:No RPATH:No RUNPATH:No
none_clang:No RELRO:No canary found:NX disabled:PIE disabled:N/A:Lazy binding:No RPATH:No RUNPATH:No
rel_gcc.o:*:No canary found:NX unknown (no GNU_STACK):REL (relocatable object):N/A:*:No RPATH:No RUNPATH:*
rel_clang.o:*:No canary found:NX unknown (no GNU_STACK):REL (relocatable object):N/A:*:No RPATH:No RUNPATH:*
dso_gcc.so:Full RELRO:Canary found:NX enabled:DSO (shared library):PIC enabled*:Bind now:No RPATH:No RUNPATH:*
dso_clang.so:Full RELRO:Canary found:NX enabled:DSO (shared library):PIC enabled*:Bind now:No RPATH:No RUNPATH:*
nofortify_gcc:Full RELRO:Canary found:NX enabled:PIE enabled:PIC enabled*:Bind now:No RPATH:No RUNPATH:No
nofortify_clang:Full RELRO:Canary found:NX enabled:PIE enabled:PIC enabled*:Bind now:No RPATH:No RUNPATH:No
'

tmpjson=$(mktemp /tmp/scc-checks.XXXXXX.json)
trap 'rm -f "${tmpjson}"' EXIT

fail=0
while IFS=: read -r file relro canary nx pie pic bindnow rpath runpath fortify; do
  [ -z "$file" ] && continue
  case "$file" in \#*) continue ;; esac
  bin="${OUT}/${file}"
  if [[ ! -f "${bin}" ]]; then
    echo "missing test binary: ${bin} (run build_binaries.sh first)" >&2
    fail=1
    continue
  fi
  # scc exits 2 when a binary fails checks — expected for several rows, so
  # tolerate the exit code and assert on the JSON content.
  "${SCC}" file "${bin}" -format json > "${tmpjson}" || true
  if BIN="$file" JSON_FILE="${tmpjson}" \
     EXP_RELRO="$relro" EXP_CANARY="$canary" EXP_NX="$nx" EXP_PIE="$pie" \
     EXP_PIC="$pic" \
     EXP_BIND_NOW="$bindnow" \
     EXP_RPATH="$rpath" EXP_RUNPATH="$runpath" EXP_FORTIFY="$fortify" \
     python3 "${DIR}/assert_checks.py"
  then
    :
  else
    fail=1
  fi
done < <(echo "$MATRIX" | grep -v '^#' | grep -v '^$')

if [ "$fail" -ne 0 ]; then
  echo "hardening validation FAILED" >&2
  exit 1
fi
echo "hardening validation tests passed"
