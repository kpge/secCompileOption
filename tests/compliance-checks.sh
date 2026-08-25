#!/usr/bin/env bash
# Validate scc's secure-compile-spec compliance mode against the compiled
# matrix: the fully hardened binaries must be fully compliant (exit 0), the
# vulnerable ones must fail (exit 2), and rpath binaries must violate the
# no-rpath rule regardless of how safe the path looks.

set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${DIR}/.." && pwd)
SCC="${SCC:-${REPO_ROOT}/scc}"
OUT="${DIR}/binaries/output"

if [[ ! -x "${SCC}" ]]; then
  echo "scc binary not found at ${SCC} (build it or set SCC=<path>)" >&2
  exit 255
fi

tmp=$(mktemp /tmp/scc-compliance.XXXXXX.json)
trap 'rm -f "${tmp}"' EXIT

# expect_compliance <desc> <bin> <expect: pass|fail>
expect_compliance() {
  local desc="$1" bin="$2" expect="$3"
  set +e
  "${SCC}" file "${bin}" -format compliance-json > "${tmp}" 2>/dev/null
  local rc=$?
  set -e
  case "${expect}" in
    pass) [ "${rc}" -eq 0 ] || {
      echo "${desc}: exit ${rc}, want 0"
      # Diagnose which rules failed before returning.
      python3 -c "import json,sys; [print(f'  FAIL: {i[\"id\"]} ({i[\"result\"][\"value\"]})') for i in json.load(open('${tmp}'))[0]['items'] if i['result']['status']=='bad']" 2>/dev/null || true
      return 1
    } ;;
    fail) [ "${rc}" -eq 2 ] || { echo "${desc}: exit ${rc}, want 2"; return 1; } ;;
  esac
  BIN="${bin}" JSON_FILE="${tmp}" EXPECT="${expect}" \
    python3 "${DIR}/assert_compliance.py"
}

fail=0
for cc in gcc clang; do
  # all_* is fully compliant by construction (spec: PIE, canary, RELRO+now,
  # NX, stripped, no rpath)
  expect_compliance "all_${cc}" "${OUT}/all_${cc}" pass || fail=1
  # none_* violates everything except no_rpath
  expect_compliance "none_${cc}" "${OUT}/none_${cc}" fail || fail=1
  # rpath is prohibited outright: even an absolute, nonexistent dir is a
  # violation of the no-rpath rule
  expect_compliance "rpath_${cc}" "${OUT}/rpath_${cc}" fail || fail=1
  # partial RELRO passes the relro rule (spec allows partial) but fails
  # bind_now
  expect_compliance "partial_${cc}" "${OUT}/partial_${cc}" fail || fail=1
done

if [ "$fail" -ne 0 ]; then
  echo "compliance validation FAILED" >&2
  exit 1
fi
echo "compliance validation tests passed"
