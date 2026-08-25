#!/usr/bin/env bash
# Validate scc's JSON output: schema shape and parseability against both the
# compiled matrix and a real system binary. The parallel of checksec's
# json-checks.sh (which jsonlints procAll output; scc has no proc mode, so
# we validate file/dir/list modes instead).

set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${DIR}/.." && pwd)
SCC="${SCC:-${REPO_ROOT}/scc}"
OUT="${DIR}/binaries/output"

if [[ ! -x "${SCC}" ]]; then
  echo "scc binary not found at ${SCC} (build it or set SCC=<path>)" >&2
  exit 255
fi

if [[ -f /bin/bash ]]; then
  sys_file=/bin/bash
elif [[ -f /bin/ls ]]; then
  sys_file=/bin/ls
else
  echo "could not find a system ELF binary to test" >&2
  exit 255
fi

tmp=$(mktemp /tmp/scc-json.XXXXXX)
trap 'rm -f "${tmp}"' EXIT

validate() {
  local desc="$1"; shift
  # exit 2 = "binary failed checks", a valid outcome; only parse the output
  "${SCC}" "$@" -format json > "${tmp}" || [ $? -eq 2 ]
  python3 "${DIR}/validate_json.py" "$desc" "$tmp"
}

validate "file mode (matrix binary)" file "${OUT}/all_gcc"
validate "file mode (system binary)" file "${sys_file}"
validate "file mode (multi-target)" file "${OUT}/all_gcc" "${OUT}/none_gcc"
validate "dir mode" dir "${OUT}"
validate "list mode" list /dev/null

echo "json validation tests passed"
