#!/usr/bin/env bash
# Validate scc's XML and CSV output against both the compiled matrix and a
# real system binary. The parallel of checksec's xml-checks.sh (which
# xmllints procAll output; scc has no proc mode, so we validate file/dir
# modes instead, plus CSV since scc supports it).

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

tmpxml=$(mktemp /tmp/scc-xml.XXXXXX.xml)
tmpcsv=$(mktemp /tmp/scc-csv.XXXXXX.csv)
trap 'rm -f "${tmpxml}" "${tmpcsv}"' EXIT

# --- XML ------------------------------------------------------------------
validate_xml() {
  local desc="$1"; shift
  "${SCC}" "$@" -format xml > "${tmpxml}" || [ $? -eq 2 ]
  python3 "${DIR}/validate_xml.py" "$desc" "${tmpxml}"
}

validate_xml "XML file mode (matrix)" file "${OUT}/all_gcc"
validate_xml "XML file mode (system)" file "${sys_file}"
validate_xml "XML dir mode" dir "${OUT}"

# --- CSV ------------------------------------------------------------------
validate_csv() {
  local desc="$1"; shift
  "${SCC}" "$@" -format csv > "${tmpcsv}" || [ $? -eq 2 ]
  python3 "${DIR}/validate_csv.py" "$desc" "${tmpcsv}"
}

validate_csv "CSV file mode (matrix)" file "${OUT}/all_gcc"
validate_csv "CSV file mode (system)" file "${sys_file}"
validate_csv "CSV dir mode" dir "${OUT}"

echo "xml/csv validation tests passed"
