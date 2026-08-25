#!/usr/bin/env bash
# Full end-to-end test entrypoint: build scc, compile the real-binary test
# matrix, then run hardening, JSON, and XML/CSV validation. The parallel of
# checksec's tests/test-checksec.sh (which does the same inside Docker).

set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${DIR}/.." && pwd)

# 1) build scc
(
  cd "${REPO_ROOT}"
  go build -o scc ./cmd/scc
)

# 2) compile the test matrix
(
  cd "${DIR}/binaries"
  bash ./build_binaries.sh
)

# 3) run all check suites
bash "${DIR}/hardening-checks.sh"
bash "${DIR}/compliance-checks.sh"
bash "${DIR}/json-checks.sh"
bash "${DIR}/xml-checks.sh"

echo "all end-to-end tests passed"
