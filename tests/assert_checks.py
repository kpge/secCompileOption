"""Assert one scc JSON report against expected check values.

Invoked by hardening-checks.sh with environment variables:
  JSON_FILE   path to the scc -format json output (array of reports)
  BIN         display name of the binary under test
  EXP_*       expected value per check (fnmatch patterns, * = any)

Exits 0 when every check matches; otherwise prints every mismatch to
stderr and exits 1.
"""
import json
import os
import fnmatch
import sys

checks = json.load(open(os.environ["JSON_FILE"]))[0]["checks"]
want = {
    "relro": os.environ["EXP_RELRO"],
    "canary": os.environ["EXP_CANARY"],
    "nx": os.environ["EXP_NX"],
    "pie": os.environ["EXP_PIE"],
    "rpath": os.environ["EXP_RPATH"],
    "runpath": os.environ["EXP_RUNPATH"],
    "fortify": os.environ["EXP_FORTIFY"],
}
failed = False
for key, expected in want.items():
    got = checks[key]["value"]
    if not fnmatch.fnmatchcase(got, expected):
        print(f'{os.environ["BIN"]}: {key} = {got!r}, want {expected!r}', file=sys.stderr)
        failed = True
if failed:
    sys.exit(1)
print(f'{os.environ["BIN"]}: all checks pass')
