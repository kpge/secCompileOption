"""Assert one compliance-json report.

Environment:
  JSON_FILE   path to `scc file X -format compliance-json` output (one summary)
  BIN         display name of the binary
  EXPECT      "pass" (0 fails) or "fail" (>=1 fail)

Validates that every spec rule is present and, for EXPECT=pass, that none
fail; for EXPECT=fail only checks the shape (which rules fail is already
covered per-binary by hardening-checks.sh).
"""
import json
import os
import sys

s = json.load(open(os.environ["JSON_FILE"]))[0]
want_ids = {"pie", "stack_protector", "relro", "bind_now", "nx", "stripped", "no_rpath"}
got_ids = {item["id"] for item in s["items"]}
if got_ids != want_ids:
    sys.exit(f'{os.environ["BIN"]}: rule ids {sorted(got_ids)}, want {sorted(want_ids)}')
for item in s["items"]:
    if set(item.keys()) < {"id", "name", "require", "result"}:
        sys.exit(f'{os.environ["BIN"]}: item keys {sorted(item.keys())}')
    if item["result"]["status"] not in {"good", "bad", "n/a"}:
        sys.exit(f'{os.environ["BIN"]}: bad status {item["result"]["status"]!r}')
if s["pass"] + s["fail"] + s["n/a"] != len(s["items"]):
    sys.exit(f'{os.environ["BIN"]}: counts {s["pass"]}+{s["fail"]}+{s["n/a"]} != {len(s["items"])}')

expect = os.environ["EXPECT"]
if expect == "pass" and s["fail"] != 0:
    failed = [i["id"] for i in s["items"] if i["result"]["status"] == "bad"]
    sys.exit(f'{os.environ["BIN"]}: expected fully compliant, failing rules: {failed}')
if expect == "fail" and s["fail"] == 0:
    sys.exit(f'{os.environ["BIN"]}: expected compliance failure, got all-pass')
print(f'{os.environ["BIN"]}: compliance {expect} OK ({s["pass"]} pass / {s["fail"]} fail / {s["n/a"]} n/a)')
