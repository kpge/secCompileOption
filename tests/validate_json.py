"""Validate scc JSON output shape: array of {name, checks:{key:{value,status}}}."""
import json, sys

desc, path = sys.argv[1], sys.argv[2]
reports = json.load(open(path))
assert isinstance(reports, list), f"{desc}: top level is not a list"
for rep in reports:
    assert set(rep.keys()) >= {"name", "checks"}, f"{desc}: report keys {sorted(rep.keys())}"
    for key, res in rep["checks"].items():
        assert set(res.keys()) == {"value", "status"}, f"{desc}: result keys {sorted(res.keys())}"
        assert res["status"] in {"good", "warn", "bad", "info", "n/a"}, \
            f"{desc}: bad status {res['status']!r}"
print(f"{desc}: JSON schema OK")