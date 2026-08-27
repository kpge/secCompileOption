"""Validate scc CSV output: exact header order and uniform row widths."""
import csv, sys

desc, path = sys.argv[1], sys.argv[2]
rows = list(csv.reader(open(path, newline="")))
assert len(rows) >= 2, f"{desc}: expected header + at least one row"
header, data = rows[0], rows[1:]
assert header[0] == "name", f"{desc}: first column is {header[0]!r}, want 'name'"
expected = ["name", "relro", "canary", "nx", "pie", "pic", "bind_now", "rpath",
            "runpath", "symbols", "fortify", "fortified", "fortifiable"]
assert header == expected, f"{desc}: header {header}, want {expected}"
for row in data:
    assert len(row) == len(header), f"{desc}: row width {len(row)} != {len(header)}"
print(f"{desc}: CSV OK")