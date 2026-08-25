"""Validate scc XML output: <secCompileCheck><file name=...><check key=... status=...>."""
import sys, xml.etree.ElementTree as ET

desc, path = sys.argv[1], sys.argv[2]
root = ET.parse(path).getroot()
assert root.tag == "secCompileCheck", f"{desc}: root is <{root.tag}>, want <secCompileCheck>"
files = root.findall("file")
assert files, f"{desc}: no <file> elements"
for f in files:
    assert f.get("name"), f"{desc}: <file> without name attribute"
    checks = f.findall("check")
    assert checks, f"{desc}: <file> without <check> elements"
    for c in checks:
        assert c.get("key"), f"{desc}: <check> without key"
        assert c.get("status") in {"good", "warn", "bad", "info", "n/a"}, \
            f"{desc}: bad status {c.get('status')!r}"
print(f"{desc}: XML OK")