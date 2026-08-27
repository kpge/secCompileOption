package checksec

import (
	"debug/elf"
	"fmt"
	"os"
)

// FileReport is the complete check output for one binary. It serializes
// directly to JSON and is the source for the table/CSV/XML renderers.
type FileReport struct {
	Name   string            `json:"name"`
	Error  string            `json:"error,omitempty"`
	Checks map[string]Result `json:"checks"`
}

// CheckOrder is the canonical column/key order. The table renderer uses it
// for headers and JSON objects preserve it via ordered marshaling.
var CheckOrder = []string{
	"relro", "canary", "nx", "pie", "pic",
	"bind_now", "rpath", "runpath", "symbols",
	"fortify", "fortified", "fortifiable",
}

// HeaderName maps a check key to its table header.
var HeaderName = map[string]string{
	"relro":       "RELRO",
	"canary":      "Canary",
	"nx":          "NX",
	"pie":         "PIE",
	"pic":         "PIC",
	"bind_now":    "BIND_NOW",
	"rpath":       "RPATH",
	"runpath":     "RUNPATH",
	"symbols":     "Symbols",
	"fortify":     "FORTIFY",
	"fortified":   "Fortified",
	"fortifiable": "Fortifiable",
}

// CheckFile runs every check against the binary at path and returns a fully
// populated report. Every key in CheckOrder is present even on error paths.
func CheckFile(path string) FileReport {
	report := FileReport{Name: path, Checks: map[string]Result{}}
	for _, k := range CheckOrder {
		report.Checks[k] = Err(k)
	}

	raw, err := os.Open(path)
	if err != nil {
		report.Error = fmt.Sprintf("cannot open: %v", err)
		return report
	}
	defer raw.Close()

	f, err := elf.NewFile(raw)
	if err != nil {
		report.Error = fmt.Sprintf("not an ELF file: %v", err)
		return report
	}

	report.Checks["relro"] = RELRO(f)
	report.Checks["canary"] = Canary(f, raw)
	report.Checks["nx"] = NX(f)
	report.Checks["pie"] = PIE(f)
	report.Checks["pic"] = PIC(f)
	report.Checks["bind_now"] = BindNow(f)
	report.Checks["rpath"] = RPATH(f, raw)
	report.Checks["runpath"] = RUNPATH(f, raw)
	report.Checks["symbols"] = Symbols(f, raw)
	fr := Fortify(f, raw, resolveLibcFlag(path, f, raw))
	report.Checks["fortify"] = fr.Summary
	report.Checks["fortified"] = fr.Fortified
	report.Checks["fortifiable"] = fr.Fortifiable

	return report
}
