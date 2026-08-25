// Package checksec implements the individual binary-hardening checks.
//
// Every check takes a parsed *elf.File (plus, where noted, the raw *os.File
// for stripped binaries whose section headers are gone) and returns a Result
// describing one secure-compile option. Results are plain data so every
// output renderer (table, JSON, CSV, XML) can consume them uniformly.
package checksec

import "fmt"

// Status is the severity of a check result. It is semantic (not a display
// color); the printer maps it to ANSI colors or nothing.
type Status string

const (
	StatusGood Status = "good" // hardening present
	StatusWarn Status = "warn" // partially present / depends on context
	StatusBad  Status = "bad"  // hardening absent
	StatusInfo Status = "info" // informational, no pass/fail meaning
	StatusNA   Status = "n/a"  // check does not apply
)

// Result is the uniform return value of every binary check.
type Result struct {
	Value  string `json:"value"`
	Status Status `json:"status"`
}

// OK builds a Result with StatusGood.
func OK(v string) Result { return Result{Value: v, Status: StatusGood} }

// Bad builds a Result with StatusBad.
func Bad(v string) Result { return Result{Value: v, Status: StatusBad} }

// Warn builds a Result with StatusWarn.
func Warn(v string) Result { return Result{Value: v, Status: StatusWarn} }

// Info builds a Result with StatusInfo.
func Info(v string) Result { return Result{Value: v, Status: StatusInfo} }

// NA builds a Result with StatusNA.
func NA(v string) Result { return Result{Value: v, Status: StatusNA} }

// Err builds a Result for a check that could not run.
func Err(check string) Result {
	return Result{Value: fmt.Sprintf("error checking %s", check), Status: StatusBad}
}
