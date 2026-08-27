package main

import (
	"testing"

	"seccompilecheck/internal/checksec"
)

// TestHasFailuresStackProtectionAlternatives pins the "any one of canary /
// ohos_retguard / pac_cfi qualifies" exit-code semantics: a binary passes
// when any of the three mechanisms is present, and fails only when none is.
func TestHasFailuresStackProtectionAlternatives(t *testing.T) {
	report := func(canary, retguard, paccfi checksec.Status) checksec.FileReport {
		r := checksec.FileReport{Name: "x", Checks: map[string]checksec.Result{}}
		for _, k := range checksec.CheckOrder {
			r.Checks[k] = checksec.OK("ok")
		}
		r.Checks["canary"] = checksec.Result{Value: "No canary found", Status: canary}
		r.Checks["ohos_retguard"] = checksec.Result{Value: "x", Status: retguard}
		r.Checks["pac_cfi"] = checksec.Result{Value: "x", Status: paccfi}
		return r
	}

	cases := []struct {
		name     string
		r        checksec.FileReport
		wantFail bool
	}{
		{"canary present", report(checksec.StatusGood, checksec.StatusBad, checksec.StatusBad), false},
		{"retguard present", report(checksec.StatusBad, checksec.StatusGood, checksec.StatusNA), false},
		{"pac cfi present", report(checksec.StatusBad, checksec.StatusNA, checksec.StatusGood), false},
		{"none present", report(checksec.StatusBad, checksec.StatusBad, checksec.StatusBad), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasFailures([]checksec.FileReport{tc.r}); got != tc.wantFail {
				t.Errorf("hasFailures = %v, want %v", got, tc.wantFail)
			}
		})
	}
}
