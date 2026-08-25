package checksec

import (
	"os"
	"path/filepath"
	"testing"

	"seccompilecheck/internal/elfgen"
)

// writeElf materializes a synthetic binary and returns its path.
func writeElf(t *testing.T, l elfgen.Layout) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), l.Name+".elf")
	if err := os.WriteFile(path, elfgen.Build(l), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRELRO(t *testing.T) {
	cases := []struct {
		name string
		l    elfgen.Layout
		want string
	}{
		{"full", elfgen.Layout{Name: "x", Relro: true, BindNow: true, DynSyms: []string{"a"}}, "Full RELRO"},
		{"partial", elfgen.Layout{Name: "x", Relro: true, DynSyms: []string{"a"}}, "Partial RELRO"},
		{"none", elfgen.Layout{Name: "x", DynSyms: []string{"a"}}, "No RELRO"},
		{"bind-now-flags", elfgen.Layout{Name: "x", Relro: true, FlagsBind: true, DynSyms: []string{"a"}}, "Full RELRO"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeElf(t, tc.l)
			r := CheckFile(path)
			if got := r.Checks["relro"].Value; got != tc.want {
				t.Errorf("relro = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCanary(t *testing.T) {
	cases := []struct {
		name string
		l    elfgen.Layout
		want string
	}{
		{"present", elfgen.Layout{Name: "x", DynSyms: []string{"__stack_chk_fail"}}, "Canary found"},
		{"guard", elfgen.Layout{Name: "x", DynSyms: []string{"__stack_chk_guard"}}, "Canary found"},
		{"absent", elfgen.Layout{Name: "x", DynSyms: []string{"printf"}}, "No canary found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeElf(t, tc.l)
			r := CheckFile(path)
			if got := r.Checks["canary"].Value; got != tc.want {
				t.Errorf("canary = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNX(t *testing.T) {
	cases := []struct {
		name string
		l    elfgen.Layout
		want string
	}{
		{"enabled", elfgen.Layout{Name: "x"}, "NX enabled"},
		{"disabled", elfgen.Layout{Name: "x", GnuStackX: true}, "NX disabled"},
		{"no-seg", elfgen.Layout{Name: "x", NoStack: true}, "NX unknown (no GNU_STACK)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeElf(t, tc.l)
			r := CheckFile(path)
			if got := r.Checks["nx"].Value; got != tc.want {
				t.Errorf("nx = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPIE(t *testing.T) {
	cases := []struct {
		name string
		l    elfgen.Layout
		want string
	}{
		{"pie", elfgen.Layout{Name: "x", Pie: true, DynSyms: []string{"a"}}, "PIE enabled"},
		{"static-pie", elfgen.Layout{Name: "x", ETDyn: true, Flags1Pie: true, DynSyms: []string{"a"}}, "Static PIE"},
		{"dso", elfgen.Layout{Name: "x", ETDyn: true, DynSyms: []string{"a"}}, "DSO (shared library)"},
		{"exec", elfgen.Layout{Name: "x", Interp: true, DynSyms: []string{"a"}}, "PIE disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeElf(t, tc.l)
			r := CheckFile(path)
			if got := r.Checks["pie"].Value; got != tc.want {
				t.Errorf("pie = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRpathRunpath(t *testing.T) {
	cases := []struct {
		name  string
		l     elfgen.Layout
		key   string
		value string
	}{
		{"rpath-relative", elfgen.Layout{Name: "x", Rpath: []string{"../lib"}, DynSyms: []string{"a"}}, "rpath", "RPATH [../lib] (prohibited; relative path)"},
		{"rpath-origin", elfgen.Layout{Name: "x", Rpath: []string{"$ORIGIN/lib"}, DynSyms: []string{"a"}}, "rpath", "RPATH [$ORIGIN/lib] (prohibited; $ORIGIN-relative)"},
		{"rpath-abs-safe", elfgen.Layout{Name: "x", Rpath: []string{"/opt/vendor/lib"}, DynSyms: []string{"a"}}, "rpath", "RPATH [/opt/vendor/lib] (prohibited; dir not found on this host)"},
		{"runpath-origin", elfgen.Layout{Name: "x", Runpath: []string{"$ORIGIN/../lib"}, DynSyms: []string{"a"}}, "runpath", "RUNPATH [$ORIGIN/../lib] ($ORIGIN-relative)"},
		{"none", elfgen.Layout{Name: "x", DynSyms: []string{"a"}}, "rpath", "No RPATH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeElf(t, tc.l)
			r := CheckFile(path)
			if got := r.Checks[tc.key].Value; got != tc.value {
				t.Errorf("%s = %q, want %q", tc.key, got, tc.value)
			}
		})
	}
}

func TestFortify(t *testing.T) {
	cases := []struct {
		name        string
		l           elfgen.Layout
		wantSummary string
		wantFort    string
		wantFortif  string
	}{
		{
			// __memcpy_chk (fortified) plus memcpy (base) = 1 fortified
			// call + 2 fortifiable calls.
			name:        "fortified",
			l:           elfgen.Layout{Name: "x", DynSyms: []string{"__memcpy_chk", "memcpy"}},
			wantSummary: "Yes",
			wantFort:    "1",
			wantFortif:  "2",
		},
		{
			name:        "unfortified-only",
			l:           elfgen.Layout{Name: "x", DynSyms: []string{"strcpy"}},
			wantSummary: "No",
			wantFort:    "0",
			wantFortif:  "1",
		},
		{
			name:        "mixed",
			l:           elfgen.Layout{Name: "x", DynSyms: []string{"__memcpy_chk", "strcpy"}},
			wantSummary: "Yes",
			wantFort:    "1",
			wantFortif:  "2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeElf(t, tc.l)
			r := CheckFile(path)
			if got := r.Checks["fortify"].Value; got != tc.wantSummary {
				t.Errorf("fortify = %q, want %q", got, tc.wantSummary)
			}
			if got := r.Checks["fortified"].Value; got != tc.wantFort {
				t.Errorf("fortified = %q, want %q", got, tc.wantFort)
			}
			if got := r.Checks["fortifiable"].Value; got != tc.wantFortif {
				t.Errorf("fortifiable = %q, want %q", got, tc.wantFortif)
			}
		})
	}
}

func TestBindNow(t *testing.T) {
	cases := []struct {
		name string
		l    elfgen.Layout
		want string
	}{
		{"bind-now-entry", elfgen.Layout{Name: "x", Relro: true, BindNow: true, DynSyms: []string{"a"}}, "Bind now"},
		{"flags-bind-now", elfgen.Layout{Name: "x", Relro: true, FlagsBind: true, DynSyms: []string{"a"}}, "Bind now"},
		{"lazy", elfgen.Layout{Name: "x", Relro: true, DynSyms: []string{"a"}}, "Lazy binding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeElf(t, tc.l)
			r := CheckFile(path)
			if got := r.Checks["bind_now"].Value; got != tc.want {
				t.Errorf("bind_now = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestComplianceHardened checks the spec rollup on a fully hardened layout:
// every rule passes except "stripped" (elfgen binaries have no symtab, so
// Symbols reports stripped — which passes too) and rel.o rows are n/a.
func TestCompliance(t *testing.T) {
	t.Run("fully hardened binary", func(t *testing.T) {
		path := writeElf(t, elfgen.Layout{
			Name: "x", Pie: true, Relro: true, BindNow: true,
			DynSyms: []string{"__stack_chk_fail", "__memcpy_chk"},
		})
		s := Compliance(CheckFile(path))
		if s.Fail != 0 {
			for _, it := range s.Items {
				if it.Result.Status == StatusBad {
					t.Errorf("rule %q failed: %s", it.ID, it.Result.Value)
				}
			}
		}
		wantPass := 7
		if s.Pass != wantPass {
			t.Errorf("pass = %d, want %d", s.Pass, wantPass)
		}
	})

	t.Run("vulnerable binary", func(t *testing.T) {
		path := writeElf(t, elfgen.Layout{
			Name: "x", Interp: true, GnuStackX: true,
			DynSyms: []string{"printf"},
		})
		s := Compliance(CheckFile(path))
		// PIE missing, no canary, no RELRO, lazy binding, exec stack,
		// rpath absent (pass) — six hard fails expected.
		if s.Fail < 5 {
			t.Errorf("fail = %d, want at least 5", s.Fail)
		}
		for _, id := range []string{"pie", "stack_protector", "relro", "bind_now", "nx"} {
			var found *ComplianceItem
			for i := range s.Items {
				if s.Items[i].ID == id {
					found = &s.Items[i]
				}
			}
			if found == nil {
				t.Fatalf("rule %q missing", id)
			}
			if found.Result.Status != StatusBad {
				t.Errorf("rule %q = %s, want bad", id, found.Result.Status)
			}
		}
	})

	t.Run("dso passes pie rule", func(t *testing.T) {
		path := writeElf(t, elfgen.Layout{Name: "x", ETDyn: true, DynSyms: []string{"a"}})
		s := Compliance(CheckFile(path))
		for _, it := range s.Items {
			if it.ID == "pie" && it.Result.Status != StatusGood {
				t.Errorf("DSO pie rule = %s, want good", it.Result.Status)
			}
		}
	})
}

func TestCheckFileErrors(t *testing.T) {
	// Nonexistent file: every check present, error recorded.
	r := CheckFile(filepath.Join(t.TempDir(), "missing.elf"))
	if r.Error == "" {
		t.Error("expected an error for a missing file")
	}
	for _, k := range CheckOrder {
		if _, ok := r.Checks[k]; !ok {
			t.Errorf("check %q missing from report", k)
		}
	}

	// Non-ELF file.
	p := filepath.Join(t.TempDir(), "text.txt")
	os.WriteFile(p, []byte("not an elf"), 0o644)
	r = CheckFile(p)
	if r.Error == "" {
		t.Error("expected an error for a non-ELF file")
	}
}

func TestBaseSymbolName(t *testing.T) {
	cases := map[string]string{
		"memcpy@@GLIBC_2.14": "memcpy",
		"__memcpy_chk":       "__memcpy_chk",
		"strcpy@GLIBC_2.3.4": "strcpy",
		"plain":              "plain",
	}
	for in, want := range cases {
		if got := baseSymbolName(in); got != want {
			t.Errorf("baseSymbolName(%q) = %q, want %q", in, got, want)
		}
	}
}
