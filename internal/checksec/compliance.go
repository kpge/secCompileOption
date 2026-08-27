package checksec

// Compliance maps each check result onto the CANN secure-compile
// specification (contributor/coding-standards/SecureCompile(C&C++).md).
// That spec's seven binary-level requirements, all marked 要求 (required):
//
//  1. PIE for executables / PIC for shared libraries (-fPIE -pie / -fPIC)
//  2. Stack protector (-fstack-protector-all/-strong)
//  3. RELRO (-Wl,-z,relro at minimum)
//  4. Immediate binding (-Wl,-z,now)
//  5. Non-executable stack (-Wl,-z,noexecstack)
//  6. Stripped symbols (-s / strip)
//  7. No rpath (prohibited)
//
// (The spec's ASLR item is a runtime sysctl, not a binary property, so it
// is out of scope here.) ComplianceItem is the per-requirement verdict;
// ComplianceSummary rolls them up per binary.

// ComplianceItem is one spec requirement's verdict for one binary.
type ComplianceItem struct {
	ID      string `json:"id"`      // short key, e.g. "pie"
	Name    string `json:"name"`    // human-readable requirement name
	Require string `json:"require"` // what the spec asks for
	Result  Result `json:"result"`  // pass/fail/na verdict
}

// ComplianceSummary is the per-binary spec compliance rollup.
type ComplianceSummary struct {
	Name  string           `json:"name"`
	Pass  int              `json:"pass"`
	Fail  int              `json:"fail"`
	NA    int              `json:"n/a"` // not applicable (e.g. PIE on a DSO)
	Items []ComplianceItem `json:"items"`
}

// complianceRule binds a spec requirement to the check verdict it maps to.
type complianceRule struct {
	id      string
	name    string
	require string
	// verdict derives the compliance Result from the binary's checks.
	verdict func(r FileReport) Result
}

var complianceRules = []complianceRule{
	{
		id: "pie", name: "Position independent", require: "-fPIE -pie (executables) / -fPIC (shared libraries)",
		verdict: func(r FileReport) Result {
			pie := r.Checks["pie"]
			switch pie.Value {
			case "PIE enabled", "Static PIE":
				return OK("pass")
			case "DSO (shared library)":
				// A shared object is position independent by construction
				// (ET_DYN), unless it carries text relocations — the PIC
				// check catches that case.
				if r.Checks["pic"].Status == StatusBad {
					return Bad("fail (text relocations)")
				}
				return OK("pass")
			case "REL (relocatable object)":
				return NA("n/a (object file)")
			default:
				return Bad("fail")
			}
		},
	},
	{
		id: "stack_protector", name: "Stack protector", require: "-fstack-protector-all / -strong, or ohos_retguard / PAC CFI (AArch64)",
		verdict: func(r FileReport) Result {
			if StackProtectionPassed(r) {
				return OK("pass")
			}
			return Bad("fail")
		},
	},
	{
		id: "relro", name: "GOT read-only after relocation", require: "-Wl,-z,relro (partial) / -Wl,-z,relro,-z,now (full)",
		verdict: func(r FileReport) Result {
			switch r.Checks["relro"].Value {
			case "Full RELRO", "Partial RELRO":
				return OK("pass")
			case "N/A":
				return NA("n/a")
			default:
				return Bad("fail")
			}
		},
	},
	{
		id: "bind_now", name: "Immediate binding", require: "-Wl,-z,now",
		verdict: func(r FileReport) Result {
			switch r.Checks["bind_now"].Value {
			case "Bind now":
				return OK("pass")
			case "error checking bind_now":
				return NA("n/a")
			default:
				return Bad("fail")
			}
		},
	},
	{
		id: "nx", name: "Non-executable stack", require: "-Wl,-z,noexecstack",
		verdict: func(r FileReport) Result {
			c := r.Checks["nx"]
			switch c.Status {
			case StatusGood:
				return OK("pass")
			case StatusWarn:
				// No GNU_STACK segment: kernel default applies, usually NX
				// on modern arches — not a confirmed violation.
				return NA("unknown (no GNU_STACK)")
			case StatusNA:
				return NA("n/a")
			default:
				return Bad("fail")
			}
		},
	},
	{
		id: "stripped", name: "Stripped symbols", require: "-s (link) or strip before release",
		verdict: func(r FileReport) Result {
			c := r.Checks["symbols"]
			switch c.Status {
			case StatusGood:
				return OK("pass")
			default:
				return Bad("fail")
			}
		},
	},
	{
		id: "no_rpath", name: "No rpath", require: "rpath prohibited (-Wl,--disable-new-dtags,--rpath must not be used)",
		verdict: func(r FileReport) Result {
			c := r.Checks["rpath"]
			switch {
			case c.Status == StatusGood:
				return OK("pass")
			case c.Status == StatusBad:
				return Bad("fail")
			default:
				return NA("n/a")
			}
		},
	},
}

// Compliance evaluates every spec rule against one report.
func Compliance(r FileReport) ComplianceSummary {
	s := ComplianceSummary{Name: r.Name}
	for _, rule := range complianceRules {
		item := ComplianceItem{
			ID:      rule.id,
			Name:    rule.name,
			Require: rule.require,
			Result:  rule.verdict(r),
		}
		switch item.Result.Status {
		case StatusGood:
			s.Pass++
		case StatusBad:
			s.Fail++
		default:
			s.NA++
		}
		s.Items = append(s.Items, item)
	}
	return s
}
