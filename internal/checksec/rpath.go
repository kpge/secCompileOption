package checksec

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

// runpathRisk classifies a single RPATH/RUNPATH entry. The security question
// is whether an attacker can influence where shared libraries are loaded
// from.
type runpathRisk int

const (
	rpSafe     runpathRisk = iota // absolute, exists, not world-writable
	rpWarn                        // $ORIGIN-relative or nonexistent: depends on deployment
	rpInsecure                    // relative path / empty (= cwd) / world-writable
)

// classifyRunpathEntry evaluates one colon-separated entry against the host
// filesystem. On a non-Linux host (e.g. scanning a Linux binary from
// Windows), every absolute path reads as nonexistent → warn, which is honest:
// the risk cannot be judged off-host.
func classifyRunpathEntry(entry string) (runpathRisk, string) {
	switch {
	case entry == "":
		return rpInsecure, "empty entry = cwd"
	case strings.Contains(entry, "$ORIGIN"), strings.Contains(entry, "${ORIGIN}"):
		return rpWarn, "$ORIGIN-relative"
	case !strings.HasPrefix(entry, "/"):
		return rpInsecure, "relative path"
	}
	fi, err := os.Stat(entry)
	if err != nil {
		return rpWarn, "dir not found on this host"
	}
	if fi.IsDir() && fi.Mode().Perm()&0o002 != 0 {
		return rpInsecure, "world-writable"
	}
	return rpSafe, ""
}

// summarizeRunpath collapses the DT_RPATH/DT_RUNPATH strings into one Result.
// RPATH entries are judged against the secure-compile specs, which PROHIBIT
// rpath outright (any rpath is a violation); RUNPATH entries keep the
// risk grading since the specs only forbid the old-style tag. The Value
// still carries the per-entry reason for diagnosis.
func summarizeRunpath(label string, paths []string) Result {
	if len(paths) == 0 {
		return OK("No " + label)
	}
	worst := rpSafe
	worstReason := ""
	var entries []string
	for _, p := range paths {
		for _, e := range strings.Split(p, ":") {
			entries = append(entries, e)
			if r, reason := classifyRunpathEntry(e); r > worst {
				worst, worstReason = r, reason
			}
		}
	}
	joined := strings.Join(entries, ":")
	switch worst {
	case rpInsecure:
		return Bad(fmt.Sprintf("%s [%s] (%s)", label, joined, worstReason))
	case rpWarn:
		return Warn(fmt.Sprintf("%s [%s] (%s)", label, joined, worstReason))
	default:
		return Info(fmt.Sprintf("%s [%s]", label, joined))
	}
}

func dynamicStringsFor(f *elf.File, raw *os.File, tag elf.DynTag) []string {
	if v, err := f.DynString(tag); err == nil && len(v) > 0 {
		return v
	}
	return dynStringPH(f, raw, parsePTDynamic(f), tag)
}

// RPATH checks DT_RPATH. Secure-compile specs prohibit rpath entirely
// (writable rpath dirs enable same-name library substitution), so any
// DT_RPATH entry is a violation regardless of how safe the path looks.
// The per-entry reason is still shown for diagnosis.
func RPATH(f *elf.File, raw *os.File) Result {
	if f == nil {
		return Err("RPATH")
	}
	return summarizeRpathStrict(dynamicStringsFor(f, raw, elf.DT_RPATH))
}

// summarizeRpathStrict reports any DT_RPATH presence as bad, per the
// spec-level prohibition.
func summarizeRpathStrict(paths []string) Result {
	if len(paths) == 0 {
		return OK("No RPATH")
	}
	worst := rpSafe
	worstReason := ""
	var entries []string
	for _, p := range paths {
		for _, e := range strings.Split(p, ":") {
			entries = append(entries, e)
			if r, reason := classifyRunpathEntry(e); r > worst {
				worst, worstReason = r, reason
			}
		}
	}
	joined := strings.Join(entries, ":")
	if worstReason == "" {
		return Bad(fmt.Sprintf("RPATH [%s] (prohibited by secure-compile specs)", joined))
	}
	return Bad(fmt.Sprintf("RPATH [%s] (prohibited; %s)", joined, worstReason))
}

// RUNPATH checks DT_RUNPATH. Applies only to the binary itself and is
// overridden by LD_LIBRARY_PATH, so it is risk-graded rather than
// prohibited outright.
func RUNPATH(f *elf.File, raw *os.File) Result {
	if f == nil {
		return Err("RUNPATH")
	}
	return summarizeRunpath("RUNPATH", dynamicStringsFor(f, raw, elf.DT_RUNPATH))
}
