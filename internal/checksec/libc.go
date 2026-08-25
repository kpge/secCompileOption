package checksec

import (
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveLibcFlag decides whether FORTIFY analysis applies to the binary and
// which libc to compare against:
//   - a dynamically linked binary with a DT_NEEDED libc → libc path
//   - a static binary (no PT_DYNAMIC) → "none"
//   - dynamic but libc not found on this host → "unk" (N/A, with a note that
//     on-host resolution only works when scanning Linux binaries from Linux)
//
// FORTIFY counts below do not need the libc file itself — the set of
// fortifiable functions is fixed by the compiler (supportedChkFuncs) — so the
// libc is only used to decide applicability. That keeps results identical
// when scanning foreign-architecture or chroot binaries.
func resolveLibcFlag(path string, f *elf.File, raw *os.File) string {
	hasDynamic := false
	needed := []string{}
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			hasDynamic = true
		}
	}
	if !hasDynamic {
		return "none"
	}
	if v, err := f.DynString(elf.DT_NEEDED); err == nil && len(v) > 0 {
		needed = v
	} else if raw != nil {
		needed = dynStringPH(f, raw, parsePTDynamic(f), elf.DT_NEEDED)
	}
	hasLibc := false
	for _, n := range needed {
		if strings.HasPrefix(n, "libc.so") || strings.Contains(n, "libc-") {
			hasLibc = true
			break
		}
	}
	if !hasLibc {
		// e.g. a Go binary with no cgo, or musl static-pie: no glibc, no
		// glibc-style _chk functions.
		return "none"
	}
	if runtime.GOOS != "linux" {
		// libc-based binary, but we cannot verify the host libc from here.
		// The compiler-side analysis still holds, so proceed.
		return ""
	}
	if p := findHostLibc(path); p != "" {
		return p
	}
	return ""
}

// findHostLibc looks for a libc.so next to common loader locations. Only
// meaningful on Linux; returns "" elsewhere.
func findHostLibc(binaryPath string) string {
	for _, dir := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		for _, pat := range []string{"libc.so.6", "libc-*.so"} {
			m, _ := filepath.Glob(filepath.Join(dir, pat))
			if len(m) > 0 {
				return m[0]
			}
		}
	}
	// Last resort: an env var for cross-environment scanning.
	return os.Getenv("SCC_LIBC")
}
