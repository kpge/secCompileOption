package checksec

import (
	"debug/elf"
	"os"
	"strings"
)

// Canary symbol-name prefixes whose presence means the binary was built with
// stack-smashing protection:
//   - __stack_chk_fail: glibc's failure handler (dynamic binaries import it)
//   - __stack_chk_guard: the guard slot itself (static/freestanding builds)
//   - __intel_security_cookie / __intel_security_check_cookie: Intel ICC
var canaryPrefixes = []string{
	"__stack_chk_fail",
	"__stack_chk_guard",
	"__intel_security_cookie",
	"__intel_security_check_cookie",
}

func isCanarySymbol(name string) bool {
	for _, p := range canaryPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Canary reports whether the binary carries stack-canary instrumentation.
// raw may be nil; when provided it enables the stripped-binary fallback that
// recovers names from the program headers.
func Canary(f *elf.File, raw *os.File) Result {
	if f == nil {
		return Err("canary")
	}
	for _, name := range allSymbolNames(f, raw) {
		if isCanarySymbol(name) {
			return OK("Canary found")
		}
	}
	return Bad("No canary found")
}
