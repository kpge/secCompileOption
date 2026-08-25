package checksec

import (
	"debug/elf"
	"fmt"
	"os"
)

// Symbols reports whether the binary retains a symbol table (i.e. was shipped
// unstripped). Symbols are not a compile-time hardening per se, but a
// stripped binary gives an attacker far less reconnaissance material.
func Symbols(f *elf.File, raw *os.File) Result {
	if f == nil {
		return Err("symbols")
	}
	if syms, err := f.Symbols(); err == nil && len(syms) > 0 {
		return Bad(fmt.Sprintf("%d symbols", len(syms)))
	}
	if raw != nil {
		// Even with section headers gone, .dynsym may still name exports.
		if dyn, err := f.DynamicSymbols(); err == nil && len(dyn) > 0 {
			return Bad(fmt.Sprintf("%d dynsyms", len(dyn)))
		}
	}
	return OK("No symbols (stripped)")
}
