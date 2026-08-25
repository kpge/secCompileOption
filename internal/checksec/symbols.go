package checksec

import (
	"debug/elf"
	"fmt"
	"os"
)

// Symbols reports whether the binary retains a static symbol table
// (.symtab), i.e. whether it was shipped unstripped. Symbols are not a
// compile-time hardening per se, but a stripped binary gives an attacker
// far less reconnaissance material.
//
// Only .symtab counts: .dynsym is required for dynamic linking and is
// present in every dynamically linked binary, stripped or not — judging by
// it would flag every stripped executable as unstripped. (checksec behaves
// the same: readelf --syms, which reads .symtab only.)
func Symbols(f *elf.File, raw *os.File) Result {
	if f == nil {
		return Err("symbols")
	}
	if syms, err := f.Symbols(); err == nil && len(syms) > 0 {
		return Bad(fmt.Sprintf("%d symbols", len(syms)))
	}
	return OK("No symbols (stripped)")
}
