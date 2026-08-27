package checksec

import (
	"bytes"
	"debug/elf"
)

// pacibspEncoding is the AArch64 pacibsp instruction (ARMv8.3-A pointer
// authentication of the return address against SP), 0xD503237F in memory
// (little-endian) byte order.
var pacibspEncoding = []byte{0x7f, 0x23, 0x03, 0xd5}

// PacCFI reports whether the binary was compiled with AArch64 pointer
// authentication call-frame protection, an in-house alternative to the
// stack canary. It is detected by the pacibsp instruction in .text and is
// only meaningful on AArch64. When section headers are stripped, the code
// is still reachable through the executable PT_LOAD segments, so they are
// scanned as a fallback.
func PacCFI(f *elf.File) Result {
	if f == nil {
		return Err("pac_cfi")
	}
	if f.Machine != elf.EM_AARCH64 {
		return NA("N/A (not AArch64)")
	}
	if sec := f.Section(".text"); sec != nil {
		if data, err := sec.Data(); err == nil {
			if bytes.Contains(data, pacibspEncoding) {
				return OK("PAC CFI enabled")
			}
			return Bad("No PAC CFI")
		}
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		data := make([]byte, p.Filesz)
		if _, err := p.ReadAt(data, 0); err == nil && bytes.Contains(data, pacibspEncoding) {
			return OK("PAC CFI enabled")
		}
	}
	return Bad("No PAC CFI")
}
