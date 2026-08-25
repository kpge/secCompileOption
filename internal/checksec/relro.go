package checksec

import "debug/elf"

// RELRO checks for relocation read-only protection.
//
//   - Full RELRO: PT_GNU_RELRO present AND immediate binding (-z now) —
//     the whole GOT is resolved at load and made read-only.
//   - Partial RELRO: PT_GNU_RELRO present but lazy binding still on — the
//     .got.plt stays writable and is a classic overwrite target.
//   - No RELRO: no PT_GNU_RELRO segment at all.
//
// The bind-now half is also reported independently by BindNow, since the
// secure-compile specs list immediate binding as its own requirement.
func RELRO(f *elf.File) Result {
	if f == nil || len(f.Progs) == 0 {
		return NA("N/A")
	}

	hasRelroSeg := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			hasRelroSeg = true
			break
		}
	}

	switch {
	case hasRelroSeg && bindNowOf(f):
		return OK("Full RELRO")
	case hasRelroSeg:
		return Warn("Partial RELRO")
	default:
		return Bad("No RELRO")
	}
}
