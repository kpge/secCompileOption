package checksec

import "debug/elf"

// RELRO checks for relocation read-only protection.
//
//   - Full RELRO: PT_GNU_RELRO present AND the linker resolves all symbols at
//     load time (DT_BIND_NOW, DF_BIND_NOW in DT_FLAGS, or DF_1_NOW in
//     DT_FLAGS_1, depending on the toolchain that produced the binary).
//   - Partial RELRO: PT_GNU_RELRO present but lazy binding still on — the
//     .got.plt stays writable and is a classic overwrite target.
//   - No RELRO: no PT_GNU_RELRO segment at all.
func RELRO(f *elf.File) Result {
	if f == nil || len(f.Progs) == 0 {
		return NA("N/A")
	}

	bindNow := false
	if v, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(v) > 0 {
		// A present DT_BIND_NOW means bind-now regardless of d_val (the
		// value is unused per the ELF ABI).
		bindNow = true
	}
	if !bindNow {
		if v, err := f.DynValue(elf.DT_FLAGS); err == nil && len(v) > 0 {
			bindNow = v[0]&uint64(elf.DF_BIND_NOW) != 0
		}
	}
	if !bindNow {
		if v, err := f.DynValue(elf.DT_FLAGS_1); err == nil && len(v) > 0 {
			bindNow = v[0]&uint64(elf.DF_1_NOW) != 0
		}
	}
	// Stripped binaries may lack section headers; fall back to a raw
	// PT_DYNAMIC scan before concluding lazy binding.
	if !bindNow {
		dyns := parsePTDynamic(f)
		if _, ok := dynValuePH(dyns, elf.DT_BIND_NOW); ok {
			bindNow = true
		} else if v, ok := dynValuePH(dyns, elf.DT_FLAGS); ok {
			bindNow = v&uint64(elf.DF_BIND_NOW) != 0
		} else if v, ok := dynValuePH(dyns, elf.DT_FLAGS_1); ok {
			bindNow = v&uint64(elf.DF_1_NOW) != 0
		}
	}

	hasRelroSeg := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			hasRelroSeg = true
			break
		}
	}

	switch {
	case bindNow:
		return OK("Full RELRO")
	case hasRelroSeg:
		return Warn("Partial RELRO")
	default:
		return Bad("No RELRO")
	}
}
