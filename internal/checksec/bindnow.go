package checksec

import "debug/elf"

// BindNow reports whether the binary resolves all dynamic symbols at load
// time (-Wl,-z,now / DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW), independent of
// whether a PT_GNU_RELRO segment exists. The secure-compile specs list
// immediate binding as its own requirement, so it needs its own verdict
// rather than being folded into RELRO.
func BindNow(f *elf.File) Result {
	if f == nil {
		return Err("bind_now")
	}
	if bindNowOf(f) {
		return OK("Bind now")
	}
	return Bad("Lazy binding")
}

// bindNowOf is the shared detection used by both RELRO (full = relro + now)
// and the standalone BindNow check.
func bindNowOf(f *elf.File) bool {
	if v, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(v) > 0 {
		// A present DT_BIND_NOW means bind-now regardless of d_val (the
		// value is unused per the ELF ABI).
		return true
	}
	if v, err := f.DynValue(elf.DT_FLAGS); err == nil && len(v) > 0 {
		if v[0]&uint64(elf.DF_BIND_NOW) != 0 {
			return true
		}
	}
	if v, err := f.DynValue(elf.DT_FLAGS_1); err == nil && len(v) > 0 {
		if v[0]&uint64(elf.DF_1_NOW) != 0 {
			return true
		}
	}
	// Stripped binaries may lack section headers; fall back to a raw
	// PT_DYNAMIC scan before concluding lazy binding.
	dyns := parsePTDynamic(f)
	if _, ok := dynValuePH(dyns, elf.DT_BIND_NOW); ok {
		return true
	}
	if v, ok := dynValuePH(dyns, elf.DT_FLAGS); ok && v&uint64(elf.DF_BIND_NOW) != 0 {
		return true
	}
	if v, ok := dynValuePH(dyns, elf.DT_FLAGS_1); ok && v&uint64(elf.DF_1_NOW) != 0 {
		return true
	}
	return false
}
