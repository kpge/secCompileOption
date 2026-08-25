package checksec

import "debug/elf"

// PIE classifies position independence.
//
// ET_DYN alone does not mean PIE — every shared library is ET_DYN too. A PIE
// executable is distinguished by DF_1_PIE (modern toolchains) or by having a
// program interpreter (it is executed directly rather than dlopen'd).
func PIE(f *elf.File) Result {
	if f == nil {
		return Err("PIE")
	}

	hasInterp := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			hasInterp = true
			break
		}
	}

	var flags1 uint64
	if v, err := f.DynValue(elf.DT_FLAGS_1); err == nil && len(v) > 0 {
		flags1 = v[0]
	} else if dyns := parsePTDynamic(f); len(dyns) > 0 {
		if v, ok := dynValuePH(dyns, elf.DT_FLAGS_1); ok {
			flags1 = v
		}
	}
	hasPIEFlag := flags1&uint64(elf.DF_1_PIE) != 0

	switch f.Type {
	case elf.ET_DYN:
		switch {
		case hasPIEFlag && !hasInterp:
			return OK("Static PIE") // gcc/clang --static-pie: self-relocating
		case hasPIEFlag, hasInterp:
			return OK("PIE enabled")
		default:
			return Info("DSO (shared library)")
		}
	case elf.ET_REL:
		return Warn("REL (relocatable object)")
	default:
		return Bad("PIE disabled")
	}
}
