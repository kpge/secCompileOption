package checksec

import "debug/elf"

// PIC reports whether a dynamic object is position independent.
//
// A shared library (or PIE) may be loaded at any address; text relocations
// break that by forcing the code segment to be patched at load time. The
// dynamic section records them as DT_TEXTREL, or as DF_TEXTREL in DT_FLAGS
// (the gABI deprecates DT_TEXTREL in favour of DF_TEXTREL, so linkers may
// emit either or both). Only ET_DYN objects carry this property: an ET_EXEC
// executable is fixed-address by design (the PIE check covers executables)
// and an ET_REL object has no dynamic section.
func PIC(f *elf.File) Result {
	if f == nil {
		return Err("pic")
	}
	if f.Type != elf.ET_DYN {
		return NA("N/A")
	}
	dyns := parsePTDynamic(f)
	if _, ok := dynTag(dyns, elf.DT_TEXTREL); ok {
		return Bad("Text relocations (not PIC)")
	}
	if v, ok := dynValuePH(dyns, elf.DT_FLAGS); ok && v&uint64(elf.DF_TEXTREL) != 0 {
		return Bad("Text relocations (not PIC)")
	}
	return OK("PIC enabled (no text relocations)")
}
