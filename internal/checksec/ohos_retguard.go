package checksec

import "debug/elf"

// retguardSegmentType is the OpenHarmony custom program-header type that
// marks a retguard-protected object.
const retguardSegmentType = elf.ProgType(0x6788FC60)

// OhosRetguard reports whether the binary carries OpenHarmony retguard
// protection, an in-house alternative to the stack canary. It is only
// meaningful on AArch64, where the compiler emits either a
// .ohos.randomdata section or a RETGUARD_TYPE program header — the two
// signals cover section-stripped binaries too (program headers survive).
func OhosRetguard(f *elf.File) Result {
	if f == nil {
		return Err("ohos_retguard")
	}
	if f.Machine != elf.EM_AARCH64 {
		return NA("N/A (not AArch64)")
	}
	if f.Section(".ohos.randomdata") != nil {
		return OK("Retguard enabled")
	}
	for _, p := range f.Progs {
		if p.Type == retguardSegmentType {
			return OK("Retguard enabled")
		}
	}
	return Bad("No retguard")
}
