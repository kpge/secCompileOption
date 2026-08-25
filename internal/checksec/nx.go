package checksec

import "debug/elf"

// NX checks the PT_GNU_STACK program header for the no-executable-stack bit.
//
//   - PT_GNU_STACK without PF_X → NX enabled
//   - PT_GNU_STACK with PF_X    → NX explicitly disabled (stack is RWX)
//   - no PT_GNU_STACK           → kernel default applies (usually NX on
//     modern x86-64/arm64, but it is architecture dependent, so warn)
func NX(f *elf.File) Result {
	if f == nil {
		return Err("NX")
	}
	var gnuStack *elf.Prog
	for i, p := range f.Progs {
		if i > 10000 {
			return Err("NX") // defensive: absurd header count
		}
		if p != nil && p.Type == elf.PT_GNU_STACK {
			gnuStack = p
			break
		}
	}
	switch {
	case gnuStack == nil:
		return Warn("NX unknown (no GNU_STACK)")
	case gnuStack.Flags&elf.PF_X == 0:
		return OK("NX enabled")
	default:
		return Bad("NX disabled")
	}
}
