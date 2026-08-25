package checksec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// This file contains helpers that read ELF structures straight from the
// program headers. They matter for stripped binaries: when the section header
// table is removed, debug/elf's section-based APIs (Symbols, DynamicSymbols,
// DynValue, DynString) find nothing, but PT_DYNAMIC / PT_LOAD and the dynamic
// symbol table they point at are still present and loadable.

// dynEntry is one (d_tag, d_val) pair read from a raw PT_DYNAMIC payload.
type dynEntry struct {
	tag elf.DynTag
	val uint64
}

// parsePTDynamic scans every PT_DYNAMIC segment and returns its entries.
// Truncated trailing entries are ignored.
func parsePTDynamic(f *elf.File) []dynEntry {
	var out []dynEntry
	for _, p := range f.Progs {
		if p.Type != elf.PT_DYNAMIC {
			continue
		}
		data := make([]byte, p.Filesz)
		if _, err := p.ReadAt(data, 0); err != nil && err != io.EOF {
			continue
		}
		out = append(out, parseDynEntries(data, f.Class, f.ByteOrder)...)
	}
	return out
}

func parseDynEntries(data []byte, class elf.Class, bo binary.ByteOrder) []dynEntry {
	var out []dynEntry
	if class == elf.ELFCLASS64 {
		for i := 0; i+16 <= len(data); i += 16 {
			tag := bo.Uint64(data[i : i+8])
			val := bo.Uint64(data[i+8 : i+16])
			if tag == uint64(elf.DT_NULL) {
				break
			}
			out = append(out, dynEntry{elf.DynTag(tag), val})
		}
	} else {
		for i := 0; i+8 <= len(data); i += 8 {
			tag := bo.Uint32(data[i : i+4])
			val := bo.Uint32(data[i+4 : i+8])
			if tag == uint32(elf.DT_NULL) {
				break
			}
			out = append(out, dynEntry{elf.DynTag(tag), uint64(val)})
		}
	}
	return out
}

// dynTag scans entries for tag and reports its value. The bool is false when
// the tag is absent.
func dynTag(dyns []dynEntry, tag elf.DynTag) (uint64, bool) {
	for _, d := range dyns {
		if d.tag == tag {
			return d.val, true
		}
	}
	return 0, false
}

// vaddrToFileOffset maps a virtual address to a file offset using the
// PT_LOAD segments. ok is false when no segment covers vaddr.
func vaddrToFileOffset(f *elf.File, vaddr uint64) (int64, bool) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Filesz {
			return int64(vaddr - p.Vaddr + p.Off), true
		}
	}
	return 0, false
}

// dynamicStrings returns the raw bytes of the dynamic string table
// (DT_STRTAB..DT_STRSZ) using only program headers.
func dynamicStrings(f *elf.File, raw *os.File, dyns []dynEntry) ([]byte, bool) {
	strtab, ok := dynTag(dyns, elf.DT_STRTAB)
	if !ok {
		return nil, false
	}
	strsz, ok := dynTag(dyns, elf.DT_STRSZ)
	if !ok || strsz == 0 || strsz > 1<<24 {
		return nil, false
	}
	off, ok := vaddrToFileOffset(f, strtab)
	if !ok {
		return nil, false
	}
	buf := make([]byte, strsz)
	if _, err := raw.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, false
	}
	return buf, true
}

// dynStringPH resolves a string-valued dynamic tag (e.g. DT_RPATH) from the
// program headers alone. Multiple entries are all returned.
func dynStringPH(f *elf.File, raw *os.File, dyns []dynEntry, tag elf.DynTag) []string {
	str, ok := dynamicStrings(f, raw, dyns)
	if !ok {
		return nil
	}
	var out []string
	for _, d := range dyns {
		if d.tag != tag {
			continue
		}
		if s, ok := cstrAt(str, d.val); ok {
			out = append(out, s)
		}
	}
	return out
}

// cstrAt reads the NUL-terminated string at offset off in a string table.
func cstrAt(str []byte, off uint64) (string, bool) {
	if off >= uint64(len(str)) {
		return "", false
	}
	end := bytes.IndexByte(str[off:], 0)
	if end < 0 {
		return string(str[off:]), true // unterminated: take the rest
	}
	return string(str[off : off+uint64(end)]), true
}

// dynValuePH resolves an integer-valued dynamic tag from program headers.
func dynValuePH(dyns []dynEntry, tag elf.DynTag) (uint64, bool) {
	return dynTag(dyns, tag)
}

// phdrSymbolNames reads all STT_FUNC symbol names from the dynamic symbol
// table using only program headers (DT_SYMTAB/DT_STRTAB/DT_SYMENT). This is
// the fallback for stripped binaries with no section headers.
func phdrSymbolNames(f *elf.File, raw *os.File) []string {
	dyns := parsePTDynamic(f)
	symtab, ok := dynTag(dyns, elf.DT_SYMTAB)
	if !ok {
		return nil
	}
	str, ok := dynamicStrings(f, raw, dyns)
	if !ok {
		return nil
	}
	syment, ok := dynTag(dyns, elf.DT_SYMENT)
	if !ok || syment == 0 {
		if f.Class == elf.ELFCLASS32 {
			syment = 16 // sizeof(Elf32_Sym)
		} else {
			syment = 24 // sizeof(Elf64_Sym)
		}
	}

	symOff, ok := vaddrToFileOffset(f, symtab)
	if !ok {
		return nil
	}

	// The dynamic section does not record the symbol count. Bound the table
	// by the end of the PT_LOAD segment covering symtab.
	var limit int64
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if symtab >= p.Vaddr && symtab < p.Vaddr+p.Filesz {
			limit = int64(p.Vaddr + p.Filesz - symtab)
			break
		}
	}
	if limit <= 0 {
		limit = 1 << 20
	}
	if limit > 1<<24 { // sanity cap: 16M of symbols is plenty
		limit = 1 << 24
	}

	var names []string
	for off := int64(0); off+int64(syment) <= limit; off += int64(syment) {
		var buf [24]byte
		n := int64(syment)
		if n > int64(len(buf)) {
			n = int64(len(buf))
		}
		if _, err := raw.ReadAt(buf[:n], symOff+off); err != nil {
			break
		}
		var nameOff uint64
		var info byte
		if f.Class == elf.ELFCLASS64 {
			nameOff = uint64(f.ByteOrder.Uint32(buf[0:4]))
			info = buf[4]
		} else {
			nameOff = uint64(f.ByteOrder.Uint32(buf[0:4]))
			info = buf[12]
		}
		if elf.SymType(info&0x0f) != elf.STT_FUNC {
			continue
		}
		if s, ok := cstrAt(str, nameOff); ok && s != "" {
			names = append(names, s)
		}
	}
	return names
}

// allSymbolNames returns every symbol name the binary advertises: full
// symbol table, dynamic symbols, and — as a stripped-binary fallback — names
// recovered from the program headers.
func allSymbolNames(f *elf.File, raw *os.File) []string {
	seen := map[string]bool{}
	var names []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			add(s.Name)
		}
	}
	if dyn, err := f.DynamicSymbols(); err == nil {
		for _, s := range dyn {
			add(s.Name)
		}
	}
	if raw != nil {
		for _, n := range phdrSymbolNames(f, raw) {
			add(n)
		}
	}
	return names
}

// importedNames returns dynamic symbol names (imports + defined dynsyms).
// Fortify and canary detection match against these for dynamically linked
// binaries.
func importedNames(f *elf.File) []string {
	var names []string
	dyn, err := f.DynamicSymbols()
	if err != nil {
		return names
	}
	for _, s := range dyn {
		if s.Name != "" {
			names = append(names, s.Name)
		}
	}
	return names
}

// ensure fmt stays referenced even if helpers above change.
var _ = fmt.Sprintf
