// Package elfgen builds minimal synthetic ELF binaries with selectable
// hardening features, for testing secCompileCheck without a Linux toolchain.
//
// Each generated file is a structurally valid ELF64 x86-64 executable: real
// ELF header, program headers, and — where the feature needs it — a dynamic
// section, dynamic symbol/string tables, and a GNU_STACK segment. Nothing is
// meant to be executed; the goal is to exercise the checker's parsing paths.
package elfgen

import (
	"debug/elf"
	"encoding/binary"
)

// layout describes the segments to emit for one test binary.
type Layout struct {
	Name         string
	Pie          bool     // ET_DYN + PT_INTERP + DF_1_PIE
	ETDyn        bool     // ET_DYN without PT_INTERP (shared object style)
	Interp       bool     // PT_INTERP present
	GnuStackX    bool     // PT_GNU_STACK with PF_X
	NoStack      bool     // omit PT_GNU_STACK entirely
	Relro        bool     // PT_GNU_RELRO present
	BindNow      bool     // DT_BIND_NOW entry present
	Flags1Pie    bool     // DF_1_PIE in DT_FLAGS_1
	FlagsBind    bool     // DF_BIND_NOW in DT_FLAGS
	TextRel      bool     // DT_TEXTREL entry present (text relocations)
	FlagsTextRel bool     // DF_TEXTREL in DT_FLAGS
	Rpath        []string // DT_RPATH entries
	Runpath      []string // DT_RUNPATH entries
	DynSyms      []string // dynamic symbol names (imports)
}

const (
	// Synthetic addresses; nothing is loaded, they just need to be mapped
	// consistently by PT_LOAD for vaddr→offset translation.
	baseVaddr = 0x400000
)

func u16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func u32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func u64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

type section struct {
	data   []byte
	vaddr  uint64
	offset uint64
}

// build assembles the ELF image for one layout.
func Build(l Layout) []byte {
	le := binary.LittleEndian

	// ---- content blobs -------------------------------------------------

	// dynstr: "\0" + names
	var strBuf []byte
	strBuf = append(strBuf, 0)
	strOff := func(s string) uint32 {
		off := uint32(len(strBuf))
		strBuf = append(strBuf, s...)
		strBuf = append(strBuf, 0)
		return off
	}
	var dynSymNames []uint32 // string offsets of dynsyms

	// Reserve all dynamic string-table slots up front (dynsym names,
	// NEEDED, RPATH, RUNPATH) so offsets are stable when the dynamic
	// section is emitted.
	for _, s := range l.DynSyms {
		dynSymNames = append(dynSymNames, strOff(s))
	}
	neededOff := -1
	if len(l.DynSyms) > 0 {
		neededOff = int(strOff("libc.so.6"))
	}

	rpathStr := ""
	for _, r := range l.Rpath {
		if rpathStr != "" {
			rpathStr += ":"
		}
		rpathStr += r
	}
	runpathStr := ""
	for _, r := range l.Runpath {
		if runpathStr != "" {
			runpathStr += ":"
		}
		runpathStr += r
	}
	// Reserve string-table slots for RPATH/RUNPATH before the dynamic
	// section is emitted so their offsets are stable.
	rpathOff := -1
	runpathOff := -1
	if rpathStr != "" {
		rpathOff = int(strOff(rpathStr))
	}
	if runpathStr != "" {
		runpathOff = int(strOff(runpathStr))
	}

	// ---- program headers (computed after we know sizes) ---------------

	// Build order: ehdr(64) | phdrs | blob (interp, dynamic, dynsym,
	// dynstr, gnu_stack is header-only, relro seg is a PT_LOAD region)

	phdrCount := 1 // PT_LOAD for the whole file
	if l.Interp || l.Pie {
		phdrCount++
	}
	hasDyn := len(dynSymNames) > 0 || l.BindNow || l.Flags1Pie || l.FlagsBind || l.TextRel || l.FlagsTextRel || rpathStr != "" || runpathStr != ""
	// tmpDyn always ends with a DT_NULL terminator, so a dynamic section
	// exists whenever any dynamic entry is wanted.
	if hasDyn {
		phdrCount++ // PT_DYNAMIC
	}
	if l.Relro {
		phdrCount++
	}
	if !l.NoStack {
		phdrCount++
	}

	ehdrLen := 64
	phdrLen := phdrCount * 56
	headerLen := ehdrLen + phdrLen

	// dynamic section content (we need its size before placing)
	var tmpDyn [][2]uint64
	if len(dynSymNames) > 0 {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_NEEDED), 0})
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_SYMTAB), 0}) // patched later
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_STRTAB), 0})
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_STRSZ), 0})
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_SYMENT), 24})
	}
	if rpathStr != "" {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_RPATH), 0})
	}
	if runpathStr != "" {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_RUNPATH), 0})
	}
	if l.BindNow {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_BIND_NOW), 0})
	}
	if l.TextRel {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_TEXTREL), 0})
	}
	var flagsVal uint64
	if l.FlagsBind {
		flagsVal |= uint64(elf.DF_BIND_NOW)
	}
	if l.FlagsTextRel {
		flagsVal |= uint64(elf.DF_TEXTREL)
	}
	if flagsVal != 0 {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_FLAGS), flagsVal})
	}
	if l.Flags1Pie {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_FLAGS_1), uint64(elf.DF_1_PIE)})
	}
	if len(tmpDyn) > 0 {
		tmpDyn = append(tmpDyn, [2]uint64{uint64(elf.DT_NULL), 0})
	}

	dynLen := len(tmpDyn) * 16
	symLen := len(dynSymNames) * 24
	interp := "/lib64/ld-linux-x86-64.so.2\x00"
	if !l.Interp && !l.Pie {
		interp = ""
	}

	// file layout
	off := headerLen
	var interpSec, dynSec, symSec, strSec section
	if interp != "" {
		interpSec = section{[]byte(interp), 0, uint64(off)}
		off += len(interp)
		off = (off + 7) &^ 7
	}
	if dynLen > 0 {
		dynSec = section{make([]byte, dynLen), 0, uint64(off)}
		off += dynLen
		off = (off + 7) &^ 7
	}
	if symLen > 0 {
		symSec = section{make([]byte, symLen), 0, uint64(off)}
		off += symLen
		off = (off + 7) &^ 7
	}
	strSec = section{strBuf, 0, uint64(off)}
	off += len(strBuf)
	off = (off + 7) &^ 7

	totalLen := off
	buf := make([]byte, totalLen)

	// ---- ELF header ----------------------------------------------------
	e := elf.ELFCLASS64
	_ = e
	copy(buf[0:4], "\x7fELF")
	buf[4] = 2 // 64-bit
	buf[5] = 1 // little endian
	buf[6] = 1 // version
	u16(buf, 16, uint16(elf.ET_EXEC))
	if l.Pie || l.ETDyn {
		u16(buf, 16, uint16(elf.ET_DYN))
	}
	u16(buf, 18, uint16(elf.EM_X86_64))
	u32(buf, 20, 1)               // EV_CURRENT
	u64(buf, 24, baseVaddr)       // entry
	u64(buf, 32, uint64(ehdrLen)) // phoff
	u64(buf, 40, 0)               // shoff: none (stripped-style)
	u32(buf, 48, 64)              // flags
	u16(buf, 52, 64)              // ehsize
	u16(buf, 54, 56)              // phentsize
	u16(buf, 56, uint16(phdrCount))
	u16(buf, 58, 0) // shentsize
	u16(buf, 60, 0) // shnum
	u16(buf, 62, 0) // shstrndx

	// ---- section contents ----------------------------------------------

	// dynsym: Elf64_Sym is {name(4), info(1), other(1), shndx(2), value(8), size(8)}
	for i, nameOff := range dynSymNames {
		b := symSec.data[i*24:]
		u32(b, 0, nameOff)
		b[4] = 0x12  // STB_GLOBAL<<4 | STT_FUNC
		u16(b, 6, 0) // SHN_UNDEF
	}

	// dynamic: patch addresses now that offsets are known
	vaddrOf := func(s section) uint64 { return baseVaddr + s.offset }
	di := 0
	writeDyn := func(tag elf.DynTag, val uint64) {
		u64(dynSec.data, di*16, uint64(tag))
		u64(dynSec.data, di*16+8, val)
		di++
	}
	for _, ent := range tmpDyn {
		tag := elf.DynTag(ent[0])
		switch tag {
		case elf.DT_NEEDED:
			writeDyn(tag, uint64(neededOff))
		case elf.DT_SYMTAB:
			writeDyn(tag, vaddrOf(symSec))
		case elf.DT_STRTAB:
			writeDyn(tag, vaddrOf(strSec))
		case elf.DT_STRSZ:
			writeDyn(tag, uint64(len(strBuf)))
		case elf.DT_RPATH:
			writeDyn(tag, uint64(rpathOff))
		case elf.DT_RUNPATH:
			writeDyn(tag, uint64(runpathOff))
		case elf.DT_BIND_NOW:
			writeDyn(tag, 0)
		default:
			writeDyn(tag, ent[1])
		}
	}

	if interpSec.data != nil {
		copy(buf[interpSec.offset:], interpSec.data)
	}
	if dynSec.data != nil {
		copy(buf[dynSec.offset:], dynSec.data)
	}
	if symSec.data != nil {
		copy(buf[symSec.offset:], symSec.data)
	}
	copy(buf[strSec.offset:], strSec.data)

	// ---- program headers -----------------------------------------------

	ph := make([]byte, phdrLen)
	pi := 0
	writePh := func(typ elf.ProgType, flags elf.ProgFlag, off, vaddr, filesz, memsz uint64) {
		b := ph[pi*56:]
		u32(b, 0, uint32(typ))
		u32(b, 4, uint32(flags))
		u64(b, 8, off)
		u64(b, 16, vaddr)
		u64(b, 24, vaddr) // paddr
		u64(b, 32, filesz)
		u64(b, 40, memsz)
		u64(b, 48, 0x1000) // align
		pi++
	}

	// PT_LOAD over the whole file
	writePh(elf.PT_LOAD, elf.PF_R|elf.PF_X, 0, baseVaddr, uint64(totalLen), uint64(totalLen))
	if interpSec.data != nil {
		writePh(elf.PT_INTERP, elf.PF_R, interpSec.offset, vaddrOf(interpSec), uint64(len(interpSec.data)), uint64(len(interpSec.data)))
	}
	if dynSec.data != nil {
		writePh(elf.PT_DYNAMIC, elf.PF_R|elf.PF_W, dynSec.offset, vaddrOf(dynSec), uint64(dynLen), uint64(dynLen))
	}
	if l.Relro {
		// A GNU_RELRO region at the end of the loadable image.
		writePh(elf.PT_GNU_RELRO, elf.PF_R, 0, baseVaddr, uint64(totalLen), uint64(totalLen))
	}
	if !l.NoStack {
		flags := elf.PF_R | elf.PF_W
		if l.GnuStackX {
			flags |= elf.PF_X
		}
		writePh(elf.PT_GNU_STACK, flags, 0, 0, 0, 0)
	}
	copy(buf[ehdrLen:], ph)

	_ = le
	return buf
}
