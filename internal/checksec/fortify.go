package checksec

import (
	"debug/elf"
	"os"
	"sort"
	"strconv"
	"strings"
)

// supportedChkFuncs are the glibc _FORTIFY_SOURCE checkable functions the
// compiler can emit (gcc builtins.def / clang), cross-checked against glibc
// 2.35's FORTIFY headers. This list is the fortifiable-function UNIVERSE
// used to derive base names for the fortifiable metric — the fortified
// detection itself is pattern-based (isFortifyChkName) and needs no list.
// Anything outside this universe is not attributed to fortify coverage.
var supportedChkFuncs = []string{
	// memory copy / fill
	"__memcpy_chk", "__memmove_chk", "__mempcpy_chk", "__memset_chk",
	"__memccpy_chk", "__explicit_bzero_chk",
	// string ops
	"__stpcpy_chk", "__stpncpy_chk", "__strcat_chk", "__strcpy_chk",
	"__strncat_chk", "__strncpy_chk", "__strlen_chk",
	"__strlcat_chk", "__strlcpy_chk",
	// formatted output
	"__snprintf_chk", "__sprintf_chk",
	"__vsnprintf_chk", "__vsprintf_chk", "__fprintf_chk", "__printf_chk",
	"__vfprintf_chk", "__vprintf_chk",
	"__asprintf_chk", "__vasprintf_chk",
	"__dprintf_chk", "__vdprintf_chk",
	"__syslog_chk", "__vsyslog_chk",
	"__obstack_printf_chk", "__obstack_vprintf_chk",
	// wide / multibyte
	"__fwprintf_chk", "__vfwprintf_chk", "__wprintf_chk", "__vwprintf_chk",
	"__swprintf_chk", "__vswprintf_chk",
	"__wcpcpy_chk", "__wcpncpy_chk", "__wcscat_chk", "__wcscpy_chk",
	"__wcsncat_chk", "__wcsncpy_chk",
	"__wmemcpy_chk", "__wmemmove_chk", "__wmempcpy_chk", "__wmemset_chk",
	"__wcrtomb_chk", "__wctomb_chk",
	"__mbsnrtowcs_chk", "__mbsrtowcs_chk", "__mbstowcs_chk",
	"__wcsnrtombs_chk", "__wcsrtombs_chk", "__wcstombs_chk",
	"__wdunderflow_chk",
	// stdio input
	"__gets_chk", "__fgets_chk", "__fgets_unlocked_chk",
	"__fgetws_chk", "__fgetws_unlocked_chk",
	"__fread_chk", "__fread_unlocked_chk",
	// IO / system info
	"__read_chk", "__pread_chk", "__pread64_chk",
	"__readlink_chk", "__readlinkat_chk", "__realpath_chk",
	"__recv_chk", "__recvfrom_chk", "__send_chk",
	"__poll_chk", "__ppoll_chk",
	"__confstr_chk", "__getcwd_chk", "__getdomainname_chk",
	"__getgroups_chk", "__gethostname_chk", "__getlogin_r_chk",
	"__getwd_chk", "__ptsname_r_chk", "__ttyname_r_chk",
	// setjmp/longjmp
	"__longjmp_chk",
}

func init() { sort.Strings(supportedChkFuncs) }

// isFortifyChkName reports whether a version-stripped dynamic symbol name is
// a fortified-variant name: __-prefixed and _chk- or _chkieee128-suffixed
// (the latter for IEEE long double ABIs such as powerpc64le). Pattern
// matching instead of a fixed list also covers fortify functions from other
// libcs (e.g. musl's __fd_chk for fdopen) and future glibc additions.
func isFortifyChkName(name string) bool {
	if !strings.HasPrefix(name, "__") {
		return false
	}
	return strings.HasSuffix(name, "_chk") || strings.HasSuffix(name, "_chkieee128")
}

// fortifiedChkNames returns the distinct fortified-variant symbol names the
// binary references. Every symbol table is scanned: dynamic symbols and,
// when present, the static symbol table (STT_FUNC/STT_NOTYPE only), plus
// program-header recovery for binaries whose section headers are stripped
// (STT_FUNC only — real _chk variants are functions). Static linking is
// where the .symtab matters: libc.a's baseline link pulls in no exact
// __X_chk dispatchers — its _chk-related symbols are ifunc variant
// implementations (__memcpy_chk_erms etc., suffixed by variant name) and
// __stack_chk_fail — so an exact _chk-suffixed hit is attributable to the
// application's fortify-enabled objects. Names are version-stripped and
// sorted.
func fortifiedChkNames(f *elf.File, raw *os.File) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		name := baseSymbolName(n)
		if name == "" || seen[name] || !isFortifyChkName(name) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	if dyn, err := f.DynamicSymbols(); err == nil {
		for _, s := range dyn {
			if s.Name == "" {
				continue
			}
			switch elf.SymType(s.Info & 0x0f) {
			case elf.STT_FUNC, elf.STT_NOTYPE:
				add(s.Name)
			}
		}
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == "" {
				continue
			}
			switch elf.SymType(s.Info & 0x0f) {
			case elf.STT_FUNC, elf.STT_NOTYPE:
				add(s.Name)
			}
		}
	}
	if raw != nil {
		for _, n := range phdrSymbolNames(f, raw) {
			add(n)
		}
	}
	sort.Strings(out)
	return out
}

// FortifySummary is the FORTIFY_SOURCE analysis for one binary.
type FortifySummary struct {
	Available     bool     // libc provides at least one _chk function
	NumLibc       int      // count of _chk functions in libc
	Fortified     int      // _chk variants the binary actually calls
	Fortifiable   int      // fortified + fortifiable-but-unprotected calls
	Unprotected   []string // base functions called unfortified
	FortifiedList []string // _chk functions the binary calls
}

// FortifyResult is the Result-shaped view of a FortifySummary used by the
// report table (summary Yes/No/N-A plus the two counts).
type FortifyResult struct {
	Summary     Result
	Fortified   Result
	Fortifiable Result
}

// Fortify computes FORTIFY_SOURCE coverage:
// which fortifiable libc functions the binary calls, and how many of those
// calls go through the fortified _chk variant. For static binaries there is
// no dynamic import boundary, so only the fortified side is reported (see
// the "none" branch below).
//
// libcPath comes from resolveLibcFlag: "" or a concrete libc path for
// dynamically linked binaries, or the sentinel "none" for static ones.
func Fortify(f *elf.File, raw *os.File, libcPath string) FortifyResult {
	if f == nil {
		return FortifyResult{
			Summary:     Err("fortify"),
			Fortified:   NA("N/A"),
			Fortifiable: NA("N/A"),
		}
	}

	if libcPath == "none" {
		// Static binary: no dynamic import boundary, so the fortifiable
		// metric stays N/A (base-vs-_chk pairing is meaningless when every
		// base function is defined inside the image itself). The fortified
		// side still works off the pattern scan over .symtab: libc.a's
		// baseline carries no exact __X_chk dispatchers (see
		// fortifiedChkNames), so hits are attributable to the application
		// build. Verified against glibc 2.35; re-verify when targeting
		// other libc versions or architectures. A stripped static binary
		// has no symbol data and stays N/A.
		if _, err := f.Symbols(); err != nil {
			// Stripped static binary: no symbol data at all.
			return FortifyResult{
				Summary:     NA("N/A"),
				Fortified:   NA("N/A"),
				Fortifiable: NA("N/A"),
			}
		}
		names := fortifiedChkNames(f, raw)
		if len(names) > 0 {
			return FortifyResult{
				Summary:     OK("Fortified calls found"),
				Fortified:   Info(strconv.Itoa(len(names))),
				Fortifiable: NA("N/A"),
			}
		}
		return FortifyResult{
			Summary:     Info("No fortified calls"),
			Fortified:   Info("0"),
			Fortifiable: NA("N/A"),
		}
	}

	// Names the binary references (imports + phdr fallback for stripped).
	binaryFuncs := map[string]bool{}
	for _, n := range importedNames(f) {
		binaryFuncs[baseSymbolName(n)] = true
	}
	if raw != nil {
		for _, n := range phdrSymbolNames(f, raw) {
			binaryFuncs[baseSymbolName(n)] = true
		}
	}

	// Fortified calls: fortified-variant symbols the binary references,
	// matched by name pattern (isFortifyChkName) rather than a fixed list,
	// so fortify functions from other libcs (e.g. musl's __fd_chk for
	// fdopen) and future glibc additions are covered without list updates.
	fortifiedList := fortifiedChkNames(f, raw)
	fortified := len(fortifiedList)

	// Fortifiable: calls to the base (unfortified) versions of functions for
	// which a _chk implementation exists. Following checksec, fortifiable
	// counts every fortifiable call: the fortified ones plus the unprotected
	// base calls.
	chkBase := map[string]bool{} // e.g. "memcpy"
	for _, chk := range supportedChkFuncs {
		chkBase[fortifyBaseName(chk)] = true
	}
	unprotectedCount := 0
	var unprotected []string
	for base := range chkBase {
		if binaryFuncs[base] {
			unprotectedCount++
			unprotected = append(unprotected, base)
		}
	}
	fortifiable := fortified + unprotectedCount
	sort.Strings(unprotected)

	res := FortifyResult{
		Fortified:   Info(strconv.Itoa(fortified)),
		Fortifiable: Info(strconv.Itoa(fortifiable)),
	}
	if fortified > 0 {
		res.Summary = OK("Yes")
	} else if fortifiable > 0 {
		res.Summary = Warn("No")
	} else {
		res.Summary = Info("No fortifiable calls")
	}
	return res
}

// baseSymbolName strips version suffixes: "memcpy@@GLIBC_2.14" → "memcpy".
func baseSymbolName(n string) string {
	if i := strings.IndexByte(n, '@'); i >= 0 {
		n = n[:i]
	}
	return n
}

// fortifyBaseName maps a _chk function to its base: "__memcpy_chk" → "memcpy".
func fortifyBaseName(chk string) string {
	name := strings.TrimPrefix(chk, "__")
	return strings.TrimSuffix(name, "_chk")
}
