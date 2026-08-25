package checksec

import (
	"debug/elf"
	"os"
	"sort"
	"strconv"
	"strings"
)

// supportedChkFuncs are the glibc _FORTIFY_SOURCE checkable functions the
// compiler can emit (gcc builtins.def / clang). Anything outside this list is
// not attributable to fortify.
var supportedChkFuncs = []string{
	"__memcpy_chk", "__memmove_chk", "__mempcpy_chk", "__memset_chk",
	"__stpcpy_chk", "__stpncpy_chk", "__strcat_chk", "__strcpy_chk",
	"__strncat_chk", "__strncpy_chk", "__snprintf_chk", "__sprintf_chk",
	"__vsnprintf_chk", "__vsprintf_chk", "__fprintf_chk", "__printf_chk",
	"__vfprintf_chk", "__vprintf_chk",
	"__gets_chk", "__fgets_chk", "__read_chk", "__recv_chk", "__send_chk",
	"__poll_chk", "__pread_chk", "__pread64_chk", "__readlink_chk",
	"__realpath_chk", "__longjmp_chk", "__wdunderflow_chk",
}

func init() { sort.Strings(supportedChkFuncs) }

func isSupportedChk(name string) bool {
	i := sort.SearchStrings(supportedChkFuncs, name)
	return i < len(supportedChkFuncs) && supportedChkFuncs[i] == name
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
// calls go through the fortified _chk variant.
//
// libcPath may be "" for auto-resolution (see ResolveLibc), a concrete libc
// path, or the sentinel "none"/"unk" (static binary / no libc found), in
// which case FORTIFY is not applicable.
func Fortify(f *elf.File, raw *os.File, libcPath string) FortifyResult {
	if f == nil {
		return FortifyResult{
			Summary:     Err("fortify"),
			Fortified:   NA("N/A"),
			Fortifiable: NA("N/A"),
		}
	}

	if libcPath == "none" || libcPath == "unk" {
		return FortifyResult{
			Summary:     NA("N/A"),
			Fortified:   NA("0"),
			Fortifiable: NA("0"),
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

	// Fortified calls: _chk functions the binary references directly.
	fortified := 0
	var fortifiedList []string
	for _, chk := range supportedChkFuncs {
		if binaryFuncs[chk] {
			fortified++
			fortifiedList = append(fortifiedList, chk)
		}
	}

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
	sort.Strings(fortifiedList)

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
