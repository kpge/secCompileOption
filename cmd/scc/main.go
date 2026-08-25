// Command scc (secCompileCheck) is a security compile-option checker for ELF
// binaries, inspired by checksec (https://github.com/slimm609/checksec).
//
// It reports RELRO, stack canary, NX, PIE, RPATH/RUNPATH, symbol counts and
// FORTIFY_SOURCE coverage for a binary, a directory tree, or a list file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"seccompilecheck/internal/checksec"
	"seccompilecheck/internal/output"
)

const version = "1.0.0"

type options struct {
	format  string
	libc    string
	verbose bool
	noColor bool
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func usage() {
	fmt.Fprintf(os.Stderr, `secCompileCheck (scc) %s — ELF binary security compile-option checker

Usage:
  scc <command> [flags] <target>

Commands:
  file <binary>              Check a single ELF binary
  dir <directory>            Check every ELF binary in a directory
    -recursive               Recurse into subdirectories
  list <file>                Check every path listed in a file (one per line)
  version                    Print version

Flags:
  -format string             Output format: table (default), json, csv, xml,
                            compliance, compliance-json (secure-compile spec verdicts)
  -libc string               Explicit libc path for FORTIFY analysis
  -verbose                   Show notes and unmatched checks
  -no-color                  Disable colored output (default when not a TTY)

Exit codes:
  0  all checks ran (or no binaries found)
  1  usage / IO error
  2  at least one binary failed one or more checks (see below)

A binary "fails" when any of RELRO / canary / NX / PIE / RPATH reports a bad
status, mirroring checksec's severity model.
`, version)
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 1
	}

	cmd := args[0]
	var fs *flag.FlagSet
	opts := &options{}

	newFlags := func(name string) *flag.FlagSet {
		f := flag.NewFlagSet(name, flag.ContinueOnError)
		f.StringVar(&opts.format, "format", "table", "output format: table, json, csv, xml")
		f.StringVar(&opts.libc, "libc", "", "explicit libc path for FORTIFY analysis")
		f.BoolVar(&opts.verbose, "verbose", false, "show notes")
		f.BoolVar(&opts.noColor, "no-color", false, "disable colors")
		return f
	}

	var paths []string
	switch cmd {
	case "file":
		fs = newFlags("file")
	case "dir":
		fs = newFlags("dir")
		fs.Bool("recursive", false, "recurse into subdirectories")
	case "list":
		fs = newFlags("list")
	case "version", "--version", "-v":
		fmt.Println("secCompileCheck (scc) " + version)
		return 0
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		return 1
	}

	if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "%s: missing target\n\n", cmd)
		usage()
		return 1
	}

	switch opts.format {
	case "table", "json", "csv", "xml", "compliance", "compliance-json":
	default:
		fmt.Fprintf(os.Stderr, "invalid -format %q (want table|json|csv|xml|compliance|compliance-json)\n", opts.format)
		return 1
	}

	switch cmd {
	case "file":
		paths = rest
	case "dir":
		recursive := fs.Lookup("recursive").Value.String() == "true"
		p, err := collectDir(rest[0], recursive)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dir: %v\n", err)
			return 1
		}
		paths = p
	case "list":
		p, err := readList(rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "list: %v\n", err)
			return 1
		}
		paths = p
	}

	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no ELF binaries found")
		return 0
	}

	reports := make([]checksec.FileReport, 0, len(paths))
	for _, p := range paths {
		reports = append(reports, checksec.CheckFile(p))
	}

	printer := output.NewPrinter(!opts.noColor && isTerminal())
	if err := printReports(os.Stdout, printer, opts.format, reports); err != nil {
		fmt.Fprintf(os.Stderr, "output: %v\n", err)
		return 1
	}

	// compliance formats gate on spec-rule failures; others on bad checks.
	if strings.HasPrefix(opts.format, "compliance") {
		for _, r := range reports {
			if s := checksec.Compliance(r); s.Fail > 0 {
				return 2
			}
		}
		return 0
	}
	if hasFailures(reports) {
		return 2
	}
	return 0
}

// failKeys are the checks whose bad status marks a binary as failing.
var failKeys = []string{"relro", "canary", "nx", "pie", "bind_now", "rpath"}

// reorderArgs moves flag arguments before positional arguments so both
// "scc file -format json x" and "scc file x -format=json" work.
// The command name (args[0]) is not part of the input.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			return append(flags, positional...)
		case strings.HasPrefix(a, "-") && a != "-":
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				flags = append(flags, a)
				i++
				continue
			}
			flags = append(flags, a)
			// Boolean flags do not consume the next argument; everything
			// else does.
			fl := fs.Lookup(name)
			if fl == nil {
				// Unknown flag: let fs.Parse report the error. Assume it
				// does not consume a value so the next arg survives.
				i++
				continue
			}
			if b, ok := fl.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
				if i+1 < len(args) {
					flags = append(flags, args[i+1])
					i++
				}
			}
			i++
		default:
			positional = append(positional, a)
			i++
		}
	}
	return append(flags, positional...)
}

func hasFailures(reports []checksec.FileReport) bool {
	for _, r := range reports {
		if r.Error != "" {
			return true
		}
		for _, k := range failKeys {
			if r.Checks[k].Status == checksec.StatusBad {
				return true
			}
		}
	}
	return false
}

func printReports(w *os.File, p *output.Printer, format string, reports []checksec.FileReport) error {
	switch format {
	case "json":
		return p.JSON(w, reports)
	case "csv":
		return p.CSV(w, reports)
	case "xml":
		return p.XML(w, reports)
	case "compliance":
		p.Compliance(w, reports)
		return nil
	case "compliance-json":
		return p.ComplianceJSON(w, reports)
	default:
		p.Table(w, reports)
		return nil
	}
}

// collectDir walks dir (optionally recursive) and returns every ELF file.
func collectDir(dir string, recursive bool) ([]string, error) {
	var out []string
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if !recursive && path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if isELF(path) {
			out = append(out, path)
		}
		return nil
	}
	if err := filepath.WalkDir(dir, walk); err != nil {
		return nil, err
	}
	return out, nil
}

func isELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}

// readList reads one path per line, skipping blanks and #-comments.
func readList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// keep encoding/json referenced for potential future structured logging.
var _ = json.Marshal
