package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"seccompilecheck/internal/checksec"
)

func sampleReports() []checksec.FileReport {
	return []checksec.FileReport{
		{
			Name: "a.elf",
			Checks: map[string]checksec.Result{
				"relro":       checksec.OK("Full RELRO"),
				"canary":      checksec.OK("Canary found"),
				"nx":          checksec.OK("NX enabled"),
				"pie":         checksec.OK("PIE enabled"),
				"rpath":       checksec.OK("No RPATH"),
				"runpath":     checksec.OK("No RUNPATH"),
				"symbols":     checksec.OK("No symbols (stripped)"),
				"fortify":     checksec.OK("Yes"),
				"fortified":   checksec.Info("1"),
				"fortifiable": checksec.Info("2"),
			},
		},
		{
			Name: "b.elf",
			Checks: map[string]checksec.Result{
				"relro":       checksec.Bad("No RELRO"),
				"canary":      checksec.Bad("No canary found"),
				"nx":          checksec.Bad("NX disabled"),
				"pie":         checksec.Bad("PIE disabled"),
				"rpath":       checksec.Bad("RPATH [../lib] (relative path)"),
				"runpath":     checksec.OK("No RUNPATH"),
				"symbols":     checksec.Bad("2334 symbols"),
				"fortify":     checksec.NA("N/A"),
				"fortified":   checksec.NA("0"),
				"fortifiable": checksec.NA("0"),
			},
		},
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	NewPrinter(false).Table(&buf, sampleReports())
	out := buf.String()
	for _, want := range []string{"RELRO", "Full RELRO", "No RELRO", "a.elf", "b.elf"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q", want)
		}
	}
	// No ANSI escapes with colors off.
	if strings.Contains(out, "\033[") {
		t.Error("table contains ANSI codes with colors disabled")
	}
}

func TestTableColors(t *testing.T) {
	var buf bytes.Buffer
	NewPrinter(true).Table(&buf, sampleReports())
	if !strings.Contains(buf.String(), "\033[31m") {
		t.Error("expected red ANSI code for bad status")
	}
}

func TestTableSingleReportHidesName(t *testing.T) {
	var buf bytes.Buffer
	NewPrinter(false).Table(&buf, sampleReports()[:1])
	if strings.Contains(buf.String(), "a.elf") {
		t.Error("single report should omit the Name column")
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := NewPrinter(false).JSON(&buf, sampleReports()); err != nil {
		t.Fatal(err)
	}
	var reports []checksec.FileReport
	if err := json.Unmarshal(buf.Bytes(), &reports); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if len(reports) != 2 || reports[0].Name != "a.elf" {
		t.Fatalf("unexpected reports: %+v", reports)
	}
	if reports[0].Checks["relro"].Value != "Full RELRO" {
		t.Errorf("relro = %q", reports[0].Checks["relro"].Value)
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := NewPrinter(false).CSV(&buf, sampleReports()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 csv rows, got %d", len(rows))
	}
	if rows[0][0] != "name" || rows[0][1] != "relro" {
		t.Errorf("bad header: %v", rows[0])
	}
	if rows[2][1] != "No RELRO" {
		t.Errorf("bad row: %v", rows[2])
	}
}

func TestXML(t *testing.T) {
	var buf bytes.Buffer
	if err := NewPrinter(false).XML(&buf, sampleReports()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		XMLName xml.Name `xml:"secCompileCheck"`
		Files   []struct {
			Name   string `xml:"name,attr"`
			Checks []struct {
				Key    string `xml:"key,attr"`
				Status string `xml:"status,attr"`
				Value  string `xml:",chardata"`
			} `xml:"check"`
		} `xml:"file"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if len(doc.Files) != 2 || doc.Files[0].Name != "a.elf" {
		t.Fatalf("unexpected files: %+v", doc.Files)
	}
	if got := doc.Files[1].Checks[0]; got.Key != "relro" || got.Value != "No RELRO" || got.Status != "bad" {
		t.Errorf("bad first check: %+v", got)
	}
}
