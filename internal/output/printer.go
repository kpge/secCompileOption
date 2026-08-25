// Package output renders FileReports in the supported formats: colored
// table, JSON, CSV, and XML. All renderers share checksec.CheckOrder as the
// column order so their fields line up.
package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"seccompilecheck/internal/checksec"
)

// ANSI colors keyed by checksec.Status. Empty string = no color (also used
// when output is not a terminal, handled by the caller via DisableColors).
var statusColor = map[checksec.Status]string{
	checksec.StatusGood: "\033[32m",
	checksec.StatusWarn: "\033[33m",
	checksec.StatusBad:  "\033[31m",
	checksec.StatusInfo: "",
	checksec.StatusNA:   "\033[2m",
}

const colorReset = "\033[0m"

// Printer renders reports. Construct with NewPrinter.
type Printer struct {
	Colors bool // colorize table cells (auto-detect terminal by caller)
}

func NewPrinter(colors bool) *Printer { return &Printer{Colors: colors} }

func (p *Printer) colorize(s checksec.Status, v string) string {
	if !p.Colors {
		return v
	}
	if c, ok := statusColor[s]; ok && c != "" {
		return c + v + colorReset
	}
	return v
}

// Table writes one table for the batch. With a single report the Name column
// is omitted (like checksec --file).
func (p *Printer) Table(w io.Writer, reports []checksec.FileReport) {
	if len(reports) == 0 {
		return
	}

	headers := make([]string, 0, len(checksec.CheckOrder)+1)
	showName := len(reports) > 1
	if showName {
		headers = append(headers, "Name")
	}
	for _, k := range checksec.CheckOrder {
		headers = append(headers, checksec.HeaderName[k])
	}

	// Column widths from raw (uncolored) values.
	rows := make([][]string, len(reports))
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for i, r := range reports {
		row := []string{}
		if showName {
			row = append(row, r.Name)
		}
		for _, k := range checksec.CheckOrder {
			row = append(row, r.Checks[k].Value)
		}
		rows[i] = row
		for j, cell := range row {
			if len(cell) > widths[j] {
				widths[j] = len(cell)
			}
		}
	}

	var sb strings.Builder
	writeSep := func() {
		sb.WriteString("+")
		for _, wd := range widths {
			sb.WriteString(strings.Repeat("-", wd+2))
			sb.WriteString("+")
		}
		sb.WriteString("\n")
	}
	writeRow := func(cells []string, colored []bool, statuses []checksec.Status) {
		sb.WriteString("|")
		for j, cell := range cells {
			val := cell
			if colored != nil && colored[j] {
				val = p.colorize(statuses[j], cell)
			}
			pad := widths[j] - len(cell)
			if pad < 0 {
				pad = 0
			}
			fmt.Fprintf(&sb, " %s%s |", val, strings.Repeat(" ", pad))
		}
		sb.WriteString("\n")
	}

	writeSep()
	writeRow(headers, nil, nil)
	writeSep()
	for i, r := range reports {
		cells := rows[i]
		if r.Error != "" {
			// Whole row in error style: single spanning message.
			fmt.Fprintf(&sb, "| %s", p.colorize(checksec.StatusBad, r.Error))
			total := len(headers) - 1
			for _, wd := range widths {
				total += wd + 3
			}
			if pad := total - len(r.Error) - 2; pad > 0 {
				sb.WriteString(strings.Repeat(" ", pad))
			}
			sb.WriteString("|\n")
			continue
		}
		var statuses []checksec.Status
		var colored []bool
		if showName {
			statuses = append(statuses, checksec.StatusInfo)
			colored = append(colored, false)
		}
		for _, k := range checksec.CheckOrder {
			statuses = append(statuses, r.Checks[k].Status)
			colored = append(colored, true)
		}
		writeRow(cells, colored, statuses)
	}
	writeSep()
	fmt.Fprint(w, sb.String())
}

// JSON writes reports as a JSON array (pretty-printed).
func (p *Printer) JSON(w io.Writer, reports []checksec.FileReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(reports)
}

// CSV writes one row per report with check keys as columns.
func (p *Printer) CSV(w io.Writer, reports []checksec.FileReport) error {
	cw := csv.NewWriter(w)
	header := []string{"name"}
	header = append(header, checksec.CheckOrder...)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, r := range reports {
		row := []string{r.Name}
		for _, k := range checksec.CheckOrder {
			row = append(row, r.Checks[k].Value)
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// xmlReports adapts FileReport to encoding/xml (maps are not marshalable).
type xmlReports struct {
	XMLName xml.Name    `xml:"secCompileCheck"`
	Files   []xmlReport `xml:"file"`
}

type xmlReport struct {
	Name   string          `xml:"name,attr"`
	Checks []xmlCheckValue `xml:"check"`
}

type xmlCheckValue struct {
	Key    string `xml:"key,attr"`
	Status string `xml:"status,attr"`
	Value  string `xml:",chardata"`
}

// XML writes reports as a single <secCompileCheck> document.
func (p *Printer) XML(w io.Writer, reports []checksec.FileReport) error {
	var out xmlReports
	for _, r := range reports {
		xr := xmlReport{Name: r.Name}
		for _, k := range checksec.CheckOrder {
			xr.Checks = append(xr.Checks, xmlCheckValue{
				Key:    k,
				Status: string(r.Checks[k].Status),
				Value:  r.Checks[k].Value,
			})
		}
		out.Files = append(out.Files, xr)
	}
	buf, err := xml.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n%s\n", buf)
	return err
}
