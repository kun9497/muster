package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/muster/internal/report"
	"github.com/kun9497/muster/internal/snapshots"
)

// dirLock is the lock rm and prune hold over the snapshot directory. It is
// an interface so no untagged file names collect.Lock, which is Linux-only
// (RA-2).
type dirLock interface{ Release() }

type lsFlags struct{ dir, format string }

func parseLsArgs(args []string) (lsFlags, error) {
	f := lsFlags{dir: snapshots.DefaultDir, format: "table"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			if args[i] == "" {
				return "", fmt.Errorf("flag %s needs a non-empty value", a)
			}
			return args[i], nil
		}
		var err error
		switch a {
		case "--dir":
			f.dir, err = next()
		case "--format":
			f.format, err = next()
		default:
			return f, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return f, err
		}
	}
	if f.format != "table" && f.format != "json" {
		return f, errors.New("--format must be table or json")
	}
	return f, nil
}

// runSnapshotLs lists the snapshot directory through one fd (RL-16, RL-18):
// exit 0 on a listing, an empty directory included; 2 on bad flags or a
// directory that is refused or cannot be read, with nothing on stdout.
func runSnapshotLs(args []string, stdout, stderr io.Writer) int {
	f, err := parseLsArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, snapshotUsage)
		return exitError
	}
	d, err := openSnapshotDir(f.dir)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	entries, other, latest, err := d.list()
	d.close()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	snapshots.Sort(entries)
	if latest.present {
		for i := range entries {
			if entries[i].Name == latest.target {
				entries[i].Latest = true
			}
		}
	}
	var buf bytes.Buffer
	if f.format == "json" {
		if err := renderLsJSON(&buf, f.dir, entries, other, latest); err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
	} else {
		renderLsTable(&buf, f.dir, entries, other, latest)
	}
	if _, err := stdout.Write(buf.Bytes()); err != nil {
		fmt.Fprintf(stderr, "muster: write: %v\n", err)
		return exitError
	}
	return exitOK
}

// orDash is a header field as the table prints it: "-" when there is none.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return report.Escape(s)
}

// renderLsTable writes the header line, the column names and one row per
// entry. Every file name and link target goes through report.Escape;
// columns are as wide as their widest cell by the check table's width rule
// (RA-29), two spaces apart, with no trailing space.
func renderLsTable(w io.Writer, dir string, entries []snapshots.Entry, other int, latest latestLink) {
	link := "no latest link"
	if latest.present {
		link = "latest -> " + report.Escape(latest.target)
		if latest.state != "ok" {
			link += " (" + latest.state + ")"
		}
	}
	fmt.Fprintf(w, "%s  (%d snapshots, %d other files; %s)\n", report.EscapeNoCut(dir), len(entries), other, link)

	rows := [][]string{{"NAME", "COLLECTED", "HOST", "MUSTER", "CONTROLS", "SIZE", "CLASS"}}
	marks := []bool{false}
	for _, e := range entries {
		row := []string{report.Escape(e.Name), "-", "-", "-", "-", fmt.Sprint(e.Size), string(e.Class)}
		if e.Class != snapshots.ClassUnreadable {
			row[1], row[2], row[3], row[4] = orDash(e.CollectedAt), orDash(e.Hostname), orDash(e.MusterVersion), orDash(e.ControlsVersion)
		}
		rows = append(rows, row)
		marks = append(marks, e.Latest)
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			widths[i] = max(widths[i], report.DisplayWidth(cell))
		}
	}
	for r, row := range rows {
		var b strings.Builder
		for i, cell := range row {
			if i > 0 {
				b.WriteString("  ")
			}
			if i < len(row)-1 || marks[r] {
				cell = report.PadRight(cell, widths[i])
			}
			b.WriteString(cell)
		}
		if marks[r] {
			b.WriteString("  *")
		}
		b.WriteString("\n")
		io.WriteString(w, b.String())
	}
}

type lsLatestJSON struct {
	Present bool   `json:"present"`
	Target  string `json:"target"`
	State   string `json:"state"`
}

type lsEntryJSON struct {
	Name            string `json:"name"`
	Class           string `json:"class"`
	Size            int64  `json:"size"`
	SchemaVersion   int    `json:"schema_version"`
	CollectedAt     string `json:"collected_at"`
	Hostname        string `json:"hostname"`
	MusterVersion   string `json:"muster_version"`
	ControlsVersion string `json:"controls_version"`
	Latest          bool   `json:"latest"`
}

type lsJSON struct {
	Dir        string        `json:"dir"`
	OtherFiles int           `json:"other_files"`
	Latest     *lsLatestJSON `json:"latest"`
	Entries    []lsEntryJSON `json:"entries"`
}

// renderLsJSON writes the listing as one JSON object, keys in a fixed order
// and entries in Sort order, with one trailing newline. latest is null when
// there is no latest link.
func renderLsJSON(w io.Writer, dir string, entries []snapshots.Entry, other int, latest latestLink) error {
	doc := lsJSON{Dir: dir, OtherFiles: other, Entries: []lsEntryJSON{}}
	if latest.present {
		doc.Latest = &lsLatestJSON{Present: true, Target: latest.target, State: latest.state}
	}
	for _, e := range entries {
		doc.Entries = append(doc.Entries, lsEntryJSON{
			Name: e.Name, Class: string(e.Class), Size: e.Size, SchemaVersion: e.SchemaVersion,
			CollectedAt: e.CollectedAt, Hostname: e.Hostname, MusterVersion: e.MusterVersion,
			ControlsVersion: e.ControlsVersion, Latest: e.Latest,
		})
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(body, '\n'))
	return err
}
