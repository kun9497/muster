// Package report assembles results into the output contract of spec §9 and
// renders it as JSON or a table. Same input, same bytes (D20).
package report

import (
	"sort"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/facts"
)

// ReportSchemaVersion is the result JSON's own schema version.
const ReportSchemaVersion = 1

// Severity derives the sort and filter key from KISA importance (spec §9).
func Severity(importance string) string {
	switch importance {
	case "상":
		return "high"
	case "중":
		return "medium"
	default:
		return "low"
	}
}

var severityRank = map[string]int{"high": 0, "medium": 1, "low": 2}

type WaiversBlock struct {
	Path         string `json:"path,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Applied      int    `json:"applied"`
	NotApplied   int    `json:"not_applied"`
	Expired      int    `json:"expired"`
	Unknown      int    `json:"unknown"`
	ExpiringSoon int    `json:"expiring_soon"`
}

// CheckBlock names the evaluating binary, control set, snapshot and waivers
// (spec §9 "Result provenance").
type CheckBlock struct {
	MusterVersion   string                    `json:"muster_version"`
	Commit          string                    `json:"commit"`
	ControlsVersion string                    `json:"controls_version"`
	ControlsDigest  string                    `json:"controls_digest"`
	SnapshotDigest  string                    `json:"snapshot_digest"`
	GuideEdition    string                    `json:"guide_edition"`
	Waivers         WaiversBlock              `json:"waivers"`
	Params          map[string]map[string]any `json:"params,omitempty"`
}

type StatusCounts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
}

type SeverityCounts struct {
	High   StatusCounts `json:"high"`
	Medium StatusCounts `json:"medium"`
	Low    StatusCounts `json:"low"`
}

type UndecidableCounts struct {
	Error         int `json:"error"`
	NotApplicable int `json:"not_applicable"`
	Waived        int `json:"waived"`
}

// Summary is the three-part summary of spec §9: automatic verdicts by
// severity, items under manual review, undecidable items.
type Summary struct {
	Automatic           SeverityCounts    `json:"automatic"`
	ManualReview        int               `json:"manual_review"`
	Undecidable         UndecidableCounts `json:"undecidable"`
	FactsFailed         int               `json:"facts_failed"`
	WaiversExpiringSoon int               `json:"waivers_expiring_soon"`
}

// Row is one result plus its derived severity.
type Row struct {
	check.Result
	Severity string `json:"severity"`
}

type Report struct {
	SchemaVersion int        `json:"schema_version"`
	Run           facts.Run  `json:"run"`
	Check         CheckBlock `json:"check"`
	Summary       Summary    `json:"summary"`
	Results       []Row      `json:"results"`
}

// Build sorts by severity then id and computes the summary.
func Build(snap *facts.Snapshot, results []check.Result, cb CheckBlock) *Report {
	rows := make([]Row, 0, len(results))
	for _, r := range results {
		rows = append(rows, Row{Result: r, Severity: Severity(r.Importance)})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if severityRank[rows[i].Severity] != severityRank[rows[j].Severity] {
			return severityRank[rows[i].Severity] < severityRank[rows[j].Severity]
		}
		return rows[i].ID < rows[j].ID
	})
	var s Summary
	for _, row := range rows {
		bucket := &s.Automatic.Low
		switch row.Severity {
		case "high":
			bucket = &s.Automatic.High
		case "medium":
			bucket = &s.Automatic.Medium
		}
		switch row.Status {
		case check.PASS:
			bucket.Pass++
		case check.FAIL:
			bucket.Fail++
		case check.WARN:
			if row.Automation == "partial" {
				s.ManualReview++
			} else {
				bucket.Warn++
			}
		case check.MANUAL:
			s.ManualReview++
		case check.ERROR:
			s.Undecidable.Error++
		case check.NotApplicable:
			s.Undecidable.NotApplicable++
		case check.WAIVED:
			s.Undecidable.Waived++
		}
	}
	for _, c := range snap.Run.Collectors {
		if c.Status != "ok" {
			s.FactsFailed++
		}
	}
	s.WaiversExpiringSoon = cb.Waivers.ExpiringSoon
	return &Report{SchemaVersion: ReportSchemaVersion, Run: snap.Run, Check: cb, Summary: s, Results: rows}
}
