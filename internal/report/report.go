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

// ScopeCounts is one scope's share of the summary (B-9): how many controls
// it holds, and the same three parts the top level states over all of them.
type ScopeCounts struct {
	Controls     int               `json:"controls"`
	Automatic    SeverityCounts    `json:"automatic"`
	ManualReview int               `json:"manual_review"`
	Undecidable  UndecidableCounts `json:"undecidable"`
}

// Scopes says how much of the verdict comes from the KISA guide and how much
// from beyond it (B-9). The two are a partition of the same rows -- scopeOf
// is one predicate, so nothing falls in both or in neither -- and they sum to
// the top-level summary, which keeps its existing meaning. It is a struct
// with a fixed field order, never a map (D20).
type Scopes struct {
	Guide  ScopeCounts `json:"guide"`
	Beyond ScopeCounts `json:"beyond"`
}

// Summary is the three-part summary of spec §9: automatic verdicts by
// severity, items under manual review, undecidable items. Every field counts
// every control, whatever its scope; Scopes splits the same rows in two.
type Summary struct {
	Automatic           SeverityCounts    `json:"automatic"`
	ManualReview        int               `json:"manual_review"`
	Undecidable         UndecidableCounts `json:"undecidable"`
	FactsFailed         int               `json:"facts_failed"`
	WaiversExpiringSoon int               `json:"waivers_expiring_soon"`
	Scopes              Scopes            `json:"scopes"`
}

// scopeOf is the predicate of B-9: beyond is a control of category "beyond",
// guide is every other control. One predicate, so the two scopes partition
// the results; the controls lint (beyond_scope) keeps the category and the
// KISA reference in step, so "guide" really does mean "implements an item".
func scopeOf(category string) string {
	if category == "beyond" {
		return "beyond"
	}
	return "guide"
}

var scopeRank = map[string]int{"guide": 0, "beyond": 1}

// count folds one row into a ScopeCounts. The total and each scope go through
// it, so the top-level numbers and the split can never disagree about what a
// status means -- which is the property TestSummaryScopesSumToTheTotal reads.
func count(into *ScopeCounts, row Row) {
	into.Controls++
	bucket := &into.Automatic.Low
	switch row.Severity {
	case "high":
		bucket = &into.Automatic.High
	case "medium":
		bucket = &into.Automatic.Medium
	}
	switch row.Status {
	case check.PASS:
		bucket.Pass++
	case check.FAIL:
		bucket.Fail++
	case check.WARN:
		if row.Automation == "partial" {
			into.ManualReview++
		} else {
			bucket.Warn++
		}
	case check.MANUAL:
		into.ManualReview++
	case check.ERROR:
		into.Undecidable.Error++
	case check.NotApplicable:
		into.Undecidable.NotApplicable++
	case check.WAIVED:
		into.Undecidable.Waived++
	}
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

// Build sorts by scope, then severity, then id, and computes the summary.
// The guide comes first and beyond it after, so a high beyond row prints
// below a low guide row (B-9); a report with no beyond row therefore sorts
// exactly as it did before the split.
func Build(snap *facts.Snapshot, results []check.Result, cb CheckBlock) *Report {
	rows := make([]Row, 0, len(results))
	for _, r := range results {
		rows = append(rows, Row{Result: r, Severity: Severity(r.Importance)})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if si, sj := scopeRank[scopeOf(rows[i].Category)], scopeRank[scopeOf(rows[j].Category)]; si != sj {
			return si < sj
		}
		if severityRank[rows[i].Severity] != severityRank[rows[j].Severity] {
			return severityRank[rows[i].Severity] < severityRank[rows[j].Severity]
		}
		return rows[i].ID < rows[j].ID
	})
	var s Summary
	// The total goes through the same fold as each scope, so the top-level
	// numbers are the sum of the split by construction rather than by two
	// loops that have to be kept in agreement.
	var total ScopeCounts
	for _, row := range rows {
		count(&total, row)
		if scopeOf(row.Category) == "beyond" {
			count(&s.Scopes.Beyond, row)
		} else {
			count(&s.Scopes.Guide, row)
		}
	}
	s.Automatic, s.ManualReview, s.Undecidable = total.Automatic, total.ManualReview, total.Undecidable
	for _, c := range snap.Run.Collectors {
		if c.Status != "ok" {
			s.FactsFailed++
		}
	}
	s.WaiversExpiringSoon = cb.Waivers.ExpiringSoon
	return &Report{SchemaVersion: ReportSchemaVersion, Run: snap.Run, Check: cb, Summary: s, Results: rows}
}
