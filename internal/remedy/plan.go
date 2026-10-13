// Package remedy plans the remediation of a check report (stage 3D-2,
// fix --dry-run). It is pure: it reads a report and the control set and
// returns a plan; it never executes anything, imports no host API and reads
// no clock (a test enforces it). Same input, same plan; no map reaches it.
package remedy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
)

// PlanSchemaVersion is the plan JSON's own schema version.
const PlanSchemaVersion = 1

// machineHashRe is the one shape of machine-id hash a script may carry.
var machineHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Options are the planner's knobs. MaxRisk "" means lockout_risk.
type Options struct{ MaxRisk string }

// FixBlock names the evaluating binary, control set, snapshot, profile,
// tuning and waivers the plan was built from, copied from the report's
// check block, plus the max risk in force. The field order is the JSON's.
type FixBlock struct {
	MusterVersion   string              `json:"muster_version"`
	Commit          string              `json:"commit"`
	ControlsVersion string              `json:"controls_version"`
	ControlsDigest  string              `json:"controls_digest"`
	SnapshotDigest  string              `json:"snapshot_digest"`
	GuideEdition    string              `json:"guide_edition"`
	Profile         report.ProfileBlock `json:"profile"`
	Tuning          *report.TuningBlock `json:"tuning,omitempty"`
	Waivers         report.WaiversBlock `json:"waivers"`
	MaxRisk         string              `json:"max_risk"`
	HostGuard       string              `json:"host_guard"` // on | off (3D-2b Q-1)
	MachineIDHash   string              `json:"-"`          // the snapshot's, when well formed; the script's guard compares it
}

// Item is one FAIL or WARN row the plan addresses, with its control's
// remediation. Script is true only when the script will be emitted; the
// unexported-to-JSON bodies are what the script renderer writes.
type Item struct {
	ID             string   `json:"id"`
	TitleEn        string   `json:"title_en"`
	TitleKo        string   `json:"title_ko"`
	Status         string   `json:"status"` // fail | warn
	Severity       string   `json:"severity"`
	SeveritySource string   `json:"severity_source"`
	Risk           string   `json:"risk"`
	Idempotent     bool     `json:"idempotent"`
	Automation     string   `json:"automation"`
	Reason         string   `json:"reason"` // report.ReasonLine(row)
	TextEn         string   `json:"text_en"`
	TextKo         string   `json:"text_ko"`
	Script         bool     `json:"script"`
	TextOnlyReason string   `json:"text_only_reason"` // "" | no_script | absent | params_tuned
	Rollback       string   `json:"rollback"`         // none | declared | restore_backup | units | both
	Backup         []string `json:"backup"`
	Units          []string `json:"units"`
	Validate       bool     `json:"validate"`
	Planned        bool     `json:"planned"`

	SourceStatus check.Status `json:"-"` // for the table's status colour
	ScriptBody   string       `json:"-"`
	ValidateCmd  string       `json:"-"`
	RollbackBody string       `json:"-"`
}

// NotPlanned is a row the plan cannot act on: an ERROR, a MANUAL, or a WARN
// that only says the collection was degraded.
type NotPlanned struct {
	ID     string `json:"id"`
	Status string `json:"status"` // error | manual | warn_degraded
	Reason string `json:"reason"` // report.ReasonLine(row)
}

type NotPlannedCounts struct {
	Error        int `json:"error"`
	Manual       int `json:"manual"`
	WarnDegraded int `json:"warn_degraded"`
}

type RiskCounts struct {
	None           int `json:"none"`
	RestartService int `json:"restart_service"`
	RebootRequired int `json:"reboot_required"`
	LockoutRisk    int `json:"lockout_risk"`
}

// Summary partitions the selection: items (planned or above max risk), the
// not-planned rows, waived and clean rows sum to the report's results.
type Summary struct {
	Planned      int              `json:"planned"`
	AboveMaxRisk int              `json:"above_max_risk"`
	WithScript   int              `json:"with_script"`
	TextOnly     int              `json:"text_only"`
	Waived       int              `json:"waived"`
	Clean        int              `json:"clean"`
	NotPlanned   NotPlannedCounts `json:"not_planned"`
	ByRisk       RiskCounts       `json:"by_risk"`
}

// Plan is the remediation plan of one check report. It holds no map (D20).
type Plan struct {
	SchemaVersion int          `json:"schema_version"`
	Run           facts.Run    `json:"run"`
	Fix           FixBlock     `json:"fix"`
	Items         []Item       `json:"items"`
	NotPlanned    []NotPlanned `json:"not_planned"`
	Summary       Summary      `json:"summary"`
}

var riskRank = map[string]int{"none": 0, "restart_service": 1, "reboot_required": 2, "lockout_risk": 3}

// severityRank is remedy's own (Z-11): report's is unexported.
var severityRank = map[string]int{"high": 0, "medium": 1, "low": 2}

// Build plans the remediation of rep's rows against set (Z-19). Items sort
// by risk, then severity, then id; not-planned rows by id.
func Build(rep *report.Report, set *controls.Set, opts Options) (*Plan, error) {
	maxRisk := opts.MaxRisk
	if maxRisk == "" {
		maxRisk = "lockout_risk"
	}
	maxRank, ok := riskRank[maxRisk]
	if !ok {
		return nil, fmt.Errorf("--max-risk must be none, restart_service, reboot_required or lockout_risk, got %q", opts.MaxRisk)
	}
	cb := rep.Check
	hash, guard := "", "off"
	if machineHashRe.MatchString(rep.Run.Host.MachineIDHash) {
		hash, guard = rep.Run.Host.MachineIDHash, "on"
	}
	p := &Plan{
		SchemaVersion: PlanSchemaVersion,
		Run:           rep.Run,
		Fix: FixBlock{MusterVersion: cb.MusterVersion, Commit: cb.Commit, ControlsVersion: cb.ControlsVersion,
			ControlsDigest: cb.ControlsDigest, SnapshotDigest: cb.SnapshotDigest, GuideEdition: cb.GuideEdition,
			Profile: cb.Profile, Tuning: cb.Tuning, Waivers: cb.Waivers, MaxRisk: maxRisk,
			HostGuard: guard, MachineIDHash: hash},
		Items:      []Item{},
		NotPlanned: []NotPlanned{},
	}
	notPlanned := func(row report.Row, status string) {
		p.NotPlanned = append(p.NotPlanned, NotPlanned{ID: row.ID, Status: status, Reason: report.ReasonLine(row)})
	}
	for _, row := range rep.Results {
		switch row.Status {
		case check.PASS, check.NotApplicable:
			p.Summary.Clean++
		case check.WAIVED:
			p.Summary.Waived++
		case check.ERROR:
			notPlanned(row, "error")
			p.Summary.NotPlanned.Error++
		case check.MANUAL:
			notPlanned(row, "manual")
			p.Summary.NotPlanned.Manual++
		case check.WARN, check.FAIL:
			// A WARN whose whole reason is the degradation says the
			// setting passed on a degraded reading: nothing to fix.
			if row.Status == check.WARN && row.Degraded != "" && row.Reason == check.ReasonDegradedPrefix+row.Degraded {
				notPlanned(row, "warn_degraded")
				p.Summary.NotPlanned.WarnDegraded++
				continue
			}
			// Z-26: an item's id reaches the script's command lines
			// (function name, log text); lint holds the embedded set to
			// the id grammar, and the planner refuses anything else.
			if !controls.ValidControlID(row.ID) {
				return nil, fmt.Errorf("refusing to plan %q: not a control id (muster.<category>.<name>)", row.ID)
			}
			p.Items = append(p.Items, item(row, set, cb, maxRank))
			for _, u := range p.Items[len(p.Items)-1].Units {
				if !controls.ValidUnitName(u) {
					return nil, fmt.Errorf("refusing to plan %s: unit %q is not a unit name a script can carry", row.ID, u)
				}
			}
		}
	}
	sort.SliceStable(p.Items, func(i, j int) bool {
		a, b := p.Items[i], p.Items[j]
		if riskRank[a.Risk] != riskRank[b.Risk] {
			return riskRank[a.Risk] < riskRank[b.Risk]
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		return a.ID < b.ID
	})
	sort.SliceStable(p.NotPlanned, func(i, j int) bool { return p.NotPlanned[i].ID < p.NotPlanned[j].ID })
	for _, it := range p.Items {
		switch it.Risk {
		case "none":
			p.Summary.ByRisk.None++
		case "restart_service":
			p.Summary.ByRisk.RestartService++
		case "reboot_required":
			p.Summary.ByRisk.RebootRequired++
		case "lockout_risk":
			p.Summary.ByRisk.LockoutRisk++
		}
		if !it.Planned {
			p.Summary.AboveMaxRisk++
			continue
		}
		p.Summary.Planned++
		if it.Script {
			p.Summary.WithScript++
		} else {
			p.Summary.TextOnly++
		}
	}
	return p, nil
}

func item(row report.Row, set *controls.Set, cb report.CheckBlock, maxRank int) Item {
	it := Item{ID: row.ID, TitleEn: row.TitleEn, TitleKo: row.TitleKo, Status: strings.ToLower(string(row.Status)),
		Severity: row.Severity, SeveritySource: row.SeveritySource, Automation: row.Automation,
		Reason: report.ReasonLine(row), Risk: "none", Rollback: "none", Backup: []string{}, Units: []string{}, SourceStatus: row.Status}
	c, ok := set.ByID(row.ID)
	if !ok || c.Remediation == nil {
		it.TextOnlyReason = "no_script"
		it.Planned = riskRank[it.Risk] <= maxRank
		return it
	}
	r := c.Remediation
	it.Risk, it.Idempotent, it.TextEn, it.TextKo = r.Risk, r.Idempotent, r.TextEn, r.TextKo
	it.Planned = riskRank[it.Risk] <= maxRank
	switch {
	case strings.TrimSpace(r.Script) == "":
		it.TextOnlyReason = "no_script"
	case strings.HasPrefix(row.Reason, check.ReasonAbsentFailPrefix): // Z-6: the bare reason
		it.TextOnlyReason = "absent"
	case tuned(cb.ParamSources[row.ID]):
		it.TextOnlyReason = "params_tuned"
	default:
		it.Script = true
		it.ScriptBody, it.ValidateCmd, it.RollbackBody = r.Script, strings.TrimSuffix(r.Validate, "\n"), r.Rollback
		it.Backup = append([]string{}, r.Backup...)
		it.Validate = r.Validate != ""
		it.Units = append([]string{}, r.Units...)
		hasRB, hasBK, hasU := strings.TrimSpace(r.Rollback) != "", len(r.Backup) > 0, len(r.Units) > 0
		switch {
		case hasRB && hasBK:
			it.Rollback = "both"
		case hasU:
			it.Rollback = "units"
		case hasRB:
			it.Rollback = "declared"
		default:
			it.Rollback = "restore_backup"
		}
	}
	return it
}

// tuned reports whether any parameter of a control is in force from a
// profile or a tuning file: the declared script assumes the defaults.
func tuned(sources map[string]string) bool {
	for _, s := range sources {
		if s != "default" {
			return true
		}
	}
	return false
}
