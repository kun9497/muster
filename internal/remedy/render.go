package remedy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/report"
)

// riskColor is the ANSI code a risk cell is painted with; none is plain.
var riskColor = map[string]string{"lockout_risk": "31", "reboot_required": "35", "restart_service": "33"}

// Table renders the plan for a human (spec §6 "Table"): the header, the
// summary, one three-line entry per item and the not-planned rows. Every
// snapshot- or control-derived string goes through report.Escape or
// report.EscapeNoCut; the padded columns are ASCII.
func Table(p *Plan, color bool) []byte {
	var b strings.Builder
	s := p.Summary
	b.WriteString(report.HeaderLine(p.Run, p.Fix.MusterVersion, p.Fix.ControlsVersion, p.Fix.GuideEdition) + "\n")
	fmt.Fprintf(&b, "fix --dry-run · %s · max-risk %s\n", report.ProfileLine(p.Fix.Profile, p.Fix.Tuning), p.Fix.MaxRisk)
	fmt.Fprintf(&b, "planned %d (script %d, text only %d) · above max-risk %d · waived %d · clean %d · not planned: error %d, manual %d, warn_degraded %d\n",
		s.Planned, s.WithScript, s.TextOnly, s.AboveMaxRisk, s.Waived, s.Clean, s.NotPlanned.Error, s.NotPlanned.Manual, s.NotPlanned.WarnDegraded)
	fmt.Fprintf(&b, "by risk: none %d · restart_service %d · reboot_required %d · lockout_risk %d\n\n",
		s.ByRisk.None, s.ByRisk.RestartService, s.ByRisk.RebootRequired, s.ByRisk.LockoutRisk)
	if len(p.Items) == 0 {
		b.WriteString("nothing to fix\n")
	} else {
		numW, idW := len(strconv.Itoa(len(p.Items))), 2
		for _, it := range p.Items {
			if len(it.ID) > idW {
				idW = len(it.ID)
			}
		}
		fmt.Fprintf(&b, "%-*s  %-15s  %-*s  %-6s  %-6s  %-6s  %-14s  %s\n", numW, "#", "risk", idW, "id", "status", "sev", "script", "rollback", "title")
		for i, it := range p.Items {
			script, rb := "no", it.Rollback
			if it.Script {
				script = "yes"
			}
			if rb == "none" {
				rb = "-"
			}
			title := report.EscapeNoCut(report.Title(it.TitleKo, it.TitleEn))
			if !it.Planned {
				title += " (above max-risk)"
			}
			fmt.Fprintf(&b, "%-*d  %s  %-*s  %s  %-6s  %-6s  %-14s  %s\n", numW, i+1,
				report.Paint(color, riskColor[it.Risk], fmt.Sprintf("%-15s", it.Risk)),
				idW, it.ID,
				report.Paint(color, report.StatusColor(it.SourceStatus), fmt.Sprintf("%-6s", it.Status)),
				it.Severity, script, rb, title)
			fmt.Fprintf(&b, "   why: %s\n", report.Escape(it.Reason))
			do := report.EscapeNoCut(report.Title(it.TextKo, it.TextEn))
			if !it.Script {
				do += " (text only: " + it.TextOnlyReason + ")"
			}
			fmt.Fprintf(&b, "   do:  %s\n", do)
		}
	}
	if len(p.NotPlanned) > 0 {
		idW := 2
		for _, n := range p.NotPlanned {
			if len(n.ID) > idW {
				idW = len(n.ID)
			}
		}
		b.WriteString("\nnot planned:\n")
		for _, n := range p.NotPlanned {
			fmt.Fprintf(&b, "  %-*s  %-13s  %s\n", idW, n.ID, n.Status, report.Escape(n.Reason))
		}
	}
	return []byte(b.String())
}

// JSON renders the plan for a machine (spec §6 "JSON"): two-space indent,
// no HTML escaping, a trailing newline.
func JSON(p *Plan) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		panic(err) // a Plan always encodes: no channels, funcs or maps
	}
	return b.Bytes()
}
