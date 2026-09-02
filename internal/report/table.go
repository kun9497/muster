package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/muster/internal/check"
)

type TableOptions struct {
	Color           bool
	Width           int
	Quiet           bool
	MaxObservations int
}

// ColorEnabled applies the rules of spec §9: --color=always/never win;
// otherwise colour only on a TTY without NO_COLOR and not TERM=dumb.
func ColorEnabled(flag, noColorEnv, term string, isTTY bool) bool {
	switch flag {
	case "always":
		return true
	case "never":
		return false
	}
	return isTTY && noColorEnv == "" && term != "dumb"
}

const maxCell = 200

// escape neutralises anything a hostile snapshot could use to repaint the
// terminal (spec §7.4): C0/C1 controls, ESC, CR; tabs survive.
func escape(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxCell {
			b.WriteString("…")
			break
		}
		n++
		switch {
		case r == '\t':
			b.WriteRune(r)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == 0x1b:
			b.WriteString(`\x1b`)
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var statusColor = map[check.Status]string{
	check.PASS: "32", check.FAIL: "31", check.WARN: "33", check.ERROR: "35",
	check.MANUAL: "36", check.NotApplicable: "90", check.WAIVED: "90",
}

func paint(on bool, code, s string) string {
	if !on || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func hidden(o TableOptions, s check.Status) bool {
	if !o.Quiet {
		return false
	}
	switch s {
	case check.PASS, check.NotApplicable, check.WAIVED, check.MANUAL:
		return true
	}
	return false
}

// WriteTable renders the summary block and one row per result (spec §9).
func WriteTable(w io.Writer, r *Report, o TableOptions) error {
	if o.Width <= 0 {
		o.Width = 100
	}
	if o.MaxObservations <= 0 {
		o.MaxObservations = 5
	}
	s := r.Summary
	fmt.Fprintf(w, "muster %s · controls %s · guide %s · host %s · collected %s\n",
		r.Check.MusterVersion, r.Check.ControlsVersion, r.Check.GuideEdition, escape(r.Run.Host.Hostname), r.Run.CollectedAt)
	fmt.Fprintf(w, "automatic  high %d/%d/%d  medium %d/%d/%d  low %d/%d/%d  (pass/fail/warn)\n",
		s.Automatic.High.Pass, s.Automatic.High.Fail, s.Automatic.High.Warn,
		s.Automatic.Medium.Pass, s.Automatic.Medium.Fail, s.Automatic.Medium.Warn,
		s.Automatic.Low.Pass, s.Automatic.Low.Fail, s.Automatic.Low.Warn)
	fmt.Fprintf(w, "manual review %d  ·  undecidable error %d / n-a %d / waived %d  ·  facts failed %d  ·  waivers expiring within 30d %d\n\n",
		s.ManualReview, s.Undecidable.Error, s.Undecidable.NotApplicable, s.Undecidable.Waived, s.FactsFailed, s.WaiversExpiringSoon)

	idWidth := 12
	for _, row := range r.Results {
		if l := len(row.ID); l > idWidth {
			idWidth = l
		}
	}
	titleWidth := o.Width - 8 - 8 - idWidth - 4
	if titleWidth < 10 {
		titleWidth = 10
	}
	for _, row := range r.Results {
		if hidden(o, row.Status) {
			continue
		}
		title := row.TitleKo
		if title == "" {
			title = row.TitleEn
		}
		status := paint(o.Color, statusColor[row.Status], padRight(string(row.Status), 14))
		fmt.Fprintf(w, "%s %s %s  %s\n", status, padRight(row.Severity, 6), padRight(row.ID, idWidth), truncateWidth(escape(title), titleWidth))
		if row.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", escape(reasonLine(row)))
		}
		if row.Waiver != nil {
			if row.Waiver.Applied {
				fmt.Fprintf(w, "    waived: %s (expires %s)\n", escape(row.Waiver.Reason), orNone(row.Waiver.Expires))
			} else {
				fmt.Fprintf(w, "    waiver not applied: %s\n", escape(row.Waiver.NotAppliedBecause))
			}
		}
		if row.Status == check.FAIL || row.Status == check.WARN || row.Status == check.ERROR {
			for _, ev := range row.Evidence {
				fmt.Fprintf(w, "    %s%s = %s%s\n", ev.Fact, sideSuffix(ev.Side), escape(fmt.Sprint(ev.Value)), sourceSuffix(ev))
			}
			shown := 0
			failing := 0
			for _, ob := range row.Observations {
				if ob.Verdict == "pass" {
					continue
				}
				failing++
				if shown < o.MaxObservations {
					fmt.Fprintf(w, "    %s: expected %v, actual %v (%s)\n", escape(ob.Subject), ob.Expected, escape(fmt.Sprint(ob.Actual)), ob.Verdict)
					shown++
				}
			}
			if failing > shown {
				fmt.Fprintf(w, "    (+%d more, use --all)\n", failing-shown)
			}
		}
	}
	return nil
}

func reasonLine(row Row) string {
	if row.ReasonCode != "" {
		return fmt.Sprintf("[%s] %s", row.ReasonCode, row.Reason)
	}
	return row.Reason
}

func orNone(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

func sideSuffix(side string) string {
	if side == "" {
		return ""
	}
	return "@" + side
}

func sourceSuffix(ev check.Evidence) string {
	if ev.Source == nil {
		return ""
	}
	switch {
	case ev.Source.Path != "" && ev.Source.Line > 0:
		return fmt.Sprintf("  (%s:%d)", ev.Source.Path, ev.Source.Line)
	case ev.Source.Path != "":
		return "  (" + ev.Source.Path + ")"
	case ev.Source.Cmd != "":
		return "  (" + ev.Source.Cmd + ")"
	}
	return ""
}
