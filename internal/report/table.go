package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/facts"
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

// MaxCell is the number of input runes Escape keeps before it cuts.
const MaxCell = 200

// beyondSeparator marks, in the row block, where the KISA guide's verdict
// ends and muster's own checks begin (B-9).
const beyondSeparator = "— beyond the guide —"

// scopeLine renders one scope's share of the summary block. The three pass/
// fail/warn numbers are the sum over the severities; manual, n/a, error and
// waived are the parts of the summary that carry no severity at all.
//
// Waived is printed because every control of a scope lands in exactly one of
// these seven buckets: without it the numbers do not sum to the count in
// front of them, and a reader who added them up would go looking for the
// control that went missing.
func scopeLine(c ScopeCounts) string {
	a := c.Automatic
	return fmt.Sprintf("(%d controls): pass %d fail %d warn %d manual %d n/a %d error %d waived %d",
		c.Controls,
		a.High.Pass+a.Medium.Pass+a.Low.Pass,
		a.High.Fail+a.Medium.Fail+a.Low.Fail,
		a.High.Warn+a.Medium.Warn+a.Low.Warn,
		c.ManualReview, c.Undecidable.NotApplicable, c.Undecidable.Error,
		c.Undecidable.Waived)
}

// escapeRune writes one rune the way Escape and EscapeNoCut render it: C0/C1
// controls, ESC and CR are spelled out; tabs survive.
func escapeRune(b *strings.Builder, r rune) {
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
		fmt.Fprintf(b, `\u%04x`, r)
	default:
		b.WriteRune(r)
	}
}

// Escape neutralises anything a hostile snapshot could use to repaint the
// terminal (spec §7.4) and cuts at MaxCell runes.
func Escape(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= MaxCell {
			b.WriteString("…")
			break
		}
		n++
		escapeRune(&b, r)
	}
	return b.String()
}

// EscapeNoCut is Escape without the cut: for control text, which is the
// plan's payload and is kept to one line by lint (stage 3D-2).
func EscapeNoCut(s string) string {
	var b strings.Builder
	for _, r := range s {
		escapeRune(&b, r)
	}
	return b.String()
}

// ProfileLine is the table's second line (spec §5 "Table"): the profile in
// force, how much of the control set it selects, and the tuning file. The
// name and the path are file-derived, so both go through Escape.
func ProfileLine(p ProfileBlock, t *TuningBlock) string {
	total := p.Selected + p.Excluded
	var s string
	if p.Excluded == 0 {
		s = fmt.Sprintf("profile %s (%d controls", Escape(p.Name), total)
	} else {
		s = fmt.Sprintf("profile %s (%d of %d, %d excluded", Escape(p.Name), p.Selected, total, p.Excluded)
	}
	if t != nil {
		s += "; tuning " + Escape(t.Path)
	}
	return s + ")"
}

// HeaderLine is the first line of check's table and of fix's (stage 3D-2),
// without its newline. The versions are the report block's, never run's.
// C1/R20: every string on this line is snapshot- or file-derived and a
// snapshot from a compromised host is a normal input (spec §7.4), so all of
// them go through Escape, not only the hostname.
func HeaderLine(run facts.Run, musterVersion, controlsVersion, guideEdition string) string {
	return fmt.Sprintf("muster %s · controls %s · guide %s · host %s · collected %s",
		Escape(musterVersion), Escape(controlsVersion), Escape(guideEdition),
		Escape(run.Host.Hostname), Escape(run.CollectedAt))
}

var statusColor = map[check.Status]string{
	check.PASS: "32", check.FAIL: "31", check.WARN: "33", check.ERROR: "35",
	check.MANUAL: "36", check.NotApplicable: "90", check.WAIVED: "90",
}

// StatusColor is the ANSI code check's table paints a status with.
func StatusColor(s check.Status) string { return statusColor[s] }

// Title is the table's title rule: Korean first, English when empty.
func Title(ko, en string) string {
	if ko == "" {
		return en
	}
	return ko
}

// Paint wraps s in the ANSI colour code when on; an empty code paints nothing.
func Paint(on bool, code, s string) string {
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
	fmt.Fprintln(w, HeaderLine(r.Run, r.Check.MusterVersion, r.Check.ControlsVersion, r.Check.GuideEdition))
	fmt.Fprintln(w, ProfileLine(r.Check.Profile, r.Check.Tuning))
	fmt.Fprintf(w, "automatic  high %d/%d/%d  medium %d/%d/%d  low %d/%d/%d  (pass/fail/warn)\n",
		s.Automatic.High.Pass, s.Automatic.High.Fail, s.Automatic.High.Warn,
		s.Automatic.Medium.Pass, s.Automatic.Medium.Fail, s.Automatic.Medium.Warn,
		s.Automatic.Low.Pass, s.Automatic.Low.Fail, s.Automatic.Low.Warn)
	fmt.Fprintf(w, "manual review %d  ·  undecidable error %d / n-a %d / waived %d  ·  facts failed %d  ·  waivers expiring within 30d %d\n",
		s.ManualReview, s.Undecidable.Error, s.Undecidable.NotApplicable, s.Undecidable.Waived, s.FactsFailed, s.WaiversExpiringSoon)
	// B-9: the exit code does not change, so the only way to see how much of
	// the verdict is the guide's and how much is muster's own is to say it.
	// The names are literals: "KISA 2026" is the guide these controls
	// implement, not the control set's own edition string.
	fmt.Fprintf(w, "KISA 2026 %s\n", scopeLine(s.Scopes.Guide))
	fmt.Fprintf(w, "beyond the guide %s\n\n", scopeLine(s.Scopes.Beyond))

	idWidth := 12
	for _, row := range r.Results {
		if l := displayWidth(Escape(row.ID)); l > idWidth {
			idWidth = l
		}
	}
	titleWidth := o.Width - 8 - 8 - idWidth - 4
	if titleWidth < 10 {
		titleWidth = 10
	}
	// B-9: the rows are sorted guide first, so one line marks where the
	// guide's verdict ends. It announces rows the reader is about to see, so
	// a run that shows no beyond row at all (--quiet, or a set without any)
	// prints no separator.
	separated := false
	for _, row := range r.Results {
		if hidden(o, row.Status) {
			continue
		}
		if !separated && scopeOf(row.Category) == "beyond" {
			fmt.Fprintf(w, "%s\n", beyondSeparator)
			separated = true
		}
		title := Title(row.TitleKo, row.TitleEn)
		status := Paint(o.Color, StatusColor(row.Status), padRight(Escape(string(row.Status)), 14))
		fmt.Fprintf(w, "%s %s %s  %s\n", status, padRight(Escape(row.Severity), 6), padRight(Escape(row.ID), idWidth), truncateWidth(Escape(title), titleWidth))
		if row.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", Escape(ReasonLine(row)))
		}
		if row.Waiver != nil {
			if row.Waiver.Applied {
				fmt.Fprintf(w, "    waived: %s (expires %s)\n", Escape(row.Waiver.Reason), orNone(Escape(row.Waiver.Expires)))
			} else {
				fmt.Fprintf(w, "    waiver not applied: %s\n", Escape(row.Waiver.NotAppliedBecause))
			}
		}
		if row.Status == check.FAIL || row.Status == check.WARN || row.Status == check.ERROR {
			for _, ev := range row.Evidence {
				// M9: a fact that is not ok has no value; naming the status is
				// the honest rendering, "= <nil>" is not.
				if ev.Status != facts.StatusOK {
					fmt.Fprintf(w, "    %s%s: %s%s\n", Escape(ev.Fact), sideSuffix(ev.Side), Escape(string(ev.Status)), sourceSuffix(ev))
					continue
				}
				fmt.Fprintf(w, "    %s%s = %s%s\n", Escape(ev.Fact), sideSuffix(ev.Side), Escape(fmt.Sprint(ev.Value)), sourceSuffix(ev))
			}
			shown := 0
			failing := 0
			for _, ob := range row.Observations {
				if ob.Verdict == "pass" {
					continue
				}
				failing++
				if shown < o.MaxObservations {
					fmt.Fprintf(w, "    %s: expected %v, actual %v (%s)\n", Escape(ob.Subject), Escape(fmt.Sprint(ob.Expected)), Escape(actualText(ob.Actual)), Escape(ob.Verdict))
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

// actualText renders an observation's actual value. M-5's missing-field
// observation carries none at all -- collection.go builds it with Actual nil
// and the JSON omits the field -- and fmt.Sprint would print a Go nil, which
// reads like a value the record held rather than a field it does not have
// (EV-2). The JSON is unchanged: this is the table's rendering of the
// observation, not the observation itself.
func actualText(v any) string {
	if v == nil {
		return "(no such field)"
	}
	return fmt.Sprint(v)
}

// ReasonLine is a row's reason as the table prints it: "[code] reason", or
// the bare reason when the row carries no code.
func ReasonLine(row Row) string {
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
	return "@" + Escape(side)
}

// sourceSuffix names the file and line, or the command, a value came from.
// C1: path and cmd are snapshot-controlled strings, so both are escaped.
func sourceSuffix(ev check.Evidence) string {
	if ev.Source == nil {
		return ""
	}
	switch {
	case ev.Source.Path != "" && ev.Source.Line > 0:
		return fmt.Sprintf("  (%s:%d)", Escape(ev.Source.Path), ev.Source.Line)
	case ev.Source.Path != "":
		return "  (" + Escape(ev.Source.Path) + ")"
	case ev.Source.Cmd != "":
		return "  (" + Escape(ev.Source.Cmd) + ")"
	}
	return ""
}
