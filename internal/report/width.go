package report

import "strings"

// wide lists East Asian wide/fullwidth ranges (inclusive). Korean item titles
// are the common case (spec §9).
var wide = [][2]rune{
	{0x1100, 0x115F}, {0x2E80, 0x303E}, {0x3041, 0x33FF}, {0x3400, 0x4DBF},
	{0x4E00, 0x9FFF}, {0xAC00, 0xD7A3}, {0xF900, 0xFAFF}, {0xFF00, 0xFF60},
	{0xFFE0, 0xFFE6}, {0x20000, 0x3FFFD},
}

func runeWidth(r rune) int {
	if r >= 0x0300 && r <= 0x036F {
		return 0
	}
	for _, rg := range wide {
		if r >= rg[0] && r <= rg[1] {
			return 2
		}
	}
	return 1
}

func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func padRight(s string, width int) string {
	if d := width - displayWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// truncateWidth cuts s so it fits width, appending "…" if anything was cut.
func truncateWidth(s string, width int) string {
	if displayWidth(s) <= width {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := runeWidth(r)
		if w+rw > width-1 {
			break
		}
		b.WriteRune(r)
		w += rw
	}
	return b.String() + "…"
}
