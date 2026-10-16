package controls_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// sedPExpr is a sed s-expression (any of the delimiters the bodies use) that
// carries a P_ variable: a parameter value would become sed program text.
var sedPExpr = regexp.MustCompile(`\bsed\b.*\bs[/|#,:].*P_`)

// TestShippedBodiesPlaceParametersSafely (S-30): a parameter value reaches a
// body only as data. No Script, Validate or Rollback line starts with a P_
// variable (it would run as a command word), and no sed s-expression
// carries one (it would run as sed program text).
func TestShippedBodiesPlaceParametersSafely(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	uses := 0
	for _, c := range set.Controls {
		r := c.Remediation
		if r == nil {
			continue
		}
		for _, b := range []struct{ name, v string }{{"script", r.Script}, {"validate", r.Validate}, {"rollback", r.Rollback}} {
			for i, l := range strings.Split(b.v, "\n") {
				l = strings.TrimSpace(l)
				if strings.Contains(l, "P_") {
					uses++
				}
				for _, p := range []string{"$P_", "${P_", `"$P_`, `"${P_`} {
					if strings.HasPrefix(l, p) {
						t.Errorf("%s %s line %d starts with a parameter: %s", c.ID, b.name, i+1, l)
					}
				}
				if sedPExpr.MatchString(l) {
					t.Errorf("%s %s line %d puts a parameter into a sed expression: %s", c.ID, b.name, i+1, l)
				}
			}
		}
	}
	if uses == 0 {
		t.Fatal("no shipped body reads a parameter; the scan proves nothing")
	}
}

// TestShippedFindsCarryATypePredicate (S-30): a find that runs chmod or chown
// names the type it acts on (-type f, -type d) or excludes links (! -type l),
// so it never changes a symlink's target, which chmod(1) would follow.
func TestShippedFindsCarryATypePredicate(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	finds := 0
	for _, c := range set.Controls {
		r := c.Remediation
		if r == nil {
			continue
		}
		for _, b := range []struct{ name, v string }{{"script", r.Script}, {"rollback", r.Rollback}} {
			for i, l := range strings.Split(b.v, "\n") {
				if !strings.Contains(l, "find ") || (!strings.Contains(l, "-exec chmod") && !strings.Contains(l, "-exec chown")) {
					continue
				}
				finds++
				if !strings.Contains(l, "! -type l") && !strings.Contains(l, "-type f") && !strings.Contains(l, "-type d") {
					t.Errorf("%s %s line %d runs chmod or chown from a find with no type predicate: %s", c.ID, b.name, i+1, strings.TrimSpace(l))
				}
			}
		}
	}
	if finds == 0 {
		t.Fatal("no shipped body runs chmod or chown from a find; the scan proves nothing")
	}
}
