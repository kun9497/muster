package controls_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestFileValidatesAcceptTheDefaultModes pins 3D-2b §5: each file control's
// validate is one case over its stat format whose patterns are exactly its
// default modes, unpadded octal, behind a fixed owner prefix, ending *) false.
func TestFileValidatesAcceptTheDefaultModes(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string][2]string{ // id -> {stat format, owner prefix}
		"muster.file.hosts_permissions":     {"%u %g %a", "0 0"},
		"muster.file.hosts_lpd_permissions": {"%u %g %a", "0 0"},
		"muster.file.passwd_permissions":    {"%u %g %a", "0 0"},
		"muster.file.services_permissions":  {"%u %g %a", "0 0"},
		"muster.file.shadow_permissions":    {"%u %a", "0"},
	}
	shipped := map[string]bool{}
	for i := range set.Controls {
		c := &set.Controls[i]
		if c.Category == "file" && c.Remediation != nil && strings.TrimSpace(c.Remediation.Script) != "" {
			shipped[c.ID] = true
		}
	}
	if len(shipped) != 5 || len(owners) != 5 {
		t.Fatalf("scripted file controls %v, want exactly the five of the owner table", shipped)
	}
	for id := range shipped {
		if _, ok := owners[id]; !ok {
			t.Errorf("%s: scripted file control missing from the owner table", id)
		}
	}
	for id, o := range owners {
		c, ok := set.ByID(id)
		if !ok || c.Remediation == nil || len(c.Remediation.Backup) != 1 {
			t.Fatalf("%s: want one backup path", id)
		}
		var modes []any
		if p, ok := c.Params["allowed_modes"]; ok {
			modes, _ = p.Default.([]any)
			if modes == nil {
				t.Fatalf("%s: allowed_modes default is %T, want a list", id, p.Default)
			}
		} else {
			modes = modeClauseList(t, c) // passwd: the literal list of its mode clause
		}
		pats := make([]string, len(modes))
		for i, m := range modes {
			pats[i] = "'" + o[1] + " " + strconv.FormatInt(int64(toInt(t, m)), 8) + "'"
		}
		want := `case "$(stat -c '` + o[0] + `' ` + c.Remediation.Backup[0] + `)" in ` + strings.Join(pats, "|") + ") ;; *) false;; esac"
		if got := strings.TrimSuffix(c.Remediation.Validate, "\n"); got != want {
			t.Errorf("%s:\n got %s\nwant %s", id, got, want)
		}
	}
}

// modeClauseList returns the literal list of the control's `.mode` `in` check.
func modeClauseList(t *testing.T, c *controls.Control) []any {
	t.Helper()
	for _, cl := range c.Checks {
		if strings.HasSuffix(cl.Fact, ".mode") && cl.Op == "in" {
			l, ok := cl.Expected.([]any)
			if !ok {
				t.Fatalf("%s: mode clause expected is %T, want a list", c.ID, cl.Expected)
			}
			return l
		}
	}
	t.Fatalf("%s: no `.mode` `in` check", c.ID)
	return nil
}

func toInt(t *testing.T, v any) int {
	t.Helper()
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case uint64:
		return int(x)
	case float64:
		return int(x)
	}
	t.Fatalf("mode value of type %T", v)
	return 0
}
