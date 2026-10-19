package controls_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestModuleScriptsNameTheControlsModules pins 3D-2c §5: a control's modules
// list is its where list, and the body and validate loop over exactly it.
func TestModuleScriptsNameTheControlsModules(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range set.Controls {
		r := c.Remediation
		if r == nil || len(r.Modules) == 0 {
			continue
		}
		n++
		var where []string
		for _, x := range c.Checks[0].Where.Expected.([]any) {
			where = append(where, fmt.Sprint(x))
		}
		if strings.Join(r.Modules, " ") != strings.Join(where, " ") {
			t.Errorf("%s: modules %v, where %v", c.ID, r.Modules, where)
		}
		list := "mods='" + strings.Join(where, " ") + "'"
		for _, body := range []string{r.Script, r.Validate} {
			if !strings.Contains(body, list) || !strings.Contains(body, "for m in $mods; do") {
				t.Errorf("%s: script or validate does not set %s and loop over it", c.ID, list)
			}
		}
	}
	if n != 3 {
		t.Errorf("%d controls declare modules, want 3", n)
	}
}
