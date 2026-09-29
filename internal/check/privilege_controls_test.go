package check

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// P-9, V-13: a fixture carries no parameter override, so the relaxation each
// 3C-2a parameter offers is driven here, end to end, through Options.Params:
// the control's own fail fixture must FAIL with the shipped default and PASS
// once the operator names what the finding was about. Dropping the
// ${param} reference from a control, or the parameter from its params,
// goes red here.
func TestPrivilegeControlsParams(t *testing.T) {
	for _, c := range []struct {
		id, fixture, param string
		value              any
	}{
		{"muster.beyond.sudo_nopasswd_all", "fail-cloud-init.json", "allowed_nopasswd_principals", []any{"ubuntu"}},
		{"muster.beyond.ld_so_preload_empty", "fail-entry.json", "allowed_preload", []any{"/usr/local/lib/libhide.so"}},
		{"muster.beyond.container_runtime_access", "fail-docker-member.json", "allowed_runtime_group_members", []any{"runner"}},
		{"muster.beyond.ssh_key_quality", "fail-rsa-2047.json", "min_rsa_bits", 1024},
	} {
		t.Run(c.id, func(t *testing.T) {
			ctrl := embedded(t, c.id)
			f, err := os.Open(filepath.Join("..", "..", "controls", "testdata", c.id, c.fixture))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			snap, err := facts.Load(f)
			if err != nil {
				t.Fatal(err)
			}
			base := Evaluate(snap, one(ctrl), reg, Options{})[0]
			if base.Status != FAIL {
				t.Fatalf("with the shipped default %s must FAIL: status=%s (%s: %s)", c.fixture, base.Status, base.ReasonCode, base.Reason)
			}
			relaxed := Evaluate(snap, one(ctrl), reg, Options{Params: map[string]map[string]any{
				c.id: {c.param: c.value},
			}})[0]
			if relaxed.Status != PASS {
				t.Fatalf("%s=%v must turn %s into PASS: status=%s (%s: %s)", c.param, c.value, c.fixture, relaxed.Status, relaxed.ReasonCode, relaxed.Reason)
			}
		})
	}
}
