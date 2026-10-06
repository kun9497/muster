package check

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// W-13, W-31: a fixture carries no parameter override, so the relaxation each
// 3C-2b parameter offers is driven here, end to end, through Options.Params:
// the control's own fail fixture must FAIL with the shipped default and PASS
// once the operator names what the finding was about. Dropping the
// ${param} reference from a control, or the parameter from its params,
// goes red here.
func TestExposureControlsParams(t *testing.T) {
	for _, c := range []struct {
		id, fixture, param string
		value              any
	}{
		{"muster.beyond.exposed_listeners_allowed", "fail-ufw-folded-http.json", "allowed_ports", []any{"tcp/22", "udp/68", "udp/546", "tcp/80"}},
		{"muster.beyond.listeners_packaged", "fail-usr-local-daemon.json", "allowed_executables", []any{"/usr/local/sbin/mydaemon"}},
		{"muster.beyond.ip_forwarding_disabled", "fail-docker-host.json", "allowed_forward", []any{0, 1}},
		{"muster.beyond.ipv6_router_advertisements_ignored", "fail-stock-ubuntu.json", "allowed_accept_ra", []any{0, 1}},
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
