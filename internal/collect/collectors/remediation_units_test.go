//go:build linux

package collectors

import (
	"regexp"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestServiceScriptsNameTheCollectorsUnits pins stage 3D-2 §3: a service
// control's script, validate and rollback name exactly the provesInstall
// units of its logical service's row, never a super-server unit.
func TestServiceScriptsNameTheCollectorsUnits(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]string{
		"muster.service.telnet_disabled":       {"telnet"},
		"muster.service.finger_disabled":       {"finger"},
		"muster.service.rservices_disabled":    {"rservices"},
		"muster.service.dos_services_disabled": {"dos_services"},
		"muster.service.nfs_server_disabled":   {"nfs_server"},
		"muster.service.automount_disabled":    {"automount"},
		"muster.service.rpcbind_disabled":      {"rpcbind"},
		"muster.service.nis_disabled":          {"nis"},
		"muster.service.tftp_talk_disabled":    {"tftp", "talk"},
		"muster.service.snmp_disabled":         {"snmp"},
	}
	byName := map[string]logicalService{}
	for _, s := range services {
		byName[s.name] = s
	}
	word := func(u string) *regexp.Regexp {
		return regexp.MustCompile(`(^|[\s"'])` + regexp.QuoteMeta(u) + `($|[\s"';])`)
	}
	for id, names := range rows {
		c, ok := set.ByID(id)
		if !ok || c.Remediation == nil {
			t.Fatalf("%s: no remediation", id)
		}
		r := c.Remediation
		for _, n := range names {
			svc, ok := byName[n]
			if !ok {
				t.Fatalf("%s: no logical service %q", id, n)
			}
			for _, u := range svc.units {
				for _, body := range []struct{ name, text string }{{"script", r.Script}, {"validate", r.Validate}, {"rollback", r.Rollback}} {
					has := word(u.name).MatchString(body.text)
					if u.provesInstall && !has {
						t.Errorf("%s: %s does not name %s", id, body.name, u.name)
					}
					if !u.provesInstall && has {
						t.Errorf("%s: %s names %s, a host of the service", id, body.name, u.name)
					}
				}
			}
		}
		for _, u := range append(append([]string{}, superServerExtraHostUnits...), "inetd.service", "xinetd.service") {
			if word(u).MatchString(r.Script) {
				t.Errorf("%s: script names super-server unit %s", id, u)
			}
		}
	}
}
