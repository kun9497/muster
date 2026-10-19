//go:build linux

package collectors

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// unitToken is a systemd unit name a remediation body can carry.
var unitToken = regexp.MustCompile(`[A-Za-z0-9@_.-]+\.(service|socket)`)

// TestServiceScriptsNameTheCollectorsUnits pins 3D-2b §3 for every
// units-declaring control (eleven: ten disable, one enables, 3D-2d O-5): it
// declares as units exactly the provesInstall units of its services rows (as
// a set; the order is the control's, socket before service), its validate
// names exactly those, its script names none literally (it loops over
// $UNITS), and it has no rollback (the unit state is the way back).
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
		"muster.beyond.auditd_active":          {"auditd"},
	}
	byName := map[string]logicalService{}
	for _, s := range services {
		byName[s.name] = s
	}
	declaring := 0
	for _, c := range set.Controls {
		if c.Remediation != nil && len(c.Remediation.Units) > 0 {
			declaring++
			if _, ok := rows[c.ID]; !ok {
				t.Errorf("%s declares units but is not mapped to a services row", c.ID)
			}
		}
	}
	if declaring != 11 || len(rows) != 11 {
		t.Fatalf("%d controls declare units, %d mapped; want 11 and 11", declaring, len(rows))
	}
	for id, names := range rows {
		c, ok := set.ByID(id)
		if !ok || c.Remediation == nil {
			t.Fatalf("%s: no remediation", id)
		}
		r := c.Remediation
		own := map[string]bool{}
		for _, n := range names {
			svc, ok := byName[n]
			if !ok {
				t.Fatalf("%s: no logical service %q", id, n)
			}
			for _, u := range svc.units {
				if u.provesInstall {
					own[u.name] = true
				}
			}
		}
		declared := map[string]bool{}
		for _, u := range r.Units {
			declared[u] = true
		}
		if !sameSet(declared, own) {
			t.Errorf("%s: units %v, want the provesInstall set %v", id, r.Units, keys(own))
		}
		inValidate := map[string]bool{}
		for _, u := range unitToken.FindAllString(r.Validate, -1) {
			inValidate[u] = true
		}
		if !sameSet(inValidate, own) {
			t.Errorf("%s: validate names %v, want %v", id, keys(inValidate), keys(own))
		}
		if us := unitToken.FindAllString(r.Script, -1); len(us) != 0 {
			t.Errorf("%s: script names %v literally; it must loop over $UNITS", id, us)
		}
		if strings.TrimSpace(r.Rollback) != "" {
			t.Errorf("%s: has a rollback; units are the way back", id)
		}
		for _, u := range append(append([]string{}, superServerExtraHostUnits...), "inetd.service", "xinetd.service") {
			if declared[u] {
				t.Errorf("%s: declares super-server unit %s", id, u)
			}
		}
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
