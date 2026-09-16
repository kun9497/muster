package check

import (
	"bytes"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// embedded returns the control the embedded set ships under id, so a test
// pins the shipped judgment rather than a control the test wrote itself.
func embedded(t *testing.T, id string) controls.Control {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for i := range set.Controls {
		if set.Controls[i].ID == id {
			return set.Controls[i]
		}
	}
	t.Fatalf("the embedded set has no %s", id)
	return controls.Control{}
}

// suidSnapshot is one host whose only setuid file is a packaged /usr/bin/su
// that the package declares setuid -- a PASS for muster.file.suid_sgid as it
// ships, and therefore a host on which only the parameter can produce a
// finding.
const suidSnapshot = `{"schema_version":1,"run":{"deep":true},"facts":{"walk":{
  "complete":{"status":"ok","value":true},
  "sticky_missing":{"status":"ok","value":[]},
  "suid_sgid":{"status":"ok","value":[
    {"path":"/usr/bin/su","mode":2541,"uid":0,"gid":0,"setuid":true,"setgid":false,
     "package":"util-linux","package_declared":true,"declared_mode":2541,
     "declared_owner":"root","declared_group":"root","declared_path":"/usr/bin/su",
     "reference":"rpmdb"}]}}}}`

// W-9: forbidden_suid is the operator's own list of bits no package
// declaration excuses. It has no default and no fixture can exercise it, so
// this is the only place the parameter is driven end to end: the same
// snapshot must PASS with the shipped default and FAIL naming the path once
// the operator names it. Deleting the second `none` clause from the control,
// or dropping the ${forbidden_suid} reference, goes red here.
func TestSuidSgidForbiddenParam(t *testing.T) {
	ctrl := embedded(t, "muster.file.suid_sgid")
	snap, err := facts.Load(bytes.NewReader([]byte(suidSnapshot)))
	if err != nil {
		t.Fatal(err)
	}

	base := Evaluate(snap, one(ctrl), reg, Options{})[0]
	if base.Status != PASS {
		t.Fatalf("with the shipped default the host is clean: status=%s (%s: %s)", base.Status, base.ReasonCode, base.Reason)
	}

	withParam := Evaluate(snap, one(ctrl), reg, Options{Params: map[string]map[string]any{
		"muster.file.suid_sgid": {"forbidden_suid": []any{"/usr/bin/su"}},
	}})[0]
	if withParam.Status != FAIL {
		t.Fatalf("a forbidden path must fail even though the package declares it: status=%s (%s: %s)", withParam.Status, withParam.ReasonCode, withParam.Reason)
	}
	var subjects []string
	for _, o := range withParam.Observations {
		subjects = append(subjects, o.Subject)
	}
	found := false
	for _, s := range subjects {
		if s == "file:/usr/bin/su" {
			found = true
		}
	}
	if !found {
		t.Errorf("the finding must name the path the operator forbade; observations: %v", subjects)
	}
}
