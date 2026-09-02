package facts

import (
	"errors"
	"strings"
	"testing"
)

func TestRegistryLoadsAndIndexesKeys(t *testing.T) {
	r, err := LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := r.Lookup("sshd.options.permit_root_login")
	if !ok {
		t.Fatal("key not found")
	}
	if e.Type != "setting<string>" || e.DefaultOn != "effective" || !r.IsSetting(e) {
		t.Errorf("entry %+v", e)
	}
	if _, ok := r.Lookup("nope.nothing"); ok {
		t.Error("unregistered key must not resolve")
	}
	for _, e := range r.Keys {
		if e.Since < 1 || e.Sensitivity == "" || e.Collector == "" || e.Description == "" {
			t.Errorf("entry %q is incomplete: %+v", e.Key, e)
		}
	}
}

func TestResolveEnvelopeSettingAndMissing(t *testing.T) {
	r, _ := LoadRegistry()
	s, err := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{
	  "services": {"ssh": {"installed": {"status":"ok","value":true}}},
	  "sshd": {"options": {"permit_root_login": {
	      "runtime": {"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}},
	      "effective": {"status":"ok","value":"no"}}}}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(s, "services.ssh.installed")
	if err != nil || got.Envelope == nil || got.Envelope.Status != StatusOK || got.Envelope.Value != true {
		t.Fatalf("envelope: %+v err=%v", got, err)
	}
	got, err = r.Resolve(s, "sshd.options.permit_root_login")
	if err != nil || got.Setting == nil || got.Setting.Effective.Value != "no" || got.Setting.Persisted != nil {
		t.Fatalf("setting: %+v err=%v", got, err)
	}
	got, err = r.Resolve(s, "walk.complete")
	if err != nil || got.Envelope == nil || got.Envelope.Status != StatusMissing {
		t.Fatalf("missing: %+v err=%v", got, err)
	}
	if _, err := r.Resolve(s, "not.registered"); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("err=%v want ErrUnregistered", err)
	}
}

func TestResolveMalformedLeafIsError(t *testing.T) {
	r, _ := LoadRegistry()
	s, _ := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{"walk":{"complete": true}}}`))
	got, err := r.Resolve(s, "walk.complete")
	if err != nil || got.Envelope.Status != StatusError || !strings.Contains(got.Envelope.Reason, "malformed") {
		t.Fatalf("%+v err=%v", got, err)
	}
}

// I4: `status` is a closed vocabulary of six values a collector may write
// (spec §5.2). Anything else — a forged value, or the reader-only "missing"
// — is a malformed fact, not something the derivation table may interpret.
func TestResolveRejectsAStatusNoCollectorMayWrite(t *testing.T) {
	r, _ := LoadRegistry()
	for _, c := range []struct{ name, status string }{{"forged", "bogus"}, {"reader-side only", "missing"}, {"empty", ""}} {
		s, err := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{"walk":{"complete":{"status":"` + c.status + `","value":true}}}}`))
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Resolve(s, "walk.complete")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got.Envelope.Status != StatusError || !strings.Contains(got.Envelope.Reason, "unknown status") {
			t.Errorf("%s status %q: %+v", c.name, c.status, got.Envelope)
		}
	}
}

func TestResolveRejectsAnUnknownStatusOnEitherSettingSide(t *testing.T) {
	r, _ := LoadRegistry()
	s, err := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{"accounts":{"login_defs":{"pass_max_days":{
	  "runtime":{"status":"ok","value":90},"persisted":{"status":"missing"}}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(s, "accounts.login_defs.pass_max_days")
	if err != nil || got.Setting == nil {
		t.Fatalf("%+v err=%v", got, err)
	}
	if got.Setting.Runtime.Status != StatusOK {
		t.Errorf("a good side must survive: %+v", got.Setting.Runtime)
	}
	if got.Setting.Persisted.Status != StatusError || !strings.Contains(got.Setting.Persisted.Reason, "unknown status") {
		t.Errorf("forged side: %+v", got.Setting.Persisted)
	}
}

func TestResolveMissingWhenIntermediateIsNotObject(t *testing.T) {
	r, _ := LoadRegistry()
	s, _ := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{"walk": 5}}`))
	got, err := r.Resolve(s, "walk.complete")
	if err != nil || got.Envelope.Status != StatusMissing {
		t.Fatalf("%+v err=%v", got, err)
	}
}
