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

func TestResolveMissingWhenIntermediateIsNotObject(t *testing.T) {
	r, _ := LoadRegistry()
	s, _ := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{"walk": 5}}`))
	got, err := r.Resolve(s, "walk.complete")
	if err != nil || got.Envelope.Status != StatusMissing {
		t.Fatalf("%+v err=%v", got, err)
	}
}
