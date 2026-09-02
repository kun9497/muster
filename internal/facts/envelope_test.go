package facts

import (
	"encoding/json"
	"testing"
)

func TestStatusValidAndCanPass(t *testing.T) {
	cases := []struct {
		s       Status
		valid   bool
		canPass bool
	}{
		{StatusOK, true, true},
		{StatusAbsent, true, false},
		{StatusDenied, true, false},
		{StatusUnsupported, true, false},
		{StatusTimeout, true, false},
		{StatusError, true, false},
		{StatusMissing, false, false},
		{Status("bogus"), false, false},
	}
	for _, c := range cases {
		if got := c.s.Valid(); got != c.valid {
			t.Errorf("%q.Valid()=%v want %v", c.s, got, c.valid)
		}
		if got := c.s.CanPass(); got != c.canPass {
			t.Errorf("%q.CanPass()=%v want %v", c.s, got, c.canPass)
		}
	}
}

func TestEnvelopeJSONRoundTripKeepsFieldOrderAndOmitsEmpty(t *testing.T) {
	code := 0
	e := Envelope{
		Status: StatusOK,
		Value:  "no",
		Source: &Source{Kind: "file", Path: "/etc/ssh/sshd_config", Line: 2, Raw: "PermitRootLogin no", ExitCode: &code},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"status":"ok","value":"no","source":{"kind":"file","path":"/etc/ssh/sshd_config","line":2,"raw":"PermitRootLogin no","exit_code":0}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	var back Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Status != StatusOK || back.Value != "no" || back.Source.Line != 2 || *back.Source.ExitCode != 0 {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestDerivedSourceCarriesInputs(t *testing.T) {
	s := Source{Kind: "derived", Inputs: []Source{{Kind: "file", Path: "/etc/sysctl.d/99-a.conf", Line: 3}}}
	b, _ := json.Marshal(s)
	want := `{"kind":"derived","inputs":[{"kind":"file","path":"/etc/sysctl.d/99-a.conf","line":3}]}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
}

func TestSettingOmitsAbsentSides(t *testing.T) {
	s := Setting{Effective: &Envelope{Status: StatusOK, Value: "no"}}
	b, _ := json.Marshal(s)
	if string(b) != `{"effective":{"status":"ok","value":"no"}}` {
		t.Fatalf("got %s", b)
	}
}

func TestMissingEnvelope(t *testing.T) {
	m := Missing("sshd.options.permit_root_login")
	if m.Status != StatusMissing || m.Reason == "" {
		t.Fatalf("got %+v", m)
	}
}
