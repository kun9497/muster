package tuning

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func set() *controls.Set {
	s := &controls.Set{Controls: []controls.Control{
		{ID: "muster.account.password_policy", Params: map[string]controls.Param{"min_len": {Type: "int", Default: 8}}},
		{ID: "muster.beyond.exposed_listeners_allowed", Params: map[string]controls.Param{"allowed_ports": {Type: "list<string>", Default: []any{"tcp/22"}}}},
		{ID: "muster.file.world_writable"},
	}}
	return s.Subset([]string{"muster.account.password_policy", "muster.beyond.exposed_listeners_allowed", "muster.file.world_writable"})
}

func openString(src string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return []byte(src), nil }
}

func TestLoadReadsValidatesAndDigests(t *testing.T) {
	src := "params:\n  muster.account.password_policy:\n    min_len: 12\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n"
	tn, err := Load(set(), "site/tuning.yaml", openString(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tn.Path != "site/tuning.yaml" || !strings.HasPrefix(tn.Digest, "sha256:") {
		t.Errorf("path/digest %q %q", tn.Path, tn.Digest)
	}
	if tn.Params["muster.account.password_policy"]["min_len"] != 12 {
		t.Errorf("min_len = %#v, want int 12", tn.Params["muster.account.password_policy"]["min_len"])
	}
	ports, ok := tn.Params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"].([]any)
	if !ok || len(ports) != 2 || ports[1] != "tcp/443" {
		t.Errorf("allowed_ports = %#v, want []any{tcp/22, tcp/443}", tn.Params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"])
	}
	tn2, _ := Load(set(), "elsewhere.yaml", openString(src))
	if tn2.Digest != tn.Digest {
		t.Errorf("digest depends on the path: %s vs %s", tn.Digest, tn2.Digest)
	}
}

func TestLoadRefusals(t *testing.T) {
	cases := map[string]string{
		"unknown key":        "params: {}\nseverity: []\n", // the error must name the key: asserted below
		"unknown control":    "params:\n  muster.no.such:\n    x: 1\n",
		"unknown parameter":  "params:\n  muster.account.password_policy:\n    max_len: 1\n",
		"wrong type":         "params:\n  muster.account.password_policy:\n    min_len: twelve\n",
		"list of wrong kind": "params:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [22]\n",
		"not a map":          "params: 3\n",
	}
	for name, src := range cases {
		_, err := Load(set(), "t.yaml", openString(src))
		if err == nil {
			t.Errorf("%s: Load accepted %q", name, src)
			continue
		}
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "t.yaml") {
			t.Errorf("%s: error %v should wrap ErrInvalid and name the path", name, err)
		}
		if name == "unknown key" && !strings.Contains(err.Error(), "severity") {
			t.Errorf("the unknown key must be named: %v", err)
		}
	}
}

func TestLoadOpenErrorAndEmptyFile(t *testing.T) {
	if _, err := Load(set(), "missing.yaml", func(string) ([]byte, error) { return nil, os.ErrNotExist }); err == nil {
		t.Errorf("Load swallowed the open error")
	}
	tn, err := Load(set(), "empty.yaml", openString(""))
	if err != nil || len(tn.Params) != 0 {
		t.Errorf("an empty file is a tuning with no params: %v %v", tn, err)
	}
}
