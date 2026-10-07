package tuning

import (
	"crypto/sha256"
	"encoding/hex"
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
	sum := sha256.Sum256([]byte(src))
	if want := "sha256:" + hex.EncodeToString(sum[:]); tn.Path != "site/tuning.yaml" || tn.Digest != want {
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
	cases := map[string]struct{ src, want string }{
		"unknown key":        {"params: {}\nseverity: []\n", "field severity not found in type tuning.File"},
		"unknown control":    {"params:\n  muster.no.such:\n    x: 1\n", `params name unknown control "muster.no.such"`},
		"unknown parameter":  {"params:\n  muster.account.password_policy:\n    max_len: 1\n", `control "muster.account.password_policy" has no parameter "max_len"`},
		"wrong type":         {"params:\n  muster.account.password_policy:\n    min_len: twelve\n", "muster.account.password_policy.min_len: value twelve is not a int"},
		"list of wrong kind": {"params:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [22]\n", "allowed_ports: value [22] is not a list<string>"},
		"not a map":          {"params: 3\n", "cannot unmarshal !!int `3` into map[string]map[string]interface {}"},
	}
	for name, c := range cases {
		_, err := Load(set(), "t.yaml", openString(c.src))
		if err == nil {
			t.Errorf("%s: Load accepted %q", name, c.src)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error %v should wrap ErrInvalid", name, err)
		}
		if msg := err.Error(); !strings.Contains(msg, "invalid tuning file: t.yaml: ") || !strings.Contains(msg, c.want) {
			t.Errorf("%s: error %q should name the path and say %q", name, msg, c.want)
		}
	}
}

func TestValidateFirstErrorIsDeterministic(t *testing.T) {
	for i := 0; i < 10; i++ {
		err := Validate(set(), map[string]map[string]any{"z.x": {"p": 1}, "a.x": {"p": 1}, "m.x": {"p": 1}})
		if err == nil || err.Error() != `params name unknown control "a.x"` {
			t.Fatalf("run %d: unknown ids: %v, want the first id in order (a.x)", i, err)
		}
		err = Validate(set(), map[string]map[string]any{"muster.account.password_policy": {"zz": 1, "bb": 1}})
		if err == nil || err.Error() != `control "muster.account.password_policy" has no parameter "bb"` {
			t.Fatalf("run %d: unknown parameters: %v, want the first name in order (bb)", i, err)
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
