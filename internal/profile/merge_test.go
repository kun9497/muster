package profile

import (
	"testing"

	"github.com/kun9497/muster/internal/tuning"
)

func TestMergePrecedenceAndSources(t *testing.T) {
	src := "profile: x\nextends: default\nexclude: [\"muster.beyond.no_deleted_executables\"]\nparams:\n  muster.account.password_policy: {min_len: 12}\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n"
	r, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), noWarn(t))
	if err != nil {
		t.Fatal(err)
	}
	tn := &tuning.Tuning{Params: map[string]map[string]any{"muster.beyond.exposed_listeners_allowed": {"allowed_ports": []any{"tcp/22"}}}}
	params, sources := Merge(set(), r, tn, noWarn(t))
	if params["muster.account.password_policy"]["min_len"] != 12 || sources["muster.account.password_policy"]["min_len"] != "profile" {
		t.Errorf("profile value: %v %v", params["muster.account.password_policy"], sources["muster.account.password_policy"])
	}
	if got := params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"].([]any); len(got) != 1 || sources["muster.beyond.exposed_listeners_allowed"]["allowed_ports"] != "tuning" {
		t.Errorf("tuning wins over the profile: %v %v", got, sources)
	}
	if _, has := params["muster.file.world_writable"]; has {
		t.Errorf("a control without params has no entry")
	}
	if _, has := params["muster.beyond.no_deleted_executables"]; has {
		t.Errorf("an excluded control has no entry")
	}
	// Default values are present with source default.
	params2, sources2 := Merge(set(), r, nil, noWarn(t))
	if sources2["muster.beyond.exposed_listeners_allowed"]["allowed_ports"] != "profile" || params2["muster.account.password_policy"]["min_len"] != 12 {
		t.Errorf("nil tuning: %v %v", params2, sources2)
	}
	rd, _ := Resolve(set(), Source{Name: "default"}, nil, noWarn(t))
	p3, s3 := Merge(set(), rd, nil, noWarn(t))
	if p3["muster.account.password_policy"]["min_len"] != 8 || s3["muster.account.password_policy"]["min_len"] != "default" {
		t.Errorf("defaults: %v %v", p3, s3)
	}
}

func TestMergeWarnsAndDropsValuesForExcludedControls(t *testing.T) {
	src := "profile: x\nextends: default\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/443]\n"
	var warnings []string
	warn := func(m string) { warnings = append(warnings, m) }
	r, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), warn)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Resolve must not warn for params: %v", warnings)
	}
	if _, kept := r.Params["muster.beyond.exposed_listeners_allowed"]; !kept {
		t.Errorf("Resolve keeps every chain value: %v", r.Params)
	}
	tn := &tuning.Tuning{Params: map[string]map[string]any{"muster.beyond.exposed_listeners_allowed": {"allowed_ports": []any{"tcp/80"}}}}
	params, sources := Merge(set(), r, tn, warn)
	want := []string{
		"profile parameter muster.beyond.exposed_listeners_allowed.allowed_ports ignored: excluded by profile",
		"tuning parameter muster.beyond.exposed_listeners_allowed.allowed_ports ignored: excluded by profile",
	}
	if len(warnings) != 2 || warnings[0] != want[0] || warnings[1] != want[1] {
		t.Errorf("warnings %v, want %v", warnings, want)
	}
	if _, has := params["muster.beyond.exposed_listeners_allowed"]; has {
		t.Errorf("an excluded control has no entry: %v %v", params, sources)
	}
}
