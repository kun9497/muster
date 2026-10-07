package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func set() *controls.Set {
	s := &controls.Set{Version: "v", Digest: "sha256:d", Controls: []controls.Control{
		{ID: "muster.account.password_policy", Importance: "상", Params: map[string]controls.Param{"min_len": {Type: "int", Default: 8}}},
		{ID: "muster.beyond.exposed_listeners_allowed", Importance: "중", Params: map[string]controls.Param{"allowed_ports": {Type: "list<string>", Default: []any{"tcp/22"}}, "allowed_foo": {Type: "list<int>", Default: []any{1}}}},
		{ID: "muster.beyond.no_deleted_executables", Importance: "중"},
		{ID: "muster.file.ip_port_restriction", Importance: "상"},
		{ID: "muster.file.world_writable", Importance: "하"},
	}}
	return s.Subset([]string{"muster.account.password_policy", "muster.beyond.exposed_listeners_allowed", "muster.beyond.no_deleted_executables", "muster.file.ip_port_restriction", "muster.file.world_writable"})
}

// files is an in-memory filesystem for open. Keys are written with forward
// slashes; the lookup normalises the opened path to that spelling so the
// helper works on Windows, where filepath.Clean rewrites the separator
// (Z-11). An absolute key must be given as filepath.ToSlash of the path.
func files(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if s, ok := m[filepath.ToSlash(filepath.Clean(p))]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
}

func noWarn(t *testing.T) func(string) {
	return func(msg string) { t.Errorf("unexpected warning %q", msg) }
}

func TestResolveBuiltinDefaultAndAlias(t *testing.T) {
	for _, name := range []string{"default", "kisa-unix-2026"} {
		r, err := Resolve(set(), Source{Name: name}, nil, noWarn(t))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Name != "default" || r.Source != "builtin" || len(r.Chain) != 1 || r.Chain[0] != "builtin:default" {
			t.Errorf("%s: name/source/chain %q %q %v", name, r.Name, r.Source, r.Chain)
		}
		if len(r.IDs) != 5 || r.IDs[0] != "muster.account.password_policy" {
			t.Errorf("%s: ids %v", name, r.IDs)
		}
		if len(r.SeverityByID) != 0 || len(r.Params) != 0 {
			t.Errorf("%s: the built-in sets no severity or params", name)
		}
	}
}

func TestResolveChainIncludeExcludeParamsSeverity(t *testing.T) {
	fs := files(map[string]string{
		"profiles/base.yaml": "profile: base\nextends: default\nexclude: [\"muster.beyond.*\"]\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n",
		"profiles/site.yaml": "profile: site\nextends: base.yaml\ninclude: [muster.beyond.exposed_listeners_allowed]\nparams:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n  muster.beyond.no_deleted_executables: {}\nseverity:\n  - { controls: muster.file.world_writable, level: high }\n",
	})
	r, err := Resolve(set(), Source{Path: "profiles/site.yaml"}, fs, noWarn(t))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantIDs := []string{"muster.account.password_policy", "muster.beyond.exposed_listeners_allowed", "muster.file.ip_port_restriction", "muster.file.world_writable"}
	if strings.Join(r.IDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("ids %v, want %v (the child re-includes one beyond control)", r.IDs, wantIDs)
	}
	wantChain := []string{"builtin:default", "file:" + filepath.Clean("profiles/base.yaml"), "file:profiles/site.yaml"}
	if strings.Join(r.Chain, ",") != strings.Join(wantChain, ",") {
		t.Errorf("chain %v, want %v", r.Chain, wantChain)
	}
	if r.Source != "file:profiles/site.yaml" || r.Name != "site" {
		t.Errorf("source/name %q %q", r.Source, r.Name)
	}
	if r.SeverityByID["muster.file.world_writable"] != "high" || r.SeverityByID["muster.file.ip_port_restriction"] != "low" {
		t.Errorf("severity map %v: the later entry wins, the earlier still applies elsewhere", r.SeverityByID)
	}
	if _, has := r.SeverityByID["muster.account.password_policy"]; has {
		t.Errorf("an unmatched control has no severity entry: %v", r.SeverityByID)
	}
	if got := r.Params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"].([]any); len(got) != 2 {
		t.Errorf("params %v", r.Params)
	}
}

func TestResolveRefusesACycleSpelledTwoWays(t *testing.T) {
	fs := files(map[string]string{
		"a.yaml": "profile: a\nextends: ./b.yaml\ninclude: [\"muster.*\"]\n",
		"b.yaml": "profile: b\nextends: a.yaml\n",
	})
	_, err := Resolve(set(), Source{Path: "./a.yaml"}, fs, noWarn(t))
	if err == nil || !strings.Contains(err.Error(), "b.yaml: extends a.yaml closes a cycle") {
		t.Fatalf("want the cycle named from the file that closed it, got %v", err)
	}
}

func TestResolveChainLengthFourFilesFiveRefused(t *testing.T) {
	m := map[string]string{"p1.yaml": "profile: p1\ninclude: [\"muster.*\"]\n"}
	for i := 2; i <= 5; i++ {
		m[fmt.Sprintf("p%d.yaml", i)] = fmt.Sprintf("profile: p%d\nextends: p%d.yaml\n", i, i-1)
	}
	fs := files(m)
	if _, err := Resolve(set(), Source{Path: "p4.yaml"}, fs, noWarn(t)); err != nil {
		t.Errorf("four files: %v", err)
	}
	if _, err := Resolve(set(), Source{Path: "p5.yaml"}, fs, noWarn(t)); err == nil || !strings.Contains(err.Error(), "four files") {
		t.Errorf("five files should refuse naming the limit, got %v", err)
	}
	// With the built-in at the root, three files plus default is the limit.
	m["q1.yaml"] = "profile: q1\nextends: default\n"
	m["q2.yaml"] = "profile: q2\nextends: q1.yaml\n"
	m["q3.yaml"] = "profile: q3\nextends: q2.yaml\n"
	m["q4.yaml"] = "profile: q4\nextends: q3.yaml\n"
	if _, err := Resolve(set(), Source{Path: "q3.yaml"}, fs, noWarn(t)); err != nil {
		t.Errorf("three files over the built-in: %v", err)
	}
	if _, err := Resolve(set(), Source{Path: "q4.yaml"}, fs, noWarn(t)); err == nil {
		t.Errorf("four files over the built-in is five in the chain")
	}
}

func TestResolveRefusals(t *testing.T) {
	cases := map[string]string{
		"unknown extends name":      "profile: x\nextends: nope\ninclude: [\"muster.*\"]\n",
		"missing extends file":      "profile: x\nextends: gone.yaml\ninclude: [\"muster.*\"]\n",
		"malformed pattern":         "profile: x\ninclude: [\"muster.[\"]\n",
		"unmatched pattern":         "profile: x\ninclude: [\"muster.nothing.*\"]\n",
		"bad name grammar":          "profile: Site\ninclude: [\"muster.*\"]\n",
		"names a built-in":          "profile: default\ninclude: [\"muster.*\"]\n",
		"empty selection":           "profile: x\ninclude: [\"muster.*\"]\nexclude: [\"muster.*\"]\n",
		"unknown control in params": "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.no.such: {a: 1}\n",
		"unknown parameter":         "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.account.password_policy: {max_len: 1}\n",
		"wrong type":                "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.account.password_policy: {min_len: \"8\"}\n",
		"unknown level":             "profile: x\ninclude: [\"muster.*\"]\nseverity:\n  - { controls: \"muster.*\", level: critical }\n",
		"severity matches nothing":  "profile: x\ninclude: [\"muster.*\"]\nseverity:\n  - { controls: \"muster.nothing.*\", level: low }\n",
		"missing profile name":      "include: [\"muster.*\"]\n",
	}
	for name, src := range cases {
		_, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), func(string) {})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "x.yaml") {
			t.Errorf("%s: %v should wrap ErrInvalid and name the file", name, err)
		}
	}
	// Rows whose reason is pinned beyond the file name.
	reasons := map[string]string{
		"malformed pattern":    "syntax error in pattern", // path.Match's verdict, not only "matches no control"
		"missing profile name": "x.yaml: profile name is required",
	}
	for name, want := range reasons {
		_, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": cases[name]}), func(string) {})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v should say %q", name, err, want)
		}
	}
	// An empty --profile value is a refusal, never the zero Source walked as a file.
	if got := SourceOf(""); got != (Source{}) {
		t.Errorf("SourceOf(\"\") = %+v, want the zero Source", got)
	}
	if _, err := Resolve(set(), SourceOf(""), neverOpenT(t), func(string) {}); err == nil || !errors.Is(err, ErrInvalid) || err.Error() != "invalid profile: profile source is empty" {
		t.Errorf("an empty source: %v", err)
	}
	neverOpen := neverOpenT(t)
	for _, name := range []string{"nope", "Default", "site_web"} {
		if _, err := Resolve(set(), Source{Name: name}, neverOpen, func(string) {}); err == nil || !strings.Contains(err.Error(), "default, kisa-unix-2026") {
			t.Errorf("%s: an unknown built-in name must list the built-ins: %v", name, err)
		}
	}
	// Inside a chain the refusal names the referring file and the extends value.
	_, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": "profile: x\nextends: gone.yaml\ninclude: [\"muster.*\"]\n"}), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "x.yaml: extends gone.yaml:") {
		t.Errorf("a missing chain file names the referrer and the value: %v", err)
	}
}

// neverOpenT is an open function that fails the test when called: a name or
// an empty source must never reach the filesystem.
func neverOpenT(t *testing.T) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		t.Errorf("a name must never be opened as a file: %s", p)
		return nil, os.ErrNotExist
	}
}

func TestResolveAndMergeTreatANilWarnAsANoOp(t *testing.T) {
	// Both calls would warn: the severity entry matches only excluded
	// controls, and the profile value is for an excluded control.
	src := "profile: x\nextends: default\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.beyond.exposed_listeners_allowed: {allowed_ports: [tcp/1]}\nseverity:\n  - { controls: \"muster.beyond.*\", level: low }\n"
	r, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if params, _ := Merge(set(), r, nil, nil); len(params) != 1 {
		t.Errorf("params %v", params)
	}
}

func TestResolveWarnsForSeverityOnExcludedOnlyAndKeepsTheEntry(t *testing.T) {
	src := "profile: x\nextends: default\nexclude: [\"muster.beyond.*\"]\nseverity:\n  - { controls: \"muster.beyond.*\", level: low }\n"
	var warnings []string
	r, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), func(m string) { warnings = append(warnings, m) })
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0] != "severity entry muster.beyond.* matches only excluded controls" {
		t.Errorf("warnings %v", warnings)
	}
	if len(r.Severity) != 1 || len(r.SeverityByID) != 0 {
		t.Errorf("the entry stays in the list (%d) and reaches no selected id (%v)", len(r.Severity), r.SeverityByID)
	}
}

func TestResolveNoOpExcludeIsSilentAndAbsoluteExtendsOpensAsGiven(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "base.yaml")
	fs := files(map[string]string{
		filepath.ToSlash(abs): "profile: base\ninclude: [\"muster.*\"]\n",
		"c.yaml":              "profile: c\nextends: " + abs + "\nexclude: [\"muster.beyond.*\"]\n",
		"d.yaml":              "profile: d\nextends: c.yaml\nexclude: [\"muster.beyond.*\"]\n",
	})
	r, err := Resolve(set(), Source{Path: "d.yaml"}, fs, noWarn(t))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Chain[0] != "file:"+filepath.Clean(abs) {
		t.Errorf("an absolute extends is opened as given: %v", r.Chain)
	}
	if len(r.IDs) != 3 {
		t.Errorf("ids %v", r.IDs)
	}
}

func TestDigestNamesContentOnly(t *testing.T) {
	a := "profile: a\nextends: default\ninclude: [muster.file.world_writable, muster.account.password_policy]\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.account.password_policy: {min_len: 12}\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n"
	b := "profile: b\nextends: default\ninclude: [muster.account.password_policy, muster.file.world_writable]\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.account.password_policy: {min_len: 12}\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n"
	c := strings.Replace(a, "min_len: 12", "min_len: 13", 1)
	ra, _ := Resolve(set(), Source{Path: "x/a.yaml"}, files(map[string]string{"x/a.yaml": a}), noWarn(t))
	rb, _ := Resolve(set(), Source{Path: "y/b.yaml"}, files(map[string]string{"y/b.yaml": b}), noWarn(t))
	rc, _ := Resolve(set(), Source{Path: "x/a.yaml"}, files(map[string]string{"x/a.yaml": c}), noWarn(t))
	if ra.Digest != rb.Digest {
		t.Errorf("name, path and include order must not change the digest: %s vs %s", ra.Digest, rb.Digest)
	}
	if ra.Digest == rc.Digest {
		t.Errorf("a changed value must change the digest")
	}
	// A new control default changes nothing: the digest holds the chain's values only.
	s2 := set()
	s2.Controls[0].Params["min_len"] = controls.Param{Type: "int", Default: 10}
	rd, _ := Resolve(s2, Source{Path: "x/a.yaml"}, files(map[string]string{"x/a.yaml": a}), noWarn(t))
	if rd.Digest != ra.Digest {
		t.Errorf("a control default leaked into the digest")
	}
	if !strings.HasPrefix(ra.Digest, "sha256:") {
		t.Errorf("digest %q", ra.Digest)
	}
	// A chain value for an excluded control is inside the digest (Z-23).
	e1 := "profile: e\nextends: default\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.beyond.exposed_listeners_allowed: {allowed_ports: [tcp/1]}\n"
	e2 := strings.Replace(e1, "tcp/1", "tcp/2", 1)
	re1, _ := Resolve(set(), Source{Path: "e.yaml"}, files(map[string]string{"e.yaml": e1}), func(string) {})
	re2, _ := Resolve(set(), Source{Path: "e.yaml"}, files(map[string]string{"e.yaml": e2}), func(string) {})
	if re1.Digest == re2.Digest {
		t.Errorf("an excluded control's chain value must be inside the digest")
	}
	// The severity list is inside the digest: a level and the order both count
	// (the last matching entry wins, so the order is content).
	two := "profile: s\nextends: default\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n  - { controls: muster.file.world_writable, level: high }\n"
	level := strings.Replace(two, "level: high", "level: medium", 1)
	swapped := "profile: s\nextends: default\nseverity:\n  - { controls: muster.file.world_writable, level: high }\n  - { controls: \"muster.file.*\", level: low }\n"
	rs, _ := Resolve(set(), Source{Path: "s.yaml"}, files(map[string]string{"s.yaml": two}), noWarn(t))
	rl, _ := Resolve(set(), Source{Path: "s.yaml"}, files(map[string]string{"s.yaml": level}), noWarn(t))
	rw, _ := Resolve(set(), Source{Path: "s.yaml"}, files(map[string]string{"s.yaml": swapped}), noWarn(t))
	if rs.Digest == rl.Digest {
		t.Errorf("a changed severity level must change the digest")
	}
	if rs.Digest == rw.Digest {
		t.Errorf("swapping two severity entries must change the digest")
	}
	// `id: {}` sets no value: it digests as the key's absence.
	empty := "profile: s\nextends: default\nparams:\n  muster.file.world_writable: {}\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n  - { controls: muster.file.world_writable, level: high }\n"
	re, _ := Resolve(set(), Source{Path: "s.yaml"}, files(map[string]string{"s.yaml": empty}), noWarn(t))
	if re.Digest != rs.Digest {
		t.Errorf("an empty params entry changed the digest: %s vs %s", re.Digest, rs.Digest)
	}
	if _, has := re.Params["muster.file.world_writable"]; has {
		t.Errorf("an empty params entry created a key: %v", re.Params)
	}
	// The contract of spec §3 "Digest": this literal is the published digest
	// of a fixed profile over the test set — ids, params and severity in the
	// canonical JSON, and the SeverityEntry json tags (controls, level). A
	// change here is a change of the published digest, never a golden refresh.
	// It is sha256 of exactly (no trailing newline):
	// {"ids":["muster.account.password_policy","muster.file.ip_port_restriction","muster.file.world_writable"],"params":{"muster.account.password_policy":{"min_len":12}},"severity":[{"controls":"muster.file.*","level":"low"}]}
	const pinned = "sha256:0dffaf3f02ebabbfe9844fbd4f79491f407f0cfa4ba012a1fe783011e3ff94ab"
	if ra.Digest != pinned {
		t.Errorf("the digest of the fixed profile is %s, the contract pins %s", ra.Digest, pinned)
	}
}

func TestResolveChildWinsASharedParameter(t *testing.T) {
	fs := files(map[string]string{
		"base.yaml":  "profile: base\nextends: default\nparams:\n  muster.account.password_policy: {min_len: 10}\n  muster.beyond.exposed_listeners_allowed: {allowed_ports: [tcp/9]}\n",
		"child.yaml": "profile: child\nextends: base.yaml\nparams:\n  muster.account.password_policy: {min_len: 12}\n",
	})
	r, err := Resolve(set(), Source{Path: "child.yaml"}, fs, noWarn(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Params["muster.account.password_policy"]["min_len"] != 12 {
		t.Errorf("the child wins a shared parameter: %v", r.Params)
	}
	if got := r.Params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"].([]any); len(got) != 1 || got[0] != "tcp/9" {
		t.Errorf("the parent's other parameter is kept: %v", r.Params)
	}
}

func TestResolveTypesEachParameterKind(t *testing.T) {
	typed := func() *controls.Set {
		s := &controls.Set{Version: "v", Digest: "sha256:d", Controls: []controls.Control{
			{ID: "muster.t.all", Importance: "중", Params: map[string]controls.Param{
				"i":  {Type: "int", Default: 1},
				"s":  {Type: "string", Default: "a"},
				"b":  {Type: "bool", Default: false},
				"li": {Type: "list<int>", Default: []any{1}},
				"ls": {Type: "list<string>", Default: []any{"a"}},
			}},
		}}
		return s.Subset([]string{"muster.t.all"})
	}
	good := map[string]string{"i": "7", "s": "x", "b": "true", "li": "[1, 2]", "ls": "[a, b]"}
	bad := map[string]string{"i": "\"7\"", "s": "[x]", "b": "yes please", "li": "[a]", "ls": "x"}
	for name, v := range good {
		src := "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.t.all: {" + name + ": " + v + "}\n"
		r, err := Resolve(typed(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), noWarn(t))
		if err != nil {
			t.Errorf("%s: %s refused: %v", name, v, err)
			continue
		}
		if err := controls.CheckParamValue(typed().Controls[0].Params[name].Type, r.Params["muster.t.all"][name]); err != nil {
			t.Errorf("%s: the stored value lost yaml.v3's shape: %v", name, err)
		}
	}
	for name, v := range bad {
		src := "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.t.all: {" + name + ": " + v + "}\n"
		if _, err := Resolve(typed(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), noWarn(t)); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %s accepted or unwrapped: %v", name, v, err)
		}
	}
}

func TestResolveRefusesAMissingRootFileNamingIt(t *testing.T) {
	_, err := Resolve(set(), Source{Path: "gone.yaml"}, files(map[string]string{}), noWarn(t))
	if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "gone.yaml") {
		t.Errorf("a missing --profile file must refuse naming it: %v", err)
	}
}
