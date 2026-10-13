package remedy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// systemctlStub stands in for systemctl in the unit-helper tests: one state
// file per unit under $STUB/state/<u> ("<enabled> <active>"), every call
// appended to $STUB/calls. noinstall/<u> makes enable a silent no-op (a unit
// with no [Install] section), also/<u> names a partner enable turns on,
// deps/<u> the units that stopping <u> stops, fail/<u> makes mask fail. An
// enabled field of "-" makes is-enabled print nothing (recorded "unknown"),
// and enable refuses while an Also= partner is masked, as systemd does.
// enable and disable leave a static or indirect unit's enablement alone;
// enable --runtime (and its Also= partner) is enabled-runtime, which only
// disable --runtime clears (disable --runtime leaves a persistent enabled).
// mask keeps the enablement it hid (premask/<u>) and unmask brings it back,
// as removing the /dev/null link does.
const systemctlStub = `printf '%s\n' "$*" >> "$STUB/calls"
q= rt= now= verb= u=
for a in "$@"; do
  case "$a" in
    --quiet) q=1;; --runtime) rt=1;; --now) now=1;;
    --|--value|-p|RequiredBy|BoundBy|ConsistsOf) ;;
    *) if [ -z "$verb" ]; then verb=$a; else u=$a; fi;;
  esac
done
f="$STUB/state/$u"
get() { [ -f "$f" ] || return 1; read -r se sa < "$f"; }
put() { printf '%s %s\n' "$1" "$2" > "$f"; }
case "$verb" in
  cat) [ -f "$f" ];;
  is-enabled) get || { echo not-found; exit 1; }; [ "$se" = - ] && exit 1; echo "$se"; case "$se" in enabled|enabled-runtime) exit 0;; esac; exit 1;;
  is-active) get || { [ -n "$q" ] || echo inactive; exit 3; }; [ -n "$q" ] || echo "$sa"; [ "$sa" = active ];;
  show) if [ -f "$STUB/deps/$u" ]; then cat "$STUB/deps/$u"; fi;;
  enable) get || exit 1; [ -f "$STUB/noinstall/$u" ] && exit 0
    case "$se" in masked*) exit 1;; static|indirect) exit 0;; esac
    if [ -f "$STUB/also/$u" ]; then read -r pe pa < "$STUB/state/$(cat "$STUB/also/$u")"; case "$pe" in masked*) exit 1;; esac; fi
    if [ -n "$rt" ]; then put enabled-runtime "$sa"; else put enabled "$sa"; fi
    if [ -f "$STUB/also/$u" ]; then p=$(cat "$STUB/also/$u"); read -r pe pa < "$STUB/state/$p"
      if [ -n "$rt" ]; then printf 'enabled-runtime %s\n' "$pa" > "$STUB/state/$p"; else printf 'enabled %s\n' "$pa" > "$STUB/state/$p"; fi
    fi;;
  disable) get || exit 1
    case "$se" in
      static|indirect) ne=$se;;
      enabled-runtime) if [ -n "$rt" ]; then ne=disabled; else ne=$se; fi;;
      enabled) if [ -n "$rt" ]; then ne=$se; else ne=disabled; fi;;
      *) ne=disabled;;
    esac
    if [ -n "$now" ]; then put "$ne" inactive; else put "$ne" "$sa"; fi
    if [ -n "$now" ] && [ -f "$STUB/deps/$u" ]; then
      for d in $(cat "$STUB/deps/$u"); do read -r de da < "$STUB/state/$d"; printf '%s inactive\n' "$de" > "$STUB/state/$d"; done
    fi;;
  mask) [ -f "$STUB/fail/$u" ] && exit 1; get || exit 1
    case "$se" in masked*) ;; *) mkdir -p "$STUB/premask"; printf '%s\n' "$se" > "$STUB/premask/$u";; esac
    if [ -n "$rt" ]; then put masked-runtime "$sa"; else put masked "$sa"; fi;;
  unmask) get || exit 1
    case "$se" in masked*)
      if [ -f "$STUB/premask/$u" ]; then put "$(cat "$STUB/premask/$u")" "$sa"; rm -f "$STUB/premask/$u"; else put disabled "$sa"; fi;;
    esac;;
  start) get || exit 1; case "$se" in masked*) exit 1;; esac; put "$se" active;;
  *) exit 1;;
esac
`

func unitsPlan(units []string) *Plan {
	return &Plan{Fix: FixBlock{MaxRisk: "lockout_risk", HostGuard: "off"}, Items: []Item{{
		ID: "muster.test.u", Risk: "restart_service", Status: "fail", Severity: "high",
		Script: true, Planned: true, Units: units, Backup: []string{}, Rollback: "units",
		// the last command fails (the stub rejects an unknown verb) and marks
		// in $STUB/calls where the body ends and the rollback begins
		ScriptBody:  "for u in $UNITS; do\n  systemctl --quiet disable --now -- \"$u\"\n  systemctl --quiet mask -- \"$u\" || true\ndone\nsystemctl body-done\n",
		Validate:    true,
		ValidateCmd: "true",
	}}}
}

// newStub returns the stub's bin directory (put first on PATH) and its state root.
func newStub(t *testing.T, before map[string]string) (bin, stub string) {
	t.Helper()
	bin, stub = t.TempDir(), t.TempDir()
	writeStub(t, bin, "systemctl", systemctlStub)
	for u, s := range before {
		write(t, stub, "state/"+u, s)
	}
	return bin, stub
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, root, rel string) { t.Helper(); write(t, root, rel, "") }

func state(t *testing.T, stub, u string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stub, "state", u))
	if err != nil {
		return "absent"
	}
	return strings.TrimSpace(string(b))
}

// TestUnitHelpersRestoreRecordedState drives each recorded state through a
// failed units block against the stub and checks the end state and the
// logs (3D-2b §3).
func TestUnitHelpersRestoreRecordedState(t *testing.T) {
	needSh(t)
	cases := []struct {
		name     string
		units    []string
		before   map[string]string // unit -> "<enabled> <active>"
		setup    func(t *testing.T, stub string)
		after    map[string]string // nil: only the logs and the failure are checked
		logs     []string
		wantFail bool // ROLLBACK INCOMPLETE expected
	}{
		{"enabled active", []string{"a.service"}, map[string]string{"a.service": "enabled active"}, nil, map[string]string{"a.service": "enabled active"}, nil, false},
		{"enabled-runtime", []string{"a.service"}, map[string]string{"a.service": "enabled-runtime active"}, nil, map[string]string{"a.service": "enabled-runtime active"}, nil, false},
		{"disabled active", []string{"a.service"}, map[string]string{"a.service": "disabled active"}, nil, map[string]string{"a.service": "disabled active"}, nil, false},
		{"masked", []string{"a.service"}, map[string]string{"a.service": "masked inactive"}, nil, map[string]string{"a.service": "masked inactive"}, nil, false},
		{"masked-runtime", []string{"a.service"}, map[string]string{"a.service": "masked-runtime inactive"}, nil, map[string]string{"a.service": "masked-runtime inactive"}, nil, false},
		{"masked active", []string{"a.service"}, map[string]string{"a.service": "masked active"}, nil, map[string]string{"a.service": "masked inactive"}, nil, false},
		{"linked", []string{"a.service"}, map[string]string{"a.service": "linked active"}, nil, nil, []string{"a.service: was linked; the link is not restored"}, true},
		{"static", []string{"a.service"}, map[string]string{"a.service": "static active"}, nil, map[string]string{"a.service": "static active"}, nil, false},
		{"absent", []string{"a.service"}, map[string]string{}, nil, map[string]string{"a.service": "absent"}, nil, false},
		{"no install section", []string{"a.service"}, map[string]string{"a.service": "enabled active"}, func(t *testing.T, s string) { touch(t, s, "noinstall/a.service") }, nil, []string{"a.service: enablement not restored (was enabled, now disabled)"}, true},
		{"also partner", []string{"a.socket", "a.service"}, map[string]string{"a.socket": "disabled inactive", "a.service": "enabled active"}, func(t *testing.T, s string) { write(t, s, "also/a.service", "a.socket") }, map[string]string{"a.socket": "disabled inactive", "a.service": "enabled active"}, nil, false},
		{"also partner runtime", []string{"a.socket", "a.service"}, map[string]string{"a.socket": "disabled inactive", "a.service": "enabled-runtime active"}, func(t *testing.T, s string) { write(t, s, "also/a.service", "a.socket") }, map[string]string{"a.socket": "disabled inactive", "a.service": "enabled-runtime active"}, nil, false},
		{"masked socket enabled service", []string{"a.socket", "a.service"}, map[string]string{"a.socket": "masked inactive", "a.service": "enabled active"}, func(t *testing.T, s string) { write(t, s, "also/a.service", "a.socket") }, map[string]string{"a.socket": "masked inactive", "a.service": "enabled active"}, nil, false},
		{"unknown", []string{"a.service"}, map[string]string{"a.service": "- active"}, nil, nil, []string{"a.service: enablement not restored (was unknown, now disabled)"}, true},
		{"dependant restarted", []string{"a.service"}, map[string]string{"a.service": "enabled active", "dep.service": "enabled active"}, func(t *testing.T, s string) { write(t, s, "deps/a.service", "dep.service") }, map[string]string{"a.service": "enabled active", "dep.service": "enabled active"}, nil, false},
		{"mask fails", []string{"a.service"}, map[string]string{"a.service": "masked inactive"}, func(t *testing.T, s string) { touch(t, s, "fail/a.service") }, nil, []string{"muster.test.u: ROLLBACK INCOMPLETE"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bin, stub := newStub(t, c.before)
			if c.setup != nil {
				c.setup(t, stub)
			}
			dir := t.TempDir()
			all, _, code := runScriptWith(t, unitsPlan(c.units), dir, filepath.Join(dir, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub}})
			if code != 1 || !strings.Contains(all, "muster.test.u: script failed (rc 1), rolling back") {
				t.Fatalf("exit %d, want 1 with the script-failed line:\n%s", code, all)
			}
			for _, l := range c.logs {
				if !strings.Contains(all, l) {
					t.Errorf("output lacks %q:\n%s", l, all)
				}
			}
			if got := strings.Contains(all, "ROLLBACK INCOMPLETE"); got != c.wantFail {
				t.Errorf("ROLLBACK INCOMPLETE %v, want %v:\n%s", got, c.wantFail, all)
			}
			for u, want := range c.after {
				if got := state(t, stub, u); got != want {
					t.Errorf("%s: %q, want %q", u, got, want)
				}
			}
			if want, ok := wantCalls[c.name]; ok {
				if got := rollbackCalls(t, stub); strings.Join(got, "; ") != strings.Join(want, "; ") {
					t.Errorf("rollback calls\n got %v\nwant %v", got, want)
				}
			}
		})
	}
}

// wantCalls pins the order of the state-changing calls the rollback makes:
// unmask, enable, re-disable, re-mask, start, dependants (3D-2b §3 passes).
var wantCalls = map[string][]string{
	"also partner":                  {"unmask a.socket", "unmask a.service", "enable a.service", "disable a.socket", "start a.service"},
	"also partner runtime":          {"unmask a.socket", "unmask a.service", "enable a.service", "disable a.socket", "start a.service"},
	"masked socket enabled service": {"unmask a.socket", "unmask a.service", "enable a.service", "mask a.socket", "start a.service"},
	"dependant restarted":           {"unmask a.service", "enable a.service", "start a.service", "start dep.service"},
}

// rollbackCalls returns the stub's state-changing calls after the body's
// body-done marker, flags stripped: "unmask a.socket".
func rollbackCalls(t *testing.T, stub string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stub, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	after := false
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "body-done" {
			after = true
			continue
		}
		var w []string
		for _, f := range strings.Fields(l) {
			switch f {
			case "--quiet", "--runtime", "--now", "--":
			default:
				w = append(w, f)
			}
		}
		if after && len(w) == 2 {
			switch w[0] {
			case "unmask", "enable", "disable", "mask", "start":
				out = append(out, w[0]+" "+w[1])
			}
		}
	}
	return out
}

// TestUnitHelpersKeepTheFirstRecord pins the first-record rule and its one
// exception: a record of an absent unit is rewritten once the unit exists.
func TestUnitHelpersKeepTheFirstRecord(t *testing.T) {
	needSh(t)
	dir := t.TempDir()
	bk := filepath.Join(dir, "bk")
	bin, stub := newStub(t, map[string]string{"a.service": "enabled active"})
	opts := runOpts{pathPrefix: bin, env: []string{"STUB=" + stub}}
	if _, _, code := runScriptWith(t, unitsPlan([]string{"a.service"}), dir, bk, opts); code != 1 {
		t.Fatalf("first run exit %d", code)
	}
	write(t, stub, "state/a.service", "disabled inactive") // the operator changed it between runs
	all, _, code := runScriptWith(t, unitsPlan([]string{"a.service"}), dir, bk, opts)
	if code != 1 || !strings.Contains(all, "a.service: unit state exists, keeping the first") || state(t, stub, "a.service") != "enabled active" {
		t.Fatalf("second run: exit %d state %q:\n%s", code, state(t, stub, "a.service"), all)
	}

	bk2 := filepath.Join(dir, "bk2")
	bin2, stub2 := newStub(t, map[string]string{})
	opts2 := runOpts{pathPrefix: bin2, env: []string{"STUB=" + stub2}}
	if _, _, code := runScriptWith(t, unitsPlan([]string{"b.service"}), dir, bk2, opts2); code != 1 {
		t.Fatalf("absent run exit %d", code)
	}
	write(t, stub2, "state/b.service", "enabled active") // installed between runs
	all, _, code = runScriptWith(t, unitsPlan([]string{"b.service"}), dir, bk2, opts2)
	if code != 1 || strings.Contains(all, "b.service: unit state exists") || state(t, stub2, "b.service") != "enabled active" {
		t.Fatalf("absent then present: exit %d state %q:\n%s", code, state(t, stub2, "b.service"), all)
	}
}
