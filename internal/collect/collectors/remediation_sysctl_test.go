//go:build linux

package collectors

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestSysctlScriptsNameTheControlsKeys pins 3D-2c §5: a control's sysctl list
// is, as a set, the kernel keys of the facts its checks judge (plus the one
// declared companion, E-13), and each key's case arms in the script and the
// validate are the clause's accepted set, written to a member of it. The
// list is also in check order with the companion last: restore_sysctl walks
// it in order, and all.forwarding must be put back before default.forwarding
// (writing it copies into default, S-46), ip_forward before its companion
// (writing it flips the companion, S-43). Nothing may sort a sysctl list.
func TestSysctlScriptsNameTheControlsKeys(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	leaf := map[string]string{"coredump.suid_dumpable": suidDumpableKey.key}
	for _, l := range sysctlLeaves {
		leaf[l.leaf] = l.key
	}
	companions := map[string]string{"muster.beyond.ip_forwarding_disabled": "net.ipv4.conf.all.accept_redirects"}
	n := 0
	for _, c := range set.Controls {
		r := c.Remediation
		if r == nil || len(r.Sysctl) == 0 {
			continue
		}
		n++
		judged := map[string]controls.Clause{}
		ordered := []string{}
		for _, cl := range c.Checks {
			k, ok := leaf[cl.Fact]
			if !ok {
				t.Errorf("%s: clause fact %s is not a sysctl leaf", c.ID, cl.Fact)
				continue
			}
			judged[k] = cl
			ordered = append(ordered, k)
		}
		want := []string{}
		for k := range judged {
			want = append(want, k)
		}
		if k := companions[c.ID]; k != "" {
			want = append(want, k)
			ordered = append(ordered, k)
		}
		if strings.Join(r.Sysctl, " ") != strings.Join(ordered, " ") {
			t.Errorf("%s: sysctl %v, want %v in that order", c.ID, r.Sysctl, ordered)
		}
		got := append([]string(nil), r.Sysctl...)
		sort.Strings(want)
		sort.Strings(got)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: sysctl %v, want %v", c.ID, got, want)
		}
		for k, cl := range judged {
			q := regexp.QuoteMeta(k)
			switch e := cl.Expected.(type) {
			case string: // "${param}"
				p := strings.TrimSuffix(strings.TrimPrefix(e, "${"), "}")
				head := `case " \$P_` + p + ` " in\s+\*" \$\(sysctl -n ` + q + `\) "\*\) ;;`
				if !regexp.MustCompile(`(?s)` + head + `\s+\*\) .*?put ` + q + ` "\$first"`).MatchString(r.Script) {
					t.Errorf("%s: no parameter case for %s over $P_%s in the script", c.ID, k, p)
				}
				if !regexp.MustCompile(head + ` \*\) false;; esac`).MatchString(r.Validate) {
					t.Errorf("%s: no parameter case for %s in the validate", c.ID, k)
				}
			default:
				arms := armsOf(t, c.ID, cl)
				m := regexp.MustCompile(`case "\$\(sysctl -n ` + q + `\)" in ` + regexp.QuoteMeta(arms) + `\) ;; \*\) put ` + q + ` ([0-9]+);; esac`).FindStringSubmatch(r.Script)
				if m == nil {
					t.Errorf("%s: no case for %s with arms %s in the script", c.ID, k, arms)
					continue
				}
				if !accepts(cl, m[1]) {
					t.Errorf("%s: %s is written as %s, which its clause does not accept", c.ID, k, m[1])
				}
				if !strings.Contains(r.Validate, `case "$(sysctl -n `+k+`)" in `+arms+`) ;; *) false;; esac`) {
					t.Errorf("%s: no case for %s with arms %s in the validate", c.ID, k, arms)
				}
			}
		}
	}
	if n != 16 {
		t.Errorf("%d controls declare sysctl, want 16", n)
	}
}

func armsOf(t *testing.T, id string, cl controls.Clause) string {
	switch cl.Op {
	case "eq":
		return fmt.Sprint(cl.Expected)
	case "in":
		var xs []string
		for _, x := range cl.Expected.([]any) {
			xs = append(xs, fmt.Sprint(x))
		}
		return strings.Join(xs, "|")
	case "gte":
		if fmt.Sprint(cl.Expected) == "2" {
			return "[2-9]|[1-9][0-9]|[1-9][0-9][0-9]*" // a glob: [1-9][0-9]* alone matches "1" (S-21)
		}
	}
	t.Errorf("%s: no arms rule for op %s %v", id, cl.Op, cl.Expected)
	return ""
}

func accepts(cl controls.Clause, v string) bool {
	switch cl.Op {
	case "eq":
		return fmt.Sprint(cl.Expected) == v
	case "in":
		for _, x := range cl.Expected.([]any) {
			if fmt.Sprint(x) == v {
				return true
			}
		}
	case "gte":
		var n, min int
		fmt.Sscan(v, &n)
		fmt.Sscan(fmt.Sprint(cl.Expected), &min)
		return n >= min
	}
	return false
}
