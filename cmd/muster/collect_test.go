package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestCollectRejectsUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--bogus"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--bogus") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty on error, got %q", out.String())
	}
}

func TestCollectOffLinuxSaysSo(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux")
	}
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--out", "-"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "requires Linux") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	// R58: --list-actions is unsupported off Linux too, and the answer is
	// the same sentence rather than a half-answered action list.
	out.Reset()
	errb.Reset()
	if code := run([]string{"collect", "--list-actions"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "requires Linux") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty off Linux, got %q", out.String())
	}
}

// The whole command end to end against the real host: it writes a 0600
// snapshot where it was told to, says so on stderr, keeps stdout empty and
// returns 0 (complete, as root) or 1 (partial, as anyone else). Nothing
// about what was collected is asserted — that is the host's business, not
// this repository's (D02).
func TestCollectWritesASnapshotOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	p := filepath.Join(t.TempDir(), "s.json")
	var out, errb bytes.Buffer
	code := run([]string{"collect", "--out", p}, &out, &errb)
	if code != exitOK && code != exitFindings {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "muster: wrote ") {
		t.Errorf("stderr %q lacks the wrote line", errb.String())
	}
	if os.Geteuid() != 0 && !strings.Contains(errb.String(), "not running as root") {
		t.Errorf("a non-root run must warn: %q", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout carries only a snapshot asked for with --out -, got %q", out.String())
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
}

// I2 (R83): an --out path that is a symbolic link is refused before
// anything is written, with --force exactly as without it, and the command
// reports it the way it reports the writer's other refusals — exit 2 and a
// "muster:" line that names the path and what it is, not a generic
// "collect failed".
func TestCollectRefusesASymlinkedOutPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "s.json")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"collect", "--out", link},
		{"collect", "--out", link, "--force"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitError {
			t.Errorf("%v: code %d, want %d (stderr %q)", args, code, exitError, errb.String())
		}
		if want := "muster: " + link + ": output path is a symbolic link"; !strings.Contains(errb.String(), want) {
			t.Errorf("%v: stderr %q lacks %q", args, errb.String(), want)
		}
		if got, _ := os.ReadFile(target); string(got) != "original" {
			t.Errorf("%v: the link's target was written: %q", args, got)
		}
	}
}

func TestCollectListActionsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--list-actions", "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	// R60: /proc/self/status is read by the "muster" pseudo-collector, so
	// the action list names it like any other declared read.
	for _, want := range []string{`"kind": "read"`, `"kind": "command"`, `"kind": "write"`, "/usr/sbin/sshd -T", "/proc/self/status", "/usr/bin/rpm -Va", "/usr/sbin/auditctl -s",
		"/usr/bin/systemctl list-units --type=service --state=active --plain --no-legend", `%|FILECAPS?{%{FILECAPS}}|`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if errb.Len() != 0 {
		t.Errorf("stderr must stay empty, got %q", errb.String())
	}
	// The processes collector's rows, exhaustively: every read, the rpm
	// query it shares with the walk and the firewall facts it reads.
	var actions []struct{ Collector, Kind, Target, Needs string }
	if err := json.Unmarshal(out.Bytes(), &actions); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range actions {
		if a.Collector != "processes" {
			continue
		}
		target := a.Target
		if a.Kind == "command" && strings.HasPrefix(target, "/usr/bin/rpm -qa --qf ") && strings.Contains(target, `%|FILECAPS?{%{FILECAPS}}|`) {
			target = "/usr/bin/rpm -qa --qf <the walk's file query>"
		}
		got = append(got, a.Kind+" "+a.Needs+" "+target)
	}
	want := []string{
		"command none /usr/bin/rpm -qa --qf <the walk's file query>",
		"fact none firewall.*",
		"read none /bin", "read none /lib", "read none /lib32", "read none /lib64", "read none /libx32",
		"read none /proc/1/ns/mnt", "read none /proc/[0-9]*/cmdline", "read none /proc/[0-9]*/exe",
		"read none /proc/[0-9]*/fd/*", "read none /proc/[0-9]*/mountinfo", "read none /proc/[0-9]*/ns/mnt", "read none /proc/[0-9]*/root", "read none /proc/[0-9]*/task/*/fd/*", "read none /proc/[0-9]*/status",
		"read none /proc/self/net/tcp", "read none /proc/self/net/tcp6", "read none /proc/self/net/udp", "read none /proc/self/net/udp6",
		"read none /proc/sys/net/ipv6/bindv6only", "read none /proc/sys/net/ipv6/conf/all/disable_ipv6", "read none /proc/sys/net/ipv6/conf/default/disable_ipv6", "read none /sbin",
		"read none /var/lib/dpkg/diversions", "read none /var/lib/dpkg/info/*.list", "read none /var/lib/dpkg/statoverride",
		"read none /var/lib/dpkg/status", "read none /var/lib/rpm",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("processes rows\n got %q\nwant %q", got, want)
	}

	// The sysctl collector's rows, exhaustively: the twelve kernel files of
	// B-2, the twenty-seven network files of P-4 and the sysctl.d chain.
	var gotSysctl []string
	for _, a := range actions {
		if a.Collector == "sysctl" {
			gotSysctl = append(gotSysctl, a.Kind+" "+a.Needs+" "+a.Target)
		}
	}
	wantSysctl := []string{
		"read none /etc/sysctl.conf", "read none /etc/sysctl.d/*.conf", "read none /run/sysctl.d/*.conf",
		"read none /usr/lib/sysctl.d/*.conf", "read none /usr/local/lib/sysctl.d/*.conf",
		"read none /proc/sys/fs/protected_fifos", "read none /proc/sys/fs/protected_hardlinks",
		"read none /proc/sys/fs/protected_regular", "read none /proc/sys/fs/protected_symlinks",
		"read none /proc/sys/kernel/dmesg_restrict", "read none /proc/sys/kernel/kptr_restrict",
		"read none /proc/sys/kernel/perf_event_paranoid", "read none /proc/sys/kernel/randomize_va_space",
		"read none /proc/sys/kernel/sysrq", "read none /proc/sys/kernel/unprivileged_bpf_disabled",
		"read none /proc/sys/kernel/yama/ptrace_scope", "read none /proc/sys/net/core/bpf_jit_harden",
		"read none /proc/sys/net/ipv4/ip_forward",
		"read none /proc/sys/net/ipv6/conf/all/forwarding", "read none /proc/sys/net/ipv6/conf/default/forwarding",
		"read none /proc/sys/net/ipv4/conf/all/accept_redirects", "read none /proc/sys/net/ipv4/conf/default/accept_redirects",
		"read none /proc/sys/net/ipv4/conf/all/secure_redirects", "read none /proc/sys/net/ipv4/conf/default/secure_redirects",
		"read none /proc/sys/net/ipv4/conf/all/send_redirects", "read none /proc/sys/net/ipv4/conf/default/send_redirects",
		"read none /proc/sys/net/ipv6/conf/all/accept_redirects", "read none /proc/sys/net/ipv6/conf/default/accept_redirects",
		"read none /proc/sys/net/ipv4/conf/all/accept_source_route", "read none /proc/sys/net/ipv4/conf/default/accept_source_route",
		"read none /proc/sys/net/ipv6/conf/all/accept_source_route", "read none /proc/sys/net/ipv6/conf/default/accept_source_route",
		"read none /proc/sys/net/ipv4/conf/all/rp_filter", "read none /proc/sys/net/ipv4/conf/default/rp_filter",
		"read none /proc/sys/net/ipv4/conf/all/log_martians", "read none /proc/sys/net/ipv4/conf/default/log_martians",
		"read none /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "read none /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses",
		"read none /proc/sys/net/ipv4/tcp_syncookies",
		"read none /proc/sys/net/ipv6/conf/all/accept_ra", "read none /proc/sys/net/ipv6/conf/default/accept_ra",
		"read none /proc/sys/net/ipv6/conf/all/disable_ipv6", "read none /proc/sys/net/ipv6/conf/default/disable_ipv6",
		"read none /proc/sys/net/ipv6/bindv6only",
	}
	slices.Sort(gotSysctl)
	slices.Sort(wantSysctl)
	if !slices.Equal(gotSysctl, wantSysctl) {
		t.Errorf("sysctl rows\n got %q\nwant %q", gotSysctl, wantSysctl)
	}
}

// W-12: --deep travels from the command line to the header of the snapshot
// on disk. run.deep false is what a later check reads as "the walk never
// ran" (main §6.5 row 9), so this flag reaching collect.Options is the
// difference between a MANUAL row and a verdict.
func TestCollectDeepReachesTheHeader(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"deep", []string{"collect", "--deep", "--walk-budget", "5s", "--out", "-"}, true},
		{"shallow", []string{"collect", "--out", "-"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := run(tc.args, &out, &errb); code != exitOK && code != exitFindings {
				t.Fatalf("code %d stderr %q", code, errb.String())
			}
			hdr, ok := readJSON(t, out.Bytes())["run"].(map[string]any)
			if !ok {
				t.Fatalf("no run header in the snapshot: %s", out.String())
			}
			if hdr["deep"] != tc.want {
				t.Errorf("run.deep %v, want %v", hdr["deep"], tc.want)
			}
			// The stage-1 warning that the walk arrives later is gone: a
			// warning that contradicts the header is worse than none.
			if strings.Contains(errb.String(), "stage 3") {
				t.Errorf("stderr still parks the walk: %q", errb.String())
			}
		})
	}
}
