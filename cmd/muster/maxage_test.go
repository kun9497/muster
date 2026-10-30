package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestParseMaxAge(t *testing.T) {
	ok := map[string]int64{
		"7d": 604800, "2w": 1209600, "1d12h": 129600, "90m": 5400, "1s": 1,
		"5214w": 5214 * 604800, "1w1d1h1m1s": 604800 + 86400 + 3600 + 60 + 1,
	}
	for in, want := range ok {
		got, err := parseMaxAge(in)
		if err != nil || got != want {
			t.Errorf("parseMaxAge(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0s", "-1d", "1.5d", "500ms", "12h1d", "1d1d", "101y", "5215w", "d", "7", "7x", " 7d",
		"99999999999999999999s", "0d0s", "1d ", "+1d"} {
		if got, err := parseMaxAge(in); err == nil {
			t.Errorf("parseMaxAge(%q) = %d, want an error", in, got)
		}
	}
}

func TestParseCollectedAt(t *testing.T) {
	if tm, err := parseCollectedAt("2026-09-02T06:00:00Z"); err != nil || tm.Unix() != 1788328800 {
		t.Errorf("good value: %v %v", tm, err)
	}
	for _, in := range []string{"", "2026-09-02T06:00:00+09:00", "2026-09-02T06:00:00.5Z", "2026-09-02T06:00:00z", "2026-09-02 06:00:00Z", "2026-02-30T06:00:00Z", "2026-09-02T06:00:00"} {
		if _, err := parseCollectedAt(in); err == nil {
			t.Errorf("parseCollectedAt(%q) accepted", in)
		}
	}
}

func TestCheckAge(t *testing.T) {
	at := "2026-09-02T06:00:00Z"
	c, _ := parseCollectedAt(at)
	if err := checkAge(at, 100, c.Add(100*time.Second)); err != nil {
		t.Errorf("age == bound must pass: %v", err)
	}
	err := checkAge(at, 100, c.Add(101*time.Second))
	if err == nil || err.Error() != "muster: snapshot collected at "+at+" is 1m41s old, older than --max-age 1m40s" {
		t.Errorf("stale: %v", err)
	}
	if err := checkAge(at, 100, c.Add(-5*time.Minute)); err != nil {
		t.Errorf("5 min ahead must pass: %v", err)
	}
	err = checkAge(at, 100, c.Add(-5*time.Minute-time.Second))
	if err == nil || err.Error() != "muster: snapshot collected at "+at+" is in the future (more than 5m ahead of this clock); cannot judge --max-age" {
		t.Errorf("future: %v", err)
	}
	err = checkAge("", 100, c)
	if err == nil || err.Error() != "muster: no usable collected_at; cannot judge --max-age" {
		t.Errorf("empty: %v", err)
	}
	if err := checkAge("2026-09-02T06:00:00+09:00", 100, c); err == nil {
		t.Error("offset form must refuse")
	}
}

func TestFormatAge(t *testing.T) {
	for in, want := range map[int64]string{0: "0s", 1: "1s", 8*86400 + 2*3600: "1w1d2h", 90: "1m30s", 604800: "1w"} {
		if got := formatAge(in); got != want {
			t.Errorf("formatAge(%d) = %q, want %q", in, got, want)
		}
	}
}

// pinNow fixes the command clock for one test.
func pinNow(t *testing.T, tm time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return tm }
	t.Cleanup(func() { now = old })
}

var staleNow = time.Date(2026, 9, 12, 6, 0, 30, 999, time.UTC) // 10d and 30s after full-*.json

const staleErr = "muster: snapshot collected at 2026-09-02T06:00:00Z is 1w3d30s old, older than --max-age 7d\n"

func TestCheckMaxAgeRefusesStale(t *testing.T) {
	pinNow(t, staleNow)
	bad := filepath.Join(t.TempDir(), "broken.yaml")
	os.WriteFile(bad, []byte("not: [valid"), 0o600)
	for _, extra := range [][]string{nil, {"--allow-error"}, {"--fail-on", "none"}, {"--profile", bad}} {
		var out, errb bytes.Buffer
		args := append([]string{"check", "--facts", fullFail, "--max-age", "7d"}, extra...)
		if code := run(args, &out, &errb); code != exitError || out.Len() != 0 || errb.String() != staleErr {
			t.Errorf("%v: code %d stdout %q stderr %q", extra, code, out.String(), errb.String())
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", fullFail, "--max-age", "11d", "--format", "json"}, &out, &errb); code == exitError || out.Len() == 0 {
		t.Errorf("fresh enough must run: %d %s", code, errb.String())
	}
}

func TestFixMaxAgeRefusesStale(t *testing.T) {
	pinNow(t, staleNow)
	bad := filepath.Join(t.TempDir(), "broken.yaml")
	os.WriteFile(bad, []byte("not: [valid"), 0o600)
	for _, extra := range [][]string{nil, {"--profile", bad}, {"--format", "script"}} {
		code, out, errb := runFixArgs(t, append([]string{"--dry-run", "--facts", fullFail, "--max-age", "7d"}, extra...)...)
		if code != exitError || len(out) != 0 || string(errb) != staleErr {
			t.Errorf("%v: code %d stdout %q stderr %q", extra, code, out, errb)
		}
	}
}

func TestMaxAgeRecordedInBlocks(t *testing.T) {
	pinNow(t, staleNow)
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", fullFail, "--max-age", "2w", "--format", "json"}, &out, &errb); code == exitError {
		t.Fatalf("check: %s", errb.String())
	}
	var rep struct {
		Check map[string]any `json:"check"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.Check["max_age_s"] != float64(1209600) {
		t.Errorf("check.max_age_s: %v %v", rep.Check["max_age_s"], err)
	}
	p := planJSON(t, "--facts", fullFail, "--max-age", "2w")
	if p.Fix.MaxAgeS != 1209600 {
		t.Errorf("fix.max_age_s = %d", p.Fix.MaxAgeS)
	}
	out.Reset()
	run([]string{"check", "--facts", fullFail, "--format", "json"}, &out, &errb)
	if strings.Contains(out.String(), "max_age_s") {
		t.Error("check block carries max_age_s without the flag")
	}
	if strings.Contains(string(runPlanBytes(t)), "max_age_s") {
		t.Error("fix block carries max_age_s without the flag")
	}
}

func runPlanBytes(t *testing.T) []byte {
	t.Helper()
	_, out, _ := runFixArgs(t, "--dry-run", "--format", "json", "--facts", fullFail)
	return out
}

func TestMaxAgeBadValueIsUsageError(t *testing.T) {
	for _, v := range []string{"", "0s", "1.5d"} {
		var out, errb bytes.Buffer
		if code := run([]string{"check", "--facts", fullFail, "--max-age", v}, &out, &errb); code != exitError || out.Len() != 0 || !strings.Contains(errb.String(), "--max-age") {
			t.Errorf("check %q: %d %q", v, code, errb.String())
		}
		if code, o, e := runFixArgs(t, "--dry-run", "--facts", fullFail, "--max-age", v); code != exitError || len(o) != 0 || !strings.Contains(string(e), "--max-age") {
			t.Errorf("fix %q: %d %q", v, code, e)
		}
	}
}

// TestWaiverExpiryFollowsTheCommandClock: the one pinned reading decides
// expiry in check and in fix, with and without --max-age. The waiver ends
// 2026-09-05, long before the real wall clock, so only a pinned earlier day
// can keep it alive.
func TestWaiverExpiryFollowsTheCommandClock(t *testing.T) {
	wf := filepath.Join(t.TempDir(), "w.yaml")
	body := "waivers:\n  - control: muster.account.root_remote_login\n    reason: clock test\n    expires: 2026-09-05\n"
	if err := os.WriteFile(wf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	type blocks struct {
		Check, Fix struct {
			Waivers struct {
				Expired int `json:"expired"`
				Applied int `json:"applied"`
			} `json:"waivers"`
		}
	}
	expired := func(cmd string, extra []string) int {
		t.Helper()
		var b blocks
		var out, errb bytes.Buffer
		args := append([]string{"--facts", fullFail, "--waivers", wf, "--format", "json"}, extra...)
		if cmd == "fix" {
			args = append([]string{"fix", "--dry-run"}, args...)
		} else {
			args = append([]string{"check"}, args...)
		}
		if code := run(args, &out, &errb); code == exitError {
			t.Fatalf("%s %v: %s", cmd, extra, errb.String())
		}
		if err := json.Unmarshal(out.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		if cmd == "fix" {
			return b.Fix.Waivers.Expired
		}
		return b.Check.Waivers.Expired
	}
	for _, cmd := range []string{"check", "fix"} {
		for _, extra := range [][]string{nil, {"--max-age", "30d"}} {
			pinNow(t, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
			if n := expired(cmd, extra); n != 0 {
				t.Errorf("%s %v: expired = %d under a clock before the expiry", cmd, extra, n)
			}
			pinNow(t, time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
			if n := expired(cmd, extra); n != 1 {
				t.Errorf("%s %v: expired = %d under a clock after the expiry", cmd, extra, n)
			}
		}
	}
}

func TestFixValueFlagsMatchParser(t *testing.T) {
	src, err := os.ReadFile("fix.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "switch a {")
	if i < 0 {
		t.Fatal("no parser switch")
	}
	// A value flag's case calls next() on the line after its case line, or on its own line.
	cases := regexp.MustCompile(`case "(--[a-z-]+)":\n\s+f\.\w+, err = next\(\)`).FindAllStringSubmatch(s[i:], -1)
	if len(cases) < 8 {
		t.Fatalf("found only %d value flags", len(cases))
	}
	for _, m := range cases {
		if !fixValueFlags[m[1]] {
			t.Errorf("%s takes a value but is not in fixValueFlags", m[1])
		}
	}
	if len(cases) != len(fixValueFlags) {
		t.Errorf("parser takes %d value flags, fixValueFlags has %d", len(cases), len(fixValueFlags))
	}
}
