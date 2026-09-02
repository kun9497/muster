package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/facts"
)

func TestDisplayWidthCountsHangulAsTwo(t *testing.T) {
	if w := displayWidth("root 계정"); w != 9 { // 4 + 1 + 2*2
		t.Errorf("width %d", w)
	}
	if got := padRight("계정", 6); got != "계정  " {
		t.Errorf("%q", got)
	}
}

func TestEscapeNeutralisesTerminalSequences(t *testing.T) {
	in := "PASS\x1b[32m fake \r\x07 tab\tok"
	got := escape(in)
	if strings.ContainsAny(got, "\x1b\r\x07") {
		t.Fatalf("control bytes survived: %q", got)
	}
	if !strings.Contains(got, "\t") {
		t.Error("tab must survive")
	}
	long := strings.Repeat("가", 300)
	if w := len([]rune(escape(long))); w != 201 {
		t.Errorf("truncation to 200 runes + ellipsis, got %d", w)
	}

	// Test escape on observation Expected with control character
	obsExpected := "\x1b[31mX"
	escaped := escape(obsExpected)
	if strings.Contains(escaped, "\x1b") {
		t.Fatalf("observation Expected ESC survived: %q", escaped)
	}

	// Test escape on waiver Expires with control character
	waiverExpires := "\x1b]0;evil\a"
	escaped = escape(waiverExpires)
	if strings.ContainsAny(escaped, "\x1b\a") {
		t.Fatalf("waiver Expires control chars survived: %q", escaped)
	}
}

func TestColorEnabled(t *testing.T) {
	if ColorEnabled("always", "1", "dumb", false) != true {
		t.Error("always wins")
	}
	if ColorEnabled("never", "", "xterm", true) != false {
		t.Error("never wins")
	}
	if ColorEnabled("auto", "", "xterm", true) != true || ColorEnabled("auto", "1", "xterm", true) != false ||
		ColorEnabled("auto", "", "dumb", true) != false || ColorEnabled("", "", "xterm", false) != false {
		t.Error("auto must honour TTY, NO_COLOR and TERM=dumb")
	}
}

func TestTruncateWidth(t *testing.T) {
	// ASCII string wider than limit is cut and ends with …
	got := truncateWidth("hello world test", 10)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("should end with ellipsis: %q", got)
	}
	if displayWidth(got) > 10 {
		t.Errorf("truncated width should not exceed limit: got %d, want <= 10", displayWidth(got))
	}

	// Hangul string is cut on rune boundary so displayWidth(result) <= limit
	got = truncateWidth("안녕하세요 세계", 8)
	if displayWidth(got) > 8 {
		t.Errorf("Hangul truncation exceeded limit: got %d, want <= 8", displayWidth(got))
	}

	// String within limit is returned unchanged
	got = truncateWidth("hello", 20)
	if got != "hello" {
		t.Errorf("string within limit should be unchanged: got %q", got)
	}
}

// sampleReportWithTitles extends sampleReport by adding titles to rows.
func sampleReportWithTitles(t *testing.T) *Report {
	r := sampleReport(t)
	for i := range r.Results {
		row := &r.Results[i]
		switch row.ID {
		case "muster.file.world_writable":
			row.TitleEn = "World-writable files must not exist in system directories"
		case "muster.account.root_remote_login":
			row.TitleKo = "원격 root 로그인 제한"
		}
	}
	return r
}

func TestTableGoldenWideAndNarrow(t *testing.T) {
	r := sampleReportWithTitles(t)
	for _, c := range []struct {
		name string
		opts TableOptions
	}{{"basic.table.golden", TableOptions{Width: 100}}, {"basic.table.narrow.golden", TableOptions{Width: 40}}} {
		var buf bytes.Buffer
		if err := WriteTable(&buf, r, c.opts); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(buf.Bytes(), []byte("\x1b")) {
			t.Error("no colour without Color=true")
		}
		golden := filepath.Join("testdata", c.name)
		if *update {
			os.WriteFile(golden, buf.Bytes(), 0o644)
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("read golden (run with -update to create): %v", err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s differs:\n%s", c.name, buf.String())
		}
	}
}

func TestTableQuietHidesPassAndManual(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, sampleReport(t), TableOptions{Quiet: true})
	out := buf.String()
	if strings.Contains(out, "muster.service.telnet_disabled") || strings.Contains(out, "muster.log.review") {
		t.Errorf("quiet must hide PASS and MANUAL rows:\n%s", out)
	}
	if !strings.Contains(out, "muster.account.root_remote_login") || !strings.Contains(out, "muster.file.passwd_permissions") {
		t.Errorf("quiet must keep FAIL and ERROR rows:\n%s", out)
	}
}

func TestTableEscapesObservationAndWaiverFields(t *testing.T) {
	snap, _ := facts.Load(strings.NewReader(`{"schema_version":1,"run":{"muster_version":"0.1.0","collected_at":"2026-09-02T06:00:00Z",
	  "host":{"hostname":"web-01"},"collectors":[{"name":"test","status":"ok","ms":1}],
	  "complete":true,"partial_failures":[]},"facts":{}}`))
	results := []check.Result{
		{ID: "test.obs", Importance: "상", Automation: "auto", Status: check.FAIL,
			Observations: []check.Observation{{Subject: "subject", Expected: "\x1b[31mX", Actual: false, Verdict: "fail"}}},
		{ID: "test.waiver", Importance: "상", Automation: "auto", Status: check.WAIVED,
			Waiver: &check.WaiverNote{Applied: true, Reason: "safe", Expires: "\x1b]0;evil\a"}},
	}
	cb := CheckBlock{MusterVersion: "0.1.0", Commit: "abc1234", ControlsVersion: "kisa-unix-2026+2026.09.02", ControlsDigest: "sha256:c", SnapshotDigest: snap.Digest(), GuideEdition: "kisa-unix-2026"}
	r := Build(snap, results, cb)

	var buf bytes.Buffer
	WriteTable(&buf, r, TableOptions{})
	out := buf.Bytes()
	if bytes.Contains(out, []byte("\x1b")) || bytes.Contains(out, []byte("\a")) {
		t.Fatalf("control chars in observation/waiver not escaped: %q", out)
	}
}
