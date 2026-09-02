package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestTableGoldenWideAndNarrow(t *testing.T) {
	r := sampleReport(t)
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
