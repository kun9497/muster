//go:build !linux

package main

import (
	"bytes"
	"testing"
)

// Off Linux the flags are parsed first, then the platform refuses.
func TestSnapshotLsRequiresLinux(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"snapshot", "ls", "--dir", t.TempDir()}, &out, &errb)
	if code != exitError || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q; want 2 and empty", code, out.String())
	}
	if errb.String() != "muster: snapshot ls, rm and prune require Linux\n" {
		t.Errorf("stderr = %q", errb.String())
	}
}
