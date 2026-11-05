//go:build !linux

package main

import (
	"bytes"
	"testing"
)

// Off Linux rm and prune parse their flags, then the platform refuses.
func TestRmAndPruneRequireLinux(t *testing.T) {
	for _, args := range [][]string{
		{"snapshot", "rm", "--dir", t.TempDir(), "a.json"},
		{"snapshot", "prune", "--dir", t.TempDir(), "--keep", "1"},
	} {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		if code != exitError || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q; want 2 and empty", args, code, out.String())
		}
		if errb.String() != "muster: snapshot ls, rm and prune require Linux\n" {
			t.Errorf("%v: stderr = %q", args, errb.String())
		}
	}
}
