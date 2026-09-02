package check

import (
	"os/exec"
	"strings"
	"testing"
)

// Forbidden imports make check impure: it must be a function of the snapshot,
// the control set, the waivers and the parameters, and nothing on the host
// (spec §4.2, D06).
//
// Two rules are enforced:
// (a) Transitive: no os/exec, net, net/http, golang.org/x/sys (syscall is
//
//	reachable from fmt; host plumbing at that depth is unavoidable).
//
// (b) Direct: check must not directly import os, os/exec, net, syscall,
//
//	io/fs, or path/filepath (these are host APIs check must not use).
func TestCheckPackageHasNoHostImports(t *testing.T) {
	// Rule (a): Transitive exec/net dependencies
	out, err := exec.Command("go", "list", "-deps", "github.com/kun9497/muster/internal/check").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	forbiddenTransitive := []string{"os/exec", "net", "net/http", "golang.org/x/sys"}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, f := range forbiddenTransitive {
			if dep == f || strings.HasPrefix(dep, f+"/") {
				t.Errorf("internal/check transitively depends on forbidden package %s", dep)
			}
		}
	}

	// Rule (b): Direct host API imports
	out, err = exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/check").Output()
	if err != nil {
		t.Fatalf("go list -f: %v", err)
	}
	forbiddenDirect := []string{"os", "os/exec", "net", "syscall", "io/fs", "path/filepath"}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, f := range forbiddenDirect {
			if imp == f {
				t.Errorf("internal/check directly imports forbidden package %s", imp)
			}
		}
	}
}
