package check

import (
	"os/exec"
	"strings"
	"testing"
)

// Forbidden imports make check impure: it must be a function of the snapshot,
// the control set, the waivers and the parameters, and nothing on the host
// (spec §4.2, D06). Direct and transitive dependencies are both checked.
func TestCheckPackageHasNoHostImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/kun9497/muster/internal/check").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	forbidden := []string{"os/exec", "net", "net/http", "syscall", "golang.org/x/sys"}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, f := range forbidden {
			if dep == f || strings.HasPrefix(dep, f+"/") {
				t.Errorf("internal/check depends on forbidden package %s", dep)
			}
		}
	}
}
