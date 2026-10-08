package remedy

import (
	"os/exec"
	"strings"
	"testing"
)

// muster never executes a remediation: the planner imports no host API and
// reads no clock (3D-2). Test files may import os; .Imports excludes them.
func TestRemedyPackageHasNoHostImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/remedy").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch imp {
		case "os", "os/exec", "net", "syscall", "time":
			t.Errorf("internal/remedy imports %s", imp)
		}
	}
}
