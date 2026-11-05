package facts

import (
	"os/exec"
	"strings"
	"testing"
)

// The facts model decodes untrusted input and touches no host API; reading a
// file is the command's job. Test files may import os; .Imports excludes them.
func TestFactsPackageHasNoHostImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/facts").Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Logf("%s", ee.Stderr)
		}
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch imp {
		case "os", "os/exec", "net", "syscall":
			t.Errorf("internal/facts imports %s", imp)
		}
	}
}
