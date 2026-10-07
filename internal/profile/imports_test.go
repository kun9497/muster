package profile

import (
	"os/exec"
	"strings"
	"testing"
)

// The profile package reads files only through the open function its caller
// passes and never writes to stderr (3D-1 Z-5): no host API is imported.
func TestProfilePackageHasNoHostImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/profile").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch imp {
		case "os", "os/exec", "net", "syscall":
			t.Errorf("internal/profile imports %s", imp)
		}
	}
}
