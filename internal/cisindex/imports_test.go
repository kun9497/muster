package cisindex

import (
	"os/exec"
	"strings"
	"testing"
)

// The index package is pure (3D-1b CB-2): no host API and no muster package.
func TestCISIndexImportsNoHostPackages(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/cisindex").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch imp {
		case "os", "os/exec", "net", "net/http", "syscall":
			t.Errorf("internal/cisindex imports %s", imp)
		}
		if strings.HasPrefix(imp, "github.com/kun9497/muster/") {
			t.Errorf("internal/cisindex imports %s", imp)
		}
	}
}
