package anonymize

import (
	"os/exec"
	"strings"
	"testing"
)

// The anonymize package is pure (3D-3 AX-2): no host API, and no import of the
// collectors or the control set.
func TestAnonymizeImportsNoHostPackages(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/anonymize").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch imp {
		case "os", "os/exec", "net", "syscall":
			t.Errorf("internal/anonymize imports %s", imp)
		}
		for _, p := range []string{"github.com/kun9497/muster/internal/collect", "github.com/kun9497/muster/internal/controls"} {
			if strings.HasPrefix(imp, p) {
				t.Errorf("internal/anonymize imports %s", imp)
			}
		}
	}
}
