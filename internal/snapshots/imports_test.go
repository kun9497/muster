package snapshots

import (
	"os/exec"
	"strings"
	"testing"
)

// The listing and the prune selection are pure: the directory is read and
// changed by cmd/muster, the clock comes in as a parameter. Test files may
// import os; .Imports excludes them.
func TestSnapshotsPackageHasNoHostImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/snapshots").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch imp {
		case "os", "os/exec", "net", "syscall":
			t.Errorf("internal/snapshots imports %s", imp)
		}
	}
}
