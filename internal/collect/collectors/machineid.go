package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var machineIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// MachineIDHash is the snapshot's host identity: the sha256 of a well-formed
// machine id (32 lowercase hex characters after trimming), and "" for
// anything else. The review script's host guard computes the same value
// (internal/remedy MachineIDHashHelper), so a malformed id turns the guard
// off instead of refusing the host it was planned on (3D-2b Q-1).
func MachineIDHash(data []byte) string {
	id := strings.TrimSpace(string(data))
	if !machineIDRe.MatchString(id) {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}
