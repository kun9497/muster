package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var machineIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// asciiSpace is the C locale's [:space:] class.
const asciiSpace = " \t\n\r\v\f"

// MachineIDHash is the snapshot's host identity: the sha256 of a well-formed
// machine id (32 lowercase hex characters after trimming ASCII whitespace),
// and "" for anything else. The review script's host guard computes the same
// value (internal/remedy MachineIDHashHelper), so a malformed id turns the
// guard off instead of refusing the host it was planned on (3D-2b Q-1). Only
// the six bytes the helper's tr -d '[:space:]' deletes in the C locale are
// trimmed; Unicode whitespace (U+00A0, U+0085) stays and fails the pattern.
func MachineIDHash(data []byte) string {
	id := strings.Trim(string(data), asciiSpace)
	if !machineIDRe.MatchString(id) {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}
