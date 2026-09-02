package facts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SchemaVersion is the facts schema this binary writes and the highest it
// reads (spec §5.7, D17).
const SchemaVersion = 1

// Limits applied before decoding untrusted input (spec §7.2).
const (
	MaxSnapshotBytes = 64 << 20
	MaxDepth         = 32
)

var (
	ErrSchemaMismatch = errors.New("schema_mismatch")
	ErrTooLarge       = errors.New("snapshot exceeds size limit")
	ErrTooDeep        = errors.New("snapshot exceeds nesting limit")
)

type OSRelease struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Family    string `json:"family"` // debian | rhel | unknown
}

type Host struct {
	Hostname      string    `json:"hostname"`
	MachineIDHash string    `json:"machine_id_hash"`
	Kernel        string    `json:"kernel"`
	OSRelease     OSRelease `json:"os_release"`
	BootID        string    `json:"boot_id"`
	UptimeS       int64     `json:"uptime_s"`
}

type Env struct {
	Container      string `json:"container"` // none | docker | podman | lxc | other
	Virt           string `json:"virt"`      // none | kvm | vmware | ... | unknown
	WSL            bool   `json:"wsl"`
	Chroot         bool   `json:"chroot"`
	HasSystemd     bool   `json:"has_systemd"`
	SysctlWritable bool   `json:"sysctl_writable"`
	CloudInit      bool   `json:"cloud_init"`
}

type CollectorRun struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | denied | timeout | error | skipped
	Ms     int64  `json:"ms"`
	Cmd    string `json:"cmd,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Redaction struct {
	Profile        string   `json:"profile"` // default | none
	IncludeSecrets bool     `json:"include_secrets"`
	RedactedFields []string `json:"redacted_fields,omitempty"`
}

// Run is the provenance header (spec §5.1).
type Run struct {
	MusterVersion   string         `json:"muster_version"`
	Commit          string         `json:"commit"`
	ControlsVersion string         `json:"controls_version"`
	ControlsDigest  string         `json:"controls_digest"`
	GuideEdition    string         `json:"guide_edition"`
	CollectedAt     string         `json:"collected_at"`
	Host            Host           `json:"host"`
	EUID            int            `json:"euid"`
	Capabilities    []string       `json:"capabilities"`
	Env             Env            `json:"env"`
	Collectors      []CollectorRun `json:"collectors"`
	Redaction       Redaction      `json:"redaction"`
	Deep            bool           `json:"deep"`
	Complete        bool           `json:"complete"`
	PartialFailures []string       `json:"partial_failures"`
}

// Snapshot is one facts file. Facts is the decoded JSON tree; leaves are
// resolved through the Registry (Task 4) so check never walks raw paths.
type Snapshot struct {
	SchemaVersion int            `json:"schema_version"`
	Run           Run            `json:"run"`
	Facts         map[string]any `json:"facts"`
}

// Load reads and validates a snapshot from untrusted input (spec §7.2): size
// and nesting limits first, then the schema-version rule.
func Load(r io.Reader) (*Snapshot, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if len(data) > MaxSnapshotBytes {
		return nil, ErrTooLarge
	}
	if err := checkDepth(data, MaxDepth); err != nil {
		return nil, err
	}
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	if s.SchemaVersion < 1 {
		return nil, fmt.Errorf("%w: snapshot has no valid schema_version", ErrSchemaMismatch)
	}
	if s.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: snapshot schema_version %d is newer than this binary supports (%d)", ErrSchemaMismatch, s.SchemaVersion, SchemaVersion)
	}
	if s.Facts == nil {
		s.Facts = map[string]any{}
	}
	return &s, nil
}

// checkDepth walks the token stream and rejects nesting beyond max without
// building the tree, so a hostile input cannot exhaust memory first.
func checkDepth(data []byte, max int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse snapshot: %w", err)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > max {
					return ErrTooDeep
				}
			case '}', ']':
				depth--
			}
		}
	}
}

// Digest is the sha256 of the canonical re-encoding, reported by check so a
// result names the exact snapshot it was computed from (spec §9).
func (s *Snapshot) Digest() string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
