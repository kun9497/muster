package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

const snapshotUsage = `usage: muster snapshot <extract> [flags]

extract cuts one control's fixture out of a snapshot: exactly the fact leaves
that control reads -- its applies_when, its checks, every mechanism's when and
checks, the evidence a manual control names, and the keys the engine resolves on
its own while it evaluates that control. Each leaf is copied content-faithfully,
with every field and every digit the host wrote and its object keys sorted, and
the file carries an empty run block and a provenance note naming the muster
version, the collection time and the OS. It never copies the hostname, it never
invents a leaf -- a key the snapshot does not carry is reported on stderr and
left out -- and it refuses to write over the snapshot it is cutting from.

The file it writes says "synthetic": false, because it is not synthetic: it came
off a real host. Read it, take out anything that identifies that host, and set
"synthetic": true by hand before committing it as a fixture -- the fixture test
rejects the file until a human has (D02, CONTRIBUTING.md).

flags:
  --facts <file>    the snapshot to cut from; - reads stdin (required)
  --control <id>    the control whose leaves to keep (required)
  --out <file>      write here instead of stdout

exit codes: 0 wrote the skeleton; 1 refused (no such control in the embedded
set); 2 bad flags or an I/O error.
`

// fixtureSkeleton is what extract writes: a snapshot cut down to the leaves
// one control reads. It is deliberately not a facts.Snapshot -- the run
// header is emptied, and a _provenance block records the little of it that a
// fixture may keep.
type fixtureSkeleton struct {
	// D02: only a human may call a file synthetic, so extract never does.
	Synthetic     bool           `json:"synthetic"`
	SchemaVersion int            `json:"schema_version"`
	Run           map[string]any `json:"run"`
	Provenance    provenance     `json:"_provenance"`
	Facts         map[string]any `json:"facts"`
}

// provenance is what a fixture may say about where it came from: which
// binary collected it, when, and which OS it was. Never the hostname, the
// machine id or an address -- a fixture is committed, and those are not
// muster's to publish (spec §5.1, D02).
type provenance struct {
	MusterVersion string `json:"muster_version"`
	CollectedAt   string `json:"collected_at"`
	OSID          string `json:"os_id"`
	OSVersionID   string `json:"os_version_id"`
}

type extractFlags struct{ facts, control, out string }

func parseExtractArgs(args []string) (extractFlags, error) {
	var f extractFlags
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--facts":
			f.facts, err = next()
		case "--control":
			f.control, err = next()
		case "--out":
			f.out, err = next()
		default:
			return f, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return f, err
		}
	}
	if f.facts == "" {
		return f, errors.New("--facts is required")
	}
	if f.control == "" {
		return f, errors.New("--control is required")
	}
	return f, nil
}

func runSnapshot(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, snapshotUsage)
		return exitError
	}
	switch args[0] {
	case "extract":
		return runSnapshotExtract(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "muster: unknown snapshot subcommand %q\n%s", args[0], snapshotUsage)
		return exitError
	}
}

func runSnapshotExtract(args []string, stdout, stderr io.Writer) int {
	f, err := parseExtractArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, snapshotUsage)
		return exitError
	}
	// The whole snapshot is in memory by the time the extract is written,
	// so pointing --out at --facts would succeed and quietly leave a few
	// hundred bytes where a host snapshot was. A snapshot is not cheap to
	// reproduce, so this is a refusal rather than a warning.
	if f.out != "" && f.facts != "-" {
		input, inErr := os.Stat(f.facts)
		output, outErr := os.Stat(f.out)
		if inErr == nil && outErr == nil && os.SameFile(input, output) {
			fmt.Fprintf(stderr, "muster: refusing to write the extract over the snapshot it was cut from: %s\n", f.out)
			return exitRefused
		}
	}
	// The bytes are kept as well as the decoded snapshot: openFacts applies
	// the size, depth and schema rules (spec 7.2), and the raw tree decoded
	// beside it is what the leaves are copied from. json.Number keeps every
	// number exactly as the snapshot wrote it -- decoded into float64 and
	// re-encoded, a large integer would come back in a different shape, and
	// a fixture that differs from its host is not evidence of anything.
	snap, data, err := openFacts(f.facts)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	var raw struct {
		Facts map[string]any `json:"facts"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		fmt.Fprintf(stderr, "muster: parse snapshot: %v\n", err)
		return exitError
	}
	set, err := controls.LoadDefault()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	c, ok := set.ByID(f.control)
	if !ok {
		fmt.Fprintf(stderr, "muster: %s is not a control of the embedded set; muster controls list names them all\n", f.control)
		return exitRefused
	}
	// The registry the evaluator would use: the engine reads the remote-NSS
	// degradation off a clause fact's subject_kind, so the keys a fixture needs
	// cannot be known from the control alone (EV-1).
	reg, err := facts.LoadRegistry()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}

	out := fixtureSkeleton{
		SchemaVersion: snap.SchemaVersion,
		Run:           map[string]any{},
		Provenance: provenance{
			MusterVersion: snap.Run.MusterVersion,
			CollectedAt:   snap.Run.CollectedAt,
			OSID:          snap.Run.Host.OSRelease.ID,
			OSVersionID:   snap.Run.Host.OSRelease.VersionID,
		},
		Facts: map[string]any{},
	}
	for _, key := range controlFactKeys(c, reg) {
		leaf, found := leafAtPath(raw.Facts, key)
		if !found {
			// Never invented: a fixture built from this file would report
			// ERROR(missing_fact) for the key, which is the truth about the
			// host it came from (spec §5.2).
			fmt.Fprintf(stderr, "missing: %s\n", key)
			continue
		}
		placeLeaf(out.Facts, key, leaf)
	}

	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	body = append(body, '\n')
	if f.out == "" {
		if _, err := stdout.Write(body); err != nil {
			fmt.Fprintf(stderr, "muster: write: %v\n", err)
			return exitError
		}
		return exitOK
	}
	// Silent on success: stderr carries the keys the snapshot could not
	// answer for and nothing else, so a clean run is a clean stderr.
	if err := os.WriteFile(f.out, body, 0o644); err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	return exitOK
}

// controlFactKeys returns, deduplicated and sorted, every fact key the
// control reads: the clauses it judges by, the evidence a manual control
// hands the reviewer (M-8), and the keys the engine resolves on its own while
// it evaluates this control (M-54). The last are controls.EngineKeys, so this
// command holds no opinion of its own about what the engine reads -- the
// walk gate and the two sshd degradations and the remote-NSS degradation all
// live beside engineReadKeys, where they can be held to it.
func controlFactKeys(c *controls.Control, reg *facts.Registry) []string {
	seen := map[string]bool{}
	mark := func(clauses []controls.Clause) {
		for _, cl := range clauses {
			if cl.Fact != "" {
				seen[cl.Fact] = true
			}
		}
	}
	mark(c.AppliesWhen)
	mark(c.Checks)
	for _, m := range c.Mechanisms {
		mark(m.When)
		mark(m.Checks)
	}
	for _, k := range c.Evidence {
		seen[k] = true
	}
	for _, k := range controls.EngineKeys(c, reg) {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// leafAtPath descends a decoded facts tree by a key's dotted segments and
// returns the leaf whole -- envelope or setting, with every field the
// snapshot wrote (the encoder later sorts the object keys, which is what the
// determinism ruling asks for; nothing else about the leaf changes). It is deliberately not facts.Registry.Resolve: that
// re-decodes a leaf into the envelope type, which drops a field the type
// does not know and elides an empty value, and a fixture must be what the
// host said, not what the reader understood of it.
func leafAtPath(tree map[string]any, key string) (any, bool) {
	var cur any = tree
	for _, seg := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// placeLeaf stores leaf at key's dotted path, creating the objects on the
// way, the same way collect's Builder.place builds the tree a snapshot is
// rendered from.
func placeLeaf(tree map[string]any, key string, leaf any) {
	segments := strings.Split(key, ".")
	cur := tree
	for _, seg := range segments[:len(segments)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[segments[len(segments)-1]] = leaf
}
