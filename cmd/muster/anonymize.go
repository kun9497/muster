package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"

	"github.com/kun9497/muster/internal/anonymize"
	"github.com/kun9497/muster/internal/facts"
)

// anonymizeSynopsis is the command line of spec §2, in the usage text and
// pinned by a test.
const anonymizeSynopsis = "muster snapshot anonymize --facts <in|-> (--key <file> | --ephemeral) --out <file|-> [--force]"

// anonScheme names the pseudonym scheme a marked snapshot was written with
// (AX-10).
const anonScheme = "muster-anon-v1"

type anonymizeFlags struct {
	facts, key, out string
	keySet          bool
	ephemeral       bool
	force           bool
}

func parseAnonymizeArgs(args []string) (anonymizeFlags, error) {
	var f anonymizeFlags
	outSet := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			if args[i] == "" {
				return "", fmt.Errorf("flag %s needs a non-empty value", a)
			}
			return args[i], nil
		}
		var err error
		switch a {
		case "--facts":
			f.facts, err = next()
		case "--key":
			f.key, err = next()
			f.keySet = true
		case "--out":
			f.out, err = next()
			outSet = true
		case "--ephemeral":
			f.ephemeral = true
		case "--force":
			f.force = true
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
	if f.keySet == f.ephemeral {
		return f, errors.New("exactly one of --key and --ephemeral is required (AX-3)")
	}
	if !outSet {
		return f, errors.New("--out is required (- writes stdout)")
	}
	return f, nil
}

// runSnapshotAnonymize rewrites a snapshot for sharing (spec §2, AX-1):
// every refusal comes before anything is written, and a refusal writes
// nothing -- no file, nothing on stdout. Exit 0 written, 2 refused.
func runSnapshotAnonymize(args []string, stdout, stderr io.Writer) int {
	f, err := parseAnonymizeArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, snapshotUsage)
		return exitError
	}
	refuse := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "muster: "+format+"\n", a...)
		return exitError
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "muster: warning: snapshot anonymize does not need root")
	}

	// --out never names the input or the key, --force or not: either would be
	// destroyed by the very run that needs it.
	replace := false
	if f.out != "-" {
		if f.facts != "-" && samePath(f.out, f.facts) {
			return refuse("refusing to write the anonymised snapshot over its input: %s", f.out)
		}
		if f.keySet && samePath(f.out, f.key) {
			return refuse("refusing to write the anonymised snapshot over the key file: %s", f.out)
		}
		st, err := os.Lstat(f.out)
		switch {
		case err == nil && !f.force:
			return refuse("refusing to overwrite %s; --force replaces it", f.out)
		case err == nil && !st.Mode().IsRegular():
			return refuse("refusing to replace %s: not a regular file", f.out)
		case err == nil:
			replace = true
		case !os.IsNotExist(err):
			return refuse("%v", err)
		}
	}

	mode := "ephemeral"
	var raw []byte
	if f.keySet {
		mode = "keyed"
		if ok, why := trustedFile(f.key); !ok {
			return refuse("refusing the key file: %s", why)
		}
		raw, err = readKeyFile(f.key)
		if err != nil {
			return refuse("%v", err)
		}
	} else {
		// AX-3: a throwaway key, never written anywhere.
		raw = make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return refuse("ephemeral key: %v", err)
		}
	}
	key, err := anonymize.NewKey(raw)
	if err != nil {
		return refuse("%v", err)
	}

	// openFacts is the schema and size gate; the document itself is the tree
	// decoded beside it with json.Number, so every key and digit survives.
	snap, data, err := openFacts(f.facts)
	if err != nil {
		return refuse("%v", err)
	}
	doc, err := decodeDocument(data)
	if err != nil {
		return refuse("%v", err)
	}
	if run, ok := doc["run"].(map[string]any); ok {
		if _, marked := run["anonymization"]; marked {
			return refuse("%v (run.anonymization is set); anonymise the original", anonymize.ErrAlreadyAnonymized)
		}
	}
	if snap.Run.Redaction.IncludeSecrets {
		return refuse("refusing a snapshot collected with run.redaction.include_secrets true: it carries secrets no rule maps")
	}

	body, err := anonymizeDocument(doc, key, mode)
	if err != nil {
		var unc *anonymize.UnclassifiedError
		if errors.As(err, &unc) {
			return refuse("%s", unclassifiedMessage(snap.Run.MusterVersion, version, unc.Path))
		}
		return refuse("%v", err)
	}
	if f.out == "-" {
		if _, err := stdout.Write(body); err != nil {
			fmt.Fprintf(stderr, "muster: write: %v\n", err)
			return exitError
		}
		return exitOK
	}
	if replace {
		if err := os.Remove(f.out); err != nil {
			return refuse("%v", err)
		}
	}
	if err := writeExclusive(f.out, body); err != nil {
		return refuse("%v", err)
	}
	return exitOK
}

// anonymizeDocument is the transform the command runs between the refusals
// and the write: the document rewritten by the default table under key,
// marked with run.anonymization (AX-10) and encoded the way collect writes a
// snapshot. The invariant and canary tests run every corpus snapshot through
// it, so what they prove is what the command writes.
func anonymizeDocument(doc map[string]any, key *anonymize.Key, mode string) ([]byte, error) {
	out, rep, err := anonymize.Transform(doc, anonymize.Default, key, mode)
	if err != nil {
		return nil, err
	}
	mark := &facts.Anonymization{
		Scheme: anonScheme, Mode: mode, KeepSet: anonymize.KeepSetVersion,
		Classes: nonNil(rep.Classes), Replaced: nonNil(rep.Replaced),
	}
	if mode == "keyed" {
		mark.KeyID = key.ID()
	}
	run, _ := out["run"].(map[string]any)
	if run == nil {
		run = map[string]any{}
		out["run"] = run
	}
	run["anonymization"] = mark
	return encodeSnapshot(out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// samePath reports whether a and b name one file: by cleaned absolute path,
// or, when both exist, by os.SameFile (a hard link, another spelling).
func samePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil && aa == bb {
		return true
	}
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}

// readKeyFile reads a key file that must hold exactly 32 bytes (AX-3); a
// longer file is not read past its 33rd byte.
func readKeyFile(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(fh, 33))
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		n := strconv.Itoa(len(raw))
		if len(raw) > 32 {
			n = "more than 32"
		}
		return nil, fmt.Errorf("key file %s must hold exactly 32 bytes, it holds %s", path, n)
	}
	return raw, nil
}

// writeExclusive creates path with mode 0600, never through an existing
// file, and removes what it wrote when the write fails.
func writeExclusive(path string, body []byte) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := fh.Write(body)
	cerr := fh.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		return fmt.Errorf("write %s: %w", path, werr)
	}
	return nil
}

// versionRE is a muster_version this binary can order: a tag, optionally
// git describe's commit count and hash, optionally dirty.
var versionRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g[0-9a-f]+)?(?:-dirty)?$`)

// parseVersion returns the tag triple and the commit count past it.
func parseVersion(v string) ([4]uint64, bool) {
	var out [4]uint64
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return out, false
	}
	for i := 1; i <= 4; i++ {
		if m[i] == "" {
			continue
		}
		n, err := strconv.ParseUint(m[i], 10, 64)
		if err != nil {
			return out, false
		}
		out[i-1] = n
	}
	return out, true
}

// unclassifiedMessage is the refusal for a document path the table does not
// classify (AX-8): a snapshot from a newer muster than this binary asks for
// that muster; anything else -- an older or equal version, or one that
// cannot be ordered (dev, a bare hash, empty) -- is a muster bug.
func unclassifiedMessage(snapVersion, binVersion, path string) string {
	s, okS := parseVersion(snapVersion)
	b, okB := parseVersion(binVersion)
	if okS && okB {
		for i := range s {
			if s[i] != b[i] {
				if s[i] > b[i] {
					return "unclassified field " + path + ": anonymise with muster ≥ " + snapVersion
				}
				break
			}
		}
	}
	return "unclassified field " + path + ": a muster bug, please report it"
}

// decodeDocument decodes a whole snapshot document with json.Number, so
// integers above 2^53 and the fixture keys survive (spec §2).
func decodeDocument(data []byte) (map[string]any, error) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	if !facts.AtEnd(dec) {
		return nil, facts.ErrTrailingData
	}
	if doc == nil {
		return nil, errors.New("parse snapshot: not a JSON object")
	}
	return doc, nil
}

// orderedObject is a JSON object written in a fixed key order.
type orderedObject struct {
	keys []string
	m    map[string]any
}

func (o orderedObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(o.m[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

var (
	runType      = reflect.TypeOf(facts.Run{})
	envelopeType = reflect.TypeOf(facts.Envelope{})
	settingType  = reflect.TypeOf(facts.Setting{})
)

// encodeSnapshot writes a document the way collect writes a snapshot
// (json.MarshalIndent of facts.Snapshot, two spaces): schema_version, run
// and facts first, run's objects in their Go types' field order, every leaf
// at a registered key in facts.Envelope's or facts.Setting's, every other
// object's keys sorted. Any other top-level key (a fixture's synthetic,
// _expect, _provenance, _notes) follows, sorted.
func encodeSnapshot(doc map[string]any) ([]byte, error) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		return nil, err
	}
	top := orderedObject{m: map[string]any{}}
	for _, k := range []string{"schema_version", "run", "facts"} {
		if _, ok := doc[k]; ok {
			top.keys = append(top.keys, k)
		}
	}
	var rest []string
	for k := range doc {
		if k != "schema_version" && k != "run" && k != "facts" {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	top.keys = append(top.keys, rest...)
	for _, k := range top.keys {
		top.m[k] = doc[k]
	}
	top.m["run"] = shape(doc["run"], runType)
	if fm, ok := doc["facts"].(map[string]any); ok {
		top.m["facts"] = shapeFacts(fm, "", reg)
	}
	body, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// shapeFacts orders each leaf at a registered key by its Go type; the
// objects above the leaves are maps, sorted by the encoder as collect's are.
func shapeFacts(m map[string]any, prefix string, reg *facts.Registry) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		key := prefix + k
		if e, ok := reg.Lookup(key); ok {
			if reg.IsSetting(e) {
				out[k] = shape(v, settingType)
			} else {
				out[k] = shape(v, envelopeType)
			}
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			out[k] = shapeFacts(sub, key+".", reg)
			continue
		}
		out[k] = v
	}
	return out
}

// shape orders an object decoded from a value of Go type typ the way
// encoding/json writes typ: a struct's fields in declaration order (a key
// the struct does not declare after them, sorted), a map's keys sorted. A
// value of interface type, or any other value, is left as it is.
func shape(v any, typ reflect.Type) any {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch val := v.(type) {
	case map[string]any:
		switch typ.Kind() {
		case reflect.Struct:
			o := orderedObject{m: make(map[string]any, len(val))}
			seen := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name := jsonName(f)
				if _, ok := val[name]; ok && !seen[name] {
					seen[name] = true
					o.keys = append(o.keys, name)
					o.m[name] = shape(val[name], f.Type)
				}
			}
			var extra []string
			for k := range val {
				if !seen[k] {
					extra = append(extra, k)
				}
			}
			sort.Strings(extra)
			for _, k := range extra {
				o.keys = append(o.keys, k)
				o.m[k] = val[k]
			}
			return o
		case reflect.Map:
			out := make(map[string]any, len(val))
			for k, e := range val {
				out[k] = shape(e, typ.Elem())
			}
			return out
		}
	case []any:
		if typ.Kind() == reflect.Slice {
			out := make([]any, len(val))
			for i, e := range val {
				out[i] = shape(e, typ.Elem())
			}
			return out
		}
	}
	return v
}

func jsonName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			tag = tag[:i]
			break
		}
	}
	if tag == "" {
		return f.Name
	}
	return tag
}
