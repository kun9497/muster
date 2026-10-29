// Command cisindex builds docs/reference/cis/<product>-<version>.json and the
// three generated CIS Level 1 profiles from the ComplianceAsCode control files
// pinned by commit and SHA-256 in sources.json, joined with map.yaml and
// review.yaml. Only recommendation numbers, levels and rule ids leave the
// downloaded files (3D-1b CB-2); the files are data and never executed.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/cisindex"
	"github.com/kun9497/muster/internal/controls"
)

// source is one entry of sources.json: a benchmark file, or (EqualTo set) a
// second file whose ids and levels must equal the named benchmark's.
type source struct {
	Product   string   `json:"product,omitempty"`
	Benchmark string   `json:"benchmark,omitempty"`
	Version   string   `json:"version,omitempty"`
	Profile   string   `json:"profile,omitempty"`
	AppliesTo []string `json:"applies_to,omitempty"`
	EqualTo   string   `json:"equal_to,omitempty"`
	Repo      string   `json:"repo"`
	Tag       string   `json:"tag"`
	Commit    string   `json:"commit"`
	Path      string   `json:"path"`
	SHA256    string   `json:"sha256"`
}

var (
	shaRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command: 0 on success, 1 when -check found a difference, 2 when
// nothing could be built.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cisindex", flag.ContinueOnError)
	fs.SetOutput(stderr)
	srcPath := fs.String("sources", "tools/cisindex/sources.json", "pinned sources")
	cache := fs.String("cache", ".cache/cisindex", "download cache directory (git-ignored)")
	refDir := fs.String("ref-dir", "docs/reference/cis", "index output directory")
	profDir := fs.String("profile-dir", "internal/profile/builtin", "generated profile directory")
	mapPath := fs.String("map", "docs/reference/cis/map.yaml", "control map")
	reviewPath := fs.String("review", "docs/reference/cis/review.yaml", "review list")
	check := fs.Bool("check", false, "exit 1 if the committed files differ instead of writing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "cisindex: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	outs, err := generate(*srcPath, *cache, *mapPath, *reviewPath, *refDir, *profDir, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "cisindex: %v\n", err)
		return 2
	}
	stale := false
	for _, o := range outs {
		if *check {
			have, err := os.ReadFile(o.path)
			if err != nil || !bytes.Equal(have, o.data) {
				fmt.Fprintf(stderr, "cisindex: %s is out of date; run: go run ./tools/cisindex\n", o.path)
				stale = true
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(o.path), 0o755); err != nil {
			fmt.Fprintf(stderr, "cisindex: %v\n", err)
			return 2
		}
		if err := os.WriteFile(o.path, o.data, 0o644); err != nil {
			fmt.Fprintf(stderr, "cisindex: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "wrote %s\n", o.path)
	}
	if stale {
		return 1
	}
	return 0
}

type output struct {
	path string
	data []byte
}

// generate fetches, proves and builds; it writes nothing.
func generate(srcPath, cache, mapPath, reviewPath, refDir, profDir string, stderr io.Writer) ([]output, error) {
	sources, err := loadSources(srcPath)
	if err != nil {
		return nil, err
	}
	var benches []cisindex.Benchmark
	decoded := map[string]*cisindex.Source{}
	equal := map[string]*cisindex.Source{} // product → its equal_to file
	for _, s := range sources {
		data, err := fetch(cache, s)
		if err != nil {
			return nil, err
		}
		src, err := cisindex.DecodeControls(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Path, err)
		}
		if s.EqualTo != "" {
			equal[s.EqualTo] = src
			continue
		}
		if src.Version != s.Version {
			return nil, fmt.Errorf("%s: the file says version %s, sources.json %s", s.Path, src.Version, s.Version)
		}
		decoded[s.Product] = src
		benches = append(benches, cisindex.Benchmark{Product: s.Product, Display: s.Benchmark, Profile: s.Profile,
			AppliesTo: s.AppliesTo, Src: src,
			Pin: cisindex.Pin{Repo: s.Repo, Tag: s.Tag, Commit: s.Commit, Path: s.Path, SHA256: s.SHA256}})
	}
	// Prove every equal_to file equal to its benchmark on ids and levels; the
	// rule difference is logged, never read, and the file stays out of the union.
	for _, s := range sources {
		if s.EqualTo == "" {
			continue
		}
		if err := cisindex.SameIDsAndLevels(decoded[s.EqualTo], equal[s.EqualTo]); err != nil {
			return nil, fmt.Errorf("%s differs from %s: %w", s.Path, s.EqualTo, err)
		}
		if n := rulesDiffer(decoded[s.EqualTo], equal[s.EqualTo]); n > 0 {
			name := strings.Replace(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(s.Path), "cis_"), ".yml"), "almalinux", "alma", 1)
			fmt.Fprintf(stderr, "cisindex: %s rules differ from %s on %d entries (logged, not read)\n", name, s.EqualTo, n)
		}
		for i := range benches {
			if benches[i].Product == s.EqualTo {
				benches[i].EqualTo = &cisindex.EqualTo{Path: s.Path, SHA256: s.SHA256, Compared: "ids and levels"}
			}
		}
	}
	var srcs []*cisindex.Source
	for _, b := range benches {
		srcs = append(srcs, b.Src)
	}
	union := cisindex.RuleUnion(srcs...)

	mapData, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, err
	}
	rows, err := cisindex.DecodeMap(mapData)
	if err != nil {
		return nil, err
	}
	reviewData, err := os.ReadFile(reviewPath)
	if err != nil {
		return nil, err
	}
	review, err := cisindex.DecodeReview(reviewData)
	if err != nil {
		return nil, err
	}
	var profiles []string
	products := map[string]bool{}
	for _, b := range benches {
		profiles = append(profiles, b.Profile)
		products[b.Product] = true
	}
	if err := cisindex.CheckReviewProfiles(review, profiles); err != nil {
		return nil, err
	}
	if err := checkRecProducts(rows, products); err != nil {
		return nil, err
	}

	set, err := controls.LoadDefault()
	if err != nil {
		return nil, err
	}
	env := cisindex.Env{IDs: map[string]bool{}, Check: controls.CheckParamValue,
		ParamType: func(control, param string) (string, bool) {
			c, ok := set.ByID(control)
			if !ok {
				return "", false
			}
			p, ok := c.Params[param]
			return p.Type, ok
		}}
	for _, c := range set.Controls {
		env.IDs[c.ID] = true
	}

	var outs []output
	var errs []error
	for _, b := range benches {
		ix, prof, err := cisindex.Build(b, union, rows, review, env)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ixBytes, err := cisindex.RenderIndex(ix)
		if err != nil {
			return nil, err
		}
		profBytes, err := cisindex.RenderProfile(prof)
		if err != nil {
			return nil, err
		}
		outs = append(outs,
			output{filepath.Join(refDir, b.Product+"-"+strings.ToLower(ix.Version)+".json"), ixBytes},
			output{filepath.Join(profDir, b.Profile+".yaml"), profBytes})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return outs, nil
}

// checkRecProducts refuses a recs: key that is not a source product; the
// error names the control and the key.
func checkRecProducts(rows []cisindex.MapRow, products map[string]bool) error {
	var errs []error
	for _, r := range rows {
		keys := make([]string, 0, len(r.Recs))
		for k := range r.Recs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !products[k] {
				errs = append(errs, fmt.Errorf("map: %s: recs: %q is not a product of sources.json", r.ID, k))
			}
		}
	}
	return errors.Join(errs...)
}

// rulesDiffer counts the entries of two files with equal ids whose rule-id
// sets or variable selections differ.
func rulesDiffer(a, b *cisindex.Source) int {
	n := 0
	for i := 0; i < len(a.Entries) && i < len(b.Entries); i++ {
		if entryKey(a.Entries[i]) != entryKey(b.Entries[i]) {
			n++
		}
	}
	return n
}

func entryKey(e cisindex.Entry) string {
	parts := append([]string(nil), e.Rules...)
	for _, s := range e.Selections {
		parts = append(parts, s.Var+"="+s.Value)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// loadSources reads sources.json strictly and checks each entry's shape.
func loadSources(path string) ([]source, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var sources []source
	if err := dec.Decode(&sources); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: more than one JSON value", path)
	}
	products := map[string]bool{}
	for i, s := range sources {
		if s.Repo == "" || s.Tag == "" || s.Path == "" || !commitRE.MatchString(s.Commit) || !shaRE.MatchString(s.SHA256) {
			return nil, fmt.Errorf("%s: entry %d needs repo, tag, a 40-hex commit, path and a 64-hex sha256", path, i)
		}
		if s.EqualTo != "" {
			if s.Product != "" || s.Benchmark != "" || s.Version != "" || s.Profile != "" || s.AppliesTo != nil {
				return nil, fmt.Errorf("%s: entry %d: an equal_to entry carries no benchmark fields", path, i)
			}
			continue
		}
		if s.Product == "" || s.Benchmark == "" || s.Version == "" || s.Profile == "" {
			return nil, fmt.Errorf("%s: entry %d needs product, benchmark, version and profile", path, i)
		}
		if products[s.Product] {
			return nil, fmt.Errorf("%s: product %s appears twice", path, s.Product)
		}
		products[s.Product] = true
	}
	seenEqual := map[string]bool{}
	for _, s := range sources {
		if s.EqualTo == "" {
			continue
		}
		if !products[s.EqualTo] {
			return nil, fmt.Errorf("%s: equal_to %q names no product", path, s.EqualTo)
		}
		if seenEqual[s.EqualTo] {
			return nil, fmt.Errorf("%s: two equal_to entries name %s", path, s.EqualTo)
		}
		seenEqual[s.EqualTo] = true
	}
	return sources, nil
}

// fetch returns the pinned file, from the cache when its digest matches the
// pin, else downloaded; a copy whose digest differs from the pin is refused.
func fetch(cache string, s source) ([]byte, error) {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, err
	}
	local := filepath.Join(cache, s.SHA256)
	if blob, err := os.ReadFile(local); err == nil && digest(blob) == s.SHA256 {
		return blob, nil
	}
	url := "https://raw.githubusercontent.com/" + s.Repo + "/" + s.Commit + "/" + s.Path
	blob, err := download(url)
	if err != nil {
		return nil, err
	}
	if got := digest(blob); got != s.SHA256 {
		return nil, fmt.Errorf("%s: sha256 %s, pinned %s - refusing", url, got, s.SHA256)
	}
	if err := os.WriteFile(local, blob, 0o644); err != nil {
		return nil, err
	}
	return blob, nil
}

// download GETs url. A package-level var so a test can replace it and never
// reach the network.
var download = func(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
