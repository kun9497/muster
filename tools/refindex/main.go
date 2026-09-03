// Command refindex builds docs/reference/stig/*.json from DISA's public
// STIG XCCDF files and CCI list, pinned by URL and SHA-256 in sources.json.
// Only identifiers, severities and titles are reproduced.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// userAgent is sent on every download: the DoD cyber exchange CDN refuses
// Go's default User-Agent, so the tool identifies itself as a browser would.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) muster-refindex"

type source struct {
	Product   string   `json:"product"`
	AppliesTo []string `json:"applies_to,omitempty"`
	Benchmark string   `json:"benchmark,omitempty"`
	Version   string   `json:"version,omitempty"`
	URL       string   `json:"url"`
	SHA256    string   `json:"sha256"`
	Member    string   `json:"member"`
}

type index struct {
	Product     string      `json:"product"`
	AppliesTo   []string    `json:"applies_to,omitempty"`
	Benchmark   string      `json:"benchmark"`
	Version     string      `json:"version"`
	ReleaseInfo string      `json:"release_info"`
	Source      indexSource `json:"source"`
	CCIList     indexCCI    `json:"cci_list"`
	Rules       []xccdfRule `json:"rules"`
}

type indexSource struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Member string `json:"member"`
}

type indexCCI struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func main() {
	cache := flag.String("cache", ".cache/refindex", "download cache directory (git-ignored)")
	out := flag.String("out", "docs/reference/stig", "output directory")
	srcPath := flag.String("sources", "tools/refindex/sources.json", "pinned sources")
	check := flag.Bool("check", false, "exit 1 if the committed files differ instead of writing")
	flag.Parse()
	raw, err := os.ReadFile(*srcPath)
	if err != nil {
		fatal(err)
	}
	var sources []source
	if err := json.Unmarshal(raw, &sources); err != nil {
		fatal(fmt.Errorf("%s: %w", *srcPath, err))
	}
	var cci *cciList
	var cciSHA string
	for _, s := range sources {
		if s.Product == "cci" {
			data, sha, err := fetchMember(*cache, s)
			if err != nil {
				fatal(err)
			}
			if cci, err = parseCCI(data); err != nil {
				fatal(err)
			}
			cciSHA = sha
		}
	}
	if cci == nil {
		fatal(fmt.Errorf("sources.json has no cci entry"))
	}
	stale := false
	for _, s := range sources {
		if s.Product == "cci" {
			continue
		}
		data, _, err := fetchMember(*cache, s)
		if err != nil {
			fatal(err)
		}
		bench, err := parseXCCDF(data)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", s.Product, err))
		}
		// A warning, not a failure: the index is still correct, but the
		// affected rules carry an empty "nist" for a reason worth naming.
		if missing := unresolvedCCIs(bench, cci); len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "refindex: %s: %d CCI(s) not in the CCI list: %s\n",
				s.Product, len(missing), strings.Join(missing, ", "))
		}
		got, err := renderIndex(s, bench, cci, cciSHA)
		if err != nil {
			fatal(err)
		}
		path := filepath.Join(*out, s.Product+"-"+strings.ToLower(s.Version)+".json")
		if *check {
			have, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(have, got) {
				fmt.Fprintf(os.Stderr, "refindex: %s is out of date; run: go run ./tools/refindex\n", path)
				stale = true
			}
			continue
		}
		if err := os.MkdirAll(*out, 0o755); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s (%d rules)\n", path, len(bench.Rules))
	}
	if stale {
		os.Exit(1)
	}
}

// unresolvedCCIs returns the sorted, de-duplicated CCI ids the benchmark's
// rules cite that the pinned CCI list does not define. Such a rule still
// renders, with an empty "nist" array indistinguishable from a rule that
// genuinely maps to no control — so the tally is returned for the caller to
// warn about rather than being swallowed.
func unresolvedCCIs(b *benchmark, cci *cciList) []string {
	missing := map[string]bool{}
	for _, r := range b.Rules {
		for _, c := range r.CCIs {
			if _, ok := cci.NIST[c]; !ok {
				missing[c] = true
			}
		}
	}
	out := make([]string, 0, len(missing))
	for c := range missing {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// renderIndex joins the parsed benchmark with the CCI list and encodes it
// deterministically.
func renderIndex(s source, b *benchmark, cci *cciList, cciSHA string) ([]byte, error) {
	idx := index{Product: s.Product, AppliesTo: s.AppliesTo, Benchmark: s.Benchmark, Version: s.Version, ReleaseInfo: b.ReleaseInfo,
		Source: indexSource{URL: s.URL, SHA256: s.SHA256, Member: s.Member}, CCIList: indexCCI{Version: cci.Version, SHA256: cciSHA}}
	for _, r := range b.Rules {
		set := map[string]bool{}
		for _, c := range r.CCIs {
			for _, n := range cci.NIST[c] {
				set[n] = true
			}
		}
		r.NIST = make([]string, 0, len(set))
		for n := range set {
			r.NIST = append(r.NIST, n)
		}
		sort.Strings(r.NIST)
		idx.Rules = append(idx.Rules, r)
	}
	if idx.Rules == nil {
		idx.Rules = []xccdfRule{}
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// fetchMember returns the named member of the zip at s.URL, downloading
// into the cache when the cached copy is missing or its digest differs,
// and refusing a downloaded file whose digest does not match the pin.
func fetchMember(cache string, s source) ([]byte, string, error) {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, "", err
	}
	local := filepath.Join(cache, filepath.Base(s.URL))
	blob, err := os.ReadFile(local)
	if err != nil || digest(blob) != s.SHA256 {
		blob, err = download(s.URL)
		if err != nil {
			return nil, "", err
		}
		if got := digest(blob); got != s.SHA256 {
			return nil, "", fmt.Errorf("%s: sha256 %s, pinned %s — refusing", s.URL, got, s.SHA256)
		}
		if err := os.WriteFile(local, blob, 0o644); err != nil {
			return nil, "", err
		}
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", local, err)
	}
	for _, f := range zr.File {
		if f.Name == s.Member {
			rc, err := f.Open()
			if err != nil {
				return nil, "", err
			}
			defer rc.Close()
			data, err := io.ReadAll(io.LimitReader(rc, 64<<20))
			return data, s.SHA256, err
		}
	}
	return nil, "", fmt.Errorf("%s: member %s not found", local, s.Member)
}

// download GETs url with a browser-like User-Agent; the DoD CDN answers
// Go's default agent with a 403.
func download(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "refindex: %v\n", err)
	os.Exit(2)
}
