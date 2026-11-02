//go:build linux

package collectors

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/kun9497/muster/internal/anonymize"
	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The anonymiser's table (3D-3 AX-8) is filled from this package's code, and
// these checks hold it to what the collectors write: every tree a collector
// test builds is recorded (recordTree, called by build/buildOn, buildBegun,
// buildBegunAt, buildPatch, pkgverifyRun, deepWalk and the all-collectors
// declaration test), and after the tests have run TestMain checks every
// recorded path against anonymize.Default and every list the table re-sorts
// against its sort spec. The recorder is test-only.

var recorded struct {
	sync.Mutex
	trees [][]byte
}

// recordTree keeps the facts b holds, as collect would write them.
func recordTree(b *collect.Builder) {
	j, err := json.Marshal(map[string]any{"facts": b.Tree()})
	if err != nil {
		panic(fmt.Sprintf("recordTree: %v", err))
	}
	recorded.Lock()
	recorded.trees = append(recorded.trees, j)
	recorded.Unlock()
}

func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		for _, check := range []func() []string{checkEmittedRecordsAreClassified, checkSortSpecsMatchCollectors} {
			if problems := check(); len(problems) > 0 {
				fmt.Fprintln(os.Stderr, strings.Join(problems, "\n"))
				code = 1
			}
		}
	}
	os.Exit(code)
}

func recordedDocs() []map[string]any {
	recorded.Lock()
	defer recorded.Unlock()
	docs := make([]map[string]any, 0, len(recorded.trees))
	for _, j := range recorded.trees {
		d := json.NewDecoder(bytes.NewReader(j))
		d.UseNumber()
		var doc map[string]any
		if err := d.Decode(&doc); err != nil {
			panic(err)
		}
		docs = append(docs, doc)
	}
	return docs
}

// TestEmittedRecordsAreClassified, run after every test: every path of
// every recorded tree is in the table.
func checkEmittedRecordsAreClassified() []string {
	gaps := map[string]bool{}
	for _, doc := range recordedDocs() {
		paths, err := anonymize.Unclassified(doc, anonymize.Default)
		if err != nil {
			return []string{"TestEmittedRecordsAreClassified: " + err.Error()}
		}
		for _, p := range paths {
			gaps[p] = true
		}
	}
	if len(gaps) == 0 {
		return nil
	}
	out := []string{fmt.Sprintf("--- FAIL: TestEmittedRecordsAreClassified: %d paths the collectors' tests emit are not in anonymize.Default:", len(gaps))}
	for p := range gaps {
		out = append(out, "    "+p)
	}
	sort.Strings(out[1:])
	return out
}

// TestSortSpecsMatchCollectors, run after every test: a list the table
// re-sorts is already in its spec's order as the collector wrote it, so
// re-sorting moves nothing but what mapping moved.
func checkSortSpecsMatchCollectors() []string {
	reg, err := facts.LoadRegistry()
	if err != nil {
		return []string{"TestSortSpecsMatchCollectors: " + err.Error()}
	}
	keys := map[string]bool{}
	for _, e := range reg.Keys {
		keys[e.Key] = true
	}
	var rows []string
	for row, r := range anonymize.Default {
		if r.Sort != nil {
			rows = append(rows, row)
		}
	}
	sort.Strings(rows)
	bad := map[string]bool{}
	seen := map[string]int{}
	for _, doc := range recordedDocs() {
		for _, row := range rows {
			key := tableFactKey(row, keys)
			if key == "" {
				bad[row+": names no registry key"] = true
				continue
			}
			for _, l := range listsAt(doc, key, strings.TrimPrefix(row, key)) {
				seen[row]++
				if !anonymize.Default[row].Sort.Sorted(l) {
					b, _ := json.Marshal(l)
					if len(b) > 300 {
						b = append(b[:300], "..."...)
					}
					bad[row+": not in its sort spec's order: "+string(b)] = true
				}
			}
		}
	}
	var out []string
	for b := range bad {
		out = append(out, "    "+b)
	}
	// A spec no test exercised is named (not failed) on a full run only: a
	// -run filter leaves most collectors unrun.
	if f := flag.Lookup("test.run"); f == nil || f.Value.String() == "" {
		for _, row := range rows {
			if seen[row] == 0 {
				fmt.Fprintf(os.Stderr, "TestSortSpecsMatchCollectors: unexercised sort spec %s\n", row)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return append([]string{"--- FAIL: TestSortSpecsMatchCollectors:"}, out...)
}

// tableFactKey is the registry key a table row continues.
func tableFactKey(row string, keys map[string]bool) string {
	for i := len(row); i > 0; i-- {
		if i < len(row) && row[i] != '.' && !strings.HasPrefix(row[i:], "[]") {
			continue
		}
		if keys[row[:i]] {
			return row[:i]
		}
	}
	return ""
}

// listsAt returns every list the value-relative path rest (""
// for the value itself, "[].f[].g" for a nested one) names under key's
// envelope values in doc, on every side of a setting.
func listsAt(doc map[string]any, key, rest string) [][]any {
	var node any = doc["facts"]
	for _, s := range strings.Split(key, ".") {
		m, _ := node.(map[string]any)
		node = m[s]
	}
	leaf, _ := node.(map[string]any)
	if leaf == nil {
		return nil
	}
	var values []any
	if _, ok := leaf["status"]; ok {
		values = append(values, leaf["value"])
	} else {
		for _, side := range []string{"runtime", "persisted", "effective"} {
			if e, ok := leaf[side].(map[string]any); ok {
				values = append(values, e["value"])
			}
		}
	}
	for _, seg := range strings.Split(strings.TrimPrefix(rest, "[]."), "[].") {
		if seg == "" {
			continue
		}
		var next []any
		for _, v := range values {
			l, _ := v.([]any)
			for _, e := range l {
				if m, ok := e.(map[string]any); ok {
					next = append(next, m[seg])
				}
			}
		}
		values = next
	}
	var out [][]any
	for _, v := range values {
		if l, ok := v.([]any); ok {
			out = append(out, l)
		}
	}
	return out
}
