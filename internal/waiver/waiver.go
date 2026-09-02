// Package waiver loads waiver files and applies them after evaluation
// (spec §6.7, D12): a waiver is counted and reasoned, never silent, and never
// covers an ERROR.
package waiver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/check"
)

var ErrInvalid = errors.New("invalid waiver file")

type Waiver struct {
	Control string `yaml:"control"`
	Subject string `yaml:"subject,omitempty"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires,omitempty"` // YYYY-MM-DD, inclusive
}

type File struct {
	Waivers []Waiver `yaml:"waivers"`
	Path    string   `yaml:"-"`
	Digest  string   `yaml:"-"`
}

// Applied is the tally shown in every summary.
type Applied struct {
	Applied, NotApplied, Expired, Unknown, ExpiringSoon int
}

// Load decodes strictly and validates every rule of spec §6.7.
func Load(r io.Reader, path string) (*File, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, path, err)
	}
	for i, w := range f.Waivers {
		if strings.TrimSpace(w.Control) == "" {
			return nil, fmt.Errorf("%w: %s: waiver %d names no control", ErrInvalid, path, i+1)
		}
		if strings.TrimSpace(w.Reason) == "" {
			return nil, fmt.Errorf("%w: %s: waiver %d for %s has no reason", ErrInvalid, path, i+1, w.Control)
		}
		if w.Expires != "" {
			if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
				return nil, fmt.Errorf("%w: %s: waiver %d expires %q is not YYYY-MM-DD", ErrInvalid, path, i+1, w.Expires)
			}
		}
	}
	sum := sha256.Sum256(data)
	f.Path, f.Digest = path, "sha256:"+hex.EncodeToString(sum[:])
	return &f, nil
}

func (w Waiver) expired(now time.Time) bool {
	if w.Expires == "" {
		return false
	}
	exp, _ := time.Parse("2006-01-02", w.Expires)
	return !now.Before(exp.AddDate(0, 0, 1)) // inclusive of the named day
}

func (w Waiver) expiringSoon(now time.Time) bool {
	if w.Expires == "" {
		return false
	}
	exp, _ := time.Parse("2006-01-02", w.Expires)
	return exp.Before(now.AddDate(0, 0, 30))
}

// Apply mutates results in place. Only FAIL and WARN are waivable; a waiver
// that matches any other status is recorded as not applied so the reader
// sees it, and the exit code is untouched.
func (f *File) Apply(results []check.Result, known map[string]bool, now time.Time, warn func(string)) Applied {
	var tally Applied
	byControl := map[string][]Waiver{}
	for _, w := range f.Waivers {
		if !known[w.Control] {
			tally.Unknown++
			warn(fmt.Sprintf("waiver names unknown control %s", w.Control))
			continue
		}
		if w.expired(now) {
			tally.Expired++
			warn(fmt.Sprintf("waiver for %s expired on %s and no longer applies", w.Control, w.Expires))
			continue
		}
		byControl[w.Control] = append(byControl[w.Control], w)
	}
	for i := range results {
		r := &results[i]
		ws := byControl[r.ID]
		if len(ws) == 0 {
			continue
		}
		if r.Status != check.FAIL && r.Status != check.WARN {
			r.Waiver = &check.WaiverNote{Applied: false, Reason: ws[0].Reason, NotAppliedBecause: fmt.Sprintf("status %s is not waivable", r.Status)}
			tally.NotApplied++
			continue
		}
		whole := false
		for _, w := range ws {
			if w.Subject == "" {
				whole = true
				r.Waiver = &check.WaiverNote{Applied: true, Reason: w.Reason, Expires: w.Expires}
				if w.expiringSoon(now) {
					tally.ExpiringSoon++
				}
				break
			}
		}
		if whole {
			r.Status = check.WAIVED
			tally.Applied++
			continue
		}
		remaining := 0
		for oi := range r.Observations {
			o := &r.Observations[oi]
			if o.Verdict != "fail" {
				continue
			}
			for _, w := range ws {
				if w.Subject == o.Subject {
					o.Verdict = "waived"
					r.Waiver = &check.WaiverNote{Applied: true, Reason: w.Reason, Expires: w.Expires, Subject: w.Subject}
					if w.expiringSoon(now) {
						tally.ExpiringSoon++
					}
					break
				}
			}
			if o.Verdict == "fail" {
				remaining++
			}
		}
		if r.Waiver != nil && r.Waiver.Applied {
			tally.Applied++
			if remaining == 0 {
				r.Status = check.WAIVED
			}
		}
	}
	return tally
}
