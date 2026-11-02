package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// maxAgeLimit is 100 years of 365 days, in seconds (AX-14).
const maxAgeLimit = 100 * 365 * 86400

// skewAllowance is how far ahead of this clock a collected_at may be and
// still read as age 0 (AX-14).
const skewAllowance = 5 * time.Minute

// now is the command clock. Every command reads it once (AX-14) through
// commandClock; a test pins it.
var now = func() time.Time { return time.Now() }

// commandClock is the one reading a command takes: UTC, whole seconds.
func commandClock() time.Time { return now().UTC().Truncate(time.Second) }

var ageUnits = []struct {
	suffix byte
	secs   int64
}{{'w', 604800}, {'d', 86400}, {'h', 3600}, {'m', 60}, {'s', 1}}

// parseMaxAge reads the --max-age grammar: whole-number terms in descending
// unit order, each unit at most once, units w d h m s, from 1 second to 100
// years inclusive. Anything else is refused.
func parseMaxAge(s string) (int64, error) {
	bad := fmt.Errorf("--max-age must be whole-number terms like 7d, 2w or 1d12h (units w d h m s, descending, 1s to 100 years), got %q", s)
	if s == "" {
		return 0, bad
	}
	var total int64
	unit := 0 // next unit index allowed
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i || j >= len(s) {
			return 0, bad
		}
		n, err := strconv.ParseInt(s[i:j], 10, 64)
		if err != nil {
			return 0, bad
		}
		k := unit
		for k < len(ageUnits) && ageUnits[k].suffix != s[j] {
			k++
		}
		if k == len(ageUnits) {
			return 0, bad
		}
		if n > maxAgeLimit/ageUnits[k].secs {
			return 0, bad
		}
		total += n * ageUnits[k].secs
		if total > maxAgeLimit {
			return 0, bad
		}
		unit = k + 1
		i = j + 1
	}
	if total < 1 {
		return 0, bad
	}
	return total, nil
}

// parseCollectedAt accepts only YYYY-MM-DDTHH:MM:SSZ, round-trip equal.
func parseCollectedAt(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.UTC().Format("2006-01-02T15:04:05Z") != s {
		return time.Time{}, errors.New("collected_at is not YYYY-MM-DDTHH:MM:SSZ")
	}
	return t.UTC(), nil
}

// formatAge spells whole seconds as the full w d h m s decomposition, zero
// terms omitted; 0 is "0s".
func formatAge(secs int64) string {
	if secs <= 0 {
		return "0s"
	}
	var b strings.Builder
	for _, u := range ageUnits {
		if n := secs / u.secs; n > 0 {
			b.WriteString(strconv.FormatInt(n, 10))
			b.WriteByte(u.suffix)
			secs -= n * u.secs
		}
	}
	return b.String()
}

// staleError is checkAge's stale answer; enforceMaxAge swaps the bound's
// spelling for the flag value as given.
type staleError struct {
	collectedAt string
	age         int64
	bound       string
}

func (e *staleError) Error() string {
	return fmt.Sprintf("muster: snapshot collected at %s is %s old, older than --max-age %s", e.collectedAt, formatAge(e.age), e.bound)
}

// checkAge refuses a snapshot whose age exceeds maxAge seconds (inclusive),
// or whose collected_at cannot be judged. nowT is the command clock.
func checkAge(collectedAt string, maxAge int64, nowT time.Time) error {
	c, err := parseCollectedAt(collectedAt)
	if err != nil {
		return errors.New("muster: no usable collected_at; cannot judge --max-age")
	}
	nowT = nowT.UTC().Truncate(time.Second)
	if c.Sub(nowT) > skewAllowance {
		return fmt.Errorf("muster: snapshot collected at %s is in the future (more than 5m ahead of this clock); cannot judge --max-age", collectedAt)
	}
	age := int64(nowT.Sub(c) / time.Second)
	if age < 0 {
		age = 0
	}
	if age > maxAge {
		return &staleError{collectedAt, age, formatAge(maxAge)}
	}
	return nil
}

// enforceMaxAge is checkAge for a command that was given flag as --max-age.
func enforceMaxAge(collectedAt, flag string, maxAge int64, nowT time.Time) error {
	err := checkAge(collectedAt, maxAge, nowT)
	var se *staleError
	if errors.As(err, &se) {
		se.bound = flag
	}
	return err
}
