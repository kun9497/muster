//go:build linux

package collectors

import (
	"context"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	loginDefsPath = "/etc/login.defs"
	shadowPath    = "/etc/shadow"
)

var accountsCollector = collect.Collector{
	Name:    "accounts",
	Declare: collect.Declaration{Reads: []string{loginDefsPath, passwdPath, shadowPath}, Needs: "root"},
	Run:     runAccounts,
}

// loginDefs is /etc/login.defs read once (R48) and then searched per key,
// rather than reopened for each of the three values taken from it.
type loginDefs struct {
	lines []string
	meta  collect.ReadMeta
	err   error
}

func readLoginDefs(a collect.Access) loginDefs {
	data, meta, err := a.ReadFile(loginDefsPath, readLimit)
	return loginDefs{lines: splitLines(data), meta: meta, err: err}
}

// value returns key's integer value with the line it came from as evidence.
func (d loginDefs) value(key string) facts.Envelope {
	if d.err != nil {
		return collect.FromReadError(d.err, d.meta)
	}
	for i, raw := range d.lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != key {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			return collect.ErrorEnv(key + " is not a number in " + loginDefsPath)
		}
		return collect.OKRead(n, &facts.Source{
			Kind: "file", Path: loginDefsPath, Line: i + 1, Raw: sourceRaw(raw),
		}, d.meta)
	}
	return collect.Absent(key + " is not set in " + loginDefsPath)
}

// shadowRow is one /etc/shadow entry reduced to what a snapshot may hold:
// the ageing fields and the hash ALGORITHM id. The hash itself never leaves
// parseShadow, and no part of it is ever stored (spec §5.6).
type shadowRow struct {
	name       string
	status     string // hashed | locked | nopass
	algo       string // the "$id$" prefix, empty when there is no hash
	lastChange int
	min        int
	max        int
	warn       int
	inactive   int
	expire     int
}

// passwordStatus classifies the password field without keeping it.
func passwordStatus(pw string) string {
	switch {
	case pw == "":
		return "nopass"
	case strings.HasPrefix(pw, "!"), strings.HasPrefix(pw, "*"):
		return "locked"
	default:
		return "hashed"
	}
}

// hashAlgo returns the "$id$" prefix of a crypt hash and nothing else: no
// salt, no digest, not one byte of either. The prefix is cloned rather than
// sliced so the returned string does not keep the whole shadow line alive
// behind it.
func hashAlgo(pw string) string {
	if !strings.HasPrefix(pw, "$") {
		return ""
	}
	end := strings.Index(pw[1:], "$")
	if end <= 0 {
		return ""
	}
	return strings.Clone(pw[:end+2])
}

func parseShadow(data []byte) []shadowRow {
	var rows []shadowRow
	for _, line := range splitLines(data) {
		f := strings.Split(line, ":")
		if len(f) < 8 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		rows = append(rows, shadowRow{
			name:       f[0],
			status:     passwordStatus(f[1]),
			algo:       hashAlgo(f[1]),
			lastChange: intField(f[2]),
			min:        intField(f[3]),
			max:        intField(f[4]),
			warn:       intField(f[5]),
			inactive:   intField(f[6]),
			expire:     intField(f[7]),
		})
	}
	return rows
}

// ageingExtremes derives the ageing policy that actually applies to the
// accounts on this host: the largest PASS_MAX_DAYS and the smallest
// PASS_MIN_DAYS over accounts that have a password hash. An account with no
// password does not constrain the policy, and neither does an unset field.
func ageingExtremes(rows []shadowRow, meta collect.ReadMeta) (facts.Envelope, facts.Envelope) {
	derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: shadowPath}}}
	mx, mn := -1, -1
	for _, r := range rows {
		if r.status != "hashed" {
			continue
		}
		if r.max >= 0 && (mx < 0 || r.max > mx) {
			mx = r.max
		}
		if r.min >= 0 && (mn < 0 || r.min < mn) {
			mn = r.min
		}
	}
	none := collect.Absent("no account with a password hash carries this ageing field")
	maxR, minR := none, none
	if mx >= 0 {
		maxR = collect.OKRead(mx, derived, meta)
	}
	if mn >= 0 {
		minR = collect.OKRead(mn, derived, meta)
	}
	return maxR, minR
}

func runAccounts(_ context.Context, a collect.Access, b *collect.Builder) error {
	defs := readLoginDefs(a)
	b.Set("accounts.login_defs.pass_min_len", defs.value("PASS_MIN_LEN"))
	maxP, minP := defs.value("PASS_MAX_DAYS"), defs.value("PASS_MIN_DAYS")

	shadowData, smeta, serr := a.ReadFile(shadowPath, readLimit)
	var rows []shadowRow
	var maxR, minR facts.Envelope
	if serr != nil {
		// Unreadable shadow means the runtime side is denied (or whatever
		// the read said), never absent and never a value: without it we do
		// not know what applies to existing accounts.
		maxR = collect.FromReadError(serr, smeta)
		minR = collect.FromReadError(serr, smeta)
	} else {
		rows = parseShadow(shadowData)
		maxR, minR = ageingExtremes(rows, smeta)
	}
	b.SetSetting("accounts.login_defs.pass_max_days", facts.Setting{Runtime: &maxR, Persisted: &maxP})
	b.SetSetting("accounts.login_defs.pass_min_days", facts.Setting{Runtime: &minR, Persisted: &minP})

	pwData, pmeta, perr := a.ReadFile(passwdPath, readLimit)
	if perr != nil {
		b.Set("accounts.users", collect.FromReadError(perr, pmeta))
		return nil
	}
	byName := make(map[string]shadowRow, len(rows))
	for _, r := range rows {
		byName[r.name] = r
	}
	users := []any{} // R50: a host with no parsable accounts yields [], not null
	for _, line := range splitLines(pwData) {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		u := map[string]any{
			"name":  f[0],
			"uid":   intField(f[2]),
			"gid":   intField(f[3]),
			"shell": f[6],
		}
		// Without shadow the row simply has no ageing fields, rather than
		// zeroes that would read as a policy nobody set.
		if r, ok := byName[f[0]]; ok {
			u["password_status"] = r.status
			u["hash_algo"] = r.algo
			u["last_change"] = r.lastChange
			u["min"] = r.min
			u["max"] = r.max
			u["warn"] = r.warn
			u["inactive"] = r.inactive
			u["expire"] = r.expire
		}
		users = append(users, u)
	}
	b.Set("accounts.users", collect.OKRead(users, &facts.Source{Kind: "file", Path: passwdPath}, pmeta))
	return nil
}
