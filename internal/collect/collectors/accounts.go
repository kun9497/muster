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

// str returns key's value verbatim — everything after the key, trimmed —
// with the line as evidence. login.defs values such as ENV_SUPATH contain
// "=" and ":" and UMASK is a mask, so nothing is parsed as a number here.
// The key must be followed by whitespace: UMASKX is not UMASK.
func (d loginDefs) str(key string) facts.Envelope {
	if d.err != nil {
		return collect.FromReadError(d.err, d.meta)
	}
	for i, raw := range d.lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(line, key)
		if !ok || rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		return collect.OKRead(strings.TrimSpace(rest), &facts.Source{
			Kind: "file", Path: loginDefsPath, Line: i + 1, Raw: sourceRaw(raw),
		}, d.meta)
	}
	return collect.Absent(key + " is not set in " + loginDefsPath)
}

// intOr is value(key) for callers that need a number to work with rather
// than a fact to report: the integer when the key is set and parses, def
// otherwise (unset, unparsable or an unreadable file).
func (d loginDefs) intOr(key string, def int) int {
	e := d.value(key)
	if e.Status != facts.StatusOK {
		return def
	}
	n, ok := e.Value.(int)
	if !ok {
		return def
	}
	return n
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
// salt, no digest, not one byte of either.
//
// The id has to look like one — 1 to 8 alphanumeric characters, which
// covers every crypt scheme in use ("1", "5", "6", "y", "2b", "gy",
// "argon2id") — because a malformed password field is not evidence of an
// algorithm, it is hash material. Without that check a line whose second
// "$" lands far into the digest would copy the digest into the snapshot
// under the name "hash_algo". The result is built from the id rather than
// sliced out of pw, so it cannot keep the whole shadow line alive behind
// it either.
func hashAlgo(pw string) string {
	if !strings.HasPrefix(pw, "$") {
		return ""
	}
	id, _, ok := strings.Cut(pw[1:], "$")
	if !ok || len(id) == 0 || len(id) > 8 || !isAlphanumeric(id) {
		return ""
	}
	return "$" + id + "$"
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		default:
			return false
		}
	}
	return true
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

// ageingWarn is the smallest PASS_WARN_AGE that applies to an account with
// a password hash (shadow field 6), the runtime side of pass_warn_age.
func ageingWarn(rows []shadowRow, meta collect.ReadMeta) facts.Envelope {
	derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: shadowPath}}}
	mn := -1
	for _, r := range rows {
		if r.status != "hashed" || r.warn < 0 {
			continue
		}
		if mn < 0 || r.warn < mn {
			mn = r.warn
		}
	}
	if mn < 0 {
		return collect.Absent("no account with a password hash carries this ageing field")
	}
	return collect.OKRead(mn, derived, meta)
}

func runAccounts(_ context.Context, a collect.Access, b *collect.Builder) error {
	defs := readLoginDefs(a)
	b.Set("accounts.login_defs.pass_min_len", defs.value("PASS_MIN_LEN"))
	maxP, minP, warnP := defs.value("PASS_MAX_DAYS"), defs.value("PASS_MIN_DAYS"), defs.value("PASS_WARN_AGE")
	// Fixed order (same input, same bytes): the integer boundaries, then the
	// verbatim strings.
	b.Set("accounts.login_defs.uid_min", defs.value("UID_MIN"))
	b.Set("accounts.login_defs.sys_uid_max", defs.value("SYS_UID_MAX"))
	b.Set("accounts.login_defs.sha_crypt_min_rounds", defs.value("SHA_CRYPT_MIN_ROUNDS"))
	for _, k := range [...]struct{ leaf, name string }{
		{"umask", "UMASK"}, {"home_mode", "HOME_MODE"}, {"encrypt_method", "ENCRYPT_METHOD"},
		{"env_supath", "ENV_SUPATH"}, {"env_path", "ENV_PATH"},
	} {
		b.Set("accounts.login_defs."+k.leaf, defs.str(k.name))
	}

	shadowData, smeta, serr := a.ReadFile(shadowPath, readLimit)
	var rows []shadowRow
	var maxR, minR, warnR facts.Envelope
	if serr != nil {
		// Unreadable shadow means the runtime side is denied (or whatever
		// the read said), never absent and never a value: without it we do
		// not know what applies to existing accounts.
		maxR = collect.FromReadError(serr, smeta)
		minR = collect.FromReadError(serr, smeta)
		warnR = collect.FromReadError(serr, smeta)
	} else {
		rows = parseShadow(shadowData)
		maxR, minR = ageingExtremes(rows, smeta)
		warnR = ageingWarn(rows, smeta)
	}
	b.SetSetting("accounts.login_defs.pass_max_days", facts.Setting{Runtime: &maxR, Persisted: &maxP})
	b.SetSetting("accounts.login_defs.pass_min_days", facts.Setting{Runtime: &minR, Persisted: &minP})
	b.SetSetting("accounts.login_defs.pass_warn_age", facts.Setting{Runtime: &warnR, Persisted: &warnP})

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
