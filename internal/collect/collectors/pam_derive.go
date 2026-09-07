//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// parseKV reads a "key = value" file the way libpwquality and pam_faillock
// read theirs: comments and blanks skipped, keys lower-cased, a bare word
// kept as a flag with an empty value, the last occurrence winning. A line
// with spaces but no "=" is not a key.
func parseKV(data []byte) map[string]string {
	kv := map[string]string{}
	for _, raw := range splitLines(data) {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok {
			if strings.ContainsAny(k, " \t") {
				continue
			}
			kv[k] = ""
			continue
		}
		kv[k] = strings.TrimSpace(v)
	}
	return kv
}

// readKV reads one conf file and tells the caller which of the three things
// happened (R148). A file that does not exist is (nil, nil, nil): the
// module's defaults apply and there is nothing to cite. A file that exists
// but could not be read is (nil, nil, err): the caller must publish that
// error, because a value derived from the defaults would claim the host is
// configured a way nobody can see. Otherwise the parsed pairs come back
// with the file as their source.
func readKV(a collect.Access, p string) (map[string]string, *facts.Source, error) {
	data, _, err := a.ReadFile(p, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return parseKV(data), &facts.Source{Kind: "file", Path: p}, nil
}

// readErrorEnv is a conf-file read error as the envelope every value that
// file could have set carries, with the path named exactly once in front of
// the reason (D16).
func readErrorEnv(p string, err error) facts.Envelope {
	e := collect.FromReadError(err, collect.ReadMeta{})
	e.Reason = p + ": " + e.Reason
	return e
}

// applyInt overrides dst[key] with kv[key] when it parses as an integer.
func applyInt(dst map[string]int, kv map[string]string, key string) {
	if v, ok := kv[key]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			dst[key] = n
		}
	}
}

// argsKV turns module arguments into the same key/value shape as a conf
// file, so one override rule serves both.
func argsKV(args []string) map[string]string {
	kv := map[string]string{}
	for _, a := range args {
		k, v, _ := strings.Cut(a, "=")
		kv[strings.ToLower(k)] = v
	}
	return kv
}

// passwordKeys is the fixed order the password-stack keys are written in.
var passwordKeys = []string{
	"pam.pwquality.enabled", "pam.pwquality.local_users_only", "pam.pwquality.minlen", "pam.pwquality.minclass",
	"pam.pwquality.dcredit", "pam.pwquality.ucredit", "pam.pwquality.lcredit", "pam.pwquality.ocredit",
	"pam.pwquality.required_classes", "pam.pwquality.enforce_for_root",
	"pam.password.unix_hash", "pam.password.remember",
}

var pwqualityInts = []string{"minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit"}

// unixHashArgs are pam_unix's hashing arguments. It is a membership set,
// not an order: the line is read left to right and the last of these wins
// (R152), exactly as the module itself resolves them.
var unixHashArgs = []string{"md5", "bigcrypt", "sha256", "sha512", "blowfish", "gost_yescrypt", "yescrypt"}

// pwhistoryDefaultRemember is pam_pwhistory's documented default (R149): a
// stack that loads the module with no remember= anywhere still checks the
// last ten passwords, so the fact is that ten, never absent.
const pwhistoryDefaultRemember = 10

// lineSource is the evidence of one stack line.
func lineSource(l pamLine) facts.Source {
	return facts.Source{Kind: "file", Path: l.Path, Line: l.Line}
}

// pwqualityFacts derives pam.pwquality.* from passwd's password stack and
// the conf files. Precedence: defaults, pwquality.conf, pwquality.conf.d
// in name order, then the module arguments of the enabled line.
func pwqualityFacts(s pamStacks, a collect.Access) map[string]facts.Envelope {
	out := map[string]facts.Envelope{}
	pw := s.byName["passwd"]
	var enabled *pamLine
	for _, l := range linesOf(pw, "password", "pam_pwquality.so") {
		if l.Control != "optional" {
			l := l
			enabled = &l
			break
		}
	}
	if enabled == nil {
		e := collect.OK(false, &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: pamDir + "/passwd"}}})
		e.Reason = "pam_pwquality.so is not stacked in passwd's password stack with an enforcing control"
		out["pam.pwquality.enabled"] = e
		for _, k := range passwordKeys[1:10] {
			out[k] = collect.Absent("pwquality is not enabled")
		}
		return out
	}
	vals := map[string]int{"minlen": 8, "minclass": 0, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0}
	flags := map[string]bool{}
	var inputs []facts.Source
	// readErr is the first conf file the module can read but this process
	// cannot; it replaces every value below, since the defaults would be a
	// guess about a file that exists (R148).
	var readErr *facts.Envelope
	fail := func(p string, err error) {
		if readErr == nil {
			e := readErrorEnv(p, err)
			readErr = &e
		}
	}
	apply := func(kv map[string]string) {
		for _, k := range pwqualityInts {
			applyInt(vals, kv, k)
		}
		for _, f := range []string{"enforce_for_root", "local_users_only"} {
			if _, ok := kv[f]; ok {
				flags[f] = true
			}
		}
	}
	if kv, src, err := readKV(a, pwqualityConf); err != nil {
		fail(pwqualityConf, err)
	} else if kv != nil {
		apply(kv)
		inputs = append(inputs, *src)
	}
	matches, err := a.Glob(pwqualityConfD)
	if err != nil {
		fail(pwqualityConfD, err)
	}
	slices.Sort(matches)
	for _, m := range matches {
		if kv, src, err := readKV(a, m); err != nil {
			fail(m, err)
		} else if kv != nil {
			apply(kv)
			inputs = append(inputs, *src)
		}
	}
	apply(argsKV(enabled.Args))
	inputs = append(inputs, lineSource(*enabled))
	// A fresh Source per key, so no two envelopes share one pointer (R147).
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(inputs)} }
	out["pam.pwquality.enabled"] = collect.OK(true, src())
	if readErr != nil {
		for _, k := range passwordKeys[1:10] {
			out[k] = *readErr
		}
		return out
	}
	out["pam.pwquality.local_users_only"] = collect.OK(flags["local_users_only"], src())
	for _, k := range pwqualityInts {
		out["pam.pwquality."+k] = collect.OK(vals[k], src())
	}
	required := vals["minclass"]
	negative := 0
	for _, k := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		if vals[k] <= -1 {
			negative++
		}
	}
	if negative > required {
		required = negative
	}
	out["pam.pwquality.required_classes"] = collect.OK(required, src())
	out["pam.pwquality.enforce_for_root"] = collect.OK(flags["enforce_for_root"], src())
	return out
}

// passwordFacts derives pam.password.* from passwd's password stack.
func passwordFacts(s pamStacks, a collect.Access) map[string]facts.Envelope {
	out := map[string]facts.Envelope{}
	pw := s.byName["passwd"]
	unix := linesOf(pw, "password", "pam_unix.so")
	if len(unix) == 0 {
		out["pam.password.unix_hash"] = collect.Absent("passwd's password stack has no pam_unix.so line")
	} else {
		// R152: read the line left to right and keep the last hashing
		// argument, which is the one pam_unix itself ends up using.
		hash := ""
		for _, arg := range unix[0].Args {
			if slices.Contains(unixHashArgs, arg) {
				hash = arg
			}
		}
		out["pam.password.unix_hash"] = collect.OK(hash, &facts.Source{Kind: "derived", Inputs: []facts.Source{lineSource(unix[0])}})
	}
	out["pam.password.remember"] = rememberFact(pw, unix, a)
	return out
}

// rememberFact resolves pam.password.remember. pam_pwhistory owns the
// answer wherever it is stacked — its argument, else pwhistory.conf, else
// its own default of ten (R149) — and pam_unix's remember= is consulted
// only when pwhistory is not stacked at all.
func rememberFact(pw, unix []pamLine, a collect.Access) facts.Envelope {
	derived := func(n int, src facts.Source) facts.Envelope {
		return collect.OK(n, &facts.Source{Kind: "derived", Inputs: []facts.Source{src}})
	}
	if hist := linesOf(pw, "password", "pam_pwhistory.so"); len(hist) > 0 {
		if v, ok := argValue(hist[0].Args, "remember"); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return derived(n, lineSource(hist[0]))
			}
		}
		kv, src, err := readKV(a, pwhistoryConf)
		if err != nil {
			return readErrorEnv(pwhistoryConf, err)
		}
		if kv != nil {
			if n, err := strconv.Atoi(kv["remember"]); err == nil {
				return derived(n, *src)
			}
		}
		return derived(pwhistoryDefaultRemember, lineSource(hist[0]))
	}
	if len(unix) > 0 {
		if v, ok := argValue(unix[0].Args, "remember"); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return derived(n, lineSource(unix[0]))
			}
		}
	}
	return collect.Absent("no remember= on pam_pwhistory.so, in pwhistory.conf or on pam_unix.so")
}
