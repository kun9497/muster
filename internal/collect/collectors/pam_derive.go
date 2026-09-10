//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"maps"
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
	parseKVInto(data, kv)
	return kv
}

// parseKVInto is parseKV into a map the caller owns, which is the shape
// mergeDropinsWith wants (M-23): a whole drop-in chain accumulates into one map
// and the last file to set a key wins. The systemd parser cannot stand in for
// it — it discards a line with no "=", which is exactly how pwquality writes a
// flag.
func parseKVInto(data []byte, kv map[string]string) {
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
		// R157: the evidence for "not stacked" is every file the stack was
		// expanded out of, not /etc/pam.d/passwd, which on Debian holds one
		// @include and none of the password lines that were searched.
		e := collect.OK(false, pamSource(s.x))
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
	// raw keeps the FINAL value seen for each integer key, parseable or not,
	// because apply is called in precedence order (the merged conf chain, then
	// the module arguments) - so raw[k] ends up holding exactly what the host
	// last said (M-50).
	raw := map[string]string{}
	apply := func(kv map[string]string) {
		for _, k := range pwqualityInts {
			if v, ok := kv[k]; ok {
				raw[k] = v
			}
			applyInt(vals, kv, k)
		}
		for _, f := range []string{"enforce_for_root", "local_users_only"} {
			if _, ok := kv[f]; ok {
				flags[f] = true
			}
		}
	}
	// pwquality.conf and its conf.d drop-ins resolve through the shared drop-in
	// helper (M-14), with pwquality's own parser rather than systemd's (M-23):
	// the main file first, then the directory in lexicographic order, the last
	// file to set a key winning. The first file that exists but cannot be read
	// comes back as the error and poisons every value below (R148); a file that
	// is simply not there is not one, and only the files actually read are cited.
	kv, confInputs, err := mergeDropinsWith(a, pwqualityConf, []string{pwqualityConfDir}, "*.conf", parseKVInto)
	if err != nil {
		e := dropinEnvelope(err)
		readErr = &e
	}
	apply(kv)
	inputs = append(inputs, confInputs...)
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
	// M-50: a value libpwquality would reject is not a value. applyInt drops it
	// silently, which would publish the compiled-in default as ok over a file
	// that plainly says something else. Such a key is absent instead, naming key
	// and value; the merged map cannot tell "minlen =" from a bare "minlen"
	// line and neither shape is an integer, so both land here. The offenders are
	// found by walking the fixed pwqualityInts, never the map (determinism).
	unparseable := func(k string) (facts.Envelope, bool) {
		v, seen := raw[k]
		if !seen {
			return facts.Envelope{}, false
		}
		if _, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return facts.Envelope{}, false
		}
		e := collect.Absent(k + " = " + strconv.Quote(v) + " is not an integer; libpwquality rejects the configuration")
		e.Source = src()
		return e, true
	}
	for _, k := range pwqualityInts {
		if e, bad := unparseable(k); bad {
			out["pam.pwquality."+k] = e
			continue
		}
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
	// required_classes is derived from minclass and the four credits; an
	// unparseable one of those five would make the derived number a guess, so it
	// goes absent with the offender. minlen is not one of its inputs.
	out["pam.pwquality.required_classes"] = collect.OK(required, src())
	for _, k := range []string{"minclass", "dcredit", "ucredit", "lcredit", "ocredit"} {
		if e, bad := unparseable(k); bad {
			out["pam.pwquality.required_classes"] = e
			break
		}
	}
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

// accessKeys is the fixed order the access-control keys are written in.
var accessKeys = []string{
	"pam.faillock.enabled", "pam.faillock.deny", "pam.faillock.unlock_time", "pam.faillock.fail_interval",
	"pam.faillock.even_deny_root", "pam.faillock.root_unlock_time",
	"pam.su.wheel_required", "pam.su.wheel_control", "pam.su.wheel_group", "pam.su.wheel_args",
	"pam.umask_module.enabled", "pam.umask_module.args", "pam.securetty_enabled",
}

// faillockServices are the services a lockout must cover to count.
var faillockServices = []string{"login", "sshd"}

// faillockInts are pam_faillock's numeric settings, in the order a
// disagreement between the preauth and the authfail line names them.
var faillockInts = []string{"deny", "unlock_time", "fail_interval", "root_unlock_time"}

// argsList renders module arguments as a fact value: a list, never nil (R50).
func argsList(args []string) []any {
	out := []any{}
	for _, a := range args {
		out = append(out, a)
	}
	return out
}

// applyFaillock overrides the numeric settings from one conf file or one
// line's arguments and reports whether root_unlock_time was among them.
func applyFaillock(dst map[string]int, kv map[string]string) bool {
	for _, k := range faillockInts {
		applyInt(dst, kv, k)
	}
	_, ok := kv["root_unlock_time"]
	return ok
}

// faillockEffective resolves one line's settings on top of base without
// disturbing it: what that half of the lockout alone would enforce.
// root_unlock_time falls back to the effective unlock_time when nothing
// set it, which is what pam_faillock itself does.
func faillockEffective(base map[string]int, rootSet bool, args []string) map[string]int {
	v := maps.Clone(base)
	if applyFaillock(v, argsKV(args)) {
		rootSet = true
	}
	if !rootSet {
		v["root_unlock_time"] = v["unlock_time"]
	}
	return v
}

// faillockComplete reports whether one service's stack is a whole lockout:
// pam_faillock.so with preauth and with authfail in the auth phase, and a
// reset half — the module in the account phase or an authsucc line in the
// auth phase (R151). It returns the two lines the values are read from.
func faillockComplete(lines []pamLine) (preauth, authfail *pamLine, ok bool) {
	authsucc := false
	for _, l := range linesOf(lines, "auth", "pam_faillock.so") {
		l := l
		if hasArg(l.Args, "preauth") && preauth == nil {
			preauth = &l
		}
		if hasArg(l.Args, "authfail") && authfail == nil {
			authfail = &l
		}
		if hasArg(l.Args, "authsucc") {
			authsucc = true
		}
	}
	reset := authsucc || len(linesOf(lines, "account", "pam_faillock.so")) > 0
	return preauth, authfail, preauth != nil && authfail != nil && reset
}

// faillockFacts derives pam.faillock.* . enabled requires the whole set in
// every existing login-facing service — a mention of the module is not a
// lockout. Values come from faillock.conf, then the preauth arguments,
// then the authfail arguments of the first complete service, each
// overriding the last.
func faillockFacts(s pamStacks, a collect.Access) map[string]facts.Envelope {
	out := map[string]facts.Envelope{}
	var preauth, authfail *pamLine
	missing := ""
	seen := false
	for _, svc := range faillockServices {
		if !s.has(svc) {
			continue
		}
		seen = true
		pre, fail, complete := faillockComplete(s.byName[svc])
		if !complete {
			if missing == "" {
				missing = svc
			}
			continue
		}
		if preauth == nil {
			preauth, authfail = pre, fail
		}
	}
	if !seen {
		for _, k := range accessKeys[:6] {
			out[k] = collect.Absent("neither login nor sshd has a PAM service file")
		}
		return out
	}
	if missing != "" {
		// R157/R158: the evidence for "the module is not stacked" is every
		// file the stacks were expanded out of, not the service file, which
		// on either family may hold nothing but includes.
		e := collect.OK(false, pamSource(s.x))
		e.Reason = missing + "'s stack lacks pam_faillock.so preauth, authfail or a reset (the module in the account phase or an authsucc line)"
		out["pam.faillock.enabled"] = e
		for _, k := range accessKeys[1:6] {
			out[k] = collect.Absent("faillock is not enabled")
		}
		return out
	}
	vals := map[string]int{"deny": 3, "unlock_time": 600, "fail_interval": 900, "root_unlock_time": 0}
	evenDenyRoot := false
	rootSet := false
	var inputs []facts.Source
	// R148: faillock.conf exists and the module reads it, so a value taken
	// from the defaults instead would be a guess about a file nobody here
	// can see. enabled still follows the stacks.
	var confErr *facts.Envelope
	if kv, src, err := readKV(a, faillockConf); err != nil {
		e := readErrorEnv(faillockConf, err)
		confErr = &e
	} else if kv != nil {
		rootSet = applyFaillock(vals, kv) || rootSet
		if _, ok := kv["even_deny_root"]; ok {
			evenDenyRoot = true
		}
		inputs = append(inputs, *src)
	}
	// R150: each line resolved on its own, so a disagreement is about the
	// values the two halves would enforce, not about the text.
	preEff := faillockEffective(vals, rootSet, preauth.Args)
	failEff := faillockEffective(vals, rootSet, authfail.Args)
	var differ []string
	for _, k := range faillockInts {
		if preEff[k] != failEff[k] {
			differ = append(differ, k)
		}
	}
	rootSet = applyFaillock(vals, argsKV(preauth.Args)) || rootSet
	inputs = append(inputs, lineSource(*preauth))
	rootSet = applyFaillock(vals, argsKV(authfail.Args)) || rootSet
	inputs = append(inputs, lineSource(*authfail))
	// R160: args_parse splits every argument that is not preauth, authfail or
	// authsucc at "=" and hands the name to set_conf_opt, which sets this flag
	// for even_deny_root whatever value follows it - so even_deny_root=0 sets
	// it, exactly as the conf file does. root_unlock_time, wherever it was
	// set, implies even_deny_root as well (pam_faillock(8)).
	evenDenyRoot = evenDenyRoot || hasArg(preauth.Args, "even_deny_root") || hasArg(authfail.Args, "even_deny_root") || rootSet
	if !rootSet {
		vals["root_unlock_time"] = vals["unlock_time"]
	}
	// A fresh Source per key, so no two envelopes share one pointer (R147).
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(inputs)} }
	enabled := collect.OK(true, src())
	if len(differ) > 0 {
		enabled.Reason = "preauth and authfail disagree on " + strings.Join(differ, ", ")
	}
	out["pam.faillock.enabled"] = enabled
	if confErr != nil {
		for _, k := range accessKeys[1:6] {
			out[k] = *confErr
		}
		return out
	}
	out["pam.faillock.deny"] = collect.OK(vals["deny"], src())
	out["pam.faillock.unlock_time"] = collect.OK(vals["unlock_time"], src())
	out["pam.faillock.fail_interval"] = collect.OK(vals["fail_interval"], src())
	out["pam.faillock.even_deny_root"] = collect.OK(evenDenyRoot, src())
	out["pam.faillock.root_unlock_time"] = collect.OK(vals["root_unlock_time"], src())
	return out
}

// suFacts derives pam.su.* from su's auth stack: the first pam_wheel.so
// line decides, by its control field and arguments, not by its presence.
func suFacts(s pamStacks) map[string]facts.Envelope {
	out := map[string]facts.Envelope{}
	if !s.has("su") {
		for _, k := range accessKeys[6:10] {
			out[k] = collect.Absent(pamDir + "/su does not exist")
		}
		return out
	}
	wheel := linesOf(s.byName["su"], "auth", "pam_wheel.so")
	if len(wheel) == 0 {
		e := collect.OK(false, pamSource(s.x))
		e.Reason = "no pam_wheel.so line in su's auth stack"
		out["pam.su.wheel_required"] = e
		for _, k := range accessKeys[7:10] {
			out[k] = collect.Absent("no pam_wheel.so line in su's auth stack")
		}
		return out
	}
	l := wheel[0]
	src := func() *facts.Source {
		return &facts.Source{Kind: "derived", Inputs: []facts.Source{lineSource(l)}}
	}
	required := (l.Control == "required" || l.Control == "requisite") && !hasArg(l.Args, "deny")
	e := collect.OK(required, src())
	if !required {
		e.Reason = "pam_wheel.so is stacked with control " + l.Control + " and arguments " + strings.Join(l.Args, " ") + ", which does not restrict su"
	}
	out["pam.su.wheel_required"] = e
	out["pam.su.wheel_control"] = collect.OK(l.Control, src())
	group := "wheel"
	if g, ok := argValue(l.Args, "group"); ok && g != "" {
		group = g
	}
	out["pam.su.wheel_group"] = collect.OK(group, src())
	out["pam.su.wheel_args"] = collect.OK(argsList(l.Args), src())
	return out
}

// umaskFacts derives pam.umask_module.* from the first existing service
// among login, sshd and other.
func umaskFacts(s pamStacks) map[string]facts.Envelope {
	out := map[string]facts.Envelope{}
	for _, svc := range []string{"login", "sshd", "other"} {
		if !s.has(svc) {
			continue
		}
		lines := linesOf(s.byName[svc], "session", "pam_umask.so")
		if len(lines) == 0 {
			e := collect.OK(false, pamSource(s.x))
			e.Reason = "no pam_umask.so line in " + svc + "'s session stack"
			out["pam.umask_module.enabled"] = e
			out["pam.umask_module.args"] = collect.Absent("pam_umask.so is not stacked")
			return out
		}
		src := func() *facts.Source {
			return &facts.Source{Kind: "derived", Inputs: []facts.Source{lineSource(lines[0])}}
		}
		out["pam.umask_module.enabled"] = collect.OK(true, src())
		out["pam.umask_module.args"] = collect.OK(argsList(lines[0].Args), src())
		return out
	}
	out["pam.umask_module.enabled"] = collect.Absent("no login, sshd or other PAM service file")
	out["pam.umask_module.args"] = collect.Absent("no login, sshd or other PAM service file")
	return out
}

// securettyFact derives pam.securetty_enabled from login's auth stack.
func securettyFact(s pamStacks) facts.Envelope {
	if !s.has("login") {
		return collect.Absent(pamDir + "/login does not exist")
	}
	lines := linesOf(s.byName["login"], "auth", "pam_securetty.so")
	if len(lines) == 0 {
		return collect.OK(false, pamSource(s.x))
	}
	return collect.OK(true, &facts.Source{Kind: "derived", Inputs: []facts.Source{lineSource(lines[0])}})
}
