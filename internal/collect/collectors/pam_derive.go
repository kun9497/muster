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

// readConf reads one conf file and tells the caller which of the three
// things happened (R148). A file that does not exist is (nil, nil, nil): the
// module's defaults apply and there is nothing to cite. A file that exists
// but could not be read is (nil, nil, err): the caller must publish that
// error, because a value derived from the defaults would claim the host is
// configured a way nobody can see. Otherwise the bytes come back with the
// file as their source, for the module's own reader (pam_conf.go).
func readConf(a collect.Access, p string) ([]byte, *facts.Source, error) {
	data, _, err := a.ReadFile(p, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return data, &facts.Source{Kind: "file", Path: p}, nil
}

// readErrorEnv is a conf-file read error as the envelope every value that
// file could have set carries, with the path named exactly once in front of
// the reason (D16).
func readErrorEnv(p string, err error) facts.Envelope {
	return pathReason(p, collect.FromReadError(err, collect.ReadMeta{}))
}

// applyInt overrides dst[key] with kv[key] when libpwquality's
// set_name_value would take it as an integer (pwqualityInt).
func applyInt(dst map[string]int, kv map[string]string, key string) {
	if v, ok := kv[key]; ok {
		if n, ok := pwqualityInt(v); ok {
			dst[key] = n
		}
	}
}

// argsKV turns pam_pwquality's module arguments into the same key/value shape
// as a conf file, so one override rule serves both: each argument is split at
// its first "=" and its name ASCII lower-cased, as pwquality_set_option hands
// it to set_name_value (strcasecmp).
func argsKV(args []string) map[string]string {
	kv := map[string]string{}
	for _, a := range args {
		k, v, _ := strings.Cut(a, "=")
		kv[asciiLower(k)] = v
	}
	return kv
}

// pwqualityStopReason is the reason every value leaf carries when a file
// stops libpwquality's reading of the chain (H-5): the file and line, the
// line as written, and what is not applied after it — the later files, or,
// in pwquality.conf (read last), the later lines.
func pwqualityStopReason(s *chainStop) string {
	after := "the files after it are not applied"
	if s.Path == pwqualityConf {
		after = "the lines after it are not applied"
	}
	what := s.Why
	if what == "" {
		what = sourceRaw(s.Text)
	}
	return "libpwquality stops reading at " + s.Path + ":" + strconv.Itoa(s.Line) + " (" + what + "); " + after
}

// pwqualityValueKeys are the pam.pwquality.* keys derived from the conf chain
// and the module line: every pwquality key but enabled. They go absent
// together when the module is not stacked and carry the same read error when
// a conf file cannot be read (R148).
var pwqualityValueKeys = []string{
	"pam.pwquality.local_users_only", "pam.pwquality.minlen", "pam.pwquality.minclass",
	"pam.pwquality.dcredit", "pam.pwquality.ucredit", "pam.pwquality.lcredit", "pam.pwquality.ocredit",
	"pam.pwquality.required_classes", "pam.pwquality.enforce_for_root", "pam.pwquality.enforcing",
}

// passwordKeys is the fixed order the password-stack keys are written in.
var passwordKeys = slices.Concat(
	[]string{"pam.pwquality.enabled"},
	pwqualityValueKeys,
	[]string{"pam.password.unix_hash", "pam.password.remember"},
)

// pwqualityInts are libpwquality's integer settings muster reads. enforcing
// is one of them (settings.c): 0 makes pam_pwquality warn about a weak
// password and accept it anyway.
var pwqualityInts = []string{"minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit", "enforcing"}

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
// the conf files. Precedence is libpwquality's (pwquality_read_config, then
// the module's own argument parsing): defaults, pwquality.conf.d in name
// order, pwquality.conf LAST of the files, then the module arguments of the
// enabled line.
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
		for _, k := range pwqualityValueKeys {
			out[k] = collect.Absent("pwquality is not enabled")
		}
		return out
	}
	// libpwquality's compiled-in defaults; enforcing defaults to 1 (reject).
	vals := map[string]int{"minlen": 8, "minclass": 0, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "enforcing": 1}
	flags := map[string]bool{}
	var inputs []facts.Source
	// readErr is the first conf file the module can read but this process
	// cannot; it replaces every value below, since the defaults would be a
	// guess about a file that exists (R148).
	var readErr *facts.Envelope
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
	// pwquality.conf and its conf.d drop-ins resolve through the shared drop-in
	// helper (M-14), with libpwquality's own reader rather than systemd's
	// (M-23, H-5) and libpwquality's order rather than systemd's: the directory
	// in lexicographic order first, then pwquality.conf, the last file to set a
	// key winning — so the main file beats every drop-in. The first file that
	// exists but cannot be read comes back as the error and poisons every value
	// below (R148); a file that is simply not there is not one, and only the
	// files actually read are cited.
	kv, confInputs, stop, err := mergeDropinsWith(a, pwqualityConf, []string{pwqualityConfDir}, "*.conf", chainReader{
		parse: parsePwqualityInto, order: mainLast, keep: pwqualityDropinName, binary: true,
	})
	if err != nil {
		e := dropinEnvelope(err)
		readErr = &e
	}
	apply(kv)
	inputs = append(inputs, confInputs...)
	// pam_pwquality hands each argument it does not handle itself to
	// pwquality_set_option and logs one libpwquality refuses, so a refused
	// argument changes nothing (applyInt skips it).
	apply(argsKV(enabled.Args))
	inputs = append(inputs, lineSource(*enabled))
	// A fresh Source per key, so no two envelopes share one pointer (R147).
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(inputs)} }
	out["pam.pwquality.enabled"] = collect.OK(true, src())
	if readErr != nil {
		for _, k := range pwqualityValueKeys {
			out[k] = *readErr
		}
		return out
	}
	out["pam.pwquality.local_users_only"] = collect.OK(flags["local_users_only"], src())
	out["pam.pwquality.enforce_for_root"] = collect.OK(flags["enforce_for_root"], src())
	// H-5 (which folds M-50 in): a line libpwquality refuses — an unknown name
	// or an integer set_name_value rejects — stops that file and every file
	// after it, and what libpwquality then enforces depends on what happened
	// to be applied before the stop. That is not a value muster publishes:
	// every integer and the classes derived from them are absent, naming the
	// line. The flags are what libpwquality applied before the stop, as it
	// applies them.
	if stop != nil {
		for _, k := range pwqualityInts {
			e := collect.Absent(pwqualityStopReason(stop))
			e.Source = src()
			out["pam.pwquality."+k] = e
		}
		e := collect.Absent(pwqualityStopReason(stop))
		e.Source = src()
		out["pam.pwquality.required_classes"] = e
		return out
	}
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
	// required_classes is derived from minclass and the four credits; minlen
	// and enforcing are not among its inputs.
	out["pam.pwquality.required_classes"] = collect.OK(required, src())
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
		data, src, err := readConf(a, pwhistoryConf)
		if err != nil {
			return readErrorEnv(pwhistoryConf, err)
		}
		// H-6: the first remember line is the answer (pam_modutil_search_key);
		// one whose value does not convert leaves the module's default.
		if data != nil {
			n, line, found, ok := pwhistoryRemember(data)
			if found && ok {
				return derived(n, *src)
			}
			if found {
				// C3: the file decided that the default stands, so it is cited
				// at that line beside the stack line.
				return collect.OK(pwhistoryDefaultRemember, &facts.Source{Kind: "derived", Inputs: []facts.Source{
					{Kind: "file", Path: pwhistoryConf, Line: line}, lineSource(hist[0]),
				}})
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

// faillockEffective resolves one line's settings on top of the conf file's
// without disturbing them: what that half of the lockout alone would enforce.
// The arguments go through the same set_conf_opt rules as the file (H-6).
// root_unlock_time falls back to the effective unlock_time when nothing set
// it, which is what pam_faillock itself does.
func faillockEffective(base faillockOpts, args []string) faillockOpts {
	o := base.clone()
	o.setArgs(args)
	if !o.rootSet {
		o.vals["root_unlock_time"] = o.vals["unlock_time"]
	}
	return o
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

// weakerFaillock is the weaker of two values of one pam_faillock setting:
// what the less strict of two stack lines, or of two services, enforces.
// deny 0 never locks (check_tally locks only when deny is set and the count
// reaches it), so it is weaker than any count, and otherwise the larger count
// is the weaker. unlock_time 0 never unlocks, so the shorter non-zero wait is
// the weaker. check_tally counts only the failures inside fail_interval, so
// the shorter window is the weaker (H-3; no control reads it).
func weakerFaillock(k string, a, b int) int {
	switch k {
	case "deny":
		if a == 0 || b == 0 {
			return 0
		}
		return max(a, b)
	case "unlock_time", "root_unlock_time":
		if a == 0 {
			return b
		}
		if b == 0 {
			return a
		}
		return min(a, b)
	case "fail_interval":
		return min(a, b)
	default:
		panic("weakerFaillock: unknown setting " + k)
	}
}

// faillockService is one complete service's lockout, resolved.
type faillockService struct {
	name           string
	vals           map[string]int
	evenDenyRoot   bool
	preauthDiffers []string
}

// faillockFacts derives pam.faillock.* . enabled requires the whole set in
// every existing login-facing service — a mention of the module is not a
// lockout. pam_faillock resolves its options on every call from the line
// that made it (defaults, faillock.conf, that line's arguments), and sshd
// authenticates through its own stack, so every complete service is
// resolved on its own: its preauth and its authfail line each on top of the
// conf file, the weaker of the two kept (R150). The facts are the weakest
// values across the services (weakerFaillock; even_deny_root only when every
// service denies root), the evidence is every service's two lines, and a
// disagreement — between a service's two lines or between services — is
// named in enabled's reason.
func faillockFacts(s pamStacks, a collect.Access) map[string]facts.Envelope {
	out := map[string]facts.Envelope{}
	type pair struct {
		svc       string
		pre, fail *pamLine
	}
	var pairs []pair
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
		pairs = append(pairs, pair{svc, pre, fail})
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
	base := faillockOpts{vals: map[string]int{"deny": 3, "unlock_time": 600, "fail_interval": 900, "root_unlock_time": 0}}
	var inputs []facts.Source
	// R148: faillock.conf exists and the module reads it, so a value taken
	// from the defaults instead would be a guess about a file nobody here
	// can see. enabled still follows the stacks.
	var confErr *facts.Envelope
	// H-6: faillock.conf is read with pam_faillock's own tokenizer and its
	// lines applied in order through set_conf_opt's rules, the last one winning.
	if data, src, err := readConf(a, faillockConf); err != nil {
		e := readErrorEnv(faillockConf, err)
		confErr = &e
	} else if data != nil {
		for _, c := range parseFaillockConf(data) {
			base.set(c.name, c.value)
		}
		inputs = append(inputs, *src)
	}
	var services []faillockService
	for _, p := range pairs {
		// R150: each line resolved on its own, so a disagreement is about
		// the values the two halves would enforce, not about the text.
		pre := faillockEffective(base, p.pre.Args)
		fail := faillockEffective(base, p.fail.Args)
		svc := faillockService{name: p.svc, vals: map[string]int{}}
		for _, k := range faillockInts {
			if pre.vals[k] != fail.vals[k] {
				svc.preauthDiffers = append(svc.preauthDiffers, k)
			}
			svc.vals[k] = weakerFaillock(k, pre.vals[k], fail.vals[k])
		}
		// R160: args_parse splits every argument that is not preauth,
		// authfail or authsucc at "=" and hands the name to set_conf_opt,
		// which sets this flag for even_deny_root whatever value follows it
		// - so even_deny_root=0 sets it, exactly as the conf file does.
		// root_unlock_time, wherever it was named, implies even_deny_root as
		// well (pam_faillock(8)). faillockOpts.set records both.
		svc.evenDenyRoot = pre.denyRoot || fail.denyRoot
		services = append(services, svc)
		for _, l := range []pamLine{*p.pre, *p.fail} {
			if ls := lineSource(l); !slices.ContainsFunc(inputs, func(in facts.Source) bool { return in.Path == ls.Path && in.Line == ls.Line }) {
				inputs = append(inputs, ls)
			}
		}
	}
	vals := maps.Clone(services[0].vals)
	evenDenyRoot := services[0].evenDenyRoot
	for _, svc := range services[1:] {
		for _, k := range faillockInts {
			vals[k] = weakerFaillock(k, vals[k], svc.vals[k])
		}
		evenDenyRoot = evenDenyRoot && svc.evenDenyRoot
	}
	// A fresh Source per key, so no two envelopes share one pointer (R147).
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(inputs)} }
	enabled := collect.OK(true, src())
	enabled.Reason = faillockDisagreement(services)
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

// faillockDisagreement names what the lockout's lines disagree on: a
// service whose preauth and authfail lines resolve differently (R150; when
// every service's lines differ on the same settings the text names no
// service), then each setting the services resolve differently, with every
// service's value in service order, e.g. "login and sshd disagree on deny
// (5 vs 0)". It is "" when nothing disagrees.
func faillockDisagreement(services []faillockService) string {
	var parts []string
	same := true
	for _, svc := range services[1:] {
		if !slices.Equal(svc.preauthDiffers, services[0].preauthDiffers) {
			same = false
		}
	}
	for _, svc := range services {
		if len(svc.preauthDiffers) == 0 {
			continue
		}
		if same {
			parts = append(parts, "preauth and authfail disagree on "+strings.Join(svc.preauthDiffers, ", "))
			break
		}
		parts = append(parts, svc.name+"'s preauth and authfail disagree on "+strings.Join(svc.preauthDiffers, ", "))
	}
	names := make([]string, len(services))
	for i, svc := range services {
		names[i] = svc.name
	}
	for _, k := range append(slices.Clone(faillockInts), "even_deny_root") {
		values := make([]string, len(services))
		for i, svc := range services {
			if k == "even_deny_root" {
				values[i] = strconv.FormatBool(svc.evenDenyRoot)
			} else {
				values[i] = strconv.Itoa(svc.vals[k])
			}
		}
		if slices.ContainsFunc(values, func(v string) bool { return v != values[0] }) {
			parts = append(parts, strings.Join(names, " and ")+" disagree on "+k+" ("+strings.Join(values, " vs ")+")")
		}
	}
	return strings.Join(parts, "; ")
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

// umaskFacts derives pam.umask_module.* . A session runs only its own
// service's stack - a non-login SSH session never reaches login's - so the
// module counts as enabled only when every existing login-facing service
// (login, sshd) stacks it in its session phase; other stands in only when
// neither exists. The evidence is each service's first pam_umask.so line,
// args are the first service's line, and a false names every service that
// lacks the module.
func umaskFacts(s pamStacks) map[string]facts.Envelope {
	out := map[string]facts.Envelope{}
	var services []string
	for _, svc := range faillockServices {
		if s.has(svc) {
			services = append(services, svc)
		}
	}
	if len(services) == 0 && s.has("other") {
		services = []string{"other"}
	}
	if len(services) == 0 {
		out["pam.umask_module.enabled"] = collect.Absent("no login, sshd or other PAM service file")
		out["pam.umask_module.args"] = collect.Absent("no login, sshd or other PAM service file")
		return out
	}
	var first []pamLine
	var lacking []string
	for _, svc := range services {
		lines := linesOf(s.byName[svc], "session", "pam_umask.so")
		if len(lines) == 0 {
			lacking = append(lacking, svc+"'s")
			continue
		}
		first = append(first, lines[0])
	}
	if len(lacking) > 0 {
		e := collect.OK(false, pamSource(s.x))
		e.Reason = "no pam_umask.so line in " + strings.Join(lacking, " or ") + " session stack"
		out["pam.umask_module.enabled"] = e
		out["pam.umask_module.args"] = collect.Absent("pam_umask.so is not stacked")
		return out
	}
	var inputs []facts.Source
	for _, l := range first {
		if ls := lineSource(l); !slices.ContainsFunc(inputs, func(in facts.Source) bool { return in.Path == ls.Path && in.Line == ls.Line }) {
			inputs = append(inputs, ls)
		}
	}
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(inputs)} }
	out["pam.umask_module.enabled"] = collect.OK(true, src())
	out["pam.umask_module.args"] = collect.OK(argsList(first[0].Args), &facts.Source{Kind: "derived", Inputs: []facts.Source{lineSource(first[0])}})
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
