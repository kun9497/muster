//go:build linux

package collectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestEveryParserHasAFuzzTarget is the completeness rule of F-6: a function
// in this package that reads host bytes must be reachable from a fuzz target.
//
// The inventory is computed from the package's own sources rather than from a
// name prefix, because "parse" is not the rule — nssSources, decodeACL,
// dnsTokenize, rsyslogLogicalLines, rpmFileTable, showValues and a dozen
// others parse host bytes under other names. A function OR METHOD is in the
// inventory when ANY of its parameters is a []byte, or its first parameter is
// a string called content, line, sel or act: that is what "this function is
// handed the bytes of a file or a command's output" looks like in this
// package. Ruling G-25 widened both halves of that rule — methods were
// skipped entirely, and a `(path string, data []byte)` parser was invisible
// because the bytes were not first.
//
// Every inventory function must then be either the direct callee of one of
// fuzz_test.go's targets, or a row of coveredThrough naming a target that
// reaches it through its parent, or a row of notParsers with a reason. Both
// tables are checked against the call graph in the same pass, so neither can
// rot: a row that claims a coverage the code no longer has fails the test as
// loudly as a parser with no target at all.

// fuzzTargets pins the set of targets fuzz_test.go declares. It exists so a
// deletion is a decision: removing a target without removing this row fails
// here rather than quietly shrinking the nightly run. The floor is 30 (spec
// §3).
var fuzzTargets = []string{
	"FuzzAptPeriodicUnattended",
	"FuzzAttrValue",
	"FuzzCountAptSecurity",
	"FuzzCountDnfAdvisories",
	"FuzzCryptoPolicyName",
	"FuzzDNSTokenize",
	"FuzzDecodeACL",
	"FuzzDnfAutomaticApply",
	"FuzzFirstLine",
	"FuzzFirstSettingLine",
	"FuzzListsRoot",
	"FuzzNSSSources",
	"FuzzNTPFile",
	"FuzzNewestDpkgInstall",
	"FuzzOSEscapes",
	"FuzzParseAptSimulation",
	"FuzzParseChronySources",
	"FuzzParseDaemonDump",
	"FuzzParseDnfCheckUpdate",
	"FuzzParseDpkgStatus",
	"FuzzParseDropin",
	"FuzzParseExportsContent",
	"FuzzParseGroup",
	"FuzzParseIptablesSave",
	"FuzzParseKV",
	"FuzzParseMountinfo",
	"FuzzParseNftRuleset",
	"FuzzParsePAMFile",
	"FuzzParsePamListfiles",
	"FuzzParsePasswd",
	"FuzzParsePostfixInto",
	"FuzzParseProcNet",
	"FuzzParseProftpd",
	"FuzzParsePureFtpdInto",
	"FuzzParseRpmQa",
	"FuzzParseRsyslogSelector",
	"FuzzParseSendmailPrivacy",
	"FuzzParseShadow",
	"FuzzParseShellFile",
	"FuzzParseSshdConfig",
	"FuzzParseSubIDs",
	"FuzzParseVsftpdInto",
	"FuzzParseXinetd",
	"FuzzProftpdClosingName",
	"FuzzRPMFileTable",
	"FuzzReadInetd",
	"FuzzSNMPParse",
	"FuzzSNMPStripComment",
	"FuzzSNMPTokens",
	"FuzzShowValues",
	"FuzzUFWEnabledLine",
}

// coveredThrough names, for each parser with no target of its own, the target
// whose parser reaches it. These are the helpers only their parent calls: a
// separate target would feed them input their parent could never hand them,
// which would be fuzzing a function this package does not have.
var coveredThrough = map[string]string{
	"assignmentValue":      "FuzzParseShellFile",
	"blockDelta":           "FuzzParseShellFile",
	"configComment":        "FuzzParseChronySources",
	"configTokens":         "FuzzParseDaemonDump",
	"cutComment":           "FuzzParseShellFile",
	"cutKeyValue":          "FuzzUFWEnabledLine",
	"declAssignment":       "FuzzParseShellFile",
	"exportName":           "FuzzParseShellFile",
	"pamTokens":            "FuzzParsePAMFile",
	"parseKVInto":          "FuzzParseKV",
	"proftpdSectionName":   "FuzzProftpdClosingName",
	"readonlyName":         "FuzzParseShellFile",
	"rsyslogDelta":         "FuzzParseRsyslogSelector",
	"rsyslogParenDelta":    "FuzzParseRsyslogSelector",
	"sendmailLogicalLines": "FuzzParseSendmailPrivacy",
	"sendmailPrivacyValue": "FuzzParseSendmailPrivacy",
	"sourceRaw":            "FuzzParseSshdConfig",
	"splitLines":           "FuzzParsePasswd",
	"splitStatements":      "FuzzParseShellFile",
	"stripAptComment":      "FuzzAptPeriodicUnattended",
	"stripComment":         "FuzzParseExportsContent",
	"stripRsyslogComment":  "FuzzParseRsyslogSelector",
	"tokenizeExportLine":   "FuzzParseExportsContent",
}

// notParsers is the escape hatch: a function the inventory grammar catches
// that no target may be written for, with the reason. A row says either that
// the bytes are not host input, or which target covers the grammar in
// substance — and it has to explain why a target of its own would prove
// nothing (or could not be written honestly).
var notParsers = map[string]string{
	"file": "rsyslogScan.file emits one rule PER FACILITY of a selector, so `*.*` " +
		"turns five bytes into two dozen rows; fuzzBody's bound is proportional to " +
		"the input and a target for it would fail on valid rsyslog rather than on a bug. " +
		"Every grammar it reads is fuzzed one level down by FuzzParseRsyslogSelector, " +
		"which runs rsyslogLogicalLines and then each selector, action, action call, " +
		"brace delta and numeric selector over the same input.",
	"continuation": "rsyslogScan.continuation is reached only from rsyslogScan.file and " +
		"takes an action string that file has already split off a logical line; it " +
		"re-emits the PREVIOUS line's selector, so it inherits file's per-facility " +
		"amplification. FuzzParseRsyslogSelector fuzzes the action strings it is handed.",
}

// stringParamNames are the parameter names that make a string parameter host
// input in this package (F-6).
var stringParamNames = map[string]bool{"content": true, "line": true, "sel": true, "act": true}

func TestEveryParserHasAFuzzTarget(t *testing.T) {
	inventory, calls := packageParsers(t)
	targets := fuzzTargetCalls(t)

	// 1. The literal list is the set of targets that exist.
	var declared []string
	for name := range targets {
		declared = append(declared, name)
	}
	slices.Sort(declared)
	if !slices.Equal(declared, fuzzTargets) {
		t.Errorf("fuzz_test.go declares %v\nfuzzTargets pins       %v", declared, fuzzTargets)
	}
	if len(fuzzTargets) < 30 {
		t.Errorf("%d fuzz targets, the floor is 30", len(fuzzTargets))
	}

	// 2. What each target reaches, directly and transitively.
	direct := map[string]string{}
	reaches := map[string]map[string]bool{}
	for _, target := range fuzzTargets {
		body := targets[target]
		for fn := range body {
			if _, ok := direct[fn]; !ok {
				direct[fn] = target
			}
		}
		reaches[target] = closure(body, calls)
	}

	// 3. Every parser is covered, and every row of the two tables is true.
	var orphans []string
	var nDirect, nThrough, nDeclared int
	for _, fn := range inventory {
		switch {
		case direct[fn] != "":
			nDirect++
			if through, ok := coveredThrough[fn]; ok {
				t.Errorf("coveredThrough says %s is reached through %s, but %s calls it directly; drop the row",
					fn, through, direct[fn])
			}
		case coveredThrough[fn] != "":
			nThrough++
			through := coveredThrough[fn]
			if !slices.Contains(fuzzTargets, through) {
				t.Errorf("coveredThrough[%s] names %s, which is not a fuzz target", fn, through)
			} else if !reaches[through][fn] {
				t.Errorf("coveredThrough[%s] names %s, but nothing %s calls reaches %s", fn, through, through, fn)
			}
		case notParsers[fn] != "":
			// Declared not to be host input, or covered in substance by
			// another target, with its reason.
			nDeclared++
		default:
			orphans = append(orphans, fn)
		}
	}
	for _, fn := range orphans {
		t.Errorf("%s reads host bytes and no fuzz target reaches it: add a Fuzz target, a coveredThrough row or a notParsers reason", fn)
	}

	// 4. Neither table may name a function the package no longer has.
	for fn := range coveredThrough {
		if !slices.Contains(inventory, fn) {
			t.Errorf("coveredThrough names %s, which is not a parser of this package", fn)
		}
	}
	for fn := range notParsers {
		if !slices.Contains(inventory, fn) {
			t.Errorf("notParsers names %s, which is not a parser of this package", fn)
		}
	}

	// The counts are tallied from the loop above rather than from the table
	// lengths, so the line reports what the call graph actually showed.
	t.Logf("%d parsers, %d fuzz targets: %d reached directly, %d through a parent, %d declared, %d uncovered",
		len(inventory), len(fuzzTargets), nDirect, nThrough, nDeclared, len(orphans))
}

// packageParsers returns the inventory of parser names, sorted, and the call
// graph of the package's top-level functions. Test files are not read: a
// helper written for a test is not a parser this package ships.
func packageParsers(t *testing.T) (inventory []string, calls map[string]map[string]bool) {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing the package: %v", err)
	}
	calls = map[string]map[string]bool{}
	fset := token.NewFileSet()
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Ruling G-25: a METHOD that is handed host bytes is a parser
			// like any other -- (*ftpParse).parseProftpd and
			// (*superServers).parseXinetd were invisible while this loop
			// skipped every fn.Recv != nil.
			if readsHostBytes(fn) && !slices.Contains(inventory, fn.Name.Name) {
				inventory = append(inventory, fn.Name.Name)
			}
			// A method is keyed by its own name, which is how a
			// *ast.SelectorExpr callee is recorded too, so `p.parseProftpd()`
			// in a target's body resolves to this declaration. Two
			// declarations that share a name (a function and a method, or two
			// methods on different types) merge into one node of the graph:
			// the graph is used to prove a parser is REACHED, and a merge can
			// only make it claim more, which the coveredThrough rows are
			// reviewed against.
			if calls[fn.Name.Name] == nil {
				calls[fn.Name.Name] = map[string]bool{}
			}
			for callee := range calledNames(fn.Body) {
				calls[fn.Name.Name][callee] = true
			}
		}
	}
	if len(inventory) == 0 {
		t.Fatal("no parser found in the package: the inventory rule read nothing")
	}
	slices.Sort(inventory)
	return inventory, calls
}

// fuzzTargetCalls returns, for every Fuzz target in fuzz_test.go, the set of
// functions its body calls — including from the closures it hands fuzzBody.
func fuzzTargetCalls(t *testing.T) map[string]map[string]bool {
	t.Helper()
	const file = "fuzz_test.go"
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	out := map[string]map[string]bool{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
			continue
		}
		out[fn.Name.Name] = calledNames(fn.Body)
	}
	return out
}

// readsHostBytes is the inventory grammar of F-6, as widened by ruling G-25.
//
// A []byte parameter ANYWHERE in the signature makes the function a parser:
// `parseProftpd(file string, data []byte, …)` and
// `parseXinetd(p string, data []byte, truncated bool)` put the path first and
// the bytes second, and the old first-parameter-only rule could not see
// either. A string parameter still counts only under one of the names
// stringParamNames pins, because widening to any string would sweep in every
// path, key and service name the package passes around.
//
// A parser shaped otherwise is still not caught — a `(name string, f
// []string)` that parses pre-split fields, or a plain `(s string)` like
// firstQuoted — so one of those has to be declared in coveredThrough (or
// given a target) by hand. Nor is a function that takes a collect.Access and
// reads the file itself: readInetd is such a function and has a target named
// in fuzzTargets, but widening the grammar to every Access-taking function
// would inventory each of this package's collectors.
func readsHostBytes(fn *ast.FuncDecl) bool {
	for i, param := range fn.Type.Params.List {
		if array, ok := param.Type.(*ast.ArrayType); ok && array.Len == nil {
			if elem, ok := array.Elt.(*ast.Ident); ok && elem.Name == "byte" {
				return true
			}
		}
		if i > 0 {
			continue
		}
		if id, ok := param.Type.(*ast.Ident); ok && id.Name == "string" {
			for _, name := range param.Names {
				if stringParamNames[name.Name] {
					return true
				}
			}
		}
	}
	return false
}

// calledNames is every function name called anywhere inside body, nested
// function literals included. A selector call (`p.parseProftpd(…)`,
// `s.parseXinetd(…)`) contributes its FINAL name, so a method reads the same
// way a plain function does — without that, ruling G-25's newly inventoried
// methods could never be shown to be reached. A package-qualified call
// (`strings.TrimSpace`) contributes that name too; it is a name this
// package's own declarations never have, so it can match nothing in the
// graph.
func calledNames(body *ast.BlockStmt) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				out[fn.Name] = true
			case *ast.SelectorExpr:
				out[fn.Sel.Name] = true
			}
		}
		return true
	})
	return out
}

// closure is everything reachable from the given call set.
func closure(from map[string]bool, calls map[string]map[string]bool) map[string]bool {
	seen := map[string]bool{}
	var queue []string
	for name := range from {
		queue = append(queue, name)
	}
	for len(queue) > 0 {
		name := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[name] {
			continue
		}
		seen[name] = true
		for callee := range calls[name] {
			if !seen[callee] {
				queue = append(queue, callee)
			}
		}
	}
	return seen
}
