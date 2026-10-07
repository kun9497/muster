package tuning

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fuzzTargets pins the package's fuzz targets; every function taking []byte
// must be a direct callee of one (the collectors' inventory rule, slimmed).
var fuzzTargets = []string{"FuzzParseTuning"}

func TestEveryParserHasAFuzzTarget(t *testing.T) {
	inventory := byteTakers(t)
	targets := fuzzTargetCalls(t)
	var declared []string
	for name := range targets {
		declared = append(declared, name)
	}
	slices.Sort(declared)
	if !slices.Equal(declared, fuzzTargets) {
		t.Errorf("fuzz_test.go declares %v, fuzzTargets pins %v", declared, fuzzTargets)
	}
	for _, fn := range inventory {
		covered := false
		for _, calls := range targets {
			if calls[fn] {
				covered = true
			}
		}
		if !covered {
			t.Errorf("%s takes []byte and no fuzz target calls it", fn)
		}
	}
}

func byteTakers(t *testing.T) []string {
	t.Helper()
	names, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	var out []string
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, p := range fn.Type.Params.List {
				if arr, ok := p.Type.(*ast.ArrayType); ok && arr.Len == nil {
					if el, ok := arr.Elt.(*ast.Ident); ok && el.Name == "byte" {
						out = append(out, fn.Name.Name)
					}
				}
			}
		}
	}
	return out
}

func fuzzTargetCalls(t *testing.T) map[string]map[string]bool {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), "fuzz_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]bool{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
			continue
		}
		calls := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				switch f := c.Fun.(type) {
				case *ast.Ident:
					calls[f.Name] = true
				case *ast.SelectorExpr:
					calls[f.Sel.Name] = true
				}
			}
			return true
		})
		out[fn.Name.Name] = calls
	}
	return out
}
