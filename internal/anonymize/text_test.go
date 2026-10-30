package anonymize

import (
	"encoding/json"
	"fmt"
	"testing"
)

func secondPass(k *Key) *walker {
	return &walker{k: k, ledger: NewLedger(), classes: map[string]bool{}, replaced: map[string]bool{}}
}

// AX-4's host-or-address decision, in order: an address form, a host form,
// else the placeholder.
func TestHostOrAddressForms(t *testing.T) {
	k := key7(t)
	h := k.Host
	a10, _ := k.AddrToken(ip4(10, 0, 0, 5))
	cases := []struct {
		in       string
		netgroup bool
		want     string
	}{
		{"", false, ""},
		{"*", false, "*"},
		{"ALL", false, "ALL"},
		{ip4(10, 0, 0, 5), false, a10},
		{"log.corp.example", false, h("log.corp.example")},
		{"Log.Corp.Example.", false, h("Log.Corp.Example.")},
		{"loghost:514", false, h("loghost") + ":514"},
		{"udp:loghost:161", false, "udp:" + h("loghost") + ":161"},
		{"tcp6:loghost", false, "tcp6:" + h("loghost")},
		{"@@log.corp.example:514", false, "@@" + h("log.corp.example") + ":514"},
		{"@(o)loghost", false, "@(o)" + h("loghost")},
		{"@@(z9)" + ip4(10, 0, 0, 5) + ":514", false, "@@(z9)" + mustAddr(t, k, ip4(10, 0, 0, 5)+":514")},
		{"@loghost", false, "@" + h("loghost")},
		{"*.corp.example", false, "*." + h("corp.example")},
		{"@my_group", false, "@" + k.Account("my_group")},
		{"@ng", true, "@" + k.Account("ng")},
		{"web1", true, h("web1")},
		{":0", false, Placeholder},
		{"bad_name!", false, Placeholder},
		{"@@(unclosed", false, Placeholder},
		{"loghost:99999", false, Placeholder},
		{"10.0.0.256", false, Placeholder},
		{"1.2.3", false, Placeholder},
		{"udp:10.0.0.256:161", false, Placeholder},
		{"web1.123.example", false, Placeholder},
	}
	for _, c := range cases {
		w := secondPass(k)
		if got := w.hostOrAddr("f", c.in, c.netgroup); got != c.want || w.err != nil {
			t.Errorf("hostOrAddr(%q, %v) = %q (%v), want %q", c.in, c.netgroup, got, w.err, c.want)
		}
		if replaced := w.replaced["f"]; replaced != (c.want == Placeholder) {
			t.Errorf("%q: replaced = %v", c.in, replaced)
		}
	}
}

func mustAddr(t *testing.T, k *Key, s string) string {
	t.Helper()
	out, ok := k.AddrToken(s)
	if !ok {
		t.Fatalf("%q is not an address form", s)
	}
	return out
}

func TestURLForms(t *testing.T) {
	k := key7(t)
	a, h := k.Account, k.Host
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://logs.corp.example", "https://" + h("logs.corp.example")},
		{"http://alice:s3cret@logs.corp.example:80/x?token=1#f", "http://" + a("alice") + ":" + Placeholder + "@" + h("logs.corp.example") + ":80/x?" + Placeholder},
		{"https://[fd00::1]:19532/", "https://" + mustAddr(t, k, "[fd00::1]:19532") + "/"},
		{"https://" + ip4(10, 0, 0, 5) + "/home/alice", "https://" + mustAddr(t, k, ip4(10, 0, 0, 5)) + "/home/" + a("alice")},
		{"file:///home/alice/f", "file:///home/" + a("alice") + "/f"},
		{"https://root@h.example", "https://root@" + h("h.example")},
		{"https://bad_host!/", "https://" + Placeholder + "/"},
		{"logs.corp.example:19532", Placeholder},
		{"1http://x", Placeholder},
	}
	for _, c := range cases {
		w := secondPass(k)
		if got := w.url("f", c.in); got != c.want || w.err != nil {
			t.Errorf("url(%q) = %q (%v), want %q", c.in, got, w.err, c.want)
		}
	}
}

func TestGrammarTokens(t *testing.T) {
	k := key7(t)
	g := &Grammar{Split: SplitWhitespace, Tokens: []Class{ClassHostOrNetgroup, ClassAccount}, Rest: ClassKept}
	cases := []struct{ in, want string }{
		{"", ""},
		{"+", "+"},
		{"-", "-"},
		{"   ", "   "},
		{"alice-host bob", k.Host("alice-host") + " " + k.Account("bob")},
		{"+@ng -bob", "+@" + k.Account("ng") + " -" + k.Account("bob")},
		{"\t+ alice # x y", "\t+ " + k.Account("alice") + " # x y"},
		{"-" + ip4(10, 0, 0, 5) + " +", "-" + mustAddr(t, k, ip4(10, 0, 0, 5)) + " +"},
	}
	for _, c := range cases {
		w := secondPass(k)
		if got := w.grammar("f", g, c.in); got != c.want || w.err != nil {
			t.Errorf("grammar(%q) = %q (%v), want %q", c.in, got, w.err, c.want)
		}
	}
	w := secondPass(k)
	w.grammar("f", &Grammar{Split: SplitWhitespace}, "x")
	if w.err == nil {
		t.Error("a grammar with no class for a token was accepted")
	}
}

// A 10k-row list through both passes (the walk lists reach that size).
func BenchmarkTransform(b *testing.B) {
	k := key7(b)
	tab := testTable()
	doc := testDoc()
	rows := make([]any, 10000)
	for i := range rows {
		rows[i] = map[string]any{"path": fmt.Sprintf("/home/user%d/.cache/f%d", i%50, i)}
	}
	doc["facts"].(map[string]any)["walk"].(map[string]any)["world_writable"] = env(rows)
	srv := make([]any, 10000)
	for i := range srv {
		srv[i] = ip4(10, byte(i>>16), byte(i>>8), byte(i))
	}
	doc["facts"].(map[string]any)["time_sync"].(map[string]any)["servers"] = env(srv)
	if _, err := json.Marshal(doc); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Transform(doc, tab, k, "keyed"); err != nil {
			b.Fatal(err)
		}
	}
}

// A negated sudo command (!/path, !!/path) keeps its "!" run as a sigil and
// maps the path behind it; a bare "!" stays.
func TestGrammarTokenKeepsNegation(t *testing.T) {
	k := key7(t)
	w := newWalker(Default, k)
	w.collect, w.ledger, w.classes, w.replaced = false, NewLedger(), map[string]bool{}, map[string]bool{}
	g := Default["sudo.rules[].commands[]"].Grammar
	a := k.Account
	for in, want := range map[string]string{
		"!/home/alice/bin/x":      "!/home/" + a("alice") + "/bin/x",
		"!!/home/alice/y":         "!!/home/" + a("alice") + "/y",
		"!":                       "!",
		"/home/alice/bin/x":       "/home/" + a("alice") + "/bin/x",
		"!/home/alice/bin/x -v x": "!/home/" + a("alice") + "/bin/x -" + Placeholder + " " + Placeholder,
	} {
		if got := w.grammar("facts.sudo.rules.value[].commands[]", g, in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if w.err != nil {
		t.Fatal(w.err)
	}
}
