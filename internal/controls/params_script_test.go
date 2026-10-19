package controls

import "testing"

func TestScriptParamValueFormatsAndRefuses(t *testing.T) {
	cases := []struct {
		typ  string
		v    any
		want string
		ok   bool
	}{
		{"int", 90, "90", true},
		{"int", -1, "-1", true},
		{"int", "90", "", false},
		{"bool", true, "true", true},
		{"bool", false, "false", true},
		{"string", "027", "027", true},
		{"string", "a.b/c@d:e+f,g=h-i_j", "a.b/c@d:e+f,g=h-i_j", true},
		{"string", "'; id; '", "", false},
		{"string", "a b", "", false},
		{"string", "", "", false},
		{"string", "$(id)", "", false},
		{"string", "a|b", "", false},
		{"list<int>", []any{0}, "0", true},
		{"list<int>", []any{0, 176}, "0 176", true},
		{"list<int>", []any{}, "", false},
		{"list<int>", []any{"0"}, "", false},
		{"list<string>", []any{"027", "022"}, "027 022", true},
		{"list<string>", []any{"ok", "bad;"}, "", false},
		{"list<string>", "027", "", false},
		{"weird", 1, "", false},
	}
	for _, c := range cases {
		got, ok := ScriptParamValue(c.typ, c.v)
		if got != c.want || ok != c.ok {
			t.Errorf("ScriptParamValue(%q, %#v) = %q, %v; want %q, %v", c.typ, c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestEntryValidators(t *testing.T) {
	for _, c := range []struct {
		f    func(string) bool
		name string
		in   string
		ok   bool
	}{
		{ValidParamName, "param", "max_days", true},
		{ValidParamName, "param", "Max", false},
		{ValidParamName, "param", "1x", false},
		{ValidBackupPath, "backup", "/etc/hosts", true},
		{ValidBackupPath, "backup", "/etc//hosts", false},
		{ValidBackupPath, "backup", "/etc/a b", false},
		{ValidModesEntry, "modes", "/etc/cron.d/*", true},
		{ValidModesEntry, "modes", "/var/log/*/*", true},
		{ValidModesEntry, "modes", "/etc/crontab", true},
		{ValidModesEntry, "modes", "/etc/x/*/*/*", false},
		{ValidModesEntry, "modes", "/etc/x//*", false},
		{ValidModesEntry, "modes", "/etc/./x/*", false},
		{ValidModesEntry, "modes", "/*", false},
		{ValidModesEntry, "modes", "/etc/'x/*", false},
		{ValidSysctlKey, "sysctl", "net.ipv4.conf.all.accept_redirects", true},
		{ValidSysctlKey, "sysctl", "kernel", false},
		{ValidSysctlKey, "sysctl", "net.ipv4.ip_forward=1", false},
		{ValidModuleName, "module", "usb-storage", true},
		{ValidModuleName, "module", "usb_storage", true},
		{ValidModuleName, "module", "-x", false}, // S-7: a name starts with a letter or digit
		{ValidModuleName, "module", "a b", false},
	} {
		if got := c.f(c.in); got != c.ok {
			t.Errorf("%s %q: got %v, want %v", c.name, c.in, got, c.ok)
		}
	}
}
