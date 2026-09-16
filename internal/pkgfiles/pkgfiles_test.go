package pkgfiles

import "testing"

// The lines below are synthetic: every path is a real distribution path but
// no line was copied from a host, and the parsers are pinned by what the
// three producing commands actually print —
// `rpm -qa --qf '[%{=NAME}\t%{FILEMODES:octal}\t…]'`, `tar -tv` over a
// .deb's filesystem tarball and `stat -c '%a %U %G %n'`.
func TestPkgfilesParsers(t *testing.T) {
	t.Run("rpm file line", func(t *testing.T) {
		cases := []struct {
			name, line        string
			pkg               string
			mode              int
			owner, group, out string
			ok                bool
		}{
			{"regular", "bash\t0100755\troot\troot\t/usr/bin/bash", "bash", 0o755, "root", "root", "/usr/bin/bash", true},
			{"setuid", "util-linux\t0104755\troot\troot\t/usr/bin/su", "util-linux", 0o4755, "root", "root", "/usr/bin/su", true},
			{"setgid names the group rpm recorded", "util-linux\t0102755\troot\ttty\t/usr/bin/wall", "util-linux", 0o2755, "root", "tty", "/usr/bin/wall", true},
			{"sticky directory", "filesystem\t0041777\troot\troot\t/tmp", "filesystem", 0o1777, "root", "root", "/tmp", true},
			// The path is last and the line splits on the FIRST four tabs,
			// so a space — or another tab — inside a path survives whole.
			{"path with a space", "vendor-data\t0100644\troot\troot\t/opt/vendor/data files/readme.txt", "vendor-data", 0o644, "root", "root", "/opt/vendor/data files/readme.txt", true},
			{"path with a tab", "vendor-data\t0100644\troot\troot\t/opt/vendor/od\td/x", "vendor-data", 0o644, "root", "root", "/opt/vendor/od\td/x", true},
			{"short line", "bash\t0100755\troot\troot", "", 0, "", "", "", false},
			{"unparsable mode", "bash\tnot-a-mode\troot\troot\t/usr/bin/bash", "", 0, "", "", "", false},
			{"relative path", "bash\t0100755\troot\troot\tusr/bin/bash", "", 0, "", "", "", false},
			{"no package name", "\t0100755\troot\troot\t/usr/bin/bash", "", 0, "", "", "", false},
			{"empty line", "", "", 0, "", "", "", false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				pkg, mode, owner, group, p, ok := ParseRPMFileLine(c.line)
				if ok != c.ok {
					t.Fatalf("ok = %v, want %v", ok, c.ok)
				}
				if !ok {
					return
				}
				if pkg != c.pkg || mode != c.mode || owner != c.owner || group != c.group || p != c.out {
					t.Errorf("= (%q, %o, %q, %q, %q), want (%q, %o, %q, %q, %q)",
						pkg, mode, owner, group, p, c.pkg, c.mode, c.owner, c.group, c.out)
				}
			})
		}
	})

	t.Run("tar -tv line", func(t *testing.T) {
		cases := []struct {
			name, line        string
			mode              int
			owner, group, out string
			ok                bool
		}{
			{"setuid regular file", "-rwsr-xr-x root/root     72712 2024-01-01 00:00 ./usr/bin/at", 0o4755, "root", "root", "/usr/bin/at", true},
			{"sticky directory", "drwxrwxrwt root/root         0 2024-01-01 00:00 ./tmp/", 0o1777, "root", "root", "/tmp", true},
			{"setgid without execute", "-rwSr-Sr-T 0/0              0 2024-01-01 00:00 ./opt/odd", 0o7644, "0", "0", "/opt/odd", true},
			{"numeric owner and a path with spaces", "-rw-r--r-- 0/0             12 2024-01-01 00:00 ./etc/a b c.conf", 0o644, "0", "0", "/etc/a b c.conf", true},
			{"selinux dot after the bits", "-rwxr-xr-x. root/root    100 2024-01-01 00:00 ./usr/bin/ls", 0o755, "root", "root", "/usr/bin/ls", true},
			// A symlink's own mode says nothing about what it names and its
			// name field carries the target, so the line is refused.
			{"symlink", "lrwxrwxrwx root/root         0 2024-01-01 00:00 ./bin -> usr/bin", 0, "", "", "", false},
			{"hard link", "hrwxr-xr-x root/root         0 2024-01-01 00:00 ./usr/bin/y link to ./usr/bin/x", 0, "", "", "", false},
			{"no owner/group field", "-rwxr-xr-x root 100 2024-01-01 00:00 ./usr/bin/ls", 0, "", "", "", false},
			{"truncated bits", "-rwxr-x root/root 100 2024-01-01 00:00 ./usr/bin/ls", 0, "", "", "", false},
			{"short line", "-rwxr-xr-x root/root 100", 0, "", "", "", false},
			{"empty line", "", 0, "", "", "", false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				mode, owner, group, p, ok := ParseTarTV(c.line)
				if ok != c.ok {
					t.Fatalf("ok = %v, want %v", ok, c.ok)
				}
				if !ok {
					return
				}
				if mode != c.mode || owner != c.owner || group != c.group || p != c.out {
					t.Errorf("= (%o, %q, %q, %q), want (%o, %q, %q, %q)",
						mode, owner, group, p, c.mode, c.owner, c.group, c.out)
				}
			})
		}
	})

	t.Run("stat line", func(t *testing.T) {
		cases := []struct {
			name, line        string
			mode              int
			owner, group, out string
			ok                bool
		}{
			{"setuid", "4755 root root /usr/bin/su", 0o4755, "root", "root", "/usr/bin/su", true},
			{"plain", "755 root root /usr/bin/ls", 0o755, "root", "root", "/usr/bin/ls", true},
			{"path with a space", "644 root root /etc/a b.conf", 0o644, "root", "root", "/etc/a b.conf", true},
			{"unparsable mode", "abc root root /usr/bin/ls", 0, "", "", "", false},
			{"non-octal digit", "778 root root /usr/bin/ls", 0, "", "", "", false},
			{"relative path", "755 root root usr/bin/ls", 0, "", "", "", false},
			{"short line", "755 root root", 0, "", "", "", false},
			{"empty line", "", 0, "", "", "", false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				mode, owner, group, p, ok := ParseStatLine(c.line)
				if ok != c.ok {
					t.Fatalf("ok = %v, want %v", ok, c.ok)
				}
				if !ok {
					return
				}
				if mode != c.mode || owner != c.owner || group != c.group || p != c.out {
					t.Errorf("= (%o, %q, %q, %q), want (%o, %q, %q, %q)",
						mode, owner, group, p, c.mode, c.owner, c.group, c.out)
				}
			})
		}
	})

	t.Run("merged-usr canonicalisation", func(t *testing.T) {
		merged := map[string]string{"/bin": "/usr/bin", "/sbin": "/usr/sbin", "/lib": "/usr/lib"}
		cases := []struct{ name, in, out string }{
			{"an alias is rewritten", "/bin/su", "/usr/bin/su"},
			{"the alias itself", "/bin", "/usr/bin"},
			{"a path already under /usr", "/usr/bin/su", "/usr/bin/su"},
			{"a longer name that only starts like an alias", "/binx/y", "/binx/y"},
			// /lib64 is not in the table here: a prefix match must respect
			// the component boundary or every /lib64 path would move.
			{"an alias that is not merged", "/lib64/ld-linux.so", "/lib64/ld-linux.so"},
			{"a path under no alias", "/opt/x/tool", "/opt/x/tool"},
			{"deep under an alias", "/lib/x86_64-linux-gnu/security/pam_unix.so", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				if got := CanonicalUsr(c.in, merged); got != c.out {
					t.Errorf("CanonicalUsr(%q) = %q, want %q", c.in, got, c.out)
				}
			})
		}
		if got := CanonicalUsr("/bin/su", nil); got != "/bin/su" {
			t.Errorf("with no merged-usr table CanonicalUsr(%q) = %q, want it unchanged", "/bin/su", got)
		}
	})
}
