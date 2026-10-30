package anonymize

import (
	"bytes"
	"strings"
	"testing"
)

func key7(t testing.TB) *Key {
	t.Helper()
	k, err := NewKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testHomes() Homes {
	var h Homes
	h.AddHome("/home/alice", "alice")
	h.AddHome("/srv/app", "app", "appsvc") // shared: the last component names one of them
	h.AddHome("/srv/app/bob", "bob")       // nested under another home
	h.AddHome("/srv/www/", "nginx", "www-data")
	h.AddHome("/srv//app", "appsvc")
	h.AddHome("/tmp", "tmp")
	h.AddHome("/var/log", "log") // a mount target a control names
	h.AddHome("/dev/shm", "shm") // a mount target a control names
	h.AddHome("/dev/null", "null")
	h.AddHome("/nonexistent", "nonexistent")
	h.AddHome("/opt", "opt") // fewer than two components
	h.AddHome("/srv/ftp", "ftp")
	h.AddHome("/srv/root", "root")
	h.AddName("carol")    // a sudo principal or a crontab owner, in no passwd row
	h.AddName("+@devs")   // sigils are stripped
	h.AddName("crontabs") // a user named like a directory
	return h
}

// AX-6: every position and every exception.
func TestMapPathPositions(t *testing.T) {
	k := key7(t)
	a := k.Account
	cases := []struct{ in, want string }{
		{"", ""},
		{"relative/alice", "relative/alice"},
		{"/", "/"},
		// the component after /home/, an account or not
		{"/home/alice", "/home/" + a("alice")},
		{"/home/alice/.ssh/authorized_keys", "/home/" + a("alice") + "/.ssh/authorized_keys"},
		{"/home/lost+found", "/home/" + a("lost+found")},
		{"/home/zed/x", "/home/" + a("zed") + "/x"},
		{"/home/root/x", "/home/root/x"},
		{"/home", "/home"},
		// a home's last component, the path under it as a prefix
		{"/srv/app", "/srv/" + a("app")},
		{"/srv/app/data/f", "/srv/" + a("app") + "/data/f"},
		{"/srv/application", "/srv/application"},
		// nested homes: every home on the path maps its last component
		{"/srv/app/bob", "/srv/" + a("app") + "/" + a("bob")},
		{"/srv/app/bob/.profile", "/srv/" + a("app") + "/" + a("bob") + "/.profile"},
		// paths and homes are cleaned before matching
		// positions are decided on the cleaned prefix, rewritten in place on
		// the raw components: two spellings stay two strings, and a ..
		// never hides a name
		{"/srv//app/data", "/srv//" + a("app") + "/data"},
		{"/srv/app/./bob/", "/srv/" + a("app") + "/./" + a("bob") + "/"},
		{"/home/x/../alice/f", "/home/" + a("x") + "/../" + a("alice") + "/f"},
		{"/srv//www", "/srv//www"},
		{"/home/alice/..", "/home/" + a("alice") + "/.."},
		{"/home/alice/./x", "/home/" + a("alice") + "/./x"},
		{"/home/alice/../../etc/x", "/home/" + a("alice") + "/../../etc/x"},
		{"/var/mail/carol/..", "/var/mail/" + a("carol") + "/.."},
		{"/var/mail/./carol", "/var/mail/./" + a("carol")},
		{"/tmp/../tmp/x", "/tmp/../tmp/x"},
		{"/home/..", "/home/.."},
		// a shared home whose last component names none of its accounts
		{"/srv/www/index.html", "/srv/www/index.html"},
		// exceptions: /tmp, mount targets, /dev/null, /nonexistent, one component, a kept account
		{"/tmp/x", "/tmp/x"},
		{"/var/log", "/var/log"},
		{"/var/log/syslog", "/var/log/syslog"},
		{"/dev/shm/f", "/dev/shm/f"},
		{"/dev/null", "/dev/null"},
		{"/nonexistent", "/nonexistent"},
		{"/opt/x", "/opt/x"},
		{"/srv/ftp/pub", "/srv/ftp/pub"},
		{"/srv/root/x", "/srv/root/x"},
		// name positions
		{"/var/spool/cron/carol", "/var/spool/cron/" + a("carol")},
		{"/var/mail/carol", "/var/mail/" + a("carol")},
		{"/var/spool/mail/carol", "/var/spool/mail/" + a("carol")},
		{"/var/lib/systemd/linger/carol", "/var/lib/systemd/linger/" + a("carol")},
		{"/var/lib/AccountsService/users/carol", "/var/lib/AccountsService/users/" + a("carol")},
		{"/var/lib/AccountsService/users/devs", "/var/lib/AccountsService/users/" + a("devs")},
		// a name position maps as a prefix too
		{"/var/mail/carol/x", "/var/mail/" + a("carol") + "/x"},
		// a user named crontabs: the directory at the name position is that name
		{"/var/spool/cron/crontabs", "/var/spool/cron/" + a("crontabs")},
		{"/var/spool/cron/crontabs/carol", "/var/spool/cron/" + a("crontabs") + "/" + a("carol")},
		{"/var/spool/cron/crontabs/dave", "/var/spool/cron/" + a("crontabs") + "/dave"},
		// base names directly under sudoers.d and cron.d
		{"/etc/sudoers.d/carol", "/etc/sudoers.d/" + a("carol")},
		{"/etc/cron.d/carol", "/etc/cron.d/" + a("carol")},
		{"/etc/sudoers.d/README", "/etc/sudoers.d/README"},
		{"/etc/cron.d/x/carol", "/etc/cron.d/x/carol"},
		// never by component equality elsewhere
		{"/etc/carol", "/etc/carol"},
		{"/usr/share/alice/carol", "/usr/share/alice/carol"},
		{"/var/spool/carol", "/var/spool/carol"},
	}
	h := testHomes()
	for _, c := range cases {
		if got := k.MapPath(c.in, h); got != c.want {
			t.Errorf("MapPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A user called log leaves /var/log alone even with no home record: no
// position rule names it.
func TestMapPathNeverByComponentEquality(t *testing.T) {
	k := key7(t)
	var h Homes
	h.AddName("log")
	h.AddName("etc")
	for _, p := range []string{"/var/log", "/var/log/audit/audit.log", "/etc/passwd"} {
		if got := k.MapPath(p, h); got != p {
			t.Errorf("MapPath(%q) = %q", p, got)
		}
	}
}

func TestMountTargetsAreTheClosedList(t *testing.T) {
	for _, m := range []string{"/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "/home", "/dev/shm", "/boot"} {
		if !isMountTarget(m) {
			t.Errorf("%s is not a mount target", m)
		}
	}
	for i := 1; i < len(MountTargets); i++ {
		if MountTargets[i-1] >= MountTargets[i] {
			t.Errorf("MountTargets not sorted at %q", MountTargets[i])
		}
	}
}

// AX-6's machine-id positions: the journal directory, the BLS layout under
// /boot, /boot/loader/entries and /efi, and the boot id of systemd's
// PrivateTmp directories under /tmp and /var/tmp map their 32 hex by the
// machine-id sub-key; nothing else does.
func TestMapPathMachineIDPositions(t *testing.T) {
	k := key7(t)
	const id = "0123456789abcdef0123456789abcdef"
	m, b := k.hostID(idLabel, id), k.hostID(bootLabel, id)
	if !isHex32(m) || !isHex32(b) || m == id || b == id || m == b {
		t.Fatalf("hostID gives %q (id) and %q (boot) for %q", m, b, id)
	}
	if m == k.MachineIDHash(id)[:32] {
		t.Fatalf("the path mapping shares the header's derivation")
	}
	cases := []struct{ in, want string }{
		{"/var/log/journal/" + id, "/var/log/journal/" + m},
		{"/var/log/journal/" + id + "/system.journal", "/var/log/journal/" + m + "/system.journal"},
		{"/run/log/journal/" + id, "/run/log/journal/" + m},
		{"/var/log//journal/" + id, "/var/log//journal/" + m},
		{"/var/log/journal/./" + id, "/var/log/journal/./" + m},
		{"/boot/loader/entries/" + id + "-6.8.0-45-generic.conf", "/boot/loader/entries/" + m + "-6.8.0-45-generic.conf"},
		{"/boot/loader/entries/" + id + ".conf", "/boot/loader/entries/" + id + ".conf"},
		{"/boot/" + id + "/6.8.0-45-generic/linux", "/boot/" + m + "/6.8.0-45-generic/linux"},
		{"/efi/" + id, "/efi/" + m},
		{"/efi/loader/entries/" + id + "-6.8.conf", "/efi/loader/entries/" + m + "-6.8.conf"},
		// not a machine-id position, or not 32 lowercase hex
		{"/var/log/journal/" + strings.ToUpper(id), "/var/log/journal/" + strings.ToUpper(id)},
		{"/var/log/journal/" + id + "0", "/var/log/journal/" + id + "0"},
		{"/var/log/journal/remote", "/var/log/journal/remote"},
		{"/var/log/" + id, "/var/log/" + id},
		{"/etc/" + id, "/etc/" + id},
		{"/boot/" + id + "0", "/boot/" + id + "0"},
		{"/boot/grub/" + id, "/boot/grub/" + id},
		{"/tmp/" + id, "/tmp/" + id},
		{"/tmp/systemd-private-" + id, "/tmp/systemd-private-" + id},
		{"/home/x/systemd-private-" + id + "-a-b", "/home/" + k.Account("x") + "/systemd-private-" + id + "-a-b"},
	}
	var h Homes
	for _, c := range cases {
		if got := k.MapPath(c.in, h); got != c.want {
			t.Errorf("MapPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
