//go:build linux

package collectors

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// P-5: the sshkeys collector. Every test runs it through build(), under the
// guard, so a read outside the declaration fails the test (V-10).

// keyRowFields are the eleven fields every ssh.authorized_keys row carries
// (V-9, V-19).
var keyRowFields = []string{"user", "uid", "path", "exists", "mode", "owner_uid", "keys", "unparsed", "unfollowed", "read_status", "reason"}

func sshkeysAccess(passwd string) *fsAccess {
	return &fsAccess{
		contents: map[string][]byte{passwdPath: []byte(passwd), shellsPath: []byte("/bin/bash\n")},
		files:    map[string]string{},
		fails:    map[string]error{},
		modes:    map[string]uint32{},
		owners:   map[string]uint32{},
	}
}

// generatedLine is line n (1-based) of the throw-away key seed, and its
// ssh-keygen -l reading.
func generatedLine(t *testing.T, n int) (string, keygenLine) {
	t.Helper()
	lines := strings.Split(string(readSeed(t, "authorized_keys.generated")), "\n")
	return lines[n-1], expectedKeygen(t)[n-1]
}

func keyRows(t *testing.T, b *collect.Builder) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range okList(t, b, sshAuthorizedKeys) {
		m := r.(map[string]any)
		for _, f := range keyRowFields {
			if _, ok := m[f]; !ok {
				t.Errorf("row %v lacks %s", m, f)
			}
		}
		if len(m) != len(keyRowFields) {
			t.Errorf("row %v has %d fields, want %d", m, len(m), len(keyRowFields))
		}
		out = append(out, m)
	}
	return out
}

// rowShape is what a row says, keys reduced to their count.
func rowShape(r map[string]any) string {
	return fmt.Sprintf("%s %v %s exists=%v mode=%v owner=%v keys=%d unparsed=%v unfollowed=%v status=%q reason=%q",
		r["user"], r["uid"], r["path"], r["exists"], r["mode"], r["owner_uid"], len(r["keys"].([]any)),
		r["unparsed"], r["unfollowed"], r["read_status"], r["reason"])
}

func okInt(t *testing.T, b *collect.Builder, key string) int {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v", key, e)
	}
	return e.Value.(int)
}

const (
	rootAK  = "/root/.ssh/authorized_keys"
	rootAK2 = "/root/.ssh/authorized_keys2"
	aliceAK = "/home/alice/.ssh/authorized_keys"
)

func TestSshkeysFacts(t *testing.T) {
	rsa1024, want1024 := generatedLine(t, 4)
	a := sshkeysAccess("root:x:0:0:root:/root:/bin/bash\n" +
		"alice:x:1000:1000::/home/alice:/bin/bash\n" +
		"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n" +
		"nohome:x:1001:1001:::/bin/bash\n")
	a.contents[rootAK] = []byte("ssh-ed25519 " + zeroEd25519 + " root\n")
	a.modes[rootAK] = 0o600
	a.contents[aliceAK] = []byte("# alice\n" + rsa1024 + "\n" + synthDSA() + "\nnot a key\n")
	a.modes[aliceAK], a.owners[aliceAK] = 0o644, 1000
	b := build(t, "sshkeys", a)

	var got []string
	for _, r := range keyRows(t, b) {
		got = append(got, rowShape(r))
	}
	want := []string{
		`alice 1000 /home/alice/.ssh/authorized_keys exists=true mode=420 owner=1000 keys=2 unparsed=1 unfollowed=false status="ok" reason=""`,
		`alice 1000 /home/alice/.ssh/authorized_keys2 exists=false mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=false status="ok" reason=""`,
		`daemon 1  exists=false mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=false status="" reason="home path outside the collector's declaration"`,
		`root 0 /root/.ssh/authorized_keys exists=true mode=384 owner=0 keys=1 unparsed=0 unfollowed=false status="ok" reason=""`,
		`root 0 /root/.ssh/authorized_keys2 exists=false mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=false status="ok" reason=""`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(want, "\n     "))
	}
	alice := keyRows(t, b)[0]["keys"].([]any)
	wantKey := map[string]any{"line": 2, "type": "ssh-rsa", "bits": 1024, "fingerprint": want1024.fingerprint, "options": []any{}, "restricted": false}
	if !reflect.DeepEqual(alice[0], wantKey) {
		t.Errorf("alice's first key %v, want %v", alice[0], wantKey)
	}
	if k := alice[1].(map[string]any); k["type"] != "ssh-dss" || k["bits"] != 1024 {
		t.Errorf("alice's DSA key %v", k)
	}
	if n := okInt(t, b, sshRootKeyCount); n != 1 {
		t.Errorf("root_key_count %d, want 1", n)
	}
	if n := okInt(t, b, sshDSAKeyCount); n != 1 {
		t.Errorf("dsa_key_count %d, want 1", n)
	}
	rsa := okList(t, b, sshRSAKeys)
	wantRSA := []any{map[string]any{"user": "alice", "path": aliceAK, "line": 2, "bits": 1024, "fingerprint": want1024.fingerprint}}
	if !reflect.DeepEqual(rsa, wantRSA) {
		t.Errorf("rsa_keys %v, want %v", rsa, wantRSA)
	}
	e := env(t, b, sshRootKeyCount)
	if e.Source == nil || e.Source.Kind != "derived" || len(e.Source.Inputs) != 4 ||
		e.Source.Inputs[0].Path != passwdPath || e.Source.Inputs[1].Path != rootAK || e.Source.Inputs[2].Path != aliceAK || e.Source.Inputs[3].Path != shellsPath {
		t.Errorf("source %+v, want derived from passwd, the two files read and /etc/shells (it decided daemon was not interactive)", e.Source)
	}

	// An interactive account homed outside the declaration is a hole in the
	// inventory: its row is unfollowed, the list stays ok, and the three
	// counts are absent naming it (C4).
	a.contents[passwdPath] = append(a.contents[passwdPath], "svc:x:998:998::/srv/svc:/bin/bash\n"...)
	b = build(t, "sshkeys", a)
	rows := keyRows(t, b)
	svc := rows[len(rows)-1]
	if rowShape(svc) != `svc 998  exists=false mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=false status="" reason="home path outside the collector's declaration"` {
		t.Errorf("svc row %s", rowShape(svc))
	}
	for _, k := range []string{sshRootKeyCount, sshDSAKeyCount, sshRSAKeys} {
		e := env(t, b, k)
		if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "svc (/srv/svc)") || e.Source == nil {
			t.Errorf("%s: %+v, want absent naming /srv/svc with its source", k, e)
		}
	}
}

func TestSshkeysDeniedHomePoisonsCounts(t *testing.T) {
	a := sshkeysAccess("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	for _, p := range []string{rootAK, rootAK2} {
		a.fails[p] = &fs.PathError{Op: "open", Path: p, Err: unix.EACCES}
	}
	a.contents[aliceAK] = []byte("ssh-ed25519 " + zeroEd25519 + "\n")
	b := build(t, "sshkeys", a)
	rows := keyRows(t, b)
	if len(rows) != 4 || rows[0]["exists"] != true || len(rows[0]["keys"].([]any)) != 1 {
		t.Fatalf("alice's readable file is not in the inventory: %v", rows)
	}
	for _, r := range rows[2:] {
		if r["read_status"] != "denied" || !strings.HasPrefix(r["reason"].(string), r["path"].(string)+": ") || r["exists"] != false || r["mode"] != -1 {
			t.Errorf("root row %s", rowShape(r))
		}
	}
	for _, k := range []string{sshRootKeyCount, sshDSAKeyCount, sshRSAKeys} {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, rootAK+": ") || e.Source == nil {
			t.Errorf("%s: %+v, want denied naming %s", k, e, rootAK)
		}
	}

}

// V-50: a symlink sshd follows and muster does not is an unfollowed row that
// exists, and the counts are absent naming the path: the answer is a look,
// never an error. Both a linked file and a linked .ssh directory (every read
// under it answers ErrSymlink) are pinned.
func TestSshkeysSymlinkIsUnfollowed(t *testing.T) {
	a := sshkeysAccess("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	a.fails[rootAK] = fmt.Errorf("%s: %w", rootAK, collect.ErrSymlink) // the file is a link
	for _, p := range []string{aliceAK, aliceAK + "2"} {               // alice's .ssh is a link
		a.fails[p] = fmt.Errorf("%s: %w", p, collect.ErrSymlink)
	}
	b := build(t, "sshkeys", a)
	var got []string
	for _, r := range keyRows(t, b) {
		got = append(got, rowShape(r))
	}
	want := []string{
		`alice 1000 /home/alice/.ssh/authorized_keys exists=true mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=true status="" reason="not examined - muster does not follow symlinks: /home/alice/.ssh/authorized_keys"`,
		`alice 1000 /home/alice/.ssh/authorized_keys2 exists=true mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=true status="" reason="not examined - muster does not follow symlinks: /home/alice/.ssh/authorized_keys2"`,
		`root 0 /root/.ssh/authorized_keys exists=true mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=true status="" reason="not examined - muster does not follow symlinks: /root/.ssh/authorized_keys"`,
		`root 0 /root/.ssh/authorized_keys2 exists=false mode=-1 owner=-1 keys=0 unparsed=0 unfollowed=false status="ok" reason=""`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(want, "\n     "))
	}
	wantReason := "not examined - muster does not follow symlinks: " + aliceAK + ", " + aliceAK + "2, " + rootAK
	for _, k := range []string{sshRootKeyCount, sshDSAKeyCount, sshRSAKeys} {
		if e := env(t, b, k); e.Status != facts.StatusAbsent || e.Reason != wantReason || e.Source == nil {
			t.Errorf("%s: %+v, want absent %q", k, e, wantReason)
		}
	}
}

// Important 2 (S3, as files.go guards it): an /etc/shells that is denied, or
// missing so the libc default (no /bin/bash) stands in, cannot say that a
// bash account homed outside the declaration is interactive, so the counts
// carry that envelope; the inventory still lists its rows.
func TestSshkeysUntrustedShells(t *testing.T) {
	for _, c := range []struct {
		name   string
		shells func(a *fsAccess)
	}{
		{"denied", func(a *fsAccess) {
			delete(a.contents, shellsPath)
			a.fails[shellsPath] = &fs.PathError{Op: "open", Path: shellsPath, Err: unix.EACCES}
		}},
		{"missing", func(a *fsAccess) { delete(a.contents, shellsPath) }},
	} {
		a := sshkeysAccess("root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/srv/svc:/bin/bash\n")
		c.shells(a)
		b := build(t, "sshkeys", a)
		if rows := keyRows(t, b); len(rows) != 3 {
			t.Errorf("%s: %d rows, want root's two and svc's", c.name, len(rows))
		}
		for _, k := range []string{sshRootKeyCount, sshDSAKeyCount, sshRSAKeys} {
			if e := env(t, b, k); e.Status != facts.StatusDenied || e.Source == nil {
				t.Errorf("%s: %s: %+v, want denied", c.name, k, e)
			}
		}
	}
}

func TestSshkeysNoKeys(t *testing.T) {
	b := build(t, "sshkeys", sshkeysAccess("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"))
	rows := keyRows(t, b)
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4", len(rows))
	}
	for _, r := range rows {
		if r["exists"] != false || r["mode"] != -1 || r["owner_uid"] != -1 || r["read_status"] != "ok" || len(r["keys"].([]any)) != 0 {
			t.Errorf("row %s", rowShape(r))
		}
	}
	if okInt(t, b, sshRootKeyCount) != 0 || okInt(t, b, sshDSAKeyCount) != 0 || len(okList(t, b, sshRSAKeys)) != 0 {
		t.Error("counts on a host with no key file")
	}
}

// 201 keys: the row keeps 200 and the inventory says it was cut; the counts
// count every key read.
func TestSshkeysKeyCap(t *testing.T) {
	a := sshkeysAccess("root:x:0:0:root:/root:/bin/bash\n")
	a.contents[rootAK] = []byte(strings.Repeat("ssh-ed25519 "+zeroEd25519+"\n", 201))
	b := build(t, "sshkeys", a)
	e := env(t, b, sshAuthorizedKeys)
	if !e.Truncated || len(keyRows(t, b)[0]["keys"].([]any)) != 200 {
		t.Errorf("authorized_keys: truncated %v", e.Truncated)
	}
	if n := okInt(t, b, sshRootKeyCount); n != 201 || env(t, b, sshRootKeyCount).Truncated {
		t.Errorf("root_key_count %d", n)
	}
}

// Two uid-0 accounts sharing /root count its keys once.
func TestSshkeysSharedHomeCountsOnce(t *testing.T) {
	a := sshkeysAccess("root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n")
	a.contents[rootAK] = []byte("ssh-ed25519 " + zeroEd25519 + "\n")
	b := build(t, "sshkeys", a)
	if n := okInt(t, b, sshRootKeyCount); n != 1 {
		t.Errorf("root_key_count %d, want 1", n)
	}
	if n := len(keyRows(t, b)); n != 4 {
		t.Errorf("%d rows, want one per account and file", n)
	}
	// Minor 4: ssh.rsa_keys lists a shared file's key once, under the first
	// account in sort order, as the counts count it once. A 512-bit modulus
	// keeps its true length (Important 1): min_rsa_bits judges it.
	a.contents[rootAK] = []byte(synthRSA512() + "\n")
	b = build(t, "sshkeys", a)
	rsa := okList(t, b, sshRSAKeys)
	if len(rsa) != 1 {
		t.Fatalf("rsa_keys %v, want one row", rsa)
	}
	if r := rsa[0].(map[string]any); r["user"] != "root" || r["path"] != rootAK || r["bits"] != 512 || r["line"] != 1 {
		t.Errorf("rsa_keys row %v", r)
	}
}

// synthRSA512 is an ssh-rsa line whose modulus is 512 bits: no one's key.
func synthRSA512() string {
	n := append([]byte{0, 0x80}, make([]byte, 63)...)
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(wireBlob([]byte("ssh-rsa"), []byte{1, 0, 1}, n)) + " synthetic-512"
}

func TestSshkeysPasswdUnreadable(t *testing.T) {
	a := sshkeysAccess("")
	delete(a.contents, passwdPath)
	a.fails[passwdPath] = &fs.PathError{Op: "open", Path: passwdPath, Err: unix.EACCES}
	b := build(t, "sshkeys", a)
	for _, k := range []string{sshAuthorizedKeys, sshRootKeyCount, sshDSAKeyCount, sshRSAKeys} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, passwdPath+": ") {
			t.Errorf("%s: %+v", k, e)
		}
	}
}
