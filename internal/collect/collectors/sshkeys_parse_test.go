package collectors

import (
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// P-5, V-8: the authorized_keys grammar. Pure Go, run on every platform; the
// collector's leaves are tested in sshkeys_test.go.

// zeroEd25519 is the synthetic vector of the research note §7.5: an Ed25519
// "public key" of 32 zero bytes, which is no one's key. Lines are built from
// it by concatenation so no source file spells a key line.
const (
	zeroEd25519   = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	zeroEd25519FP = "SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk"
)

func TestParseAuthorizedKeysSyntheticVector(t *testing.T) {
	keys, unparsed := parseAuthorizedKeys(readSeed(t, "authorized_keys.synthetic"))
	want := []authorizedKey{
		{Line: 1, Type: "ssh-ed25519", Bits: 256, Fingerprint: zeroEd25519FP},
		{Line: 2, Type: "ssh-ed25519", Bits: 256, Fingerprint: zeroEd25519FP,
			Options: []string{"restrict", `command="echo \"hi\""`}, Restricted: true},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys\n got %+v\nwant %+v", keys, want)
	}
	// The comment and the blank line are nothing; the broken base64 line and
	// the rsa-sha2-512 line carrying an Ed25519 blob are the two unparsed.
	if unparsed != 2 {
		t.Errorf("unparsed = %d, want 2", unparsed)
	}
	for _, line := range []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5!!!notbase64 broken",
		"rsa-sha2-512 " + zeroEd25519 + " mismatch",
		"ssh-rsa " + zeroEd25519 + " mismatch",
		"ssh-ed25519-cert-v01@openssh.com " + zeroEd25519 + " plain blob under a cert name",
		"ssh-ed25519 " + zeroEd25519[:len(zeroEd25519)-4] + " cut short",
		"not-a-type " + zeroEd25519,
		"ssh-ed25519",
	} {
		if k, n := parseAuthorizedKeys([]byte(line + "\n")); len(k) != 0 || n != 1 {
			t.Errorf("%q: keys %+v unparsed %d, want none and 1", line, k, n)
		}
	}
	for _, line := range []string{"", "   ", "\t", "# ssh-ed25519 " + zeroEd25519, "   # indented comment"} {
		if k, n := parseAuthorizedKeys([]byte(line + "\n")); len(k) != 0 || n != 0 {
			t.Errorf("%q: keys %+v unparsed %d, want nothing", line, k, n)
		}
	}
	// Leading whitespace, a tab between the fields and a CRLF ending are what
	// sshd skips; the key is the same key.
	k, n := parseAuthorizedKeys([]byte("  ssh-ed25519\t" + zeroEd25519 + "\r\n"))
	if n != 0 || len(k) != 1 || k[0].Fingerprint != zeroEd25519FP {
		t.Errorf("whitespace variant: keys %+v unparsed %d", k, n)
	}
}

// shortType is the name ssh-keygen -l prints in parentheses.
var shortType = map[string]string{
	"ssh-ed25519": "ED25519", "ecdsa-sha2-nistp256": "ECDSA", "ssh-rsa": "RSA",
	"ssh-ed25519-cert-v01@openssh.com": "ED25519-CERT",
}

type keygenLine struct {
	bits        int
	fingerprint string
	typ         string
}

func expectedKeygen(t *testing.T) []keygenLine {
	t.Helper()
	var out []keygenLine
	for _, l := range strings.Split(strings.TrimSpace(string(readSeed(t, "authorized_keys.generated.expected"))), "\n") {
		f := strings.Fields(l)
		bits, err := strconv.Atoi(f[0])
		if err != nil || len(f) < 4 {
			t.Fatalf("expected line %q", l)
		}
		out = append(out, keygenLine{bits, f[1], strings.Trim(f[len(f)-1], "()")})
	}
	return out
}

// TestParseAuthorizedKeysGeneratedMatchesSshKeygen holds the decoder to
// ssh-keygen -l over throw-away keys generated once (ed25519, ecdsa-256,
// rsa-2048, rsa-1024 and an ed25519 certificate). A certificate is recorded
// with bits 0 and the SHA-256 of its whole blob (V-8), where ssh-keygen
// prints the underlying key's size and fingerprint, so its row is checked
// against V-8 rather than against the expected line.
func TestParseAuthorizedKeysGeneratedMatchesSshKeygen(t *testing.T) {
	data := readSeed(t, "authorized_keys.generated")
	keys, unparsed := parseAuthorizedKeys(data)
	want := expectedKeygen(t)
	if unparsed != 0 || len(keys) != len(want) {
		t.Fatalf("keys %d unparsed %d, want %d and 0", len(keys), unparsed, len(want))
	}
	lines := strings.Split(string(data), "\n")
	for i, k := range keys {
		if k.Line != i+1 || k.Options != nil || k.Restricted {
			t.Errorf("key %d: %+v", i, k)
		}
		if strings.HasSuffix(k.Type, "-cert-v01@openssh.com") {
			blob, err := base64.StdEncoding.DecodeString(strings.Fields(lines[i])[1])
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(blob)
			if k.Bits != 0 || k.Fingerprint != "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]) || shortType[k.Type] != want[i].typ {
				t.Errorf("certificate: %+v (ssh-keygen: %+v)", k, want[i])
			}
			continue
		}
		if got := (keygenLine{k.Bits, k.Fingerprint, shortType[k.Type]}); got != want[i] {
			t.Errorf("line %d: got %+v, ssh-keygen %+v", i+1, got, want[i])
		}
	}
	if keys[3].Type != "ssh-rsa" || keys[3].Bits != 1024 {
		t.Errorf("the rsa-1024 key: %+v", keys[3])
	}
	// sshd matches the type word to the blob by key type, not by name: the
	// signature-only rsa-sha2-512 word in front of an ssh-rsa blob is the RSA
	// key it carries (ssh-keygen -l prints "1024 … (RSA)" for it), so it is
	// counted, never hidden in unparsed.
	f := strings.Fields(lines[3])
	k, n := parseAuthorizedKeys([]byte("rsa-sha2-512 " + f[1] + " relabelled\n"))
	if n != 0 || len(k) != 1 || k[0].Type != "ssh-rsa" || k[0].Bits != 1024 || k[0].Fingerprint != want[3].fingerprint {
		t.Errorf("rsa-sha2-512 over an ssh-rsa blob: keys %+v unparsed %d", k, n)
	}
	// An ECDSA blob under another curve's name is sshd's curve mismatch.
	f = strings.Fields(lines[1])
	if k, n := parseAuthorizedKeys([]byte("ecdsa-sha2-nistp384 " + f[1] + "\n")); len(k) != 0 || n != 1 {
		t.Errorf("nistp256 blob under nistp384: keys %+v unparsed %d", k, n)
	}
}

// Review Focus 3: a quoted value holds a comma and an escaped quote, and the
// options field still ends at the first unquoted space.
func TestParseAuthorizedKeysQuotedComma(t *testing.T) {
	keys, unparsed := parseAuthorizedKeys([]byte(`command="echo \"a,b\"",restrict ssh-ed25519 ` + zeroEd25519 + " c\n"))
	want := []authorizedKey{{Line: 1, Type: "ssh-ed25519", Bits: 256, Fingerprint: zeroEd25519FP,
		Options: []string{`command="echo \"a,b\""`, "restrict"}, Restricted: true}}
	if unparsed != 0 || !reflect.DeepEqual(keys, want) {
		t.Errorf("got %+v unparsed %d\nwant %+v", keys, unparsed, want)
	}
	cases := []struct {
		opts       string
		options    []string
		restricted bool
	}{
		{`from="10.0.0.0/8"`, []string{`from="10.0.0.0/8"`}, true},
		{`FROM="10.0.0.0/8"`, []string{`FROM="10.0.0.0/8"`}, true},
		{`Restrict,pty`, []string{"Restrict", "pty"}, true},
		{`no-pty,no-port-forwarding`, []string{"no-pty", "no-port-forwarding"}, false},
		{`command="a b c"`, []string{`command="a b c"`}, false},
		{`environment="X=a b",from="*.example.com"`, []string{`environment="X=a b"`, `from="*.example.com"`}, true},
	}
	for _, c := range cases {
		keys, unparsed := parseAuthorizedKeys([]byte(c.opts + " ssh-ed25519 " + zeroEd25519 + "\n"))
		if unparsed != 0 || len(keys) != 1 || !reflect.DeepEqual(keys[0].Options, c.options) || keys[0].Restricted != c.restricted {
			t.Errorf("%s: keys %+v unparsed %d", c.opts, keys, unparsed)
		}
	}
	// An unterminated quote is sshd's error: the line is not a key.
	for _, bad := range []string{`command="x ssh-ed25519 ` + zeroEd25519, `restrict,command="x`} {
		if k, n := parseAuthorizedKeys([]byte(bad + "\n")); len(k) != 0 || n != 1 {
			t.Errorf("%q: keys %+v unparsed %d", bad, k, n)
		}
	}
}

// A line past sshd's 8 KiB is unparsed; the parser itself keeps every key
// (the 200-per-file cap is the collector's, through capRows).
func TestParseAuthorizedKeysLimits(t *testing.T) {
	long := "ssh-ed25519 " + zeroEd25519 + " " + strings.Repeat("c", authorizedKeysLineMax)
	if k, n := parseAuthorizedKeys([]byte(long + "\n")); len(k) != 0 || n != 1 {
		t.Errorf("an over-long line: keys %d unparsed %d", len(k), n)
	}
	atCap := "ssh-ed25519 " + zeroEd25519 + " "
	atCap += strings.Repeat("c", authorizedKeysLineMax-len(atCap))
	if k, n := parseAuthorizedKeys([]byte(atCap + "\n")); len(k) != 1 || n != 0 {
		t.Errorf("a line at the cap: keys %d unparsed %d", len(k), n)
	}
	many := strings.Repeat("ssh-ed25519 "+zeroEd25519+"\n", 201)
	if k, n := parseAuthorizedKeys([]byte(many)); len(k) != 201 || n != 0 || k[200].Line != 201 {
		t.Errorf("201 lines: keys %d unparsed %d", len(k), n)
	}
}

// Every name the list carries is one OpenSSH 9.9's sshkey_read accepts.
func TestKeyTypeNames(t *testing.T) {
	if len(keyTypeNames) != 21 {
		t.Errorf("%d key type names, want the 21 of OpenSSH 9.9 keyimpls", len(keyTypeNames))
	}
	for _, n := range []string{"ssh-dss", "rsa-sha2-256", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com"} {
		if !keyTypeNames[n] {
			t.Errorf("%s missing", n)
		}
	}
}
