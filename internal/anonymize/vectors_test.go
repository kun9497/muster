package anonymize

import (
	"bytes"
	"testing"
)

// Known answers for the all-0x07 32-byte key, computed independently of this
// package with python -I:
//
//	K = bytes([7])*32; h(k,m) = hmac.new(k, m.encode(), sha256).digest()
//	sub(c) = h(K, "muster/anon/v1/" + c)
//	b32(b) = base64.b32encode(b).decode().rstrip("=").lower()
//	ID            = h(K, "muster/anon/v1/key-id").hex()[:16]
//	Account(x)    = "u" + b32(h(sub("account"), x))[:12]
//	Host label l  = "h" + b32(h(sub("host"), l))[:10]
//	Fingerprint   = "SHA256:" + b64(h(sub("fingerprint"), x)) without padding
//	MachineIDHash = h(sub("machine_id_hash"), x).hex()
func TestKnownAnswers(t *testing.T) {
	k, err := NewKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, got, want string }{
		{"ID", k.ID(), "e045a03cec53e005"},
		{"Account", k.Account("alice"), "ugzc5yjlf3ksg"},
		{"Host multi", k.Host("Web01.Corp.org"), "h4b7vf4mmhb.h5fd6ln2jdu.org"},
		{"Host single", k.Host("solo"), "h6qg7wfjicz"},
		{"Fingerprint", k.Fingerprint("SHA256:abc"), "SHA256:RMoVhzYgFlxv4P401kT9yUF6lA+tFxTyAnvUrCK0jHI"},
		{"MachineIDHash", k.MachineIDHash(string(bytes.Repeat([]byte("a"), 64))), "fda774bac21ee93d9497f70261833f12c1f4c968c17536c577874e552310ceb8"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	// The sub-key step: HMAC(key, "alice") taken directly gives another value.
	if k.Account("alice") == "unkefdrmq3xvv" {
		t.Error("account pseudonym equals the direct HMAC: sub-key step missing")
	}
}
