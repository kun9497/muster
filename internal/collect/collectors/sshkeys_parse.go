package collectors

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
)

// The authorized_keys grammar the sshkeys collector reads (P-5, V-8). This
// file has no build tag: it reads bytes, touches nothing, and is tested on
// every platform. The key body is decoded to learn its type, size and
// fingerprint and is never kept.

// authorizedKeysLineMax is sshd(8)'s line limit: "Lines up to 8 kilobytes".
const authorizedKeysLineMax = 8 << 10

// authorizedKey is one key line: what it is and how it may be used, never its
// body. Options is nil when the line has no options field.
type authorizedKey struct {
	Line        int
	Type        string
	Bits        int
	Fingerprint string
	Options     []string
	Restricted  bool
}

// keyTypeNames is OpenSSH 9.9's keyimpls: every name sshkey_read accepts as a
// line's type word (sshkey.c V_9_9_P1, DSA and its certificate included, as
// EL9 builds them).
var keyTypeNames = map[string]bool{
	"ssh-ed25519":                                 true,
	"ssh-ed25519-cert-v01@openssh.com":            true,
	"sk-ssh-ed25519@openssh.com":                  true,
	"sk-ssh-ed25519-cert-v01@openssh.com":         true,
	"ecdsa-sha2-nistp256":                         true,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com":    true,
	"ecdsa-sha2-nistp384":                         true,
	"ecdsa-sha2-nistp384-cert-v01@openssh.com":    true,
	"ecdsa-sha2-nistp521":                         true,
	"ecdsa-sha2-nistp521-cert-v01@openssh.com":    true,
	"sk-ecdsa-sha2-nistp256@openssh.com":          true,
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
	"ssh-dss":                                     true,
	"ssh-dss-cert-v01@openssh.com":                true,
	"ssh-rsa":                                     true,
	"ssh-rsa-cert-v01@openssh.com":                true,
	"rsa-sha2-256":                                true,
	"rsa-sha2-512":                                true,
	"rsa-sha2-256-cert-v01@openssh.com":           true,
	"rsa-sha2-512-cert-v01@openssh.com":           true,
	"webauthn-sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// signatureOnly maps the keyimpls names that are signature algorithms, not
// key formats, to the key type their blob carries. sshkey_read compares the
// line's word with the blob by key type (peek_type_nid, then k->type !=
// type), so "rsa-sha2-512 <an ssh-rsa blob>" is the RSA key it carries —
// ssh-keygen -l prints it as RSA — and must be counted, never filed unparsed.
var signatureOnly = map[string]string{
	"rsa-sha2-256":                                "ssh-rsa",
	"rsa-sha2-512":                                "ssh-rsa",
	"rsa-sha2-256-cert-v01@openssh.com":           "ssh-rsa-cert-v01@openssh.com",
	"rsa-sha2-512-cert-v01@openssh.com":           "ssh-rsa-cert-v01@openssh.com",
	"webauthn-sk-ecdsa-sha2-nistp256@openssh.com": "sk-ecdsa-sha2-nistp256@openssh.com",
}

// parseAuthorizedKeys reads an authorized_keys file per sshd(8)'s
// AUTHORIZED_KEYS FILE FORMAT: leading blanks skipped, blank lines and lines
// starting with # ignored, every other line a key or unparsed.
func parseAuthorizedKeys(data []byte) (keys []authorizedKey, unparsed int) {
	for i, raw := range strings.Split(string(data), "\n") {
		text := strings.TrimSuffix(raw, "\r")
		if len(text) > authorizedKeysLineMax {
			unparsed++
			continue
		}
		text = strings.TrimLeft(text, " \t")
		if text == "" || text[0] == '#' {
			continue
		}
		k, ok := keyLine(text)
		if !ok {
			unparsed++
			continue
		}
		k.Line = i + 1
		keys = append(keys, k)
	}
	return keys, unparsed
}

// keyLine decodes one non-comment line. The first word is the key type iff
// keyimpls names it; otherwise the line starts with options, which end at the
// first unquoted blank (sshkey_advance_past_options).
func keyLine(text string) (authorizedKey, bool) {
	var k authorizedKey
	word, rest := cutBlank(text)
	if !keyTypeNames[word] {
		end, ok := optionsEnd(text)
		if !ok {
			return k, false
		}
		if k.Options, ok = splitOptions(text[:end]); !ok {
			return k, false
		}
		k.Restricted = restricts(k.Options)
		word, rest = cutBlank(strings.TrimLeft(text[end:], " \t"))
		if !keyTypeNames[word] {
			return k, false
		}
	}
	b64, _ := cutBlank(strings.TrimLeft(rest, " \t"))
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(blob) == 0 {
		return k, false
	}
	typ, bits, ok := decodeKeyBlob(blob)
	want := word
	if plain, sig := signatureOnly[word]; sig {
		want = plain
	}
	if !ok || typ != want {
		return k, false
	}
	sum := sha256.Sum256(blob)
	k.Type, k.Bits = typ, bits
	k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	return k, true
}

// cutBlank splits s at its first space or tab.
func cutBlank(s string) (word, rest string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// optionsEnd is where the options field ends: the first space or tab outside
// quotes. `\"` is skipped as a pair and `"` toggles quoting; an unterminated
// quote is sshd's error.
func optionsEnd(text string) (int, bool) {
	quoted := false
	i := 0
	for ; i < len(text) && (quoted || (text[i] != ' ' && text[i] != '\t')); i++ {
		if text[i] == '\\' && i+1 < len(text) && text[i+1] == '"' {
			i++
		} else if text[i] == '"' {
			quoted = !quoted
		}
	}
	return i, !quoted && i > 0
}

// splitOptions splits the options field at its unquoted commas, keeping each
// option whole — a quoted value may hold a comma. An empty option (",,") is
// sshd's "unknown key option" and makes the line unparsed.
func splitOptions(field string) ([]string, bool) {
	var out []string
	quoted, start := false, 0
	for i := 0; i < len(field); i++ {
		switch {
		case field[i] == '\\' && i+1 < len(field) && field[i+1] == '"':
			i++
		case field[i] == '"':
			quoted = !quoted
		case field[i] == ',' && !quoted:
			if i == start {
				return nil, false
			}
			out = append(out, field[start:i])
			start = i + 1
		}
	}
	if start == len(field) {
		return nil, false
	}
	return append(out, field[start:]), true
}

// restricts reports whether the options confine the key: restrict (every
// restriction sshd has, and every future one) or from= (the source address).
// Option names are case-insensitive in sshd.
func restricts(options []string) bool {
	for _, o := range options {
		name, _, _ := strings.Cut(o, "=")
		if n := strings.ToLower(name); n == "restrict" || n == "from" {
			return true
		}
	}
	return false
}

// decodeKeyBlob reads the RFC 4251 wire form of a public key: its inner type
// string and the size ssh-keygen -l prints (sshkey_size). Every field of a
// plain key is read and nothing may follow them: sshkey_from_blob refuses
// trailing bytes, and a blob sshd refuses is no key. A certificate is
// recorded with bits 0 (V-8); only its type is read.
func decodeKeyBlob(blob []byte) (typ string, bits int, ok bool) {
	t, rest, ok := sshString(blob)
	if !ok {
		return "", 0, false
	}
	typ = string(t)
	if strings.HasSuffix(typ, "-cert-v01@openssh.com") {
		return typ, 0, true
	}
	switch {
	case typ == "ssh-rsa":
		// string type, mpint e, mpint n: the modulus bit length, exact
		// whether or not the encoder wrote the sign byte. A zero e or n is
		// no RSA key; a short modulus keeps its true length, which
		// min_rsa_bits judges.
		var e, n []byte
		if e, rest, ok = sshMpint(rest); !ok || isZero(e) {
			return "", 0, false
		}
		if n, rest, ok = sshMpint(rest); !ok || isZero(n) {
			return "", 0, false
		}
		bits = new(big.Int).SetBytes(n).BitLen()
	case typ == "ssh-dss":
		// string type, mpint p, q, g, y: the size of p.
		var p []byte
		if p, rest, ok = sshMpint(rest); !ok || isZero(p) {
			return "", 0, false
		}
		for range 3 {
			if _, rest, ok = sshMpint(rest); !ok {
				return "", 0, false
			}
		}
		bits = new(big.Int).SetBytes(p).BitLen()
	case typ == "ssh-ed25519", typ == "sk-ssh-ed25519@openssh.com":
		// string type, string key (32 octets) [, string application].
		var pk []byte
		if pk, rest, ok = sshString(rest); !ok || len(pk) != 32 {
			return "", 0, false
		}
		if typ != "ssh-ed25519" {
			if _, rest, ok = sshString(rest); !ok {
				return "", 0, false
			}
		}
		bits = 256
	case strings.HasPrefix(typ, "ecdsa-sha2-"), typ == "sk-ecdsa-sha2-nistp256@openssh.com":
		// string type, string curve, string Q [, string application]: the
		// curve must be the one the type names (sshd's curve mismatch).
		sk := typ == "sk-ecdsa-sha2-nistp256@openssh.com"
		want := strings.TrimPrefix(typ, "ecdsa-sha2-")
		if sk {
			want = "nistp256"
		}
		bits = map[string]int{"nistp256": 256, "nistp384": 384, "nistp521": 521}[want]
		var curve []byte
		if curve, rest, ok = sshString(rest); !ok || string(curve) != want || bits == 0 {
			return "", 0, false
		}
		if _, rest, ok = sshString(rest); !ok {
			return "", 0, false
		}
		if sk {
			if _, rest, ok = sshString(rest); !ok {
				return "", 0, false
			}
			bits = 256 // the sk- types' fixed keybits
		}
	default:
		return "", 0, false
	}
	if len(rest) != 0 {
		return "", 0, false
	}
	return typ, bits, true
}

// isZero reports whether an mpint's magnitude is zero (RFC 4251 stores zero
// as the empty string).
func isZero(mag []byte) bool {
	for _, c := range mag {
		if c != 0 {
			return false
		}
	}
	return true
}

// sshString reads an RFC 4251 string: a uint32 big-endian length and that
// many bytes.
func sshString(b []byte) (field, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// sshMpint reads an RFC 4251 mpint as a string whose value is non-negative:
// sshd refuses a negative modulus or prime (SSH_ERR_BIGNUM_IS_NEGATIVE), and
// a key sshd refuses is no key.
func sshMpint(b []byte) (mag, rest []byte, ok bool) {
	mag, rest, ok = sshString(b)
	if !ok || (len(mag) > 0 && mag[0]&0x80 != 0) {
		return nil, nil, false
	}
	return mag, rest, true
}
