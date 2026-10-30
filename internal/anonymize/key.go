// Package anonymize holds the keyed pseudonym functions, the closed keep set and
// the collision ledger of the snapshot anonymiser (3D-3 AX-2..AX-5, AX-9). It is
// pure: no host API.
package anonymize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// Key is a 256-bit anonymisation key. Treat it as sensitive as the snapshot.
type Key struct{ raw [32]byte }

// NewKey wraps exactly 32 bytes.
func NewKey(raw []byte) (*Key, error) {
	if len(raw) != 32 {
		return nil, errors.New("anonymization key must be exactly 32 bytes")
	}
	k := &Key{}
	copy(k.raw[:], raw)
	return k, nil
}

func mac(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func (k *Key) sub(class string) []byte { return mac(k.raw[:], "muster/anon/v1/"+class) }

// ID is the first 16 hex characters of HMAC(key, "muster/anon/v1/key-id").
func (k *Key) ID() string { return hex.EncodeToString(k.sub("key-id"))[:16] }

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func (k *Key) token(class, in string, n int) string {
	return strings.ToLower(b32.EncodeToString(mac(k.sub(class), in)))[:n]
}

// Account maps a user or group name (one namespace). A leading %, +, - or @ is
// kept and the rest mapped; "#" before digits only (a uid) is kept whole.
func (k *Key) Account(name string) string {
	if name == "" {
		return ""
	}
	switch name[0] {
	case '%', '+', '-', '@':
		return name[:1] + k.Account(name[1:])
	case '#':
		rest := name[1:]
		if rest == "" || allDigits(rest) {
			return name
		}
		return "#" + k.Account(rest)
	}
	if Kept(name) {
		return name
	}
	return "u" + k.token(ClassAccount, name, 12)
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Host maps a DNS name: lower-cased, each label but the last becomes "h" + 10
// base32 characters, the final label and a trailing dot are kept, and a
// single-label name maps whole.
func (k *Key) Host(name string) string {
	if name == "" {
		return ""
	}
	name = strings.ToLower(name)
	dot := ""
	if strings.HasSuffix(name, ".") {
		name, dot = name[:len(name)-1], "."
	}
	labels := strings.Split(name, ".")
	last := len(labels) - 1
	if last == 0 {
		return k.hostLabel(name) + dot
	}
	for i := 0; i < last; i++ {
		labels[i] = k.hostLabel(labels[i])
	}
	return strings.Join(labels, ".") + dot
}

func (k *Key) hostLabel(l string) string {
	if l == "" {
		return ""
	}
	return "h" + k.token(ClassHost, l, 10)
}

// Fingerprint maps an SSH key fingerprint to "SHA256:" + 43 base64 characters.
func (k *Key) Fingerprint(fp string) string {
	if fp == "" {
		return ""
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(mac(k.sub(ClassFingerprint), fp))
}

// MachineIDHash maps a machine-id hash to 64 lowercase hex characters.
func (k *Key) MachineIDHash(h string) string {
	if h == "" {
		return ""
	}
	return hex.EncodeToString(mac(k.sub(ClassMachineID), h))
}

// Ledger records every (class, input -> output) and refuses a collision (AX-9).
type Ledger struct {
	byClass map[string]map[string]string // class -> out -> in
	byField map[string]map[string]ledgerEntry
}

type ledgerEntry struct{ class, in string }

// NewLedger returns an empty ledger.
func NewLedger() *Ledger {
	return &Ledger{byClass: map[string]map[string]string{}, byField: map[string]map[string]ledgerEntry{}}
}

// Note records in -> out for class at field. It errors when two different
// inputs of one class give one output, when an output equals a kept name that
// is not its own input, or when within one field an output equals another
// class's output for a different input.
func (l *Ledger) Note(field, class, in, out string) error {
	if in == "" && out == "" {
		return nil
	}
	if out != in && Kept(out) {
		return errors.New("anonymization collision in class " + class + " (field " + field + "): output equals a kept name")
	}
	m := l.byClass[class]
	if m == nil {
		m = map[string]string{}
		l.byClass[class] = m
	}
	if prev, ok := m[out]; ok && prev != in {
		return errors.New("anonymization collision in class " + class + " (field " + field + "): two inputs map to one output")
	}
	m[out] = in
	f := l.byField[field]
	if f == nil {
		f = map[string]ledgerEntry{}
		l.byField[field] = f
	}
	if prev, ok := f[out]; ok && (prev.class != class || prev.in != in) {
		return errors.New("anonymization collision in class " + class + " (field " + field + "): output equals class " + prev.class + "'s output for another input")
	}
	f[out] = ledgerEntry{class, in}
	return nil
}
