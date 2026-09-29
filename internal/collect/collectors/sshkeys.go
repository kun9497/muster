//go:build linux

package collectors

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The sshkeys collector (P-5): every local account's authorized_keys files,
// inventoried without their bodies, and the three counts the key controls
// judge. The grammar is sshkeys_parse.go's.

const (
	sshAuthorizedKeys = "ssh.authorized_keys"
	sshRootKeyCount   = "ssh.root_key_count"
	sshDSAKeyCount    = "ssh.dsa_key_count"
	sshRSAKeys        = "ssh.rsa_keys"

	// authorizedKeysLimit bounds one file's read; sshd's 8 KiB lines times
	// the 200 keys a row keeps is well inside it.
	authorizedKeysLimit = 256 << 10
	authorizedKeysRows  = 500  // V-12
	authorizedKeysKeys  = 200  // per file, V-12
	rsaKeysRows         = 2000 // V-12

	homeOutside = "home path outside the collector's declaration"
)

// authorizedKeysNames are the two defaults of AuthorizedKeysFile in
// sshd_config(5). Both are read on every release: EL ships only the first
// uncommented, and a key in the second there is a stale key for review.
var authorizedKeysNames = []string{"authorized_keys", "authorized_keys2"}

var sshkeysCollector = collect.Collector{
	Name: "sshkeys",
	Declare: collect.Declaration{
		// V-10: the .ssh directories are declared beside the files, under
		// the home patterns the files collector declares.
		Reads: []string{
			passwdPath, shellsPath,
			"/home/*/.ssh", "/home/*/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys2",
			"/home/*/*/.ssh", "/home/*/*/.ssh/authorized_keys", "/home/*/*/.ssh/authorized_keys2",
			"/root/.ssh", "/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2",
		},
		Needs: "none",
	},
	Run: runSshkeys,
}

// keyFile is one authorized_keys path's reading, shared by every account
// whose home names it, so a key is counted once however many accounts
// share the home.
type keyFile struct {
	exists    bool
	status    string // ok | denied | error
	reason    string
	env       facts.Envelope // the read's envelope when status is not ok
	mode, uid int
	keys      []authorizedKey
	unparsed  int
	truncated bool
}

func runSshkeys(_ context.Context, a collect.Access, b *collect.Builder) error {
	keys := []string{sshAuthorizedKeys, sshRootKeyCount, sshDSAKeyCount, sshRSAKeys}
	data, meta, err := a.ReadFile(passwdPath, readLimit)
	if err != nil {
		e := collect.FromReadError(err, meta)
		e.Reason = passwdPath + ": " + e.Reason
		for _, k := range keys {
			b.Set(k, e)
		}
		return nil
	}
	users, _ := parsePasswd(data)
	shells, _ := loginShells(a)

	inputs := []facts.Source{{Kind: "file", Path: passwdPath}}
	truncated, keysCut := meta.Truncated, false
	files := map[string]*keyFile{}
	var rows []any
	var undeclared []string
	var poison *facts.Envelope
	rootPaths, allPaths := map[string]bool{}, map[string]bool{}
	type rsaRow struct {
		user, path string
		key        authorizedKey
	}
	var rsa []rsaRow

	for _, u := range users {
		if u.home == "" {
			continue
		}
		if !declared(a, path.Join(u.home, ".ssh", authorizedKeysNames[0])) {
			if interactive(u.shell, shells) {
				undeclared = append(undeclared, undeclaredHome(u))
			}
			rows = append(rows, keyRow(u, "", &keyFile{}, true, homeOutside))
			continue
		}
		for _, name := range authorizedKeysNames {
			p := path.Join(u.home, ".ssh", name)
			f, seen := files[p]
			if !seen {
				f = readKeyFile(a, p)
				files[p] = f
				switch {
				case f.status == "ok" && f.exists:
					inputs = append(inputs, facts.Source{Kind: "file", Path: p})
					// A file past the read cap is silence past its end for
					// every leaf; one past the 200 keys a row keeps is that
					// for the inventory alone, since the counts count all.
					truncated = truncated || f.truncated
					keysCut = keysCut || len(f.keys) > authorizedKeysKeys
				case f.status != "ok" && poison == nil:
					poison = &f.env
				}
			}
			rows = append(rows, keyRow(u, p, f, false, f.reason))
			if f.status != "ok" || !f.exists {
				continue
			}
			allPaths[p] = true
			if u.uid == 0 {
				rootPaths[p] = true
			}
			for _, k := range f.keys {
				if k.Type == "ssh-rsa" {
					rsa = append(rsa, rsaRow{u.name, p, k})
				}
			}
		}
	}

	src := &facts.Source{Kind: "derived", Inputs: inputs}
	slices.SortStableFunc(rows, func(x, y any) int {
		mx, my := x.(map[string]any), y.(map[string]any)
		return cmp.Or(cmp.Compare(mx["user"].(string), my["user"].(string)), cmp.Compare(mx["path"].(string), my["path"].(string)))
	})
	shown, cut := capRows(orEmpty(rows), authorizedKeysRows)
	b.Set(sshAuthorizedKeys, withTruncation(collect.OK(shown, src), cut || keysCut || truncated))

	// The three counts are an inventory: a file that could not be read (C3)
	// or an interactive home muster declined to visit (C4) is a hole in it,
	// and the counts say so rather than count around it.
	switch {
	case poison != nil:
		e := *poison
		e.Source = src
		for _, k := range keys[1:] {
			b.Set(k, e)
		}
		return nil
	case len(undeclared) > 0:
		e := undeclaredHomes(undeclared, src)
		for _, k := range keys[1:] {
			b.Set(k, e)
		}
		return nil
	}
	rootCount, dsaCount := 0, 0
	for p := range allPaths {
		for _, k := range files[p].keys {
			if rootPaths[p] {
				rootCount++
			}
			if k.Type == "ssh-dss" {
				dsaCount++
			}
		}
	}
	slices.SortStableFunc(rsa, func(x, y rsaRow) int {
		return cmp.Or(cmp.Compare(x.user, y.user), cmp.Compare(x.path, y.path), cmp.Compare(x.key.Line, y.key.Line))
	})
	rsaList := []any{}
	for _, r := range rsa {
		rsaList = append(rsaList, map[string]any{
			"user": r.user, "path": r.path, "line": r.key.Line, "bits": r.key.Bits, "fingerprint": r.key.Fingerprint,
		})
	}
	rsaShown, rsaCut := capRows(rsaList, rsaKeysRows)
	b.Set(sshRootKeyCount, withTruncation(collect.OK(rootCount, src), truncated))
	b.Set(sshDSAKeyCount, withTruncation(collect.OK(dsaCount, src), truncated))
	b.Set(sshRSAKeys, withTruncation(collect.OK(rsaShown, src), rsaCut || truncated))
	return nil
}

// readKeyFile reads one authorized_keys path. A missing file (or a missing
// .ssh, or a home that is a file) is a reading: no keys. A file that exists
// and cannot be read — denied, or a symlink muster does not follow — is the
// read's status (C3/C4).
func readKeyFile(a collect.Access, p string) *keyFile {
	data, meta, err := a.ReadFile(p, authorizedKeysLimit)
	switch {
	case err == nil:
		keys, unparsed := parseAuthorizedKeys(data)
		return &keyFile{exists: true, status: "ok", mode: int(meta.Mode), uid: int(meta.UID),
			keys: keys, unparsed: unparsed, truncated: meta.Truncated}
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		return &keyFile{status: "ok"}
	}
	// The path is named exactly once (D16): the primitive may already have
	// put it in front of the error's text.
	env := collect.FromReadError(err, collect.ReadMeta{})
	env.Reason = p + ": " + strings.TrimPrefix(env.Reason, p+": ")
	return &keyFile{status: string(env.Status), reason: env.Reason, env: env}
}

// keyRow is one ssh.authorized_keys row. Every row carries all eleven fields
// (V-9, V-19): mode and owner_uid -1 and keys [] where no file was read.
func keyRow(u passwdRow, p string, f *keyFile, unfollowed bool, reason string) map[string]any {
	status := f.status
	if unfollowed {
		status = ""
	}
	mode, uid := -1, -1
	if f.exists {
		mode, uid = f.mode, f.uid
	}
	keys := []any{}
	for _, k := range f.keys {
		options := []any{}
		for _, o := range k.Options {
			// R64: an option is evidence, not a copy of the file; a long
			// command= or environment= value is cut on a rune boundary.
			options = append(options, sourceRaw(o))
		}
		keys = append(keys, map[string]any{
			"line": k.Line, "type": k.Type, "bits": k.Bits, "fingerprint": k.Fingerprint,
			"options": options, "restricted": k.Restricted,
		})
	}
	keys, _ = capRows(keys, authorizedKeysKeys)
	return map[string]any{
		"user": u.name, "uid": u.uid, "path": p, "exists": f.exists,
		"mode": mode, "owner_uid": uid, "keys": keys, "unparsed": f.unparsed,
		"unfollowed": unfollowed, "read_status": status, "reason": reason,
	}
}

func orEmpty(rows []any) []any {
	if rows == nil {
		return []any{}
	}
	return rows
}
