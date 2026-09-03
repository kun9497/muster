//go:build linux

package collectors

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	passwdPath    = "/etc/passwd"
	securettyPath = "/etc/securetty"
)

var filesCollector = collect.Collector{
	Name:    "files",
	Declare: collect.Declaration{Reads: []string{passwdPath, securettyPath}, Needs: "none"},
	Run:     runFiles,
}

// aclPresent reports whether an access ACL is set on p. R46: the attribute
// names come from Access.Llistxattr, which lists them through the same
// no-follow open the reads use — never unix.Llistxattr on the path, which
// resolves every component but the last. A filesystem without extended
// attribute support (EOPNOTSUPP) or a file with none at all (ENODATA)
// simply has no ACL; anything else propagates, so the fact is denied rather
// than a confident false.
func aclPresent(a collect.Access, p string) (bool, error) {
	names, err := a.Llistxattr(p)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENODATA) {
			return false, nil
		}
		return false, err
	}
	for _, n := range names {
		if n == "system.posix_acl_access" {
			return true, nil
		}
	}
	return false, nil
}

func runFiles(_ context.Context, a collect.Access, b *collect.Builder) error {
	src := &facts.Source{Kind: "file", Path: passwdPath}
	meta, err := a.Stat(passwdPath)
	if err != nil {
		e := collect.FromReadError(err, meta)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_passwd."+k, e)
		}
	} else {
		// R51/R69: the raw 0o7777 bits as fstat reported them, not
		// FileMode.Perm(), which cannot carry setuid, setgid or sticky and
		// would silently report 0o4755 as 0o755.
		b.Set("files.etc_passwd.mode", collect.OK(int(meta.Mode), src))
		b.Set("files.etc_passwd.uid", collect.OK(int(meta.UID), src))
		b.Set("files.etc_passwd.gid", collect.OK(int(meta.GID), src))
		if present, aerr := aclPresent(a, passwdPath); aerr != nil {
			b.Set("files.etc_passwd.acl_present", collect.FromReadError(aerr, meta))
		} else {
			b.Set("files.etc_passwd.acl_present", collect.OK(present, src))
		}
	}

	// /etc/securetty is absent on RHEL 8+ and on the Debian family; the
	// control that reads it treats that as "this mechanism is not in use".
	data, smeta, err := a.ReadFile(securettyPath, readLimit)
	if err != nil {
		e := collect.FromReadError(err, smeta)
		b.Set("files.etc_securetty", e)
		b.Set("files.etc_securetty_lines", e)
		return nil
	}
	ssrc := &facts.Source{Kind: "file", Path: securettyPath}
	lines := []any{} // R50: an empty file yields [], never null
	for _, l := range splitLines(data) {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	// R70: file-derived facts carry the read's truncation flag.
	b.Set("files.etc_securetty", collect.OKRead(map[string]any{
		"mode": int(smeta.Mode),
		"uid":  int(smeta.UID),
		"gid":  int(smeta.GID),
	}, ssrc, smeta))
	b.Set("files.etc_securetty_lines", collect.OKRead(lines, ssrc, smeta))
	return nil
}
