//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/pkgfiles"
)

// The walk's capability and ACL lists (P-3). ReadDir, under
// ReadDirOptions{Xattrs: true}, opens every regular entry with an execute
// bit and hands back its security.capability and system.posix_acl_access
// attributes; this file turns them into rows and, in the join, decides
// each capability against the owning package's own declaration — rpm's
// %{FILECAPS} tag or the setcap call in a dpkg postinst. There is no
// reference list: a capability either is declared where packages declare
// capabilities, or it is not.
const (
	// declaredFromFile is declared_caps for a postinst that hands setcap its
	// set on standard input from a file the package ships: the script
	// names the path, the text is not in it.
	declaredFromFile = "(from file)"

	// dpkgPostinstGlob is what the walk may read of the maintainer
	// scripts: the postinst beside each .list, multi-arch names included.
	dpkgPostinstGlob = "/var/lib/dpkg/info/*.postinst"
)

// capabilityRow reads one executable's attributes into the two lists. An
// entry whose attributes could not be read is a skip (V-39). ReadDir sets
// Caps only when it read the capability from the verified fd, so a
// capability beside a failure means the ACL read failed after it: the
// capability row is emitted as well as the skip (V-68), never lost to a
// failure of the other attribute. Anything else with a failure is the skip
// alone. A capability attribute that does not decode is a skip too — the
// kernel would refuse it, so it is no capability, but a reader should see
// that the walk met one.
func (w *walker) capabilityRow(e collect.DirEntry, p string) {
	if e.XattrErr != nil {
		reason, detail := xattrSkipReason(e.XattrErr)
		w.addSkip(p, reason, detail)
		if e.Caps == nil {
			return
		}
		e.ACL = nil // not read: the failure was the ACL's
	}
	if e.Caps != nil {
		cs, err := decodeVfsCap(e.Caps)
		if err != nil {
			w.addSkip(p, "xattr_undecoded", err.Error())
		} else {
			// The package fields are initialised here, as the setuid rows'
			// are, so a run whose join failed still emits one shape.
			w.r.lists.addRow(capCapabilities, map[string]any{
				"path": p, "caps": capText(cs), "rootid": int(cs.RootID),
				"package": "", "package_declared": false, "declared_caps": "",
				"reference": refUnpackaged, "reason": "",
			})
		}
	}
	if e.ACL != nil {
		entries, err := decodeACL(e.ACL)
		if err != nil {
			w.addSkip(p, "xattr_undecoded", err.Error())
			return
		}
		if grants := aclWidens(entries, e.Mode); grants != nil {
			list := make([]any, 0, len(grants))
			for _, g := range grants {
				list = append(list, g)
			}
			w.r.lists.addRow(capACLGrants, map[string]any{"path": p, "entries": list})
		}
	}
}

// xattrSkipReason maps an entry's attribute failure onto walk.skipped's
// closed vocabulary: a file this process may not open is xattr_denied; one
// that is not the file the listing named is vanished, and one that is gone,
// is a link now, or was replaced by a device or socket (ENXIO on the open)
// is vanished with the errno in detail; any other errno
// (EIO, ENOMEM, …) is xattr_error with the errno in detail, so nothing is
// lost and the vocabulary stays closed.
func xattrSkipReason(err error) (reason, detail string) {
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM), errors.Is(err, fs.ErrPermission):
		return "xattr_denied", ""
	case errors.Is(err, collect.ErrVanished):
		return "vanished", "the entry changed between listing and opening"
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		if errno == unix.ENOENT || errno == unix.ELOOP || errno == unix.ENOTDIR || errno == unix.ENXIO {
			return "vanished", errno.Error()
		}
		return "xattr_error", errno.Error()
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, collect.ErrSymlink) {
		return "vanished", err.Error()
	}
	return "xattr_error", err.Error()
}

// aclWidens is the access-ACL entries that grant a named user or group
// write or execute beyond what the owning group's own entry grants, after
// the mask (acl(5): a named entry's effective rights are its rights and the
// mask). The comparison is against the group:: entry because the mode's
// group bits ARE the mask once an ACL has named entries, so nothing could
// ever exceed them; group:: is what those bits meant before the ACL. A
// list with no group:: entry (not one the kernel writes) falls back to the
// mode's group bits. Read is never a widening here: this list is about who
// may change or run an executable. nil when no entry widens.
func aclWidens(entries []string, mode uint32) []string {
	mask, groupObj := 7, int(mode>>3)&7
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e, "mask::"):
			mask = aclPerm(e)
		case strings.HasPrefix(e, "group::"):
			groupObj = aclPerm(e)
		}
	}
	var out []string
	for _, e := range entries {
		named := (strings.HasPrefix(e, "user:") && !strings.HasPrefix(e, "user::")) ||
			(strings.HasPrefix(e, "group:") && !strings.HasPrefix(e, "group::"))
		if !named {
			continue
		}
		if aclPerm(e)&mask&3&^groupObj != 0 {
			out = append(out, e)
		}
	}
	return out
}

// aclPerm reads the rwx triple decodeACL renders at the end of an entry.
func aclPerm(entry string) int {
	if len(entry) < 3 {
		return 0
	}
	t, perm := entry[len(entry)-3:], 0
	if t[0] == 'r' {
		perm |= 4
	}
	if t[1] == 'w' {
		perm |= 2
	}
	if t[2] == 'x' {
		perm |= 1
	}
	return perm
}

// rowRootID is the namespace root a capability row's attribute names.
func rowRootID(row map[string]any) int {
	n, _ := row["rootid"].(int)
	return n
}

// rootIDReason is the reason a row with a namespace root carries. A
// revision-3 attribute with a non-zero rootid was written from inside a
// user namespace: neither rpm, which stores the build's text, nor a
// postinst's setcap without -n writes one, so whatever the text says, the
// package did not set this attribute (spec P-3).
func rootIDReason(row map[string]any) string {
	if n := rowRootID(row); n != 0 {
		return "rootid " + strconv.Itoa(n) + ": set from a user namespace, not by the package"
	}
	return ""
}

// declaresCaps says whether a declared text is the set a row carries, triple
// against triple (V-3): the row's caps is capText's own output, which
// parses back to the attribute's set. A row with a namespace root is never
// declared (rootIDReason).
func declaresCaps(row map[string]any, declared string) bool {
	if declared == "" || rowRootID(row) != 0 {
		return false
	}
	have, err := parseCapText(rowField(row, "caps"))
	if err != nil {
		return false
	}
	want, err := parseCapText(declared)
	return err == nil && sameCaps(have, want)
}

// applyRPMCaps decides the capability rows from rpm's file table: the
// %{FILECAPS} column is the package's declaration, in its build host's
// libcap spelling. A path the table does not hold stays unpackaged.
func applyRPMCaps(r *walkResult, table map[string]rpmFile) {
	for _, row := range r.lists.capabilities {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		row["package"] = f.Pkg
		row["package_declared"] = declaresCaps(row, f.Caps)
		row["declared_caps"] = f.Caps
		row["reference"] = refRPMDB
		row["reason"] = rootIDReason(row)
	}
}

// postinstPath is the maintainer script beside a .list, multi-arch
// qualifier and all: libgstreamer1.0-0:amd64.list -> …:amd64.postinst.
func postinstPath(listFile string) string {
	return strings.TrimSuffix(listFile, ".list") + ".postinst"
}

// readPostinst reads and parses the postinst beside a .list. It never fails
// the join (V-22): a package's script says what that package declares and
// nothing about any other, so an unreadable one is that row's answer alone.
func (j *dpkgJoin) readPostinst(listFile string) ([]postinstCap, error) {
	if listFile == "" {
		return nil, fs.ErrNotExist
	}
	data, _, err := j.a.ReadFile(postinstPath(listFile), dpkgJoinReadLimit)
	if err != nil {
		return nil, err
	}
	return parsePostinstSetcap(data), nil
}

// applyDpkgCaps decides the capability rows on a dpkg host. A .deb cannot
// carry an attribute, so the package that owns the path sets it at install
// time from its postinst; the script is read once per package, and a row
// is declared when the script's setcap names the path with the same set,
// or names it with a set read from a file. A missing script declares
// nothing and says nothing more (most packages have none); an unreadable
// one declares nothing and says why, and so does a script whose only
// setcap calls muster could not resolve.
func (j *dpkgJoin) applyDpkgCaps(r *walkResult) {
	type read struct {
		caps []postinstCap
		err  error
	}
	cache := map[string]read{}
	for _, row := range r.lists.capabilities {
		p := rowField(row, "path")
		pkg, owned := j.idx.Owner[p]
		if !owned {
			continue
		}
		row["package"] = pkg
		row["package_declared"] = false
		row["declared_caps"] = ""
		row["reference"] = refPostinst
		lf := j.idx.ListFile[p]
		rd, seen := cache[lf]
		if !seen {
			rd.caps, rd.err = j.readPostinst(lf)
			cache[lf] = rd
		}
		if rd.err != nil {
			if !errors.Is(rd.err, fs.ErrNotExist) {
				row["reason"] = postinstPath(lf) + ": " + collect.FromReadError(rd.err, collect.ReadMeta{}).Reason
			}
			if reason := rootIDReason(row); reason != "" {
				row["reason"] = reason
			}
			continue
		}
		declared, text, unresolved := j.postinstDecides(row, p, rd.caps)
		row["package_declared"] = declared
		row["declared_caps"] = text
		switch {
		case rootIDReason(row) != "":
			row["reason"] = rootIDReason(row)
		case !declared && text == "" && unresolved:
			row["reason"] = postinstPath(lf) + ": a setcap call muster could not resolve"
		}
	}
}

// postinstDecides matches a script's setcap calls to one row. A literal
// name matches when it canonicalises to the row's own path (a pre-merge
// /bin spelling included); a name that came from dpkg-divert --truename is
// wherever dpkg put the package's file, so it matches a diverted row
// through the name the package's .list gave it. A literal setcap on a
// diverted name acts on the diverter's file, never on this one. The first
// call that declares the row's set wins; failing that, the first call that
// names the path says what the package did declare. unresolved reports
// whether the script had a setcap call muster could not read.
func (j *dpkgJoin) postinstDecides(row map[string]any, p string, calls []postinstCap) (declared bool, text string, unresolved bool) {
	shipped := j.idx.ListPath[p]
	named := false
	for _, c := range calls {
		if c.Unresolved {
			unresolved = true
			continue
		}
		canon := pkgfiles.CanonicalUsr(c.Path, j.merged)
		if canon != p && (!c.Truename || shipped == "" || canon != shipped) {
			continue
		}
		if c.FromFile {
			return rowRootID(row) == 0, declaredFromFile, unresolved
		}
		if declaresCaps(row, c.Caps) {
			return true, c.Caps, unresolved
		}
		if !named {
			text, named = c.Caps, true
		}
	}
	return false, text, unresolved
}
