//go:build linux

package collectors

import (
	"github.com/kun9497/muster/internal/pkgindex"
)

// rpmCommand is the file-table query pkgindex runs (its comment says what
// each column is and why the bounds are what they are). The walk declares
// it; the guard compares Path and Args, so the one row licenses the query
// whatever bounds a caller runs it under.
var rpmCommand = pkgindex.RPMCommand

// rpmFile is one row of the file table, for a candidate path only.
type rpmFile = pkgindex.RPMFile

// rpmFileTable is pkgindex.RPMFileTable, the reader the walk's tests pin.
func rpmFileTable(stdout []byte, cands map[string]bool, truncated bool) (map[string]rpmFile, error) {
	return pkgindex.RPMFileTable(stdout, cands, truncated)
}

// applyRPM writes the table's answer onto every candidate row. A path the
// table does not hold keeps the fields the traversal initialised — package
// "", package_declared false, reference unpackaged — which is exactly the
// answer for a file no package owns.
func applyRPM(r *walkResult, table map[string]rpmFile) {
	for _, row := range r.lists.suid {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		bits := candidateBits(row)
		row["package"] = f.Pkg
		row["package_declared"] = f.Mode&bits == bits
		row["declared_mode"] = f.Mode
		row["declared_owner"], row["declared_group"] = f.Owner, f.Group
		row["reference"] = refRPMDB
	}
	for _, row := range r.lists.worldWritable {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		row["package"] = f.Pkg
		row["package_declared"] = f.Mode&0o002 != 0
		row["reference"] = refRPMDB
	}
	for _, row := range r.lists.hidden {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		// A hidden entry carries no bit to compare, so being owned by a
		// package IS the declaration (W-6).
		row["package"] = f.Pkg
		row["package_declared"] = true
		row["reference"] = refRPMDB
	}
	applyRPMCaps(r, table)
}
