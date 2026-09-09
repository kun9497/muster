//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The nfs collector reads the exports files (the judged source) and, as
// corroboration only, asks the running kernel export table to confirm
// them. C1: /etc/exports' own permission facts are NOT written here — a
// fixed path's permission facts belong to the files collector
// (files.etc_exports.*, added alongside this collector); this collector
// owns the CONTENT of the export files, discovered from nothing but its own
// fixed candidate list (the main file plus its drop-in directory), the same
// shape as sshd's Include globs.
const (
	exportsPath  = "/etc/exports"
	exportsDGlob = "/etc/exports.d/*.exports"
)

// exportfsCmd corroborates the parsed exports against the live kernel
// export table. It is never the judged source — a host can only differ from
// what the files say when someone ran exportfs by hand outside the
// persisted configuration — so its failure is never denied or error; see
// nfsRuntimeCollected.
var exportfsCmd = collect.Command{Path: "/usr/sbin/exportfs", Args: []string{"-v"}}

var nfsCollector = collect.Collector{
	Name: "nfs",
	Declare: collect.Declaration{
		Reads:    []string{exportsPath, exportsDGlob},
		Commands: []collect.Command{exportfsCmd},
		// Needs: "none" — exportfs is corroboration, not the judged source,
		// so nothing about this collector requires root.
		Needs: "none",
	},
	Run: runNfs,
}

// runNfs parses /etc/exports and its exports.d fragments into per-path,
// per-client records (the judged source), then records which files
// contributed and whether the exportfs corroboration succeeded.
//
// C3: an export file that EXISTS but cannot be read is the answer for every
// value it could set — nfs.exports and nfs.exports_source both carry that
// read's status rather than a silently wrong empty list; a file that is
// simply absent contributes nothing and parsing continues with whatever
// else is there (a missing /etc/exports with fragments still parses).
func runNfs(ctx context.Context, a collect.Access, b *collect.Builder) error {
	var records []any
	// readFiles is every export file whose content actually reached the
	// parse, in read order: it is both the exports_source value and, per
	// Ruling JR-10, the provenance every envelope here cites. truncated is
	// the subset the read primitive cut at the cap (Ruling JR-2).
	var readFiles, truncated []string

	switch data, meta, err := a.ReadFile(exportsPath, readLimit); {
	case err == nil:
		records = append(records, parseExportsContent(data)...)
		readFiles = append(readFiles, exportsPath)
		if meta.Truncated {
			truncated = append(truncated, exportsPath)
		}
	case errors.Is(err, fs.ErrNotExist):
		// Nothing exported from the main file is not a finding; the
		// fragments below may still export something.
	default:
		return nfsJudged(ctx, a, b, pathReason(exportsPath, collect.FromReadError(err, meta)))
	}

	matches, err := a.Glob(exportsDGlob)
	if err != nil {
		// Ruling JR-6: this collector declares Needs "none", so a Glob that
		// fails is an environment limitation and never an error — one error
		// envelope ranks worst in Builder.Worst, flips run.complete and
		// breaks the collect-contract leg over a condition the reason
		// already describes. patch's identical branch says the same thing.
		return nfsJudged(ctx, a, b, collect.Unsupported("glob "+exportsDGlob+": "+err.Error()))
	}
	sort.Strings(matches)
	for _, m := range matches {
		data, meta, err := a.ReadFile(m, readLimit)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			// The sshd Include precedent: a fragment that cannot be READ must
			// never be silently skipped — that would publish the other
			// files' exports as the complete answer when this one might add
			// or change entries.
			return nfsJudged(ctx, a, b, pathReason(m, collect.FromReadError(err, meta)))
		}
		records = append(records, parseExportsContent(data)...)
		readFiles = append(readFiles, m)
		if meta.Truncated {
			truncated = append(truncated, m)
		}
	}

	// R70 / Ruling JR-2: the read primitive answers a file past the cap with
	// the prefix, Truncated true and NO error, so a directive written past
	// it is invisible. A parse of that prefix is not the answer — publishing
	// it as one is a confident-wrong PASS on the wildcard nobody could see —
	// so both judged leaves go absent naming what was cut, the shape
	// snmp.communities already takes.
	if len(truncated) > 0 {
		return nfsJudged(ctx, a, b, collect.Absent(strings.Join(truncated, ", ")+
			" was cut at the read limit; what is past the cap cannot be judged"))
	}

	sortExportRecords(records)
	var sourceFiles []any
	for _, f := range readFiles {
		sourceFiles = append(sourceFiles, f)
	}
	src := filesSource(readFiles)
	b.Set("nfs.exports", collect.OK(records, src))
	b.Set("nfs.exports_source", collect.OK(sourceFiles, src))
	b.Set("nfs.exports_runtime_collected", nfsRuntimeCollected(ctx, a))
	return nil
}

// nfsJudged publishes one envelope on both judged leaves and still records
// the corroboration — the shape every early return out of runNfs shares, so
// a new one cannot forget the third key (a registered key the snapshot lacks
// is ERROR(missing_fact), never absent_means).
func nfsJudged(ctx context.Context, a collect.Access, b *collect.Builder, e facts.Envelope) error {
	b.Set("nfs.exports", e)
	b.Set("nfs.exports_source", e)
	b.Set("nfs.exports_runtime_collected", nfsRuntimeCollected(ctx, a))
	return nil
}

// nfsRuntimeCollected asks the kernel export table to corroborate the parsed
// files. exportfs is corroboration only, never the judged source, so ANY
// failure — the binary absent, a non-root privilege refusal, a timeout —
// is recorded as a plain false, never denied or error: a missing
// corroboration is not itself an environment limitation worth flagging, so
// this stays "ok" throughout (Worst("nfs") == ok on every shape).
func nfsRuntimeCollected(ctx context.Context, a collect.Access) facts.Envelope {
	out := a.Run(ctx, exportfsCmd)
	return withTruncation(collect.OK(cmdOK(out), out.Source(exportfsCmd)), out.Truncated)
}

// parseExportsContent parses one exports file's content into records.
// Comments and blank lines are skipped, a trailing backslash continues the
// line, the first token is the path (a quoted path with an embedded space
// is honoured) and every remaining token is a client spec
// `client(options)`; a path with no client spec at all exports to the world
// under the kernel's own defaults (ro, root_squash).
func parseExportsContent(data []byte) []any {
	recs := []any{}
	raw := splitLines(data)
	// Round-1 review finding 1: exports(5) says '#' introduces a comment
	// anywhere on a line, not only at its start. Strip per PHYSICAL line,
	// before backslash-continuation joining, so a comment can never smuggle
	// a stray "\" into the join.
	deCommented := make([]string, len(raw))
	for i, l := range raw {
		deCommented[i] = stripComment(l)
	}
	for _, line := range joinBackslashContinuedLines(deCommented) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		toks := tokenizeExportLine(trimmed)
		if len(toks) == 0 {
			continue
		}
		path := toks[0]
		clients := toks[1:]
		if len(clients) == 0 {
			recs = append(recs, exportRecord(path, "*", ""))
			continue
		}
		for _, ct := range clients {
			if strings.HasPrefix(ct, "-") {
				// Round-1 review finding 3 (LOW): BSD exportfs's
				// "-options,root=host" defaults-line syntax is not valid
				// exports(5) on Linux; skip it rather than mint a bogus
				// client named "-rw".
				continue
			}
			client, options := splitClientSpec(ct)
			if client == "" {
				// Round-1 review finding 2: exportfs's classic space-before-'('
				// trap. tokenizeExportLine already split "client (options)" on
				// the space into TWO tokens, so a token that is bare
				// "(options)" is a SECOND, separate client spec — the world —
				// not the preceding host's options. Normalise it the same way
				// the no-client-spec branch above already does.
				client = "*"
			}
			recs = append(recs, exportRecord(path, client, options))
		}
	}
	return recs
}

// stripComment removes everything from the first unquoted '#' onward:
// exports(5) documents '#' as introducing a comment wherever it appears on a
// line, not only at the start. Kept simple per the round-1 review: a '#'
// inside a double-quoted path is honoured, but there is no escape-character
// handling beyond that — exports(5) itself does not define any.
func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

// exportRecord builds one nfs.exports record. wildcard and root_squash are
// both DERIVED, never read from an explicit directive: the kernel exports
// to the world and squashes root by default, so a bare path or a bare
// client name says exactly as much about the host as an explicit option
// would.
func exportRecord(path, client, options string) map[string]any {
	return map[string]any{
		"path":        path,
		"client":      client,
		"options":     options,
		"wildcard":    isWildcardClient(client),
		"root_squash": !strings.Contains(options, "no_root_squash"),
	}
}

// isWildcardClient reports whether client names every host: the bare "*",
// or a glob containing "*"/"?". A CIDR, a hostname and a netgroup
// (`@group`) all name a bounded set and are never wildcards.
func isWildcardClient(client string) bool {
	return client == "*" || strings.ContainsAny(client, "*?")
}

// splitClientSpec splits one `client(options)` token. A token with no
// parenthesised options at all (a bare client) carries an empty options
// string, matching the kernel's own default options.
func splitClientSpec(tok string) (client, options string) {
	if i := strings.IndexByte(tok, '('); i >= 0 && strings.HasSuffix(tok, ")") {
		return tok[:i], tok[i+1 : len(tok)-1]
	}
	return tok, ""
}

// tokenizeExportLine splits an exports line on whitespace, honouring double
// quotes so a path with an embedded space ("/srv/my share") is one token;
// the quote characters themselves are not part of the token.
func tokenizeExportLine(line string) []string {
	var toks []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t') && !inQuote:
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

// joinBackslashContinuedLines joins a line ending in `\` with the next
// physical line, the same continuation exportfs itself honours.
func joinBackslashContinuedLines(raw []string) []string {
	out := []string{}
	buf := ""
	for _, line := range raw {
		line = strings.TrimRight(line, " \t")
		if strings.HasSuffix(line, "\\") {
			buf += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		out = append(out, buf+line)
		buf = ""
	}
	if buf != "" {
		out = append(out, buf)
	}
	return out
}

// sortExportRecords sorts records by (path, client) so the same input
// always yields the same bytes, independent of which file — or which order
// within a file — a record came from.
func sortExportRecords(recs []any) {
	sort.Slice(recs, func(i, j int) bool {
		ri, rj := recs[i].(map[string]any), recs[j].(map[string]any)
		pi, pj := ri["path"].(string), rj["path"].(string)
		if pi != pj {
			return pi < pj
		}
		return ri["client"].(string) < rj["client"].(string)
	})
}
