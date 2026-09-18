//go:build linux

package collectors

import (
	"path"
	"strings"
)

// moduleObjectSuffixes are the spellings of a compiled module object. A
// distribution that compresses its modules writes .ko.zst (Fedora/EL9,
// Ubuntu 24.04) or .ko.xz, and .ko.gz is the third compressor the kernel
// build supports; the longest suffix is tried first so ".ko" can never cut a
// ".ko.zst" down to "udf.ko".
var moduleObjectSuffixes = []string{".ko.zst", ".ko.xz", ".ko.gz", ".ko"}

// foldModuleName is the one spelling a module is compared under. modprobe
// treats "-" and "_" as the same character in a module name — usb-storage
// and usb_storage are one module, and an administrator's blacklist line may
// use either — so every name that reaches a row is folded first (B-2).
func foldModuleName(name string) string {
	return strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
}

// moduleObjectName turns a path out of modules.dep or modules.builtin —
// "kernel/fs/squashfs/squashfs.ko.zst" — into the folded module name.
func moduleObjectName(p string) string {
	base := path.Base(strings.TrimSpace(p))
	for _, suffix := range moduleObjectSuffixes {
		if trimmed, ok := strings.CutSuffix(base, suffix); ok {
			base = trimmed
			break
		}
	}
	return foldModuleName(base)
}

// parseModulesDep reads the module tree's dependency index: one line per
// module the tree ships, "kernel/net/sctp/sctp.ko: kernel/lib/libcrc32c.ko".
// Only the left of the colon is collected — every module named as a
// dependency has a line of its own — and a line without one is not an entry.
func parseModulesDep(data []byte) []string {
	out := []string{}
	for _, raw := range splitLines(data) {
		object, _, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		if object = strings.TrimSpace(object); object == "" {
			continue
		}
		out = append(out, moduleObjectName(object))
	}
	return out
}

// parseModulesBuiltin reads the index of modules compiled INTO the kernel:
// one object path per line, no other syntax. A module listed here is not a
// module any more — modprobe cannot load it, blacklist cannot stop it, and
// only a rebuild removes it (B-4).
func parseModulesBuiltin(data []byte) []string {
	out := []string{}
	for _, raw := range splitLines(data) {
		if line := strings.TrimSpace(raw); line != "" {
			out = append(out, moduleObjectName(line))
		}
	}
	return out
}

// parseProcModules reads the kernel's list of loaded modules: the first field
// of each row is the module's name, in the kernel's own folded spelling.
func parseProcModules(data []byte) []string {
	out := []string{}
	for _, raw := range splitLines(data) {
		if fields := strings.Fields(raw); len(fields) > 0 {
			out = append(out, foldModuleName(fields[0]))
		}
	}
	return out
}

// modprobeDirective is one directive of a modprobe.d file, reduced to what a
// row is decided from: which directive it is, the module it names (folded),
// and — for install alone — the command it would run instead of loading.
type modprobeDirective struct {
	kind    string
	module  string
	command string
}

// modprobeModuleFirst are the directives of modprobe.d(5) whose FIRST
// argument is a module name. blacklist and install decide two of the row's
// fields; options, remove and softdep decide none but still MENTION the
// module, which is what puts their file in the row's sources.
//
// alias is deliberately absent: its first argument is the alias pattern, not
// a module, and a row that counted it would cite a file by matching the
// wrong word.
var modprobeModuleFirst = map[string]bool{
	"blacklist": true,
	"install":   true,
	"options":   true,
	"remove":    true,
	"softdep":   true,
}

// parseModprobeD reads one modprobe.d file, the way kmod reads one.
//
// Two rules, and only two. A backslash escapes the character after it: at the
// end of a physical line that character is the newline, so the next line is
// part of the same logical line and the two are joined with NOTHING between
// them (kmod's freadline_wrapped drops the backslash and the newline and
// keeps every other byte, including the whitespace either side). And a
// logical line is a comment only when its FIRST character is "#" — kmod does
// not scan for a "#" anywhere else, so a "#" further along the line is an
// ordinary argument, and an install command that carries one keeps it.
//
// Reading a trailing "#" as a comment would be the dangerous half of that: it
// would cut an install command short and could turn a command muster does not
// recognise into "/bin/false", which is the one direction that turns a live
// module into a PASS.
func parseModprobeD(data []byte) []modprobeDirective {
	out := []modprobeDirective{}
	pending := ""
	for _, raw := range splitLines(data) {
		text, continued := unescapeModprobeLine(raw)
		pending += text
		if continued {
			continue
		}
		line := pending
		pending = ""
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !modprobeModuleFirst[fields[0]] {
			continue
		}
		d := modprobeDirective{kind: fields[0], module: foldModuleName(fields[1])}
		if d.kind == "install" {
			d.command = strings.Join(fields[2:], " ")
		}
		out = append(out, d)
	}
	return out
}

// modprobeEscape is the character kmod reads as an escape.
const modprobeEscape = '\\'

// unescapeModprobeLine applies kmod's character rule to one physical line: a
// backslash at the end of the line says the logical line continues on the
// next one, and a backslash anywhere else is dropped and the character after
// it kept verbatim. It returns the line's contribution and whether the
// logical line continues.
func unescapeModprobeLine(line string) (string, bool) {
	if !strings.Contains(line, `\`) {
		return line, false
	}
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] != modprobeEscape {
			b.WriteByte(line[i])
			continue
		}
		if i == len(line)-1 {
			return b.String(), true
		}
		i++
		b.WriteByte(line[i])
	}
	return b.String(), false
}

// installDisables reports whether an install command is the "never load
// this" idiom (B-7). `install <name> /bin/false` (or /bin/true) replaces
// loading with a command that does nothing; `install <name> /sbin/modprobe
// --ignore-install <name>` is the OPPOSITE — it is how an administrator
// hangs something off a load that still happens — and reading it as disabled
// would pass a host on which the module loads exactly as before.
func installDisables(command string) bool {
	fields := strings.Fields(command)
	return len(fields) > 0 && (fields[0] == installFalse || fields[0] == installTrue)
}
