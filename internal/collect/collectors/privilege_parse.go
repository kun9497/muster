package collectors

import "strings"

// This file is untagged so its test runs on every platform; the collector
// that calls it is privilege.go (linux).

// ldSoPreloadSeparators are the separators glibc's loader splits
// /etc/ld.so.preload on (elf/rtld.c: strsep(&runp, ": \t\n")). A carriage
// return is not one of them, so a CRLF file loads "name\r".
const ldSoPreloadSeparators = ": \t\n"

// parseLdSoPreload returns the entries the loader would preload, in file
// order (V-6): every '#' through the end of its line is a comment wherever
// it stands — glibc blanks it before splitting — and the rest is split on
// space, tab, newline and ':', empty tokens dropped. Never nil.
func parseLdSoPreload(data []byte) []string {
	out := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return strings.ContainsRune(ldSoPreloadSeparators, r)
		}) {
			out = append(out, tok)
		}
	}
	return out
}
