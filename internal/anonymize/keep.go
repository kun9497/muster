package anonymize

// KeepSetVersion is recorded in the header as keep_set (AX-5).
const KeepSetVersion = "v1"

var keepSet = map[string]bool{
	"root": true, "ftp": true, "lp": true, "uucp": true, "nuucp": true, "adm": true,
	"syslog": true, "utmp": true, "wheel": true, "sudo": true, "admin": true,
	"ALL": true, "*": true,
}

// Kept reports whether an account or group name, without its sigil, is in the
// closed keep set.
func Kept(name string) bool { return keepSet[name] }
