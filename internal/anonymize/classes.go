package anonymize

// Value classes (AX-4, AX-10). The first seven are the tokens of
// run.anonymization.classes; the rest steer the walker and never appear there.
const (
	ClassAccount     = "account"
	ClassHost        = "host"
	ClassAddress     = "address"
	ClassURL         = "url"
	ClassFingerprint = "fingerprint"
	ClassMachineID   = "machine_id_hash"
	ClassPath        = "path"

	ClassHostOrAddr = "host_or_address"
	// ClassHostOrNetgroup is a host-or-address value whose leading "@" names
	// a netgroup, mapped by the account rule, rather than rsyslog's forward
	// sigil (hosts.equiv's first token, an NFS client).
	ClassHostOrNetgroup = "host_or_netgroup"
	ClassPlaceholder    = "placeholder"
	// ClassBlank empties a value: a string becomes "", a number 0, presence
	// is kept; its paths enter run.anonymization.replaced.
	ClassBlank   = "blank"
	ClassKept    = "kept"
	ClassGrammar = "grammar"
)
