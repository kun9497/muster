package tuning

import "testing"

func FuzzParseTuning(f *testing.F) {
	// Seeds are literals (Z-12): the valid file of TestLoadReadsValidatesAndDigests,
	// an empty params map, a list parameter and a malformed file.
	f.Add([]byte("params:\n  muster.account.password_policy:\n    min_len: 12\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n"))
	f.Add([]byte("params: {}\n"))
	f.Add([]byte("params:\n  a.b:\n    c: [1, 2]\n"))
	f.Add([]byte("params: [\n")) // malformed: Parse must refuse it with a nil file
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil && file != nil {
			t.Fatalf("error with a file: %v", err)
		}
		// parse is Parse without the sentinel: the same verdict on the same bytes.
		inner, innerErr := parse(data)
		if (innerErr == nil) != (err == nil) || (innerErr != nil && inner != nil) {
			t.Fatalf("parse and Parse disagree: %v vs %v", innerErr, err)
		}
	})
}
