package controls

import "testing"

func FuzzParseCISIndex(f *testing.F) {
	f.Add([]byte(cisDoc("mini", `"a"`)))
	f.Add([]byte(`{"product":"p","version":"1","recs":[{"rec":"1.1","rules":"all"}]}`))
	f.Add([]byte(`{"product":"p","title":"x"}`))
	f.Add([]byte(`{} {}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		ix, err := parseCISIndex(data)
		if err == nil && (ix == nil || ix.Product == "" || ix.Version == "") {
			t.Fatalf("accepted an index without product or version: %q", data)
		}
	})
}
