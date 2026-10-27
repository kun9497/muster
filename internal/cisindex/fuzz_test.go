package cisindex

import "testing"

func FuzzDecodeControls(f *testing.F) {
	f.Add([]byte(sampleYAML))
	f.Add([]byte("version: v1\ncontrols:\n  - id: reload_dconf_db\n  - id: 1.1.1\n    rules: [a, b=c]\n"))
	f.Add([]byte("version: v1\ncontrols:\n  - id: '1.2'\n    rules: [\"=x\"]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		src, err := DecodeControls(data)
		if err != nil {
			return
		}
		for _, e := range src.Entries {
			if !ValidRec(e.ID) {
				t.Fatalf("invalid id %q", e.ID)
			}
		}
	})
}

func FuzzDecodeIndex(f *testing.F) {
	good, _ := RenderIndex(sampleIndex())
	f.Add(good)
	f.Add([]byte(`{"product":"p","version":"v","recs":[{"rec":"1.1","rules":"none"}]}`))
	f.Add([]byte(`{"recs":[{"rec":"1.1","title":"x"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ix, err := DecodeIndex(data)
		if err != nil {
			return
		}
		for _, r := range ix.Recs {
			if !ValidRec(r.Rec) {
				t.Fatalf("invalid rec %q", r.Rec)
			}
		}
	})
}
