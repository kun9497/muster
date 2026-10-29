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

func FuzzDecodeMap(f *testing.F) {
	f.Add([]byte(sampleMap))
	f.Add([]byte("- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: { 14: 14 } }]\n"))
	f.Add([]byte("- id: muster.a\n  rules: [r]\n---\n- id: muster.b\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rows, err := DecodeMap(data)
		if err != nil {
			return
		}
		for i, r := range rows {
			if r.ID == "" || (i > 0 && rows[i-1].ID >= r.ID) {
				t.Fatalf("rows not sorted and unique: %+v", rows)
			}
			for _, v := range r.Vars {
				if (v.Param == "none") != (v.Reason != "") || (v.Param == "none") == (v.As != nil) {
					t.Fatalf("vars row %+v", v)
				}
			}
		}
	})
}

func FuzzDecodeReview(f *testing.F) {
	f.Add([]byte(sampleReview))
	f.Add([]byte("[]\n"))
	f.Add([]byte("- { profile: p, id: muster.a, reason: x }\n- { profile: p, id: muster.a, reason: y }\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rows, err := DecodeReview(data)
		if err != nil {
			return
		}
		seen := map[ReviewRow]bool{}
		for _, r := range rows {
			k := ReviewRow{Profile: r.Profile, ID: r.ID}
			if seen[k] || r.Reason == "" {
				t.Fatalf("rows %+v", rows)
			}
			seen[k] = true
		}
	})
}
