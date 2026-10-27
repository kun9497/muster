package cisindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Pin names the upstream file an index was decoded from.
type Pin struct {
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// EqualTo names a second pinned file whose ids and levels matched the first.
type EqualTo struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Compared string `json:"compared"`
}

// Counts holds the one count the index carries beyond the mapped rows.
type Counts struct {
	L1Server int `json:"l1_server"`
}

// Row is one mapped recommendation.
type Row struct {
	Rec      string   `json:"rec"`
	Levels   []string `json:"levels"`
	Controls []string `json:"controls"`
	Rules    string   `json:"rules"`
}

// Index is the generated per-product CIS index.
type Index struct {
	Product   string   `json:"product"`
	Benchmark string   `json:"benchmark"`
	Version   string   `json:"version"`
	AppliesTo []string `json:"applies_to"`
	Source    Pin      `json:"source"`
	EqualTo   *EqualTo `json:"equal_to,omitempty"`
	Counts    Counts   `json:"counts"`
	Recs      []Row    `json:"recs"`
}

// RenderIndex is the index's canonical bytes: two-space indent, trailing
// newline, a nil AppliesTo, row Levels or row Controls spelled [].
func RenderIndex(ix *Index) ([]byte, error) {
	c := *ix
	if c.AppliesTo == nil {
		c.AppliesTo = []string{}
	}
	c.Recs = make([]Row, len(ix.Recs))
	for i, r := range ix.Recs {
		if r.Levels == nil {
			r.Levels = []string{}
		}
		if r.Controls == nil {
			r.Controls = []string{}
		}
		c.Recs[i] = r
	}
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeIndex reads one index strictly: unknown fields, a second value, a
// missing product or version, an invalid rec or an unknown rules word refuse.
func DecodeIndex(data []byte) (*Index, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var ix Index
	if err := dec.Decode(&ix); err != nil {
		return nil, fmt.Errorf("cis index: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("cis index: more than one JSON value")
	}
	if ix.Product == "" || ix.Version == "" {
		return nil, fmt.Errorf("cis index: product and version are required")
	}
	for _, r := range ix.Recs {
		if !ValidRec(r.Rec) {
			return nil, fmt.Errorf("cis index: rec %q is not a recommendation number", r.Rec)
		}
		switch r.Rules {
		case "all", "some", "none":
		default:
			return nil, fmt.Errorf("cis index: rec %s: rules word %q", r.Rec, r.Rules)
		}
	}
	return &ix, nil
}
