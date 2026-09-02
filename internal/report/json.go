package report

import (
	"encoding/json"
	"io"
)

// WriteJSON renders the report as indented JSON with a trailing newline.
// encoding/json sorts map keys, so the only map (check.params) is stable too.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
