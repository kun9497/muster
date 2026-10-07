package report

import (
	"encoding/json"
	"io"
)

// WriteJSON renders the report as indented JSON with a trailing newline.
// encoding/json sorts map keys, so the maps (check.params, check.param_sources)
// are stable too.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
