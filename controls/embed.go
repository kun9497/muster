// Package controls embeds the default control set (spec §6.1, D15). Controls
// live at controls/<area>/<name>.yaml; fixtures under controls/testdata are
// read from disk by tests and are not embedded.
package controls

import "embed"

//go:embed VERSION */*.yaml
var FS embed.FS
