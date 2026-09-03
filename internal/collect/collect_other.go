//go:build !linux

package collect

import "errors"

// Supported reports whether collect can run on this platform (D23).
const Supported = false

var errPlatform = errors.New("muster collect requires Linux")

func ReadFile(string, int64) ([]byte, ReadMeta, error) { return nil, ReadMeta{}, errPlatform }
func Stat(string) (ReadMeta, error)                    { return ReadMeta{}, errPlatform }
