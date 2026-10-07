//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// trustedFile refuses, when running as root, a data file that someone other
// than root could have written (spec §4.4, §6.7): a waiver, profile or tuning
// file on the host can change what check reports -- turn a FAIL into a clean
// run, drop a control from the run or relax the value it judges against.
func trustedFile(path string) (bool, string) {
	if os.Geteuid() != 0 {
		return true, ""
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, err.Error()
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
		return false, fmt.Sprintf("%s is owned by uid %d, not root", path, sys.Uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return false, fmt.Sprintf("%s is group- or world-writable (%04o)", path, st.Mode().Perm())
	}
	return true, ""
}
