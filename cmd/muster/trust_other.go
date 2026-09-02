//go:build !linux

package main

// trustedFile has nothing to check off Linux: check does not run as root
// there in a way that matters, and the ownership model differs.
func trustedFile(path string) (bool, string) { return true, "" }
