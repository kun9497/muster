package main

import (
	"fmt"
	"io"
)

func runControls(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "muster: controls is not implemented yet")
	return exitError
}
