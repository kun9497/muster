package main

import (
	"fmt"
	"io"
)

func runCheck(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "muster: check is not implemented yet")
	return exitError
}
