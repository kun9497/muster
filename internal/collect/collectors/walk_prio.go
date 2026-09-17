//go:build linux

package collectors

import "golang.org/x/sys/unix"

// applyPriority lowers the calling thread's scheduling and I/O priority so
// that a whole-filesystem walk stays out of the way of whatever the host is
// actually for: niceness 10, and the idle I/O class, which only gets disk
// time when nothing else wants any.
//
// Both settings are per-THREAD on Linux, not per-process, which is why the
// caller locks the goroutine to its thread before calling and why the walk
// does its reading on that same thread. Neither call is required to
// succeed: a kernel without ioprio_set, a seccomp profile that filters it,
// or a container whose policy forbids it all leave the walk perfectly able
// to run, just less polite. The two return values say which one took, so
// the collector can record what it actually did rather than what it asked
// for, and nothing here panics or fails a collection.
func applyPriority() (nice, ioprio bool) {
	nice = unix.Setpriority(unix.PRIO_PROCESS, 0, walkNiceness) == nil
	// There is no ioprio_set wrapper in x/sys/unix, so the syscall is made
	// directly: (IOPRIO_WHO_PROCESS, 0 = this thread, class idle shifted
	// into the class field with a priority of 0 in the data field).
	_, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprioClassIdle<<ioprioClassShift)
	return nice, errno == 0
}

const (
	// walkNiceness is how far the walk steps back from everything else on
	// the host. 10 is the conventional "background job" niceness: clearly
	// below interactive and service work, without being the 19 that can
	// starve a walk for minutes on a busy host.
	walkNiceness = 10

	// The ioprio_set(2) constants, which x/sys/unix does not export.
	ioprioWhoProcess = 1 // IOPRIO_WHO_PROCESS: who = 0 then means this thread
	ioprioClassIdle  = 3 // IOPRIO_CLASS_IDLE
	ioprioClassShift = 13
)
