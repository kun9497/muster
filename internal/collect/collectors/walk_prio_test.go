//go:build linux

package collectors

import (
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// prioResult is what the locked thread reports back: what applyPriority
// claimed, what the two settings read back as on that same thread, and —
// only when a call failed — the errno it failed with, taken by repeating
// that one call on that same thread, since applyPriority itself keeps only
// the boolean.
type prioResult struct {
	nice, ioprio bool
	niceErr      error
	setIoprioErr unix.Errno

	rawPrio     int
	prioErr     error
	ioprioValue int
	ioprioErr   unix.Errno
}

// TestApplyPriorityOnThisThread runs applyPriority on a thread of its own
// and reads both settings back from that same thread, so the assertion is
// about the effect on the host and not about the two booleans agreeing with
// themselves. The goroutine never unlocks: the runtime retires the thread
// when it returns, which is how the rest of the test binary keeps its own
// scheduling.
//
// It runs under whatever uid the suite runs as, because neither call needs
// privilege — RAISING niceness is always allowed, and IOPRIO_CLASS_IDLE has
// needed no capability since Linux 2.6.25 — so an unprivileged CI runner
// checks A-5's constants too. Only an environment that refuses the call
// outright (a seccomp profile answering EPERM, a container policy answering
// EACCES, a kernel without the syscall) is a skip, and it says so.
func TestApplyPriorityOnThisThread(t *testing.T) {
	ch := make(chan prioResult, 1)
	go func() {
		runtime.LockOSThread()
		var r prioResult
		r.nice, r.ioprio = applyPriority()
		if !r.nice {
			// The same call on the same thread: it fails the same way, and
			// this is the only place the errno can still be had.
			r.niceErr = unix.Setpriority(unix.PRIO_PROCESS, 0, walkNiceness)
		}
		if !r.ioprio {
			_, _, r.setIoprioErr = unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprioClassIdle<<ioprioClassShift)
		}
		// getpriority(2) returns 20 - nice, so a niceness of 10 reads back
		// as 10 here. ioprio_get answers the calling thread's ioprio in the
		// shape ioprio_set was given: the class in the top three bits.
		r.rawPrio, r.prioErr = unix.Getpriority(unix.PRIO_PROCESS, 0)
		v, _, errno := unix.Syscall(unix.SYS_IOPRIO_GET, ioprioWhoProcess, 0, 0)
		r.ioprioValue, r.ioprioErr = int(v), errno
		ch <- r
	}()
	r := <-ch

	if !r.nice {
		skipIfRefused(t, "setpriority", r.niceErr)
		t.Fatalf("applyPriority reported the niceness did not take: %v", r.niceErr)
	}
	if r.prioErr != nil {
		t.Fatalf("getpriority: %v", r.prioErr)
	}
	if want := 20 - walkNiceness; r.rawPrio != want {
		t.Errorf("getpriority returned %d, want %d (niceness %d)", r.rawPrio, want, walkNiceness)
	}

	if !r.ioprio {
		// A zero Errno in an error interface is not nil, so it is unwrapped
		// here rather than inside the helper.
		var err error
		if r.setIoprioErr != 0 {
			err = r.setIoprioErr
		}
		skipIfRefused(t, "ioprio_set", err)
		t.Fatalf("applyPriority reported the I/O class did not take: %v", err)
	}
	if r.ioprioErr != 0 {
		t.Fatalf("ioprio_get: %v", r.ioprioErr)
	}
	if got, want := r.ioprioValue>>ioprioClassShift, ioprioClassIdle; got != want {
		t.Errorf("I/O class is %d, want %d (idle)", got, want)
	}
	if got := r.ioprioValue & (1<<ioprioClassShift - 1); got != 0 {
		t.Errorf("I/O priority within the class is %d, want 0", got)
	}
}

// skipIfRefused turns "this environment forbids the call" into a skip and
// leaves anything else to the caller: a sandbox that will not let a thread
// lower its own priority is a fact about the environment, while a call that
// fails for any other reason is a fact about the code.
func skipIfRefused(t *testing.T, call string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSYS) {
		t.Skipf("%s is refused here (%v); applyPriority reports that rather than failing", call, err)
	}
}

// The main test thread must be left alone: applyPriority is called by the
// walk on a thread it locked for itself, and a helper that quietly reniced
// the whole process would slow every other collector down.
func TestApplyPriorityLeavesThisThreadAlone(t *testing.T) {
	// Lock this goroutine too: getpriority(2) answers for the calling
	// THREAD, so the before and after readings have to come from one.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		t.Skipf("getpriority is unavailable here: %v", err)
	}
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		applyPriority()
		close(done)
	}()
	<-done
	after, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		t.Fatalf("getpriority: %v", err)
	}
	if before != after {
		t.Errorf("this thread's priority changed from %d to %d", before, after)
	}
}
