//go:build linux

package collectors

import (
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// prioResult is what the locked thread reports back.
type prioResult struct {
	nice, ioprio bool
	rawPrio      int
	prioErr      error
	ioprioClass  int
	ioprioErr    unix.Errno
}

// TestApplyPriorityOnThisThread runs applyPriority on a thread of its own
// and reads both settings back from that same thread, so the assertion is
// about the effect on the host and not about the two booleans agreeing with
// themselves. The goroutine never unlocks: the runtime retires the thread
// when it returns, which is how the rest of the test binary keeps its own
// scheduling.
func TestApplyPriorityOnThisThread(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skipf("applyPriority is asserted as the collector runs it, as uid 0; this process is uid %d", os.Getuid())
	}
	ch := make(chan prioResult, 1)
	go func() {
		runtime.LockOSThread()
		var r prioResult
		r.nice, r.ioprio = applyPriority()
		// getpriority(2) returns 20 - nice, so a niceness of 10 reads back
		// as 10 here. ioprio_get answers the calling thread's class in the
		// top three bits of the value ioprio_set was given.
		r.rawPrio, r.prioErr = unix.Getpriority(unix.PRIO_PROCESS, 0)
		v, _, errno := unix.Syscall(unix.SYS_IOPRIO_GET, 1, 0, 0)
		r.ioprioClass, r.ioprioErr = int(v)>>13, errno
		ch <- r
	}()
	r := <-ch

	if !r.nice || !r.ioprio {
		t.Fatalf("applyPriority() = (%v, %v), want both true as uid 0", r.nice, r.ioprio)
	}
	if r.prioErr != nil {
		t.Fatalf("Getpriority: %v", r.prioErr)
	}
	if want := 20 - 10; r.rawPrio != want {
		t.Errorf("getpriority returned %d, want %d (niceness 10)", r.rawPrio, want)
	}
	if r.ioprioErr != 0 {
		t.Fatalf("ioprio_get: %v", r.ioprioErr)
	}
	if want := 3; r.ioprioClass != want {
		t.Errorf("I/O class is %d, want %d (idle)", r.ioprioClass, want)
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
