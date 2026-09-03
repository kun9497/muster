//go:build linux

package collectors

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// procNetLimit caps each kernel socket table. R64: spec §5 leaves the
// per-file limit to the collector, and 4 MiB holds tens of thousands of
// rows — far more than any host the check side needs to reason about.
const procNetLimit = 4 << 20

// Connection states as /proc/net/{tcp,udp} spells them: TCP LISTEN is 0A,
// and a UDP socket that is bound but not connected is 07.
const (
	tcpListen      = "0A"
	udpUnconnected = "07"
)

// procNetTables are the four kernel socket tables, in report order. R40:
// /proc/net is a symlink to self/net and the read primitive refuses every
// symlink, so the declared and requested form is /proc/self/net/... —
// Access substitutes this process's pid immediately before the read.
// optional marks a table whose absence is not a failure: the v6 tables are
// missing on a host built without IPv6, and a table that is not there holds
// no sockets, so nothing is hidden by skipping it. Only the primary TCP
// table must exist — without it procfs is telling us nothing at all, and
// reporting an empty list would be a PASS on no evidence (R41). An
// unreadable table, as opposed to a missing one, is always an error.
var procNetTables = []struct {
	path, proto string
	optional    bool
}{
	{"/proc/self/net/tcp", "tcp", false},
	{"/proc/self/net/tcp6", "tcp6", true},
	{"/proc/self/net/udp", "udp", true},
	{"/proc/self/net/udp6", "udp6", true},
}

// procNetPaths is the declaration both sockets and services use, so the two
// can never drift apart from the tables actually read.
func procNetPaths() []string {
	out := make([]string, 0, len(procNetTables))
	for _, t := range procNetTables {
		out = append(out, t.path)
	}
	return out
}

var socketsCollector = collect.Collector{
	Name:    "sockets",
	Declare: collect.Declaration{Reads: procNetPaths(), Needs: "none"},
	Run:     runSockets,
}

// socketTables is what one pass over the kernel tables produced.
type socketTables struct {
	list []any
	src  *facts.Source
	// truncated reports that a table hit procNetLimit, so rows are missing
	// and no caller may treat the list as exhaustive.
	truncated bool
}

// listeningSockets parses the four tables into the records
// sockets.listening carries. services calls it too, so neither collector
// depends on the order collectors run in.
//
// A table that is simply absent (no IPv6 on this host) is skipped; any
// other read failure is returned rather than swallowed, because a table we
// could not see might have held the very socket the caller is asking about
// and reporting the rows we did get as the whole answer would turn a blind
// spot into a PASS (R41).
func listeningSockets(a collect.Access) (socketTables, error) {
	t := socketTables{list: []any{}} // R50: never nil, so it serialises as []
	inputs := make([]facts.Source, 0, len(procNetTables))
	for _, tbl := range procNetTables {
		data, meta, err := a.ReadFile(tbl.path, procNetLimit)
		if err != nil {
			if tbl.optional && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return socketTables{}, fmt.Errorf("%s: %w", tbl.path, err)
		}
		t.truncated = t.truncated || meta.Truncated
		inputs = append(inputs, facts.Source{Kind: "proc", Path: tbl.path})
		t.list = append(t.list, parseProcNet(data, tbl.proto)...)
	}
	t.src = &facts.Source{Kind: "derived", Inputs: inputs}
	return t, nil
}

// parseProcNet keeps only the listening rows of one table.
func parseProcNet(data []byte, proto string) []any {
	var out []any
	for i, line := range splitLines(data) {
		if i == 0 {
			continue // the column header
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if strings.HasPrefix(proto, "tcp") {
			if f[3] != tcpListen {
				continue
			}
		} else if f[3] != udpUnconnected {
			continue
		}
		addr, port, loopback, ok := parseProcAddr(f[1])
		if !ok {
			continue
		}
		inode, err := strconv.Atoi(f[9])
		if err != nil {
			inode = -1
		}
		// pid and exe stay out of stage 1: mapping an inode to a process
		// means walking every /proc/<pid>/fd, which is a far wider read
		// than this collector declares.
		out = append(out, map[string]any{
			"proto":    proto,
			"addr":     addr,
			"port":     port,
			"inode":    inode,
			"loopback": loopback,
		})
	}
	return out
}

// parseProcAddr decodes a "<hex address>:<hex port>" column. The kernel
// prints the address as 32-bit words in host byte order, so on every
// platform muster supports (all little-endian) each word's bytes are
// reversed relative to network order.
func parseProcAddr(s string) (addr string, port int, loopback, ok bool) {
	host, portHex, cut := strings.Cut(s, ":")
	if !cut {
		return "", 0, false, false
	}
	p, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, false, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false, false
	}
	ip := make(net.IP, len(raw))
	for w := 0; w+4 <= len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return ip.String(), int(p), ip.IsLoopback(), true
}

func runSockets(_ context.Context, a collect.Access, b *collect.Builder) error {
	t, err := listeningSockets(a)
	if err != nil {
		b.Set("sockets.listening", collect.FromReadError(err, collect.ReadMeta{}))
		return nil
	}
	// R70: the truncation flag rides along, so the check side can tell an
	// exhaustive table from one that hit the read limit.
	b.Set("sockets.listening", collect.OKRead(t.list, t.src, collect.ReadMeta{Truncated: t.truncated}))
	return nil
}
