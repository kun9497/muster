//go:build linux

package collectors

import (
	"context"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	systemctlPath = "/usr/bin/systemctl"
	systemdMarker = "/run/systemd/system"
	inetdConf     = "/etc/inetd.conf"
	xinetdGlob    = "/etc/xinetd.d/*"
)

// showCmd is the single systemctl invocation this collector makes per unit.
// The four properties are one round trip; stage 1 reads LoadState and
// ActiveState from the answer, and asking for UnitFileState and SubState
// here keeps the declared command — the one --list-actions prints and a
// change-control reviewer approves — the same one stage 2 will keep using.
func showCmd(unit string) collect.Command {
	return collect.Command{
		Path: systemctlPath,
		Args: []string{"show", "-p", "LoadState,ActiveState,UnitFileState,SubState", unit},
	}
}

// unitRef is one systemd unit and whether its being loaded proves the
// logical service is installed. R63: inetd and xinetd are asked about so
// that "systemd did not answer at all" can be told apart from "systemd says
// there is no telnet unit", but a loaded super-server does not by itself
// mean telnet is installed — only a telnet unit does, or a telnet entry in
// the super-server's own configuration.
type unitRef struct {
	name          string
	provesInstall bool
}

type portSpec struct {
	proto string // "tcp" or "udp"
	port  int
}

type logicalService struct {
	name       string     // fact segment under services.
	units      []unitRef  // systemd units; provesInstall keeps its established meaning (R223), NOT "canonical for unit_file_state"
	inetdNames []string   // inetd.conf field-0 names / xinetd.d service names (super-server hosting)
	servers    []string   // real server-program basenames to match against the inetd/xinetd server field (R233)
	ports      []portSpec // fixed listening ports for the reachable leaf; empty ⇒ no reachable leaf
}

// services is the logical-service table. Order is the emission order; keep it
// stable (same input, same bytes).
//
// Ruling R223: the ssh and telnet unitRef lists are verbatim from the former
// logicalUnits map (ssh keeps ssh.service / sshd.service / ssh.socket; telnet
// keeps telnet.socket / telnet.service / telnetd.service plus the
// inetd.service / xinetd.service entries with their current provesInstall
// flags per R63). Only the new logical services are appended. provesInstall
// keeps its established meaning (proves-installed vs "systemd did not answer");
// it is NOT "the canonical unit for unit_file_state" (that is R222's
// first-loaded rule). Every genuinely new real unit gets provesInstall: true.
var services = []logicalService{
	// ssh and telnet: verbatim from the former logicalUnits map.
	{name: "ssh", units: []unitRef{{"ssh.service", true}, {"sshd.service", true}, {"ssh.socket", true}}},
	{name: "telnet", units: []unitRef{{"telnet.socket", true}, {"telnet.service", true}, {"telnetd.service", true}, {"inetd.service", false}, {"xinetd.service", false}}, inetdNames: []string{"telnet"}, servers: []string{"telnetd", "in.telnetd"}, ports: []portSpec{{"tcp", 23}}},
	// New logical services (all real units provesInstall: true; R234/R246 give
	// tftp both the RHEL 9 tftp.service and the socket-activated Debian atftpd.socket).
	{name: "finger", units: []unitRef{{"finger.socket", true}, {"fingerd.service", true}}, inetdNames: []string{"finger"}, servers: []string{"in.fingerd"}, ports: []portSpec{{"tcp", 79}}},
	{name: "rservices", units: []unitRef{{"rsh.socket", true}, {"rlogin.socket", true}, {"rexec.socket", true}}, inetdNames: []string{"shell", "login", "exec"}, servers: []string{"in.rshd", "in.rlogind", "in.rexecd"}, ports: []portSpec{{"tcp", 514}, {"tcp", 513}, {"tcp", 512}}},
	{name: "dos_services", units: []unitRef{{"echo.socket", true}, {"discard.socket", true}, {"daytime.socket", true}, {"chargen.socket", true}}, inetdNames: []string{"echo", "discard", "daytime", "chargen"}, ports: []portSpec{{"tcp", 7}, {"udp", 7}, {"tcp", 9}, {"udp", 9}, {"tcp", 13}, {"udp", 13}, {"tcp", 19}, {"udp", 19}}},
	{name: "nfs_server", units: []unitRef{{"nfs-server.service", true}, {"nfs-kernel-server.service", true}}, ports: []portSpec{{"tcp", 2049}, {"udp", 2049}}},
	{name: "automount", units: []unitRef{{"autofs.service", true}}},
	{name: "rpcbind", units: []unitRef{{"rpcbind.service", true}, {"rpcbind.socket", true}}, ports: []portSpec{{"tcp", 111}, {"udp", 111}}},
	{name: "nis", units: []unitRef{{"ypserv.service", true}, {"ypbind.service", true}, {"ypxfrd.service", true}, {"yppasswdd.service", true}}},
	{name: "tftp", units: []unitRef{{"tftp.socket", true}, {"tftp.service", true}, {"tftpd.service", true}, {"tftpd-hpa.service", true}, {"atftpd.socket", true}, {"atftpd.service", true}}, inetdNames: []string{"tftp"}, servers: []string{"in.tftpd", "atftpd"}, ports: []portSpec{{"udp", 69}}},
	{name: "talk", units: []unitRef{{"talk.socket", true}, {"ntalk.socket", true}}, inetdNames: []string{"talk", "ntalk"}, servers: []string{"in.talkd", "in.ntalkd"}, ports: []portSpec{{"udp", 517}, {"udp", 518}}},
	{name: "snmp", units: []unitRef{{"snmpd.service", true}}, ports: []portSpec{{"udp", 161}}},
}

// declaredShowCommands lists every systemctl invocation the collector may
// make, derived from the services table so the declaration can never drift
// from the commands actually run. The flattened unit names are sorted so the
// declaration is deterministic (R48).
func declaredShowCommands() []collect.Command {
	var units []string
	for _, svc := range services {
		for _, u := range svc.units {
			units = append(units, u.name)
		}
	}
	// R227: the shared super-server reader probes the host units once per run;
	// the ones not already named by a service's unitRef list are declared here
	// so the guard licenses those systemctl show invocations.
	units = append(units, superServerExtraHostUnits...)
	slices.Sort(units)
	units = slices.Compact(units)
	out := make([]collect.Command, 0, len(units))
	for _, u := range units {
		out = append(out, showCmd(u))
	}
	return out
}

var servicesCollector = collect.Collector{
	Name: "services",
	Declare: collect.Declaration{
		Reads:    append([]string{systemdMarker, inetdConf, xinetdGlob}, procNetPaths()...),
		Commands: declaredShowCommands(),
		Needs:    "none",
	},
	Run: runServices,
}

// inetdServerField is where the server program sits on an /etc/inetd.conf
// line: service, socket type, protocol, flags, user, server, arguments. The
// shared super-server reader (services_super.go) matches against its basename
// (R233).
const inetdServerField = 5

// showValues parses the "Key=Value" lines systemctl show prints. R235:
// SubState is not parsed — nothing reads it — even though the show command
// still requests it so the declared invocation is unchanged.
func showValues(stdout []byte) (load, active, unitFile string) {
	for _, line := range splitLines(stdout) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			load = v
		case "ActiveState":
			active = v
		case "UnitFileState":
			unitFile = v
		}
	}
	return load, active, unitFile
}

// enabledFromUnitFile reports whether a unit's UnitFileState means "will start
// at boot or on socket activation" (Ruling R228).
//
//	enabled, enabled-runtime → true
//	indirect                 → active (a socket unit that is actually listening)
//	generated                → active (sysv-generator stamps every init.d script
//	                           "generated" whether or not an rcN.d/S* link exists)
//	alias                    → false (e.g. Ubuntu nfs-kernel-server.service reports
//	                           "alias" regardless of the target's enable state; the
//	                           target unit is in the same list and answers for itself)
//	static, disabled, masked, bad, "", not-found → false
func enabledFromUnitFile(state string, active bool) bool {
	switch state {
	case "enabled", "enabled-runtime":
		return true
	case "indirect", "generated":
		return active
	default: // alias, static, disabled, masked, bad, "", not-found
		return false
	}
}

// groupState is what systemd said about one logical service.
type groupState struct {
	// complete is false as soon as ONE queried unit did not answer. The
	// judgement has to be made unit by unit, not over the group as a
	// whole: if ssh.service times out and sshd.service answers not-found,
	// a group-level "something answered" would publish installed=false on
	// evidence that never covered ssh.service — the unit most likely to
	// have been the one that mattered. Any gap therefore means the caller
	// writes firstFailure instead of a value.
	complete  bool
	installed bool
	active    bool
	enabled   bool
	truncated bool
	src       *facts.Source

	// unitFileState is the UnitFileState of the FIRST unit in list order whose
	// LoadState != "not-found" (R222); it is evidence only, never judged. R231:
	// "not-found" (systemd's own LoadState word) when no unit was found — not
	// "absent", which would collide with the envelope-status vocabulary.
	unitFileState    string
	unitFileStateSet bool

	// firstFailure is the FIRST unit that did not answer: the one whose
	// absence from the evidence a reader has to know about. Later failures
	// are usually the same cause repeated.
	firstFailure facts.Envelope
}

// fail records a unit that did not answer, keeping the first one only.
func (g *groupState) fail(e facts.Envelope) {
	if g.complete {
		g.complete, g.firstFailure = false, e
	}
}

// probeUnits asks systemctl about each unit of a logical service in turn.
func probeUnits(ctx context.Context, a collect.Access, units []unitRef) groupState {
	g := groupState{complete: true}
	for _, u := range units {
		cmd := showCmd(u.name)
		out := a.Run(ctx, cmd)
		src := out.Source(cmd)
		switch {
		case out.TimedOut:
			e := collect.TimeoutEnv("systemctl show " + u.name + " timed out")
			e.Source = src
			g.fail(withTruncation(e, out.Truncated))
			continue
		case out.Err != nil, out.ExitCode != 0:
			// services declares Needs: none — systemctl answers for any
			// user — so a failure here is never a privilege problem by
			// virtue of this process's euid (R84); only what systemctl
			// itself said can make it denied.
			g.fail(commandFailure("systemctl show "+u.name, out, src, false))
			continue
		}
		g.truncated = g.truncated || out.Truncated
		if g.src == nil {
			g.src = src
		}
		load, active, unitFile := showValues(out.Stdout)
		unitActive := active == "active"
		// R231: a unit that is present at all (even masked) proves the logical
		// service is installed, provided the unit is one that proves it (R223);
		// the former rule required LoadState == "loaded".
		if load != "not-found" && u.provesInstall && !g.installed {
			g.installed, g.src = true, src
		}
		// R222: unit_file_state is the first present unit's UnitFileState, in
		// list order — evidence only, whatever the enable verdict works out to.
		if load != "not-found" && !g.unitFileStateSet {
			g.unitFileState, g.unitFileStateSet = unitFile, true
		}
		// A socket unit that is listening reports ActiveState=active too,
		// so there is nothing else to look at here.
		if unitActive {
			g.active = true
		}
		// R222: enabled is the OR over EVERY probed unit, not the canonical one
		// — a sibling that is enabled-but-stopped still means the service will
		// come up at boot.
		if enabledFromUnitFile(unitFile, unitActive) {
			g.enabled = true
		}
	}
	return g
}

func runServices(ctx context.Context, a collect.Access, b *collect.Builder) error {
	if _, err := a.Stat(systemdMarker); err != nil {
		// R239: with no systemd, every leaf the table registers degrades to
		// unsupported — the reachable leaf too, even though /proc/net could
		// answer it — so the collect contract stays "complete" on a
		// systemd-less container and no leaf ever reads as a silent PASS.
		reason := "no systemd on this host or inside this container"
		for _, svc := range services {
			b.Set("services."+svc.name+".installed", collect.Unsupported(reason))
			b.Set("services."+svc.name+".active", collect.Unsupported(reason))
			b.Set("services."+svc.name+".unit_file_state", collect.Unsupported(reason))
			b.Set("services."+svc.name+".enabled", collect.Unsupported(reason))
			if len(svc.ports) > 0 {
				b.Set("services."+svc.name+".reachable", collect.Unsupported(reason))
			}
		}
		return nil
	}
	// R232: read the listening-socket table ONCE for the whole sweep — reading
	// it per service would be up to 48 procfs reads and 12 chances to disagree
	// with sockets.listening about the same host.
	t, sockErr := listeningSockets(a)
	// R227: read /etc/inetd.conf and the xinetd.d fragments — and probe the
	// super-server host units — ONCE for the whole sweep, not per service.
	supers := readSuperServers(ctx, a)
	for _, svc := range services {
		g := probeUnits(ctx, a, svc.units)
		setService(b, svc, g, t, sockErr, &supers)
	}
	return nil
}

// setService writes every leaf one logical service registers from the systemd
// verdict, the shared listening-socket table and the shared super-server reader
// (R227/R233): a service with inetdNames/servers folds the once-parsed
// inetd.conf / xinetd entries — host-gated — into its installed/enabled/active.
func setService(b *collect.Builder, svc logicalService, g groupState, t socketTables, sockErr error, supers *superServers) {
	k := "services." + svc.name

	// Super-server contribution (once-read entries + host gate). Only services
	// that can be hosted by inetd/xinetd consult it.
	var superInstalled, superEnabled, superActive bool
	var superEv *facts.Envelope
	if len(svc.inetdNames) > 0 || len(svc.servers) > 0 {
		superInstalled, superEnabled, superActive, _, superEv = supers.match(svc.inetdNames, svc.servers)
	}

	// reachable (fixed-port services only). R41: written false only when the
	// table was actually read; an unseen table is never a PASS.
	var reachable bool
	var reachEnv facts.Envelope
	if len(svc.ports) > 0 {
		switch {
		case sockErr != nil:
			// R82: the same failure the sockets collector would report, filed
			// the same way — a masked procfs is unsupported, never an absent a
			// control's absent_means: pass could read as a PASS.
			reachEnv = socketReadEnvelope(sockErr)
		case t.truncated:
			reachEnv = collect.ErrorEnv("the listening-socket table was truncated at its read limit")
		default:
			reachable = hasNonLoopbackPort(t.list, svc.ports)
			reachEnv = collect.OK(reachable, t.src)
		}
	}

	// installed ← a proving unit found (R231, masked counts) OR a reachable
	// non-loopback port OR a super-server entry (R227). Positive evidence
	// stands on its own whatever the sweep managed (R80).
	installedEnv := g.verdict(g.installed)
	if !g.installed {
		switch {
		case reachable:
			installedEnv = collect.OK(true, t.src)
		case superInstalled:
			installedEnv = collect.OKRead(true, supers.hit, collect.ReadMeta{Truncated: supers.hitTruncated})
		case superEv != nil && g.complete:
			// A super-server file we could not read might have named it, so
			// "not installed" would be a guess. On a complete unit sweep the
			// read error is the honest answer; on an incomplete one verdict
			// below reports the unit failure, which came first.
			installedEnv = *superEv
		}
	}
	b.Set(k+".installed", installedEnv)

	// active ← a live systemd unit OR (for a fixed-port service) a reachable
	// non-loopback port OR a host-active super-server entry (R227). R224: on a
	// complete sweep a judged leaf is ok:false, never absent. But a
	// reachable=false only means "no listener" when the socket table was
	// actually read: when that read errored or was truncated (exactly when the
	// reachable leaf carries socketReadEnvelope / the truncation ErrorEnv), the
	// non-systemd channel could not be checked, so active must surface THAT
	// failure — not a silent ok:false that a (active==false AND enabled==false)
	// control would read as a PASS.
	switch {
	case superActive:
		b.Set(k+".active", collect.OK(true, supers.hitEnabled))
	case len(svc.ports) > 0 && !g.active && reachEnv.Status != facts.StatusOK:
		b.Set(k+".active", reachEnv)
	case superEv != nil && !g.active && !reachable && g.complete:
		// The super-server read error could have hidden a live entry; do not
		// pass a silent ok:false.
		b.Set(k+".active", *superEv)
	default:
		b.Set(k+".active", g.verdict(g.active || reachable))
	}
	switch {
	case superEnabled:
		b.Set(k+".enabled", collect.OK(true, supers.hitEnabled))
	case superEv != nil && !g.enabled && g.complete:
		// Likewise for enabled: an unreadable config might have named an
		// enabled entry, so surface the read error rather than ok:false.
		b.Set(k+".enabled", *superEv)
	default:
		b.Set(k+".enabled", g.verdict(g.enabled))
	}

	// unit_file_state is evidence only (R222); "not-found" when no unit was
	// found (R231). R249: on an incomplete sweep where no unit answered with a
	// file state, the honest evidence is the first probe failure — not an
	// "ok:not-found" that claims systemd said not-found for a sweep it never
	// finished. Otherwise it is the first present unit's state (or "not-found").
	if !g.complete && !g.unitFileStateSet {
		b.Set(k+".unit_file_state", g.firstFailure)
	} else {
		b.Set(k+".unit_file_state", withTruncation(collect.OK(g.unitFileStateOrNotFound(), g.src), g.truncated))
	}

	if len(svc.ports) > 0 {
		b.Set(k+".reachable", reachEnv)
	}
}

// unitFileStateOrNotFound is the first present unit's UnitFileState, or the
// systemd word "not-found" when the sweep found no unit at all (R231).
func (g groupState) unitFileStateOrNotFound() string {
	if g.unitFileStateSet {
		return g.unitFileState
	}
	return "not-found"
}

// verdict turns one proven/not-proven question into an envelope (R80).
//
// Proven true is ok:true whatever else happened during the sweep: a sibling
// unit that timed out cannot make a unit that answered "loaded" unloaded,
// so positive evidence never needs the sweep to have been complete.
//
// Not proven is ok:false only when every queried unit answered or was
// not-found, because "false" is the claim that nothing anywhere was found —
// and the unit that never answered is exactly the one that might have said
// yes. Otherwise the first failing unit's envelope is the answer.
func (g groupState) verdict(proven bool) facts.Envelope {
	switch {
	case proven:
		return withTruncation(collect.OK(true, g.src), g.truncated)
	case !g.complete:
		return g.firstFailure
	default:
		return withTruncation(collect.OK(false, g.src), g.truncated)
	}
}

// hasNonLoopbackPort reports whether any listening socket in the
// sockets.listening list matches one of the given proto+port pairs on a
// non-loopback address.
func hasNonLoopbackPort(list []any, ports []portSpec) bool {
	for _, ps := range ports {
		for _, row := range list {
			m, ok := row.(map[string]any)
			if !ok {
				continue
			}
			// R221: compare proto by PREFIX, not equality — sockets.listening
			// rows carry "tcp"/"tcp6"/"udp"/"udp6" (sockets.go), so a ::-bound
			// daemon (snmpd/rpcbind/nfsd/fingerd) appears only in tcp6/udp6.
			if strings.HasPrefix(asString(m["proto"]), ps.proto) && asInt(m["port"]) == ps.port && !asBool(m["loopback"]) {
				return true
			}
		}
	}
	return false
}

// asString, asInt and asBool read the fields of a sockets.listening record
// (sockets.go parseProcNet), tolerating a missing or wrongly-typed field
// rather than panicking on a type assertion. R221: port is a Go int here.
func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int {
	n, _ := v.(int)
	return n
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}
