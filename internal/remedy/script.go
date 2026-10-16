package remedy

import (
	"fmt"
	"strings"

	"github.com/kun9497/muster/internal/report"
)

// rootCheckLine is the prologue's root check; the Linux tests drop it.
const rootCheckLine = `[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }`

// backupOwnerLine refuses a MUSTER_BACKUP that root does not own or that
// group or other can write (Z-28); the Linux tests drop it unless they run as
// root, since a non-root user's temp dir is never root-owned.
const backupOwnerLine = `[ -n "$(find "$MUSTER_BACKUP" -maxdepth 0 -type d -user 0 ! -perm /022 2>/dev/null)" ] || { printf 'muster-fix: MUSTER_BACKUP must be a root-owned directory that only root can write\n' >&2; exit 2; }`

// prologueHead opens every script; log() comes first so the guard can use it.
const prologueHead = `set -u
umask 077
log() { printf 'muster-fix: %s\n' "$*"; }`

// MachineIDHashHelper computes the host identity the snapshot carries
// (collectors.MachineIDHash): the sha256 of a 32-lowercase-hex machine id,
// nothing for anything else. Its errors go nowhere: the guard's refusal is
// the only line a failure prints (3D-2b §2).
const MachineIDHashHelper = `muster_machine_id_hash() {
  id=$( { tr -d '[:space:]' < "$1"; } 2>/dev/null ) || id=
  case "$id" in *[!0-9a-f]*|'') return 0;; esac
  [ "${#id}" -eq 32 ] || return 0
  { printf '%s' "$id" | sha256sum | cut -d' ' -f1; } 2>/dev/null
}`

const guardOff = "# host guard: off (the snapshot has no machine id)"

const guardBody = `here=$(muster_machine_id_hash /etc/machine-id)
if [ "$here" != "$MUSTER_SNAPSHOT_HOST" ]; then
  if [ "${MUSTER_ANY_HOST:-}" = 1 ]; then
    log "warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1"
  else
    printf 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n' >&2
    exit 2
  fi
fi`

// prologueBackup makes and checks MUSTER_BACKUP; each block keeps its records
// under $MUSTER_BACKUP/blocks/<fn> (3D-2c E-1).
const prologueBackup = `MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
case "$MUSTER_BACKUP" in
  /|//*|*/.|*/..|*/./*|*/../*) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
  /?*) ;;
  *) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
esac
mkdir -p "$MUSTER_BACKUP" || exit 2
` + backupOwnerLine

// backupHelpers copy a block's declared paths under $MB/files and mark the
// absent ones under $MB/absent (3D-2c E-2); restore removes a path that was
// absent and copies back one that was not. They keep their status in brc,
// never the block's rc (T-6).
const backupHelpers = `backup() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      if [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
      rm -f "$MB/absent$p"
      mkdir -p "$MB/files$(dirname "$p")" && cp -a "$p" "$MB/files$p" || return 1
    else
      if [ -e "$MB/absent$p" ] || [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then continue; fi
      mkdir -p "$MB/absent$(dirname "$p")" && : > "$MB/absent$p" || return 1
    fi
  done
}
restore() {
  brc=0
  for p in "$@"; do
    if [ -e "$MB/absent$p" ]; then
      if [ -d "$p" ] && [ ! -L "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
      rm -f "$p" || { log "restore: $p failed"; brc=1; }
      continue
    fi
    { [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; brc=1; continue; }; fi
    cp -a "$MB/files$p" "$p" || { log "restore: $p failed"; brc=1; }
  done
  return $brc
}`

// unitHelpers record a block's declared units before its body runs and put
// them back on a failure path, in seven passes (3D-2b §3).
const unitHelpers = `save_units() {
  mkdir -p "$MB/units" || return 1
  for u in "$@"; do
    f="$MB/units/$u"
    if [ -f "$f" ] && ! grep -qx 'absent absent' "$f"; then log "$u: unit state exists, keeping the first"; continue; fi
    if systemctl cat -- "$u" >/dev/null 2>&1; then
      ue=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
      ua=$(systemctl is-active -- "$u" 2>/dev/null) || :
      printf '%s %s\n' "${ue:-unknown}" "${ua:-unknown}" > "$f" || return 1
      : > "$f.deps" || return 1
      for d in $(systemctl show -p RequiredBy -p BoundBy -p ConsistsOf --value -- "$u" 2>/dev/null); do
        if systemctl is-active --quiet -- "$d"; then printf '%s\n' "$d" >> "$f.deps" || return 1; fi
      done
    else
      printf 'absent absent\n' > "$f" || return 1
    fi
  done
}
restore_units() {
  urc=0
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    [ "$ue" = absent ] || systemctl --quiet unmask -- "$u" || urc=1
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in
      enabled) systemctl --quiet enable -- "$u" || urc=1;;
      enabled-runtime) systemctl --quiet enable --runtime -- "$u" || urc=1;;
      linked|linked-runtime) log "$u: was $ue; the link is not restored"; urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in
      disabled) now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
        case "$now" in
          enabled) systemctl --quiet disable -- "$u" || urc=1;;
          enabled-runtime) systemctl --quiet disable --runtime -- "$u" || urc=1;;
        esac;;
    esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in
      masked) systemctl --quiet mask -- "$u" || urc=1;;
      masked-runtime) systemctl --quiet mask --runtime -- "$u" || urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in masked|masked-runtime) continue;; esac
    case "$ua" in active|activating|reloading) systemctl --quiet start -- "$u" || urc=1;; esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u.deps" ] || continue
    while read -r d; do
      systemctl is-active --quiet -- "$d" || systemctl --quiet start -- "$d" || urc=1
    done < "$MB/units/$u.deps"
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    [ "$ue" = absent ] && continue
    now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
    [ "${now:-unknown}" = "$ue" ] || { log "$u: enablement not restored (was $ue, now ${now:-unknown})"; urc=1; }
  done
  return $urc
}`

// stateHelpers record and restore the three state kinds (3D-2c E-3): a
// path's owner, group, mode and type; a sysctl key's runtime value; a
// module's load state. Each keeps the first record per block; each restore
// returns 1 when anything was left as is.
const stateHelpers = `modes_paths() { # one path per line for one entry
  case "$1" in
    */\*/\*) find "${1%/\*/\*}" -mindepth 2 -maxdepth 2 ! -type l 2>/dev/null;;
    */\*) find "${1%/\*}" -mindepth 1 -maxdepth 1 ! -type l 2>/dev/null;;
    *) if [ -e "$1" ] && [ ! -L "$1" ]; then printf '%s\n' "$1"; fi;;
  esac
  return 0
}
modes_type() { if [ -f "$1" ]; then echo f; elif [ -d "$1" ]; then echo d; else echo o; fi; }
save_modes() {
  [ -f "$MB/modes.list" ] || : > "$MB/modes.list" || return 1
  for spec in "$@"; do
    modes_paths "$spec" | while IFS= read -r p; do
      P="$p" awk '{ q=$0; sub(/^[^ ]+ [^ ]+ [^ ]+ [^ ]+ /, "", q); if (q == ENVIRON["P"]) f=1 } END { exit !f }' "$MB/modes.list" && continue
      if s=$(stat -c '%u %g %a' -- "$p" 2>/dev/null); then
        printf '%s %s %s\n' "$s" "$(modes_type "$p")" "$p" >> "$MB/modes.list" || exit 1
      elif [ -e "$p" ]; then
        exit 1
      else
        log "save_modes: $p vanished, not recorded"
      fi
    done || return 1
  done
}
restore_modes() {
  mrc=0
  while read -r uid gid mode t p; do
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then continue; fi
    if [ -L "$p" ] || [ "$(modes_type "$p")" != "$t" ]; then log "restore_modes: $p changed type, left as is"; mrc=1; continue; fi
    cur=$(stat -c '%u %g %a' -- "$p" 2>/dev/null) || cur=
    [ "$cur" = "$uid $gid $mode" ] && continue
    modes_trusted "$p" "$uid" || { log "restore_modes: $p is under a directory others can write, left as is"; mrc=1; continue; }
    if [ "${cur% *}" != "$uid $gid" ]; then chown -h -- "$uid:$gid" "$p" || { mrc=1; continue; }; fi # a chown drops security.capability
    chmod -- "$mode" "$p" || mrc=1
  done < "$MB/modes.list"
  return $mrc
}
modes_trusted() { # modes_trusted <path> <recorded uid>: no one but root can swap <path> (S-24)
  d=${1%/*}
  if [ "$2" != 0 ] && [ -n "$(find "${d:-/}" -maxdepth 0 -perm /022 2>/dev/null)" ]; then return 1; fi
  while :; do
    [ -n "$(find "${d:-/}" -maxdepth 0 -user 0 ! -perm -002 2>/dev/null)" ] || return 1
    [ -n "$d" ] || return 0
    d=${d%/*}
  done
}
save_sysctl() {
  [ -f "$MB/sysctl.list" ] || : > "$MB/sysctl.list" || return 1
  for k in "$@"; do
    awk -v k="$k" '$1 == k { f=1 } END { exit !f }' "$MB/sysctl.list" && continue
    v=$(sysctl -n -- "$k" 2>/dev/null) || v=absent
    printf '%s %s\n' "$k" "$v" >> "$MB/sysctl.list" || return 1
  done
}
restore_sysctl() {
  src=0
  for k in "$@"; do
    v=$(awk -v k="$k" '$1 == k { $1=""; sub(/^ /, ""); print; exit }' "$MB/sysctl.list")
    case "$v" in ''|absent) continue;; esac
    sysctl -q -w -- "$k=$v" || src=1
  done
  return $src
}
save_modules() {
  [ -f "$MB/modules.list" ] || : > "$MB/modules.list" || return 1
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    awk -v m="$n" '$1 == m { f=1 } END { exit !f }' "$MB/modules.list" && continue
    if grep -q "^$n " /proc/modules; then s=loaded; else s=not-loaded; fi
    printf '%s %s\n' "$n" "$s" >> "$MB/modules.list" || return 1
  done
}
restore_modules() {
  orc=0
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    [ "$(awk -v m="$n" '$1 == m { print $2; exit }' "$MB/modules.list")" = loaded ] || continue
    modprobe --ignore-install -- "$n" || orc=1
  done
  return $orc
}`

// prologue is the script's fixed part for this plan (3D-2b §2 order): the
// guard and its helper only when the snapshot carried a well-formed hash,
// re-checked here so a hand-built plan cannot put another value in the script.
func prologue(p *Plan) string {
	var b strings.Builder
	b.WriteString(prologueHead + "\n")
	if p.Fix.HostGuard == "on" && machineHashRe.MatchString(p.Fix.MachineIDHash) {
		b.WriteString(MachineIDHashHelper + "\n" + rootCheckLine + "\n")
		b.WriteString("MUSTER_SNAPSHOT_HOST=" + p.Fix.MachineIDHash + "\n" + guardBody + "\n")
	} else {
		b.WriteString(rootCheckLine + "\n" + guardOff + "\n")
	}
	b.WriteString(prologueBackup + "\n" + backupHelpers + "\n" + unitHelpers + "\n" + stateHelpers + "\nfailed=0\n")
	return b.String()
}

const epilogue = `
if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
`

var textOnlyPhrase = map[string]string{
	"no_script":     "no script declared",
	"absent":        "the finding is an absent file",
	"params_tuned":  "params tuned, see muster check --format json: check.param_sources",
	"params_unsafe": "a parameter value cannot be carried safely; see muster check --format json: check.params",
}

// Script renders p as the POSIX sh review script (spec §5): a fixed
// template, one independent block per item in plan order. Snapshot- and
// control-derived text lands only in '#' comment lines; commands are the
// template, the declared bodies, the control id, the declared backup, units,
// modes, sysctl and modules names (each re-checked by recheck) and the
// P_<name>='<value>' lines of the parameter values controls.ScriptParamValue
// admits. muster never runs it.
func Script(p *Plan) []byte {
	var b strings.Builder
	s := p.Summary
	b.WriteString("#!/bin/sh\n# shellcheck disable=SC2181\n# muster fix --dry-run: review before running. muster never runs this file.\n") // Z-20
	fmt.Fprintf(&b, "# snapshot: host %s, collected %s; controls %s %s\n",
		report.Escape(p.Run.Host.Hostname), report.Escape(p.Run.CollectedAt), report.Escape(p.Fix.ControlsVersion), report.Escape(p.Fix.ControlsDigest))
	fmt.Fprintf(&b, "# profile %s (%s); max-risk %s\n", report.Escape(p.Fix.Profile.Name), report.Escape(p.Fix.Profile.Digest), p.Fix.MaxRisk)
	fmt.Fprintf(&b, "# planned %d (script %d, text only %d); above max-risk %d; not planned: error %d, manual %d, warn_degraded %d\n",
		s.Planned, s.WithScript, s.TextOnly, s.AboveMaxRisk, s.NotPlanned.Error, s.NotPlanned.Manual, s.NotPlanned.WarnDegraded)
	b.WriteString(prologue(p))
	if len(p.Items) == 0 {
		b.WriteString("\n# nothing to fix\n")
	}
	for i, it := range p.Items {
		b.WriteString("\n")
		for _, l := range block(i+1, len(p.Items), it, p.Fix.MaxRisk) {
			b.WriteString(l + "\n")
		}
	}
	b.WriteString(epilogue)
	return []byte(b.String())
}

func indent(body, pfx string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if l == "" {
			out = append(out, "") // no trailing whitespace; block() comments it as "#" above the cap
			continue
		}
		out = append(out, pfx+l)
	}
	return out
}

// failurePath is the way back (3D-2c §3): the declared rollback in its own
// subshell, then each record kind's restore in a fixed order — units, modes,
// files and absent markers, sysctl values (after the file that would persist
// the script's value is gone), modules (after their install line is gone or
// put back).
func failurePath(it Item, pfx string) []string {
	var out []string
	if strings.TrimSpace(it.RollbackBody) != "" {
		out = append(out, pfx+"( set -e")
		out = append(out, indent(it.RollbackBody, pfx+"  ")...)
		out = append(out, pfx+"); rrc=$?",
			fmt.Sprintf(`%s[ "$rrc" -eq 0 ] || log "%s: rollback failed (rc $rrc)"`, pfx, it.ID))
	}
	incomplete := ` || log "` + it.ID + `: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`
	for _, rs := range []struct {
		cmd  string
		args []string
		bare bool
	}{{"restore_units", it.Units, false}, {"restore_modes", it.Modes, true}, {"restore", it.Backup, false}, {"restore_sysctl", it.Sysctl, false}, {"restore_modules", it.Modules, false}} {
		switch {
		case len(rs.args) == 0:
		case rs.bare:
			out = append(out, pfx+rs.cmd+incomplete)
		default:
			out = append(out, pfx+rs.cmd+" "+strings.Join(rs.args, " ")+incomplete)
		}
	}
	return out
}

// block renders one item. The function is called as a bare line and its
// status read on the next: a call that is an operand of ||, &&, if or !
// would switch set -e off inside every subshell it runs (spec §5).
func block(n, total int, it Item, maxRisk string) []string {
	header := fmt.Sprintf("# ---- %d/%d %s [risk %s] [%s, %s]", n, total, report.EscapeNoCut(it.ID), it.Risk, it.Status, it.Severity)
	if !it.Planned {
		header += fmt.Sprintf(" -- above max-risk %s, NOT RUN", maxRisk)
	}
	lines := []string{}
	if it.Risk == "lockout_risk" {
		lines = append(lines, "# keep a second session open; a lockout here needs console access")
	}
	lines = append(lines,
		"# why: "+report.Escape(it.Reason),
		"# do:  "+report.EscapeNoCut(it.TextEn),
		"# ko:  "+report.EscapeNoCut(it.TextKo))
	if !it.Script {
		lines = append(lines, "# text only: "+textOnlyPhrase[it.TextOnlyReason])
	} else {
		fn := "fix_" + strings.ReplaceAll(it.ID, ".", "_")
		lines = append(lines, fn+"() {")
		for _, pv := range it.ScriptParams {
			lines = append(lines, "  P_"+pv.Name+"='"+pv.Value+"'")
		}
		stop := ` || { log "` + it.ID + `: backup failed, nothing changed"; return 1; }`
		lines = append(lines, `  MB="$MUSTER_BACKUP/blocks/`+fn+`"; mkdir -p "$MB"`+stop)
		quoted := make([]string, len(it.Modes))
		for i, e := range it.Modes {
			quoted[i] = "'" + e + "'"
		}
		for _, rec := range []struct {
			cmd  string
			args []string
		}{{"backup", it.Backup}, {"save_units", it.Units}, {"save_modes", quoted}, {"save_sysctl", it.Sysctl}, {"save_modules", it.Modules}} {
			if len(rec.args) > 0 {
				lines = append(lines, "  "+rec.cmd+" "+strings.Join(rec.args, " ")+stop)
			}
		}
		lines = append(lines, "  ( set -e")
		if len(it.Units) > 0 {
			lines = append(lines, "    UNITS='"+strings.Join(it.Units, " ")+"'")
		}
		lines = append(lines, indent(it.ScriptBody, "    ")...)
		lines = append(lines, "  ); rc=$?", `  if [ "$rc" -ne 0 ]; then`,
			fmt.Sprintf(`    log "%s: script failed (rc $rc), rolling back"`, it.ID))
		lines = append(lines, failurePath(it, "    ")...)
		lines = append(lines, "    return 1", "  fi")
		if it.Validate {
			lines = append(lines, "  # validate", "  ( set -e", "    "+it.ValidateCmd, "  ); rc=$?", `  if [ "$rc" -ne 0 ]; then`,
				fmt.Sprintf(`    log "%s: validate failed, rolling back"`, it.ID))
			lines = append(lines, failurePath(it, "    ")...)
			lines = append(lines, "    return 1", "  fi")
		}
		lines = append(lines, fmt.Sprintf(`  log "%s: done"`, it.ID), "}", fn, `[ "$?" -eq 0 ] || failed=$((failed+1))`)
	}
	out := []string{header}
	for _, l := range lines {
		switch {
		case it.Planned || strings.HasPrefix(l, "#"):
			out = append(out, l)
		case l == "":
			out = append(out, "#")
		default:
			out = append(out, "# "+l)
		}
	}
	return out
}
