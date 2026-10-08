package remedy

import (
	"fmt"
	"strings"

	"github.com/kun9497/muster/internal/report"
)

// rootCheckLine is the prologue's root check; the Linux tests drop it.
const rootCheckLine = `[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }`

const prologue = `set -u
umask 077
` + rootCheckLine + `
MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
case "$MUSTER_BACKUP" in
  /|//*|*/.|*/..|*/./*|*/../*) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
  /?*) ;;
  *) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
esac
mkdir -p "$MUSTER_BACKUP" || exit 2
log() { printf 'muster-fix: %s\n' "$*"; }
backup() {
  for p in "$@"; do
    { [ -e "$p" ] || [ -L "$p" ]; } || continue
    if [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
    mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p" || return 1
  done
}
restore() {
  rc=0
  for p in "$@"; do
    { [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; rc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; rc=1; continue; }; fi
    cp -a "$MUSTER_BACKUP$p" "$p" || { log "restore: $p failed"; rc=1; }
  done
  return $rc
}
failed=0
`

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
	"no_script":    "no script declared",
	"absent":       "the finding is an absent file",
	"params_tuned": "params tuned, see muster check --format json: check.param_sources",
}

// Script renders p as the POSIX sh review script (spec §5): a fixed
// template, one independent block per item in plan order. Snapshot- and
// control-derived text lands only in '#' comment lines; commands are the
// template, the declared bodies, the control id and declared backup paths.
// muster never runs it.
func Script(p *Plan) []byte {
	var b strings.Builder
	s := p.Summary
	b.WriteString("#!/bin/sh\n# shellcheck disable=SC2181\n# muster fix --dry-run: review before running. muster never runs this file.\n") // Z-20
	fmt.Fprintf(&b, "# snapshot: host %s, collected %s; controls %s %s\n",
		report.Escape(p.Run.Host.Hostname), report.Escape(p.Run.CollectedAt), report.Escape(p.Fix.ControlsVersion), report.Escape(p.Fix.ControlsDigest))
	fmt.Fprintf(&b, "# profile %s (%s); max-risk %s\n", report.Escape(p.Fix.Profile.Name), report.Escape(p.Fix.Profile.Digest), p.Fix.MaxRisk)
	fmt.Fprintf(&b, "# planned %d (script %d, text only %d); above max-risk %d; not planned: error %d, manual %d, warn_degraded %d\n",
		s.Planned, s.WithScript, s.TextOnly, s.AboveMaxRisk, s.NotPlanned.Error, s.NotPlanned.Manual, s.NotPlanned.WarnDegraded)
	b.WriteString(prologue)
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

// failurePath is the way back: the declared rollback in its own subshell,
// then restore of the declared backups ("both" runs both, in that order).
func failurePath(it Item, pfx string) []string {
	var out []string
	if strings.TrimSpace(it.RollbackBody) != "" {
		out = append(out, pfx+"( set -e")
		out = append(out, indent(it.RollbackBody, pfx+"  ")...)
		out = append(out, pfx+"); rrc=$?",
			fmt.Sprintf(`%s[ "$rrc" -eq 0 ] || log "%s: rollback failed (rc $rrc)"`, pfx, it.ID))
	}
	if len(it.Backup) > 0 {
		out = append(out, fmt.Sprintf(`%srestore %s || log "%s: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`, pfx, strings.Join(it.Backup, " "), it.ID))
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
		if len(it.Backup) > 0 {
			lines = append(lines, fmt.Sprintf(`  backup %s || { log "%s: backup failed, nothing changed"; return 1; }`, strings.Join(it.Backup, " "), it.ID))
		}
		lines = append(lines, "  ( set -e")
		lines = append(lines, indent(it.ScriptBody, "    ")...)
		lines = append(lines, "  ); rc=$?", `  if [ "$rc" -ne 0 ]; then`,
			fmt.Sprintf(`    log "%s: script failed (rc $rc), rolling back"`, it.ID))
		lines = append(lines, failurePath(it, "    ")...)
		lines = append(lines, "    return 1", "  fi")
		if it.Validate {
			lines = append(lines, "  ( set -e", "    "+it.ValidateCmd, "  ); rc=$?", `  if [ "$rc" -ne 0 ]; then`,
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
