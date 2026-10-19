package remedy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/report"
)

// The remedy tests build their own rows and control set (Z-10): report's
// test helpers are package-private.

// row builds one report row with the fields the planner reads.
func row(id, status, reason, degraded, severity string) report.Row {
	return report.Row{
		Result: check.Result{
			ID: id, TitleEn: id + " en", TitleKo: id + " ko", Category: "account", Importance: "상",
			Automation: "auto", Status: check.Status(status), Reason: reason, Degraded: degraded,
		},
		Severity: severity, SeveritySource: "importance",
	}
}

const controlHead = `title_en: T
title_ko: 제목
description_en: d
description_ko: 설명
category: account
importance: 상
references:
  kisa: { "2026": ["U-01"] }
requires_facts: ">=1"
absent_means: not_applicable
checks:
  - { fact: sshd.options.permit_root_login, on: effective, op: in, expected: ["no"] }
`

// testControls are the shapes the planner distinguishes.
var testControls = map[string]string{
	"muster.test.a_none": `automation: auto
remediation:
  text_en: fix a
  text_ko: 조치 a
  risk: none
  idempotent: true
  script: chmod 644 /etc/hosts
  backup: [/etc/hosts]
`,
	"muster.test.b_restart": `automation: auto
remediation:
  text_en: "fix b <a & b>"
  text_ko: 조치 b
  risk: restart_service
  idempotent: true
  script: systemctl restart foo
  rollback: systemctl restart foo
`,
	"muster.test.c_lockout": `automation: auto
remediation:
  text_en: fix c
  text_ko: 조치 c
  risk: lockout_risk
  idempotent: true
  script: sed -i s/a/b/ /etc/ssh/sshd_config
  rollback: systemctl reload ssh
  backup: [/etc/ssh/sshd_config]
  validate: |
    sshd -t
`,
	"muster.test.d_reboot": `automation: auto
remediation:
  text_en: fix d
  text_ko: 조치 d
  risk: reboot_required
  idempotent: true
`,
	"muster.test.e_param": `automation: auto
params:
  mode: { type: string, default: "644", description: d }
remediation:
  text_en: fix e
  text_ko: 조치 e
  risk: none
  idempotent: true
  script: chmod 644 /etc/group
  backup: [/etc/group]
`,
	"muster.test.g_units": `automation: auto
remediation:
  text_en: t
  text_ko: 조치
  risk: restart_service
  idempotent: true
  units: [g.socket, g.service]
  script: |
    for u in $UNITS; do systemctl --quiet disable --now "$u"; done
  validate: "! systemctl is-active --quiet g.service"
`,
	"muster.test.h_params": `automation: auto
params:
  limit: { type: int, default: 5, description: d }
  names: { type: list<string>, default: ["a", "b"], description: d }
remediation:
  text_en: fix h
  text_ko: 조치 h
  risk: none
  idempotent: true
  script_params: [names, limit]
  script: |
    for n in $P_names; do printf '%s %s\n' "$n" "$P_limit" >> /etc/h.conf; done
  backup: [/etc/h.conf]
  validate: '[ "$P_limit" -ge 1 ]'
`,
	"muster.test.i_state": `automation: auto
remediation:
  text_en: fix i
  text_ko: 조치 i
  risk: none
  idempotent: true
  modes: ["/etc/i.d/*", /etc/i.conf]
  sysctl: [kernel.i_key]
  modules: [i-mod]
  script: chmod o-w /etc/i.conf
  validate: "true"
`,
	"muster.test.j_absent": `automation: auto
remediation:
  text_en: fix j
  text_ko: 조치 j
  risk: none
  idempotent: true
  script_on_absent: true
  script: printf 'J 1\n' >> /etc/j.conf
  backup: [/etc/j.conf]
  validate: grep -q '^J 1$' /etc/j.conf
`,
	"muster.test.k_both": `automation: auto
remediation:
  text_en: fix k
  text_ko: 조치 k
  risk: none
  idempotent: true
  sysctl: [kernel.k_key]
  backup: [/etc/k.conf]
  script: printf 'kernel.k_key = 1\n' > /etc/k.conf
  validate: "true"
`,
	"muster.test.f_partial": `automation: partial
remediation:
  text_en: fix f
  text_ko: 조치 f
  risk: none
  idempotent: true
`,
}

func testSet(t *testing.T) *controls.Set {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("test+1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for id, body := range testControls {
		data := "id: " + id + "\n" + controlHead + body
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := controls.LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("load test controls: %v", err)
	}
	return set
}

func testReport(rows ...report.Row) *report.Report {
	return &report.Report{SchemaVersion: report.ReportSchemaVersion, Results: rows}
}
