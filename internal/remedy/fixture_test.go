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

// testControls are the six shapes the planner distinguishes.
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
  text_en: fix b
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
