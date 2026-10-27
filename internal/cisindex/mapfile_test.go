package cisindex

import (
	"reflect"
	"strings"
	"testing"
)

const sampleMap = `- id: muster.a
  rules: [ra1, ra2]
  vars:
    - { var: var_n, param: max, as: int }
    - { var: var_t, param: timeout, as: { "15_min": 900, "027": ["027", "077"] } }
    - { var: var_w, param: none, reason: "the control judges that a service is enabled" }
- id: muster.c
  rules: []
  recs:
    ubuntu2204: [{ rec: "1.1.3", reason: "the control judges the file" }]
`

const sampleReview = `- { profile: cis-ubuntu2204-l1, id: muster.a, reason: "the control's threshold is weaker" }
- { profile: cis-rhel9-l1, id: muster.a, reason: "the control's threshold is weaker" }
`

func TestDecodeMap(t *testing.T) {
	rows, err := DecodeMap([]byte(sampleMap))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != "muster.a" || len(rows[0].Vars) != 3 || rows[0].Vars[0].As != "int" {
		t.Fatalf("rows %+v", rows)
	}
	tbl, ok := rows[0].Vars[1].As.(map[string]any)
	if !ok || tbl["15_min"] != 900 || !reflect.DeepEqual(tbl["027"], []any{"027", "077"}) {
		t.Fatalf("table %#v", rows[0].Vars[1].As)
	}
	want := map[string][]RecRow{"ubuntu2204": {{Rec: "1.1.3", Reason: "the control judges the file"}}}
	if !reflect.DeepEqual(rows[1].Recs, want) {
		t.Fatalf("recs %+v", rows[1].Recs)
	}
}

func TestDecodeMapIsStrict(t *testing.T) {
	cases := map[string]string{
		"unknown key":         "- id: muster.a\n  rules: [r]\n  title: x\n",
		"unknown var key":     "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: int, note: x }]\n",
		"unsorted":            "- id: muster.b\n  rules: [r]\n- id: muster.a\n  rules: [r]\n",
		"duplicate":           "- id: muster.a\n  rules: [r]\n- id: muster.a\n  rules: [s]\n",
		"no id":               "- rules: [r]\n",
		"none without reason": "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: none }]\n",
		"as beside none":      "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: none, as: int, reason: x }]\n",
		"param without as":    "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p }]\n",
		"reason beside as":    "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: int, reason: x }]\n",
		"as word":             "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: octal }]\n",
		"as list":             "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: [1] }]\n",
		"unquoted int key":    "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: { 14: 14 } }]\n",
		"empty table":         "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: {} }]\n",
		"no param":            "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, as: int }]\n",
		"no var":              "- id: muster.a\n  rules: [r]\n  vars: [{ param: p, as: int }]\n",
		"var twice":           "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: p, as: int }, { var: v, param: q, as: int }]\n",
		"empty none reason":   "- id: muster.a\n  rules: [r]\n  vars: [{ var: v, param: none, reason: \"\" }]\n",
		"empty rec reason":    "- id: muster.a\n  rules: []\n  recs: { ubuntu2204: [{ rec: \"1.1\", reason: \"\" }] }\n",
		"no rec":              "- id: muster.a\n  rules: []\n  recs: { ubuntu2204: [{ reason: x }] }\n",
		"two documents":       "- id: muster.a\n  rules: [r]\n---\n- id: muster.b\n  rules: [r]\n",
		"empty":               "",
		"not a list":          "id: muster.a\n",
	}
	for name, c := range cases {
		if _, err := DecodeMap([]byte(c)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDecodeReview(t *testing.T) {
	rows, err := DecodeReview([]byte(sampleReview))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1] != (ReviewRow{Profile: "cis-rhel9-l1", ID: "muster.a", Reason: "the control's threshold is weaker"}) {
		t.Fatalf("rows %+v", rows)
	}
	if rows, err := DecodeReview([]byte("[]\n")); err != nil || len(rows) != 0 {
		t.Fatalf("empty list: %v %v", rows, err)
	}
}

func TestDecodeReviewIsStrict(t *testing.T) {
	cases := map[string]string{
		"unknown key":   "- { profile: p, id: muster.a, reason: x, note: y }\n",
		"no reason":     "- { profile: p, id: muster.a }\n",
		"empty reason":  "- { profile: p, id: muster.a, reason: \"\" }\n",
		"no profile":    "- { id: muster.a, reason: x }\n",
		"no id":         "- { profile: p, reason: x }\n",
		"duplicate":     "- { profile: p, id: muster.a, reason: x }\n- { profile: p, id: muster.a, reason: y }\n",
		"two documents": "- { profile: p, id: muster.a, reason: x }\n---\n- { profile: q, id: muster.a, reason: x }\n",
		"empty":         "",
	}
	for name, c := range cases {
		if _, err := DecodeReview([]byte(c)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCheckReviewProfiles(t *testing.T) {
	rows, _ := DecodeReview([]byte(sampleReview))
	if err := CheckReviewProfiles(rows, []string{"cis-ubuntu2204-l1", "cis-rhel9-l1"}); err != nil {
		t.Fatal(err)
	}
	err := CheckReviewProfiles(rows, []string{"cis-ubuntu2204-l1"})
	if err == nil || !strings.Contains(err.Error(), "cis-rhel9-l1") {
		t.Fatalf("unknown profile: %v", err)
	}
}

func TestDecodeMapReportsTheFirstBadProductInSortedOrder(t *testing.T) {
	doc := "- id: muster.a\n  rules: [x]\n  recs:\n    zz: [{rec: '', reason: r}]\n    aa: [{rec: '', reason: r}]\n    mm: [{rec: '', reason: r}]\n"
	for i := 0; i < 20; i++ {
		_, err := DecodeMap([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "recs: aa:") {
			t.Fatalf("run %d: error %v does not name product aa", i, err)
		}
	}
}
