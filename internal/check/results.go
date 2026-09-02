package check

import "github.com/kun9497/muster/internal/facts"

// Status is a control's outcome (spec §6.5).
type Status string

const (
	PASS          Status = "PASS"
	FAIL          Status = "FAIL"
	WARN          Status = "WARN"
	MANUAL        Status = "MANUAL"
	NotApplicable Status = "NOT_APPLICABLE"
	ERROR         Status = "ERROR"
	WAIVED        Status = "WAIVED"
)

// ReasonCode is the fixed vocabulary CI matches on (spec §7.2).
type ReasonCode string

const (
	PermissionDenied ReasonCode = "permission_denied"
	Timeout          ReasonCode = "timeout"
	Truncated        ReasonCode = "truncated"
	UnsupportedEnv   ReasonCode = "unsupported_env"
	ParseError       ReasonCode = "parse_error"
	MissingFact      ReasonCode = "missing_fact"
	SchemaMismatch   ReasonCode = "schema_mismatch"
	WalkIncomplete   ReasonCode = "walk_incomplete"
	InternalError    ReasonCode = "internal_error"
)

// Evidence is one fact the verdict was decided on (D08).
type Evidence struct {
	Fact   string        `json:"fact"`
	Status facts.Status  `json:"status"`
	Value  any           `json:"value,omitempty"`
	Source *facts.Source `json:"source,omitempty"`
	Side   string        `json:"side,omitempty"` // runtime | persisted | effective, for settings
}

// Observation is one element of a collection judgment (spec §6.4).
type Observation struct {
	Subject  string        `json:"subject"`
	Expected any           `json:"expected,omitempty"`
	Actual   any           `json:"actual,omitempty"`
	Verdict  string        `json:"verdict"` // pass | fail
	Source   *facts.Source `json:"source,omitempty"`
}

// WaiverNote records how a waiver touched a result (spec §6.7).
type WaiverNote struct {
	Applied           bool   `json:"applied"`
	Reason            string `json:"reason,omitempty"`
	Expires           string `json:"expires,omitempty"`
	Subject           string `json:"subject,omitempty"`
	NotAppliedBecause string `json:"not_applied_because,omitempty"`
}

// Result is one control's outcome with everything needed to explain it.
type Result struct {
	ID           string        `json:"id"`
	TitleEn      string        `json:"title_en"`
	TitleKo      string        `json:"title_ko"`
	Category     string        `json:"category"`
	Importance   string        `json:"importance"`
	Automation   string        `json:"automation"`
	Status       Status        `json:"status"`
	ReasonCode   ReasonCode    `json:"reason_code,omitempty"`
	Reason       string        `json:"reason,omitempty"`
	Degraded     string        `json:"degraded,omitempty"`
	Evidence     []Evidence    `json:"evidence,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
	Waiver       *WaiverNote   `json:"waiver,omitempty"`
	Mechanism    int           `json:"mechanism,omitempty"` // 1-based index of the mechanism judged; 0 when checks/custom
}
