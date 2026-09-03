package main

import (
	"encoding/xml"
	"fmt"
	"sort"
)

type xccdfRule struct {
	StigID   string   `json:"stig_id"`
	GroupID  string   `json:"group_id"`
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	CCIs     []string `json:"ccis"`
	NIST     []string `json:"nist"`
}

type benchmark struct {
	ReleaseInfo string
	Rules       []xccdfRule
}

// parseXCCDF reads the DISA manual XCCDF (XCCDF 1.1). Only identifiers,
// severity and the rule title are kept; description, check-content and
// fixtext are skipped unread (ATTRIBUTION.md).
func parseXCCDF(data []byte) (*benchmark, error) {
	var doc struct {
		PlainText []struct {
			ID   string `xml:"id,attr"`
			Text string `xml:",chardata"`
		} `xml:"plain-text"`
		Groups []struct {
			ID   string `xml:"id,attr"`
			Rule struct {
				ID       string `xml:"id,attr"`
				Severity string `xml:"severity,attr"`
				Version  string `xml:"version"`
				Title    string `xml:"title"`
				Idents   []struct {
					System string `xml:"system,attr"`
					Value  string `xml:",chardata"`
				} `xml:"ident"`
			} `xml:"Rule"`
		} `xml:"Group"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("xccdf: %w", err)
	}
	b := &benchmark{}
	for _, p := range doc.PlainText {
		if p.ID == "release-info" {
			b.ReleaseInfo = p.Text
		}
	}
	for _, g := range doc.Groups {
		r := g.Rule
		if r.Version == "" {
			return nil, fmt.Errorf("xccdf: group %s: rule %s has no <version> (STIG id)", g.ID, r.ID)
		}
		rule := xccdfRule{StigID: r.Version, GroupID: g.ID, RuleID: r.ID, Severity: r.Severity, Title: r.Title, CCIs: []string{}, NIST: []string{}}
		for _, id := range r.Idents {
			if id.System == "http://cyber.mil/cci" {
				rule.CCIs = append(rule.CCIs, id.Value)
			}
		}
		sort.Strings(rule.CCIs)
		b.Rules = append(b.Rules, rule)
	}
	sort.Slice(b.Rules, func(i, j int) bool { return b.Rules[i].StigID < b.Rules[j].StigID })
	return b, nil
}
