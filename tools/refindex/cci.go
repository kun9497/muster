package main

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
)

type cciList struct {
	Version string
	NIST    map[string][]string // CCI id → normalised NIST 800-53 control ids
}

var nistRe = regexp.MustCompile(`^([A-Z]{2}-\d+)(?:\s*\((\d+)\))?`)

// nistID reduces a CCI reference index ("AC-6 (10)", "CM-6 b", "AC-1 a 1")
// to a control or enhancement id; "" when it is not one.
func nistID(index string) string {
	m := nistRe.FindStringSubmatch(index)
	if m == nil {
		return ""
	}
	if m[2] != "" {
		return m[1] + "(" + m[2] + ")"
	}
	return m[1]
}

// parseCCI maps every CCI to NIST 800-53 ids, preferring the Revision 5
// references, then Revision 4, then the unversioned title.
func parseCCI(data []byte) (*cciList, error) {
	var doc struct {
		Version string `xml:"metadata>version"`
		Items   []struct {
			ID   string `xml:"id,attr"`
			Refs []struct {
				Title string `xml:"title,attr"`
				Index string `xml:"index,attr"`
			} `xml:"references>reference"`
		} `xml:"cci_items>cci_item"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("cci: %w", err)
	}
	out := &cciList{Version: doc.Version, NIST: map[string][]string{}}
	for _, it := range doc.Items {
		best := -1
		var ids map[string]bool
		for _, r := range it.Refs {
			rank := map[string]int{"NIST SP 800-53 Revision 5": 3, "NIST SP 800-53 Revision 4": 2, "NIST SP 800-53": 1}[r.Title]
			if rank == 0 || rank < best {
				continue
			}
			if rank > best {
				best, ids = rank, map[string]bool{}
			}
			if id := nistID(r.Index); id != "" {
				ids[id] = true
			}
		}
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		sort.Strings(list)
		out.NIST[it.ID] = list
	}
	return out, nil
}
