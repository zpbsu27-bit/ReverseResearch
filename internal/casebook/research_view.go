package casebook

import (
	"encoding/json"
	"errors"
	"reverseresearch/internal/recordio"
)

// ResearchView is a disposable projection of the canonical Case. It does not
// create a graph database, perform a function-name join or accept completion.
type ResearchViewOptions struct {
	FindingID      string `json:"finding_id,omitempty"`
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}
type ResearchLink struct {
	Relation string `json:"relation"`
	TargetID string `json:"target_id"`
}
type ResearchItem struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind"`
	Label        string         `json:"label"`
	Details      string         `json:"details,omitempty"`
	Status       string         `json:"status,omitempty"`
	Strength     string         `json:"strength,omitempty"`
	Location     string         `json:"location,omitempty"`
	SourceSHA256 string         `json:"source_sha256,omitempty"`
	Links        []ResearchLink `json:"links"`
}
type ResearchProgress struct {
	WorkItems          int `json:"workitems"`
	Done               int `json:"done"`
	Cancelled          int `json:"cancelled"`
	Blocked            int `json:"blocked"`
	Open               int `json:"open"`
	UnverifiedFindings int `json:"unverified_findings"`
	OpenHypotheses     int `json:"open_hypotheses"`
}
type ResearchView struct {
	CaseID             string           `json:"case_id"`
	CaseSHA256         string           `json:"case_sha256"`
	FindingID          string           `json:"finding_id,omitempty"`
	Targets            []Target         `json:"targets"`
	TargetScope        string           `json:"target_scope"`
	TotalItems         int              `json:"total_items"`
	Offset             int              `json:"offset"`
	Items              []ResearchItem   `json:"items"`
	NextOffset         *int             `json:"next_offset,omitempty"`
	CoverageComplete   bool             `json:"coverage_complete"`
	Progress           ResearchProgress `json:"progress"`
	Verification       Verification     `json:"verification"`
	CompletionAccepted bool             `json:"completion_accepted"`
	EvidenceAuthority  string           `json:"evidence_authority"`
	Limitations        []string         `json:"limitations"`
}

func (s *Store) ResearchView(id string, o ResearchViewOptions) (ResearchView, error) {
	if o.Limit == 0 {
		o.Limit = 50
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 200 {
		return ResearchView{}, errors.New("offset must be nonnegative; limit must be 1..200")
	}
	v, revision, err := s.Snapshot(id)
	if err != nil {
		return ResearchView{}, err
	}
	if err = recordio.CheckExpectedSHA256(revision, o.ExpectedSHA256); err != nil {
		return ResearchView{}, err
	}
	verification, err := s.Verify(id)
	if err != nil {
		return ResearchView{}, err
	}
	if verification.CaseSHA256 != revision {
		return ResearchView{}, errors.New("case changed during research view verification")
	}
	items := []ResearchItem{}
	add := func(item ResearchItem) {
		if item.Links == nil {
			item.Links = []ResearchLink{}
		}
		items = append(items, item)
	}
	links := func(kind string, ids []string) []ResearchLink {
		r := []ResearchLink{}
		for _, id := range ids {
			r = append(r, ResearchLink{kind, id})
		}
		return r
	}
	for _, a := range v.Artifacts {
		add(ResearchItem{ID: a.ID, Kind: "artifact", Label: a.Identity, Location: a.Source, SourceSHA256: a.SHA256})
	}
	for _, e := range v.Evidence {
		item := ResearchItem{ID: e.ID, Kind: "evidence", Label: e.Summary, Location: e.SourcePath, SourceSHA256: e.SourceSHA256}
		if e.LinkedWorkItemID != "" {
			item.Links = append(item.Links, ResearchLink{"workitem", e.LinkedWorkItemID})
		}
		if e.SupersedesEvidenceID != "" {
			item.Links = append(item.Links, ResearchLink{"supersedes", e.SupersedesEvidenceID})
		}
		add(item)
	}
	for _, f := range v.Findings {
		add(ResearchItem{ID: f.ID, Kind: "finding", Label: f.Title, Details: f.Conclusion, Status: f.Status, Strength: f.Strength, Location: f.Location, Links: links("evidence", f.EvidenceIDs)})
	}
	for _, p := range v.Paths {
		item := ResearchItem{ID: p.ID, Kind: "path", Label: p.Title, Links: links("finding", p.FindingIDs)}
		for _, step := range p.Steps {
			item.Links = append(item.Links, links("evidence", step.EvidenceIDs)...)
			item.Links = append(item.Links, links("finding", step.FindingIDs)...)
		}
		add(item)
	}
	for _, w := range v.WorkItems {
		add(ResearchItem{ID: w.ID, Kind: "workitem", Label: w.Title, Status: w.Status, Links: links("evidence", w.EvidenceIDs)})
	}
	for _, h := range v.Hypotheses {
		add(ResearchItem{ID: h.ID, Kind: "hypothesis", Label: h.Hypothesis, Status: string(h.Status), Links: append(links("supports", h.SupportingEvidenceIDs), links("conflicts", h.ConflictingEvidenceIDs)...)})
	}
	for _, ob := range v.Observations {
		add(ResearchItem{ID: ob.ID, Kind: "observation", Label: ob.Summary, Links: links("evidence", ob.EvidenceIDs)})
	}
	if o.FindingID != "" {
		selected := map[string]bool{}
		for _, item := range items {
			if item.Kind == "finding" && item.ID == o.FindingID {
				selected[item.ID] = true
				for _, link := range item.Links {
					selected[link.TargetID] = true
				}
			}
		}
		if len(selected) == 0 {
			return ResearchView{}, errors.New("finding_id is not an exact Finding in this Case")
		}
		// Include declared containers referencing the selected finding or its
		// evidence; unrelated targets are never matched by text or function name.
		for _, item := range items {
			for _, link := range item.Links {
				if selected[link.TargetID] {
					selected[item.ID] = true
					break
				}
			}
		}
		filtered := []ResearchItem{}
		for _, item := range items {
			if selected[item.ID] {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	if o.Offset > len(items) {
		return ResearchView{}, errors.New("offset outside research view")
	}
	end := min(len(items), o.Offset+o.Limit)
	r := ResearchView{CaseID: id, CaseSHA256: revision, FindingID: o.FindingID, Targets: v.Targets, TargetScope: "case-declared; object-to-target binding is not inferred", TotalItems: len(items), Offset: o.Offset, Items: items[o.Offset:end], CoverageComplete: o.Offset == 0 && end == len(items), Verification: verification, EvidenceAuthority: "canonical-case-snapshot", Limitations: []string{"projection covers Artifact/Evidence/Finding/Path/WorkItem/Hypothesis/Observation links", "links are declared record references, not proven calls or cross-build function identity", "progress counts are recorded statuses; only existing Case review/report owners accept completion"}}
	if end < len(items) {
		r.NextOffset = &end
	}
	for _, w := range v.WorkItems {
		r.Progress.WorkItems++
		switch w.Status {
		case "done":
			r.Progress.Done++
		case "cancelled":
			r.Progress.Cancelled++
		case "blocked":
			r.Progress.Blocked++
		default:
			r.Progress.Open++
		}
	}
	for _, f := range v.Findings {
		if f.Strength == "" || f.Strength == "unverified" {
			r.Progress.UnverifiedFindings++
		}
	}
	for _, h := range v.Hypotheses {
		if h.Status == HypothesisOpen {
			r.Progress.OpenHypotheses++
		}
	}
	body, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if len(body) > 48<<10 {
		return r, errors.New("research view exceeds 48 KiB; reduce limit")
	}
	_, final, err := s.Snapshot(id)
	if err != nil {
		return r, err
	}
	if final != revision {
		return r, errors.New("case changed during research view projection")
	}
	return r, nil
}
