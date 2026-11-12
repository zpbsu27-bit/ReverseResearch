package migration

import (
	"fmt"
	"sort"
	"strings"
)

type SemanticNameOrigin string

const (
	NameOriginDefault  SemanticNameOrigin = "default"
	NameOriginAnalysis SemanticNameOrigin = "analysis"
	NameOriginUser     SemanticNameOrigin = "user"
)

type SemanticComment struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

type FunctionSemantic struct {
	RVA        uint64             `json:"rva"`
	Name       string             `json:"name,omitempty"`
	NameOrigin SemanticNameOrigin `json:"name_origin,omitempty"`
	Comments   []SemanticComment  `json:"comments,omitempty"`
}

type StructMemberSemantic struct {
	Offset     int                `json:"offset"`
	Name       string             `json:"name,omitempty"`
	NameOrigin SemanticNameOrigin `json:"name_origin,omitempty"`
	Type       string             `json:"type,omitempty"`
	Comment    string             `json:"comment,omitempty"`
}

type StructureSemantic struct {
	Key        string                 `json:"key,omitempty"`
	Name       string                 `json:"name"`
	NameOrigin SemanticNameOrigin     `json:"name_origin,omitempty"`
	Size       int                    `json:"size,omitempty"`
	Members    []StructMemberSemantic `json:"members,omitempty"`
}

type SemanticSnapshot struct {
	Functions  []FunctionSemantic  `json:"functions,omitempty"`
	Structures []StructureSemantic `json:"structures,omitempty"`
}

type SyncPreviewRequest struct {
	Migration Result           `json:"migration"`
	Source    SemanticSnapshot `json:"source"`
	Target    SemanticSnapshot `json:"target"`
}

type SyncDecision string

const (
	DecisionSuggest  SyncDecision = "suggest"
	DecisionPreserve SyncDecision = "preserve"
	DecisionConflict SyncDecision = "conflict"
	DecisionSame     SyncDecision = "same"
	DecisionSkip     SyncDecision = "skip"
)

type SyncAction struct {
	Kind          string       `json:"kind"`
	Decision      SyncDecision `json:"decision"`
	Label         string       `json:"label,omitempty"`
	OldRVA        uint64       `json:"old_rva,omitempty"`
	NewRVA        uint64       `json:"new_rva,omitempty"`
	StructureKey  string       `json:"structure_key,omitempty"`
	StructureName string       `json:"structure_name,omitempty"`
	MemberOffset  *int         `json:"member_offset,omitempty"`
	CommentKind   string       `json:"comment_kind,omitempty"`
	SourceValue   string       `json:"source_value,omitempty"`
	TargetValue   string       `json:"target_value,omitempty"`
	ProposedValue string       `json:"proposed_value,omitempty"`
	Reason        string       `json:"reason"`
}

type SyncPreview struct {
	Validation      string       `json:"validation"`
	RuntimeVerified bool         `json:"runtime_verified"`
	WritesPerformed bool         `json:"writes_performed"`
	Actions         []SyncAction `json:"actions"`
	Suggested       int          `json:"suggested"`
	Preserved       int          `json:"preserved"`
	Conflicts       int          `json:"conflicts"`
	Same            int          `json:"same"`
	Skipped         int          `json:"skipped"`
}

func PreviewSemanticSync(request SyncPreviewRequest) (SyncPreview, error) {
	if err := validateSnapshot(request.Source, "source"); err != nil {
		return SyncPreview{}, err
	}
	if err := validateSnapshot(request.Target, "target"); err != nil {
		return SyncPreview{}, err
	}
	preview := SyncPreview{
		Validation:      "preview-only",
		RuntimeVerified: false,
		WritesPerformed: false,
		Actions:         make([]SyncAction, 0),
	}

	sourceFunctions := indexFunctions(request.Source.Functions)
	targetFunctions := indexFunctions(request.Target.Functions)
	entries := append([]Entry(nil), request.Migration.Entries...)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Label != entries[j].Label {
			return entries[i].Label < entries[j].Label
		}
		if entries[i].OldRVA != entries[j].OldRVA {
			return entries[i].OldRVA < entries[j].OldRVA
		}
		return entries[i].NewRVA < entries[j].NewRVA
	})
	for _, entry := range entries {
		if entry.Status != StatusMapped {
			appendAction(&preview, SyncAction{
				Kind: "function_mapping", Decision: DecisionSkip, Label: entry.Label,
				OldRVA: entry.OldRVA, NewRVA: entry.NewRVA,
				Reason: "function migration entry is not uniquely mapped",
			})
			continue
		}
		source, ok := sourceFunctions[entry.OldRVA]
		if !ok {
			appendAction(&preview, SyncAction{
				Kind: "function_semantics", Decision: DecisionSkip, Label: entry.Label,
				OldRVA: entry.OldRVA, NewRVA: entry.NewRVA,
				Reason: "source semantic snapshot has no function at mapped old RVA",
			})
			continue
		}
		target, targetOK := targetFunctions[entry.NewRVA]
		previewFunctionName(&preview, entry, source, target, targetOK)
		previewFunctionComments(&preview, entry, source, target, targetOK)
	}

	sourceStructures := indexStructures(request.Source.Structures)
	targetStructures := indexStructures(request.Target.Structures)
	keys := make([]string, 0, len(sourceStructures))
	for key := range sourceStructures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		source := sourceStructures[key]
		target, ok := targetStructures[key]
		previewStructure(&preview, key, source, target, ok)
	}

	sort.SliceStable(preview.Actions, func(i, j int) bool {
		left, right := preview.Actions[i], preview.Actions[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Label != right.Label {
			return left.Label < right.Label
		}
		if left.NewRVA != right.NewRVA {
			return left.NewRVA < right.NewRVA
		}
		if left.StructureKey != right.StructureKey {
			return left.StructureKey < right.StructureKey
		}
		leftOffset, rightOffset := -1, -1
		if left.MemberOffset != nil {
			leftOffset = *left.MemberOffset
		}
		if right.MemberOffset != nil {
			rightOffset = *right.MemberOffset
		}
		if leftOffset != rightOffset {
			return leftOffset < rightOffset
		}
		return left.CommentKind < right.CommentKind
	})
	return preview, nil
}

func validateSnapshot(snapshot SemanticSnapshot, side string) error {
	functions := make(map[uint64]bool, len(snapshot.Functions))
	for index, function := range snapshot.Functions {
		if function.RVA == 0 {
			return fmt.Errorf("%s function %d requires a nonzero RVA", side, index)
		}
		if functions[function.RVA] {
			return fmt.Errorf("%s has duplicate function RVA 0x%X", side, function.RVA)
		}
		functions[function.RVA] = true
		if err := validateNameOrigin(function.NameOrigin); err != nil {
			return fmt.Errorf("%s function 0x%X: %w", side, function.RVA, err)
		}
		comments := make(map[string]bool, len(function.Comments))
		for _, comment := range function.Comments {
			kind := normalizeKey(comment.Kind)
			if kind == "" {
				return fmt.Errorf("%s function 0x%X has comment without kind", side, function.RVA)
			}
			if comments[kind] {
				return fmt.Errorf("%s function 0x%X has duplicate comment kind %q", side, function.RVA, comment.Kind)
			}
			comments[kind] = true
		}
	}
	structures := make(map[string]bool, len(snapshot.Structures))
	for index, structure := range snapshot.Structures {
		if strings.TrimSpace(structure.Name) == "" {
			return fmt.Errorf("%s structure %d requires a name", side, index)
		}
		if err := validateNameOrigin(structure.NameOrigin); err != nil {
			return fmt.Errorf("%s structure %q: %w", side, structure.Name, err)
		}
		key := structureKey(structure)
		if structures[key] {
			return fmt.Errorf("%s has duplicate structure key %q", side, key)
		}
		structures[key] = true
		offsets := make(map[int]bool, len(structure.Members))
		for _, member := range structure.Members {
			if member.Offset < 0 {
				return fmt.Errorf("%s structure %q has negative member offset", side, structure.Name)
			}
			if offsets[member.Offset] {
				return fmt.Errorf("%s structure %q has duplicate member offset %d", side, structure.Name, member.Offset)
			}
			offsets[member.Offset] = true
			if err := validateNameOrigin(member.NameOrigin); err != nil {
				return fmt.Errorf("%s structure %q member %d: %w", side, structure.Name, member.Offset, err)
			}
		}
	}
	return nil
}

func validateNameOrigin(origin SemanticNameOrigin) error {
	switch origin {
	case "", NameOriginDefault, NameOriginAnalysis, NameOriginUser:
		return nil
	default:
		return fmt.Errorf("unsupported name_origin %q", origin)
	}
}

func indexFunctions(functions []FunctionSemantic) map[uint64]FunctionSemantic {
	result := make(map[uint64]FunctionSemantic, len(functions))
	for _, function := range functions {
		result[function.RVA] = function
	}
	return result
}

func indexStructures(structures []StructureSemantic) map[string]StructureSemantic {
	result := make(map[string]StructureSemantic, len(structures))
	for _, structure := range structures {
		result[structureKey(structure)] = structure
	}
	return result
}

func structureKey(structure StructureSemantic) string {
	if key := normalizeKey(structure.Key); key != "" {
		return key
	}
	return normalizeKey(structure.Name)
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func previewFunctionName(preview *SyncPreview, entry Entry, source, target FunctionSemantic, targetOK bool) {
	sourceName := strings.TrimSpace(source.Name)
	if sourceName == "" || source.NameOrigin == NameOriginDefault {
		appendAction(preview, SyncAction{
			Kind: "function_name", Decision: DecisionSkip, Label: entry.Label,
			OldRVA: entry.OldRVA, NewRVA: entry.NewRVA,
			Reason: "source function has no non-default semantic name to migrate",
		})
		return
	}
	targetName := ""
	if targetOK {
		targetName = strings.TrimSpace(target.Name)
	}
	action := SyncAction{
		Kind: "function_name", Label: entry.Label,
		OldRVA: entry.OldRVA, NewRVA: entry.NewRVA,
		SourceValue: sourceName, TargetValue: targetName,
	}
	switch {
	case targetName == sourceName:
		action.Decision = DecisionSame
		action.Reason = "target already has the source semantic name"
	case targetOK && target.NameOrigin == NameOriginUser && targetName != "":
		action.Decision = DecisionPreserve
		action.Reason = "target has a different user-authored name; preserve it"
	case targetName == "" || target.NameOrigin == NameOriginDefault:
		action.Decision = DecisionSuggest
		action.ProposedValue = sourceName
		action.Reason = "target name is empty or default-generated"
	default:
		action.Decision = DecisionConflict
		action.Reason = "target has a different non-default name; preview does not overwrite it"
	}
	appendAction(preview, action)
}

func previewFunctionComments(preview *SyncPreview, entry Entry, source, target FunctionSemantic, targetOK bool) {
	targetComments := make(map[string]string)
	if targetOK {
		for _, comment := range target.Comments {
			targetComments[normalizeKey(comment.Kind)] = strings.TrimSpace(comment.Text)
		}
	}
	comments := append([]SemanticComment(nil), source.Comments...)
	sort.SliceStable(comments, func(i, j int) bool {
		return normalizeKey(comments[i].Kind) < normalizeKey(comments[j].Kind)
	})
	for _, comment := range comments {
		kind := normalizeKey(comment.Kind)
		sourceText := strings.TrimSpace(comment.Text)
		if sourceText == "" {
			continue
		}
		targetText := targetComments[kind]
		action := SyncAction{
			Kind: "function_comment", Label: entry.Label, OldRVA: entry.OldRVA, NewRVA: entry.NewRVA,
			CommentKind: kind, SourceValue: sourceText, TargetValue: targetText,
		}
		switch {
		case targetText == sourceText:
			action.Decision = DecisionSame
			action.Reason = "target comment already matches"
		case targetText == "":
			action.Decision = DecisionSuggest
			action.ProposedValue = sourceText
			action.Reason = "target has no comment of this kind"
		default:
			action.Decision = DecisionConflict
			action.Reason = "target has a different existing comment; preview never overwrites it"
		}
		appendAction(preview, action)
	}
}

func previewStructure(preview *SyncPreview, key string, source, target StructureSemantic, targetOK bool) {
	sourceName := strings.TrimSpace(source.Name)
	if !targetOK {
		appendAction(preview, SyncAction{
			Kind: "structure", Decision: DecisionSuggest, StructureKey: key, StructureName: sourceName,
			SourceValue: sourceName, ProposedValue: sourceName,
			Reason: "target snapshot has no structure with the same semantic key",
		})
		for _, member := range sortedMembers(source.Members) {
			offset := member.Offset
			appendAction(preview, SyncAction{
				Kind: "structure_member", Decision: DecisionSuggest, StructureKey: key, StructureName: sourceName,
				MemberOffset: &offset, SourceValue: memberSummary(member), ProposedValue: memberSummary(member),
				Reason: "member belongs to a structure that would need to be created",
			})
		}
		return
	}
	targetName := strings.TrimSpace(target.Name)
	if sourceName != targetName {
		action := SyncAction{
			Kind: "structure_name", StructureKey: key, StructureName: targetName,
			SourceValue: sourceName, TargetValue: targetName,
		}
		if target.NameOrigin == NameOriginUser && targetName != "" {
			action.Decision = DecisionPreserve
			action.Reason = "target structure has a user-authored name; preserve it"
		} else {
			action.Decision = DecisionConflict
			action.Reason = "structure names differ; preview does not implicitly rename the target"
		}
		appendAction(preview, action)
	}

	targetMembers := make(map[int]StructMemberSemantic, len(target.Members))
	for _, member := range target.Members {
		targetMembers[member.Offset] = member
	}
	for _, sourceMember := range sortedMembers(source.Members) {
		targetMember, ok := targetMembers[sourceMember.Offset]
		offset := sourceMember.Offset
		if !ok {
			appendAction(preview, SyncAction{
				Kind: "structure_member", Decision: DecisionSuggest, StructureKey: key, StructureName: targetName,
				MemberOffset: &offset, SourceValue: memberSummary(sourceMember), ProposedValue: memberSummary(sourceMember),
				Reason: "target structure has no member at this offset",
			})
			continue
		}
		previewMemberName(preview, key, targetName, offset, sourceMember, targetMember)
		previewMemberType(preview, key, targetName, offset, sourceMember, targetMember)
		previewMemberComment(preview, key, targetName, offset, sourceMember, targetMember)
	}
}

func previewMemberName(preview *SyncPreview, key, structureName string, offset int, source, target StructMemberSemantic) {
	sourceName := strings.TrimSpace(source.Name)
	targetName := strings.TrimSpace(target.Name)
	if sourceName == "" || source.NameOrigin == NameOriginDefault {
		return
	}
	action := SyncAction{
		Kind: "structure_member_name", StructureKey: key, StructureName: structureName,
		MemberOffset: intPointer(offset), SourceValue: sourceName, TargetValue: targetName,
	}
	switch {
	case sourceName == targetName:
		action.Decision = DecisionSame
		action.Reason = "target member name already matches"
	case target.NameOrigin == NameOriginUser && targetName != "":
		action.Decision = DecisionPreserve
		action.Reason = "target member has a different user-authored name; preserve it"
	case targetName == "" || target.NameOrigin == NameOriginDefault:
		action.Decision = DecisionSuggest
		action.ProposedValue = sourceName
		action.Reason = "target member name is empty or default-generated"
	default:
		action.Decision = DecisionConflict
		action.Reason = "target member has a different non-default name"
	}
	appendAction(preview, action)
}

func previewMemberType(preview *SyncPreview, key, structureName string, offset int, source, target StructMemberSemantic) {
	sourceType := strings.TrimSpace(source.Type)
	targetType := strings.TrimSpace(target.Type)
	if sourceType == "" {
		return
	}
	action := SyncAction{
		Kind: "structure_member_type", StructureKey: key, StructureName: structureName,
		MemberOffset: intPointer(offset), SourceValue: sourceType, TargetValue: targetType,
	}
	switch {
	case sourceType == targetType:
		action.Decision = DecisionSame
		action.Reason = "target member type already matches"
	case targetType == "":
		action.Decision = DecisionSuggest
		action.ProposedValue = sourceType
		action.Reason = "target member has no type"
	default:
		action.Decision = DecisionConflict
		action.Reason = "target member has a different existing type; preview never overwrites it"
	}
	appendAction(preview, action)
}

func previewMemberComment(preview *SyncPreview, key, structureName string, offset int, source, target StructMemberSemantic) {
	sourceText := strings.TrimSpace(source.Comment)
	targetText := strings.TrimSpace(target.Comment)
	if sourceText == "" {
		return
	}
	action := SyncAction{
		Kind: "structure_member_comment", StructureKey: key, StructureName: structureName,
		MemberOffset: intPointer(offset), SourceValue: sourceText, TargetValue: targetText,
	}
	switch {
	case sourceText == targetText:
		action.Decision = DecisionSame
		action.Reason = "target member comment already matches"
	case targetText == "":
		action.Decision = DecisionSuggest
		action.ProposedValue = sourceText
		action.Reason = "target member has no comment"
	default:
		action.Decision = DecisionConflict
		action.Reason = "target member has a different existing comment; preview never overwrites it"
	}
	appendAction(preview, action)
}

func sortedMembers(members []StructMemberSemantic) []StructMemberSemantic {
	result := append([]StructMemberSemantic(nil), members...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].Offset < result[j].Offset })
	return result
}

func memberSummary(member StructMemberSemantic) string {
	return fmt.Sprintf("offset=%d name=%q type=%q comment=%q", member.Offset, strings.TrimSpace(member.Name), strings.TrimSpace(member.Type), strings.TrimSpace(member.Comment))
}

func intPointer(value int) *int {
	copy := value
	return &copy
}

func appendAction(preview *SyncPreview, action SyncAction) {
	preview.Actions = append(preview.Actions, action)
	switch action.Decision {
	case DecisionSuggest:
		preview.Suggested++
	case DecisionPreserve:
		preview.Preserved++
	case DecisionConflict:
		preview.Conflicts++
	case DecisionSame:
		preview.Same++
	case DecisionSkip:
		preview.Skipped++
	}
}
