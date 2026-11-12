package migration

import (
	"reflect"
	"testing"
)

func mappedMigration() Result {
	return Result{
		Entries: []Entry{
			{Label: "mapped", Status: StatusMapped, OldRVA: 0x1000, NewRVA: 0x2000},
			{Label: "ambiguous", Status: StatusAmbiguous, OldRVA: 0x1100},
		},
	}
}

func findAction(t *testing.T, actions []SyncAction, kind string, offset *int) SyncAction {
	t.Helper()
	for _, action := range actions {
		if action.Kind != kind {
			continue
		}
		if offset == nil && action.MemberOffset == nil {
			return action
		}
		if offset != nil && action.MemberOffset != nil && *offset == *action.MemberOffset {
			return action
		}
	}
	t.Fatalf("action kind=%s offset=%v not found in %+v", kind, offset, actions)
	return SyncAction{}
}

func TestPreviewSemanticSyncPreservesTargetUserNameAndConflictingComments(t *testing.T) {
	request := SyncPreviewRequest{
		Migration: mappedMigration(),
		Source: SemanticSnapshot{Functions: []FunctionSemantic{
			{RVA: 0x1000, Name: "SplitArmy", NameOrigin: NameOriginUser, Comments: []SemanticComment{{Kind: "plate", Text: "source note"}}},
		}},
		Target: SemanticSnapshot{Functions: []FunctionSemantic{
			{RVA: 0x2000, Name: "MySplitArmy", NameOrigin: NameOriginUser, Comments: []SemanticComment{{Kind: "plate", Text: "target note"}}},
		}},
	}
	preview, err := PreviewSemanticSync(request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Validation != "preview-only" || preview.RuntimeVerified || preview.WritesPerformed {
		t.Fatalf("preview safety=%+v", preview)
	}
	name := findAction(t, preview.Actions, "function_name", nil)
	if name.Decision != DecisionPreserve || name.ProposedValue != "" {
		t.Fatalf("name=%+v", name)
	}
	comment := findAction(t, preview.Actions, "function_comment", nil)
	if comment.Decision != DecisionConflict || comment.ProposedValue != "" {
		t.Fatalf("comment=%+v", comment)
	}
	if preview.Skipped != 1 {
		t.Fatalf("ambiguous mapping was not skipped: %+v", preview)
	}
}

func TestPreviewSemanticSyncSuggestsIntoDefaultAndEmptyTarget(t *testing.T) {
	request := SyncPreviewRequest{
		Migration: Result{Entries: []Entry{{Label: "mapped", Status: StatusMapped, OldRVA: 0x1000, NewRVA: 0x2000}}},
		Source: SemanticSnapshot{Functions: []FunctionSemantic{{
			RVA: 0x1000, Name: "SplitArmy", NameOrigin: NameOriginAnalysis,
			Comments: []SemanticComment{{Kind: "eol", Text: "moves units"}},
		}}},
		Target: SemanticSnapshot{Functions: []FunctionSemantic{{RVA: 0x2000, Name: "FUN_00402000", NameOrigin: NameOriginDefault}}},
	}
	preview, err := PreviewSemanticSync(request)
	if err != nil {
		t.Fatal(err)
	}
	name := findAction(t, preview.Actions, "function_name", nil)
	if name.Decision != DecisionSuggest || name.ProposedValue != "SplitArmy" {
		t.Fatalf("name=%+v", name)
	}
	comment := findAction(t, preview.Actions, "function_comment", nil)
	if comment.Decision != DecisionSuggest || comment.ProposedValue != "moves units" {
		t.Fatalf("comment=%+v", comment)
	}
}

func TestPreviewSemanticSyncStructuresAreAdditiveAndNonDestructive(t *testing.T) {
	offset0, offset4 := 0, 4
	request := SyncPreviewRequest{
		Migration: Result{Entries: []Entry{{Label: "mapped", Status: StatusMapped, OldRVA: 0x1000, NewRVA: 0x2000}}},
		Source: SemanticSnapshot{Structures: []StructureSemantic{{
			Key: "unit", Name: "Unit", NameOrigin: NameOriginUser, Size: 8,
			Members: []StructMemberSemantic{
				{Offset: 0, Name: "hp", NameOrigin: NameOriginUser, Type: "int", Comment: "health"},
				{Offset: 4, Name: "flags", NameOrigin: NameOriginAnalysis, Type: "uint32_t"},
			},
		}}},
		Target: SemanticSnapshot{Structures: []StructureSemantic{{
			Key: "unit", Name: "MyUnit", NameOrigin: NameOriginUser, Size: 8,
			Members: []StructMemberSemantic{
				{Offset: 0, Name: "healthPoints", NameOrigin: NameOriginUser, Type: "short", Comment: "manually verified"},
			},
		}}},
	}
	preview, err := PreviewSemanticSync(request)
	if err != nil {
		t.Fatal(err)
	}
	structName := findAction(t, preview.Actions, "structure_name", nil)
	if structName.Decision != DecisionPreserve {
		t.Fatalf("structure name=%+v", structName)
	}
	memberName := findAction(t, preview.Actions, "structure_member_name", &offset0)
	if memberName.Decision != DecisionPreserve {
		t.Fatalf("member name=%+v", memberName)
	}
	memberType := findAction(t, preview.Actions, "structure_member_type", &offset0)
	if memberType.Decision != DecisionConflict {
		t.Fatalf("member type=%+v", memberType)
	}
	memberComment := findAction(t, preview.Actions, "structure_member_comment", &offset0)
	if memberComment.Decision != DecisionConflict {
		t.Fatalf("member comment=%+v", memberComment)
	}
	missingMember := findAction(t, preview.Actions, "structure_member", &offset4)
	if missingMember.Decision != DecisionSuggest {
		t.Fatalf("missing member=%+v", missingMember)
	}
}

func TestPreviewSemanticSyncMissingStructureCreatesPreviewOnly(t *testing.T) {
	offset := 0
	preview, err := PreviewSemanticSync(SyncPreviewRequest{
		Migration: Result{Entries: []Entry{{Label: "mapped", Status: StatusMapped, OldRVA: 0x1000, NewRVA: 0x2000}}},
		Source: SemanticSnapshot{Structures: []StructureSemantic{{
			Key: "unit", Name: "Unit", Members: []StructMemberSemantic{{Offset: 0, Name: "hp", Type: "int"}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if findAction(t, preview.Actions, "structure", nil).Decision != DecisionSuggest ||
		findAction(t, preview.Actions, "structure_member", &offset).Decision != DecisionSuggest {
		t.Fatalf("preview=%+v", preview)
	}
}

func TestPreviewSemanticSyncIsDeterministicAcrossInputOrder(t *testing.T) {
	base := SyncPreviewRequest{
		Migration: Result{Entries: []Entry{
			{Label: "b", Status: StatusMapped, OldRVA: 0x1100, NewRVA: 0x2100},
			{Label: "a", Status: StatusMapped, OldRVA: 0x1000, NewRVA: 0x2000},
		}},
		Source: SemanticSnapshot{Functions: []FunctionSemantic{
			{RVA: 0x1100, Name: "B", NameOrigin: NameOriginUser},
			{RVA: 0x1000, Name: "A", NameOrigin: NameOriginUser},
		}},
	}
	first, err := PreviewSemanticSync(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Migration.Entries[0], base.Migration.Entries[1] = base.Migration.Entries[1], base.Migration.Entries[0]
	base.Source.Functions[0], base.Source.Functions[1] = base.Source.Functions[1], base.Source.Functions[0]
	second, err := PreviewSemanticSync(base)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("preview changed with input order:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestPreviewSemanticSyncRejectsDuplicateSemanticKeys(t *testing.T) {
	_, err := PreviewSemanticSync(SyncPreviewRequest{
		Source: SemanticSnapshot{Functions: []FunctionSemantic{{RVA: 0x1000}, {RVA: 0x1000}}},
	})
	if err == nil {
		t.Fatal("duplicate function RVA accepted")
	}
	_, err = PreviewSemanticSync(SyncPreviewRequest{
		Source: SemanticSnapshot{Structures: []StructureSemantic{{Key: "x", Name: "A"}, {Key: "x", Name: "B"}}},
	})
	if err == nil {
		t.Fatal("duplicate structure key accepted")
	}
}
