package detection

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSigmaFixtureValidationPassesPositiveAndNegative(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	result, err := ValidateSigmaFiles(SigmaRequest{
		RulePath:         filepath.Join(root, "testdata", "detection", "sigma_scheduled_task.yml"),
		PositiveFixtures: []string{filepath.Join(root, "testdata", "detection", "sigma_scheduled_task_positive.json")},
		NegativeFixtures: []string{filepath.Join(root, "testdata", "detection", "sigma_scheduled_task_negative.json")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Validated || !result.SyntaxValid || !result.SchemaValid || !result.PositivePassed || !result.NegativePassed {
		t.Fatalf("result=%+v", result)
	}
	if result.PositiveFixtures[0].Matches != 1 || result.NegativeFixtures[0].Matches != 0 || len(result.RuleSHA256) != 64 {
		t.Fatalf("fixtures=%+v %+v", result.PositiveFixtures, result.NegativeFixtures)
	}
}

func TestSigmaUnsupportedModifierFailsClosed(t *testing.T) {
	body := []byte("title: x\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|base64: evil\n  condition: selection\n")
	_, err := compileSigma(body)
	if err == nil || !strings.Contains(err.Error(), "unsupported field modifier") {
		t.Fatalf("err=%v", err)
	}
}

func TestSigmaConditionAndFieldModifiers(t *testing.T) {
	body := []byte("title: x\nlogsource:\n  product: windows\ndetection:\n  a:\n    Image|endswith: cmd.exe\n  b:\n    CommandLine|contains: /c whoami\n  condition: a and not b\n")
	rule, err := compileSigma(body)
	if err != nil {
		t.Fatal(err)
	}
	if !matchSigma(rule, map[string]any{"Image": "C:/Windows/cmd.exe", "CommandLine": "cmd.exe /c echo ok"}) {
		t.Fatal("expected event to match")
	}
	if matchSigma(rule, map[string]any{"Image": "C:/Windows/cmd.exe", "CommandLine": "cmd.exe /c whoami"}) {
		t.Fatal("negative predicate did not block event")
	}
}
