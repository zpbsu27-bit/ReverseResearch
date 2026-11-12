package router

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineAndroidCodeRecoveryDoesNotAcquireRuntimeMutationRoute(t *testing.T) {
	e, err := Load(filepath.Join("..", "..", "config", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	for query, want := range map[string]string{
		"用 JADX 恢复 APK 的方法代码，查询静态引用":                                   "android-code",
		"android code recovery dex code recovery jadx recovery 安卓代码恢复": "android-code",
		"读取离线 dex 指令和 dex 控制流":                                         "android-static",
		"android apk adb frida runtime hook":                           "android",
	} {
		got := e.Route(query)
		if got.Route.ID != want {
			t.Fatalf("%q routed to %s, want %s", query, got.Route.ID, want)
		}
		if want != "android" && got.Route.EffectClass != "observation" {
			t.Fatalf("offline query acquired mutation authority: %+v", got.Route)
		}
	}
}

func TestRoutingBenchmark(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	engine, err := Load(filepath.Join(root, "config", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "testdata", "routing-benchmark.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Text     string `json:"text"`
		Expected string `json:"expected"`
	}
	if err := json.Unmarshal(body, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		result := engine.Route(tc.Text)
		if result.Route.ID != tc.Expected {
			t.Errorf("%q route=%s score=%d matched=%v want=%s", tc.Text, result.Route.ID, result.Score, result.MatchedKeywords, tc.Expected)
		}
	}
}

func TestDuplicateKeywordsDoNotInflateRouteScore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	body := []byte(`{
	  "version": 1,
	  "fallback": "fallback",
	  "routes": [
	    {"id":"generic","priority":100,"description":"generic","keywords":["hook","hook"]},
	    {"id":"android","priority":50,"description":"android","keywords":["hook","apk"]},
	    {"id":"fallback","priority":0,"description":"fallback","keywords":[]}
	  ]
	}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Route("hook apk")
	if result.Route.ID != "android" {
		t.Fatalf("route=%+v", result)
	}
	for _, candidate := range result.Candidates {
		if candidate.ID == "generic" && len(candidate.MatchedKeywords) != 1 {
			t.Fatalf("duplicate keyword inflated candidate=%+v", candidate)
		}
	}
}

func TestRouteReportsAlternativesDeterministically(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	engine, err := Load(filepath.Join(root, "config", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Route("跨版本补丁和函数迁移")
	if result.Route.ID != "binary-diff" {
		t.Fatalf("route=%+v", result)
	}
	if len(result.Candidates) == 0 {
		t.Fatal("expected ranked candidates")
	}
}

func TestRouteV4RequiresStructuredDimensions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	body := []byte(`{"version":4,"fallback":"fallback","routes":[{"id":"native","priority":10,"description":"native","keywords":["binary"],"domain":"native","intents":["reverse"],"effect_class":"observation"},{"id":"fallback","priority":0,"description":"fallback","keywords":[],"domain":"unknown","intents":["triage"],"effect_class":"observation"}]}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Route("binary")
	if result.Classification.Domain != "native" || result.Classification.EffectClass != "observation" {
		t.Fatalf("classification=%+v", result.Classification)
	}
}

func TestRouteV4RejectsMissingEffectClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	body := []byte(`{"version":4,"fallback":"fallback","routes":[{"id":"fallback","priority":0,"description":"fallback","keywords":[],"domain":"unknown","intents":["triage"]}]}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected v4 route without effect_class to fail")
	}
}
