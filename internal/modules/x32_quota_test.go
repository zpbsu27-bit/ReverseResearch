package modules

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestX32CachedResultFallsBackToBoundedDigestSummary(t *testing.T) {
	result := &mcp.CallToolResult{}
	result.Content = append(result.Content, &mcp.TextContent{Text: strings.Repeat("x", maxX32CachedResultBytes+4096)})
	cached, err := cacheX32Result(result)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(cached)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > maxX32CachedResultBytes {
		t.Fatalf("cached result bytes=%d max=%d", len(body), maxX32CachedResultBytes)
	}
	if len(cached.Text) != 1 || !strings.Contains(cached.Text[0], "durable replay result omitted") {
		t.Fatalf("unexpected bounded fallback: %+v", cached)
	}
}

func TestX32PreparedReceiptPathIsSharded(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	const operationID = "prepared-shard"
	key := x32OperationKey(operationID)
	want := filepath.Join("prepared", key[:2], key+".json")
	if !strings.HasSuffix(guard.operationPath(operationID), want) {
		t.Fatalf("prepared path=%s want suffix=%s", guard.operationPath(operationID), want)
	}
}
