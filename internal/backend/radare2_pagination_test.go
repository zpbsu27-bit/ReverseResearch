package backend

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type r2PaginationTestTransport struct {
	connect func(context.Context) (mcp.Connection, error)
}

func (t *r2PaginationTestTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	return t.connect(ctx)
}

type r2PaginationTestConnection struct {
	read  func(context.Context) (jsonrpc.Message, error)
	write func(context.Context, jsonrpc.Message) error
	close func() error
}

func (c *r2PaginationTestConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	return c.read(ctx)
}

func (c *r2PaginationTestConnection) Write(ctx context.Context, msg jsonrpc.Message) error {
	return c.write(ctx, msg)
}

func (c *r2PaginationTestConnection) Close() error { return c.close() }
func (*r2PaginationTestConnection) SessionID() string {
	return "original-r2-session"
}

func r2PaginationResponse(t *testing.T, raw string) *jsonrpc.Response {
	t.Helper()
	id, err := jsonrpc.MakeID("r2-call-7")
	if err != nil {
		t.Fatal(err)
	}
	return &jsonrpc.Response{ID: id, Result: json.RawMessage(raw), Extra: &struct{ Source string }{"original"}}
}

func r2PaginationRead(t *testing.T, original jsonrpc.Message) (jsonrpc.Message, error) {
	t.Helper()
	conn := &r2PaginationConnection{Connection: &r2PaginationTestConnection{
		read: func(context.Context) (jsonrpc.Message, error) { return original, nil },
	}}
	return conn.Read(t.Context())
}

func TestR2PaginationSurvivesRealSDKDecode(t *testing.T) {
	original := r2PaginationResponse(t, `{"content":[{"type":"text","text":"one\ntwo","annotations":{"audience":["assistant"]}}],"structuredContent":{"producer":"r2","items":[1,2]},"_meta":{"existing":{"retain":true}},"pagination":{"hasMore":true,"nextCursor":"1000"},"isError":false}`)
	originalBytes := string(original.Result)
	var before mcp.CallToolResult
	if err := json.Unmarshal(original.Result, &before); err != nil {
		t.Fatal(err)
	}
	msg, err := r2PaginationRead(t, original)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := msg.(*jsonrpc.Response)
	if !ok || response == original {
		t.Fatalf("expected a copied response, got %T", msg)
	}
	if response.ID != original.ID || response.Extra != original.Extra || response.Error != original.Error {
		t.Fatal("response identity, error or Extra changed")
	}
	if string(original.Result) != originalBytes {
		t.Fatal("normalization mutated the original response")
	}
	var after mcp.CallToolResult
	if err := json.Unmarshal(response.Result, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Content, after.Content) || !reflect.DeepEqual(before.StructuredContent, after.StructuredContent) || before.IsError != after.IsError {
		t.Fatal("original tool content, structured content or error state changed")
	}
	if !reflect.DeepEqual(after.Meta["existing"], before.Meta["existing"]) {
		t.Fatal("existing metadata changed")
	}
	want := map[string]any{"hasMore": true, "nextCursor": "1000"}
	if !reflect.DeepEqual(after.Meta[r2PaginationMetaKey], want) {
		t.Fatalf("provider pagination did not survive SDK decode: %#v", after.Meta)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Result, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["pagination"]; exists {
		t.Fatal("provider extension was not moved into standard metadata")
	}
	for _, forbidden := range []string{"truncated", "coverage_complete", "function_complete"} {
		if _, exists := fields[forbidden]; exists {
			t.Fatalf("adapter invented %s", forbidden)
		}
	}
}

func TestR2PaginationOtherMessagesPassThrough(t *testing.T) {
	protocolError := r2PaginationResponse(t, `{"content":[],"pagination":{"nextCursor":"7"}}`)
	protocolError.Error = errors.New("provider protocol error")
	for name, original := range map[string]jsonrpc.Message{
		"protocol-error": protocolError,
		"tool-error":     r2PaginationResponse(t, `{"content":[{"type":"text","text":"failed"}],"isError":true,"pagination":{"nextCursor":"7"}}`),
		"plain-tool":     r2PaginationResponse(t, `{"content":[{"type":"text","text":"ordinary"}],"_meta":{"keep":"same"}}`),
		"tools-list":     r2PaginationResponse(t, `{"tools":[],"pagination":{"nextCursor":"7"}}`),
		"scalar":         r2PaginationResponse(t, `"plain value"`),
		"null":           r2PaginationResponse(t, `null`),
		"notification":   &jsonrpc.Request{Method: "notifications/message", Params: json.RawMessage(`{"level":"info"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := r2PaginationRead(t, original)
			if err != nil || got != original {
				t.Fatalf("unrelated message changed: got=%#v err=%v", got, err)
			}
		})
	}
}

func TestR2PaginationPreservesUnknownValueWithoutInterpretation(t *testing.T) {
	for _, rawPagination := range []string{`null`, `{"hasMore":false}`, `{"nextCursor":"not-a-number"}`, `{"opaque":9007199254740993,"extra":[true,"x"]}`} {
		t.Run(rawPagination, func(t *testing.T) {
			original := r2PaginationResponse(t, `{"content":[],"pagination":`+rawPagination+`}`)
			msg, err := r2PaginationRead(t, original)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(msg.(*jsonrpc.Response).Result, &fields); err != nil {
				t.Fatal(err)
			}
			var meta map[string]json.RawMessage
			if err := json.Unmarshal(fields["_meta"], &meta); err != nil {
				t.Fatal(err)
			}
			if string(meta[r2PaginationMetaKey]) != rawPagination {
				t.Fatalf("provider value changed: %s", meta[r2PaginationMetaKey])
			}
		})
	}
}

func TestR2PaginationMetadataConflictsAreExplicit(t *testing.T) {
	for name, raw := range map[string]string{
		"different-value": `{"content":[],"pagination":{"nextCursor":"7"},"_meta":{"reverseresearch/r2-pagination":{"nextCursor":"8"}}}`,
		"same-value":      `{"content":[],"pagination":{"nextCursor":"7"},"_meta":{"reverseresearch/r2-pagination":{"nextCursor":"7"}}}`,
		"non-object-meta": `{"content":[],"pagination":{},"_meta":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			original := r2PaginationResponse(t, raw)
			msg, err := r2PaginationRead(t, original)
			if err == nil || msg != nil || !strings.Contains(err.Error(), "pagination") {
				t.Fatalf("metadata conflict did not fail explicitly: msg=%#v err=%v", msg, err)
			}
			if string(original.Result) != raw {
				t.Fatal("failure modified the original response")
			}
		})
	}
}

func TestR2PaginationTransportDelegatesWithoutRetry(t *testing.T) {
	connectCalls, writeCalls, closeCalls := 0, 0, 0
	writeErr := errors.New("delegate write")
	closeErr := errors.New("delegate close")
	request := &jsonrpc.Request{Method: "tools/call"}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	base := &r2PaginationTestConnection{
		read: func(got context.Context) (jsonrpc.Message, error) {
			if got != ctx {
				t.Error("read context replaced")
			}
			return nil, io.EOF
		},
		write: func(got context.Context, msg jsonrpc.Message) error {
			writeCalls++
			if got != ctx || msg != request {
				t.Error("write request/context replaced")
			}
			return writeErr
		},
		close: func() error { closeCalls++; return closeErr },
	}
	transport := &r2PaginationTransport{Transport: &r2PaginationTestTransport{
		connect: func(got context.Context) (mcp.Connection, error) {
			connectCalls++
			if got != ctx {
				t.Error("connect context replaced")
			}
			return base, nil
		},
	}}
	conn, err := transport.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if conn.SessionID() != "original-r2-session" {
		t.Fatal("session identity replaced")
	}
	if _, err := conn.Read(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("read error changed: %v", err)
	}
	if err := conn.Write(ctx, request); !errors.Is(err, writeErr) {
		t.Fatalf("write error changed: %v", err)
	}
	for range 2 {
		if err := conn.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("close error changed: %v", err)
		}
	}
	if connectCalls != 1 || writeCalls != 1 || closeCalls != 2 {
		t.Fatalf("adapter repeated or intercepted delegated work: connect=%d write=%d close=%d", connectCalls, writeCalls, closeCalls)
	}
}

func TestR2PaginationCancellationAndCloseUnblockRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	readCalls := 0
	conn := &r2PaginationConnection{Connection: &r2PaginationTestConnection{
		read: func(ctx context.Context) (jsonrpc.Message, error) {
			readCalls++
			return nil, ctx.Err()
		},
	}}
	if _, err := conn.Read(ctx); !errors.Is(err, context.Canceled) || readCalls != 1 {
		t.Fatalf("cancellation was retried or replaced: calls=%d err=%v", readCalls, err)
	}
	closed := make(chan struct{})
	entered := make(chan struct{})
	conn = &r2PaginationConnection{Connection: &r2PaginationTestConnection{
		read: func(ctx context.Context) (jsonrpc.Message, error) {
			close(entered)
			select {
			case <-closed:
				return nil, io.EOF
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		close: func() error { close(closed); return nil },
	}}
	done := make(chan error, 1)
	go func() { _, err := conn.Read(t.Context()); done <- err }()
	<-entered
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("delegate close outcome changed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("delegate Close did not unblock Read")
	}
}

func TestR2PaginationConnectFailurePassesThrough(t *testing.T) {
	want := errors.New("delegate connect")
	calls := 0
	transport := &r2PaginationTransport{Transport: &r2PaginationTestTransport{
		connect: func(context.Context) (mcp.Connection, error) { calls++; return nil, want },
	}}
	conn, err := transport.Connect(t.Context())
	if conn != nil || !errors.Is(err, want) || calls != 1 {
		t.Fatalf("connect failure changed or retried: conn=%v calls=%d err=%v", conn, calls, err)
	}
}

func TestR2PaginationSchemaDiagnostic(t *testing.T) {
	if os.Getenv("RR_R2_SCHEMA_DIAGNOSTIC") != "1" {
		t.Skip("opt-in only: RR_R2_SCHEMA_DIAGNOSTIC=1 lists the original r2 backend schema without opening a target")
	}
	root := os.Getenv("RR_R2_SCHEMA_ROOT")
	if root == "" {
		var err error
		root, err = filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			t.Fatal(err)
		}
	}
	backend := NewRadare2(root)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := backend.CloseContext(ctx); err != nil {
			t.Errorf("close original r2 owner: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	generation, err := backend.ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tools, listErr := generation.session.ListTools(ctx, nil)
	releaseErr := backend.release(generation)
	if err := errors.Join(listErr, releaseErr); err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Name != "disassemble_function" {
			continue
		}
		body, err := json.Marshal(tool)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("R2_SCHEMA_DIAGNOSTIC %s", body)
		var schema struct {
			Properties map[string]struct{ Type string }
			Required   []string
		}
		rawSchema, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(rawSchema, &schema); err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]string{"address": "string", "cursor": "string", "page_size": "integer"} {
			if schema.Properties[name].Type != want {
				t.Fatalf("actual %s schema=%#v want type %s", name, schema.Properties[name], want)
			}
		}
		if !reflect.DeepEqual(schema.Required, []string{"address"}) {
			t.Fatalf("unexpected required selectors: %v", schema.Required)
		}
		return
	}
	t.Fatal("original r2 tools/list omitted disassemble_function")
}
