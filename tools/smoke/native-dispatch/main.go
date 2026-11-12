// native-dispatch records bounded read-only queries against one owned Ghidra
// session. PASS describes this harness's checks, never research completion.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/backend"
	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

const (
	databaseID     = "wf17_dispatch"
	maxQueries     = 16
	maxQueryBytes  = 64 << 10
	maxTargetBytes = 128 << 20
	totalBudget    = 4 * time.Minute
	analysisBudget = 3*time.Minute + 15*time.Second
)

type options struct {
	root, target, expectedSHA, work, queries string
	port                                     int
}

type query struct {
	Tool      string                     `json:"tool"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}

type callSummary struct {
	Tool         string `json:"tool"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	OutputBytes  int    `json:"output_bytes"`
	OutputSHA256 string `json:"output_sha256"`
	ResultPath   string `json:"result_path"`
	FileSHA256   string `json:"file_sha256,omitempty"`
	Error        string `json:"error,omitempty"`
}

type receipt struct {
	Schema                   string                   `json:"schema"`
	Status                   string                   `json:"status"`
	StartedUTC               string                   `json:"started_utc"`
	EndedUTC                 string                   `json:"ended_utc,omitempty"`
	ElapsedMS                int64                    `json:"elapsed_ms"`
	WorkDir                  string                   `json:"work_dir"`
	Root                     string                   `json:"root"`
	Port                     int                      `json:"port"`
	Database                 string                   `json:"database"`
	StateDir                 string                   `json:"state_dir"`
	EvidenceDir              string                   `json:"evidence_dir"`
	QueriesSHA256            string                   `json:"queries_sha256,omitempty"`
	ExpectedSHA256           string                   `json:"expected_sha256"`
	QueryCount               int                      `json:"query_count"`
	Source                   *targetidentity.Identity `json:"source_identity,omitempty"`
	Frozen                   *targetidentity.Identity `json:"frozen_identity,omitempty"`
	SourceAfter              *targetidentity.Identity `json:"source_after,omitempty"`
	FrozenAfter              *targetidentity.Identity `json:"frozen_after,omitempty"`
	SourceUnchanged          bool                     `json:"source_unchanged"`
	FrozenUnchanged          bool                     `json:"frozen_unchanged"`
	DatabaseClosed           bool                     `json:"database_closed"`
	BackendClosed            bool                     `json:"backend_closed"`
	ShutdownVerified         bool                     `json:"shutdown_verified"`
	ResearchComplete         bool                     `json:"research_complete"`
	TargetExecutionPerformed bool                     `json:"target_execution_performed"`
	Measurement              string                   `json:"measurement"`
	Calls                    []callSummary            `json:"calls"`
	Error                    string                   `json:"error,omitempty"`
}

type summary struct {
	Status           string        `json:"status"`
	ElapsedMS        int64         `json:"elapsed_ms"`
	OutputBytes      int           `json:"output_bytes"`
	ResultPath       string        `json:"result_path,omitempty"`
	SHA256           string        `json:"sha256,omitempty"`
	ShutdownVerified bool          `json:"shutdown_verified"`
	ResearchComplete bool          `json:"research_complete"`
	Calls            []callSummary `json:"calls,omitempty"`
	Error            string        `json:"error,omitempty"`
}

func main() {
	var o options
	flag.StringVar(&o.root, "root", ".", "ReverseResearch repository root")
	flag.StringVar(&o.target, "target", "", "native artifact to inspect; never executed")
	flag.StringVar(&o.expectedSHA, "expected-sha256", "", "required exact target SHA-256")
	flag.StringVar(&o.work, "work-dir", "", "new operation directory with no dot-prefixed path elements")
	flag.IntVar(&o.port, "port", 19197, "unused isolated Ghidra port; never 19096")
	flag.StringVar(&o.queries, "queries", "", "JSON array of at most 16 {tool,arguments} read-only queries")
	flag.Parse()
	result, err := run(o)
	if err != nil {
		result.Status, result.Error = "FAILED", err.Error()
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		err = errors.Join(err, encodeErr)
	}
	if err != nil {
		// All deferred cleanup and receipt publication are inside run, which has
		// already returned. This exit cannot skip a backend cleanup defer.
		os.Exit(1)
	}
}

func run(o options) (out summary, err error) {
	started := time.Now()
	if strings.TrimSpace(o.work) == "" {
		return out, errors.New("work-dir is required")
	}
	work, err := filepath.Abs(o.work)
	if err != nil {
		return out, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(work))
	if err != nil {
		return out, fmt.Errorf("resolve existing work-dir parent: %w", err)
	}
	work = filepath.Join(parent, filepath.Base(work))
	if hasDotElement(work) {
		return out, errors.New("work-dir cannot contain dot-prefixed path elements")
	}
	out.ResultPath = filepath.Join(work, "receipt.json")
	if err = os.Mkdir(work, 0o700); err != nil {
		return out, fmt.Errorf("work-dir must be new; inspect the existing receipt instead of repeating this operation: %w", err)
	}

	ctx, cancel := context.WithDeadline(context.Background(), started.Add(totalBudget))
	defer cancel()
	r := &receipt{Schema: "native-dispatch-smoke.v1", Status: "RUNNING",
		StartedUTC: started.UTC().Format(time.RFC3339Nano), WorkDir: work,
		Port: o.port, Database: databaseID, StateDir: filepath.Join(work, "state"),
		EvidenceDir: filepath.Join(work, "evidence"), Calls: []callSummary{},
		ExpectedSHA256: o.expectedSHA,
		Measurement:    "output_bytes counts serialized MCP CallToolResult JSON, not wire bytes or tokens"}
	var h *harness
	defer func() {
		if h != nil {
			if h.usable && h.openAttempted {
				closed, closeErr := h.call(ctx, "close_database", map[string]any{"database": databaseID, "save": false})
				if closeErr == nil {
					value, parseErr := resultObject(closed)
					if parseErr != nil {
						closeErr = parseErr
					} else if value["status"] != "closed" || value["saved"] != false || value["database"] != databaseID {
						closeErr = errors.New("close_database did not confirm this database closed with save=false")
					}
				}
				r.DatabaseClosed = closeErr == nil
				err = errors.Join(err, closeErr)
			}
			closeErr := h.backend.CloseContext(ctx)
			r.BackendClosed = closeErr == nil
			err = errors.Join(err, closeErr)
			r.ShutdownVerified = r.DatabaseClosed && r.BackendClosed
		}
		if r.Source != nil {
			var checkErr error
			r.SourceAfter, checkErr = recheck(ctx, r.Source)
			r.SourceUnchanged = checkErr == nil
			err = errors.Join(err, checkErr)
		}
		if r.Frozen != nil {
			var checkErr error
			r.FrozenAfter, checkErr = recheck(ctx, r.Frozen)
			r.FrozenUnchanged = checkErr == nil
			err = errors.Join(err, checkErr)
		}
		r.Status = "PASS"
		if err != nil {
			r.Status, r.Error = "FAILED", err.Error()
		}
		r.EndedUTC, r.ElapsedMS = time.Now().UTC().Format(time.RFC3339Nano), time.Since(started).Milliseconds()
		body, writeErr := writeJSON(out.ResultPath, r)
		err = errors.Join(err, writeErr)
		out.Status, out.ElapsedMS, out.Calls = r.Status, r.ElapsedMS, r.Calls
		out.ShutdownVerified = r.ShutdownVerified
		if writeErr == nil {
			out.SHA256 = digest(body)
		}
		for _, call := range r.Calls {
			out.OutputBytes += call.OutputBytes
		}
	}()

	if _, err = writeJSON(out.ResultPath, r); err != nil {
		return out, err
	}
	if o.port < 1024 || o.port > 65535 || o.port == 19096 {
		return out, errors.New("port must be 1024..65535 and must not be 19096")
	}
	if o.target == "" || o.queries == "" {
		return out, errors.New("target and queries are required")
	}
	expected, decodeErr := hex.DecodeString(o.expectedSHA)
	if decodeErr != nil || len(expected) != sha256.Size {
		return out, errors.New("expected-sha256 must contain exactly 64 hexadecimal characters")
	}
	r.Root, err = filepath.Abs(o.root)
	if err != nil {
		return out, err
	}
	queryBody, querySHA, err := readQueryFile(ctx, o.queries)
	if err != nil {
		return out, fmt.Errorf("capture queries: %w", err)
	}
	queries, err := parseQueries(queryBody)
	if err != nil {
		return out, err
	}
	r.QueriesSHA256, r.QueryCount = querySHA, len(queries)
	if err = recordio.WriteFile(filepath.Join(work, "queries.json"), queryBody, 0o600); err != nil {
		return out, err
	}
	identity, err := targetidentity.InspectBoundedContext(ctx, o.target, maxTargetBytes)
	if err != nil {
		return out, err
	}
	r.Source = &identity
	if !strings.EqualFold(identity.SHA256, o.expectedSHA) {
		return out, errors.New("source identity does not match expected-sha256")
	}
	frozenPath := filepath.Join(work, "rr_"+identity.SHA256+".bin")
	r.Frozen, err = prepareFixture(ctx, identity, frozenPath)
	if err != nil {
		return out, err
	}
	if err = os.Mkdir(filepath.Join(work, "calls"), 0o700); err != nil {
		return out, err
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", o.port))
	if err != nil {
		return out, fmt.Errorf("isolated port is unavailable: %w", err)
	}
	if err = listener.Close(); err != nil {
		return out, err
	}
	if _, err = writeJSON(out.ResultPath, r); err != nil {
		return out, err
	}
	h = &harness{backend: backend.NewGhidraIsolated(r.Root, r.StateDir, r.EvidenceDir, o.port), receipt: r, usable: true}
	analysisCtx, analysisCancel := context.WithDeadline(ctx, started.Add(analysisBudget))
	defer analysisCancel()
	h.openAttempted = true
	if _, err = h.call(analysisCtx, "open_database", map[string]any{"file_path": frozenPath,
		"database_id": databaseID, "run_auto_analysis": true, "keep_open": true, "force_new": true}); err != nil {
		return out, err
	}
	ready, err := h.call(analysisCtx, "wait_for_analysis", map[string]any{"database": databaseID})
	if err != nil {
		return out, err
	}
	readyValue, err := resultObject(ready)
	if err != nil {
		return out, err
	}
	if readyValue["status"] != "ready" || readyValue["database"] != databaseID {
		return out, errors.New("wait_for_analysis did not confirm this database ready")
	}
	info, err := h.call(analysisCtx, "get_database_info", map[string]any{"database": databaseID})
	if err != nil {
		return out, err
	}
	infoValue, err := resultObject(info)
	if err != nil {
		return out, err
	}
	gotPath, _ := infoValue["file_path"].(string)
	if infoValue["database"] != databaseID || !samePath(gotPath, frozenPath) {
		return out, errors.New("database identity/path differs from the frozen copy")
	}
	for _, q := range queries {
		if _, err = h.call(analysisCtx, "call", queryCallArgs(q)); err != nil {
			return out, err
		}
	}
	return out, nil
}

type harness struct {
	backend               *backend.Lazy
	receipt               *receipt
	usable, openAttempted bool
}

func (h *harness) call(ctx context.Context, tool string, args any) (*mcp.CallToolResult, error) {
	encoded, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	result, callErr := h.backend.Call(ctx, tool, encoded)
	if callErr != nil {
		h.usable = false
	} // Lazy retired it; cleanup must never start a new generation.
	if callErr == nil && result == nil {
		callErr = errors.New("backend returned no MCP result")
	}
	if result != nil && result.IsError {
		callErr = errors.Join(callErr, errors.New("MCP IsError=true; inspect the saved result"))
	}
	raw, marshalErr := json.Marshal(result)
	path := filepath.Join(h.receipt.WorkDir, "calls", fmt.Sprintf("%03d-%s.json", len(h.receipt.Calls)+1, tool))
	item := callSummary{Tool: tool, ElapsedMS: time.Since(started).Milliseconds(), ResultPath: path}
	if marshalErr == nil && result != nil {
		item.OutputBytes, item.OutputSHA256 = len(raw), digest(raw)
	}
	envelope := struct {
		Tool      string              `json:"tool"`
		Arguments json.RawMessage     `json:"arguments"`
		Result    *mcp.CallToolResult `json:"result"`
		Error     string              `json:"error,omitempty"`
	}{Tool: tool, Arguments: encoded, Result: result}
	if callErr != nil {
		envelope.Error = callErr.Error()
	}
	body, writeErr := writeJSON(path, envelope)
	if writeErr == nil {
		item.FileSHA256 = digest(body)
	}
	err = errors.Join(callErr, marshalErr, writeErr)
	if err != nil {
		item.Error = err.Error()
	}
	h.receipt.Calls = append(h.receipt.Calls, item)
	_, receiptErr := writeJSON(filepath.Join(h.receipt.WorkDir, "receipt.json"), h.receipt)
	return result, errors.Join(err, receiptErr)
}

func parseQueries(body []byte) ([]query, error) {
	if len(body) > maxQueryBytes {
		return nil, errors.New("queries exceeds 64 KiB")
	}
	if !utf8.Valid(body) {
		return nil, errors.New("queries must be UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var queries []query
	for decoder.More() {
		if len(queries) == maxQueries {
			return nil, errors.New("queries must contain 1..16 entries")
		}
		q, err := parseQuery(decoder)
		if err != nil {
			return nil, fmt.Errorf("query %d: %w", len(queries), err)
		}
		queries = append(queries, q)
	}
	if err := expectDelimiter(decoder, ']'); err != nil {
		return nil, err
	}
	if err := expectEOF(decoder); err != nil {
		return nil, err
	}
	if len(queries) == 0 {
		return nil, errors.New("queries must contain 1..16 entries")
	}
	return queries, nil
}

// This is the smoke's fixed configuration shape, not an artifact JSON parser:
// array -> {tool, arguments} -> flat string/number arguments. No recursion.
func parseQuery(decoder *json.Decoder) (query, error) {
	q := query{Arguments: map[string]json.RawMessage{}}
	if err := expectDelimiter(decoder, '{'); err != nil {
		return q, err
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return q, err
		}
		key, ok := token.(string)
		if !ok || (key != "tool" && key != "arguments") || seen[key] {
			return q, errors.New("query has an unknown or duplicate field")
		}
		seen[key] = true
		if key == "tool" {
			if err := decoder.Decode(&q.Tool); err != nil {
				return q, errors.New("tool must be a string")
			}
		} else {
			q.Arguments, err = parseQueryArguments(decoder)
			if err != nil {
				return q, err
			}
		}
	}
	if err := expectDelimiter(decoder, '}'); err != nil {
		return q, err
	}
	return q, validateQuery(&q)
}

func parseQueryArguments(decoder *json.Decoder) (map[string]json.RawMessage, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	arguments := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("argument key must be a string")
		}
		if _, duplicate := arguments[key]; duplicate {
			return nil, errors.New("duplicate argument key")
		}
		value, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch value.(type) {
		case string, json.Number:
			arguments[key], err = json.Marshal(value)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("arguments must be flat strings or numbers")
		}
	}
	return arguments, expectDelimiter(decoder, '}')
}

func expectDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != want {
		return fmt.Errorf("expected JSON delimiter %q", want)
	}
	return nil
}

func expectEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON contains trailing content or an invalid ending")
	}
	return nil
}

func validateQuery(q *query) error {
	fields := ""
	switch q.Tool {
	case "get_function", "disassemble_function", "decompile_function", "get_switch_info", "get_basic_blocks", "get_cfg_edges":
		fields = " address "
	case "get_xrefs_to", "get_xrefs_from":
		fields = " address offset limit "
	case "get_call_graph":
		fields = " address depth "
	case "list_switches", "list_functions":
		fields = " offset limit "
	case "read_bytes":
		fields = " address size "
	default:
		return errors.New("tool is not on the explicit read-only allowlist")
	}
	for key := range q.Arguments {
		allowed := false
		for _, field := range strings.Fields(fields) {
			if key == field {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("argument is not allowed; database selection is owned by this harness")
		}
	}
	if strings.Contains(fields, " address ") {
		var address string
		if err := json.Unmarshal(q.Arguments["address"], &address); err != nil || len(address) == 0 || len(address) > 256 || strings.IndexByte(address, 0) >= 0 {
			return errors.New("address must be a nonempty string of at most 256 bytes without NUL")
		}
	}
	for key, bounds := range map[string][2]int{"offset": {0, 1000000}, "limit": {1, 200}, "depth": {1, 3}, "size": {1, 4096}} {
		if raw, ok := q.Arguments[key]; ok {
			var n *int
			if err := json.Unmarshal(raw, &n); err != nil || n == nil || *n < bounds[0] || *n > bounds[1] {
				return fmt.Errorf("%s must be an integer in %d..%d", key, bounds[0], bounds[1])
			}
		}
	}
	return nil
}

func queryCallArgs(q query) map[string]any {
	// The existing hidden-tool gateway injects this top-level database into
	// the inner request. Keep database selection in this one harness owner.
	arguments := make(map[string]json.RawMessage, len(q.Arguments))
	for key, value := range q.Arguments {
		if key != "database" {
			arguments[key] = value
		}
	}
	return map[string]any{"tool": q.Tool, "arguments": arguments, "database": databaseID}
}

func resultObject(result *mcp.CallToolResult) (map[string]any, error) {
	if result == nil || result.IsError {
		return nil, errors.New("a successful MCP object result is required")
	}
	var body []byte
	if result.StructuredContent != nil {
		var err error
		body, err = json.Marshal(result.StructuredContent)
		if err != nil {
			return nil, err
		}
	} else if len(result.Content) == 1 {
		text, ok := result.Content[0].(*mcp.TextContent)
		if !ok {
			return nil, errors.New("MCP result did not contain a JSON text object")
		}
		body = []byte(text.Text)
	}
	if !utf8.Valid(body) {
		return nil, errors.New("MCP lifecycle object must be UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := expectDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	value := map[string]any{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("MCP lifecycle key must be a string")
		}
		if _, duplicate := value[key]; duplicate {
			return nil, errors.New("duplicate MCP lifecycle field")
		}
		// Only lifecycle top-level fields carry harness decisions. Nested
		// provider facets remain ordinary SDK JSON, without recursive validation.
		var field any
		if err := decoder.Decode(&field); err != nil {
			return nil, err
		}
		value[key] = field
	}
	if err := expectDelimiter(decoder, '}'); err != nil {
		return nil, err
	}
	if err := expectEOF(decoder); err != nil {
		return nil, err
	}
	return value, nil
}

// Read only the smoke's bounded query configuration. Identity/currentness
// remains with the committed targetidentity API rather than a new snapshot API.
func readQueryFile(ctx context.Context, path string) (body []byte, hash string, err error) {
	admitted, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if !admitted.Mode().IsRegular() {
		return nil, "", errors.New("queries must be a regular file without a final symlink")
	}
	before, err := targetidentity.InspectBoundedContext(ctx, path, maxQueryBytes)
	if err != nil {
		return nil, "", err
	}
	file, err := os.Open(before.Path)
	if err != nil {
		return nil, "", err
	}
	body, readErr := io.ReadAll(io.LimitReader(budgetReader{ctx: ctx, reader: file}, maxQueryBytes+1))
	if err = errors.Join(readErr, file.Close()); err != nil {
		return nil, "", err
	}
	if len(body) > maxQueryBytes {
		return nil, "", errors.New("queries exceeds 64 KiB")
	}
	after, err := targetidentity.InspectBoundedContext(ctx, path, maxQueryBytes)
	if err != nil {
		return nil, "", err
	}
	hash = digest(body)
	if int64(len(body)) != before.Size || hash != before.SHA256 || after.SHA256 != before.SHA256 || after.Size != before.Size || !samePath(after.Path, before.Path) {
		return nil, "", errors.New("query configuration changed during read")
	}
	return body, hash, nil
}

// This one-shot test preparation copies bytes to an exclusive operation-local
// file. Both sides are inspected by the existing identity owner after copying.
func prepareFixture(ctx context.Context, source targetidentity.Identity, destination string) (*targetidentity.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, err := os.Open(source.Path)
	if err != nil {
		return nil, err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.Join(err, input.Close())
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(budgetReader{ctx: ctx, reader: input}, maxTargetBytes+1))
	err = errors.Join(copyErr, input.Close(), output.Sync(), output.Chmod(0o400), output.Close())
	if n > maxTargetBytes || n != source.Size || hex.EncodeToString(hash.Sum(nil)) != source.SHA256 {
		err = errors.Join(err, errors.New("copied fixture size/SHA differs from frozen source identity"))
	}
	_, sourceErr := recheck(ctx, &source)
	frozen, frozenErr := targetidentity.InspectBoundedContext(ctx, destination, maxTargetBytes)
	err = errors.Join(err, sourceErr, frozenErr)
	if frozenErr != nil {
		return nil, err
	}
	if frozen.Size != source.Size || frozen.SHA256 != source.SHA256 {
		err = errors.Join(err, errors.New("prepared fixture identity differs from source"))
	}
	return &frozen, err
}

type budgetReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r budgetReader) Read(body []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(body)
}

func recheck(ctx context.Context, before *targetidentity.Identity) (*targetidentity.Identity, error) {
	after, err := targetidentity.InspectBoundedContext(ctx, before.Path, maxTargetBytes)
	if err != nil {
		return nil, fmt.Errorf("final identity check %s: %w", before.Path, err)
	}
	if after.SHA256 != before.SHA256 || after.Size != before.Size {
		return &after, fmt.Errorf("artifact changed: %s", before.Path)
	}
	return &after, nil
}

func writeJSON(path string, value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	return body, recordio.WriteFile(path, body, 0o600)
}

func digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func hasDotElement(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

func samePath(left, right string) bool {
	normalize := func(path string) string {
		if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
			path = path[1:]
		}
		return filepath.Clean(filepath.FromSlash(path))
	}
	left, right = normalize(left), normalize(right)
	if filepath.VolumeName(right) != "" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
