package appinspect

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/backend"
	"reverseresearch/internal/securefile"
	"reverseresearch/internal/toolindex"
)

type AndroidRecoveryOptions struct {
	PageOptions
	View                 string `json:"view"`
	ClassName            string `json:"class_name,omitempty"`
	MethodName           string `json:"method_name,omitempty"`
	OverloadIndex        *int   `json:"overload_index,omitempty"`
	Query                string `json:"query,omitempty"`
	ExpectedResultSHA256 string `json:"expected_result_sha256,omitempty"`
}

type AndroidProducerObservation struct {
	Tool           string `json:"tool"`
	ResponseSHA256 string `json:"response_sha256"`
	ResponseBytes  int    `json:"response_bytes"`
}

type AndroidRecoveryReport struct {
	Path                  string                       `json:"path"`
	SHA256                string                       `json:"sha256"`
	View                  string                       `json:"view"`
	EngineSHA256          string                       `json:"engine_sha256"`
	BridgeSHA256          string                       `json:"bridge_sha256"`
	ResultSHA256          string                       `json:"result_sha256"`
	JavaVersion           string                       `json:"java_version,omitempty"`
	MaxHeapBytes          int64                        `json:"max_heap_bytes,omitempty"`
	TotalBytes            int                          `json:"total_bytes"`
	Offset                int                          `json:"offset"`
	NextOffset            *int                         `json:"next_offset,omitempty"`
	ReadBytes             int                          `json:"read_bytes"`
	DataBase64            string                       `json:"data_base64"`
	Observations          []AndroidProducerObservation `json:"producer_observations"`
	ProducerResponses     int                          `json:"producer_responses"`
	ProducerTraceSHA256   string                       `json:"producer_trace_sha256,omitempty"`
	ObservationsTruncated bool                         `json:"observations_truncated"`
	CleanupVerified       bool                         `json:"cleanup_verified"`
	ExecutionPerformed    bool                         `json:"target_execution_performed"`
	Limitations           []string                     `json:"limitations"`
}

// RecoverAndroid uses one immutable private target/engine/metadata bridge and
// the original backend lifecycle. Each request closes its session before the
// workspace is removed. No retained session or new durable record is created.
func RecoverAndroid(parent context.Context, root, path string, o AndroidRecoveryOptions) (report AndroidRecoveryReport, resultErr error) {
	if parent == nil {
		return report, errors.New("Android recovery requires a caller context")
	}
	if err := parent.Err(); err != nil {
		return report, err
	}
	if o.View == "" {
		o.View = "classes"
	}
	if o.View != "classes" && o.View != "class" && o.View != "method" && o.View != "references" {
		return report, errors.New("Android recovery view must be classes, class, method or references")
	}
	if o.Offset < 0 || o.Limit < 0 || o.Limit > 16384 {
		return report, errors.New("Android recovery byte page outside profile")
	}
	if len(o.ClassName) > 4096 || len(o.MethodName) > 4096 || len(o.Query) > 4096 || (o.OverloadIndex != nil && (*o.OverloadIndex < 0 || *o.OverloadIndex > 65535)) {
		return report, errors.New("Android recovery selector exceeds profile")
	}
	if o.ExpectedResultSHA256 != "" {
		if b, err := hex.DecodeString(o.ExpectedResultSHA256); err != nil || len(b) != sha256.Size {
			return report, errors.New("Android derived result digest must be SHA256 hex")
		}
	}
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.Offset > 0 && (o.ExpectedSHA256 == "" || o.ExpectedResultSHA256 == "") {
		return report, errors.New("subsequent Android recovery pages require artifact and result digests")
	}
	if o.View != "classes" && o.ClassName == "" || o.View == "method" && o.MethodName == "" {
		return report, errors.New("exact class and selected method names required")
	}
	if o.View == "classes" && (o.ClassName != "" || o.MethodName != "" || o.OverloadIndex != nil) || o.View != "classes" && o.Query != "" || o.View == "class" && (o.MethodName != "" || o.OverloadIndex != nil) || o.View == "references" && o.OverloadIndex != nil {
		return report, errors.New("Android recovery selectors do not match selected view")
	}
	body, abs, sha, err := readArtifact(path, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return report, err
	}
	report = AndroidRecoveryReport{Path: abs, SHA256: sha, View: o.View, Limitations: []string{"JADX derived Java/smali text and parsed display signatures are not byte-equivalent reconstruction or observed runtime calls", "provider overload indexes are artifact/engine-local; exact DEX identities remain in app_dex_inspect", "class discovery lists top-level producer names; inner classes are available through exact class metadata", "producer text is capped at 1MiB; completeness is unknown and fallback markers are preserved", "static reference locations and JNI bindings are unknown; no signature/install/device verification"}}
	suffix := ".dex"
	if strings.HasPrefix(string(body[:min(4, len(body))]), "dex\n") {
		if _, err := parseDEX(body); err != nil {
			return report, err
		}
	} else {
		_, entries, err := parseZIP(body)
		if err != nil {
			return report, err
		}
		found := false
		var expanded uint64
		for _, entry := range entries {
			if entry.Kind != "directory" && !entry.Available {
				return report, errors.New("Android recovery archive has unavailable entries")
			}
			if entry.Size > uint64(MaxArtifactBytes)-expanded {
				return report, errors.New("Android recovery expanded archive exceeds profile")
			}
			expanded += entry.Size
			if entry.Path == "AndroidManifest.xml" {
				found = true
			}
		}
		if !found {
			return report, errors.New("Android recovery archive must have root AndroidManifest.xml")
		}
		suffix = ".apk"
	}
	jarPath, bridgePath := toolindex.JADXPaths(root)
	jar, _, jarSHA, err := readArtifact(jarPath, 128<<20, toolindex.JADXEngineSHA256)
	if err != nil {
		return report, fmt.Errorf("pinned JADX engine not available: %w", err)
	}
	bridge, _, bridgeSHA, err := readArtifact(bridgePath, 1<<20, "")
	if err != nil {
		return report, err
	}
	report.EngineSHA256, report.BridgeSHA256 = jarSHA, bridgeSHA
	index, err := toolindex.Scan(root)
	if err != nil {
		return report, err
	}
	java, ok := index.ByName("java21")
	if !ok || !java.Available {
		return report, errors.New("JADX requires the existing Java21 ToolIndex profile")
	}
	profile, ok := index.ByName("jadx-headless")
	if !ok || !profile.Available {
		return report, fmt.Errorf("JADX interpreted runtime profile unavailable: %s", profile.IdentityError)
	}
	base := filepath.Join(root, "state", "tmp")
	if err := os.MkdirAll(base, 0700); err != nil {
		return report, err
	}
	if err := securefile.RestrictDir(base); err != nil {
		return report, err
	}
	work, err := os.MkdirTemp(base, "rr-jadx-")
	if err != nil {
		return report, err
	}
	var engine *backend.Lazy
	defer func() {
		if engine != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := engine.CloseContext(closeCtx); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("JADX cleanup unverified; private workspace retained at %s: %w", work, err))
				return
			}
		}
		if errors.Is(resultErr, backend.ErrJADXCleanupUnverified) {
			resultErr = errors.Join(resultErr, fmt.Errorf("JADX private workspace retained at %s", work))
			return
		}
		report.CleanupVerified = true
		if err := os.RemoveAll(work); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove owned JADX workspace: %w", err))
			report.CleanupVerified = false
		}
	}()
	if err := securefile.RestrictDir(work); err != nil {
		return report, err
	}
	input := filepath.Join(work, "input"+suffix)
	copiedJar := filepath.Join(work, "engine.jar")
	copiedBridge := filepath.Join(work, "ReverseResearchJadxBridge.java")
	for name, data := range map[string][]byte{input: body, copiedJar: jar, copiedBridge: bridge} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			return report, err
		}
		if err := securefile.RestrictFile(name); err != nil {
			return report, err
		}
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	engine = backend.NewJADX(java.Path, copiedJar, copiedBridge, work)
	trace := sha256.New()
	defer func() { report.ProducerTraceSHA256 = hex.EncodeToString(trace.Sum(nil)) }()
	call := func(name string, args map[string]any) (map[string]any, error) {
		raw, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		r, err := engine.Call(ctx, name, raw)
		if err != nil {
			return nil, err
		}
		if r == nil || len(r.Content) != 1 {
			return nil, errors.New("JADX result envelope missing or ambiguous")
		}
		text, ok := r.Content[0].(*mcp.TextContent)
		if !ok || len(text.Text) > 8<<20 {
			return nil, errors.New("JADX result exceeds text/profile boundary")
		}
		fmt.Fprintf(trace, "%d:%s:%d:", len(name), name, len(text.Text))
		_, _ = trace.Write([]byte(text.Text))
		report.ProducerResponses++
		observation := AndroidProducerObservation{name, digest([]byte(text.Text)), len(text.Text)}
		if len(report.Observations) < 32 {
			report.Observations = append(report.Observations, observation)
		} else {
			report.Observations[31] = observation
			report.ObservationsTruncated = true
		}
		if r.IsError {
			return nil, fmt.Errorf("JADX %s rejected: %s", name, text.Text[:min(len(text.Text), 1500)])
		}
		var value map[string]any
		if err := json.Unmarshal([]byte(text.Text), &value); err != nil {
			return nil, fmt.Errorf("JADX invalid producer JSON: %w", err)
		}
		if value == nil || value["error"] != nil {
			return nil, fmt.Errorf("JADX %s returned an error payload", name)
		}
		return value, nil
	}
	jvm, err := call("rr_jvm_status", map[string]any{})
	if err != nil {
		return report, err
	}
	if jvm["engine_reported_version"] != "0.7.1" {
		return report, errors.New("JADX reported engine version differs from pinned profile")
	}
	javaVersion, versionOK := jvm["java_version"].(string)
	heap, heapOK := jvm["max_heap_bytes"].(float64)
	if !versionOK || (javaVersion != "21" && !strings.HasPrefix(javaVersion, "21.") && !strings.HasPrefix(javaVersion, "21-")) || !heapOK || heap <= 0 || heap > 1024<<20 || heap != float64(int64(heap)) {
		return report, errors.New("JADX JVM observation outside the heap/version profile")
	}
	report.JavaVersion, report.MaxHeapBytes = javaVersion, int64(heap)
	if _, err := call("load_apk", map[string]any{"path": input}); err != nil {
		return report, err
	}
	var selected any
	if o.View == "classes" {
		rows := []string{}
		total := -1
		for offset := 0; ; {
			v, err := call("list_classes", map[string]any{"offset": offset, "limit": 200})
			if err != nil {
				return report, err
			}
			n, nOK := v["total"].(float64)
			items, iOK := v["items"].([]any)
			if !nOK || n < 0 || n > 65536 || n != float64(int(n)) || !iOK {
				return report, errors.New("JADX class page counts invalid")
			}
			if total < 0 {
				total = int(n)
			} else if total != int(n) {
				return report, errors.New("JADX class total changed across pages")
			}
			if v["offset"] != float64(offset) || len(items) != min(200, total-offset) {
				return report, errors.New("JADX class page incomplete")
			}
			for _, item := range items {
				name, ok := item.(string)
				if !ok {
					return report, errors.New("JADX class row is not a name")
				}
				if strings.Contains(name, o.Query) {
					rows = append(rows, name)
				}
			}
			offset += len(items)
			if offset == total {
				break
			}
		}
		selected = map[string]any{"query": o.Query, "total_class_rows": total, "matching_rows": rows, "duplicates_preserved": true}
	} else {
		summary, err := call("get_class_summary", map[string]any{"class_name": o.ClassName})
		if err != nil {
			return report, err
		}
		if summary["full_name"] != o.ClassName {
			return report, errors.New("JADX exact class selector resolved to a different class")
		}
		methods, ok := summary["methods"].([]any)
		if !ok || summary["method_count"] != float64(len(methods)) {
			return report, errors.New("JADX parsed method inventory/count differs")
		}
		matches := 0
		matchingMethods := []map[string]any{}
		for _, item := range methods {
			method, ok := item.(map[string]any)
			if !ok {
				return report, errors.New("JADX method metadata invalid")
			}
			if method["name"] == o.MethodName {
				matches++
				matchingMethods = append(matchingMethods, method)
			}
		}
		switch o.View {
		case "class":
			selected = summary
		case "method":
			if matches == 0 {
				return report, errors.New("JADX selected method not in parsed inventory")
			}
			if matches > 1 && o.OverloadIndex == nil {
				return report, errors.New("ambiguous JADX method requires explicit overload_index")
			}
			ordinal := 0
			if o.OverloadIndex != nil {
				ordinal = *o.OverloadIndex
			}
			if ordinal < 0 || ordinal >= matches {
				return report, errors.New("JADX overload_index outside selected inventory")
			}
			v, err := call("get_method_body", map[string]any{"class_name": o.ClassName, "method_name": o.MethodName, "overload_index": ordinal})
			if err != nil {
				return report, err
			}
			if v["class_name"] != o.ClassName || v["method_name"] != o.MethodName || v["overload_index"] != float64(ordinal) || v["overload_count"] != float64(matches) {
				return report, errors.New("JADX method result does not match selected overload identity")
			}
			if err := validateAndroidMethod(v, matchingMethods[ordinal]); err != nil {
				return report, err
			}
			selected = v
		case "references":
			name, args := "get_xrefs_to_class", map[string]any{"class_name": o.ClassName}
			if o.MethodName != "" {
				if matches != 1 {
					return report, errors.New("JADX method references require a unique method; overload selection unsupported")
				}
				name = "get_xrefs_to_method"
				args["method_name"] = o.MethodName
			}
			v, err := call(name, args)
			if err != nil {
				return report, err
			}
			target := o.ClassName
			if o.MethodName != "" {
				target += "." + o.MethodName
			}
			if err := validateAndroidReferences(v, target); err != nil {
				return report, err
			}
			selected = v
		}
	}
	canonical, err := json.Marshal(selected)
	if err != nil {
		return report, err
	}
	if len(canonical) > 8<<20 {
		return report, errors.New("JADX canonical result exceeds 8MiB")
	}
	report.ResultSHA256 = digest(canonical)
	if o.ExpectedResultSHA256 != "" && !strings.EqualFold(o.ExpectedResultSHA256, report.ResultSHA256) {
		return report, errors.New("JADX derived result changed; restart paging")
	}
	if o.Offset > len(canonical) {
		return report, errors.New("Android recovery byte offset outside result")
	}
	end := min(len(canonical), o.Offset+o.Limit)
	report.Offset, report.TotalBytes, report.ReadBytes = o.Offset, len(canonical), end-o.Offset
	report.DataBase64 = base64.StdEncoding.EncodeToString(canonical[o.Offset:end])
	if end < len(canonical) {
		report.NextOffset = &end
	}
	_, _, after, err := readArtifact(path, MaxArtifactBytes, sha)
	if err != nil || after != sha {
		return report, errors.Join(errors.New("JADX original artifact changed during recovery"), err)
	}
	return report, projectionLimit(report)
}

func validateAndroidMethod(v, metadata map[string]any) error {
	id, ok := v["producer_short_id"].(string)
	code, codeOK := v["code_available"].(bool)
	body, bodyOK := v["body"].(string)
	_, fallbackOK := v["fell_back"].(bool)
	markers, markersOK := v["markers"].([]any)
	mode, modeOK := v["mode"].(string)
	if !ok || id == "" || id != metadata["producer_short_id"] || !codeOK || code != metadata["code_available"] || !bodyOK || len(body) > 1<<20 || !fallbackOK || !markersOK || !modeOK || (mode != "java" && mode != "smali") {
		return errors.New("JADX body/parsed identity or source profile differs")
	}
	for _, marker := range markers {
		if _, ok := marker.(string); !ok {
			return errors.New("JADX fallback marker is not text")
		}
	}
	return nil
}

func validateAndroidReferences(v map[string]any, target string) error {
	items, ok := v["items"].([]any)
	if !ok || v["target"] != target || v["total"] != float64(len(items)) || v["count"] != float64(len(items)) || v["resolve_line"] != false {
		return errors.New("JADX static reference identity/count differs")
	}
	for _, item := range items {
		if _, ok := item.(map[string]any); !ok {
			return errors.New("JADX static reference row is not metadata")
		}
	}
	return nil
}
