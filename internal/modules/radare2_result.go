package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const r2ResultMetaKey = "reverseresearch/r2-result"

// These are complete response profiles from the retained r2mcp 1.8.8 source,
// not searches for diagnostic words in decompiled code or arbitrary JSON.
var (
	r2CompletedHeader = regexp.MustCompile("^Analysis completed with level [0-4]\\.\nFound [0-9]+ functions\\.$")
	r2StoppedHeader   = regexp.MustCompile("^Analysis stopped after [0-9]+ seconds? at level [0-4]\\.\nFound [0-9]+ functions so far\\.$")
	r2CachedHeader    = regexp.MustCompile("^File was already analyzed at level [0-4]( \\(>= requested level [0-4]\\))?\\. Found [0-9]+ functions\\. Re-analysis skipped\\.$")
	r2LogLine         = regexp.MustCompile("^\\[(INFO|WARN|ERROR|FATAL|DEBUG)\\] [^\r\n]*$")
	r2TimeoutLine     = regexp.MustCompile("^\\[INFO\\] Timeout interruption after [0-9]+s$")
	r2MissingFunction = regexp.MustCompile("^\\[ERROR\\] Cannot find function (at|in) 0x[0-9a-fA-F]+$")
)

type r2ResultObservation struct {
	status string
	reason string
}

func r2ResultTool(module, tool string) bool {
	return module == "r2" && (tool == "analyze" || tool == "decompile_function" || tool == "disassemble_function")
}

func withR2ResultMetadata(module, tool string, result *mcp.CallToolResult) (*mcp.CallToolResult, error) {
	if !r2ResultTool(module, tool) || result == nil || result.IsError {
		return result, nil
	}
	observed := classifyR2ToolResult(tool, result)
	if tool != "analyze" && observed.status != "function_not_found" {
		// Ordinary function bodies keep their original success/flattening shape,
		// including metadata owned by the provider or another adapter.
		return result, nil
	}
	if _, exists := result.Meta[r2ResultMetaKey]; exists {
		return result, fmt.Errorf("r2 result metadata namespace collision at %s", r2ResultMetaKey)
	}
	clone := *result
	clone.Meta = make(mcp.Meta, len(result.Meta)+1)
	for key, value := range result.Meta {
		clone.Meta[key] = value
	}
	clone.Meta[r2ResultMetaKey] = map[string]any{
		"status":             observed.status,
		"completionVerified": false,
		"reason":             observed.reason,
	}
	return &clone, nil
}

// R2ToolResultIssue reports only an explicit timeout or missing-function
// observation in the retained provider response profiles. It does not verify
// completion, trust caller-supplied metadata, change IsError, or request a retry.
// Nil and original IsError results retain the caller's existing error handling.
func R2ToolResultIssue(module, tool string, result *mcp.CallToolResult) error {
	if !r2ResultTool(module, tool) || result == nil || result.IsError {
		return nil
	}
	observed := classifyR2ToolResult(tool, result)
	switch observed.status {
	case "timeout_observed", "function_not_found":
		return fmt.Errorf("r2 %s: %s", tool, observed.reason)
	default:
		return nil
	}
}

func classifyR2ToolResult(tool string, result *mcp.CallToolResult) r2ResultObservation {
	unknown := r2ResultObservation{"unknown", "response does not match a retained provider profile"}
	text, ok := r2ResultText(result)
	if !ok {
		return unknown
	}
	if tool != "analyze" {
		logs, ok := r2LogOnly(text)
		if ok && len(logs) == 1 && r2MissingFunction.MatchString(logs[0]) {
			return r2ResultObservation{"function_not_found", "provider reported function not found"}
		}
		return unknown
	}
	if r2CachedHeader.MatchString(text) {
		return r2ResultObservation{"cached_unverified", "provider skipped analysis using its cached level; completion is unverified"}
	}
	header, logs, valid := r2AnalysisResponse(text)
	if !valid {
		return unknown
	}
	if r2StoppedHeader.MatchString(header) && len(logs) > 0 {
		return r2ResultObservation{"timeout_observed", "provider reported analysis stopped because of timeout"}
	}
	if !r2CompletedHeader.MatchString(header) {
		return unknown
	}
	for _, line := range logs {
		if r2TimeoutLine.MatchString(line) || line == "[WARN] Stopped because of timeout" {
			return r2ResultObservation{"timeout_observed", "provider timeout log contradicts its completion header"}
		}
	}
	return r2ResultObservation{"provider_reported_completion", "provider reported completion; coverage and cached level are unverified"}
}

func r2AnalysisResponse(text string) (string, []string, bool) {
	header, tail, hasLog := strings.Cut(text, "\n\n<log>\n")
	if !hasLog {
		return text, nil, !strings.Contains(text, "<log>") && !strings.Contains(text, "</log>")
	}
	logs, ok := r2LogOnly("<log>\n" + tail)
	return header, logs, ok
}

func r2LogOnly(text string) ([]string, bool) {
	body, ok := strings.CutPrefix(text, "<log>\n")
	if !ok {
		return nil, false
	}
	body, ok = strings.CutSuffix(body, "\n</log>")
	if !ok {
		return nil, false
	}
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		if line == "" {
			continue
		}
		if !r2LogLine.MatchString(line) {
			return nil, false
		}
		lines = append(lines, line)
	}
	return lines, true
}

// structured/both mode mirrors the same payload in structuredContent and text
// JSON. Accept only a single "content" envelope, and require mirrors to agree.
func r2ResultText(result *mcp.CallToolResult) (string, bool) {
	var payload string
	seen := false
	add := func(text string, ok bool) bool {
		if !ok || len(text) > 64*1024 {
			return false
		}
		text = strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
		if seen && payload != text {
			return false
		}
		payload, seen = text, true
		return true
	}
	if result.StructuredContent != nil {
		if !add(r2StructuredText(result.StructuredContent)) {
			return "", false
		}
	}
	for _, content := range result.Content {
		text, ok := content.(*mcp.TextContent)
		if !ok || text == nil {
			return "", false
		}
		body := strings.TrimSpace(text.Text)
		if strings.HasPrefix(body, "{") {
			if !add(r2ContentEnvelope(body)) {
				return "", false
			}
		} else if !add(text.Text, true) {
			return "", false
		}
	}
	return payload, seen
}

func r2StructuredText(value any) (string, bool) {
	switch value := value.(type) {
	case map[string]any:
		text, ok := value["content"].(string)
		return text, ok && len(value) == 1
	case map[string]string:
		text, ok := value["content"]
		return text, ok && len(value) == 1
	case json.RawMessage:
		return r2ContentEnvelope(string(value))
	default:
		return "", false
	}
}

// Token-level shape checks also reject duplicate keys, additional fields,
// nested objects, and trailing JSON instead of treating them as diagnostics.
func r2ContentEnvelope(text string) (string, bool) {
	if len(text) > 64*1024 {
		return "", false
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return "", false
	}
	key, err := decoder.Token()
	if err != nil || key != "content" {
		return "", false
	}
	var content string
	if err = decoder.Decode(&content); err != nil {
		return "", false
	}
	close, err := decoder.Token()
	if err != nil || close != json.Delim('}') {
		return "", false
	}
	_, err = decoder.Token()
	return content, errors.Is(err, io.EOF)
}
