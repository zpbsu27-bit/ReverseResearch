package server

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/webinspect"
)

func (r *Runtime) addHARViewTools() {
	r.addTool(&mcp.Tool{Name: "web_har_api", Description: "Page a historical HAR API surface grouped by exact visible method/URL, with status/MIME counts and bounded producer ordinal samples. Query values/headers/cookies/bodies omitted; no schema inference, network, replay or live identity proof.", InputSchema: applicationSchema(nil)}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			webinspect.HAROptions
		}
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectWebHARAPI(a.Path, a.HAROptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "web_har_body_read", Description: "Explicitly read at most 16384 decoded producer body bytes from one selected HAR request/response entry as base64. Preserves unavailable/empty; does not prove original wire bytes or replay any request. May expose captured application data.", InputSchema: applicationSchema(map[string]any{"entry_ordinal": map[string]any{"type": "integer", "minimum": 0}, "side": map[string]any{"type": "string", "enum": []string{"request", "response"}}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}}, "entry_ordinal", "side")}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			webinspect.HARBodyOptions
		}
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		v, err := r.core.ReadWebHARBody(a.Path, a.HARBodyOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "web_har_compare", Description: "Compare historical HAR method/URL summaries with counts/status/MIME/query names and digest-fenced paging. Equal summaries exclude headers/bodies/query values and do not establish behavior or request equivalence. expected_sha256 pins comparison_sha256.", InputSchema: applicationSchema(map[string]any{"right_path": map[string]any{"type": "string", "minLength": 1}, "expected_left_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"}, "expected_right_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"}}, "right_path")}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path      string `json:"path"`
			RightPath string `json:"right_path"`
			webinspect.HARCompareOptions
		}
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		v, err := r.core.CompareWebHAR(a.Path, a.RightPath, a.HARCompareOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
}
