package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (r *Runtime) addP0KnowledgeTools() {
	r.addTool(&mcp.Tool{
		Name:        "knowledge_pack_list",
		Description: "List reviewed Knowledge/Standards Packs that bind canonical standards and reviewed builtin knowledge to research domains/routes.",
		InputSchema: objectSchema(map[string]any{}),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := decodeArguments(request, &struct{}{}); err != nil {
			return nil, err
		}
		value, err := r.core.ListKnowledgePacks()
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "knowledge_pack_get",
		Description: "Get one reviewed Knowledge/Standards Pack including standards, canonical sources, routes, and bound builtin knowledge note IDs.",
		InputSchema: objectSchema(map[string]any{
			"pack_id": map[string]any{"type": "string", "minLength": 1},
		}, "pack_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PackID string `json:"pack_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.GetKnowledgePack(args.PackID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "knowledge_pack_route",
		Description: "Return all reviewed Knowledge/Standards Packs applicable to one canonical route. This does not classify tasks or replace the Router.",
		InputSchema: objectSchema(map[string]any{
			"route_id": map[string]any{"type": "string", "minLength": 1},
		}, "route_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			RouteID string `json:"route_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.KnowledgePacksForRoute(args.RouteID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})
}
