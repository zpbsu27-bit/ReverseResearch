package catalog

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed *.json
var manifests embed.FS

type Definition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func Load(name, prefix string) ([]*mcp.Tool, error) {
	body, err := manifests.ReadFile(name + ".json")
	if err != nil {
		return nil, fmt.Errorf("read %s manifest: %w", name, err)
	}
	var defs []Definition
	if err := json.Unmarshal(body, &defs); err != nil {
		return nil, fmt.Errorf("decode %s manifest: %w", name, err)
	}
	tools := make([]*mcp.Tool, 0, len(defs))
	seen := make(map[string]struct{}, len(defs))
	for _, def := range defs {
		if def.Name == "" {
			return nil, fmt.Errorf("%s manifest contains empty tool name", name)
		}
		publicName := prefix + def.Name
		if _, ok := seen[publicName]; ok {
			return nil, fmt.Errorf("%s manifest contains duplicate tool %q", name, publicName)
		}
		seen[publicName] = struct{}{}
		tools = append(tools, &mcp.Tool{
			Name:        publicName,
			Description: def.Description,
			InputSchema: def.InputSchema,
		})
	}
	return tools, nil
}
