package backend

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const r2PaginationMetaKey = "reverseresearch/r2-pagination"

// r2PaginationTransport preserves the provider's nonstandard pagination member
// before the SDK decodes a CallToolResult. The original transport still owns
// connection/process lifecycle; this adapter never starts, retries or waits.
type r2PaginationTransport struct {
	mcp.Transport
}

func (t *r2PaginationTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &r2PaginationConnection{Connection: conn}, nil
}

type r2PaginationConnection struct {
	mcp.Connection
}

func (c *r2PaginationConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.Connection.Read(ctx)
	if err != nil {
		return msg, err
	}
	response, ok := msg.(*jsonrpc.Response)
	if !ok || response.Error != nil {
		return msg, nil
	}
	result, changed, err := preserveR2Pagination(response.Result)
	if err != nil {
		return nil, fmt.Errorf("radare2 pagination metadata: %w", err)
	}
	if !changed {
		return msg, nil
	}
	copy := *response
	copy.Result = result
	return &copy, nil
}

func preserveR2Pagination(result json.RawMessage) (json.RawMessage, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result, &fields); err != nil {
		// Non-tool messages and invalid results remain the SDK's responsibility.
		return result, false, nil
	}
	pagination, exists := fields["pagination"]
	if !exists {
		return result, false, nil
	}
	var content []json.RawMessage
	if err := json.Unmarshal(fields["content"], &content); err != nil || content == nil {
		return result, false, nil
	}
	if raw, exists := fields["isError"]; exists {
		var isError bool
		if err := json.Unmarshal(raw, &isError); err != nil || isError {
			return result, false, nil
		}
	}
	var meta map[string]json.RawMessage
	if raw, exists := fields["_meta"]; exists {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, false, fmt.Errorf("existing _meta is not an object")
		}
	}
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}
	if _, exists := meta[r2PaginationMetaKey]; exists {
		return nil, false, fmt.Errorf("namespace collision at %s", r2PaginationMetaKey)
	}
	// Keep the original JSON value without deriving completeness or truncation.
	meta[r2PaginationMetaKey] = pagination
	body, err := json.Marshal(meta)
	if err != nil {
		return nil, false, err
	}
	fields["_meta"] = body
	delete(fields, "pagination")
	body, err = json.Marshal(fields)
	return body, err == nil, err
}
