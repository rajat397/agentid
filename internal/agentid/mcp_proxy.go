package agentid

import (
	"context"
	"fmt"
	"sync"
)

// MCPProxy sits between an MCP client and a server. It forwards every message
// transparently except consequential tools/call requests, which are validated
// before the server sees them. Allowed calls are annotated with a receipt id
// on the way back.
type MCPProxy struct {
	wrapper *MCPWrapper
	mu      sync.Mutex
	pending map[string]string
}

// NewMCPProxy creates a stdio/Streamable-HTTP transport proxy.
func NewMCPProxy(wrapper *MCPWrapper) *MCPProxy {
	return &MCPProxy{wrapper: wrapper, pending: map[string]string{}}
}

// ProcessClient handles a client line. forward=true means write it to the
// server unchanged; a non-nil response is the reply to send to the client.
func (p *MCPProxy) ProcessClient(ctx context.Context, line []byte) (bool, []byte) {
	value, err := DecodeJSON(line)
	if err != nil {
		return false, mustJSON(rpcError(nil, -32700, "parse error", ""))
	}
	request := AsMap(value)
	if stringField(request, "method") != "tools/call" {
		return true, nil
	}
	response := p.wrapper.HandleRPC(ctx, request)
	if AsMap(response["error"]) != nil {
		return false, mustJSON(response)
	}
	receiptID := stringField(AsMap(AsMap(response["result"])["_meta"]), "receipt_id")
	if receiptID != "" {
		key := requestIDKey(request["id"])
		p.mu.Lock()
		p.pending[key] = receiptID
		p.mu.Unlock()
	}
	return true, nil
}

// ProcessServerResponse annotates a server reply for an allowed call.
func (p *MCPProxy) ProcessServerResponse(line []byte) ([]byte, error) {
	value, err := DecodeJSON(line)
	if err != nil {
		return line, nil
	}
	object := AsMap(value)
	key := requestIDKey(object["id"])
	p.mu.Lock()
	receiptID, ok := p.pending[key]
	if ok {
		delete(p.pending, key)
	}
	p.mu.Unlock()
	if !ok {
		return line, nil
	}
	result := AsMap(object["result"])
	if result == nil {
		return line, nil
	}
	meta := AsMap(result["_meta"])
	if meta == nil {
		meta = map[string]any{}
	}
	meta["receipt_id"] = receiptID
	result["_meta"] = meta
	object["result"] = result
	return mustJSON(object), nil
}

func requestIDKey(id any) string { return fmt.Sprint(id) }

func mustJSON(value any) []byte {
	data, err := CanonicalJSON(value)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"}}`)
	}
	return data
}
