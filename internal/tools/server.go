// Package tools exposes Intruder operations over MCP. Tools return plain text,
// matching the Python server this was ported from.
package tools

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yurhasko/intruder-mcp-go/internal/intruder"
)

// Options configures the MCP server. Zero values select defaults.
type Options struct {
	Version        string
	ToolTimeout    time.Duration
	MaxOutputBytes int
}

type server struct {
	client *intruder.Client
	opts   Options
	mcp    *mcp.Server
}

func New(client *intruder.Client, opts Options) (*mcp.Server, error) {
	if client == nil {
		return nil, errors.New("API client is required")
	}

	if opts.Version == "" {
		opts.Version = "dev"
	}
	if opts.ToolTimeout == 0 {
		opts.ToolTimeout = 2 * time.Minute
	}
	if opts.MaxOutputBytes == 0 {
		opts.MaxOutputBytes = 8 << 20
	}
	if opts.ToolTimeout < 0 || opts.MaxOutputBytes < 1 {
		return nil, errors.New("invalid tool resource limits")
	}

	s := &server{
		client: client,
		opts:   opts,
		mcp:    mcp.NewServer(&mcp.Implementation{Name: "intruder", Version: opts.Version}, nil),
	}
	s.registerReads()
	s.registerMutations()
	return s.mcp, nil
}

type toolFlags uint8

const (
	readOnly toolFlags = 1 << iota
	destructive
	idempotent

	// write is the absence of all three.
	write toolFlags = 0
)

// add applies the deadline, the output limit, and the MCP envelope.
func add[In any](s *server, name, description string, flags toolFlags, schema any, handler func(context.Context, In) (string, error)) {
	isDestructive := flags&destructive != 0

	tool := &mcp.Tool{
		Name:        name,
		Description: description,
		InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    flags&readOnly != 0,
			DestructiveHint: &isDestructive,
			IdempotentHint:  flags&idempotent != 0,
		},
	}

	mcp.AddTool(s.mcp, tool, func(ctx context.Context, _ *mcp.CallToolRequest, input In) (*mcp.CallToolResult, any, error) {
		ctx, cancel := context.WithTimeout(ctx, s.opts.ToolTimeout)
		defer cancel()

		text, err := handler(ctx, input)
		if err != nil {
			return nil, nil, err
		}
		// A handler can return text it built before the deadline hit.
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		// len is the cheap lower bound for the escaped size.
		if len(text) > s.opts.MaxOutputBytes || outputBytes(text) > s.opts.MaxOutputBytes {
			return nil, nil, fmt.Errorf("tool output exceeded %d bytes; narrow the filters", s.opts.MaxOutputBytes)
		}

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
	})
}

// object is closed: an unnamed property is an error, not a silent no-op.
func object(properties map[string]any, required ...string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}

	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func stringField(description string) map[string]any {
	return map[string]any{"type": "string", "description": description}
}

func boolField(description string) map[string]any {
	return map[string]any{"type": "boolean", "description": description}
}

func enum(description string, values ...string) map[string]any {
	return map[string]any{"type": "string", "enum": values, "description": description}
}

// optional allows an explicit null alongside schema.
func optional(schema map[string]any) map[string]any {
	return map[string]any{"anyOf": []any{schema, map[string]any{"type": "null"}}}
}

// maxSafeInteger is the largest integer safe in a float64 JSON parser.
const maxSafeInteger = int64(1<<53 - 1)

func id(description string) map[string]any {
	return map[string]any{
		"type":        "integer",
		"minimum":     1,
		"maximum":     maxSafeInteger,
		"description": description,
	}
}

func array(items any, description string) map[string]any {
	return map[string]any{
		"type":        "array",
		"items":       items,
		"description": description,
		"maxItems":    10000,
	}
}
