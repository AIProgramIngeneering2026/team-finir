package core

import (
	"context"
	"fmt"
	"io"
)

const (
	CodeUnknownOperation  = "unknown_operation"
	CodeInvalidParams     = "invalid_params"
	CodeManifestParse     = "manifest_parse_error"
	CodeSourceUnavailable = "vuln_source_unavailable"
)

type ToolError struct {
	Code    string
	Field   string
	Message string
	Err     error
}

func (e *ToolError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}
func (e *ToolError) Unwrap() error { return e.Err }

type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

type Unchecked struct {
	Package Package
	Reason  string
}

type Parser interface {
	Name() string
	CanParse(filename string) bool
	Parse(context.Context, io.Reader) ([]Package, []Unchecked, error)
}

type Match struct {
	Package Package
	VulnIDs []string
}

type Vuln struct {
	ID           string
	CVE          string
	Summary      string
	Severity     string
	CVSSScore    float64
	CVSSVector   string
	FixedVersion string
}

type VulnSource interface {
	QueryBatch(context.Context, []Package) ([]Match, []Unchecked, error)
	GetVuln(context.Context, string, Package) (Vuln, error)
}

type Tool interface{ Name() string }

type Registry struct{ tools map[string]Tool }

func NewRegistry(tools ...Tool) (*Registry, error) {
	r := &Registry{tools: make(map[string]Tool, len(tools))}
	for _, tool := range tools {
		if tool == nil || tool.Name() == "" {
			return nil, &ToolError{Code: CodeInvalidParams, Field: "tool", Message: "tool and name are required"}
		}
		if _, exists := r.tools[tool.Name()]; exists {
			return nil, &ToolError{Code: CodeInvalidParams, Field: "tool.name", Message: "duplicate tool name: " + tool.Name()}
		}
		r.tools[tool.Name()] = tool
	}
	return r, nil
}

func (r *Registry) Get(operation string) (Tool, error) {
	if r == nil || r.tools[operation] == nil {
		return nil, &ToolError{Code: CodeUnknownOperation, Field: "operation", Message: "unknown operation: " + operation}
	}
	return r.tools[operation], nil
}

func invalid(field, message string) error {
	return &ToolError{Code: CodeInvalidParams, Field: field, Message: message}
}

func asParser(tool Tool) (Parser, error) {
	p, ok := tool.(Parser)
	if !ok {
		return nil, fmt.Errorf("tool %q does not implement Parser", tool.Name())
	}
	return p, nil
}
