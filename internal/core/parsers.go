package core

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
)

type GoModParser struct{}

func (GoModParser) Name() string                  { return "gomod" }
func (GoModParser) CanParse(filename string) bool { return path.Base(filename) == "go.mod" }

type replacement struct{ module, version string }

func (GoModParser) Parse(ctx context.Context, r io.Reader) ([]Package, []Unchecked, error) {
	if r == nil {
		return nil, nil, invalid("file", "file is required")
	}
	requires := make(map[string]string)
	replaces := make(map[string]replacement)
	section := ""
	s := bufio.NewScanner(r)
	lineNo := 0
	for s.Scan() {
		lineNo++
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		line := strings.TrimSpace(strings.SplitN(s.Text(), "//", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, "(") {
			section = strings.TrimSpace(strings.TrimSuffix(line, "("))
			if section != "require" && section != "replace" {
				section = ""
			}
			continue
		}
		if line == ")" {
			section = ""
			continue
		}
		kind := section
		fields := strings.Fields(line)
		if section == "" {
			if len(fields) == 0 {
				continue
			}
			kind, fields = fields[0], fields[1:]
		}
		switch kind {
		case "require":
			if len(fields) < 2 {
				return nil, nil, parseError(lineNo, "require needs module and version")
			}
			requires[fields[0]] = strings.TrimPrefix(fields[1], "v")
		case "replace":
			idx := -1
			for i, f := range fields {
				if f == "=>" {
					idx = i
					break
				}
			}
			if idx != 1 || len(fields) <= idx+1 {
				return nil, nil, parseError(lineNo, "invalid replace directive")
			}
			version := ""
			if len(fields) > idx+2 {
				version = strings.TrimPrefix(fields[idx+2], "v")
			}
			replaces[fields[0]] = replacement{module: fields[idx+1], version: version}
		}
	}
	if err := s.Err(); err != nil {
		return nil, nil, fmt.Errorf("read go.mod: %w", err)
	}
	packages := make([]Package, 0, len(requires))
	unchecked := make([]Unchecked, 0)
	for name, version := range requires {
		pkg := Package{Ecosystem: "Go", Name: name, Version: version}
		if repl, ok := replaces[name]; ok {
			if repl.version == "" {
				unchecked = append(unchecked, Unchecked{Package: pkg, Reason: "local_module"})
				continue
			}
			pkg.Name, pkg.Version = repl.module, repl.version
		}
		packages = append(packages, pkg)
	}
	return packages, unchecked, nil
}

func parseError(line int, message string) error {
	return &ToolError{Code: CodeManifestParse, Message: fmt.Sprintf("go.mod:%d: %s", line, message)}
}

type NpmLockParser struct{}

func (NpmLockParser) Name() string { return "npm" }
func (NpmLockParser) CanParse(filename string) bool {
	return path.Base(filename) == "package-lock.json"
}

func (NpmLockParser) Parse(ctx context.Context, r io.Reader) ([]Package, []Unchecked, error) {
	if r == nil {
		return nil, nil, invalid("file", "file is required")
	}
	var doc struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
	}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, &ToolError{Code: CodeManifestParse, Message: "package-lock.json: " + err.Error(), Err: err}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if doc.LockfileVersion != 2 && doc.LockfileVersion != 3 {
		return nil, nil, invalid("lockfileVersion", "package-lock.json must use lockfileVersion 2 or 3")
	}
	packages := make([]Package, 0, len(doc.Packages))
	unchecked := make([]Unchecked, 0)
	for key, entry := range doc.Packages {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if key == "" {
			continue
		}
		marker := "node_modules/"
		idx := strings.LastIndex(key, marker)
		if idx < 0 {
			continue
		}
		name := strings.TrimPrefix(key[idx+len(marker):], "/")
		pkg := Package{Ecosystem: "npm", Name: name, Version: strings.TrimPrefix(entry.Version, "v")}
		if entry.Link {
			unchecked = append(unchecked, Unchecked{Package: pkg, Reason: "local_module"})
			continue
		}
		if name == "" || pkg.Version == "" {
			continue
		}
		packages = append(packages, pkg)
	}
	return packages, unchecked, nil
}
