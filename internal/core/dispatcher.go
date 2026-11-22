package core

import (
	"context"
	"fmt"
	"io"
)

type Result struct {
	Packages  []Package
	Unchecked []Unchecked
	Findings  []Vuln
}

type Dispatcher struct {
	registry *Registry
	source   VulnSource
}

func NewDispatcher(registry *Registry, source VulnSource) *Dispatcher {
	return &Dispatcher{registry: registry, source: source}
}

// Run executes one complete scan. The operation is resolved before the Job is
// claimed, so an unknown operation cannot leave a job stuck in parsing.
func (d *Dispatcher) Run(ctx context.Context, job *Job, operation, filename string, input io.Reader) (Result, error) {
	if job == nil {
		return Result{}, invalid("job", "job is required")
	}
	if filename == "" {
		return Result{}, invalid("filename", "filename is required")
	}
	if input == nil {
		return Result{}, invalid("file", "file is required")
	}
	if d == nil || d.registry == nil {
		return Result{}, invalid("registry", "registry is required")
	}
	tool, err := d.registry.Get(operation)
	if err != nil {
		return Result{}, err
	}
	parser, err := asParser(tool)
	if err != nil {
		return Result{}, err
	}
	if !parser.CanParse(filename) {
		return Result{}, invalid("filename", "operation does not support filename")
	}
	if d.source == nil {
		return Result{}, invalid("source", "vulnerability source is required")
	}
	attempt, err := job.begin()
	if err != nil {
		return Result{}, err
	}

	pkgs, unchecked, err := parser.Parse(ctx, input)
	if err != nil {
		return Result{}, d.fail(job, attempt, err)
	}
	if err = job.transitionAttempt(attempt, Querying); err != nil {
		return Result{}, err
	}
	matches, unverified, err := d.source.QueryBatch(ctx, pkgs)
	if err != nil {
		return Result{}, d.fail(job, attempt, err)
	}
	unchecked = append(unchecked, unverified...)
	if err = job.transitionAttempt(attempt, Enriching); err != nil {
		return Result{}, err
	}
	result := Result{Packages: pkgs, Unchecked: unchecked}
	for _, match := range matches {
		for _, id := range match.VulnIDs {
			vuln, getErr := d.source.GetVuln(ctx, id, match.Package)
			if getErr != nil {
				return Result{}, d.fail(job, attempt, getErr)
			}
			result.Findings = append(result.Findings, vuln)
		}
	}
	outcome := Done
	if len(result.Unchecked) > 0 {
		outcome = Partial
	}
	state, err := job.finish(attempt, outcome)
	if err != nil {
		return Result{}, err
	}
	if state == Cancelled {
		return Result{}, nil
	}
	return result, nil
}

func (d *Dispatcher) fail(job *Job, attempt uint64, cause error) error {
	state, err := job.finish(attempt, Failed)
	if err != nil {
		return fmt.Errorf("tool failed (%v); finalize job: %w", cause, err)
	}
	if state == Cancelled {
		return nil
	}
	return cause
}
