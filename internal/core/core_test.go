package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeSource struct{ queryErr, getErr error }

func (f fakeSource) QueryBatch(context.Context, []Package) ([]Match, []Unchecked, error) {
	if f.queryErr != nil {
		return nil, nil, f.queryErr
	}
	pkg := Package{Ecosystem: "Go", Name: "example.com/lib", Version: "1.2.0"}
	return []Match{{Package: pkg, VulnIDs: []string{"GO-1"}}}, nil, nil
}
func (f fakeSource) GetVuln(_ context.Context, id string, pkg Package) (Vuln, error) {
	if f.getErr != nil {
		return Vuln{}, f.getErr
	}
	return Vuln{ID: id, CVE: "CVE-2026-0001", Severity: "HIGH", FixedVersion: "1.2.1"}, nil
}

type gatedParser struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (p *gatedParser) Name() string              { return "gomod" }
func (p *gatedParser) CanParse(name string) bool { return strings.HasSuffix(name, "go.mod") }
func (p *gatedParser) Parse(ctx context.Context, _ io.Reader) ([]Package, []Unchecked, error) {
	p.calls.Add(1)
	close(p.entered)
	select {
	case <-p.release:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return []Package{{Ecosystem: "Go", Name: "example.com/lib", Version: "1.2.0"}}, nil, nil
}

func registry(t *testing.T, tools ...Tool) *Registry {
	t.Helper()
	r, err := NewRegistry(tools...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDispatcherSuccessfulLifecycle(t *testing.T) {
	r := registry(t, GoModParser{}, NpmLockParser{})
	d := NewDispatcher(r, fakeSource{})
	job := NewJob()
	got, err := d.Run(context.Background(), job, "gomod", "go.mod", strings.NewReader("module app\nrequire example.com/lib v1.2.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if job.State() != Done {
		t.Fatalf("state = %s, want done", job.State())
	}
	if len(got.Packages) != 1 || len(got.Findings) != 1 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestRegistryHasTwoParserTools(t *testing.T) {
	r := registry(t, GoModParser{}, NpmLockParser{})
	for _, name := range []string{"gomod", "npm"} {
		if _, err := r.Get(name); err != nil {
			t.Errorf("Get(%q): %v", name, err)
		}
	}
}

func TestUnknownOperationAndInvalidParameters(t *testing.T) {
	d := NewDispatcher(registry(t, GoModParser{}, NpmLockParser{}), fakeSource{})
	job := NewJob()
	_, err := d.Run(context.Background(), job, "nope", "go.mod", strings.NewReader(""))
	var toolErr *ToolError
	if !errors.As(err, &toolErr) || toolErr.Code != CodeUnknownOperation || toolErr.Field != "operation" {
		t.Fatalf("unexpected unknown-op error: %v", err)
	}
	if job.State() != Created {
		t.Fatalf("unknown operation changed state to %s", job.State())
	}
	_, err = d.Run(context.Background(), NewJob(), "gomod", "", strings.NewReader(""))
	if !errors.As(err, &toolErr) || toolErr.Code != CodeInvalidParams || toolErr.Field != "filename" {
		t.Fatalf("unexpected parameter error: %v", err)
	}
}

func TestNpmParserHandlesScopedAndLinkedPackages(t *testing.T) {
	input := `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/@scope/lib":{"version":"2.0.0"},"node_modules/local":{"version":"1.0.0","link":true}}}`
	pkgs, unchecked, err := (NpmLockParser{}).Parse(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "@scope/lib" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
	if len(unchecked) != 1 || unchecked[0].Reason != "local_module" {
		t.Fatalf("unexpected unchecked: %+v", unchecked)
	}
}

func TestGoModParserAppliesReplaceAndMarksLocal(t *testing.T) {
	input := "module app\nrequire (\n example.com/remote v1.2.0\n example.com/local v1.0.0\n)\nreplace example.com/remote => example.org/fork v1.3.0\nreplace example.com/local => ../local\n"
	pkgs, unchecked, err := (GoModParser{}).Parse(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "example.org/fork" || pkgs[0].Version != "1.3.0" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
	if len(unchecked) != 1 || unchecked[0].Reason != "local_module" {
		t.Fatalf("unexpected unchecked: %+v", unchecked)
	}
}

func TestToolFailureMovesJobToFailed(t *testing.T) {
	d := NewDispatcher(registry(t, GoModParser{}, NpmLockParser{}), fakeSource{queryErr: errors.New("OSV unavailable")})
	job := NewJob()
	_, err := d.Run(context.Background(), job, "gomod", "go.mod", strings.NewReader("module app\n"))
	if err == nil {
		t.Fatal("expected source error")
	}
	if job.State() != Failed {
		t.Fatalf("state = %s, want failed", job.State())
	}
}

func TestJobRejectsInvalidTransitionsAndAllSixAttacks(t *testing.T) {
	t.Run("Z1 double work", func(t *testing.T) {
		job := NewJob()
		if _, err := job.begin(); err != nil {
			t.Fatal(err)
		}
		if _, err := job.begin(); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("second start accepted: %v", err)
		}
		if job.State() != Parsing {
			t.Fatalf("state = %s", job.State())
		}
	})
	t.Run("Z2 restart", func(t *testing.T) {
		job := NewJob()
		for i := 1; i <= 3; i++ {
			if _, err := job.begin(); err != nil {
				t.Fatal(err)
			}
			if i < 3 {
				if err := job.Restart(); err != nil {
					t.Fatal(err)
				}
			} else if err := job.Restart(); err != nil {
				t.Fatal(err)
			}
		}
		if job.State() != Failed {
			t.Fatalf("third lost attempt state = %s, want failed", job.State())
		}
	})
	t.Run("Z2 late worker after restart", func(t *testing.T) {
		job := NewJob()
		oldAttempt, err := job.begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = job.Restart(); err != nil {
			t.Fatal(err)
		}
		newAttempt, err := job.begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = job.transitionAttempt(oldAttempt, Querying); !errors.Is(err, ErrStaleAttempt) {
			t.Fatalf("old worker was not rejected: %v", err)
		}
		if job.State() != Parsing {
			t.Fatalf("old worker changed state to %s", job.State())
		}
		if err = job.transitionAttempt(newAttempt, Querying); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Z3 late result after cancel", func(t *testing.T) {
		p := &gatedParser{entered: make(chan struct{}), release: make(chan struct{})}
		d := NewDispatcher(registry(t, p), fakeSource{})
		job := NewJob()
		done := make(chan error, 1)
		go func() {
			_, err := d.Run(context.Background(), job, "gomod", "go.mod", bytes.NewBufferString(""))
			done <- err
		}()
		<-p.entered
		if err := job.Cancel(); err != nil {
			t.Fatal(err)
		}
		close(p.release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if job.State() != Cancelled {
			t.Fatalf("late Tool result changed state to %s", job.State())
		}
		if p.calls.Load() != 1 {
			t.Fatalf("parser calls = %d", p.calls.Load())
		}
	})
	t.Run("Z4 two outcomes", func(t *testing.T) {
		job := NewJob()
		_, _ = job.begin()
		_ = job.Transition(Failed)
		if err := job.Transition(Done); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("second outcome accepted: %v", err)
		}
	})
	t.Run("Z5 success without work", func(t *testing.T) {
		job := NewJob()
		if err := job.Transition(Done); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("success accepted: %v", err)
		}
	})
	t.Run("Z6 repeat successful job", func(t *testing.T) {
		job := NewJob()
		_, _ = job.begin()
		_ = job.Transition(Querying)
		_ = job.Transition(Enriching)
		_ = job.Transition(Done)
		if _, err := job.begin(); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("completed job restarted: %v", err)
		}
	})
}

func TestDispatcherAcceptsAtMostOneConcurrentRun(t *testing.T) {
	p := &gatedParser{entered: make(chan struct{}), release: make(chan struct{})}
	d := NewDispatcher(registry(t, p), fakeSource{})
	job := NewJob()
	done := make(chan error, 1)
	go func() {
		_, err := d.Run(context.Background(), job, "gomod", "go.mod", strings.NewReader(""))
		done <- err
	}()
	<-p.entered
	_, err := d.Run(context.Background(), job, "gomod", "go.mod", strings.NewReader(""))
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("concurrent run error = %v", err)
	}
	close(p.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("parser called %d times", p.calls.Load())
	}
}

func TestCancellationBeforeWorkIsTerminal(t *testing.T) {
	job := NewJob()
	if err := job.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, err := job.begin(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cancelled job started: %v", err)
	}
}

func TestGoModParserReportsSyntaxError(t *testing.T) {
	_, _, err := (GoModParser{}).Parse(context.Background(), strings.NewReader("require broken\n"))
	var toolErr *ToolError
	if !errors.As(err, &toolErr) || toolErr.Code != CodeManifestParse {
		t.Fatalf("unexpected parse error: %v", err)
	}
}
