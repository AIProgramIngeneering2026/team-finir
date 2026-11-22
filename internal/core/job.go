package core

import (
	"errors"
	"fmt"
	"sync"
)

type State string

const (
	Created   State = "created"
	Parsing   State = "parsing"
	Querying  State = "querying"
	Enriching State = "enriching"
	Done      State = "done"
	Partial   State = "partial"
	Failed    State = "failed"
	Cancelled State = "cancelled"
)

var ErrInvalidTransition = errors.New("invalid_transition")
var ErrStaleAttempt = errors.New("stale_job_attempt")

type Job struct {
	mu              sync.Mutex
	state           State
	cancelRequested bool
	restartAttempts int
	attempt         uint64
}

func NewJob() *Job { return &Job{state: Created} }

func (j *Job) State() State {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state
}

// Transition changes state only when the P2 state diagram permits the edge.
func (j *Job) Transition(to State) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.transitionLocked(to)
}

func (j *Job) transitionLocked(to State) error {
	allowed := map[State]map[State]bool{
		Created:   {Parsing: true, Cancelled: true},
		Parsing:   {Querying: true, Failed: true, Created: true},
		Querying:  {Enriching: true, Failed: true, Created: true},
		Enriching: {Done: true, Partial: true, Failed: true, Cancelled: true, Created: true},
	}
	if !allowed[j.state][to] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, j.state, to)
	}
	j.state = to
	return nil
}

// Cancel immediately ends queued jobs and marks active jobs for cancellation
// after their current Tool call returns.
func (j *Job) Cancel() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	switch j.state {
	case Created:
		return j.transitionLocked(Cancelled)
	case Parsing, Querying, Enriching:
		j.cancelRequested = true
		return nil
	default:
		return fmt.Errorf("%w: cannot cancel %s", ErrInvalidTransition, j.state)
	}
}

func (j *Job) begin() (uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.transitionLocked(Parsing); err != nil {
		return 0, err
	}
	j.attempt++
	return j.attempt, nil
}

func (j *Job) transitionAttempt(attempt uint64, to State) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if attempt != j.attempt {
		return ErrStaleAttempt
	}
	return j.transitionLocked(to)
}

// finish commits exactly one terminal outcome. A requested cancellation wins
// over a late Tool result, so a cancelled scan can never publish a report.
func (j *Job) finish(attempt uint64, outcome State) (State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if attempt != j.attempt {
		return j.state, ErrStaleAttempt
	}
	if j.cancelRequested {
		// Keep the declared graph valid even when cancellation races with an
		// early Tool error: advance through the remaining workflow states before
		// committing the terminal cancellation.
		if j.state == Parsing {
			if err := j.transitionLocked(Querying); err != nil {
				return j.state, err
			}
		}
		if j.state == Querying {
			if err := j.transitionLocked(Enriching); err != nil {
				return j.state, err
			}
		}
		outcome = Cancelled
	}
	if err := j.transitionLocked(outcome); err != nil {
		return j.state, err
	}
	return j.state, nil
}

// Restart returns an interrupted job to the queue. The third lost attempt is
// terminal, as specified in the architecture document.
func (j *Job) Restart() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != Parsing && j.state != Querying && j.state != Enriching {
		return fmt.Errorf("%w: restart from %s", ErrInvalidTransition, j.state)
	}
	j.restartAttempts++
	j.attempt++ // invalidate any late result from the lost worker
	j.cancelRequested = false
	if j.restartAttempts >= 3 {
		return j.transitionLocked(Failed)
	}
	return j.transitionLocked(Created)
}
