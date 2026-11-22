package composite

// Regression tests for bounded waits on an entry that an operation still holds
// (Connector PR #454): ClaimContext and AbortWithReasonContext. These APIs are
// new in that change; cleanup_bounds_test.go and the compositetraefik UDS tests
// cover the same paths through APIs that also exist before it.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

const (
	waitSession = "wait-bound-session"
	waitURI     = "/wait-bound"
	waitBound   = 50 * time.Millisecond
)

// waitEngine blocks request-header processing until released and counts
// transaction closes, so tests control exactly when the entry is held.
type waitEngine struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	closes  int
}

func newWaitEngine(t *testing.T) *waitEngine {
	t.Helper()
	e := &waitEngine{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(e.unblock)
	return e
}

func (e *waitEngine) unblock() { e.once.Do(func() { close(e.release) }) }

func (e *waitEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return &waitTx{engine: e}, nil
}

func (e *waitEngine) closeCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closes
}

type waitTx struct{ engine *waitEngine }

func (tx *waitTx) ProcessHeaders(_ context.Context, direction processor.Direction, _ []processor.Header, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionRequest {
		close(tx.engine.entered)
		<-tx.engine.release
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (*waitTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (tx *waitTx) Close(context.Context, processor.Summary) {
	tx.engine.mu.Lock()
	tx.engine.closes++
	tx.engine.mu.Unlock()
}

type waitEvents struct {
	mu     sync.Mutex
	events []Event
}

func (o *waitEvents) Observe(event Event) error {
	o.mu.Lock()
	o.events = append(o.events, event)
	o.mu.Unlock()
	return nil
}

func (o *waitEvents) terminalReasons() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var reasons []string
	for _, event := range o.events {
		if event.Phase == "terminal" {
			reasons = append(reasons, event.Reason)
		}
	}
	return reasons
}

type activateResult struct {
	decision processor.Decision
	err      error
}

// startHeldActivation reserves an entry and starts ForwardAuth activation,
// returning once its native P1 call holds the entry.
func startHeldActivation(t *testing.T, c *Coordinator, engine *waitEngine) (string, <-chan activateResult) {
	t.Helper()
	token, err := c.Reserve(waitSession, reservationSnapshot(http.MethodGet, waitURI))
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan activateResult, 1)
	go func() {
		_, d, err := c.Activate(context.Background(), token, http.MethodGet, waitURI, reservationMetadata(http.MethodGet, waitURI), true)
		results <- activateResult{decision: d, err: err}
	}()
	select {
	case <-engine.entered:
	case <-time.After(boundReturnWithin):
		t.Fatal("activation never reached its native P1 call")
	}
	return token, results
}

func newWaitCoordinator(t *testing.T, capacity int, engine processor.TransactionOpener, observer Observer) *Coordinator {
	t.Helper()
	c, err := New("traefik", boundKey, Limits{Capacity: capacity, CleanupTimeout: boundCleanupTimeout}, engine, observer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			c.Close()
		}
	})
	return c
}

func TestEntryWaitClaimContextReturnsBusyWhileRequestPhaseHoldsEntry(t *testing.T) {
	engine := newWaitEngine(t)
	c := newWaitCoordinator(t, 4, engine, nil)
	token, results := startHeldActivation(t, c, engine)

	ctx, cancel := context.WithTimeout(context.Background(), waitBound)
	defer cancel()
	start := time.Now()
	_, err := c.ClaimContext(ctx, token, waitSession)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("ClaimContext error = %v, want ErrBusy", err)
	}
	if elapsed := time.Since(start); elapsed > boundReturnWithin {
		t.Fatalf("ClaimContext returned after %s, want about %s", elapsed, waitBound)
	}

	// A busy claim is not terminal: once P1 completes, the owning session can
	// claim normally (legitimate control).
	engine.unblock()
	if result := <-results; result.err != nil || result.decision.Action != processor.ActionAllow {
		t.Fatalf("activation = %#v / %v, want allow", result.decision, result.err)
	}
	if _, err := c.ClaimContext(context.Background(), token, waitSession); err != nil {
		t.Fatalf("claim after activation: %v", err)
	}
}

func TestEntryWaitAbortWhileHeldPreventsLateActivation(t *testing.T) {
	events := &waitEvents{}
	engine := newWaitEngine(t)
	// Capacity 2 with one unrelated live reservation detects a double release:
	// releasing twice would free the unrelated holder's slot as well.
	c := newWaitCoordinator(t, 2, engine, events)
	if _, err := c.Reserve("unrelated-session", reservationSnapshot(http.MethodGet, "/unrelated")); err != nil {
		t.Fatal(err)
	}
	token, results := startHeldActivation(t, c, engine)

	ctx, cancel := context.WithTimeout(context.Background(), waitBound)
	defer cancel()
	if err := c.AbortWithReasonContext(ctx, token, waitSession, "timeout"); !errors.Is(err, ErrBusy) {
		t.Fatalf("abort while P1 holds the entry = %v, want ErrBusy", err)
	}
	if got := engine.closeCount(); got != 0 {
		t.Fatalf("transaction closed %d times while its native call was running, want 0", got)
	}

	// The late P1 result must not make the reservation claimable.
	engine.unblock()
	result := <-results
	if !errors.Is(result.err, ErrAborted) {
		t.Fatalf("late activation error = %v, want ErrAborted", result.err)
	}
	if _, err := c.ClaimContext(context.Background(), token, waitSession); err == nil {
		t.Fatal("an aborted reservation became claimable after its native call returned")
	}
	if got := engine.closeCount(); got != 1 {
		t.Fatalf("transaction closes = %d, want exactly 1", got)
	}
	if _, err := c.Reserve("after-abort", reservationSnapshot(http.MethodGet, "/after")); err != nil {
		t.Fatalf("aborted entry did not release its slot: %v", err)
	}
	if _, err := c.Reserve("over-capacity", reservationSnapshot(http.MethodGet, "/over")); !errors.Is(err, ErrLimit) {
		t.Fatalf("third reservation error = %v, want ErrLimit (a double release would admit it)", err)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("an aborted session faulted the coordinator: %v", err)
	}
	waitForTerminalReason(t, events, "timeout")
}

func TestEntryWaitAbortOfIdleReservationFinishesImmediately(t *testing.T) {
	// Legitimate control: without a held entry the bounded abort behaves like
	// AbortWithReason and finishes at once with the session's reason.
	events := &waitEvents{}
	c := newWaitCoordinator(t, 2, processor.PassthroughEngine{}, events)
	token, err := c.Reserve(waitSession, reservationSnapshot(http.MethodGet, waitURI))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitBound)
	defer cancel()
	if err := c.AbortWithReasonContext(ctx, token, "other-session", "disconnect"); !errors.Is(err, ErrSession) {
		t.Fatalf("wrong-session abort = %v, want ErrSession", err)
	}
	if err := c.AbortWithReasonContext(ctx, token, waitSession, "disconnect"); err != nil {
		t.Fatalf("abort of an idle reservation: %v", err)
	}
	waitForTerminalReason(t, events, "disconnect")
}

func TestEntryWaitBoundedCallsRejectInvalidInputsWithoutWaiting(t *testing.T) {
	c := newWaitCoordinator(t, 2, processor.PassthroughEngine{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), waitBound)
	defer cancel()
	for _, tc := range []struct {
		name, token, session string
		want                 error
	}{
		{"empty token", "", waitSession, ErrInvalidLease},
		{"unknown token", "not-a-lease", waitSession, ErrInvalidLease},
		{"empty session", "not-a-lease", "", ErrSession},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.ClaimContext(ctx, tc.token, tc.session); !errors.Is(err, tc.want) {
				t.Fatalf("ClaimContext = %v, want %v", err, tc.want)
			}
			if err := c.AbortWithReasonContext(ctx, tc.token, tc.session, "abort"); !errors.Is(err, tc.want) {
				t.Fatalf("AbortWithReasonContext = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := c.ClaimContext(ctx, "", ""); !errors.Is(err, ErrSession) {
		t.Fatalf("empty claim = %v, want ErrSession", err)
	}
}

func waitForTerminalReason(t *testing.T, events *waitEvents, want string) {
	t.Helper()
	deadline := time.Now().Add(boundReturnWithin)
	for time.Now().Before(deadline) {
		for _, got := range events.terminalReasons() {
			if got == want {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("terminal reasons = %q, want %q", events.terminalReasons(), want)
}
