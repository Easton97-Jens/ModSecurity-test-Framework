package composite

// Regression tests for bounded native cleanup in the composite coordinator
// (Connector PR #454). The transactions are test doubles whose Close models
// processor.commonRuntimeTransaction.Close: a canceled context fails at once,
// and a gate held by a native call that never returns is waited for only until
// the context ends. Statements about the real Common runtime are covered by
// cleanup_runtime_test.go.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

const (
	boundConnector      = "envoy-ext-proc"
	boundCleanupTimeout = 50 * time.Millisecond
	// boundReturnWithin must exceed boundCleanupTimeout by far, so a bounded
	// path passes reliably while an unbounded wait is still detected.
	boundReturnWithin = 2 * time.Second
	// boundDefaultWithin exceeds the 5s default cleanup timeout.
	boundDefaultWithin = 10 * time.Second
)

// boundKey is a non-secret 256-bit test fixture.
var boundKey = []byte("01234567890123456789012345678901")

var errBoundTestFault = errors.New("composite cleanup bound test fault")

type boundCloseMode int

const (
	boundCloseNormal boundCloseMode = iota
	// boundCloseGateHeld waits for the context like Close does while another
	// native call holds the serial Common runtime gate.
	boundCloseGateHeld
)

// boundEngine opens boundTx transactions. When openEntered is set, Open
// signals it and waits for openRelease before returning.
type boundEngine struct {
	mode        boundCloseMode
	openEntered chan struct{}
	openRelease chan struct{}
	release     chan struct{} // ends a gate-held Close on test cleanup
	mu          sync.Mutex
	txs         []*boundTx
}

func newBoundEngine(t *testing.T, mode boundCloseMode) *boundEngine {
	t.Helper()
	e := &boundEngine{mode: mode, release: make(chan struct{})}
	t.Cleanup(func() { close(e.release) })
	return e
}

func (e *boundEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	if e.openEntered != nil {
		close(e.openEntered)
		<-e.openRelease
	}
	tx := &boundTx{engine: e}
	e.mu.Lock()
	e.txs = append(e.txs, tx)
	e.mu.Unlock()
	return tx, nil
}

func (e *boundEngine) onlyTx(t *testing.T) *boundTx {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.txs) != 1 {
		t.Fatalf("opened transactions = %d, want 1", len(e.txs))
	}
	return e.txs[0]
}

type boundTx struct {
	engine *boundEngine
	mu     sync.Mutex
	closes int
	// remaining is the context budget observed when Close started; negative
	// when the context had no deadline.
	remaining time.Duration
	err       error
}

func (*boundTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (*boundTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (*boundTx) RecordHostAction(context.Context, processor.HostAction) error { return nil }

func (tx *boundTx) Close(ctx context.Context, _ processor.Summary) {
	remaining := time.Duration(-1)
	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}
	var failure error
	if err := ctx.Err(); err != nil {
		failure = err
	} else if tx.engine.mode == boundCloseGateHeld {
		select {
		case <-ctx.Done():
			failure = ctx.Err()
		case <-tx.engine.release:
			failure = errors.New("test released a gate-held Close without a deadline")
		}
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.closes++
	tx.remaining = remaining
	if failure != nil && tx.err == nil {
		tx.err = fmt.Errorf("%w: %w", processor.ErrCommonRuntimeTransactionCleanupTimeout, failure)
	}
}

func (tx *boundTx) CleanupFailure() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.err
}

func (tx *boundTx) snapshot() (int, time.Duration, error) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.closes, tx.remaining, tx.err
}

func newBoundCoordinator(t *testing.T, limits Limits, engine processor.TransactionOpener) *Coordinator {
	t.Helper()
	c, err := New(boundConnector, boundKey, limits, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	// After a detected unbounded wait goroutines may still be blocked; do not
	// let Close turn that failure into a hung test binary.
	t.Cleanup(func() {
		if !t.Failed() {
			c.Close()
		}
	})
	return c
}

type beginResult struct {
	err error
}

// startBeginRequestBehindOpen starts BeginRequest and returns once Open has
// been entered; finishing Open is left to the caller.
func startBeginRequestBehindOpen(t *testing.T, c *Coordinator, engine *boundEngine) (chan<- struct{}, <-chan beginResult) {
	t.Helper()
	engine.openEntered = make(chan struct{})
	release := make(chan struct{})
	engine.openRelease = release
	results := make(chan beginResult, 1)
	go func() {
		_, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
		results <- beginResult{err: err}
	}()
	select {
	case <-engine.openEntered:
	case <-time.After(boundReturnWithin):
		t.Fatal("BeginRequest never reached engine.Open")
	}
	return release, results
}

func awaitBegin(t *testing.T, results <-chan beginResult) beginResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(boundReturnWithin):
		t.Fatalf("BeginRequest did not return within %s although CleanupTimeout is %s: the cleanup of an opened but unregistered transaction is unbounded", boundReturnWithin, boundCleanupTimeout)
		return beginResult{}
	}
}

func TestCleanupBoundBeginRequestAfterFaultUsesCleanupBudget(t *testing.T) {
	engine := newBoundEngine(t, boundCloseGateHeld)
	c := newBoundCoordinator(t, Limits{Capacity: 4, CleanupTimeout: boundCleanupTimeout}, engine)
	release, results := startBeginRequestBehindOpen(t, c, engine)
	// The fault is published between a successful Open and registration.
	c.setFault(errBoundTestFault)
	close(release)
	result := awaitBegin(t, results)
	if !errors.Is(result.err, errBoundTestFault) {
		t.Fatalf("BeginRequest error = %v, want the coordinator fault", result.err)
	}
	closes, remaining, cleanupErr := engine.onlyTx(t).snapshot()
	if closes != 1 {
		t.Fatalf("unregistered transaction closed %d times, want 1", closes)
	}
	if remaining < 0 || remaining > boundCleanupTimeout {
		t.Fatalf("cleanup budget = %v, want a deadline of at most %v", remaining, boundCleanupTimeout)
	}
	if !errors.Is(cleanupErr, processor.ErrCommonRuntimeTransactionCleanupTimeout) {
		t.Fatalf("gate-held cleanup error = %v, want the recorded cleanup timeout", cleanupErr)
	}
	if held := len(c.slots); held != 0 {
		t.Fatalf("admission slots still held = %d, want 0", held)
	}
}

func TestCleanupBoundBeginRequestAfterCloseUsesCleanupBudget(t *testing.T) {
	engine := newBoundEngine(t, boundCloseGateHeld)
	c, err := New(boundConnector, boundKey, Limits{Capacity: 4, CleanupTimeout: boundCleanupTimeout}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	release, results := startBeginRequestBehindOpen(t, c, engine)
	c.Close() // shutdown between Open and registration
	close(release)
	result := awaitBegin(t, results)
	if !errors.Is(result.err, ErrClosed) && !errors.Is(result.err, processor.ErrCommonRuntimeTransactionCleanupTimeout) {
		t.Fatalf("BeginRequest error = %v, want ErrClosed or the recorded cleanup timeout", result.err)
	}
	if closes, remaining, _ := engine.onlyTx(t).snapshot(); closes != 1 || remaining < 0 || remaining > boundCleanupTimeout {
		t.Fatalf("unregistered transaction closes=%d budget=%v, want one bounded close", closes, remaining)
	}
	if held := len(c.slots); held != 0 {
		t.Fatalf("admission slots still held = %d, want 0", held)
	}
}

func TestCleanupBoundBeginRequestAfterFaultClosesNormalTransactionOnce(t *testing.T) {
	// Legitimate control: a cleanup that can acquire the gate completes and
	// records no cleanup failure; the request still fails with the fault.
	engine := newBoundEngine(t, boundCloseNormal)
	c := newBoundCoordinator(t, Limits{Capacity: 4, CleanupTimeout: boundCleanupTimeout}, engine)
	release, results := startBeginRequestBehindOpen(t, c, engine)
	c.setFault(errBoundTestFault)
	close(release)
	if result := awaitBegin(t, results); !errors.Is(result.err, errBoundTestFault) {
		t.Fatalf("BeginRequest error = %v, want the coordinator fault", result.err)
	}
	if closes, _, cleanupErr := engine.onlyTx(t).snapshot(); closes != 1 || cleanupErr != nil {
		t.Fatalf("normal cleanup closes=%d err=%v, want one successful close", closes, cleanupErr)
	}
}

func finishWithin(t *testing.T, ctx context.Context, r *Response, why string, within time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		r.Finish(ctx, why)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("Finish(%q) did not return within %s", why, within)
	}
}

func TestCleanupBoundGateHeldFinishFailsClosedAtDefaultBudget(t *testing.T) {
	// Default limits on purpose: the 5s default must bound the cleanup.
	engine := newBoundEngine(t, boundCloseGateHeld)
	c := newBoundCoordinator(t, Limits{Capacity: 4}, engine)
	r := claimedResponse(t, c, "bound-session")
	finishWithin(t, context.Background(), r, "disconnect", boundDefaultWithin)
	if c.Err() == nil {
		t.Fatal("a native cleanup timeout must leave the coordinator in a fail-closed fault state")
	}
	if _, _, err := c.BeginRequest(context.Background(), metadata(), nil, true); err == nil {
		t.Fatal("new work was admitted after an unsafe native cleanup")
	}
}

func TestCleanupBoundBudgetStartsAtCleanupForLongLivedEntry(t *testing.T) {
	const budget = 40 * time.Millisecond
	engine := newBoundEngine(t, boundCloseNormal)
	c := newBoundCoordinator(t, Limits{Capacity: 4, CleanupTimeout: budget, TTL: time.Minute, IdleTTL: time.Minute}, engine)
	r := claimedResponse(t, c, "bound-session")
	// The entry outlives its cleanup budget before it is finished. A budget
	// created at session start would already be spent at Close.
	time.Sleep(3 * budget)
	finishWithin(t, context.Background(), r, "finish", boundReturnWithin)
	closes, remaining, cleanupErr := engine.onlyTx(t).snapshot()
	if closes != 1 || cleanupErr != nil {
		t.Fatalf("closes=%d cleanup error=%v, want one successful close", closes, cleanupErr)
	}
	if remaining <= budget/2 || remaining > budget {
		t.Fatalf("budget at Close = %v, want a fresh budget close to %v", remaining, budget)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("legitimate cleanup faulted the coordinator: %v", err)
	}
}

func TestCleanupBoundCanceledCallerContextIsDetached(t *testing.T) {
	engine := newBoundEngine(t, boundCloseNormal)
	c := newBoundCoordinator(t, Limits{Capacity: 4, CleanupTimeout: boundCleanupTimeout}, engine)
	r := claimedResponse(t, c, "bound-session")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	finishWithin(t, canceled, r, "cancel", boundReturnWithin)
	if _, _, cleanupErr := engine.onlyTx(t).snapshot(); cleanupErr != nil {
		t.Fatalf("a canceled caller context reached native cleanup: %v", cleanupErr)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("a canceled caller context faulted the coordinator: %v", err)
	}
}

func TestCleanupBoundNilCallerContextAndEmptyReason(t *testing.T) {
	engine := newBoundEngine(t, boundCloseNormal)
	c := newBoundCoordinator(t, Limits{Capacity: 4, CleanupTimeout: boundCleanupTimeout}, engine)
	r := claimedResponse(t, c, "bound-session")
	//nolint:staticcheck // A nil context is the boundary case under test.
	finishWithin(t, nil, r, "", boundReturnWithin)
	if err := c.Err(); err != nil {
		t.Fatalf("nil context or empty reason faulted the coordinator: %v", err)
	}
}

func TestCleanupBoundSequentialLifecyclesReleaseCapacity(t *testing.T) {
	// Capacity 2 keeps the event queue (8 events per slot) larger than two
	// lifecycles; a capacity-1 queue can saturate before dispatch drains it.
	engine := newBoundEngine(t, boundCloseNormal)
	c := newBoundCoordinator(t, Limits{Capacity: 2, CleanupTimeout: boundCleanupTimeout}, engine)
	for i := range 2 {
		r := claimedResponse(t, c, fmt.Sprintf("bound-session-%d", i))
		finishWithin(t, context.Background(), r, "finish", boundReturnWithin)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("legitimate lifecycles faulted the coordinator: %v", err)
	}
	if held := len(c.slots); held != 0 {
		t.Fatalf("admission slots still held = %d, want 0", held)
	}
}

// boundBusyEngine blocks request-header processing until released, which
// models a long or never-returning native P1 call holding the entry.
type boundBusyEngine struct {
	entered chan struct{}
	release chan struct{}
}

func (e *boundBusyEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return &boundBusyTx{engine: e}, nil
}

type boundBusyTx struct{ engine *boundBusyEngine }

func (tx *boundBusyTx) ProcessHeaders(_ context.Context, direction processor.Direction, _ []processor.Header, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionRequest {
		close(tx.engine.entered)
		<-tx.engine.release
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (*boundBusyTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (*boundBusyTx) Close(context.Context, processor.Summary) {}

func TestCleanupBoundSweepSkipsEntryHeldByOperation(t *testing.T) {
	busy := &boundBusyEngine{entered: make(chan struct{}), release: make(chan struct{})}
	released := false
	t.Cleanup(func() {
		if !released {
			close(busy.release)
		}
	})
	c := newBoundCoordinator(t, Limits{Capacity: 4, CleanupTimeout: boundCleanupTimeout, TTL: time.Minute, IdleTTL: time.Minute}, busy)
	go func() { _, _, _ = c.BeginRequest(context.Background(), metadata(), nil, true) }()
	<-busy.entered
	swept := make(chan struct{})
	go func() {
		c.Sweep(time.Now().Add(2 * time.Minute))
		close(swept)
	}()
	select {
	case <-swept:
	case <-time.After(boundReturnWithin):
		t.Fatal("Sweep waited for an entry held by an in-flight operation and stalled expiry of every other entry")
	}
	close(busy.release)
	released = true
}
