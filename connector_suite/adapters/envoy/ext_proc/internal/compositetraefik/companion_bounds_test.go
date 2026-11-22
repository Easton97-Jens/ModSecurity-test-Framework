package compositetraefik

// Regression tests for the Traefik composite companion (Connector PR #454):
// bounded UDS waits, no late activation after an aborted session, ForwardAuth
// redirect validation and detached cleanup after a client disconnect. They use
// test-double engines; companion_runtime_test.go repeats the disconnect case
// with the real Common runtime.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

const (
	companionConnector    = "traefik"
	companionFrameTimeout = 100 * time.Millisecond
	// companionReturnWithin must exceed companionFrameTimeout by far.
	companionReturnWithin = 2 * time.Second
	// companionMaxRedirect mirrors the Common bridge redirect_url[2049] bound.
	companionMaxRedirect = 2048
)

// companionKey is a non-secret 256-bit test fixture.
var companionKey = []byte("01234567890123456789012345678901")

func companionReserve(t *testing.T, c *composite.Coordinator, session, method, uri string) string {
	t.Helper()
	token, err := c.Reserve(session, composite.ReservationSnapshot{
		Version: composite.ReservationSnapshotVersion, Protocol: "HTTP/1.1",
		ServerAddress: "127.0.0.1", ServerPort: 8080, Method: method, URI: uri,
		Headers: []processor.Header{{Name: "host", Value: []byte("example.test")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func companionForwardAuth(c *composite.Coordinator, ctx context.Context, lease, method, uri string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://127.0.0.1"+uri, body)
	for name, value := range map[string]string{
		LeaseHeader: lease, "X-Forwarded-Method": method, "X-Forwarded-Uri": uri,
		"X-Forwarded-Proto": "http", "X-Forwarded-Host": "example.test", "X-Forwarded-For": "127.0.0.1",
	} {
		req.Header.Set(name, value)
	}
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19182})
	rec := httptest.NewRecorder()
	(&ForwardAuth{Coordinator: c}).ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

func newCompanionCoordinator(t *testing.T, capacity int, engine processor.TransactionOpener) *composite.Coordinator {
	t.Helper()
	c, err := composite.New(companionConnector, companionKey, composite.Limits{Capacity: capacity}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	// After a detected unbounded wait goroutines may still be blocked; Close
	// must not turn that failure into a hung test binary.
	t.Cleanup(func() {
		if !t.Failed() {
			c.Close()
		}
	})
	return c
}

// --- Claim during a held ForwardAuth request phase -------------------------

// heldBodyEngine blocks request-body processing until released, modeling a
// long or never-returning native P2 call that holds the entry.
type heldBodyEngine struct {
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	enteredOnce sync.Once
	mu          sync.Mutex
	closes      int
}

func newHeldBodyEngine(t *testing.T) *heldBodyEngine {
	t.Helper()
	e := &heldBodyEngine{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(e.unblock)
	return e
}

func (e *heldBodyEngine) unblock() { e.once.Do(func() { close(e.release) }) }

func (e *heldBodyEngine) closeCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closes
}

func (e *heldBodyEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return &heldBodyTx{engine: e}, nil
}

type heldBodyTx struct{ engine *heldBodyEngine }

func (*heldBodyTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (tx *heldBodyTx) ProcessBody(_ context.Context, direction processor.Direction, _ []byte, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionRequest {
		// Only the first body call holds the entry; ForwardAuth may call again
		// for the final chunk once it is released.
		tx.engine.enteredOnce.Do(func() { close(tx.engine.entered) })
		<-tx.engine.release
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (tx *heldBodyTx) Close(context.Context, processor.Summary) {
	tx.engine.mu.Lock()
	tx.engine.closes++
	tx.engine.mu.Unlock()
}

func TestCompanionClaimDuringHeldRequestPhaseReleasesHandler(t *testing.T) {
	const path = "/held-request-phase"
	engine := newHeldBodyEngine(t)
	// Capacity 2 plus one unrelated live reservation detects a double release.
	c := newCompanionCoordinator(t, 2, engine)
	companionReserve(t, c, "unrelated-session", http.MethodGet, "/unrelated")

	server, client := net.Pipe()
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing the companion pipe: %v", err)
		}
	})
	handled := make(chan struct{})
	go func() { (&UDS{Coordinator: c, Timeout: companionFrameTimeout}).handle(server); close(handled) }()

	reserved := exchangeUDS(t, client, opReserve, reservationSnapshotPayload(t, http.MethodPost, path, nil))
	if reserved.decision != decisionAllow || reserved.value == "" {
		t.Fatalf("reserve result = %#v", reserved)
	}
	forwardAuthStatus := make(chan int, 1)
	go func() {
		forwardAuthStatus <- companionForwardAuth(c, context.Background(), reserved.value, http.MethodPost, path, bytes.NewReader([]byte("held body"))).Code
	}()
	select {
	case <-engine.entered:
	case <-time.After(companionReturnWithin):
		t.Fatal("ForwardAuth never reached its native P2 call")
	}

	// Claim while P2 still holds the entry: bounded by the frame deadline.
	if err := writeFrame(client, opClaim, tokenPayload(reserved.value)); err != nil {
		t.Fatalf("claim frame was not delivered: %v", err)
	}
	type readResult struct {
		result udsResult
		err    error
	}
	claimed := make(chan readResult, 1)
	go func() {
		result, err := readUDSResult(client)
		claimed <- readResult{result, err}
	}()
	select {
	case got := <-claimed:
		// The bounded wait may use the whole frame deadline, so the session can
		// end before its 503 result is written. Both outcomes fail closed: the
		// plugin treats a closed companion transport as unavailable.
		if got.err == nil && (got.result.decision != decisionDeny || got.result.status != http.StatusServiceUnavailable) {
			t.Fatalf("busy claim result = %#v, want a 503 deny or a closed session", got.result)
		}
		if got.err != nil && !errors.Is(got.err, io.EOF) && !errors.Is(got.err, io.ErrUnexpectedEOF) && !errors.Is(got.err, io.ErrClosedPipe) {
			t.Fatalf("busy claim read error = %v, want a 503 deny or a closed session", got.err)
		}
	case <-time.After(companionReturnWithin):
		t.Fatalf("claim waited beyond %s for ForwardAuth's native call although the frame deadline is %s", companionReturnWithin, companionFrameTimeout)
	}
	select {
	case <-handled:
	case <-time.After(companionReturnWithin):
		t.Fatal("UDS handler and its admission slot stayed held after the bounded claim")
	}
	if got := engine.closeCount(); got != 0 {
		t.Fatalf("transaction closed %d times while its native call was running, want 0", got)
	}

	// Late completion: the aborted reservation must not authorize the request.
	engine.unblock()
	select {
	case status := <-forwardAuthStatus:
		if status != http.StatusServiceUnavailable {
			t.Fatalf("ForwardAuth status after the session aborted = %d, want %d (late activation)", status, http.StatusServiceUnavailable)
		}
	case <-time.After(companionReturnWithin):
		t.Fatal("ForwardAuth did not finish after its native call returned")
	}
	if got := engine.closeCount(); got != 1 {
		t.Fatalf("transaction closes = %d, want exactly 1", got)
	}
	companionReserve(t, c, "after-abort", http.MethodGet, "/after")
	if _, err := c.Reserve("over-capacity", composite.ReservationSnapshot{
		Version: composite.ReservationSnapshotVersion, Protocol: "HTTP/1.1",
		ServerAddress: "127.0.0.1", ServerPort: 8080, Method: http.MethodGet, URI: "/over",
		Headers: []processor.Header{{Name: "host", Value: []byte("example.test")}},
	}); !errors.Is(err, composite.ErrLimit) {
		t.Fatalf("reservation beyond capacity = %v, want ErrLimit (a double release would admit it)", err)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("an aborted companion session faulted the coordinator: %v", err)
	}
}

// --- UDS engine work bounded by the frame deadline ------------------------

// gateHeldResponseEngine models response work queued behind a native call
// that never returns: like lockCommonRuntimeMutex it waits for its context.
type gateHeldResponseEngine struct{ release chan struct{} }

func (e gateHeldResponseEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return gateHeldResponseTx(e), nil
}

type gateHeldResponseTx struct{ release chan struct{} }

func (tx gateHeldResponseTx) ProcessHeaders(ctx context.Context, direction processor.Direction, _ []processor.Header, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionResponse {
		select {
		case <-ctx.Done():
			return processor.Decision{}, ctx.Err()
		case <-tx.release:
			return processor.Decision{}, errors.New("test released response work without a deadline")
		}
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (gateHeldResponseTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (gateHeldResponseTx) Close(context.Context, processor.Summary) {}

func TestCompanionResponseEngineWorkIsBoundedByFrameDeadline(t *testing.T) {
	engine := gateHeldResponseEngine{release: make(chan struct{})}
	t.Cleanup(func() { close(engine.release) })
	c := newCompanionCoordinator(t, 2, engine)
	server, client := net.Pipe()
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing the companion pipe: %v", err)
		}
	})
	handled := make(chan struct{})
	go func() { (&UDS{Coordinator: c, Timeout: companionFrameTimeout}).handle(server); close(handled) }()

	reserved := exchangeUDS(t, client, opReserve, reservationSnapshotPayload(t, http.MethodGet, "/gate", nil))
	forwardAuthRequest(t, c, reserved.value, http.MethodGet, "/gate", nil, http.StatusOK)
	if got := exchangeUDS(t, client, opClaim, tokenPayload(reserved.value)); got.decision != decisionAllow {
		t.Fatalf("claim result = %#v", got)
	}
	writeErr := make(chan error, 1)
	go func() { writeErr <- writeFrame(client, opResponseHeaders, responseHeaderPayload(http.StatusOK)) }()
	readErr := make(chan error, 1)
	go func() {
		_, err := readUDSResult(client)
		readErr <- err
	}()
	select {
	case <-handled:
	case <-time.After(companionReturnWithin):
		t.Fatalf("UDS session stayed in engine work beyond %s; its admission slot is never released", companionReturnWithin)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("P3 frame was not delivered: %v", err)
	}
	select {
	case err := <-readErr:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("unexpected companion read error after the session ended: %v", err)
		}
	case <-time.After(companionReturnWithin):
		t.Fatal("companion read did not observe the ended session")
	}
}

func TestCompanionNormalLifecycleWithShortFrameDeadline(t *testing.T) {
	c := newCompanionCoordinator(t, 2, processor.PassthroughEngine{})
	client := startUDSPipe(t, &UDS{Coordinator: c, Timeout: companionFrameTimeout})
	reserved := exchangeUDS(t, client, opReserve, reservationSnapshotPayload(t, http.MethodPost, "/normal", nil))
	forwardAuthRequest(t, c, reserved.value, http.MethodPost, "/normal", []byte("hello"), http.StatusOK)
	for _, step := range []struct {
		op      byte
		payload []byte
	}{
		{opClaim, tokenPayload(reserved.value)},
		{opResponseHeaders, responseHeaderPayload(http.StatusOK)},
		{opResponseCommit, []byte{1, 0}},
		{opResponseEOS, nil},
		{opOutcome, []byte{0, 0, http.StatusOK}},
		{opFinish, nil},
	} {
		if got := exchangeUDS(t, client, step.op, step.payload); got.decision != decisionAllow {
			t.Fatalf("op %d result = %#v", step.op, got)
		}
	}
	if err := c.Err(); err != nil {
		t.Fatalf("normal lifecycle faulted the coordinator: %v", err)
	}
}

// --- ForwardAuth redirect validation ---------------------------------------

type redirectEngine struct{ target string }

func (e redirectEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return redirectTx(e), nil
}

type redirectTx struct{ target string }

func (tx redirectTx) ProcessHeaders(_ context.Context, direction processor.Direction, _ []processor.Header, _ bool) (processor.Decision, error) {
	if direction != processor.DirectionRequest {
		return processor.Decision{Action: processor.ActionAllow}, nil
	}
	return processor.Decision{Action: processor.ActionRedirect, Status: http.StatusFound, RedirectURL: tx.target}, nil
}
func (redirectTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (redirectTx) Close(context.Context, processor.Summary) {}

func TestCompanionForwardAuthRedirectLocationIsValidated(t *testing.T) {
	const path = "/redirect"
	cases := []struct {
		name, target string
		wantStatus   int
		wantLocation string
	}{
		{"valid absolute", "https://example.test/blocked", http.StatusFound, "https://example.test/blocked"},
		{"valid relative with percent-encoded controls", "/blocked?x=%0d%0aSet-Cookie:%20a=b", http.StatusFound, "/blocked?x=%0d%0aSet-Cookie:%20a=b"},
		{"valid maximum length", "/" + strings.Repeat("a", companionMaxRedirect-1), http.StatusFound, "/" + strings.Repeat("a", companionMaxRedirect-1)},
		{"CRLF header injection", "https://example.test/\r\nSet-Cookie: injected=1", http.StatusForbidden, ""},
		{"bare LF", "https://example.test/\nX: y", http.StatusForbidden, ""},
		{"NUL", "https://example.test/\x00", http.StatusForbidden, ""},
		{"DEL", "https://example.test/\x7f", http.StatusForbidden, ""},
		{"leading space", " https://example.test/", http.StatusForbidden, ""},
		{"invalid UTF-8", "https://example.test/\xff", http.StatusForbidden, ""},
		{"empty", "", http.StatusForbidden, ""},
		{"over maximum length", "/" + strings.Repeat("a", companionMaxRedirect), http.StatusForbidden, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCompanionCoordinator(t, 2, redirectEngine{target: tc.target})
			rec := companionForwardAuth(c, context.Background(), companionReserve(t, c, "redirect-session", http.MethodGet, path), http.MethodGet, path, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Location"); got != tc.wantLocation {
				t.Fatalf("Location = %q, want %q", got, tc.wantLocation)
			}
			if values := rec.Header().Values("Set-Cookie"); len(values) != 0 {
				t.Fatalf("unexpected Set-Cookie header: %q", values)
			}
		})
	}
}

// --- Client disconnect during ForwardAuth ----------------------------------

// lockSemanticsEngine models commonRuntimeTransaction.Close: a canceled
// context makes cleanup unsafe and is recorded as a cleanup failure.
type lockSemanticsEngine struct{}

func (lockSemanticsEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return &lockSemanticsTx{}, nil
}

type lockSemanticsTx struct {
	mu  sync.Mutex
	err error
}

func (*lockSemanticsTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (*lockSemanticsTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (tx *lockSemanticsTx) Close(ctx context.Context, _ processor.Summary) {
	if err := ctx.Err(); err != nil {
		tx.mu.Lock()
		tx.err = fmt.Errorf("%w: %w", processor.ErrCommonRuntimeTransactionCleanupTimeout, err)
		tx.mu.Unlock()
	}
}
func (tx *lockSemanticsTx) CleanupFailure() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.err
}

// cancelAfterFirstRead returns one chunk and then cancels the request context,
// like a client that disconnects during the P2 body upload.
type cancelAfterFirstRead struct {
	data   []byte
	cancel context.CancelFunc
	done   bool
}

func (r *cancelAfterFirstRead) Read(p []byte) (int, error) {
	if r.done {
		return 0, context.Canceled
	}
	r.done = true
	n := copy(p, r.data)
	r.cancel()
	return n, nil
}

func TestCompanionClientDisconnectDetachesCleanup(t *testing.T) {
	c := newCompanionCoordinator(t, 4, lockSemanticsEngine{})
	const path = "/disconnect"
	ctx, cancel := context.WithCancel(context.Background())
	rec := companionForwardAuth(c, ctx, companionReserve(t, c, "disconnect-session", http.MethodPost, path), http.MethodPost, path, &cancelAfterFirstRead{data: []byte("partial body"), cancel: cancel})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disconnected request status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("one client disconnect faulted the composite coordinator: %v", err)
	}
	const nextPath = "/after-disconnect"
	if next := companionForwardAuth(c, context.Background(), companionReserve(t, c, "next-session", http.MethodGet, nextPath), http.MethodGet, nextPath, nil); next.Code != http.StatusOK {
		t.Fatalf("next request status = %d, want %d", next.Code, http.StatusOK)
	}
}
