package composite

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

type fakeEngine struct {
	mu            sync.Mutex
	opens, closes int
	lastID        string
}

type blockingEngine struct{}

func (blockingEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return blockingTx{}, nil
}

type blockingTx struct{}

func (blockingTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionDeny, Status: 403}, nil
}
func (blockingTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionDeny, Status: 403}, nil
}
func (blockingTx) Close(context.Context, processor.Summary)                     {}
func (blockingTx) RecordHostAction(context.Context, processor.HostAction) error { return nil }

func (f *fakeEngine) Open(_ context.Context, meta processor.StreamMetadata) (processor.Transaction, error) {
	f.mu.Lock()
	f.opens++
	f.lastID = meta.TransactionID
	f.mu.Unlock()
	return &fakeTx{}, nil
}

type fakeTx struct {
	mu         sync.Mutex
	phases     []processor.Direction
	closeCount int
	committed  bool
	actions    []processor.HostAction
}

func (f *fakeTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (f *fakeTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (f *fakeTx) Close(context.Context, processor.Summary) {
	f.mu.Lock()
	f.closeCount++
	f.mu.Unlock()
}
func (f *fakeTx) MarkResponseCommitted(context.Context) error {
	f.mu.Lock()
	f.committed = true
	f.mu.Unlock()
	return nil
}
func (f *fakeTx) RecordHostAction(_ context.Context, action processor.HostAction) error {
	f.mu.Lock()
	f.actions = append(f.actions, action)
	f.mu.Unlock()
	return nil
}

type snapshotCaptureEngine struct {
	mu      sync.Mutex
	headers []processor.Header
	meta    processor.StreamMetadata
}

func (e *snapshotCaptureEngine) Open(_ context.Context, meta processor.StreamMetadata) (processor.Transaction, error) {
	e.mu.Lock()
	e.meta = meta
	e.mu.Unlock()
	return &snapshotCaptureTx{engine: e}, nil
}

type snapshotCaptureTx struct{ engine *snapshotCaptureEngine }

func (t *snapshotCaptureTx) ProcessHeaders(_ context.Context, direction processor.Direction, headers []processor.Header, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionRequest {
		copyHeaders := make([]processor.Header, len(headers))
		for i, header := range headers {
			copyHeaders[i] = processor.Header{Name: header.Name, Value: append([]byte(nil), header.Value...)}
		}
		t.engine.mu.Lock()
		t.engine.headers = copyHeaders
		t.engine.mu.Unlock()
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (*snapshotCaptureTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}
func (*snapshotCaptureTx) Close(context.Context, processor.Summary) {}

type eventLog struct {
	mu     sync.Mutex
	events []Event
}

type blockingObserver struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (o *blockingObserver) Observe(Event) error {
	o.once.Do(func() { close(o.started) })
	<-o.release
	return nil
}

type failingObserver struct{ err error }

func (o failingObserver) Observe(Event) error { return o.err }

func (l *eventLog) Observe(e Event) error {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
	return nil
}

func newTestCoordinator(t *testing.T, limits Limits) (*Coordinator, *eventLog) {
	t.Helper()
	log := &eventLog{}
	c, err := New("envoy-ext-proc", []byte("01234567890123456789012345678901"), limits, &fakeEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, log
}

func claimedResponse(t *testing.T, c *Coordinator, session string) *Response {
	t.Helper()
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.Lease()
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Claim(token, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Headers(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	return r
}

func metadata() processor.StreamMetadata {
	return processor.StreamMetadata{TransactionID: "host-id", Request: processor.RequestMetadata{Method: "POST", URI: "/"}}
}

func reservationSnapshot(method, uri string, headers ...processor.Header) ReservationSnapshot {
	stored := make([]processor.Header, 0, len(headers)+1)
	hasHost := false
	for _, header := range headers {
		if header.Name == "host" {
			hasHost = true
		}
		stored = append(stored, processor.Header{Name: header.Name, Value: append([]byte(nil), header.Value...)})
	}
	if !hasHost {
		stored = append(stored, processor.Header{Name: "host", Value: []byte("example.test")})
	}
	sort.SliceStable(stored, func(i, j int) bool { return stored[i].Name < stored[j].Name })
	return ReservationSnapshot{Version: ReservationSnapshotVersion, Method: method, URI: uri, Protocol: "HTTP/1.1", ServerAddress: "198.51.100.7", ServerPort: 443, Headers: stored}
}

func reservationMetadata(method, uri string) processor.StreamMetadata {
	return processor.StreamMetadata{TransactionID: "host-id", Request: processor.RequestMetadata{Method: method, URI: uri, Protocol: "HTTP/1.1", Hostname: "example.test", ServerAddress: "198.51.100.7", ServerPort: 443}}
}

func TestLeaseTamperReplayAndSessionBinding(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.Lease()
	if err != nil {
		t.Fatal(err)
	}
	bad := "B" + token[1:]
	if _, err := c.Claim(bad, "s1"); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("tamper error = %v", err)
	}
	if _, err := c.Claim(token, "s1"); err != nil {
		t.Fatalf("first session claim = %v", err)
	}
	if _, err := c.Claim(token, "s2"); !errors.Is(err, ErrSession) {
		t.Fatalf("second session error = %v", err)
	}
}

func TestReservedLeaseActivatesAndClaimsOnlyOriginalSession(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	snapshot := reservationSnapshot("GET", "/test")
	token, err := c.Reserve("uds-session", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Claim(token, "other-session"); !errors.Is(err, ErrSession) {
		t.Fatalf("wrong reservation session = %v", err)
	}
	a, d, err := c.Activate(context.Background(), token, "GET", "/test", reservationMetadata("GET", "/test"), true)
	if err != nil || d.Action != processor.ActionAllow {
		t.Fatalf("activate = %#v, %v", d, err)
	}
	if _, _, err := c.Activate(context.Background(), token, "GET", "/test", reservationMetadata("GET", "/test"), true); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay activation = %v", err)
	}
	a.Finish(context.Background(), "test")
}

func TestReservedLeaseIsClaimableOnlyAfterP2Allow(t *testing.T) {
	log := &eventLog{}
	c, err := New("traefik", []byte("01234567890123456789012345678901"), Limits{}, &fakeEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	token, err := c.Reserve("uds-session", reservationSnapshot("POST", "/test"))
	if err != nil {
		t.Fatal(err)
	}
	a, d, err := c.Activate(context.Background(), token, "POST", "/test", reservationMetadata("POST", "/test"), false)
	if err != nil || d.Action != processor.ActionAllow {
		t.Fatalf("activate = %#v, %v", d, err)
	}
	a.e.mu.Lock()
	issuedBeforeP2 := a.e.leaseIssued
	a.e.mu.Unlock()
	if issuedBeforeP2 {
		t.Fatal("reservation became claimable before P2")
	}
	if d, err = a.ProcessBody(context.Background(), nil, true); err != nil || d.Action != processor.ActionAllow {
		t.Fatalf("P2 = %#v, %v", d, err)
	}
	if _, err := c.Claim(token, "uds-session"); err != nil {
		t.Fatalf("claim after P2 = %v", err)
	}
}

func TestReservedRequestBlockNeverEmitsLease(t *testing.T) {
	log := &eventLog{}
	c, err := New("traefik", []byte("01234567890123456789012345678901"), Limits{}, blockingEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	token, err := c.Reserve("uds-session", reservationSnapshot("GET", "/blocked"))
	if err != nil {
		t.Fatal(err)
	}
	a, d, err := c.Activate(context.Background(), token, "GET", "/blocked", reservationMetadata("GET", "/blocked"), true)
	if err != nil || d.Action != processor.ActionDeny {
		t.Fatalf("activate = %#v, %v", d, err)
	}
	if err := a.RecordHostAction(context.Background(), processor.HostAction{Action: processor.AppliedActionDeny, VisibleStatus: 403, TransportResult: "response_sent"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Claim(token, "uds-session"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("blocked claim = %v", err)
	}
	a.Finish(context.Background(), "request_block")
	time.Sleep(time.Millisecond)
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, event := range log.events {
		if event.Phase == "lease" {
			t.Fatalf("blocked reservation emitted lease event: %#v", event)
		}
	}
}

func TestUnactivatedReservationAbortOpensAndClosesEventLifecycle(t *testing.T) {
	c, log := newTestCoordinator(t, Limits{Capacity: 1})
	snapshot := reservationSnapshot("GET", "/test")
	token, err := c.Reserve("uds-session", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Abort(token, "uds-session"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		log.mu.Lock()
		ready := len(log.events) >= 2
		log.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
	log.mu.Lock()
	events := append([]Event(nil), log.events...)
	log.mu.Unlock()
	if len(events) != 2 || events[0].Phase != "reservation" || events[0].Outcome != "reserved" || events[1].Phase != "terminal" || events[1].Reason != "abort" || events[1].CleanupOutcome != "closed" {
		t.Fatalf("unactivated reservation lifecycle = %#v", events)
	}
	if _, err := c.Reserve("uds-session-2", snapshot); err != nil {
		t.Fatalf("capacity not released: %v", err)
	}
}

func TestPreActivationClaimLeavesTerminalReasonToOwner(t *testing.T) {
	c, log := newTestCoordinator(t, Limits{Capacity: 1})
	token, err := c.Reserve("uds-session", reservationSnapshot("GET", "/pre-claim"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Claim(token, "uds-session"); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("pre-activation claim = %v", err)
	}
	if err := c.AbortWithReason(token, "uds-session", "disconnect"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.events) != 2 || log.events[1].Phase != "terminal" || log.events[1].Reason != "disconnect" {
		t.Fatalf("pre-activation lifecycle = %#v", log.events)
	}
}

func TestFinishOutOfOrderClaimClosesUnreservedEntry(t *testing.T) {
	c, log := newTestCoordinator(t, Limits{Capacity: 1})
	if err := c.admitCapacity(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e := &entry{
		c:       c,
		id:      "unreserved-out-of-order",
		created: now,
		last:    now,
		phase:   phaseRequestHeaders,
		summary: processor.Summary{TransactionID: "unreserved-out-of-order", LateAction: processor.LateActionNone},
	}
	c.mu.Lock()
	c.entries[e.id] = e
	c.mu.Unlock()

	finishOutOfOrderClaim(e)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		_, present := c.entries[e.id]
		c.mu.Unlock()
		log.mu.Lock()
		complete := !present && len(log.events) == 1
		log.mu.Unlock()
		if complete {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	_, present := c.entries[e.id]
	c.mu.Unlock()
	if present {
		t.Fatal("unreserved entry remained registered")
	}
	e.mu.Lock()
	terminal, closeReason := e.terminal, e.summary.CloseReason
	e.mu.Unlock()
	if !terminal || closeReason != processor.CloseReason("out_of_order") {
		t.Fatalf("unreserved close = terminal %v, reason %q", terminal, closeReason)
	}
	log.mu.Lock()
	events := append([]Event(nil), log.events...)
	log.mu.Unlock()
	if len(events) != 1 || events[0].Phase != "terminal" || events[0].Reason != "out_of_order" {
		t.Fatalf("unreserved terminal events = %#v", events)
	}
	if got := len(c.slots); got != 0 {
		t.Fatalf("capacity slots after unreserved close = %d, want 0", got)
	}
}

func TestReservationSnapshotIsImmutableAndBoundToForwardAuthMetadata(t *testing.T) {
	engine := &snapshotCaptureEngine{}
	c, err := New("traefik", []byte("01234567890123456789012345678901"), Limits{}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	original := []byte("original")
	snapshot := reservationSnapshot("POST", "/snapshot", processor.Header{Name: "x-msconnector-vector", Value: original})
	token, err := c.Reserve("uds-session", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// The caller-owned request bytes cannot influence a reservation after the
	// UDS admission copy has completed.
	original[0] = 'X'
	snapshot.Headers[0].Value[1] = 'Y'
	wrongHost := reservationMetadata("POST", "/snapshot")
	wrongHost.Request.Hostname = "different.example"
	if _, _, err := c.Activate(context.Background(), token, "POST", "/snapshot", wrongHost, true); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("changed host activation = %v", err)
	}
	if _, _, err := c.Activate(context.Background(), token, "POST", "/other", reservationMetadata("POST", "/other"), true); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("changed URI activation = %v", err)
	}
	a, decision, err := c.Activate(context.Background(), token, "POST", "/snapshot", reservationMetadata("POST", "/snapshot"), true)
	if err != nil || decision.Action != processor.ActionAllow {
		t.Fatalf("activate immutable snapshot = %#v, %v", decision, err)
	}
	a.Finish(context.Background(), "test")
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.headers) != 2 || engine.headers[1].Name != "x-msconnector-vector" || string(engine.headers[1].Value) != "original" {
		t.Fatalf("P1 headers = %#v", engine.headers)
	}
}

func TestReservationSnapshotBindsOriginalConnectionMetadata(t *testing.T) {
	engine := &snapshotCaptureEngine{}
	c, err := New("traefik", []byte("01234567890123456789012345678901"), Limits{}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	snapshot := reservationSnapshot("GET", "/bound")
	token, err := c.Reserve("uds-session", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	loopback := reservationMetadata("GET", "/bound")
	loopback.Request.Protocol, loopback.Request.ServerAddress, loopback.Request.ServerPort = "HTTP/2", "127.0.0.1", 19182
	a, _, err := c.Activate(context.Background(), token, "GET", "/bound", loopback, true)
	if err != nil {
		t.Fatal(err)
	}
	a.Finish(context.Background(), "test")
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.meta.Request.Protocol != snapshot.Protocol || engine.meta.Request.ServerAddress != snapshot.ServerAddress || engine.meta.Request.ServerPort != snapshot.ServerPort {
		t.Fatalf("Common metadata=%+v, want original connection metadata", engine.meta.Request)
	}
}

func TestReservationSnapshotRejectsMissingConnectionMetadata(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	snapshot := reservationSnapshot("GET", "/missing")
	snapshot.Protocol, snapshot.ServerAddress, snapshot.ServerPort = "", "", 0
	if _, err := c.Reserve("uds-session", snapshot); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("missing connection metadata = %v", err)
	}
}

func TestReservationSnapshotRejectsInvalidConnectionMetadata(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	for name, mutate := range map[string]func(*ReservationSnapshot){
		"non-http-protocol": func(snapshot *ReservationSnapshot) { snapshot.Protocol = "SMTP/1" },
		"non-ip-address":    func(snapshot *ReservationSnapshot) { snapshot.ServerAddress = "listener.example.test" },
		"invalid-port":      func(snapshot *ReservationSnapshot) { snapshot.ServerPort = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := reservationSnapshot("GET", "/invalid-metadata")
			mutate(&snapshot)
			if _, err := c.Reserve("uds-session", snapshot); !errors.Is(err, ErrInvalidLease) {
				t.Fatalf("invalid connection metadata = %v", err)
			}
		})
	}
}

func TestReservationSnapshotRejectsNonCanonicalHeaders(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	if _, err := c.Reserve("uds-session", reservationSnapshot("GET", "/", processor.Header{Name: "X-Upper", Value: []byte("value")})); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("upper-case snapshot header = %v", err)
	}
	if _, err := c.Reserve("uds-session", reservationSnapshot("GET", "/", processor.Header{Name: "x-bad", Value: []byte("bad\x00value")})); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("NUL snapshot header value = %v", err)
	}
}

func TestLifecycleEventsCarryStaticPipelineMetadata(t *testing.T) {
	for _, test := range []struct {
		connector, requestPath, responsePath, transport string
	}{
		{"envoy", "envoy.ext_authz", "envoy.ext_proc", "envoy_ext_authz_ext_proc_grpc"},
		{"traefik", "traefik.forwardAuth", "traefik.native_uds", "traefik_forwardauth_private_uds"},
	} {
		t.Run(test.connector, func(t *testing.T) {
			log := &eventLog{}
			c, err := New(test.connector, []byte("01234567890123456789012345678901"), Limits{}, &fakeEngine{}, log)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			_, _, err = c.BeginRequest(context.Background(), metadata(), nil, true)
			if err != nil {
				t.Fatal(err)
			}
			waitForRecordedLifecycleEvent(log)
			log.mu.Lock()
			defer log.mu.Unlock()
			if len(log.events) == 0 || log.events[0].RequestPath != test.requestPath || log.events[0].ResponsePath != test.responsePath || log.events[0].Transport != test.transport {
				t.Fatalf("event missing static pipeline metadata: %#v", log.events)
			}
		})
	}
}

func TestGeneratedIDAndLeaseRoundTrip(t *testing.T) {
	eng := &fakeEngine{}
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{}, eng, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := c.BeginRequest(context.Background(), processor.StreamMetadata{TransactionID: "caller-controlled"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if eng.lastID == "" || eng.lastID == "caller-controlled" {
		t.Fatalf("generated ID was not installed: %q", eng.lastID)
	}
	tok, err := a.Lease()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Lease(); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second lease = %v", err)
	}
	if _, err = c.Claim(tok, "generated-stream"); err != nil {
		t.Fatalf("round-trip claim = %v", err)
	}
	c.Close()
}

func TestRequestBlockRetainsAdmissionForActualHostAction(t *testing.T) {
	log := &eventLog{}
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{TTL: time.Millisecond}, blockingEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	a, d, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != processor.ActionDeny {
		t.Fatal("expected P1 deny")
	}
	if _, err = a.Lease(); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("blocked lease = %v", err)
	}
	if err = a.RecordHostAction(context.Background(), processor.HostAction{Action: processor.AppliedActionDeny, VisibleStatus: 403, TransportResult: "response_sent"}); err != nil {
		t.Fatal(err)
	}
	a.Finish(context.Background(), "block")
	c.Close()
}

func TestInvalidAdmissionHostActionDoesNotBlockCleanup(t *testing.T) {
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{Capacity: 1}, blockingEngine{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.RecordHostAction(context.Background(), processor.HostAction{Action: processor.AppliedActionDeny, VisibleStatus: 99, TransportResult: "response_sent"}); err == nil {
		t.Fatal("invalid status was accepted")
	}
	done := make(chan struct{})
	go func() { a.Finish(context.Background(), "block"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Finish blocked after invalid host action")
	}
	if _, _, err = c.BeginRequest(context.Background(), metadata(), nil, true); err != nil {
		t.Fatalf("slot was not released: %v", err)
	}
}

func TestSingleClaimAndResponseOrdering(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := a.Lease()
	r, err := c.Claim(token, "server-stream-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Body(context.Background(), nil, true); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("body before P3 = %v", err)
	}
	if _, err = c.Claim(token, "server-stream-2"); !errors.Is(err, ErrSession) {
		t.Fatalf("duplicate = %v", err)
	}
}

func TestCapacityExpiryAndBoundedBodies(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{Capacity: 1, TTL: time.Hour, IdleTTL: time.Hour})
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.BeginRequest(context.Background(), metadata(), nil, true); !errors.Is(err, ErrLimit) {
		t.Fatalf("capacity = %v", err)
	}
	if _, err = a.ProcessBody(context.Background(), []byte("123"), true); err != nil {
		t.Fatalf("body limit = %v", err)
	}
	a.Finish(context.Background(), "block")
	if _, _, err = c.BeginRequest(context.Background(), metadata(), nil, true); err != nil {
		t.Fatalf("capacity was not released: %v", err)
	}

	e, _ := newTestCoordinator(t, Limits{TTL: time.Millisecond, IdleTTL: time.Hour})
	aa, _, err := e.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := aa.Lease()
	time.Sleep(2 * time.Millisecond)
	if _, err = e.Claim(tok, "s"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry = %v", err)
	}
}

func TestRequestChunksHaveNoConnectorAggregateGate(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		d, err := a.ProcessBody(context.Background(), []byte("full-chunk"), i == 299)
		if err != nil || d.Action != processor.ActionAllow {
			t.Fatalf("chunk%d decision=%#v error=%v", i, d, err)
		}
	}
	a.Finish(context.Background(), "success")
}

func TestCleanupExactlyOnceOnCancelAndRestart(t *testing.T) {
	eng := &fakeEngine{}
	log := &eventLog{}
	c, err := New("connector", []byte("01234567890123456789012345678901"), Limits{}, eng, log)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	a.Cancel(context.Background())
	a.Cancel(context.Background())
	c.Restart()
	c.Close()
	log.mu.Lock()
	defer log.mu.Unlock()
	terminal := 0
	for _, e := range log.events {
		if e.Phase == "terminal" {
			terminal++
		}
		if e.Reason == "" && e.Phase == "terminal" {
			t.Fatal("terminal event has no reason")
		}
	}
	if terminal != 1 {
		t.Fatalf("terminal events = %d", terminal)
	}
}

func TestEmptyRequestAndResponseBody(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	r := claimedResponse(t, c, "session")
	r.Finish(context.Background(), "success")
}

func TestResponseChunksHaveNoCumulativeInspectionBudget(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.ProcessBody(context.Background(), []byte("request"), true); err != nil {
		t.Fatalf("request body = %v", err)
	}
	token, err := a.Lease()
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Claim(token, "stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Headers(context.Background(), nil, false); err != nil {
		t.Fatalf("response headers = %v", err)
	}
	for i := 0; i < 300; i++ {
		if _, err = r.Body(context.Background(), []byte("response"), i == 299); err != nil {
			t.Fatalf("response chunk %d: %v", i, err)
		}
	}
	r.Finish(context.Background(), "success")
}

func TestCommitAndPostCommitActionAreBoundAndTruthful(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	r := claimedResponse(t, c, "server-session")
	if err := r.MarkResponseCommitted(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordHostAction(context.Background(), processor.HostAction{Action: processor.AppliedActionDeny, VisibleStatus: 403, TransportResult: "response_sent"}); err != nil {
		t.Fatal(err)
	}
	r.Finish(context.Background(), "success")
}

func TestEventQueueSaturationFailsClosed(t *testing.T) {
	observer := &blockingObserver{started: make(chan struct{}), release: make(chan struct{})}
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{Capacity: 1}, &fakeEngine{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	e := &entry{c: c, id: "event-only"}
	if err := e.emitLocked(Event{DecisionID: e.id, Connector: "envoy", Phase: "test"}); err != nil {
		t.Fatal(err)
	}
	<-observer.started
	for i := 0; i < cap(c.events); i++ {
		if err := e.emitLocked(Event{DecisionID: e.id, Connector: "envoy", Phase: "test"}); err != nil {
			t.Fatalf("queued event %d: %v", i, err)
		}
	}
	if err := e.emitLocked(Event{DecisionID: e.id, Connector: "envoy", Phase: "overflow"}); !errors.Is(err, ErrEventBackpressure) {
		t.Fatalf("overflow = %v", err)
	}
	if err := c.Err(); !errors.Is(err, ErrEventBackpressure) {
		t.Fatalf("fault = %v", err)
	}
	if _, _, err := c.BeginRequest(context.Background(), metadata(), nil, true); !errors.Is(err, ErrEventBackpressure) {
		t.Fatalf("admission after saturation = %v", err)
	}
	close(observer.release)
	c.Close()
}

func TestObserverFailureFailsClosed(t *testing.T) {
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{}, &fakeEngine{}, failingObserver{err: errors.New("sink unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	e := &entry{c: c, id: "event-only"}
	if err := e.emitLocked(Event{DecisionID: e.id, Connector: "envoy", Phase: "test"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for c.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := c.Err(); !errors.Is(err, ErrObserver) {
		t.Fatalf("observer fault = %v", err)
	}
	if _, _, err := c.BeginRequest(context.Background(), metadata(), nil, true); !errors.Is(err, ErrObserver) {
		t.Fatalf("admission after observer failure = %v", err)
	}
	c.Close()
}

func TestCloseSynchronizesConcurrentFinish(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.Finish(context.Background(), "success") }()
	c.Close()
	wg.Wait()
}

func TestNeutralOutcomeCarriesVisibleStatus(t *testing.T) {
	log := &eventLog{}
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{}, &fakeEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	r := claimedResponse(t, c, "stream")
	if err := r.MarkResponseCommitted(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordNeutralOutcome(context.Background(), 200, "continue_sent"); err != nil {
		t.Fatal(err)
	}
	r.Finish(context.Background(), "success")
	c.Close()
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, event := range log.events {
		if event.Phase == "neutral_outcome" {
			if event.VisibleStatus != 200 {
				t.Fatalf("visible status = %d", event.VisibleStatus)
			}
			return
		}
	}
	t.Fatal("neutral outcome event missing")
}

func TestNeutralOutcomeRequiresCommittedResponseEnd(t *testing.T) {
	c, _ := newTestCoordinator(t, Limits{})
	a, _, err := c.BeginRequest(context.Background(), metadata(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.Lease()
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Claim(token, "stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Headers(context.Background(), nil, false); err != nil {
		t.Fatal(err)
	}
	if err = r.MarkResponseCommitted(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = r.RecordNeutralOutcome(context.Background(), 200, "too_early"); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("early neutral outcome = %v", err)
	}
	if _, err = r.Body(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	if err = r.RecordNeutralOutcome(context.Background(), 200, "response_completed"); err != nil {
		t.Fatalf("completed neutral outcome = %v", err)
	}
}

// This observer changes its error on each call so replay or replacement of the
// first sink failure is visible independently of the physical writer's latch.
type countedFailureObserver struct {
	calls int
	first error
}

func (o *countedFailureObserver) Observe(Event) error {
	o.calls++
	if o.calls == 1 {
		return o.first
	}
	return errors.New("later observer failure")
}
func TestDispatcherDoesNotReplayFailedObserver(t *testing.T) {
	first := errors.New("first sink failure")
	observer := &countedFailureObserver{first: first}
	c := &Coordinator{observer: observer, events: make(chan Event, 3), eventDone: make(chan struct{})}
	for i := 0; i < 3; i++ {
		c.events <- Event{}
	}
	close(c.events)
	c.dispatchEvents()
	if observer.calls != 1 {
		t.Fatalf("dispatchEvents() observer calls = %d, want 1", observer.calls)
	}
	if got := c.Err(); !errors.Is(got, ErrObserver) || !errors.Is(got, first) {
		t.Fatalf("Err() = %v, want observer class and first cause %v", got, first)
	}
}

type cleanupReportingTx struct {
	*fakeTx
	err error
}

func (tx *cleanupReportingTx) CleanupFailure() error { return tx.err }

type cleanupReportingEngine struct {
	err          error
	beforeReturn func()
	latest       *cleanupReportingTx
}

func (e *cleanupReportingEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	tx := &cleanupReportingTx{fakeTx: &fakeTx{}, err: e.err}
	e.latest = tx
	if e.beforeReturn != nil {
		e.beforeReturn()
	}
	return tx, nil
}
func TestCoordinatorReportsCleanupFailureWithoutDuplicateTerminal(t *testing.T) {
	for _, mode := range []string{"sink", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			testCoordinatorCleanupFailure(t, mode)
		})
	}
}

func testCoordinatorCleanupFailure(t *testing.T, mode string) {
	t.Helper()
	first := errors.New("physical sink failure")
	if mode == "incomplete" {
		first = fmt.Errorf("%w: request incomplete", processor.ErrTransactionFinishPhaseSequence)
	}
	engine := &cleanupReportingEngine{err: first}
	log := &eventLog{}
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{}, engine, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	admission, _, err := c.BeginRequest(context.Background(), metadata(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	tx := engine.latest
	id := admission.e.id
	admission.e.finish(context.Background(), "disconnect")
	admission.e.finish(context.Background(), "disconnect")
	assertCoordinatorCleanupAdmission(t, c, mode, first)
	c.Close()
	tx.mu.Lock()
	closes := tx.closeCount
	tx.mu.Unlock()
	if closes != 1 {
		t.Fatalf("finish(retry) cleanup calls = %d, want 1", closes)
	}
	assertSingleFailedCleanupTerminal(t, log, id)
}

func assertCoordinatorCleanupAdmission(t *testing.T, c *Coordinator, mode string, first error) {
	t.Helper()
	if mode == "sink" {
		if got := c.Err(); !errors.Is(got, first) {
			t.Fatalf("Err(after sink cleanup) = %v, want first cause %v", got, first)
		}
		if _, _, got := c.BeginRequest(context.Background(), metadata(), nil, true); !errors.Is(got, first) {
			t.Fatalf("BeginRequest(after sink cleanup) = %v, want %v", got, first)
		}
	} else {
		if got := c.Err(); got != nil {
			t.Fatalf("Err(after local incomplete finish) = %v, want nil", got)
		}
		if _, _, got := c.BeginRequest(context.Background(), metadata(), nil, true); got != nil {
			t.Fatalf("BeginRequest(after local incomplete finish) = %v, want admitted", got)
		}
	}
}

func assertSingleFailedCleanupTerminal(t *testing.T, log *eventLog, id string) {
	t.Helper()
	log.mu.Lock()
	defer log.mu.Unlock()
	terminal := 0
	for _, event := range log.events {
		if event.DecisionID == id && event.Phase == "terminal" {
			terminal++
			if event.Outcome != "failed" || event.CleanupOutcome != "failed" {
				t.Fatalf("cleanup terminal = %#v, want failed outcome and cleanup", event)
			}
		}
	}
	if terminal != 1 {
		t.Fatalf("finish(retry) terminal events = %d, want 1", terminal)
	}
}

func TestCoordinatorReportsCleanupFailureAfterAdmissionClosesDuringOpen(t *testing.T) {
	first := errors.New("sink cleanup failure after shutdown")
	engine := &cleanupReportingEngine{err: first}
	c, err := New("envoy", []byte("01234567890123456789012345678901"), Limits{}, engine, &eventLog{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	engine.beforeReturn = c.Close
	_, _, err = c.BeginRequest(context.Background(), metadata(), nil, false)
	if !errors.Is(err, first) || !errors.Is(c.Err(), first) {
		t.Fatalf("BeginRequest(shutdown during open) = %v, fault=%v, want %v", err, c.Err(), first)
	}
	if engine.latest.closeCount != 1 {
		t.Fatalf("shutdown close calls = %d, want 1", engine.latest.closeCount)
	}
}

func waitForRecordedLifecycleEvent(log *eventLog) {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		log.mu.Lock()
		ready := len(log.events) > 0
		log.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
}
