package compositetraefik

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

type udsEventLog struct {
	mu     sync.Mutex
	events []composite.Event
}

func (l *udsEventLog) Observe(event composite.Event) error {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
	return nil
}

type p2BlockingEngine struct{}

func (p2BlockingEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return p2BlockingTx{}, nil
}

type p2BlockingTx struct{}

func (p2BlockingTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (p2BlockingTx) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionDeny, Status: http.StatusForbidden}, nil
}

func (p2BlockingTx) Close(context.Context, processor.Summary) {}

type p4LogOnlyEngine struct{}

func (p4LogOnlyEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return p4LogOnlyTx{}, nil
}

type p4LogOnlyTx struct{}

func (p4LogOnlyTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (p4LogOnlyTx) ProcessBody(_ context.Context, direction processor.Direction, body []byte, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionResponse && len(body) > 0 {
		return processor.Decision{Action: processor.ActionDeny, Status: http.StatusForbidden}, nil
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (p4LogOnlyTx) Close(context.Context, processor.Summary) {}

type p4ProcessingErrorEngine struct{}

func (p4ProcessingErrorEngine) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	return p4ProcessingErrorTx{}, nil
}

type p4ProcessingErrorTx struct{}

func (p4ProcessingErrorTx) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (p4ProcessingErrorTx) ProcessBody(_ context.Context, direction processor.Direction, _ []byte, _ bool) (processor.Decision, error) {
	if direction == processor.DirectionResponse {
		return processor.Decision{}, errors.New("P4 processing failure")
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (p4ProcessingErrorTx) Close(context.Context, processor.Summary) {}

func TestPrivateUDSForwardAuthAndResponseUseOneTransaction(t *testing.T) {
	log := &udsEventLog{}
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, processor.PassthroughEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := startUDSPipe(t, &UDS{Coordinator: c})

	reserved := exchangeUDS(t, client, opReserve, reservationSnapshotPayload(t, http.MethodPost, "/check", nil))
	if reserved.op != opReserve || reserved.decision != decisionAllow || reserved.value == "" {
		t.Fatalf("reserve result = %#v", reserved)
	}
	forwardAuthRequest(t, c, reserved.value, http.MethodPost, "/check", []byte("hello"), http.StatusOK)

	claimed := exchangeUDS(t, client, opClaim, tokenPayload(reserved.value))
	if claimed.op != opClaim || claimed.decision != decisionAllow || claimed.flags != 0 {
		t.Fatalf("claim result = %#v", claimed)
	}
	if got := exchangeUDS(t, client, opResponseHeaders, responseHeaderPayload(http.StatusOK)); got.decision != decisionAllow {
		t.Fatalf("P3 result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseCommit, []byte{1, 0}); got.decision != decisionAllow {
		t.Fatalf("commit result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseEOS, nil); got.decision != decisionAllow {
		t.Fatalf("P4 result = %#v", got)
	}
	if got := exchangeUDS(t, client, opOutcome, []byte{0, 0, http.StatusOK}); got.decision != decisionAllow {
		t.Fatalf("outcome result = %#v", got)
	}
	if got := exchangeUDS(t, client, opFinish, nil); got.decision != decisionAllow {
		t.Fatalf("finish result = %#v", got)
	}

	events := waitForTerminal(t, log)
	assertOneTransaction(t, events, "P1", "P2", "P3", "P4")
}

func TestP4LogOnlyResultPreservesCommittedChunkAndRecordsOutcome(t *testing.T) {
	log := &udsEventLog{}
	c, client, lease := startP4Test(t, p4LogOnlyEngine{}, log, "/p4-log-only", []byte("request"))
	defer c.Close()
	completeP4LogOnlyLifecycle(t, client, lease)

	events := waitForTerminal(t, log)
	assertOneTransaction(t, events, "P1", "P2", "P3", "P4")
	assertP4LogOnlyEvents(t, events)
}

func startP4Test(t *testing.T, engine processor.TransactionOpener, log composite.Observer, path string, body []byte) (*composite.Coordinator, net.Conn, string) {
	t.Helper()
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, engine, log)
	if err != nil {
		t.Fatal(err)
	}
	client := startUDSPipe(t, &UDS{Coordinator: c})
	reserved := exchangeUDS(t, client, opReserve, reservationSnapshotPayload(t, http.MethodPost, path, nil))
	if reserved.decision != decisionAllow || reserved.value == "" {
		t.Fatalf("reserve result = %#v", reserved)
	}
	forwardAuthRequest(t, c, reserved.value, http.MethodPost, path, body, http.StatusOK)
	return c, client, reserved.value
}

func completeP4LogOnlyLifecycle(t *testing.T, client net.Conn, lease string) {
	t.Helper()
	if got := exchangeUDS(t, client, opClaim, tokenPayload(lease)); got.decision != decisionAllow || got.flags != 0 {
		t.Fatalf("claim result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseHeaders, responseHeaderPayload(http.StatusOK)); got.decision != decisionAllow {
		t.Fatalf("P3 result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseCommit, []byte{1, 0}); got.decision != decisionAllow {
		t.Fatalf("commit result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseChunk, []byte("committed")); got.decision != decisionAllow || got.flags != resultFlagPostCommitLogOnly || got.status != 0 {
		t.Fatalf("P4 log-only result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseEOS, nil); got.decision != decisionAllow || got.flags != 0 {
		t.Fatalf("P4 EOS result = %#v", got)
	}
	if got := exchangeUDS(t, client, opOutcome, []byte{3, 0, http.StatusOK}); got.decision != decisionAllow {
		t.Fatalf("log-only outcome result = %#v", got)
	}
	if got := exchangeUDS(t, client, opFinish, nil); got.decision != decisionAllow {
		t.Fatalf("finish result = %#v", got)
	}
}

func assertP4LogOnlyEvents(t *testing.T, events []composite.Event) {
	t.Helper()
	var sawP4Deny, sawLogOnlyOutcome bool
	for _, event := range events {
		switch event.Phase {
		case "P4":
			sawP4Deny = event.RequestedAction == string(processor.ActionDeny)
		case "host_action":
			sawLogOnlyOutcome = event.ActualHostAction == string(processor.AppliedActionLogOnly) && event.VisibleStatus == http.StatusOK
		}
	}
	if !sawP4Deny || !sawLogOnlyOutcome {
		t.Fatalf("P4 log-only lifecycle evidence = %#v", events)
	}
}

func TestP4ProcessingErrorReturnsTerminalRejectWithoutLogOnlyFlag(t *testing.T) {
	c, client, lease := startP4Test(t, p4ProcessingErrorEngine{}, nil, "/p4-processing-error", []byte("request"))
	defer c.Close()
	if got := exchangeUDS(t, client, opClaim, tokenPayload(lease)); got.decision != decisionAllow {
		t.Fatalf("claim result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseHeaders, responseHeaderPayload(http.StatusOK)); got.decision != decisionAllow {
		t.Fatalf("P3 result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseCommit, []byte{1, 0}); got.decision != decisionAllow {
		t.Fatalf("commit result = %#v", got)
	}
	if got := exchangeUDS(t, client, opResponseChunk, []byte("invalid")); got.decision != decisionDeny || got.status != http.StatusServiceUnavailable || got.flags != 0 {
		t.Fatalf("P4 processing failure result = %#v", got)
	}
}

func TestP2BlockUsesRequestTerminalFlagWithoutP3P4(t *testing.T) {
	log := &udsEventLog{}
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{}, p2BlockingEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := startUDSPipe(t, &UDS{Coordinator: c})

	reserved := exchangeUDS(t, client, opReserve, reservationSnapshotPayload(t, http.MethodPost, "/blocked", nil))
	forwardAuthRequest(t, c, reserved.value, http.MethodPost, "/blocked", []byte("body"), http.StatusForbidden)
	claimed := exchangeUDS(t, client, opClaim, tokenPayload(reserved.value))
	if claimed.op != opClaim || claimed.decision != decisionAllow || claimed.flags != resultFlagRequestTerminal {
		t.Fatalf("request-terminal claim = %#v", claimed)
	}
	if got := exchangeUDS(t, client, opFinish, nil); got.decision != decisionAllow {
		t.Fatalf("request-terminal finish = %#v", got)
	}

	events := waitForTerminal(t, log)
	assertOneTransaction(t, events, "P1", "P2")
	for _, event := range events {
		if event.Phase == "P3" || event.Phase == "P4" || event.Phase == "lease" {
			t.Fatalf("request-terminal path emitted forbidden event: %#v", event)
		}
	}
}

func TestUnclaimedReservationUDSTimeoutRecordsTimeoutCleanup(t *testing.T) {
	log := &udsEventLog{}
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{IdleTTL: time.Second}, processor.PassthroughEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := startUDSPipe(t, &UDS{Coordinator: c, Timeout: 10 * time.Millisecond})
	reserved := exchangeUDS(t, client, opReserve, reservationSnapshotPayload(t, http.MethodGet, "/timeout", nil))
	if reserved.op != opReserve || reserved.decision != decisionAllow || reserved.value == "" {
		t.Fatalf("reserve result = %#v", reserved)
	}

	events := waitForTerminal(t, log)
	terminal := events[len(events)-1]
	if terminal.Phase != "terminal" || terminal.Reason != "timeout" || terminal.CleanupOutcome != "closed" {
		t.Fatalf("timeout terminal = %#v", terminal)
	}
	for _, event := range events {
		if event.Phase == "P1" || event.Phase == "P2" || event.Phase == "lease" {
			t.Fatalf("unclaimed timeout emitted request/lease evidence: %#v", event)
		}
	}
}

func TestUnclaimedReservationUDSWriteTimeoutRecordsTimeoutCleanup(t *testing.T) {
	log := &udsEventLog{}
	c, err := composite.New("traefik", []byte("01234567890123456789012345678901"), composite.Limits{IdleTTL: time.Second}, processor.PassthroughEngine{}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := startUDSPipe(t, &UDS{Coordinator: c, Timeout: 10 * time.Millisecond})
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeFrame(client, opReserve, reservationSnapshotPayload(t, http.MethodGet, "/write-timeout", nil))
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("reserve write = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reserve write did not complete")
	}

	events := waitForTerminal(t, log)
	terminal := events[len(events)-1]
	if terminal.Phase != "terminal" || terminal.Reason != "timeout" || terminal.CleanupOutcome != "closed" {
		t.Fatalf("write-timeout terminal = %#v", terminal)
	}
	for _, event := range events {
		if event.Phase == "P1" || event.Phase == "P2" || event.Phase == "lease" {
			t.Fatalf("unclaimed write timeout emitted request/lease evidence: %#v", event)
		}
	}
}

func TestResponseHeadersRejectInformationalP3(t *testing.T) {
	if _, err := parseResponseHeaders(responseHeaderPayload(http.StatusEarlyHints)); err == nil {
		t.Fatal("accepted informational response as P3")
	}
}

func TestReservationSnapshotRejectsPrivateOrNonCanonicalHeaders(t *testing.T) {
	private := reservationSnapshotPayload(t, http.MethodGet, "/", []processor.Header{{Name: "x-msconnector-composite-lease", Value: []byte("forged")}})
	if _, err := parseReservationSnapshot(private); err == nil {
		t.Fatal("accepted private lease as P1 snapshot header")
	}
	upper := reservationSnapshotPayload(t, http.MethodGet, "/", []processor.Header{{Name: "X-Upper", Value: []byte("value")}})
	if _, err := parseReservationSnapshot(upper); err == nil {
		t.Fatal("accepted non-canonical header name")
	}
	oversized := reservationSnapshotPayload(t, http.MethodGet, "/", []processor.Header{{Name: "x-large", Value: bytes.Repeat([]byte("x"), maxHeaderValue+1)}})
	if _, err := parseReservationSnapshot(oversized); err == nil {
		t.Fatal("accepted oversized request snapshot value")
	}
}

func TestReservationSnapshotAllowsEmptyOrdinaryValueOnly(t *testing.T) {
	snapshot, err := parseReservationSnapshot(reservationSnapshotPayload(t, http.MethodGet, "/", []processor.Header{{Name: "x-optional", Value: nil}}))
	if err != nil {
		t.Fatalf("empty ordinary header value rejected: %v", err)
	}
	defer wipeParsedHeaders(snapshot.Headers)
	foundEmptyOptional := false
	for _, header := range snapshot.Headers {
		if header.Name == "x-optional" && len(header.Value) == 0 {
			foundEmptyOptional = true
			break
		}
	}
	if !foundEmptyOptional {
		t.Fatalf("empty ordinary header value missing: %#v", snapshot.Headers)
	}
	for name, payload := range map[string][]byte{
		"method":      {composite.ReservationSnapshotVersion, 0, 0},
		"uri":         {composite.ReservationSnapshotVersion, 0, 3, 'G', 'E', 'T', 0, 0},
		"header-name": {composite.ReservationSnapshotVersion, 0, 3, 'G', 'E', 'T', 0, 1, '/', 0, 1, 0, 0},
	} {
		if _, err := parseReservationSnapshot(payload); err == nil {
			t.Fatalf("accepted empty %s", name)
		}
	}
}

func TestReservationSnapshotPreservesProtectedConnectionMetadata(t *testing.T) {
	snapshot, err := parseReservationSnapshot(reservationSnapshotPayload(t, http.MethodGet, "/metadata", nil))
	if err != nil {
		t.Fatalf("parse reservation snapshot: %v", err)
	}
	if snapshot.Protocol != "HTTP/1.1" || snapshot.ServerAddress != "127.0.0.1" || snapshot.ServerPort != 8080 {
		t.Fatalf("protected connection metadata = %#v", snapshot)
	}
}

func TestReservationSnapshotRejectsMissingProtectedConnectionMetadata(t *testing.T) {
	// The pre-metadata wire layout must not remain activatable after the
	// protocol change; it has no authenticated protected listener context.
	old := []byte{composite.ReservationSnapshotVersion, 0, 3, 'G', 'E', 'T', 0, 1, '/', 0, 1, 0, 0}
	if _, err := parseReservationSnapshot(old); err == nil {
		t.Fatal("accepted reservation without protected connection metadata")
	}
}

func startUDSPipe(t *testing.T, svc *UDS) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	go svc.handle(server)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func forwardAuthRequest(t *testing.T, c *composite.Coordinator, lease, method, uri string, body []byte, wantStatus int) {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+uri, bytes.NewReader(body))
	req.Header.Set(LeaseHeader, lease)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "example.test")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19182}))
	rec := httptest.NewRecorder()
	(&ForwardAuth{Coordinator: c}).ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("ForwardAuth status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(LeaseHeader); got != "" {
		t.Fatalf("ForwardAuth leaked lease header %q", got)
	}
}

type udsResult struct {
	op, decision, flags byte
	status              uint16
	value               string
}

func exchangeUDS(t *testing.T, conn net.Conn, op byte, payload []byte) udsResult {
	t.Helper()
	if err := writeFrame(conn, op, payload); err != nil {
		t.Fatal(err)
	}
	result, err := readUDSResult(conn)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func readUDSResult(r io.Reader) (udsResult, error) {
	header := make([]byte, frameSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return udsResult{}, err
	}
	if string(header[:4]) != "MSC2" || header[4] != 1 || header[5] != opResult || header[6] != 0 || header[7] != 0 {
		return udsResult{}, errMSC2
	}
	n := binary.BigEndian.Uint32(header[8:12])
	if n < 8 || n > maxFrame {
		return udsResult{}, errMSC2
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return udsResult{}, err
	}
	valueLen := int(binary.BigEndian.Uint16(payload[6:8]))
	if len(payload) != 8+valueLen {
		return udsResult{}, errMSC2
	}
	return udsResult{op: payload[0], decision: payload[2], flags: payload[3], status: binary.BigEndian.Uint16(payload[4:6]), value: string(payload[8:])}, nil
}

func responseHeaderPayload(status int) []byte {
	proto := "HTTP/1.1"
	payload := make([]byte, 6+len(proto))
	binary.BigEndian.PutUint16(payload[:2], uint16(status))
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(proto)))
	copy(payload[4:], proto)
	// The final two bytes are a zero header count.
	return payload
}

func tokenPayload(token string) []byte {
	payload := make([]byte, 2+len(token))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(token)))
	copy(payload[2:], token)
	return payload
}

func reservationSnapshotPayload(t *testing.T, method, uri string, headers []processor.Header) []byte {
	t.Helper()
	groups := make(map[string][][]byte)
	hasHost := false
	for _, header := range headers {
		groups[header.Name] = append(groups[header.Name], append([]byte(nil), header.Value...))
		if header.Name == "host" {
			hasHost = true
		}
	}
	if !hasHost {
		groups["host"] = [][]byte{[]byte("example.test")}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	payload := []byte{composite.ReservationSnapshotVersion}
	payload = appendReservationTestText(t, payload, method)
	payload = appendReservationTestText(t, payload, uri)
	payload = appendReservationTestText(t, payload, "HTTP/1.1")
	payload = appendReservationTestText(t, payload, "127.0.0.1")
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 8080)
	payload = append(payload, port[:]...)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(names)))
	payload = append(payload, size[:]...)
	for _, name := range names {
		payload = appendReservationTestText(t, payload, name)
		values := groups[name]
		binary.BigEndian.PutUint16(size[:], uint16(len(values)))
		payload = append(payload, size[:]...)
		for _, value := range values {
			if len(value) > int(^uint16(0)) {
				t.Fatal("test header value is too long")
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(value)))
			payload = append(payload, size[:]...)
			payload = append(payload, value...)
		}
	}
	return payload
}

func appendReservationTestText(t *testing.T, payload []byte, value string) []byte {
	t.Helper()
	if len(value) == 0 || len(value) > int(^uint16(0)) {
		t.Fatal("test reservation field is invalid")
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(value)))
	payload = append(payload, size[:]...)
	return append(payload, value...)
}

func waitForTerminal(t *testing.T, log *udsEventLog) []composite.Event {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		log.mu.Lock()
		events := append([]composite.Event(nil), log.events...)
		log.mu.Unlock()
		for _, event := range events {
			if event.Phase == "terminal" {
				return events
			}
		}
		time.Sleep(time.Millisecond)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	t.Fatalf("missing terminal event: %#v", log.events)
	return nil
}

func assertOneTransaction(t *testing.T, events []composite.Event, phases ...string) {
	t.Helper()
	ids := make(map[string]string)
	for _, event := range events {
		for _, phase := range phases {
			if event.Phase == phase {
				ids[phase] = event.DecisionID
			}
		}
	}
	var transactionID string
	for _, phase := range phases {
		id := ids[phase]
		if id == "" {
			t.Fatalf("missing %s event in %#v", phase, events)
		}
		if transactionID == "" {
			transactionID = id
		}
		if id != transactionID {
			t.Fatalf("phase %s uses %q; expected %q", phase, id, transactionID)
		}
	}
}
