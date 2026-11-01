package response_observer

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startProvenancePeer(t *testing.T, status int, handle string) (string, <-chan []byte) {
	t.Helper()
	directory, err := os.MkdirTemp("", "mtp")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "p.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	payloads := make(chan []byte, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 12)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		if string(header[:8]) != "MTP1\x01\x01\x00\x00" {
			return
		}
		payload := make([]byte, int(binary.BigEndian.Uint32(header[8:])))
		if len(payload) > 391 {
			return
		}
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		payloads <- payload
		tokenReply := append([]byte{0}, []byte(testHandle)...)
		if _, err := conn.Write(provenanceFrame(128, tokenReply)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		if string(header) != "MTP1\x01\x02\x00\x00\x00\x00\x00\x00" {
			return
		}
		reply := make([]byte, 67)
		binary.BigEndian.PutUint16(reply[1:3], uint16(status))
		copy(reply[3:], handle)
		_, _ = conn.Write(provenanceFrame(128, reply))
	}()
	t.Cleanup(func() { _ = listener.Close(); <-finished; _ = os.RemoveAll(directory) })
	return path, payloads
}

func provenanceRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "192.0.2.1:12345"
	return request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 8080}))
}

func serveConfirmedProvenance(t *testing.T, backend http.Handler, observer, path string) *httptest.ResponseRecorder {
	t.Helper()
	confirm, err := New(context.Background(), backend, &Config{ConfirmProvenance: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(context.Background(), confirm, &Config{SocketPath: observer, ProvenanceSocketPath: path, RunID: "run-1", TransportCaseID: "case-1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, provenanceRequest())
	return recorder
}

func TestProvenanceTerminalReplyRequiresPrivateStatusAndStripsForgedCapability(t *testing.T) {
	path, payloads := startProvenancePeer(t, 403, "")
	var observed string
	handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = r.Header.Get(provenanceHeader)
		if r.Header.Get(responseHandleHeader) != "" {
			t.Error("client handle survived outer observer")
		}
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "deny-bytes")
	}), &Config{ProvenanceSocketPath: path, RunID: "run-1", TransportCaseID: "case-1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	request := provenanceRequest()
	request.Header.Set(provenanceHeader, "forged-client-token")
	request.Header.Set(responseHandleHeader, testHandle)
	request.Header.Set("X-Forwarded-Connection-ID", "forged-connection")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 403 || recorder.Body.String() != "deny-bytes" {
		t.Fatalf("status/body = %d %q", recorder.Code, recorder.Body.String())
	}
	if observed != testHandle || request.Header.Get(provenanceHeader) != "" {
		t.Fatal("reservation was not replaced and stripped")
	}
	payload := <-payloads
	if !strings.Contains(string(payload), "run-1") || !strings.Contains(string(payload), "case-1") ||
		strings.Contains(string(payload), "forged-connection") || payload[len(payload)-1] != 0 {
		t.Fatalf("invalid trusted payload %x", payload)
	}
}

func TestProvenanceOuterAllowUsesPrivateHandleForCanonicalLifecycle(t *testing.T) {
	observer, stop, operations := startFakeObserver(t, func(byte) (byte, byte) { return resultOK, decisionAllow })
	defer stop()
	path, _ := startProvenancePeer(t, 200, testHandle)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(provenanceHeader) != "" || r.Header.Get(responseHandleHeader) != "" {
			t.Error("private headers reached backend")
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "allow-bytes")
	})
	recorder := serveConfirmedProvenance(t, backend, observer, path)
	if recorder.Code != 201 || recorder.Body.String() != "allow-bytes" {
		t.Fatalf("status/body = %d %q", recorder.Code, recorder.Body.String())
	}
	got := operations.snapshot()
	want := []byte{opClaim, opResponseHeaders, opCommit, opResponseBody, opResponseEOS, opRelease}
	if !sameBytes(got, want) {
		t.Fatalf("operations = %v, want %v", got, want)
	}
}

// Fake transport ordering only. Common's physical MTP1/registry C test proves
// the initial five-second deadline and the trusted one-time TTL confirmation.
func TestProvenanceFakeTransportConfirmationPrecedesSlowBackend(t *testing.T) {
	observer, stop, operations := startFakeObserver(t, func(byte) (byte, byte) { return resultOK, decisionAllow })
	defer stop()
	path, _ := startProvenancePeer(t, 200, testHandle)
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5100 * time.Millisecond)
		if len(operations.snapshot()) != 0 {
			t.Error("MRC1 claim consumed backend waiting time")
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "slow-allow-bytes")
	})
	recorder := serveConfirmedProvenance(t, backend, observer, path)
	if recorder.Code != 201 || recorder.Body.String() != "slow-allow-bytes" {
		t.Fatalf("status/body = %d %q", recorder.Code, recorder.Body.String())
	}
}

func startCleanupCausePeer(t *testing.T) (string, <-chan byte) {
	t.Helper()
	directory, err := os.MkdirTemp("", "mrc-cancel")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "c.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	causes := make(chan byte, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		op, handle, err := readTestFrame(reader)
		if err != nil || op != opClaim || string(handle) != testHandle {
			return
		}
		if writeTestResult(conn, opClaim, decisionAllow, resultOK) != nil {
			return
		}
		op, payload, err := readTestFrame(reader)
		if err != nil || op != opCancel || len(payload) != 1 {
			return
		}
		causes <- payload[0]
		_ = writeTestResult(conn, opCancel, decisionError, resultOK)
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; _ = os.RemoveAll(directory) })
	return path, causes
}

func provenanceHeaderExitFixture(t *testing.T, mode string) (http.Handler, *http.Request, <-chan byte) {
	t.Helper()
	observer, causes := startCleanupCausePeer(t)
	path, _ := startProvenancePeer(t, 200, testHandle)
	request := provenanceRequest()
	ctx, cancel := context.WithCancel(request.Context())
	t.Cleanup(cancel)
	request = request.WithContext(ctx)
	confirm, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		if mode == "cancel" {
			cancel()
		}
		if mode == "panic" {
			panic("fixture panic")
		}
	}), &Config{ConfirmProvenance: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := New(context.Background(), confirm, &Config{SocketPath: observer, ProvenanceSocketPath: path, RunID: "run", TransportCaseID: "case"}, "")
	if err != nil {
		t.Fatal(err)
	}
	return outer, request, causes
}

func assertProvenanceHeaderExit(t *testing.T, mode string) {
	t.Helper()
	outer, request, causes := provenanceHeaderExitFixture(t, mode)
	recorder := httptest.NewRecorder()
	var recovered any
	func() { defer func() { recovered = recover() }(); outer.ServeHTTP(recorder, request) }()
	if mode == "panic" && recovered != "fixture panic" {
		t.Fatalf("panic = %v", recovered)
	}
	if mode != "panic" && (recovered != nil || recorder.Code != 503) {
		t.Fatalf("panic/status = %v %d", recovered, recorder.Code)
	}
	want := cancelConnectorError
	if mode == "cancel" {
		want = cancelClientCancel
	}
	select {
	case got := <-causes:
		if got != want {
			t.Fatalf("cause = %d want %d", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no typed cleanup claim/cancel")
	}
}

func TestProvenanceBeforeHeaderExitClaimsOnlyForTypedCleanup(t *testing.T) {
	for _, mode := range []string{"cancel", "panic", "return"} {
		t.Run(mode, func(t *testing.T) { assertProvenanceHeaderExit(t, mode) })
	}
}

func TestProvenanceCleanupClaimFailureIsPhysicallyLoggedAndFailsClosed(t *testing.T) {
	path, _ := startProvenancePeer(t, 200, testHandle)
	confirm, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), &Config{ConfirmProvenance: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := New(context.Background(), confirm, &Config{SocketPath: path + ".missing", ProvenanceSocketPath: path, RunID: "private-run-do-not-log", TransportCaseID: "private-case-do-not-log"}, "")
	if err != nil {
		t.Fatal(err)
	}
	readLog, writeLog, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readLog.Close()
	original := log.Writer()
	log.SetOutput(writeLog)
	defer log.SetOutput(original)
	recorder := httptest.NewRecorder()
	outer.ServeHTTP(recorder, provenanceRequest())
	log.SetOutput(original)
	_ = writeLog.Close()
	physical, err := io.ReadAll(io.LimitReader(readLog, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 503 || recorder.Body.Len() != 0 {
		t.Fatalf("status/body = %d %q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(string(physical), "trusted reservation cleanup failed") || strings.Contains(string(physical), testHandle) || strings.Contains(string(physical), "private-run-do-not-log") {
		t.Fatalf("unsafe/missing physical cleanup log: %q", physical)
	}
}

func TestProvenanceConfirmationRejectsMissingAndDuplicateContext(t *testing.T) {
	called := false
	backend := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	confirm, err := New(context.Background(), backend, &Config{ConfirmProvenance: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	confirm.ServeHTTP(recorder, provenanceRequest())
	if called || recorder.Code != 503 {
		t.Fatal("missing private context reached backend")
	}
	path, _ := startProvenancePeer(t, 200, testHandle)
	duplicate, err := New(context.Background(), confirm, &Config{ConfirmProvenance: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := New(context.Background(), duplicate, &Config{SocketPath: path + ".missing", ProvenanceSocketPath: path, RunID: "run-1", TransportCaseID: "case-1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	outer.ServeHTTP(recorder, provenanceRequest())
	if called || recorder.Code != 503 {
		t.Fatal("duplicate confirmation reached backend")
	}
}

func TestProvenanceTerminalStatusMismatchFailsBeforeClientBytes(t *testing.T) {
	path, _ := startProvenancePeer(t, 403, "")
	handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "unattested-bytes")
	}), &Config{ProvenanceSocketPath: path, RunID: "run-1", TransportCaseID: "case-1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, provenanceRequest())
	if recorder.Code != 503 || recorder.Body.Len() != 0 {
		t.Fatalf("status/body = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestProvenanceCorrelationDoesNotTrustForwardedHeadersOrAssertReuse(t *testing.T) {
	m := &middleware{}
	if err := m.initializeCorrelationSecret(); err != nil {
		t.Fatal(err)
	}
	request := provenanceRequest()
	first, err := m.connectionCorrelation(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Forwarded-For", "attacker")
	again, err := m.connectionCorrelation(request)
	if err != nil || first != again {
		t.Fatal("forwarded metadata changed physical tuple correlation")
	}
	request.RemoteAddr = "192.0.2.1:12346"
	other, err := m.connectionCorrelation(request)
	if err != nil || other == first {
		t.Fatal("distinct physical tuples shared correlation")
	}
	request.RemoteAddr = "bad tuple"
	if _, err := m.connectionCorrelation(request); err == nil {
		t.Fatal("missing binding accepted")
	}
}

func TestProvenanceConfigurationIsAtomicAndBounded(t *testing.T) {
	for _, config := range []Config{
		{ConfirmProvenance: true, RunID: "run"},
		{RunID: "run"}, {ProvenanceSocketPath: "/run/p.sock", RunID: "run"},
		{ProvenanceSocketPath: "/run/p.sock", RunID: "bad value", TransportCaseID: "case"},
		{ProvenanceSocketPath: "/run/p.sock", RunID: strings.Repeat("a", 129), TransportCaseID: "case"},
	} {
		if _, err := normalizeConfig(&config); err == nil {
			t.Fatalf("invalid provenance config accepted: %+v", config)
		}
	}
}
