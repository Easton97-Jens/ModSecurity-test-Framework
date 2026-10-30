package composite_middleware

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testLeaseHeader = "X-Msconnector-Composite-Lease"

func testRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	return req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2443}))
}

func reservationPayloadForTest(method, target string, headers http.Header, authority string, contentLength int64) ([]byte, error) {
	return reservationPayloadWithMetadata(method, target, headers, reservationTransportMetadata{
		authority: authority, contentLength: contentLength, protocol: "HTTP/1.1",
		serverAddress: "127.0.0.1", serverPort: 2443,
	})
}

func TestMiddlewareReplacesClientLeaseAndCompletesPrivateLifecycle(t *testing.T) {
	token := testToken()
	expectedHeaders := make(http.Header)
	expectedHeaders.Set("X-Msconnector-Vector", "p1-private-snapshot")
	expectedReserve, err := reservationPayloadForTest(http.MethodGet, "/items?mode=full", expectedHeaders, "example.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	socket, done := startMSC2Server(t, privateLifecycleServer(expectedReserve, token))

	mw, err := New(t.Context(), upstreamHandler(t, token), &Config{SocketPath: socket}, "")
	if err != nil {
		t.Fatal(err)
	}
	req := testRequest(http.MethodGet, "http://example.test/items?mode=full")
	req.Header.Set(testLeaseHeader, "client-controlled")
	req.Header.Set(requestContextHeader, "client-controlled")
	req.Header.Set("X-Msconnector-Vector", "p1-private-snapshot")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated || rec.Body.String() != "ok" {
		t.Fatalf("response = %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(testLeaseHeader); got != "" {
		t.Fatalf("lease leaked to client: %q", got)
	}
	if got := rec.Header().Get(requestContextHeader); got != "" {
		t.Fatalf("context leaked to client: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func privateLifecycleServer(expectedReserve []byte, token string) func(net.Conn) error {
	return func(conn net.Conn) error {
		op, payload, err := readMSC2Frame(conn)
		if err != nil {
			return err
		}
		if op != opReserve || !bytes.Equal(payload, expectedReserve) {
			return fmt.Errorf("reserve frame = op %d payload %x", op, payload)
		}
		if err := writeMSC2Result(conn, opReserve, decisionAllow, 0, 0, token); err != nil {
			return err
		}
		if err := expectClaim(conn, token); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opClaim, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectResponseHeaders(conn, token); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opResponseHeaders, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectResponseCommit(conn); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opResponseCommit, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectResponseChunk(conn); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opResponseChunk, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectEmptyOp(conn, opResponseEOS); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opResponseEOS, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectOutcome(conn); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opOutcome, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectEmptyOp(conn, opFinish); err != nil {
			return err
		}
		return writeMSC2Result(conn, opFinish, decisionAllow, 0, 0, "")
	}
}

func expectResponseHeaders(conn net.Conn, token string) error {
	op, payload, err := readMSC2Frame(conn)
	if err != nil {
		return err
	}
	if op != opResponseHeaders || bytes.Contains(payload, []byte(token)) {
		return fmt.Errorf("response header frame leaked lease or has op %d", op)
	}
	return nil
}

func expectResponseCommit(conn net.Conn) error {
	op, payload, err := readMSC2Frame(conn)
	if err != nil {
		return err
	}
	if op != opResponseCommit || !bytes.Equal(payload, []byte{1, 0}) {
		return fmt.Errorf("response commit = op %d payload %x", op, payload)
	}
	return nil
}

func expectResponseChunk(conn net.Conn) error {
	op, payload, err := readMSC2Frame(conn)
	if err != nil {
		return err
	}
	if op != opResponseChunk || string(payload) != "ok" {
		return fmt.Errorf("response chunk = op %d payload %q", op, payload)
	}
	return nil
}

func expectOutcome(conn net.Conn) error {
	op, payload, err := readMSC2Frame(conn)
	if err != nil {
		return err
	}
	if op != opOutcome || !bytes.Equal(payload, []byte{0, 0, 201}) {
		return fmt.Errorf("outcome = op %d payload %x", op, payload)
	}
	return nil
}

func upstreamHandler(t *testing.T, token string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(testLeaseHeader); got != token {
			t.Errorf("server lease = %q", got)
		}
		if got := r.Header.Get(requestContextHeader); got != "" {
			t.Errorf("client context header survived outer sanitization: %q", got)
		}
		stripInternalHeaders(r.Header, testLeaseHeader, requestContextHeader)
		if got := r.Header.Get(testLeaseHeader); got != "" {
			t.Errorf("lease reached simulated upstream: %q", got)
		}
		if got := r.Header.Get(requestContextHeader); got != "" {
			t.Errorf("context reached simulated upstream: %q", got)
		}
		w.Header().Set(testLeaseHeader, token)
		w.Header().Set(requestContextHeader, "forged")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestStripInternalHeadersRemovesTrailerForms(t *testing.T) {
	headers := http.Header{
		testLeaseHeader:                           []string{"forged"},
		requestContextHeader:                      []string{"forged"},
		http.TrailerPrefix + testLeaseHeader:      []string{"forged"},
		http.TrailerPrefix + requestContextHeader: []string{"forged"},
		"Trailer": []string{testLeaseHeader + ", " + requestContextHeader + ", X-Safe"},
		"X-Safe":  []string{"preserved"},
	}
	stripInternalHeaders(headers, testLeaseHeader, requestContextHeader)
	if headers.Get(testLeaseHeader) != "" || headers.Get(requestContextHeader) != "" || headers.Get(http.TrailerPrefix+testLeaseHeader) != "" || headers.Get(http.TrailerPrefix+requestContextHeader) != "" {
		t.Fatalf("private metadata remained in headers: %#v", headers)
	}
	if got := headers.Get("Trailer"); got != "X-Safe" {
		t.Fatalf("Trailer = %q", got)
	}
	if got := headers.Get("X-Safe"); got != "preserved" {
		t.Fatalf("safe header = %q", got)
	}
}

func TestReservationPayloadPreservesTransportContentLength(t *testing.T) {
	payload, err := reservationPayloadForTest(http.MethodPost, "/body", make(http.Header), "example.test", 19)
	if err != nil {
		t.Fatal(err)
	}
	headers := reservationPayloadHeaderValues(t, payload)
	if got := headers["content-length"]; len(got) != 1 || got[0] != "19" {
		t.Fatalf("content-length snapshot = %#v", got)
	}
	if got := headers["host"]; len(got) != 1 || got[0] != "example.test" {
		t.Fatalf("host snapshot = %#v", got)
	}
}

func TestReservationPayloadPreservesZeroTransportContentLength(t *testing.T) {
	payload, err := reservationPayloadForTest(http.MethodPost, "/empty", make(http.Header), "example.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	headers := reservationPayloadHeaderValues(t, payload)
	if got := headers["content-length"]; len(got) != 1 || got[0] != "0" {
		t.Fatalf("zero content-length snapshot = %#v", got)
	}
}

func TestReservationPayloadBindsActualRequestTransportMetadata(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/metadata", nil)
	req.Proto = "HTTP/2.0"
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 2443}))
	payload, err := reservationPayloadForRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	metadata := reservationPayloadTransportMetadata(t, payload)
	if metadata.protocol != "HTTP/2.0" || metadata.address != "192.0.2.44" || metadata.port != 2443 {
		t.Fatalf("transport metadata = %#v", metadata)
	}
}

func TestReservationPayloadRejectsMissingOrInvalidLocalAddress(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/metadata", nil)
	if _, err := reservationPayloadForRequest(req); err == nil {
		t.Fatal("accepted request without actual local address")
	}
	for _, address := range []net.Addr{&net.TCPAddr{IP: nil, Port: 2443}, &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 0}} {
		r := req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, address))
		if _, err := reservationPayloadForRequest(r); err == nil {
			t.Fatalf("accepted invalid local address %v", address)
		}
	}
}

func TestReservationPayloadAllowsEmptyOrdinaryHeaderValue(t *testing.T) {
	payload, err := reservationPayloadForTest(http.MethodGet, "/empty-header", http.Header{"X-Optional": []string{""}}, "example.test", -1)
	if err != nil {
		t.Fatal(err)
	}
	headers := reservationPayloadHeaderValues(t, payload)
	if got, ok := headers["x-optional"]; !ok || len(got) != 1 || got[0] != "" {
		t.Fatalf("empty ordinary header value = %#v", got)
	}
	if _, err := reservationPayloadForTest(http.MethodGet, "/empty-host", http.Header{"Host": []string{""}}, "example.test", -1); err == nil {
		t.Fatal("accepted empty Host value")
	}
}

func TestResponseWriterRecordsDownstreamWriteFailures(t *testing.T) {
	for name, writer := range map[string]http.ResponseWriter{
		"error":       &failingResponseWriter{err: io.ErrClosedPipe},
		"short-write": &failingResponseWriter{short: true},
	} {
		t.Run(name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			peerResult := make(chan error, 1)
			go func() {
				op, _, err := readMSC2Frame(peer)
				if err != nil || op != opResponseChunk {
					peerResult <- fmt.Errorf("response chunk = op %d, err %w", op, err)
					return
				}
				if err := writeMSC2Result(peer, opResponseChunk, decisionAllow, 0, 0, ""); err != nil {
					peerResult <- err
					return
				}
				_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if op, _, err := readMSC2Frame(peer); err == nil {
					peerResult <- fmt.Errorf("unexpected terminal op %d after downstream write failure", op)
					return
				}
				peerResult <- nil
			}()
			rw := &responseWriter{
				writer: writer,
				proto:  &protocolConn{conn: client, timeout: time.Second},
				parent: &Middleware{config: Config{MaxResponseChunkBytes: 4}},
			}
			rw.exchange = func(op byte, payload []byte) (result, error) {
				return rw.proto.exchange(context.Background(), op, payload)
			}
			n, err := rw.writeChunks([]byte("chunk"))
			if err == nil || rw.transportErr == nil {
				t.Fatalf("writeChunks = %d, %v; transportErr = %v", n, err, rw.transportErr)
			}
			if rw.transportErr != err {
				t.Fatalf("transportErr = %v, write error = %v", rw.transportErr, err)
			}
			rw.finish(context.Background())
			if err := <-peerResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResponseWriterSuppressesRejectedResponseChunk(t *testing.T) {
	written := &informationalRecorder{header: make(http.Header)}
	chunkCalls := 0
	rw := &responseWriter{
		writer: written,
		parent: &Middleware{config: Config{MaxResponseChunkBytes: 4}},
	}
	rw.exchange = func(op byte, payload []byte) (result, error) {
		if op != opResponseChunk {
			return result{}, fmt.Errorf("unexpected opcode %d", op)
		}
		chunkCalls++
		if string(payload) != "bad!" {
			return result{}, fmt.Errorf("chunk = %q", payload)
		}
		return result{decision: decisionDeny, status: http.StatusServiceUnavailable}, nil
	}

	n, err := rw.writeChunks([]byte("bad!"))
	if !errors.Is(err, errResponseBodyRejected) || !errors.Is(rw.transportErr, errResponseBodyRejected) {
		t.Fatalf("writeChunks = %d, %v; transportErr = %v", n, err, rw.transportErr)
	}
	if n != 0 || written.body.Len() != 0 || chunkCalls != 1 {
		t.Fatalf("rejected chunk reached writer: n=%d bytes=%q calls=%d", n, written.body.Bytes(), chunkCalls)
	}
}

func TestResponseWriterForwardsAllowedResponseChunkAtSameBoundary(t *testing.T) {
	written := &informationalRecorder{header: make(http.Header)}
	rw := &responseWriter{
		writer: written,
		parent: &Middleware{config: Config{MaxResponseChunkBytes: 4}},
	}
	rw.exchange = func(op byte, payload []byte) (result, error) {
		if op != opResponseChunk || string(payload) != "good" {
			return result{}, fmt.Errorf("unexpected chunk op=%d payload=%q", op, payload)
		}
		return result{decision: decisionAllow}, nil
	}

	n, err := rw.writeChunks([]byte("good"))
	if err != nil || n != 4 || written.body.String() != "good" {
		t.Fatalf("allowed chunk = %d, %v; body=%q", n, err, written.body.String())
	}
}

func TestResponseWriterForwardsPostCommitLogOnlyResponseChunk(t *testing.T) {
	written := &informationalRecorder{header: make(http.Header)}
	rw := &responseWriter{
		writer: written,
		parent: &Middleware{config: Config{MaxResponseChunkBytes: 4}},
	}
	rw.exchange = func(op byte, payload []byte) (result, error) {
		if op != opResponseChunk || string(payload) != "safe" {
			return result{}, fmt.Errorf("unexpected chunk op=%d payload=%q", op, payload)
		}
		return result{decision: decisionAllow, flags: resultFlagPostCommitLogOnly}, nil
	}

	n, err := rw.writeChunks([]byte("safe"))
	if err != nil || n != 4 || written.body.String() != "safe" || !rw.late {
		t.Fatalf("post-commit log-only chunk = %d, %v; body=%q late=%t", n, err, written.body.String(), rw.late)
	}
}

func TestResponseWriterFailsClosedForHijackAndUnwrap(t *testing.T) {
	underlying := &hijackResponseWriter{}
	rw := &responseWriter{writer: underlying}
	if _, ok := any(rw).(http.Hijacker); ok {
		t.Fatal("responseWriter still exposes http.Hijacker")
	}
	if _, ok := any(rw).(interface{ Unwrap() http.ResponseWriter }); ok {
		t.Fatal("responseWriter still exposes Unwrap")
	}
	if _, _, err := http.NewResponseController(rw).Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack error = %v, want %v", err, http.ErrNotSupported)
	}
	if underlying.hijacked {
		t.Fatal("underlying writer was hijacked through wrapper")
	}
}

func TestReservationPayloadRejectsUnboundedHeadersBeforeCopy(t *testing.T) {
	tooManyNames := make(http.Header, maxHeaders+1)
	for i := 0; i < maxHeaders+1; i++ {
		tooManyNames[fmt.Sprintf("X-Test-%d", i)] = []string{"v"}
	}
	if _, err := reservationPayloadForTest(http.MethodGet, "/", tooManyNames, "example.test", 0); err == nil {
		t.Fatal("accepted too many request header names")
	}
	tooManyValues := make(http.Header)
	values := make([]string, maxHeaders+1)
	for i := range values {
		values[i] = "v"
	}
	tooManyValues["X-Test"] = values
	if _, err := reservationPayloadForTest(http.MethodGet, "/", tooManyValues, "example.test", 0); err == nil {
		t.Fatal("accepted too many request header values")
	}
}

func TestMiddlewarePreservesForwardAuthRequestTerminalResponse(t *testing.T) {
	token := testToken()
	socket, done := startMSC2Server(t, func(conn net.Conn) error {
		op, _, err := readMSC2Frame(conn)
		if err != nil || op != opReserve {
			return fmt.Errorf("reserve = op %d err %w", op, err)
		}
		if err := writeMSC2Result(conn, opReserve, decisionAllow, 0, 0, token); err != nil {
			return err
		}
		if err := expectClaim(conn, token); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opClaim, decisionAllow, resultFlagRequestTerminal, 0, ""); err != nil {
			return err
		}
		if err := expectEmptyOp(conn, opFinish); err != nil {
			return err
		}
		return writeMSC2Result(conn, opFinish, decisionAllow, 0, 0, "")
	})

	mw, err := New(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(testLeaseHeader) != token {
			t.Error("reservation was not injected for ForwardAuth")
		}
		w.Header().Set(testLeaseHeader, token)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked\n"))
	}), &Config{SocketPath: socket}, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, testRequest(http.MethodPost, "http://example.test/blocked"))
	if rec.Code != http.StatusForbidden || rec.Body.String() != "blocked\n" {
		t.Fatalf("request-terminal response = %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(testLeaseHeader); got != "" {
		t.Fatalf("lease leaked to client: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMiddlewareReplacesPreCommitUDSFailureWith503(t *testing.T) {
	token := testToken()
	socket, done := startMSC2Server(t, func(conn net.Conn) error {
		if err := reserveAndClaim(conn, token); err != nil {
			return err
		}
		op, _, err := readMSC2Frame(conn)
		if err != nil || op != opResponseHeaders {
			return fmt.Errorf("response headers = op %d err %w", op, err)
		}
		// Closing before a result models the timeout/disconnect seam before
		// response commitment. The outer middleware must still send 503.
		return nil
	})

	mw, err := New(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Upstream-Only", "must-not-survive")
		w.WriteHeader(http.StatusOK)
		if n, err := w.Write([]byte("upstream response")); err != nil || n != len("upstream response") {
			t.Errorf("pre-commit write = %d, %v", n, err)
		}
	}), &Config{SocketPath: socket}, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, testRequest(http.MethodGet, "http://example.test/timeout"))
	if rec.Code != http.StatusServiceUnavailable || rec.Body.Len() != 0 {
		t.Fatalf("pre-commit failure response = %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Upstream-Only"); got != "" {
		t.Fatalf("upstream header survived failure replacement: %q", got)
	}
	if got := rec.Header().Get(testLeaseHeader); got != "" {
		t.Fatalf("lease leaked in failure response: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMiddlewareForwardsInformationalResponseWithoutP3Commit(t *testing.T) {
	token := testToken()
	socket, done := startMSC2Server(t, func(conn net.Conn) error {
		if err := reserveAndClaim(conn, token); err != nil {
			return err
		}
		op, payload, err := readMSC2Frame(conn)
		if err != nil {
			return err
		}
		if op != opResponseHeaders || binary.BigEndian.Uint16(payload[:2]) != http.StatusNoContent {
			return fmt.Errorf("P3 must be final 204, got op %d payload %x", op, payload)
		}
		if err := writeMSC2Result(conn, opResponseHeaders, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		op, payload, err = readMSC2Frame(conn)
		if err != nil || op != opResponseCommit || !bytes.Equal(payload, []byte{1, 0}) {
			return fmt.Errorf("commit = op %d payload %x err %w", op, payload, err)
		}
		if err := writeMSC2Result(conn, opResponseCommit, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectEmptyOp(conn, opResponseEOS); err != nil {
			return err
		}
		if err := writeMSC2Result(conn, opResponseEOS, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		op, payload, err = readMSC2Frame(conn)
		if err != nil || op != opOutcome || !bytes.Equal(payload, []byte{0, 0, http.StatusNoContent}) {
			return fmt.Errorf("outcome = op %d payload %x err %w", op, payload, err)
		}
		if err := writeMSC2Result(conn, opOutcome, decisionAllow, 0, 0, ""); err != nil {
			return err
		}
		if err := expectEmptyOp(conn, opFinish); err != nil {
			return err
		}
		return writeMSC2Result(conn, opFinish, decisionAllow, 0, 0, "")
	})
	mw, err := New(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusNoContent)
	}), &Config{SocketPath: socket}, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := &informationalRecorder{header: make(http.Header)}
	mw.ServeHTTP(rec, testRequest(http.MethodGet, "http://example.test/information"))
	if got := rec.statuses; !bytes.Equal(intsAsBytes(got), intsAsBytes([]int{http.StatusEarlyHints, http.StatusNoContent})) {
		t.Fatalf("statuses = %v", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMiddlewareRejectsProtocolSwitchBeforeP3(t *testing.T) {
	token := testToken()
	socket, done := startMSC2Server(t, func(conn net.Conn) error {
		op, _, err := readMSC2Frame(conn)
		if err != nil || op != opReserve {
			return fmt.Errorf("reserve = op %d err %w", op, err)
		}
		if err := writeMSC2Result(conn, opReserve, decisionAllow, 0, 0, token); err != nil {
			return err
		}
		_, _, err = readMSC2Frame(conn)
		if err != io.EOF {
			return fmt.Errorf("expected no Claim/P3 after 101, got %v", err)
		}
		return nil
	})
	mw, err := New(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	}), &Config{SocketPath: socket}, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := &informationalRecorder{header: make(http.Header)}
	mw.ServeHTTP(rec, testRequest(http.MethodGet, "http://example.test/upgrade"))
	if len(rec.statuses) != 1 || rec.statuses[0] != http.StatusServiceUnavailable {
		t.Fatalf("protocol switch was not failed closed: %v", rec.statuses)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestParseResultRejectsUnexpectedTerminalFlag(t *testing.T) {
	frame := resultPayload(opResponseHeaders, decisionAllow, resultFlagRequestTerminal, 0, "")
	if _, err := parseResult(frame); err == nil {
		t.Fatal("accepted request-terminal flag outside Claim")
	}
	frame = resultPayload(opReserve, decisionAllow, 0, 0, "not-base64")
	if _, err := parseResult(frame); err == nil {
		t.Fatal("accepted non-opaque reservation token")
	}
}

func TestParseResultAcceptsPostCommitLogOnlyFlagOnlyAtP4(t *testing.T) {
	res, err := parseResult(resultPayload(opResponseChunk, decisionAllow, resultFlagPostCommitLogOnly, 0, ""))
	if err != nil || res.flags != resultFlagPostCommitLogOnly {
		t.Fatalf("post-commit log-only result = %#v, %v", res, err)
	}
	if _, err := parseResult(resultPayload(opResponseHeaders, decisionAllow, resultFlagPostCommitLogOnly, 0, "")); err == nil {
		t.Fatal("accepted post-commit log-only flag outside P4")
	}
}

func TestNewRejectsUnsafeSocketPath(t *testing.T) {
	if _, err := New(t.Context(), http.NotFoundHandler(), &Config{SocketPath: "relative.sock"}, ""); err == nil {
		t.Fatal("accepted relative UDS path")
	}
}

func reservationPayloadHeaderValues(t *testing.T, payload []byte) map[string][]string {
	t.Helper()
	result, err := parseReservationPayloadHeaderValues(payload)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type reservationPayloadCursor struct {
	payload []byte
	i       int
}

func (c *reservationPayloadCursor) text(allowEmpty bool) (string, error) {
	if c.i+2 > len(c.payload) {
		return "", errors.New("reservation payload length")
	}
	n := int(binary.BigEndian.Uint16(c.payload[c.i : c.i+2]))
	c.i += 2
	if (!allowEmpty && n == 0) || c.i+n > len(c.payload) {
		return "", errors.New("reservation payload field")
	}
	value := string(c.payload[c.i : c.i+n])
	c.i += n
	return value, nil
}

func (c *reservationPayloadCursor) uint16(label string) (int, error) {
	if c.i+2 > len(c.payload) {
		return 0, fmt.Errorf("reservation payload %s", label)
	}
	value := int(binary.BigEndian.Uint16(c.payload[c.i : c.i+2]))
	c.i += 2
	return value, nil
}

func parseReservationPayloadHeaderValues(payload []byte) (map[string][]string, error) {
	if len(payload) < 1 || payload[0] != reservationSnapshotVersion {
		return nil, errors.New("reservation payload version")
	}
	c := reservationPayloadCursor{payload: payload, i: 1}
	for range 4 {
		if _, err := c.text(false); err != nil {
			return nil, err
		}
	}
	if _, err := c.uint16("server port"); err != nil {
		return nil, err
	}
	groups, err := c.uint16("group count")
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string, groups)
	for group := 0; group < groups; group++ {
		name, err := c.text(false)
		if err != nil {
			return nil, err
		}
		count, err := c.uint16("value count")
		if err != nil {
			return nil, err
		}
		for value := 0; value < count; value++ {
			text, err := c.text(true)
			if err != nil {
				return nil, err
			}
			result[name] = append(result[name], text)
		}
	}
	if c.i != len(payload) {
		return nil, errors.New("reservation payload trailing data")
	}
	return result, nil
}

type transportMetadata struct {
	protocol, address string
	port              int
}

func reservationPayloadTransportMetadata(t *testing.T, payload []byte) transportMetadata {
	t.Helper()
	if len(payload) < 1 || payload[0] != reservationSnapshotVersion {
		t.Fatal("reservation payload version")
	}
	i := 1
	read := func() string {
		if i+2 > len(payload) {
			t.Fatal("reservation payload length")
		}
		n := int(binary.BigEndian.Uint16(payload[i : i+2]))
		i += 2
		if i+n > len(payload) {
			t.Fatal("reservation payload field")
		}
		value := string(payload[i : i+n])
		i += n
		return value
	}
	_ = read()
	_ = read()
	protocol, address := read(), read()
	if i+2 > len(payload) {
		t.Fatal("reservation payload port")
	}
	port := int(binary.BigEndian.Uint16(payload[i : i+2]))
	return transportMetadata{protocol: protocol, address: address, port: port}
}

type failingResponseWriter struct {
	header http.Header
	err    error
	short  bool
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*failingResponseWriter) WriteHeader(int) {}

func (w *failingResponseWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return len(p) - 1, nil
}

type hijackResponseWriter struct {
	header   http.Header
	hijacked bool
}

func (w *hijackResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*hijackResponseWriter) WriteHeader(int) {}

func (*hijackResponseWriter) Write([]byte) (int, error) { return 0, nil }

func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, nil
}

func testToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 96))
}

func startMSC2Server(t *testing.T, handler func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	// Unix-domain socket paths are intentionally capped at 108 bytes. A caller
	// with an unusually long test TMPDIR may set MSC2_TEST_TMPDIR to a short,
	// task-owned directory; ordinary test environments use os.TempDir().
	tmpRoot := os.Getenv("MSC2_TEST_TMPDIR")
	if tmpRoot == "" {
		tmpRoot = os.TempDir()
	}
	dir, err := os.MkdirTemp(tmpRoot, "msc2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "composite.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- handler(conn)
	}()
	return path, done
}

func expectClaim(conn net.Conn, token string) error {
	op, payload, err := readMSC2Frame(conn)
	if err != nil {
		return err
	}
	if op != opClaim || !bytes.Equal(payload, claimPayload(token)) {
		return fmt.Errorf("claim = op %d payload %x", op, payload)
	}
	return nil
}

func reserveAndClaim(conn net.Conn, token string) error {
	op, _, err := readMSC2Frame(conn)
	if err != nil || op != opReserve {
		return fmt.Errorf("reserve = op %d err %w", op, err)
	}
	if err := writeMSC2Result(conn, opReserve, decisionAllow, 0, 0, token); err != nil {
		return err
	}
	if err := expectClaim(conn, token); err != nil {
		return err
	}
	return writeMSC2Result(conn, opClaim, decisionAllow, 0, 0, "")
}

func expectEmptyOp(conn net.Conn, want byte) error {
	op, payload, err := readMSC2Frame(conn)
	if err != nil {
		return err
	}
	if op != want || len(payload) != 0 {
		return fmt.Errorf("frame = op %d payload %x; want empty op %d", op, payload, want)
	}
	return nil
}

func readMSC2Frame(r io.Reader) (byte, []byte, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	if string(header[:4]) != "MSC2" || header[4] != 1 || header[6] != 0 || header[7] != 0 {
		return 0, nil, errProtocol
	}
	n := binary.BigEndian.Uint32(header[8:12])
	if n > maxPayload {
		return 0, nil, errProtocol
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[5], payload, nil
}

func writeMSC2Result(w io.Writer, requestOp, decision, flags byte, status uint16, value string) error {
	return writeMSC2Frame(w, opResult, resultPayload(requestOp, decision, flags, status, value))
}

func resultPayload(requestOp, decision, flags byte, status uint16, value string) []byte {
	payload := make([]byte, 8+len(value))
	payload[0], payload[1], payload[2], payload[3] = requestOp, resultOK, decision, flags
	binary.BigEndian.PutUint16(payload[4:6], status)
	binary.BigEndian.PutUint16(payload[6:8], uint16(len(value)))
	copy(payload[8:], value)
	return payload
}

func writeMSC2Frame(w io.Writer, op byte, payload []byte) error {
	if len(payload) > maxPayload {
		return errProtocol
	}
	header := make([]byte, frameHeaderSize)
	copy(header[:4], "MSC2")
	header[4], header[5] = 1, op
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	if err := writeAll(w, header); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type informationalRecorder struct {
	header   http.Header
	statuses []int
	body     bytes.Buffer
}

func (r *informationalRecorder) Header() http.Header { return r.header }

func (r *informationalRecorder) WriteHeader(status int) {
	r.statuses = append(r.statuses, status)
}

func (r *informationalRecorder) Write(body []byte) (int, error) {
	if len(r.statuses) == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(body)
}

func intsAsBytes(values []int) []byte {
	result := make([]byte, len(values)*2)
	for i, value := range values {
		binary.BigEndian.PutUint16(result[i*2:], uint16(value))
	}
	return result
}
