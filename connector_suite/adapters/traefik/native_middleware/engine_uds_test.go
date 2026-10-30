package native_middleware

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type udsTestResult struct {
	code   byte
	action byte
	status int
}

type udsTestCall struct {
	opcode  byte
	payload []byte
}

type udsWriteNotificationConn struct {
	net.Conn
	writes chan<- struct{}
}

func (connection *udsWriteNotificationConn) Write(payload []byte) (int, error) {
	select {
	case connection.writes <- struct{}{}:
	default:
	}
	return connection.Conn.Write(payload)
}

type udsTestServer struct {
	listener net.Listener
	results  map[byte]udsTestResult
	done     chan struct{}
	calls    []udsTestCall
	err      error
}

func newUDSTestSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "uds-")
	if err != nil {
		t.Fatalf("create short UDS test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove UDS test directory: %v", err)
		}
	})
	return filepath.Join(directory, "engine.sock")
}

func serveUDSTestConnection(server *udsTestServer, connection net.Conn) {
	defer connection.Close()
	for {
		opcode, payload, err := readUDSFrame(connection)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				server.err = err
			}
			return
		}
		copyPayload := append([]byte(nil), payload...)
		server.calls = append(server.calls, udsTestCall{opcode: opcode, payload: copyPayload})
		result := udsTestResult{action: udsActionAllow}
		if configured, ok := server.results[opcode]; ok {
			result = configured
		}
		if err := writeUDSTestResult(connection, opcode, result); err != nil {
			server.err = err
			return
		}
		if opcode == udsOpcodeDestroy {
			return
		}
	}
}

func startUDSTestServer(t *testing.T, results map[byte]udsTestResult) (string, *udsTestServer) {
	t.Helper()
	socketPath := newUDSTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen Unix socket: %v", err)
	}
	server := &udsTestServer{listener: listener, results: results, done: make(chan struct{})}
	go func() {
		defer close(server.done)
		defer server.listener.Close()
		connection, err := server.listener.Accept()
		if err != nil {
			server.err = err
			return
		}
		serveUDSTestConnection(server, connection)
	}()
	return socketPath, server
}

func writeUDSTestResult(writer io.Writer, command byte, result udsTestResult) error {
	payload := make([]byte, 14)
	payload[0] = command
	payload[1] = result.code
	payload[2] = result.action
	binary.BigEndian.PutUint16(payload[4:6], uint16(result.status))
	return writeUDSTestFrame(writer, udsOpcodeResult, payload)
}

// writeUDSTestFrame keeps byte-buffer test construction independent from the
// production UDS connection contract.
func writeUDSTestFrame(writer io.Writer, opcode byte, payload []byte) error {
	frame, err := makeUDSFrame(opcode, payload)
	if err != nil {
		return err
	}
	return writeUDSTestAll(writer, frame)
}

func writeUDSTestAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		count, err := writer.Write(payload)
		if count > 0 {
			payload = payload[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func TestWriteUDSConnectionFrameUsesDuplexConnection(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	result := make(chan error, 1)
	go func() {
		opcode, payload, err := readUDSFrame(server)
		if err != nil {
			result <- err
			return
		}
		if opcode != udsOpcodeBegin || !bytes.Equal(payload, []byte("header-check")) {
			result <- errors.New("connection frame did not preserve opcode and payload")
			return
		}
		result <- nil
	}()

	if err := writeUDSConnectionFrame(client, udsOpcodeBegin, []byte("header-check")); err != nil {
		t.Fatalf("writeUDSConnectionFrame() error = %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func (server *udsTestServer) wait(t *testing.T) []udsTestCall {
	t.Helper()
	select {
	case <-server.done:
	case <-time.After(3 * time.Second):
		_ = server.listener.Close()
		t.Fatal("Unix engine test server did not finish")
	}
	if server.err != nil {
		t.Fatalf("Unix engine test server: %v", server.err)
	}
	return server.calls
}

func newUDSTestMiddleware(t *testing.T, socketPath string, next http.Handler) *Middleware {
	t.Helper()
	config := CreateConfig()
	config.EngineMode = "uds"
	config.EngineSocketPath = socketPath
	config.MaxRequestChunkBytes = 3
	config.MaxResponseChunkBytes = 2
	handler, err := New(context.Background(), next, config, "uds-test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	middleware, ok := handler.(*Middleware)
	if !ok {
		t.Fatalf("New() handler type = %T, want *Middleware", handler)
	}
	return middleware
}

func startBlockedUDSTransaction(t *testing.T, timeout time.Duration, requestURI string) (*unixSocketTransaction, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	transaction := &unixSocketTransaction{
		connection: client,
		timeout:    timeout,
		metadata: Metadata{
			Method:     http.MethodGet,
			RequestURI: requestURI,
		},
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	requestRead := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if _, _, err := readUDSFrame(server); err != nil {
			return
		}
		close(requestRead)
		_, _, _ = readUDSFrame(server)
	}()
	return transaction, requestRead, serverDone
}

func assertUDSFollowUpTransaction(t *testing.T, requestURI string) {
	t.Helper()
	socketPath, server := startUDSTestServer(t, nil)
	engine := &unixSocketEngine{socketPath: socketPath, timeout: time.Second}
	followUp, err := engine.Open(context.Background(), Metadata{Method: http.MethodGet, RequestURI: requestURI})
	if err != nil {
		t.Fatalf("follow-up Open() error = %v", err)
	}
	decision, err := followUp.ProcessHeaders(context.Background(), DirectionRequest, nil, true)
	if err != nil {
		t.Fatalf("follow-up ProcessHeaders() error = %v", err)
	}
	if decision.Action != ActionAllow {
		t.Fatalf("follow-up decision = %#v, want allow", decision)
	}
	followUp.Close(context.Background(), Summary{})
	calls := server.wait(t)
	if countUDSCalls(calls, udsOpcodeBegin) != 1 || countUDSCalls(calls, udsOpcodeDestroy) != 1 {
		t.Fatalf("follow-up UDS lifecycle was not completed: %#v", calls)
	}
}

func TestUDSConfigRejectsValuesOutsideTheWireContract(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "header-count",
			mutate: func(config *Config) {
				config.MaxHeaderCount = udsMaxHeaders + 1
			},
		},
		{
			name: "header-bytes",
			mutate: func(config *Config) {
				config.MaxHeaderBytes = udsMaxPayload + 1
			},
		},
		{
			name: "request-chunk",
			mutate: func(config *Config) {
				config.MaxRequestChunkBytes = udsMaxChunk + 1
			},
		},
		{
			name: "response-chunk",
			mutate: func(config *Config) {
				config.MaxResponseChunkBytes = udsMaxChunk + 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := CreateConfig()
			config.EngineMode = "uds"
			config.EngineSocketPath = "/private/engine.sock"
			test.mutate(config)
			if _, err := New(context.Background(), http.NotFoundHandler(), config, "uds-limit-test"); err == nil {
				t.Fatal("New() unexpectedly accepted an out-of-contract UDS limit")
			}
		})
	}
}

func TestUDSBuildersPreserveWireFormatAndDefaultHTTPVersion(t *testing.T) {
	headers := []Header{
		{Name: "X-One", Value: "alpha"},
		{Name: "X-Two", Value: ""},
	}
	metadata := Metadata{
		TransactionID: "request-7",
		Method:        http.MethodPost,
		RequestURI:    "/orders?a=1",
		Hostname:      "example.test",
		ClientAddress: "192.0.2.10",
		ClientPort:    1234,
		ServerAddress: "198.51.100.2",
		ServerPort:    443,
	}

	begin, err := buildUDSBegin(metadata, headers)
	if err != nil {
		t.Fatalf("buildUDSBegin() error = %v", err)
	}
	wantBegin := make([]byte, 0, len(begin))
	wantBegin = appendUDSWireText(wantBegin, http.MethodPost)
	wantBegin = appendUDSWireText(wantBegin, "/orders?a=1")
	wantBegin = appendUDSWireText(wantBegin, "HTTP/1.1")
	wantBegin = appendUDSWireText(wantBegin, "example.test")
	wantBegin = appendUDSWireText(wantBegin, "192.0.2.10")
	wantBegin = appendUDSWireUint16(wantBegin, 1234)
	wantBegin = appendUDSWireText(wantBegin, "198.51.100.2")
	wantBegin = appendUDSWireUint16(wantBegin, 443)
	wantBegin = appendUDSWireText(wantBegin, "request-7")
	wantBegin = appendUDSWireUint16(wantBegin, 2)
	wantBegin = appendUDSWireText(wantBegin, "X-One")
	wantBegin = appendUDSWireText(wantBegin, "alpha")
	wantBegin = appendUDSWireText(wantBegin, "X-Two")
	wantBegin = appendUDSWireText(wantBegin, "")
	if !bytes.Equal(begin, wantBegin) {
		t.Fatalf("buildUDSBegin() payload = %#v, want %#v", begin, wantBegin)
	}

	response, err := buildUDSResponseHeaders(http.StatusCreated, "", headers)
	if err != nil {
		t.Fatalf("buildUDSResponseHeaders() error = %v", err)
	}
	wantResponse := make([]byte, 0, len(response))
	wantResponse = appendUDSWireUint16(wantResponse, http.StatusCreated)
	wantResponse = appendUDSWireText(wantResponse, "HTTP/1.1")
	wantResponse = appendUDSWireUint16(wantResponse, 2)
	wantResponse = appendUDSWireText(wantResponse, "X-One")
	wantResponse = appendUDSWireText(wantResponse, "alpha")
	wantResponse = appendUDSWireText(wantResponse, "X-Two")
	wantResponse = appendUDSWireText(wantResponse, "")
	if !bytes.Equal(response, wantResponse) {
		t.Fatalf("buildUDSResponseHeaders() payload = %#v, want %#v", response, wantResponse)
	}
}

func TestUDSBuildersRejectInvalidHeaderSerialization(t *testing.T) {
	builders := []struct {
		name  string
		build func([]Header) ([]byte, error)
	}{
		{
			name: "begin",
			build: func(headers []Header) ([]byte, error) {
				return buildUDSBegin(Metadata{Method: http.MethodGet, RequestURI: "/"}, headers)
			},
		},
		{
			name: "response-headers",
			build: func(headers []Header) ([]byte, error) {
				return buildUDSResponseHeaders(http.StatusOK, "HTTP/1.1", headers)
			},
		},
	}
	tests := []struct {
		name        string
		makeHeaders func() []Header
	}{
		{
			name: "too-many-headers",
			makeHeaders: func() []Header {
				return make([]Header, udsMaxHeaders+1)
			},
		},
		{
			name: "empty-name",
			makeHeaders: func() []Header {
				return []Header{{Name: "", Value: "value"}}
			},
		},
		{
			name: "nul-name",
			makeHeaders: func() []Header {
				return []Header{{Name: "X\x00Name", Value: "value"}}
			},
		},
		{
			name: "nul-value",
			makeHeaders: func() []Header {
				return []Header{{Name: "X-Name", Value: "value\x00"}}
			},
		},
		{
			name: "oversized-name",
			makeHeaders: func() []Header {
				return []Header{{Name: strings.Repeat("n", udsMaxHeaderName+1), Value: "value"}}
			},
		},
		{
			name: "oversized-value",
			makeHeaders: func() []Header {
				return []Header{{Name: "X-Name", Value: strings.Repeat("v", udsMaxHeaderValue+1)}}
			},
		},
		{
			name: "oversized-aggregate-payload",
			makeHeaders: func() []Header {
				headers := make([]Header, 8)
				for index := range headers {
					headers[index] = Header{Name: "X", Value: strings.Repeat("v", udsMaxHeaderValue)}
				}
				return headers
			},
		},
	}

	for _, builder := range builders {
		for _, test := range tests {
			t.Run(builder.name+"/"+test.name, func(t *testing.T) {
				payload, err := builder.build(test.makeHeaders())
				if !errors.Is(err, errUDSEngineProtocol) {
					t.Fatalf("builder error = %v, want errUDSEngineProtocol", err)
				}
				if payload != nil {
					t.Fatalf("builder payload = %#v, want nil after invalid header serialization", payload)
				}
			})
		}
	}
}

func appendUDSWireText(payload []byte, value string) []byte {
	payload = appendUDSWireUint16(payload, uint16(len(value)))
	return append(payload, value...)
}

func appendUDSWireUint16(payload []byte, value uint16) []byte {
	return append(payload, byte(value>>8), byte(value))
}

func TestUDSEngineUsesOneSessionForFullLifecycle(t *testing.T) {
	socketPath, server := startUDSTestServer(t, nil)
	middleware := newUDSTestMiddleware(t, socketPath, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, err := io.ReadAll(request.Body); err != nil {
			t.Errorf("ReadAll(request.Body) error = %v", err)
			return
		}
		_, _ = writer.Write([]byte("result"))
	}))

	request := httptest.NewRequest(http.MethodPost, "http://example.test/uds", strings.NewReader("request"))
	request.Header.Set("X-Request-Id", "uds-full-lifecycle")
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, request)
	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	calls := server.wait(t)
	assertUDSOrder(t, calls, []byte{
		udsOpcodeBegin,
		udsOpcodeRequestChunk,
		udsOpcodeRequestEOS,
		udsOpcodeResponseHead,
		udsOpcodeResponseCommit,
		udsOpcodeResponseBody,
		udsOpcodeResponseEOS,
		udsOpcodeFinish,
		udsOpcodeDestroy,
	})
	if countUDSCalls(calls, udsOpcodeBegin) != 1 || countUDSCalls(calls, udsOpcodeDestroy) != 1 {
		t.Fatalf("expected exactly one UDS session, calls=%#v", calls)
	}
}

func TestUDSEngineCancellationClosesBlockedConnection(t *testing.T) {
	transaction, requestRead, serverDone := startBlockedUDSTransaction(t, time.Second, "/cancel")

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := transaction.ProcessHeaders(ctx, DirectionRequest, nil, true)
		result <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("UDS cancellation test did not receive request frame")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ProcessHeaders() error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("canceled UDS read remained blocked")
	}
	if transaction.connection != nil {
		t.Fatal("canceled UDS transaction retained its connection")
	}
	if !transaction.closed {
		t.Fatal("canceled UDS transaction was not made terminal")
	}

	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("canceled UDS peer did not observe connection cleanup")
	}

	// Close is intentionally idempotent after cancellation cleanup.
	transaction.Close(context.Background(), Summary{})
}

func TestUDSEngineTimeoutClosesBlockedConnection(t *testing.T) {
	transaction, requestRead, serverDone := startBlockedUDSTransaction(t, 20*time.Millisecond, "/timeout")

	result := make(chan error, 1)
	started := time.Now()
	go func() {
		_, err := transaction.ProcessHeaders(context.Background(), DirectionRequest, nil, true)
		result <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("UDS timeout test did not receive request frame")
	}

	select {
	case err := <-result:
		var networkErr net.Error
		if !errors.As(err, &networkErr) || !networkErr.Timeout() {
			t.Fatalf("ProcessHeaders() error = %v, want timeout", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed-out UDS read remained blocked")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("UDS timeout took %s", elapsed)
	}
	if transaction.connection != nil || !transaction.closed {
		t.Fatalf("timed-out UDS transaction state = connection:%v closed:%t", transaction.connection != nil, transaction.closed)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("timed-out UDS peer did not observe connection cleanup")
	}

	assertUDSFollowUpTransaction(t, "/timeout-follow-up")
}

func TestUDSEngineCancellationClosesBlockedWriteConnection(t *testing.T) {
	client, server := net.Pipe()
	writeStarted := make(chan struct{}, 1)
	transaction := &unixSocketTransaction{
		connection: &udsWriteNotificationConn{Conn: client, writes: writeStarted},
		timeout:    time.Second,
		metadata: Metadata{
			Method:     http.MethodGet,
			RequestURI: "/cancel-write",
		},
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := transaction.ProcessHeaders(ctx, DirectionRequest, nil, true)
		result <- err
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("UDS cancellation test did not begin a blocked write")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ProcessHeaders() error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("canceled UDS write remained blocked")
	}
	if transaction.connection != nil || !transaction.closed {
		t.Fatalf("canceled UDS transaction state = connection:%v closed:%t", transaction.connection != nil, transaction.closed)
	}
}

func TestUDSEngineInvalidOrIncompleteResultDiscardsConnection(t *testing.T) {
	testCases := []struct {
		name          string
		writeResponse func(net.Conn)
		wantError     error
	}{
		{
			name: "invalid opcode",
			writeResponse: func(connection net.Conn) {
				_ = writeUDSConnectionFrame(connection, udsOpcodeOutcome, nil)
			},
			wantError: errUDSEngineProtocol,
		},
		{
			name: "truncated frame",
			writeResponse: func(connection net.Conn) {
				frame, err := makeUDSFrame(udsOpcodeResult, []byte{0, 0, 0, 0})
				if err != nil {
					return
				}
				_, _ = connection.Write(frame[:udsFrameHeaderSize+1])
			},
			wantError: io.ErrUnexpectedEOF,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client, server := net.Pipe()
			transaction := &unixSocketTransaction{
				connection: client,
				timeout:    time.Second,
				metadata:   Metadata{Method: http.MethodGet, RequestURI: "/invalid-result"},
			}
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				defer server.Close()
				if _, _, err := readUDSFrame(server); err == nil {
					testCase.writeResponse(server)
				}
			}()

			_, err := transaction.ProcessHeaders(context.Background(), DirectionRequest, nil, true)
			if !errors.Is(err, testCase.wantError) {
				t.Fatalf("ProcessHeaders() error = %v, want %v", err, testCase.wantError)
			}
			if transaction.connection != nil || !transaction.closed {
				t.Fatalf("invalid-result UDS transaction state = connection:%v closed:%t", transaction.connection != nil, transaction.closed)
			}
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("invalid-result UDS peer did not complete")
			}

			assertUDSFollowUpTransaction(t, "/invalid-result-follow-up")
		})
	}
}

func TestUDSEngineCancellationAllowsFollowUpTransaction(t *testing.T) {
	firstClient, firstServer := net.Pipe()
	firstTransaction := &unixSocketTransaction{
		connection: firstClient,
		timeout:    time.Second,
		metadata:   Metadata{Method: http.MethodGet, RequestURI: "/first"},
	}
	firstRequestRead := make(chan struct{})
	go func() {
		defer firstServer.Close()
		_, _, _ = readUDSFrame(firstServer)
		close(firstRequestRead)
		_, _, _ = readUDSFrame(firstServer)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, err := firstTransaction.ProcessHeaders(ctx, DirectionRequest, nil, true)
		firstResult <- err
	}()
	select {
	case <-firstRequestRead:
	case <-time.After(time.Second):
		t.Fatal("first UDS transaction did not send request")
	}
	cancel()
	select {
	case err := <-firstResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first ProcessHeaders() error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first canceled UDS transaction remained blocked")
	}

	assertUDSFollowUpTransaction(t, "/follow-up")
}

func TestUDSEngineCloseWithCanceledContextDiscardsConnectionWithoutPanic(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	transaction := &unixSocketTransaction{
		connection: client,
		timeout:    time.Second,
		begun:      true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	transaction.Close(ctx, Summary{})

	if !transaction.closed {
		t.Fatal("Close() did not retain the terminal transaction state")
	}
	if transaction.connection != nil {
		t.Fatal("Close() retained a connection after canceled cleanup")
	}
}

type udsDenyCase struct {
	name       string
	results    map[byte]udsTestResult
	request    *http.Request
	readBody   bool
	denyOpcode byte
}

func runUDSDenyCase(t *testing.T, test udsDenyCase) {
	t.Helper()
	socketPath, server := startUDSTestServer(t, test.results)
	called := false
	middleware := newUDSTestMiddleware(t, socketPath, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		called = true
		if test.readBody {
			_, _ = io.ReadAll(request.Body)
		}
	}))
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, test.request)
	if got, want := response.Code, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if test.name == "phase1" && called {
		t.Fatal("P1 deny unexpectedly invoked downstream handler")
	}
	calls := server.wait(t)
	if countUDSCalls(calls, test.denyOpcode) != 1 {
		t.Fatalf("missing deny opcode %d: %#v", test.denyOpcode, calls)
	}
	outcome := findUDSCall(calls, udsOpcodeOutcome)
	if outcome == nil || len(outcome.payload) != 4 || outcome.payload[1] != udsOutcomeApplied {
		t.Fatalf("missing applied host outcome: %#v", calls)
	}
}

func TestUDSEngineAcknowledgesP1AndP2HostDenies(t *testing.T) {
	tests := []udsDenyCase{
		{
			name:       "phase1",
			results:    map[byte]udsTestResult{udsOpcodeBegin: {action: udsActionDeny, status: http.StatusForbidden}},
			request:    httptest.NewRequest(http.MethodGet, "http://example.test/p1", nil),
			denyOpcode: udsOpcodeBegin,
		},
		{
			name:       "phase2",
			results:    map[byte]udsTestResult{udsOpcodeRequestEOS: {action: udsActionDeny, status: http.StatusForbidden}},
			request:    httptest.NewRequest(http.MethodPost, "http://example.test/p2", strings.NewReader("request")),
			readBody:   true,
			denyOpcode: udsOpcodeRequestEOS,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runUDSDenyCase(t, test)
		})
	}
}

func TestUDSEngineDoesNotAcknowledgeAnUnconfirmedHostWrite(t *testing.T) {
	socketPath, server := startUDSTestServer(t, map[byte]udsTestResult{
		udsOpcodeBegin: {action: udsActionDeny, status: http.StatusForbidden},
	})
	middleware := newUDSTestMiddleware(t, socketPath, http.NotFoundHandler())
	response := &failingDecisionResponseWriter{header: make(http.Header)}
	expectHostStop(t, func() {
		middleware.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/p1", nil))
	})
	if got, want := response.status, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	calls := server.wait(t)
	if outcome := findUDSCall(calls, udsOpcodeOutcome); outcome != nil {
		t.Fatalf("host outcome was recorded after failed ResponseWriter.Write: %#v", outcome)
	}
	if countUDSCalls(calls, udsOpcodeResponseCommit) != 1 {
		t.Fatalf("expected commit metadata after WriteHeader, calls=%#v", calls)
	}
}

type udsResponseCase struct {
	name        string
	results     map[byte]udsTestResult
	wantStatus  int
	wantBody    string
	lateLogOnly bool
}

func runUDSResponseCase(t *testing.T, test udsResponseCase) {
	t.Helper()
	socketPath, server := startUDSTestServer(t, test.results)
	middleware := newUDSTestMiddleware(t, socketPath, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("first"))
		_, _ = writer.Write([]byte("second"))
	}))
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/response", nil))
	if got := response.Code; got != test.wantStatus {
		t.Fatalf("status = %d, want %d", got, test.wantStatus)
	}
	if got := response.Body.String(); got != test.wantBody {
		t.Fatalf("body = %q, want %q", got, test.wantBody)
	}
	assertUDSOutcome(t, server.wait(t), test.lateLogOnly)
}

func assertUDSOutcome(t *testing.T, calls []udsTestCall, lateLogOnly bool) {
	t.Helper()
	outcome := findUDSCall(calls, udsOpcodeOutcome)
	if outcome == nil || len(outcome.payload) != 4 {
		t.Fatalf("missing outcome: %#v", calls)
	}
	if lateLogOnly {
		if outcome.payload[0] != udsActionLogOnly || outcome.payload[1] != 0 ||
			binary.BigEndian.Uint16(outcome.payload[2:]) != http.StatusOK {
			t.Fatalf("P4 outcome is not log-only: %#v", outcome.payload)
		}
	} else if outcome.payload[1] != udsOutcomeApplied {
		t.Fatalf("P3 outcome is not applied: %#v", outcome.payload)
	}
}

func TestUDSEngineAppliesP3BeforeCommitAndDowngradesP4AfterCommit(t *testing.T) {
	tests := []udsResponseCase{
		{
			name:       "phase3-precommit",
			results:    map[byte]udsTestResult{udsOpcodeResponseHead: {action: udsActionDeny, status: http.StatusForbidden}},
			wantStatus: http.StatusForbidden,
			wantBody:   "request rejected\n",
		},
		{
			name:        "phase4-postcommit-log-only",
			results:     map[byte]udsTestResult{udsOpcodeResponseEOS: {action: udsActionDeny, status: http.StatusForbidden}},
			wantStatus:  http.StatusOK,
			wantBody:    "firstsecond",
			lateLogOnly: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runUDSResponseCase(t, test)
		})
	}
}

func assertUDSOrder(t *testing.T, calls []udsTestCall, required []byte) {
	t.Helper()
	position := 0
	for _, call := range calls {
		if position < len(required) && call.opcode == required[position] {
			position++
		}
	}
	if position != len(required) {
		t.Fatalf("required UDS lifecycle %v not found in calls %#v", required, calls)
	}
}

func countUDSCalls(calls []udsTestCall, opcode byte) int {
	count := 0
	for _, call := range calls {
		if call.opcode == opcode {
			count++
		}
	}
	return count
}

func findUDSCall(calls []udsTestCall, opcode byte) *udsTestCall {
	for index := range calls {
		if calls[index].opcode == opcode {
			return &calls[index]
		}
	}
	return nil
}

type failingDecisionResponseWriter struct {
	header http.Header
	status int
}

func (writer *failingDecisionResponseWriter) Header() http.Header {
	return writer.header
}

func (writer *failingDecisionResponseWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
}

func (writer *failingDecisionResponseWriter) Write(_ []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return 0, errors.New("injected response writer failure")
}

func TestUDSTechnicalResultReachesProductiveMiddleware(t *testing.T) {
	for _, opcode := range []byte{udsOpcodeBegin, udsOpcodeRequestChunk, udsOpcodeRequestEOS, udsOpcodeResponseHead, udsOpcodeResponseBody, udsOpcodeResponseEOS, udsOpcodeResponseCommit, udsOpcodeFinish, udsOpcodeDestroy, udsOpcodeOutcome} {
		t.Run(fmt.Sprint(opcode), func(t *testing.T) {
			runUDSTechnicalResult(t, opcode)
		})
	}
}

// This integration requires the real C service with explicit native request
// and response limits of 10 bytes and the selected Reject/ProcessPartial
// policy. A protocol double cannot establish when native Reject materializes.
func TestUDSEngineNativeBodyPolicy(t *testing.T) {
	socketPath := os.Getenv("TRAEFIK_UDS_NATIVE_TEST_SOCKET")
	if socketPath == "" {
		t.Skip("requires a private real Common/libModSecurity UDS service")
	}
	policy := os.Getenv("TRAEFIK_UDS_NATIVE_TEST_POLICY")
	if policy != "Reject" && policy != "ProcessPartial" {
		t.Fatal("native fixture policy must be Reject or ProcessPartial")
	}
	t.Run("native-append-after-eos", func(t *testing.T) {
		runUDSNativeAppendAfterEOS(t, socketPath)
	})
	for _, direction := range []Direction{DirectionRequest, DirectionResponse} {
		for _, combinedEOS := range []bool{false, true} {
			for _, oversized := range []bool{false, true} {
				name := fmt.Sprintf("%v/combined-eos-%t/oversized-%t", direction, combinedEOS, oversized)
				t.Run(name, func(t *testing.T) {
					runUDSNativeBodyPolicyCase(t, socketPath, policy, direction, combinedEOS, oversized)
				})
			}
		}
	}
}

func runUDSNativeAppendAfterEOS(t *testing.T, socketPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened, err := newUnixSocketEngine(socketPath).Open(ctx, Metadata{Method: http.MethodPost, RequestURI: "/append-after-eos", HTTPVersion: "HTTP/1.1", Hostname: "example.test", ClientAddress: "127.0.0.1", ClientPort: 12345, ServerAddress: "127.0.0.1", ServerPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	transaction := opened.(*unixSocketTransaction)
	defer transaction.Close(ctx, Summary{})
	if _, err := transaction.ProcessHeaders(ctx, DirectionRequest, nil, true); err != nil {
		t.Fatal(err)
	}
	_, err = transaction.ProcessBody(ctx, DirectionRequest, []byte("late"), true)
	if !errors.Is(err, errUDSEngineRejected) {
		t.Fatalf("native append-after-EOS error = %v, want lifecycle rejection", err)
	}
	if transaction.connection != nil || !transaction.closed {
		t.Fatal("native failed append retained its connection or active lifecycle")
	}
	if err := transaction.CloseChecked(ctx, Summary{}); err != nil {
		t.Fatalf("terminal cleanup = %v", err)
	}
}

func runUDSNativeBodyPolicyCase(t *testing.T, socketPath, policy string, direction Direction, combinedEOS, oversized bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	engine := newUnixSocketEngine(socketPath)
	opened, err := engine.Open(ctx, Metadata{Method: http.MethodPost, RequestURI: "/native-body-policy", HTTPVersion: "HTTP/1.1", Hostname: "example.test", ClientAddress: "127.0.0.1", ClientPort: 12345, ServerAddress: "127.0.0.1", ServerPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	transaction := opened.(*unixSocketTransaction)
	defer transaction.Close(ctx, Summary{})
	decision, err := transaction.ProcessHeaders(ctx, DirectionRequest, []Header{{Name: "content-type", Value: "text/plain"}}, direction == DirectionResponse)
	if err != nil || decision.disruptive() {
		t.Fatalf("request headers = %+v, %v", decision, err)
	}
	if direction == DirectionResponse {
		decision, err = transaction.ProcessResponseHeaders(ctx, http.StatusOK, "HTTP/1.1", []Header{{Name: "content-type", Value: "text/plain"}})
		if err != nil || decision.disruptive() {
			t.Fatalf("response headers = %+v, %v", decision, err)
		}
	}
	decision = processUDSNativeBodyPolicy(t, ctx, transaction, direction, combinedEOS, oversized)
	assertUDSNativeBodyPolicyDecision(t, decision, policy, oversized)
	if direction == DirectionRequest && !decision.disruptive() {
		completeUDSNativeControlResponse(t, ctx, transaction)
	}
	if err := transaction.CloseChecked(ctx, Summary{}); err != nil {
		t.Fatalf("native Finish/Destroy = %v", err)
	}
	if !transaction.closed || transaction.connection != nil {
		t.Fatal("native transaction retained its connection after Finish/Destroy")
	}
}

func completeUDSNativeControlResponse(t *testing.T, ctx context.Context, transaction *unixSocketTransaction) {
	t.Helper()
	if _, err := transaction.ProcessResponseHeaders(ctx, http.StatusOK, "HTTP/1.1", nil); err != nil {
		t.Fatalf("control response headers = %v", err)
	}
	if _, err := transaction.ProcessBody(ctx, DirectionResponse, nil, true); err != nil {
		t.Fatalf("control response EOS = %v", err)
	}
}

func processUDSNativeBodyPolicy(t *testing.T, ctx context.Context, transaction *unixSocketTransaction, direction Direction, combinedEOS, oversized bool) Decision {
	t.Helper()
	body := []byte("small")
	if oversized {
		body = []byte("abcdefghijklmnop")
	}
	decision, err := transaction.ProcessBody(ctx, direction, body, combinedEOS)
	if err != nil {
		t.Fatalf("body append = %v", err)
	}
	if !combinedEOS {
		if decision.disruptive() {
			t.Fatalf("successful native append unexpectedly decided before EOS: %+v", decision)
		}
		decision, err = transaction.ProcessBody(ctx, direction, nil, true)
		if err != nil {
			t.Fatalf("body EOS = %v", err)
		}
	}
	return decision
}

func assertUDSNativeBodyPolicyDecision(t *testing.T, decision Decision, policy string, oversized bool) {
	t.Helper()
	if oversized && policy == "Reject" {
		if decision.Action != ActionDeny || decision.Status != http.StatusForbidden {
			t.Fatalf("native Reject decision = %+v, want Deny 403", decision)
		}
	} else if decision.disruptive() {
		t.Fatalf("legitimate native control decision = %+v, want Allow", decision)
	}
}

func runUDSTechnicalResult(t *testing.T, opcode byte) {
	t.Helper()
	results := map[byte]udsTestResult{opcode: {code: 1}}
	if opcode == udsOpcodeOutcome {
		results[udsOpcodeBegin] = udsTestResult{action: udsActionDeny, status: 403}
	}
	path, server := startUDSTestServer(t, results)
	config := CreateConfig()
	config.EngineSocketPath = path
	handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("original")) }), config, "uds-error")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	if opcode == udsOpcodeRequestChunk {
		request = httptest.NewRequest("POST", "http://example.test/", strings.NewReader("body"))
	}
	call := func() { handler.ServeHTTP(recorder, request) }
	if udsFailureBeforeCommit(opcode) {
		call()
		if recorder.Code != 500 {
			t.Fatalf("status=%d", recorder.Code)
		}
	} else {
		expectHostStop(t, call)
	}
	assertUDSTerminalFailure(t, server.wait(t), opcode)
}

func udsFailureBeforeCommit(opcode byte) bool {
	switch opcode {
	case udsOpcodeBegin, udsOpcodeRequestChunk, udsOpcodeRequestEOS, udsOpcodeResponseHead:
		return true
	default:
		return false
	}
}

func assertUDSTerminalFailure(t *testing.T, calls []udsTestCall, opcode byte) {
	t.Helper()
	for i, call := range calls {
		if call.opcode == opcode && i != len(calls)-1 {
			t.Fatalf("operation after terminal failure: %#v", calls)
		}
	}
}
