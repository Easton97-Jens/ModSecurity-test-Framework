package native_middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The real server is essential: ResponseRecorder treats the first 1xx as final.
// Completion is synchronized before inspecting the transaction, including under -race.
type informationalTransaction struct {
	recordingTransaction
	statuses []int
	commits  [][2]bool
	action   Action
}

func (tx *informationalTransaction) ProcessResponseHeaders(ctx context.Context, status int, _ string, headers []Header) (Decision, error) {
	tx.statuses = append(tx.statuses, status)
	_, _ = tx.ProcessHeaders(ctx, DirectionResponse, headers, false)
	for _, header := range headers {
		if strings.EqualFold(header.Name, "X-Final-Protected") && header.Value == "secret" {
			switch tx.action {
			case ActionDeny:
				return Decision{Action: ActionDeny, Status: 403}, nil
			case ActionRedirect:
				return Decision{Action: ActionRedirect, Status: 307, Location: "/safe"}, nil
			}
		}
	}
	return allowDecision(), nil
}

func (tx *informationalTransaction) SetResponseCommit(_ context.Context, headers, body bool) error {
	tx.commits = append(tx.commits, [2]bool{headers, body})
	return nil
}

func informationalMiddleware(t *testing.T, tx *informationalTransaction, next http.Handler) *Middleware {
	t.Helper()
	config := CreateConfig()
	config.EngineSocketPath = "/run/msconnector-test.sock"
	config.MaxRequestChunkBytes, config.MaxResponseChunkBytes = 3, 2
	middleware, err := newWithEngine(next, config, "SEC-TRAEFIK-NATIVE-001", informationalEngine{tx})
	if err != nil {
		t.Fatal(err)
	}
	return middleware
}

type informationalEngine struct{ tx *informationalTransaction }

func (engine informationalEngine) Open(context.Context, Metadata) (Transaction, error) {
	return engine.tx, nil
}

type informationalResponseCase struct {
	name   string
	infos  []int
	status int
	action Action
}

func TestInformationalResponseFinalDecision(t *testing.T) {
	tests := []informationalResponseCase{
		{"100-200-allow", []int{100}, 200, ActionAllow},
		{"102-201-allow", []int{102}, 201, ActionAllow},
		{"103-200-allow", []int{103}, 200, ActionAllow},
		{"103-201-allow", []int{103}, 201, ActionAllow},
		{"103-401-allow", []int{103}, 401, ActionAllow},
		{"103-403-allow", []int{103}, 403, ActionAllow},
		{"multiple-201-allow", []int{100, 102, 103, 103}, 201, ActionAllow},
		{"103-201-deny", []int{103}, 201, ActionDeny},
		{"multiple-401-deny", []int{100, 102, 103}, 401, ActionDeny},
		{"103-200-redirect", []int{103}, 200, ActionRedirect},
		{"control-201-allow", nil, 201, ActionAllow},
		{"control-201-deny", nil, 201, ActionDeny},
		{"control-200-redirect", nil, 200, ActionRedirect},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runInformationalFinalDecision(t, test)
		})
	}
}

func runInformationalFinalDecision(t *testing.T, test informationalResponseCase) {
	t.Helper()
	completed := make(chan *informationalTransaction, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := &informationalTransaction{action: test.action}
		next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			serveInformationalFinal(t, tx, test, writer, request)
		})
		informationalMiddleware(t, tx, next).ServeHTTP(w, r)
		completed <- tx
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var infos []int
	var reused bool
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error { infos = append(infos, code); return nil },
		GotConn:        func(info httptrace.GotConnInfo) { reused = info.Reused },
	}
	request, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, server.URL, nil)
	response, body := readInformationalResponse(t, client, request)
	tx := <-completed
	assertInformationalFinal(t, test, response, body, infos, tx)
	followup, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, server.URL+"/followup", nil)
	response, body = readInformationalResponse(t, client, followup)
	followTx := <-completed
	if response.StatusCode != 200 || string(body) != "legitimate" || !reused {
		t.Errorf("followup status=%d body=%q keepalive-reused=%t", response.StatusCode, body, reused)
	}
	if len(followTx.closed) != 1 {
		t.Errorf("followup cleanup count=%d", len(followTx.closed))
	}
}

func serveInformationalFinal(t *testing.T, tx *informationalTransaction, test informationalResponseCase, writer http.ResponseWriter, request *http.Request) {
	t.Helper()
	if request.URL.Path == "/followup" {
		_, _ = writer.Write([]byte("legitimate"))
		return
	}
	writer.Header().Set("Link", "</early.css>; rel=preload")
	for _, status := range test.infos {
		writer.WriteHeader(status)
		if len(tx.statuses) != 0 || len(tx.commits) != 0 {
			t.Errorf("1xx consumed P3/commit: statuses=%v commits=%v", tx.statuses, tx.commits)
		}
	}
	writer.Header().Set("X-Final-Protected", "secret")
	writer.WriteHeader(test.status)
	writer.WriteHeader(202) // A repeated final status must not re-evaluate P3.
	_, _ = writer.Write([]byte("PROTECTED-UPSTREAM-BYTES"))
}

func readInformationalResponse(t *testing.T, client *http.Client, request *http.Request) (*http.Response, []byte) {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

func assertInformationalFinal(t *testing.T, test informationalResponseCase, response *http.Response, body []byte, infos []int, tx *informationalTransaction) {
	t.Helper()
	wantStatus := test.status
	if test.action == ActionDeny {
		wantStatus = 403
	}
	if test.action == ActionRedirect {
		wantStatus = 307
	}
	if response.StatusCode != wantStatus {
		t.Errorf("final status=%d want=%d body=%q", response.StatusCode, wantStatus, body)
	}
	if !reflect.DeepEqual(infos, test.infos) {
		t.Errorf("observed 1xx=%v want=%v", infos, test.infos)
	}
	if !reflect.DeepEqual(tx.statuses, []int{test.status}) {
		t.Errorf("P3 statuses=%v want exactly [%d]", tx.statuses, test.status)
	}
	assertInformationalProtectedHeader(t, tx)
	assertInformationalBody(t, test.action, response, body, tx)
	if len(tx.closed) != 1 {
		t.Errorf("cleanup count=%d", len(tx.closed))
	}
	if test.action == ActionAllow && (len(tx.closed) != 1 || !tx.closed[0].ResponseEOS) {
		t.Errorf("missing response EOS: %+v", tx.closed)
	}
}

func assertInformationalProtectedHeader(t *testing.T, tx *informationalTransaction) {
	t.Helper()
	var protected bool
	for index, call := range tx.headerCalls {
		if call.direction == DirectionResponse {
			for _, header := range tx.headerValues[index] {
				protected = protected || (header.Name == "X-Final-Protected" && header.Value == "secret")
			}
		}
	}
	if !protected {
		t.Error("P3 missed final-only protected header")
	}
}

func assertInformationalBody(t *testing.T, action Action, response *http.Response, body []byte, tx *informationalTransaction) {
	t.Helper()
	if action == ActionAllow {
		if string(body) != "PROTECTED-UPSTREAM-BYTES" {
			t.Errorf("allow body=%q", body)
		}
		assertBoundedBodies(t, tx.bodyCalls, DirectionResponse, 2, len(body))
	} else {
		if strings.Contains(string(body), "PROTECTED-UPSTREAM-BYTES") {
			t.Errorf("denial leaked upstream bytes: %q", body)
		}
		if string(body) != "request rejected\n" {
			t.Errorf("own rejection body=%q", body)
		}
		if action == ActionRedirect && response.Header.Get("Location") != "/safe" {
			t.Error("lost redirect Location")
		}
	}
}

func TestInformationalResponseDoesNotDrainRequest(t *testing.T) {
	for _, status := range []int{100, 102, 103} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			tx := &informationalTransaction{}
			body := newTrackingRequestBody("request-body")
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				if body.readBytes != 0 || len(tx.bodyCalls) != 0 {
					t.Errorf("1xx prematurely drained P2: read=%d calls=%v", body.readBytes, tx.bodyCalls)
				}
				payload, err := io.ReadAll(r.Body)
				if err != nil || string(payload) != "request-body" {
					t.Errorf("request payload=%q err=%v", payload, err)
				}
				w.WriteHeader(201)
			})
			request := httptest.NewRequest(http.MethodPost, "http://example.test", nil)
			request.Body, request.ContentLength = body, int64(len("request-body"))
			// This seam checks request state only; HTTP 1xx wire semantics are above.
			informationalMiddleware(t, tx, next).ServeHTTP(httptest.NewRecorder(), request)
			assertBoundedBodies(t, tx.bodyCalls, DirectionRequest, 3, len("request-body"))
			if len(tx.closed) != 1 {
				t.Errorf("cleanup count=%d", len(tx.closed))
			}
		})
	}
}

func TestInformationalResponseImplicitFinal(t *testing.T) {
	for _, method := range []string{"write", "empty-write", "flush", "read-from", "finish"} {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			t.Run(method+"-"+string(action), func(t *testing.T) {
				runInformationalImplicitFinal(t, method, action)
			})
		}
	}
}

func runInformationalImplicitFinal(t *testing.T, method string, action Action) {
	t.Helper()
	done := make(chan *informationalTransaction, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := &informationalTransaction{action: action}
		informationalMiddleware(t, tx, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(103)
			writer.Header().Set("X-Final-Protected", "secret")
			writeInformationalImplicitFinal(writer, method)
		})).ServeHTTP(w, r)
		done <- tx
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	var infos []int
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error { infos = append(infos, code); return nil }}
	request, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, server.URL, nil)
	response, body := readInformationalResponse(t, client, request)
	tx := <-done
	status := 200
	if action == ActionDeny {
		status = 403
	}
	if response.StatusCode != status || !reflect.DeepEqual(infos, []int{103}) || !reflect.DeepEqual(tx.statuses, []int{200}) {
		t.Errorf("status=%d infos=%v P3=%v", response.StatusCode, infos, tx.statuses)
	}
	if action == ActionDeny && strings.Contains(string(body), "protected") {
		t.Errorf("protected body leaked: %q", body)
	}
	if len(tx.closed) != 1 {
		t.Errorf("cleanup count=%d", len(tx.closed))
	}
}

func writeInformationalImplicitFinal(writer http.ResponseWriter, method string) {
	switch method {
	case "write":
		_, _ = writer.Write([]byte("protected"))
	case "empty-write":
		_, _ = writer.Write(nil)
	case "flush":
		writer.(http.Flusher).Flush()
	case "read-from":
		_, _ = writer.(io.ReaderFrom).ReadFrom(&plainReader{reader: strings.NewReader("protected")})
	}
}

func TestInformationalResponseStreamsBeforeEOS(t *testing.T) {
	release := make(chan struct{})
	done := make(chan *informationalTransaction, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := &informationalTransaction{}
		informationalMiddleware(t, tx, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(103)
			_, _ = writer.Write([]byte("first"))
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = writer.Write([]byte("second"))
		})).ServeHTTP(w, r)
		done <- tx
	}))
	defer server.Close()
	defer close(release)
	client := server.Client()
	client.Timeout = 5 * time.Second
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 5)
	if _, err = io.ReadFull(response.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("first bytes before release=%q err=%v", first, err)
	}
	// A value releases the upstream while leaving deferred close safe on failures.
	release <- struct{}{}
	rest, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(rest) != "second" {
		t.Fatalf("remaining stream=%q err=%v", rest, err)
	}
	tx := <-done
	assertBoundedBodies(t, tx.bodyCalls, DirectionResponse, 2, 11)
	ends := 0
	for _, call := range tx.bodyCalls {
		if call.direction == DirectionResponse && call.end {
			ends++
		}
	}
	if ends != 1 || len(tx.closed) != 1 || !tx.closed[0].ResponseEOS {
		t.Errorf("P4 EOS=%d cleanup=%+v", ends, tx.closed)
	}
}

func TestInformationalResponseSwitchingProtocolsRemainsTerminal(t *testing.T) {
	tx := &informationalTransaction{}
	underlying := newAdvancedResponseWriter(t)
	defer underlying.connection.Close()
	state := &streamState{config: mustTestConfig(t), engine: tx, requestEOS: true}
	writer := newResponseWriter(httptest.NewRequest(http.MethodGet, "/upgrade", nil), underlying, state)
	writer.WriteHeader(103)
	writer.Header().Set("Upgrade", "test-protocol")
	writer.WriteHeader(101)
	if !writer.committed || !reflect.DeepEqual(tx.statuses, []int{101}) {
		t.Errorf("101 terminal state=%t P3=%v", writer.committed, tx.statuses)
	}
	connection, _, err := writer.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	writer.finish()
	state.close(context.Background())
	state.close(context.Background())
	if len(tx.closed) != 1 || tx.closed[0].ResponseEOS || len(tx.bodyCalls) != 0 {
		t.Errorf("upgrade invented EOS/cleanup: %+v body=%v", tx.closed, tx.bodyCalls)
	}
}

func TestInformationalResponseRejectsInvalidHeaders(t *testing.T) {
	for _, variant := range []string{"invalid-name", "count-limit", "bytes-limit"} {
		t.Run(variant, func(t *testing.T) {
			tx := &informationalTransaction{}
			middleware := informationalMiddleware(t, tx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				switch variant {
				case "invalid-name":
					w.Header()["Invalid Name"] = []string{"value"}
				case "count-limit":
					for i := 0; i <= CreateConfig().MaxHeaderCount; i++ {
						w.Header().Add("X-Many", "v")
					}
				case "bytes-limit":
					w.Header().Set("X-Large", strings.Repeat("x", CreateConfig().MaxHeaderBytes+1))
				}
				w.WriteHeader(103)
				w.WriteHeader(201)
				_, _ = w.Write([]byte("PROTECTED-UPSTREAM-BYTES"))
			}))
			response := httptest.NewRecorder()
			middleware.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test", nil))
			if response.Code != 500 || strings.Contains(response.Body.String(), "PROTECTED-UPSTREAM-BYTES") || len(tx.statuses) != 0 || len(tx.closed) != 1 {
				t.Errorf("header bounds result status=%d body=%q P3=%v cleanup=%d", response.Code, response.Body.String(), tx.statuses, len(tx.closed))
			}
		})
	}
}
