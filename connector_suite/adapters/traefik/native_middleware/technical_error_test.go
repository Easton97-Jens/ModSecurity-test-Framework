package native_middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

var injectedTechnicalError = errors.New("injected technical engine failure")

type errorTransaction struct {
	recordingTransaction
	boundary string
	calls    int
}

func (tx *errorTransaction) ProcessHeaders(ctx context.Context, dir Direction, headers []Header, end bool) (Decision, error) {
	if (tx.boundary == "request-headers" && dir == DirectionRequest) || (tx.boundary == "response-headers" && dir == DirectionResponse) {
		tx.calls++
		return Decision{Action: ActionRedirect, Status: 302, Location: "/stale-rule"}, injectedTechnicalError
	}
	return tx.recordingTransaction.ProcessHeaders(ctx, dir, headers, end)
}
func (tx *errorTransaction) ProcessBody(ctx context.Context, dir Direction, chunk []byte, end bool) (Decision, error) {
	if dir == DirectionResponse && ((tx.boundary == "response-body" && !end) || (tx.boundary == "response-eos" && end)) {
		tx.calls++
		return allowDecision(), injectedTechnicalError
	}
	return tx.recordingTransaction.ProcessBody(ctx, dir, chunk, end)
}
func (tx *errorTransaction) SetResponseCommit(context.Context, bool, bool) error {
	if tx.boundary == "commit" {
		tx.calls++
		return injectedTechnicalError
	}
	return nil
}
func (tx *errorTransaction) AcknowledgeApplied(context.Context, Decision) error {
	if tx.boundary == "outcome" {
		tx.calls++
		return injectedTechnicalError
	}
	return nil
}
func (tx *errorTransaction) AcknowledgeLateLogOnly(context.Context, int) error {
	if tx.boundary == "late-outcome" {
		tx.calls++
		return injectedTechnicalError
	}
	return nil
}

type errorOpener struct{ tx Transaction }

func (op errorOpener) Open(context.Context, Metadata) (Transaction, error) { return op.tx, nil }
func expectHostStop(t *testing.T, call func()) {
	t.Helper()
	defer func() {
		if value := recover(); value != http.ErrAbortHandler {
			t.Fatalf("host stop=%v, want ErrAbortHandler", value)
		}
	}()
	call()
}
func TestTechnicalFailureReachesMiddlewareHost(t *testing.T) {
	for _, boundary := range []string{"request-headers", "response-headers", "response-body", "response-eos", "commit", "outcome", "late-outcome"} {
		t.Run(boundary, func(t *testing.T) {
			runTechnicalMiddlewareFailure(t, boundary)
		})
	}
}

func technicalFailureTransaction(boundary string) *errorTransaction {
	tx := &errorTransaction{boundary: boundary}
	if boundary == "outcome" {
		tx.headerDecision = func(Direction, []Header, bool) Decision { return Decision{Action: ActionDeny, Status: 403} }
	}
	if boundary == "late-outcome" {
		tx.bodyDecision = func(dir Direction, _ []byte, end bool) Decision {
			if dir == DirectionResponse && end {
				return Decision{Action: ActionDeny, Status: 403}
			}
			return allowDecision()
		}
	}
	return tx
}

func runTechnicalMiddlewareFailure(t *testing.T, boundary string) {
	t.Helper()
	tx := technicalFailureTransaction(boundary)
	config := CreateConfig()
	config.EngineSocketPath = "/run/private/engine.sock"
	nextCalls := 0
	afterHeader := false
	handler, err := newWithEngine(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls++
		w.WriteHeader(200)
		afterHeader = true
		_, _ = w.Write([]byte("original"))
	}), config, "technical", errorOpener{tx})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	call := func() { handler.ServeHTTP(recorder, request) }
	pre := boundary == "request-headers" || boundary == "response-headers"
	if pre {
		call()
		if recorder.Code != 500 {
			t.Fatalf("status=%d", recorder.Code)
		}
	} else {
		expectHostStop(t, call)
	}
	assertTechnicalMiddlewareFailure(t, boundary, tx, recorder, pre, afterHeader, nextCalls)
}

func assertTechnicalMiddlewareFailure(t *testing.T, boundary string, tx *errorTransaction, recorder *httptest.ResponseRecorder, pre, afterHeader bool, nextCalls int) {
	t.Helper()
	if recorder.Header().Get("Location") != "" {
		t.Fatal("stale rule redirect escaped")
	}
	if boundary == "commit" && afterHeader {
		t.Fatal("continued handler after failed commit acknowledgement")
	}
	if tx.calls != 1 || len(tx.closed) != 1 {
		t.Fatalf("failure calls=%d closes=%d", tx.calls, len(tx.closed))
	}
	if boundary == "request-headers" && nextCalls != 0 {
		t.Fatal("next handler invoked")
	}
	if !pre && boundary != "outcome" && recorder.Code != 200 {
		t.Fatalf("committed status changed: %d", recorder.Code)
	}
	if boundary == "outcome" && (recorder.Code != http.StatusForbidden || recorder.Body.String() != "request rejected\n" || !tx.closed[0].ResponseCommitted || tx.closed[0].ResponseEOS) {
		t.Fatalf("failed acknowledgement host status/body/summary = %d/%q/%+v, want complete 403 denial and committed non-EOS cleanup", recorder.Code, recorder.Body.String(), tx.closed[0])
	}
}
func TestTechnicalFailureIsTerminalAndKeepsFirstCause(t *testing.T) {
	tx := &errorTransaction{boundary: "response-body"}
	state := &streamState{engine: tx, config: *CreateConfig()}
	for i := 0; i < 2; i++ {
		_, err := state.processResponseBody(context.Background(), []byte("x"), false, false)
		if err != injectedTechnicalError {
			t.Fatalf("cause=%v", err)
		}
	}
	if tx.calls != 1 {
		t.Fatalf("reentered engine %d times", tx.calls)
	}
	_, err := state.processResponseHeaders(context.Background(), 200, nil)
	if err != injectedTechnicalError {
		t.Fatalf("cause=%v", err)
	}
	if state.lateAction != "" {
		t.Fatalf("technical error became %s", state.lateAction)
	}
}

func TestTechnicalResponseBodyBeforeCommitFailsClosed(t *testing.T) {
	tx := &errorTransaction{boundary: "response-body"}
	config := CreateConfig()
	config.EngineSocketPath = "/run/private/engine.sock"
	handler, err := newWithEngine(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("must-not-pass"))
		_, _ = w.Write([]byte("reentry"))
	}), config, "precommit", errorOpener{tx})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "http://example.test/", nil))
	if recorder.Code != 500 || tx.calls != 1 || len(tx.closed) != 1 || tx.closed[0].ResponseEOS {
		t.Fatalf("status=%d calls=%d closes=%v", recorder.Code, tx.calls, tx.closed)
	}
}
