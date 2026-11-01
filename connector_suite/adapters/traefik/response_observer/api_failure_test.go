package response_observer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type panickingStatusWriter struct{ *httptest.ResponseRecorder }

func (w panickingStatusWriter) WriteHeader(int) { panic("host status failed") }

func TestImmediateOutcomeRequiresObservedHostStatus(t *testing.T) {
	path, stop, operations := startFakeObserver(t, func(op byte) (byte, byte) {
		if op == opResponseHeaders {
			return decisionDeny, resultOK
		}
		return decisionAllow, resultOK
	})
	defer stop()
	handler := newObserverHandler(t, path, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	func() {
		defer func() {
			if recover() != "host status failed" {
				t.Fatal("host panic was not propagated")
			}
		}()
		handler.ServeHTTP(panickingStatusWriter{httptest.NewRecorder()}, newObserverRequest())
	}()
	for _, op := range operations.snapshot() {
		if op == opOutcome {
			t.Fatal("host action acknowledged before failing host WriteHeader")
		}
	}
	if got := operations.payloadFor(opCancel); len(got) != 1 || got[0] != cancelConnectorError {
		t.Fatalf("host failure cancellation=%v", got)
	}
}
