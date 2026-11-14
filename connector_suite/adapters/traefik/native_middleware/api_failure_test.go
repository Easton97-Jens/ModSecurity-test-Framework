package native_middleware

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

var errHostBridge = errors.New("host bridge failed")

type failingHostTransaction struct {
	recordingTransaction
	commitErr, outcomeErr error
	commits, outcomes     int
}

func (tx *failingHostTransaction) SetResponseCommit(context.Context, bool, bool) error {
	tx.commits++
	return tx.commitErr
}
func (tx *failingHostTransaction) AcknowledgeApplied(context.Context, Decision) error {
	tx.outcomes++
	return tx.outcomeErr
}
func (tx *failingHostTransaction) AcknowledgeLateLogOnly(context.Context, int) error {
	tx.outcomes++
	return tx.outcomeErr
}

func TestResponseCommitFailureStopsBodyAndEOS(t *testing.T) {
	cases := []struct {
		name      string
		commitErr error
		wantEOS   bool
		check     func(*testing.T, *responseWriter, *failingHostTransaction, *httptest.ResponseRecorder, int, error)
	}{
		{"success", nil, true, assertSuccessfulResponseWrite},
		{"failure", errHostBridge, false, assertFailedCommitStopsResponse},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			tx := &failingHostTransaction{commitErr: test.commitErr}
			state := &streamState{config: *CreateConfig(), engine: tx, requestEOS: true}
			target := httptest.NewRecorder()
			writer := newResponseWriter(httptest.NewRequest(http.MethodGet, "/", nil), target, state)
			var n int
			var err error
			if test.commitErr != nil {
				expectHostStop(t, func() { n, err = writer.Write([]byte("first")) })
				err = state.responseFailure()
			} else {
				n, err = writer.Write([]byte("first"))
			}
			test.check(t, writer, tx, target, n, err)
			state.close(context.Background())
			state.close(context.Background())
			if len(tx.closed) != 1 {
				t.Fatalf("cleanup count = %d", len(tx.closed))
			}
			if tx.closed[0].ResponseEOS != test.wantEOS {
				t.Fatalf("cleanup summary = %+v", tx.closed)
			}
		})
	}
}

func assertFailedCommitStopsResponse(t *testing.T, writer *responseWriter, tx *failingHostTransaction, target *httptest.ResponseRecorder, n int, err error) {
	t.Helper()
	if !errors.Is(err, errHostBridge) || n != 0 || target.Body.Len() != 0 {
		t.Fatalf("commit failure forwarded body: n=%d err=%v body=%q", n, err, target.Body.String())
	}
	before := len(tx.bodyCalls)
	if _, err = writer.Write([]byte("retry")); !errors.Is(err, errHostBridge) {
		t.Fatalf("reentry error = %v", err)
	}
	expectHostStop(t, writer.finish)
	if len(tx.bodyCalls) != before {
		t.Fatal("engine reentered after failed commit")
	}
}

func assertSuccessfulResponseWrite(t *testing.T, writer *responseWriter, _ *failingHostTransaction, _ *httptest.ResponseRecorder, n int, err error) {
	t.Helper()
	if n != 5 || err != nil {
		t.Fatalf("success write n=%d err=%v", n, err)
	}
	writer.finish()
	if !writer.state.responseEOS {
		t.Fatal("successful stream missing EOS")
	}
}

func TestLateOutcomeFailureStopsEngineReentry(t *testing.T) {
	tx := &failingHostTransaction{outcomeErr: errHostBridge}
	tx.bodyDecision = func(Direction, []byte, bool) Decision { return Decision{Action: ActionDeny, Status: 403} }
	state := &streamState{engine: tx, responseStatus: 200}
	_, err := state.processResponseBody(context.Background(), []byte("body"), false, false)
	if !errors.Is(err, errHostBridge) {
		t.Fatalf("outcome failure ignored: %v", err)
	}
	_, err = state.processResponseBody(context.Background(), nil, true, false)
	if !errors.Is(err, errHostBridge) || len(tx.bodyCalls) != 1 || tx.outcomes != 1 || state.responseEOS {
		t.Fatalf("failure reentry: err=%v calls=%d outcomes=%d eos=%v", err, len(tx.bodyCalls), tx.outcomes, state.responseEOS)
	}
}

func TestAppliedOutcomeFailureStopsLaterProcessing(t *testing.T) {
	tx := &failingHostTransaction{outcomeErr: errHostBridge}
	state := &streamState{engine: tx}
	expectHostStop(t, func() {
		state.writeDecision(context.Background(), httptest.NewRecorder(), Decision{Action: ActionDeny, Status: 403})
	})
	_, err := state.processResponseBody(context.Background(), nil, true, false)
	if !errors.Is(err, errHostBridge) || len(tx.bodyCalls) != 0 || tx.outcomes != 1 || state.responseEOS {
		t.Fatalf("failed outcome continued: err=%v calls=%d outcomes=%d eos=%v", err, len(tx.bodyCalls), tx.outcomes, state.responseEOS)
	}
}

func TestAppliedDenialConsumesUpstreamWithoutTerminalCommit(t *testing.T) {
	// Common rejects commit updates after the applied rule outcome is terminal.
	tx := &failingHostTransaction{commitErr: errHostBridge}
	tx.headerDecision = func(Direction, []Header, bool) Decision {
		return Decision{Action: ActionDeny, Status: http.StatusForbidden}
	}
	state := &streamState{config: *CreateConfig(), engine: tx, requestEOS: true}
	target := httptest.NewRecorder()
	writer := newResponseWriter(httptest.NewRequest(http.MethodGet, "/", nil), target, state)
	writer.WriteHeader(http.StatusOK)
	for _, payload := range [][]byte{[]byte("upstream body"), []byte("retry")} {
		if n, err := writer.Write(payload); n != len(payload) || err != nil {
			t.Fatalf("applied denial failed to consume upstream: n=%d err=%v", n, err)
		}
	}
	writer.finish()
	state.close(context.Background())
	if target.Code != http.StatusForbidden || target.Body.String() != "request rejected\n" {
		t.Fatalf("selected denial changed: status=%d body=%q", target.Code, target.Body.String())
	}
	if tx.outcomes != 1 || tx.commits != 0 || len(tx.bodyCalls) != 0 || state.responseEOS {
		t.Fatalf("terminal engine reentered: outcomes=%d commits=%d body=%d eos=%v", tx.outcomes, tx.commits, len(tx.bodyCalls), state.responseEOS)
	}
	if len(tx.closed) != 1 || !tx.closed[0].ResponseCommitted || state.responseStatus != http.StatusForbidden {
		t.Fatalf("actual host commit missing from summary: %+v", tx.closed)
	}
}

func TestResponseBodyObservationSaturatesAndStillReachesEngineEOS(t *testing.T) {
	for _, test := range []struct {
		name       string
		bytes      int64
		chunks     uint64
		wantBytes  int64
		wantChunks uint64
	}{
		{name: "cross32", bytes: math.MaxInt32 - 1, chunks: math.MaxUint32 - 1, wantBytes: math.MaxInt32 + 3, wantChunks: math.MaxUint32 + 1},
		{name: "cross64", bytes: math.MaxInt64 - 1, chunks: math.MaxUint64 - 1, wantBytes: math.MaxInt64, wantChunks: math.MaxUint64},
		{name: "already_saturated", bytes: math.MaxInt64, chunks: math.MaxUint64, wantBytes: math.MaxInt64, wantChunks: math.MaxUint64},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transaction := &recordingTransaction{}
			state := &streamState{engine: transaction, responseBodyBytes: test.bytes, responseBodyChunks: test.chunks}
			for _, eos := range []bool{false, true} {
				body := []byte("data")
				if eos {
					body = nil
				}
				decision, err := state.processResponseBody(context.Background(), body, eos, false)
				if err != nil || decision.Action != ActionAllow {
					t.Fatalf("processResponseBody(eos=%v) = (%#v, %v), want allow, nil", eos, decision, err)
				}
			}
			if len(transaction.bodyCalls) != 2 || transaction.bodyCalls[0].length != 4 || transaction.bodyCalls[0].end || !transaction.bodyCalls[1].end || !state.responseEOS {
				t.Fatalf("processResponseBody() engine calls=%#v, eos=%v, want data then EOS", transaction.bodyCalls, state.responseEOS)
			}
			if state.responseBodyBytes != test.wantBytes || state.responseBodyChunks != test.wantChunks {
				t.Errorf("processResponseBody() counters=(%d,%d), want (%d,%d)", state.responseBodyBytes, state.responseBodyChunks, test.wantBytes, test.wantChunks)
			}
		})
	}
}

func TestRequestBodyAccountingOverflowStillStopsBeforeEngine(t *testing.T) {
	for _, test := range []struct {
		name   string
		bytes  int64
		chunks uint64
	}{
		{name: "bytes", bytes: math.MaxInt64},
		{name: "chunks", chunks: math.MaxUint64},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transaction := &recordingTransaction{}
			state := &streamState{engine: transaction, requestBodyBytes: test.bytes, requestBodyChunks: test.chunks}
			if err := state.processRequestBody(context.Background(), []byte("x"), false); err == nil || len(transaction.bodyCalls) != 0 {
				t.Fatalf("processRequestBody(overflow) calls=%v, error=%v, want no engine calls and error", transaction.bodyCalls, err)
			}
		})
	}
}
