package native_middleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type denialHostWriter struct {
	*httptest.ResponseRecorder
	count, writes, headers int
	err                    error
}

func (w *denialHostWriter) WriteHeader(status int) {
	w.headers++
	w.ResponseRecorder.WriteHeader(status)
}

func (w *denialHostWriter) Write(payload []byte) (int, error) {
	w.writes++
	_, _ = w.ResponseRecorder.Write(payload[:w.count])
	return w.count, w.err
}

type denialTransaction struct {
	failingHostTransaction
	state                         *streamState
	committedAtAck                bool
	statusAtAck                   int
	headersReported, bodyReported bool
}

func (tx *denialTransaction) AcknowledgeApplied(ctx context.Context, decision Decision) error {
	tx.state.mu.Lock()
	tx.committedAtAck = tx.state.responseCommitted
	tx.statusAtAck = tx.state.responseStatus
	tx.state.mu.Unlock()
	return tx.failingHostTransaction.AcknowledgeApplied(ctx, decision)
}

func (tx *denialTransaction) SetResponseCommit(ctx context.Context, headers, body bool) error {
	tx.headersReported, tx.bodyReported = headers, body
	return tx.failingHostTransaction.SetResponseCommit(ctx, headers, body)
}

type denialWriteCase struct {
	name                        string
	count                       int
	writeErr, ackErr, commitErr error
	wantErr                     error
	wantOutcomes, wantCommits   int
}

func TestDenialWriteRetainsHostCommitAndFirstFailure(t *testing.T) {
	t.Parallel()
	writeFailure := errors.New("host denial write failed")
	tests := []denialWriteCase{
		{name: "complete", count: len("request rejected\n"), wantOutcomes: 1},
		{name: "acknowledgement fails", count: len("request rejected\n"), ackErr: errHostBridge, wantErr: errHostBridge, wantOutcomes: 1},
		{name: "short write", count: 3, wantErr: io.ErrShortWrite, wantCommits: 1},
		{name: "partial write fails", count: 3, writeErr: writeFailure, wantErr: writeFailure, wantCommits: 1},
		{name: "zero body write fails", writeErr: writeFailure, wantErr: writeFailure, wantCommits: 1},
		{name: "complete count with write error", count: len("request rejected\n"), writeErr: writeFailure, wantErr: writeFailure, wantCommits: 1},
		{name: "write and commit report fail", count: 3, writeErr: writeFailure, commitErr: errHostBridge, wantErr: writeFailure, wantCommits: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runDenialWriteCase(t, test)
		})
	}
}

func runDenialWriteCase(t *testing.T, test denialWriteCase) {
	t.Helper()
	tx := &denialTransaction{failingHostTransaction: failingHostTransaction{commitErr: test.commitErr, outcomeErr: test.ackErr}}
	state := &streamState{config: *CreateConfig(), engine: tx, requestEOS: true}
	tx.state = state
	target := &denialHostWriter{ResponseRecorder: httptest.NewRecorder(), count: test.count, err: test.writeErr}
	writer := newResponseWriter(httptest.NewRequest(http.MethodGet, "/", nil), target, state)
	call := func() { writer.writeDecision(Decision{Action: ActionDeny, Status: http.StatusForbidden}) }
	if test.wantErr != nil {
		expectHostStop(t, call)
	} else {
		call()
	}
	if err := state.responseFailure(); !errors.Is(err, test.wantErr) {
		t.Errorf("writeDecision(%s) error = %v, want %v", test.name, err, test.wantErr)
	}
	// Reentry must neither replace the denial nor create a false EOS.
	writer.WriteHeader(http.StatusInternalServerError)
	writer.writeDecision(Decision{Action: ActionRedirect, Status: 302, Location: "/retry"})
	_, _ = writer.Write([]byte("retry"))
	writer.finish()
	state.close(context.Background())
	state.close(context.Background())
	assertDenialHostObservation(t, test, target, tx)
	assertDenialCleanup(t, test, state, tx)
}

func assertDenialHostObservation(t *testing.T, test denialWriteCase, target *denialHostWriter, tx *denialTransaction) {
	t.Helper()
	if target.headers != 1 || target.writes != 1 || target.Code != http.StatusForbidden || target.Body.Len() != test.count {
		t.Errorf("writeDecision(%s) host = headers %d writes %d status %d bytes %d, want 1 1 403 %d", test.name, target.headers, target.writes, target.Code, target.Body.Len(), test.count)
	}
	if tx.outcomes != test.wantOutcomes || tx.commits != test.wantCommits {
		t.Errorf("writeDecision(%s) outcomes/commits = %d/%d, want %d/%d", test.name, tx.outcomes, tx.commits, test.wantOutcomes, test.wantCommits)
	}
	if test.wantOutcomes > 0 && (!tx.committedAtAck || tx.statusAtAck != http.StatusForbidden) {
		t.Errorf("writeDecision(%s) state at acknowledgement = %t/%d, want true/403", test.name, tx.committedAtAck, tx.statusAtAck)
	}
	if test.wantCommits > 0 && (!tx.headersReported || tx.bodyReported != (test.count > 0)) {
		t.Errorf("writeDecision(%s) commit flags = %t/%t, want true/%t", test.name, tx.headersReported, tx.bodyReported, test.count > 0)
	}
}

func assertDenialCleanup(t *testing.T, test denialWriteCase, state *streamState, tx *denialTransaction) {
	t.Helper()
	if len(tx.closed) != 1 || !tx.closed[0].ResponseCommitted || tx.closed[0].ResponseEOS || len(tx.bodyCalls) != 0 || state.responseStatus != http.StatusForbidden {
		t.Errorf("writeDecision(%s) cleanup = %+v body calls %d status %d, want one committed non-EOS close, no body calls, status 403", test.name, tx.closed, len(tx.bodyCalls), state.responseStatus)
	}
}
