//go:build libmodsecurity

package processor

import (
	"context"
	"testing"
)

// Exercise the Go receiver, C ABI and real Common contract together. A C-only
// latch is insufficient when the Go caller unconditionally reports success.
func TestCommonResponseCommitErrorReachesGoCaller(t *testing.T) {
	engine, _ := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	ctx := context.Background()
	transaction, err := engine.Open(ctx, commonTestStreamMetadata("early-commit-error"))
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close(ctx, Summary{CloseReason: ClosePeerEOF})
	decision, err := transaction.ProcessHeaders(ctx, DirectionRequest, nil, true)
	assertCommonDecision(t, "request", decision, err, ActionAllow, 0)
	committer, ok := transaction.(ResponseCommitter)
	if !ok {
		t.Fatal("missing Common response committer")
	}
	first := committer.MarkResponseCommitted(ctx)
	if first == nil {
		t.Fatal("commit before response headers reported success")
	}
	second := committer.MarkResponseCommitted(ctx)
	if second == nil || second.Error() != first.Error() {
		t.Fatalf("first=%v repeated=%v; first failure must survive", first, second)
	}
	if _, err := transaction.ProcessHeaders(ctx, DirectionResponse,
		[]Header{{Name: ":status", Value: []byte("200")}}, false); err == nil {
		t.Fatal("response processing resumed after commit failure")
	}
}

func TestCommonResponseCommitAcceptsValidEmptyCompletion(t *testing.T) {
	engine, _ := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	ctx := context.Background()
	transaction, err := engine.Open(ctx, commonTestStreamMetadata("empty-commit-success"))
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close(ctx, Summary{CloseReason: ClosePeerEOF})
	decision, err := transaction.ProcessHeaders(ctx, DirectionRequest, nil, true)
	assertCommonDecision(t, "request", decision, err, ActionAllow, 0)
	decision, err = transaction.ProcessHeaders(ctx, DirectionResponse,
		[]Header{{Name: ":status", Value: []byte("200")}}, false)
	assertCommonDecision(t, "response headers", decision, err, ActionAllow, 0)
	committer, ok := transaction.(ResponseCommitter)
	if !ok {
		t.Fatal("missing Common response committer")
	}
	if err := committer.MarkResponseCommitted(ctx); err != nil {
		t.Fatalf("valid commit failed: %v", err)
	}
	decision, err = transaction.ProcessBody(ctx, DirectionResponse, nil, true)
	assertCommonDecision(t, "empty response EOS", decision, err, ActionAllow, 0)
}
