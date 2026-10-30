//go:build libmodsecurity

package processor

import (
	"bytes"
	"context"
	"os"
	"testing"
)

const commonBodyLimitPayload = "envoy-body-limit-payload-must-not-be-an-event-field"

// Use a fresh real engine transaction for each valid or invalid host outcome.
// A rejected host acknowledgement must not be repaired by a later valid one.
func newCommonBodyLimitTransaction(t *testing.T, requestLimit int, requestAction string) (Transaction, string) {
	t.Helper()
	engine, eventPath := newCommonRuntimeEngineForRulesTest(t, `SecRuleEngine On
SecRequestBodyAccess On
`, requestLimit, requestAction, 1048576, "Reject")
	ctx := context.Background()
	transaction, err := engine.Open(ctx, commonTestStreamMetadata("body-limit-without-rule-id"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { transaction.Close(ctx, Summary{CloseReason: CloseImmediateResponse}) })
	decision, err := transaction.ProcessHeaders(ctx, DirectionRequest,
		[]Header{{Name: "host", Value: []byte("example.test")}}, false)
	assertCommonDecision(t, "request headers", decision, err, ActionAllow, 0)
	decision, err = transaction.ProcessBody(ctx, DirectionRequest, []byte(commonBodyLimitPayload), true)
	assertCommonDecision(t, "body limit", decision, err, ActionDeny, 403)
	if decision.RuleID != "" {
		t.Fatalf("body-limit rule ID=%q, want empty", decision.RuleID)
	}
	return transaction, eventPath
}

func TestCommonBodyLimitInvalidHostActionRemainsTerminal(t *testing.T) {
	transaction, eventPath := newCommonBodyLimitTransaction(t, 32, "Reject")
	ctx := context.Background()
	recorder, ok := transaction.(HostActionRecorder)
	if !ok {
		t.Fatal("Common transaction does not expose host-action recording")
	}
	first := recorder.RecordHostAction(ctx, HostAction{
		Action: AppliedActionRedirect, VisibleStatus: 302, TransportResult: "http_status",
	})
	if first == nil {
		t.Fatal("RecordHostAction() accepted a non-native body-limit action")
	}
	before, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []HostAction{
		{Action: AppliedActionRedirect, VisibleStatus: 302, TransportResult: "http_status"},
		{Action: AppliedActionDeny, VisibleStatus: 403, TransportResult: "http_status"},
	} {
		if next := recorder.RecordHostAction(ctx, action); next == nil || next.Error() != first.Error() {
			t.Fatalf("host acknowledgement resumed or replaced first error: first=%v next=%v", first, next)
		}
	}
	if _, err := transaction.ProcessBody(ctx, DirectionRequest, nil, true); err == nil {
		t.Fatal("request body resumed after a failed host acknowledgement")
	}
	if _, err := transaction.ProcessHeaders(ctx, DirectionResponse,
		[]Header{{Name: ":status", Value: []byte("200")}}, true); err == nil {
		t.Fatal("response processing resumed after a failed host acknowledgement")
	}
	after, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("retries appended duplicate events after the terminal host error")
	}
}
