//go:build libmodsecurity

package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCommonRuntimeEngineEvaluatesIncrementalLifecycle(t *testing.T) {
	engine, _ := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	contextValue := context.Background()
	testCases := []commonRuntimeLifecycleTestCase{
		{name: "phase1_request_headers", run: testCommonRuntimePhase1},
		{name: "phase2_request_body_eos", run: testCommonRuntimePhase2},
		{name: "phase3_response_headers_before_commit", run: testCommonRuntimePhase3},
		{name: "phase4_response_body_eos", run: testCommonRuntimePhase4},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			transaction, err := engine.Open(contextValue, commonTestStreamMetadata(testCase.name))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer transaction.Close(contextValue, Summary{CloseReason: ClosePeerEOF})
			testCase.run(t, contextValue, transaction)
		})
	}
}

func TestCommonRuntimeEngineRejectsStrictPolicyBeforeStreamAdmission(t *testing.T) {
	engine, _ := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	_, err := NewService(testConfig(LateActionStrict), engine)
	if err == nil || !strings.Contains(err.Error(), "phase4_mode=safe") {
		t.Fatalf("NewService() error = %v, want strict/safe admission rejection", err)
	}
}

func TestRequestHeadersForCommonRestoresOnlyValidatedAuthority(t *testing.T) {
	t.Run("authority becomes Host when absent", testRequestHeadersForCommonAddsValidatedHost)
	t.Run("ordinary Host wins without duplicate", testRequestHeadersForCommonRetainsOrdinaryHost)
	t.Run("missing authority is rejected", testRequestHeadersForCommonRejectsMissingAuthority)
	t.Run("control characters in authority are rejected", testRequestHeadersForCommonRejectsInjectedAuthority)
}

func testRequestHeadersForCommonAddsValidatedHost(t *testing.T) {
	headers, err := requestHeadersForCommon([]Header{
		{Name: ":method", Value: []byte("GET")},
		{Name: ":authority", Value: []byte("example.test:8443")},
		{Name: "x-request-id", Value: []byte("authority-host")},
	})
	if err != nil {
		t.Fatalf("requestHeadersForCommon() error = %v", err)
	}
	if got, want := len(headers), 4; got != want {
		t.Fatalf("header count = %d, want %d", got, want)
	}
	last := headers[len(headers)-1]
	if last.Name != "Host" || string(last.Value) != "example.test:8443" {
		t.Fatalf("injected Host = %#v, want validated authority", last)
	}
}

func testRequestHeadersForCommonRetainsOrdinaryHost(t *testing.T) {
	headers, err := requestHeadersForCommon([]Header{
		{Name: ":authority", Value: []byte("authority.example")},
		{Name: "Host", Value: []byte("header.example")},
	})
	if err != nil {
		t.Fatalf("requestHeadersForCommon() error = %v", err)
	}
	hostCount := 0
	for _, header := range headers {
		if strings.EqualFold(header.Name, "host") {
			hostCount++
			if got, want := string(header.Value), "header.example"; got != want {
				t.Fatalf("ordinary Host = %q, want %q", got, want)
			}
		}
	}
	if got, want := hostCount, 1; got != want {
		t.Fatalf("Host header count = %d, want %d", got, want)
	}
}

func testRequestHeadersForCommonRejectsMissingAuthority(t *testing.T) {
	assertRequestHeadersForCommonRejectsAuthority(t, nil)
}

func testRequestHeadersForCommonRejectsInjectedAuthority(t *testing.T) {
	assertRequestHeadersForCommonRejectsAuthority(t, []byte("example.test\r\ninjected: true"))
}

func assertRequestHeadersForCommonRejectsAuthority(t *testing.T, authority []byte) {
	t.Helper()
	if _, err := requestHeadersForCommon([]Header{{Name: ":authority", Value: authority}}); err == nil {
		t.Fatalf("requestHeadersForCommon() accepted invalid authority %q", authority)
	}
}

type commonRuntimeLifecycleTestCase struct {
	name string
	run  func(*testing.T, context.Context, Transaction)
}

func testCommonRuntimePhase1(t *testing.T, contextValue context.Context, transaction Transaction) {
	decision, err := transaction.ProcessHeaders(contextValue, DirectionRequest, []Header{{Name: "x-ms-p1", Value: []byte("block")}}, true)
	if err != nil || decision.Action != ActionDeny || decision.Status != 403 {
		t.Fatalf("phase-1 decision=%#v err=%v", decision, err)
	}
	if decision.RuleID != "1200001" {
		t.Fatalf("phase-1 rule ID=%q, want 1200001", decision.RuleID)
	}
	recorder, ok := transaction.(HostActionRecorder)
	if !ok {
		t.Fatal("Common transaction does not expose host-action recording")
	}
	if err := recorder.RecordHostAction(contextValue, HostAction{Action: AppliedActionDeny, VisibleStatus: 403, TransportResult: "http_status"}); err != nil {
		t.Fatalf("RecordHostAction() error = %v", err)
	}
}

func testCommonRuntimePhase2(t *testing.T, contextValue context.Context, transaction Transaction) {
	decision, err := transaction.ProcessHeaders(contextValue, DirectionRequest, []Header{{Name: "host", Value: []byte("example.test")}}, false)
	assertCommonDecision(t, "request headers", decision, err, ActionAllow, 0)
	decision, err = transaction.ProcessBody(contextValue, DirectionRequest, []byte("envoy-phase2-marker"), true)
	assertCommonDecision(t, "phase-2", decision, err, ActionDeny, 403)
	if decision.RuleID != "1200002" {
		t.Fatalf("phase-2 rule ID=%q, want 1200002", decision.RuleID)
	}
}

func testCommonRuntimePhase3(t *testing.T, contextValue context.Context, transaction Transaction) {
	decision, err := transaction.ProcessHeaders(contextValue, DirectionRequest, nil, true)
	assertCommonDecision(t, "request headers", decision, err, ActionAllow, 0)
	decision, err = transaction.ProcessHeaders(contextValue, DirectionResponse, []Header{{Name: ":status", Value: []byte("200")}, {Name: "x-ms-p3", Value: []byte("block")}}, false)
	assertCommonDecision(t, "phase-3", decision, err, ActionDeny, 403)
	if decision.RuleID != "1200003" {
		t.Fatalf("phase-3 rule ID=%q, want 1200003", decision.RuleID)
	}
}

func testCommonRuntimePhase4(t *testing.T, contextValue context.Context, transaction Transaction) {
	decision, err := transaction.ProcessHeaders(contextValue, DirectionRequest, nil, true)
	assertCommonDecision(t, "request headers", decision, err, ActionAllow, 0)
	decision, err = transaction.ProcessHeaders(contextValue, DirectionResponse, []Header{{Name: ":status", Value: []byte("200")}, {Name: "content-type", Value: []byte("text/plain")}}, false)
	assertCommonDecision(t, "response headers", decision, err, ActionAllow, 0)
	committer, ok := transaction.(ResponseCommitter)
	if !ok {
		t.Fatal("Common transaction does not expose response commit bookkeeping")
	}
	if err := committer.MarkResponseCommitted(contextValue); err != nil {
		t.Fatalf("MarkResponseCommitted() error = %v", err)
	}
	decision, err = transaction.ProcessBody(contextValue, DirectionResponse, []byte("envoy-phase4-marker"), true)
	assertCommonDecision(t, "phase-4", decision, err, ActionDeny, 403)
	if decision.RuleID != "1200004" {
		t.Fatalf("phase-4 rule ID=%q, want 1200004", decision.RuleID)
	}
	recorder, ok := transaction.(HostActionRecorder)
	if !ok {
		t.Fatal("Common transaction does not expose host-action recording")
	}
	if err := recorder.RecordHostAction(contextValue, HostAction{Action: AppliedActionLogOnly, VisibleStatus: 200, TransportResult: "log_only"}); err != nil {
		t.Fatalf("RecordHostAction() error = %v", err)
	}
}

func assertCommonDecision(t *testing.T, phase string, decision Decision, err error, action Action, status int) {
	t.Helper()
	if err != nil || decision.Action != action || decision.Status != status {
		t.Fatalf("%s decision=%#v err=%v", phase, decision, err)
	}
}

func TestCommonRuntimeEngineSerializesParallelStreams(t *testing.T) {
	engine, _ := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	const streamCount = 12
	errors := make(chan error, streamCount)
	var workers sync.WaitGroup
	for index := 0; index < streamCount; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			transaction, err := engine.Open(context.Background(), commonTestStreamMetadata(fmt.Sprintf("parallel-%d", index)))
			if err != nil {
				errors <- err
				return
			}
			defer transaction.Close(context.Background(), Summary{CloseReason: CloseResponseEOS})
			if decision, err := transaction.ProcessHeaders(context.Background(), DirectionRequest, nil, true); err != nil || decision.Action != ActionAllow {
				errors <- fmt.Errorf("request %d: decision=%#v err=%w", index, decision, err)
				return
			}
			if decision, err := transaction.ProcessHeaders(context.Background(), DirectionResponse, []Header{{Name: ":status", Value: []byte("200")}}, true); err != nil || decision.Action != ActionAllow {
				errors <- fmt.Errorf("response %d: decision=%#v err=%w", index, decision, err)
			}
		}(index)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCommonRuntimeEngineCloseHonorsShutdownContext(t *testing.T) {
	engine := &CommonRuntimeEngine{transactions: make(map[*commonRuntimeTransaction]struct{})}
	engine.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := engine.Close(ctx)
	elapsed := time.Since(started)
	engine.mu.Unlock()

	if !errors.Is(err, ErrCommonRuntimeShutdownTimeout) {
		t.Fatalf("Close() error = %v, want ErrCommonRuntimeShutdownTimeout", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Close() blocked for %s", elapsed)
	}
}

func TestCommonRuntimeEngineCloseRejectsCanceledContextBeforeDestroy(t *testing.T) {
	engine := &CommonRuntimeEngine{transactions: make(map[*commonRuntimeTransaction]struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := engine.Close(ctx)

	if !errors.Is(err, ErrCommonRuntimeShutdownTimeout) {
		t.Fatalf("Close() error = %v, want ErrCommonRuntimeShutdownTimeout", err)
	}
	if engine.closed {
		t.Fatal("Close() destroyed the Common runtime after the shutdown context was canceled")
	}
	if !engine.closing.Load() {
		t.Fatal("Close() did not retain the controlled shutting-down state")
	}
}

func TestCommonRuntimeEngineCloseBoundsBlockingDestructorAndPreventsReuse(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	engine := &CommonRuntimeEngine{
		transactions: make(map[*commonRuntimeTransaction]struct{}),
		destructor: func() {
			close(started)
			<-release
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	err := engine.Close(ctx)
	if !errors.Is(err, ErrCommonRuntimeShutdownTimeout) {
		t.Fatalf("Close() error = %v, want ErrCommonRuntimeShutdownTimeout", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("Close() blocked for %s", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("destructor worker did not start")
	}
	if _, err := engine.Open(context.Background(), commonTestStreamMetadata("after-destructor-timeout")); err == nil {
		t.Fatal("Open() succeeded after destructor ownership was handed off")
	}

	close(release)
	select {
	case <-engine.destroyDone:
	case <-time.After(time.Second):
		t.Fatal("destructor worker did not return")
	}
	if err := engine.Close(context.Background()); err != nil {
		t.Fatalf("Close() after late destructor return = %v", err)
	}
	if err := engine.Close(context.Background()); err != nil {
		t.Fatalf("repeated Close() = %v, want idempotent success", err)
	}
}

func TestCommonRuntimeEngineCloseDestructorRunsExactlyOnce(t *testing.T) {
	var calls atomic.Int32
	engine := &CommonRuntimeEngine{
		transactions: make(map[*commonRuntimeTransaction]struct{}),
		destructor:   func() { calls.Add(1) },
	}
	for index := 0; index < 3; index++ {
		if err := engine.Close(context.Background()); err != nil {
			t.Fatalf("Close(%d) = %v", index, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("destructor calls = %d, want exactly one", got)
	}
}

func TestCommonRuntimeTransactionCleanupHonorsContext(t *testing.T) {
	engine := &CommonRuntimeEngine{transactions: make(map[*commonRuntimeTransaction]struct{})}
	transaction := &commonRuntimeTransaction{engine: engine}
	engine.transactions[transaction] = struct{}{}
	engine.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	transaction.Close(ctx, Summary{CloseReason: CloseContextCanceled})
	elapsed := time.Since(started)
	engine.mu.Unlock()

	if elapsed > 500*time.Millisecond {
		t.Fatalf("transaction Close() blocked for %s", elapsed)
	}
	if err := transaction.CleanupFailure(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CleanupFailure() = %v, want context deadline", err)
	}
	if !errors.Is(transaction.CleanupFailure(), ErrCommonRuntimeTransactionCleanupTimeout) {
		t.Fatalf("CleanupFailure() = %v, want ErrCommonRuntimeTransactionCleanupTimeout", transaction.CleanupFailure())
	}
	if transaction.closed {
		t.Fatal("transaction marked closed after bounded mutex cleanup failure")
	}
	if !engine.closing.Load() {
		t.Fatal("transaction cleanup timeout did not prevent further native runtime reuse")
	}
	if err := engine.terminalFailure(); !errors.Is(err, ErrCommonRuntimeTransactionCleanupTimeout) {
		t.Fatalf("terminalFailure() = %v, want ErrCommonRuntimeTransactionCleanupTimeout", err)
	}
}

func TestCommonRuntimeEngineOperationsHonorMutexContext(t *testing.T) {
	engine := &CommonRuntimeEngine{transactions: make(map[*commonRuntimeTransaction]struct{})}
	transaction := &commonRuntimeTransaction{engine: engine}
	engine.mu.Lock()
	defer engine.mu.Unlock()

	testCases := []struct {
		name string
		run  func(context.Context) error
	}{
		{
			name: "open",
			run: func(ctx context.Context) error {
				_, err := engine.Open(ctx, commonTestStreamMetadata("mutex-timeout"))
				return err
			},
		},
		{
			name: "process_headers",
			run: func(ctx context.Context) error {
				_, err := transaction.ProcessHeaders(ctx, DirectionRequest, nil, true)
				return err
			},
		},
		{
			name: "process_body",
			run: func(ctx context.Context) error {
				_, err := transaction.ProcessBody(ctx, DirectionRequest, nil, true)
				return err
			},
		},
		{
			name: "mark_response_committed",
			run:  transaction.MarkResponseCommitted,
		},
		{
			name: "record_host_action",
			run: func(ctx context.Context) error {
				return transaction.RecordHostAction(ctx, HostAction{
					Action:          AppliedActionDeny,
					VisibleStatus:   403,
					TransportResult: "http_status",
				})
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			started := time.Now()
			err := testCase.run(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("operation error = %v, want context deadline", err)
			}
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("operation blocked for %s", elapsed)
			}
		})
	}

	if got := len(engine.transactions); got != 0 {
		t.Fatalf("transaction count = %d, want 0 after cancelled mutex waits", got)
	}
}

func TestCommonRuntimeEngineUsesCanonicalEnvoyEventIdentity(t *testing.T) {
	engine, eventPath := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	contextValue := context.Background()
	transaction, err := engine.Open(contextValue, commonTestStreamMetadata("canonical-event-identity"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	decision, err := transaction.ProcessHeaders(contextValue, DirectionRequest, []Header{{Name: "x-ms-p1", Value: []byte("block")}}, true)
	if err != nil || decision.Action != ActionDeny {
		t.Fatalf("request decision=%#v err=%v", decision, err)
	}
	recorder, ok := transaction.(HostActionRecorder)
	if !ok {
		t.Fatal("Common transaction does not expose host-action recording")
	}
	if err := recorder.RecordHostAction(contextValue, HostAction{
		Action: AppliedActionDeny, VisibleStatus: 403, TransportResult: "http_status",
	}); err != nil {
		t.Fatalf("RecordHostAction() error = %v", err)
	}
	transaction.Close(contextValue, Summary{CloseReason: CloseImmediateResponse})

	raw, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", eventPath, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("unmarshal Common event: %v", err)
		}
		if event["connector"] != "envoy" || event["integration_mode"] != "ext_proc" {
			t.Fatalf("Common event identity = connector=%#v integration_mode=%#v, want envoy/ext_proc", event["connector"], event["integration_mode"])
		}
	}
}

func TestCommonRuntimeEngineClassifiesModSecurityBodyLimitWithoutRuleID(t *testing.T) {
	transaction, eventPath := newCommonBodyLimitTransaction(t, 32, "Reject")
	contextValue := context.Background()
	recorder, ok := transaction.(HostActionRecorder)
	if !ok {
		t.Fatal("Common transaction does not expose host-action recording")
	}
	if err := recorder.RecordHostAction(contextValue, HostAction{
		Action: AppliedActionDeny, VisibleStatus: 403, TransportResult: "http_status",
	}); err != nil {
		t.Fatalf("RecordHostAction() error = %v", err)
	}

	raw, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", eventPath, err)
	}
	if strings.Contains(string(raw), commonBodyLimitPayload) {
		t.Fatal("event JSONL retained a request-body payload")
	}
	foundBodyLimit := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("unmarshal Common event: %v", err)
		}
		if event["message_id"] != "MSCONN_EVENT_BODY_LIMIT" {
			continue
		}
		foundBodyLimit = true
		if status, ok := event["http_status"].(float64); !ok || int(status) != 403 {
			t.Fatalf("body-limit event status=%#v, want 403", event["http_status"])
		}
		if ruleID, present := event["rule_id"]; present && ruleID != nil && ruleID != "" {
			t.Fatalf("body-limit event rule ID=%#v, want absent or empty", ruleID)
		}
	}
	if !foundBodyLimit {
		t.Fatal("body-limit event was not emitted")
	}
}

func TestCommonRuntimeEngineMapsP3RedirectLocation(t *testing.T) {
	const redirectTarget = "/msconnector-p3-redirect-target"
	engine, _ := newCommonRuntimeEngineForRulesTest(t, `SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecRule RESPONSE_HEADERS:X-Msconnector-Vector "@streq msconnector-p3-redirect" "id:1203002,phase:3,redirect:/msconnector-p3-redirect-target,status:302,log,t:none"
`, 1048576, "Reject", 1048576, "Reject")
	contextValue := context.Background()
	transaction, err := engine.Open(contextValue, commonTestStreamMetadata("p3-redirect-location"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer transaction.Close(contextValue, Summary{CloseReason: CloseImmediateResponse})

	decision, err := transaction.ProcessHeaders(contextValue, DirectionRequest, nil, true)
	assertCommonDecision(t, "request headers", decision, err, ActionAllow, 0)
	decision, err = transaction.ProcessHeaders(contextValue, DirectionResponse, []Header{
		{Name: ":status", Value: []byte("200")},
		{Name: "x-msconnector-vector", Value: []byte("msconnector-p3-redirect")},
	}, false)
	if err != nil || decision.Action != ActionRedirect || decision.Status != 302 || decision.RedirectURL != redirectTarget {
		t.Fatalf("phase-3 redirect decision=%#v err=%v", decision, err)
	}
	recorder, ok := transaction.(HostActionRecorder)
	if !ok {
		t.Fatal("Common transaction does not expose host-action recording")
	}
	if err := recorder.RecordHostAction(contextValue, HostAction{
		Action: AppliedActionRedirect, VisibleStatus: 302, TransportResult: "http_status",
	}); err != nil {
		t.Fatalf("RecordHostAction() error = %v", err)
	}
}

func newCommonRuntimeEngineForTest(t *testing.T, requestLimit int, requestLimitAction string, responseLimit int, responseLimitAction string) (*CommonRuntimeEngine, string) {
	return newCommonRuntimeEngineForRulesTest(t, `SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule REQUEST_HEADERS:X-Ms-P1 "@streq block" "id:1200001,phase:1,deny,status:403,log,t:none"
SecRule REQUEST_BODY "@contains envoy-phase2-marker" "id:1200002,phase:2,deny,status:403,log,t:none"
SecRule RESPONSE_HEADERS:X-Ms-P3 "@streq block" "id:1200003,phase:3,deny,status:403,log,t:none"
SecRule RESPONSE_BODY "@contains envoy-phase4-marker" "id:1200004,phase:4,deny,status:403,log,t:none"
`, requestLimit, requestLimitAction, responseLimit, responseLimitAction)
}

func newCommonRuntimeEngineForRulesTest(t *testing.T, rules string, requestLimit int, requestLimitAction string, responseLimit int, responseLimitAction string) (*CommonRuntimeEngine, string) {
	t.Helper()
	rules = fmt.Sprintf("SecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\nSecRequestBodyLimitAction %s\nSecResponseBodyLimit %d\nSecResponseBodyLimitAction %s\n", requestLimit, requestLimit, requestLimitAction, responseLimit, responseLimitAction) + rules
	directory := t.TempDir()
	rulesPath := filepath.Join(directory, "rules.conf")
	configPath := filepath.Join(directory, "runtime.conf")
	eventPath := filepath.Join(directory, "events.jsonl")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	config := fmt.Sprintf(`enabled=on
rules_file=%s
transaction_id_header=x-request-id
request_body_mode=streaming
response_body_mode=streaming
phase4_mode=safe
default_block_status=403
default_error_status=500
use_error_log=off
max_header_count=128
max_header_name_size=256
max_header_value_size=8192
max_total_header_bytes=32768
max_event_json_bytes=16384
event_path=%s
`, rulesPath, eventPath)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}
	engine, err := NewCommonRuntimeEngine(configPath)
	if err != nil {
		t.Fatalf("NewCommonRuntimeEngine() error = %v", err)
	}
	t.Cleanup(func() {
		if err := engine.Close(context.Background()); err != nil {
			t.Errorf("Common runtime close: %v", err)
		}
	})
	return engine, eventPath
}

func commonTestStreamMetadata(transactionID string) StreamMetadata {
	return StreamMetadata{
		TransactionID: transactionID,
		Request: RequestMetadata{
			Method:        "POST",
			URI:           "/common-bridge-test",
			Protocol:      "HTTP/1.1",
			Hostname:      "example.test",
			ClientAddress: "127.0.0.1",
			ClientPort:    49152,
			ServerAddress: "127.0.0.1",
			ServerPort:    18080,
		},
	}
}

func TestCommonRuntimeResponseReachesEnginePastFormerConnectorBudget(t *testing.T) {
	engine, _ := newCommonRuntimeEngineForRulesTest(t, `SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_BODY "@contains marker-past-former-budget" "id:1200994,phase:4,deny,status:451,log,t:none"
`, 2097152, "Reject", 2097152, "Reject")
	ctx := context.Background()
	tx, err := engine.Open(ctx, commonTestStreamMetadata("response-past-former-budget"))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close(ctx, Summary{CloseReason: CloseResponseEOS})
	d, err := tx.ProcessHeaders(ctx, DirectionRequest, nil, true)
	assertCommonDecision(t, "request", d, err, ActionAllow, 0)
	d, err = tx.ProcessHeaders(ctx, DirectionResponse, []Header{{Name: ":status", Value: []byte("200")}, {Name: "content-type", Value: []byte("text/plain")}}, false)
	assertCommonDecision(t, "response headers", d, err, ActionAllow, 0)
	chunk := make([]byte, 16384)
	for i := range chunk {
		chunk[i] = 'x'
	}
	for i := 0; i < 65; i++ {
		d, err = tx.ProcessBody(ctx, DirectionResponse, chunk, false)
		assertCommonDecision(t, "streamed response", d, err, ActionAllow, 0)
	}
	d, err = tx.ProcessBody(ctx, DirectionResponse, []byte("marker-past-former-budget"), true)
	assertCommonDecision(t, "engine tail rule", d, err, ActionDeny, 451)
	if d.RuleID != "1200994" {
		t.Fatalf("rule ID=%q", d.RuleID)
	}
}

func TestCommonRuntimeCleanupFailureRetainsFirstCause(t *testing.T) {
	transaction := &commonRuntimeTransaction{}
	first := errors.New("first cleanup failure")
	transaction.setCleanupFailure(first)
	transaction.setCleanupFailure(errors.New("later cleanup failure"))
	if got := transaction.CleanupFailure(); got != first {
		t.Fatalf("CleanupFailure() = %v, want first cause %v", got, first)
	}
}

func TestCommonRuntimeCloseReportsTerminalEventSinkFailure(t *testing.T) {
	for _, mode := range []string{"incomplete-request", "incomplete-response", "expired-composite-lease", "restarted-composite-service"} {
		t.Run(mode, func(t *testing.T) {
			testCommonRuntimeTerminalSinkFailure(t, mode)
		})
	}
}

func testCommonRuntimeTerminalSinkFailure(t *testing.T, mode string) {
	t.Helper()
	engine, eventPath := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	ctx := context.Background()
	tx, err := engine.Open(ctx, commonTestStreamMetadata(mode))
	if err != nil {
		t.Fatal(err)
	}
	native := tx.(*commonRuntimeTransaction)
	prepareIncompleteNativeTransaction(t, ctx, tx, mode)
	// Runtime owns an already-open FILE*. Replace only this test's event FD
	// with a real read-only file description; changing the pathname cannot
	// inject a failure into an existing open descriptor.
	sinkFD := nativeEventDescriptor(t, eventPath)
	readOnly, err := os.Open(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := unix.Dup2(int(readOnly.Fd()), sinkFD); err != nil {
		t.Fatal(err)
	}
	reason := ClosePeerEOF
	if mode == "expired-composite-lease" {
		reason = CloseReason("timeout")
	} else if mode == "restarted-composite-service" {
		reason = CloseReason("restart")
	}
	tx.Close(ctx, Summary{CloseReason: reason})
	first := native.CleanupFailure()
	if first == nil || !strings.Contains(first.Error(), "I/O error") {
		t.Fatalf("CleanupFailure(after physical sink failure) = %v, want Common I/O event output failure", first)
	}
	healthy, err := os.OpenFile(eventPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	if err := unix.Dup2(int(healthy.Fd()), sinkFD); err != nil {
		t.Fatal(err)
	}
	tx.Close(ctx, Summary{CloseReason: reason})
	if got := native.CleanupFailure(); got != first {
		t.Fatalf("CleanupFailure(after repeated close) = %v, want %v", got, first)
	}
	if err := engine.Close(ctx); err != nil {
		t.Fatalf("engine Close(after failed sink) = %v", err)
	}
	content, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("Close(retry) wrote %d bytes, want 0", len(content))
	}
}

func TestCommonRuntimeCloseObservedCompositeTimeoutKeepsNativeTerminal(t *testing.T) {
	testCommonRuntimeObservedCompositeClose(t, "timeout", "engine_timeout", "MSCONN_EVENT_ENGINE_TIMEOUT", "transaction")
}

func TestCommonRuntimeCloseObservedCompositeRestartKeepsNativeTerminal(t *testing.T) {
	testCommonRuntimeObservedCompositeClose(t, "restart", "connector_error", "MSCONN_EVENT_CONNECTOR_ERROR", nil)
}

func testCommonRuntimeObservedCompositeClose(t *testing.T, reason, eventType, messageID string, timeoutStage any) {
	t.Helper()
	engine, eventPath := newCommonRuntimeEngineForTest(t, 4096, "Reject", 8192, "Reject")
	ctx := context.Background()
	tx, err := engine.Open(ctx, commonTestStreamMetadata("observed-composite-"+reason))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := tx.ProcessHeaders(ctx, DirectionRequest, []Header{{Name: "x-safe", Value: []byte("allow")}}, true)
	assertCommonDecision(t, "request", decision, err, ActionAllow, 0)
	tx.Close(ctx, Summary{CloseReason: CloseReason(reason)})
	tx.Close(ctx, Summary{CloseReason: CloseReason(reason)})
	if err := tx.(*commonRuntimeTransaction).CleanupFailure(); err != nil {
		t.Fatalf("CleanupFailure(observed %s)=%v, want successful checked native cleanup", reason, err)
	}
	if tx.(*commonRuntimeTransaction).native != nil || len(engine.transactions) != 0 {
		t.Fatal("observed close retained native transaction")
	}
	raw, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("%s emitted %d native events, want one terminal without invented P3/P4", reason, len(lines))
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event["event"] != eventType || event["message_id"] != messageID || event["status"] != "error" || event["timeout_stage"] != timeoutStage {
		t.Fatalf("native %s event=%v, want typed %s terminal", reason, event, eventType)
	}
	if event["phase"] != "request_body" || event["eos_seen"] != false || event["response_started"] != false || event["visible_http_status"] != float64(0) {
		t.Fatalf("native %s event fabricated response phases/EOS/host action: %v", reason, event)
	}
	if event["cancelled"] != false || event["client_disconnected"] != false || event["upstream_disconnected"] != false || event["connection_aborted"] != false {
		t.Fatalf("native %s event invented client/upstream abort: %v", reason, event)
	}
}

func prepareIncompleteNativeTransaction(t *testing.T, ctx context.Context, tx Transaction, mode string) {
	t.Helper()
	decision, err := tx.ProcessHeaders(ctx, DirectionRequest, []Header{{Name: "x-safe", Value: []byte("allow")}}, mode != "incomplete-request")
	if err != nil || decision.Action != ActionAllow {
		t.Fatalf("ProcessHeaders(request) = %#v, %v, want allow", decision, err)
	}
	if mode == "incomplete-response" {
		decision, err = tx.ProcessHeaders(ctx, DirectionResponse, []Header{{Name: ":status", Value: []byte("200")}}, false)
		if err != nil || decision.Action != ActionAllow {
			t.Fatalf("ProcessHeaders(response) = %#v, %v, want allow", decision, err)
		}
	}
}

func nativeEventDescriptor(t *testing.T, eventPath string) int {
	t.Helper()
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	sinkFD := -1
	for _, descriptor := range descriptors {
		target, err := os.Readlink("/proc/self/fd/" + descriptor.Name())
		if err == nil && target == eventPath {
			if sinkFD != -1 {
				t.Fatal("multiple native event descriptors")
			}
			sinkFD, err = strconv.Atoi(descriptor.Name())
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if sinkFD == -1 {
		t.Fatal("native event descriptor not found")
	}
	return sinkFD
}

func TestCommonRuntimeCloseIncompleteHealthySinkKeepsSequenceEvent(t *testing.T) {
	engine, eventPath := newCommonRuntimeEngineForTest(t, 1048576, "Reject", 1048576, "Reject")
	ctx := context.Background()
	tx, err := engine.Open(ctx, commonTestStreamMetadata("healthy-incomplete"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessHeaders(ctx, DirectionRequest, []Header{{Name: "x-safe", Value: []byte("allow")}}, false); err != nil {
		t.Fatal(err)
	}
	tx.Close(ctx, Summary{CloseReason: ClosePeerEOF})
	err = tx.(*commonRuntimeTransaction).CleanupFailure()
	if !errors.Is(err, ErrTransactionFinishPhaseSequence) {
		t.Fatalf("CleanupFailure(incomplete with healthy sink) = %v, want transaction-local sequence failure", err)
	}
	content, readErr := os.ReadFile(eventPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("incomplete close terminal events = %d, want 1", len(lines))
	}
}
