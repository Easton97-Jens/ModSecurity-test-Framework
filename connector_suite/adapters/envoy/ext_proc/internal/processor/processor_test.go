package processor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func assertTerminalFailureAndRejectsFollowUp(t *testing.T, service *Service, wantedSubstring, failureDescription, timeoutMessage string) {
	t.Helper()
	select {
	case fatal := <-service.FatalErrors():
		if fatal == nil || !strings.Contains(fatal.Error(), wantedSubstring) {
			t.Fatalf("FatalErrors() = %v, want %s", fatal, failureDescription)
		}
	case <-time.After(time.Second):
		t.Fatal(timeoutMessage)
	}
	if followUpErr := service.Process(&fakeProcessStream{contextFactory: testStreamContext(context.Background())}); status.Code(followUpErr) != codes.Unavailable {
		t.Fatalf("follow-up Process() code = %s, want Unavailable (err=%v)", status.Code(followUpErr), followUpErr)
	}
}

func assertProcessResultCode(t *testing.T, processDone <-chan error, want codes.Code, wantDescription, timeoutMessage string) {
	t.Helper()
	select {
	case err := <-processDone:
		if got := status.Code(err); got != want {
			t.Fatalf("Process() code = %s, want %s (err=%v)", got, wantDescription, err)
		}
	case <-time.After(time.Second):
		t.Fatal(timeoutMessage)
	}
}

func TestProcessStreamsChunksAndCleansUpAtResponseEOS(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{
		{request: requestHeaders(false)},
		{request: requestBody([]byte("one"), false)},
		{request: requestBody([]byte("two"), true)},
		{request: responseHeaders(false)},
		{request: responseBody([]byte("result"), true)},
	}}

	if err := service.Process(stream); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if got, want := len(stream.sent), 5; got != want {
		t.Fatalf("sent responses = %d, want %d", got, want)
	}
	if stream.sent[0].GetRequestHeaders() == nil || stream.sent[1].GetRequestBody() == nil || stream.sent[3].GetResponseHeaders() == nil || stream.sent[4].GetResponseBody() == nil {
		t.Fatalf("responses did not match streamed request phases")
	}
	if got, want := transaction.requestBodyLengths, []int{3, 3}; !sameInts(got, want) {
		t.Fatalf("request chunk lengths = %v, want %v", got, want)
	}
	if got, want := transaction.responseBodyLengths, []int{6}; !sameInts(got, want) {
		t.Fatalf("response chunk lengths = %v, want %v", got, want)
	}
	if len(transaction.closed) != 1 {
		t.Fatalf("close calls = %d, want 1", len(transaction.closed))
	}
	summary := transaction.closed[0]
	if summary.CloseReason != CloseResponseEOS || summary.RequestBodyBytes != 6 || summary.ResponseBodyBytes != 6 {
		t.Fatalf("unexpected cleanup summary: %#v", summary)
	}
}

func TestProcessEnforcesAbsoluteStreamLifetimeAndReleasesAdmission(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamMaxLifetimeMS = 10
	recvRelease := make(chan struct{})
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(false)}},
		recvBlock:      recvRelease,
	}
	err := service.Process(stream)
	close(recvRelease)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("Process() code = %s, want DeadlineExceeded (err=%v)", status.Code(err), err)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseStreamMaxLifetime {
		t.Fatalf("cleanup = %#v, want one max-lifetime cleanup", transaction.closed)
	}
	deadline := time.Now().Add(time.Second)
	for service.pendingReceives.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := service.pendingReceives.Load(); got != 0 {
		t.Fatalf("pending receives = %d, want 0 after blocked Recv release", got)
	}
	if err := service.Process(&fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(true)}},
	}); err != nil {
		t.Fatalf("follow-up Process() error = %v", err)
	}
}

func TestProcessIdleTimeoutCancelsTransportReceiveAndAllowsFollowUp(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamIdleTimeoutMS = 25
	service.config.StreamMaxLifetimeMS = 1000
	client, _, closeServer := startBufconnProcessorServer(t, service)
	defer closeServer()

	idleCtx, cancelIdle := context.WithTimeout(context.Background(), time.Second)
	defer cancelIdle()
	idleStream, err := client.Process(idleCtx)
	if err != nil {
		t.Fatalf("Process() idle stream error = %v", err)
	}
	if err := idleStream.Send(requestHeaders(false)); err != nil {
		t.Fatalf("idle stream Send(request headers) error = %v", err)
	}
	if response, err := idleStream.Recv(); err != nil || response.GetRequestHeaders() == nil {
		t.Fatalf("idle stream initial Recv() = (%#v, %v), want request-headers continue", response, err)
	}
	if _, err := idleStream.Recv(); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("idle stream Recv() code = %s, want DeadlineExceeded (err=%v)", status.Code(err), err)
	}
	waitForPendingReceives(t, service, 0)
	if got, want := len(transaction.closed), 1; got != want {
		t.Fatalf("idle stream cleanup calls = %d, want %d", got, want)
	}
	if got, want := transaction.closed[0].CloseReason, CloseStreamIdleTimeout; got != want {
		t.Fatalf("idle stream cleanup reason = %q, want %q", got, want)
	}

	followUpCtx, cancelFollowUp := context.WithTimeout(context.Background(), time.Second)
	defer cancelFollowUp()
	followUp, err := client.Process(followUpCtx)
	if err != nil {
		t.Fatalf("Process() follow-up stream error = %v", err)
	}
	if err := followUp.Send(requestHeaders(true)); err != nil {
		t.Fatalf("follow-up Send(request headers) error = %v", err)
	}
	if response, err := followUp.Recv(); err != nil || response.GetRequestHeaders() == nil {
		t.Fatalf("follow-up initial Recv() = (%#v, %v), want request-headers continue", response, err)
	}
	if err := followUp.CloseSend(); err != nil {
		t.Fatalf("follow-up CloseSend() error = %v", err)
	}
	if _, err := followUp.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("follow-up final Recv() = %v, want EOF", err)
	}
	waitForPendingReceives(t, service, 0)
	if got, want := len(transaction.closed), 2; got != want {
		t.Fatalf("follow-up cleanup calls = %d, want %d", got, want)
	}
	if got, want := transaction.closed[1].CloseReason, ClosePeerEOF; got != want {
		t.Fatalf("follow-up cleanup reason = %q, want %q", got, want)
	}
}

func TestProcessConcurrentAdmissionRejectsBeforeOpeningAndReleasesSlot(t *testing.T) {
	transaction := &recordingTransaction{}
	var openCalls atomic.Int32
	config := testConfig(LateActionSafe)
	config.MaxConcurrentStreams = 1
	config.StreamIdleTimeoutMS = 1000
	config.StreamMaxLifetimeMS = 2000
	service, err := NewService(config, countingRecordingEngine{transaction: transaction, openCalls: &openCalls})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- service.Process(&fakeProcessStream{
			contextFactory: testStreamContext(context.Background()),
			receive:        []receiveResult{{request: requestHeaders(false)}},
			recvBlock:      releaseFirst,
		})
	}()
	waitForAtomicInt32(t, &openCalls, 1)

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- service.Process(&fakeProcessStream{contextFactory: testStreamContext(context.Background())})
	}()
	select {
	case secondErr := <-secondDone:
		if got := status.Code(secondErr); got != codes.ResourceExhausted {
			t.Fatalf("concurrent Process() code = %s, want ResourceExhausted (err=%v)", got, secondErr)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Process() blocked instead of rejecting admission")
	}
	if got, want := openCalls.Load(), int32(1); got != want {
		t.Fatalf("engine Open calls after rejected admission = %d, want %d", got, want)
	}

	close(releaseFirst)
	select {
	case firstErr := <-firstDone:
		if firstErr != nil {
			t.Fatalf("first Process() error = %v", firstErr)
		}
	case <-time.After(time.Second):
		t.Fatal("first Process() did not release its admission slot")
	}
	if err := service.Process(&fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(true)}},
	}); err != nil {
		t.Fatalf("follow-up Process() error = %v", err)
	}
	if got, want := openCalls.Load(), int32(2); got != want {
		t.Fatalf("engine Open calls after released admission = %d, want %d", got, want)
	}
}

func TestProcessServerStopCancelsActiveStreamAndReleasesAdmission(t *testing.T) {
	transaction := &recordingTransaction{closeDone: make(chan struct{})}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamIdleTimeoutMS = 1000
	service.config.StreamMaxLifetimeMS = 2000
	client, server, closeServer := startBufconnProcessorServer(t, service)
	defer closeServer()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("Process() stream error = %v", err)
	}
	if err := stream.Send(requestHeaders(false)); err != nil {
		t.Fatalf("server-stop stream Send(request headers) error = %v", err)
	}
	if response, err := stream.Recv(); err != nil || response.GetRequestHeaders() == nil {
		t.Fatalf("server-stop stream initial Recv() = (%#v, %v), want request-headers continue", response, err)
	}

	server.Stop()
	if _, err := stream.Recv(); err == nil {
		t.Fatal("server-stop stream Recv() succeeded after server Stop")
	}
	select {
	case <-transaction.closeDone:
	case <-time.After(time.Second):
		t.Fatal("server Stop did not close the active transaction")
	}
	waitForPendingReceives(t, service, 0)
	waitForAdmission(t, service, 0)
	if got, want := len(transaction.closed), 1; got != want {
		t.Fatalf("server-stop cleanup calls = %d, want %d", got, want)
	}
	if got, want := transaction.closed[0].CloseReason, CloseContextCanceled; got != want {
		t.Fatalf("server-stop cleanup reason = %q, want %q", got, want)
	}
}

func TestProcessEnforcesAbsoluteStreamLifetimeDuringBlockedSend(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamMaxLifetimeMS = 10
	sendRelease := make(chan struct{})
	sendDone := make(chan struct{})
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(false)}},
		sendBlock:      sendRelease,
		sendDone:       sendDone,
	}
	err := service.Process(stream)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("Process() code = %s, want DeadlineExceeded (err=%v)", status.Code(err), err)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseStreamMaxLifetime {
		t.Fatalf("cleanup = %#v, want one max-lifetime cleanup", transaction.closed)
	}
	assertTerminalFailureAndRejectsFollowUp(t, service, "response send exceeded", "blocked-send terminal failure", "blocked Send did not report terminal failure")
	close(sendRelease)
	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("blocked Send goroutine did not finish after release")
	}
}

func TestProcessRecordsConfirmedResponseEvidenceAtStreamDeadline(t *testing.T) {
	tests := []struct {
		name            string
		transaction     *recordingTransaction
		receive         []receiveResult
		blockOnSendCall int
		wantCommits     int
		wantHostActions []HostAction
	}{
		{
			name:            "response continue commit",
			transaction:     &recordingTransaction{},
			receive:         []receiveResult{{request: requestHeaders(true)}, {request: responseHeaders(false)}},
			blockOnSendCall: 2,
			wantCommits:     1,
		},
		{
			name: "immediate host action",
			transaction: &recordingTransaction{headerDecision: func(direction Direction) Decision {
				if direction == DirectionRequest {
					return Decision{Action: ActionDeny, Status: 403}
				}
				return allowDecision()
			}},
			receive:         []receiveResult{{request: requestHeaders(false)}},
			blockOnSendCall: 1,
			wantHostActions: []HostAction{{
				Action: AppliedActionDeny, VisibleStatus: 403, TransportResult: "http_status",
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runConfirmedResponseEvidenceCase(t, test)
		})
	}
}

func runConfirmedResponseEvidenceCase(t *testing.T, test struct {
	name            string
	transaction     *recordingTransaction
	receive         []receiveResult
	blockOnSendCall int
	wantCommits     int
	wantHostActions []HostAction
}) {
	t.Helper()
	service := newTestService(t, test.transaction, LateActionSafe)
	service.config.StreamMaxLifetimeMS = 5
	service.config.CleanupTimeoutMS = 100
	sendRelease := make(chan struct{})
	sendStarted := make(chan struct{})
	stream := &fakeProcessStream{
		contextFactory:  testStreamContext(context.Background()),
		receive:         test.receive,
		sendBlock:       sendRelease,
		sendStarted:     sendStarted,
		blockOnSendCall: test.blockOnSendCall,
	}

	processDone := make(chan error, 1)
	go func() { processDone <- service.Process(stream) }()
	select {
	case <-sendStarted:
	case <-time.After(time.Second):
		t.Fatal("response Send did not begin")
	}
	// This is intentionally longer than the stream maximum but shorter
	// than cleanup grace: Send returns successfully after the real
	// derived deadline, not merely after a synthetic context cancel.
	time.Sleep(25 * time.Millisecond)
	close(sendRelease)
	assertProcessResultCode(t, processDone, codes.DeadlineExceeded, "DeadlineExceeded", "Process did not finish after late Send completed")
	if got := test.transaction.responseCommits; got != test.wantCommits {
		t.Fatalf("response commits = %d, want %d", got, test.wantCommits)
	}
	if got := test.transaction.hostActions; !sameHostActions(got, test.wantHostActions) {
		t.Fatalf("host actions = %#v, want %#v", got, test.wantHostActions)
	}
	if len(test.transaction.closed) != 1 || test.transaction.closed[0].CloseReason != CloseStreamMaxLifetime {
		t.Fatalf("cleanup = %#v, want one max-lifetime cleanup", test.transaction.closed)
	}
	assertTerminalFailureAndRejectsFollowUp(t, service, "response send exceeded", "late-send terminal failure", "late successful Send did not report terminal failure")
}
func TestProcessRejectsExcessActiveStreamBeforeTransactionOpenAndReleasesSlot(t *testing.T) {
	transaction := &recordingTransaction{}
	engine := &countingEngine{transaction: transaction}
	service := newTestServiceWithStreamLimit(t, engine, LateActionSafe, 1)

	firstContext, firstCancelCause := context.WithCancelCause(context.Background())
	defer firstCancelCause(nil)
	held := newBlockingProcessStream(firstContext)
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- service.Process(held)
	}()

	select {
	case <-held.waiting:
	case <-time.After(time.Second):
		t.Fatal("first stream did not reach its controlled idle receive")
	}
	if got := engine.opens.Load(); got != 1 {
		t.Fatalf("transaction opens before admission rejection = %d, want 1", got)
	}

	excess := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{{request: requestHeaders(true)}}}
	if err := service.Process(excess); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("excess stream error code = %v, want %v (err=%v)", status.Code(err), codes.ResourceExhausted, err)
	}
	if got := engine.opens.Load(); got != 1 {
		t.Fatalf("excess stream opened a transaction: opens = %d, want 1", got)
	}

	close(held.release)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("held stream Process() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("held stream did not release its capacity slot")
	}

	next := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{{request: requestHeaders(true)}}}
	if err := service.Process(next); err != nil {
		t.Fatalf("stream after release Process() error = %v", err)
	}
	if got := engine.opens.Load(); got != 2 {
		t.Fatalf("transaction opens after released slot = %d, want 2", got)
	}
}

func TestCumulativeBodyAccountingRejectsSignedOverflow(t *testing.T) {
	for _, test := range []struct {
		name       string
		direction  Direction
		setCurrent func(*Summary, int64)
		getCurrent func(Summary) int64
	}{
		{name: "request", direction: DirectionRequest,
			setCurrent: func(summary *Summary, value int64) { summary.RequestBodyBytes = value },
			getCurrent: func(summary Summary) int64 { return summary.RequestBodyBytes }},
		{name: "response", direction: DirectionResponse,
			setCurrent: func(summary *Summary, value int64) { summary.ResponseBodyBytes = value },
			getCurrent: func(summary Summary) int64 { return summary.ResponseBodyBytes }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig(LateActionSafe)
			state := newStreamState(config, recordingEngine{transaction: &recordingTransaction{}}, discardObserver{})

			// The last representable byte is a legitimate boundary and must be
			// admitted when it remains within the configured limit.
			test.setCurrent(&state.summary, math.MaxInt64-1)
			if decision := state.bodyLimitDecision(test.direction, 1); decision.Action != ActionAllow {
				t.Fatalf("boundary body chunk decision = %#v, want allow", decision)
			}
			state.recordBodyProgress(test.direction, 1, false)
			if got := test.getCurrent(state.summary); got != math.MaxInt64 {
				t.Fatalf("boundary body total = %d, want %d", got, int64(math.MaxInt64))
			}

			// A further chunk must fail closed before comparison or progress
			// recording can wrap the signed counter negative.
			before := state.summary
			if decision := state.bodyLimitDecision(test.direction, 1); decision.Action != ActionDeny {
				t.Fatalf("overflow body chunk decision = %#v, want deny", decision)
			}
			state.recordBodyProgress(test.direction, 1, false)
			if got := test.getCurrent(state.summary); got != test.getCurrent(before) {
				t.Fatalf("overflow body total = %d, want unchanged %d", got, test.getCurrent(before))
			}
		})
	}
}

func TestProcessStopsAfterSuccessfulResponseEvidenceFailure(t *testing.T) {
	transaction := &recordingTransaction{
		hostActionError: errors.New("Common event write rejected"),
		headerDecision: func(direction Direction) Decision {
			if direction == DirectionRequest {
				return Decision{Action: ActionDeny, Status: 403}
			}
			return allowDecision()
		},
	}
	service := newTestService(t, transaction, LateActionSafe)
	err := service.Process(&fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(false)}},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("Process() code = %s, want Internal (err=%v)", status.Code(err), err)
	}
	if len(transaction.hostActions) != 0 {
		t.Fatalf("failed evidence recorded host actions: %#v", transaction.hostActions)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseProcessorError {
		t.Fatalf("cleanup = %#v, want one processor-error cleanup", transaction.closed)
	}
	assertTerminalFailureAndRejectsFollowUp(t, service, "successful response evidence failed", "evidence terminal failure", "successful response evidence failure did not report fatal")
}

func TestProcessStuckNativeEquivalentReportsFatalAfterCleanupGrace(t *testing.T) {
	transaction := &recordingTransaction{
		headerBlock: make(chan struct{}),
		closeDone:   make(chan struct{}),
	}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamMaxLifetimeMS = 10
	service.config.CleanupTimeoutMS = 10
	started := make(chan struct{})
	transaction.headerStarted = started
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(false)}},
	}
	processDone := make(chan error, 1)
	go func() { processDone <- service.Process(stream) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native-equivalent handler did not start")
	}
	assertProcessResultCode(t, processDone, codes.DeadlineExceeded, "DeadlineExceeded", "Process() did not return after bounded cleanup grace")
	assertTerminalFailureAndRejectsFollowUp(t, service, "native handler remained blocked", "stuck-handler terminal failure", "stuck native-equivalent handler did not report fatal")
	if len(transaction.closed) != 0 {
		t.Fatalf("cleanup called concurrently with stuck handler: %#v", transaction.closed)
	}
	close(transaction.headerBlock)
	select {
	case <-transaction.closeDone:
	case <-time.After(time.Second):
		t.Fatal("deferred native handler cleanup did not run after handler release")
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseStreamMaxLifetime {
		t.Fatalf("deferred cleanup = %#v, want one max-lifetime cleanup", transaction.closed)
	}
}

func TestProcessStuckSuccessfulEvidenceTransfersCleanupOwnership(t *testing.T) {
	transaction := &recordingTransaction{
		responseCommitBlock:   make(chan struct{}),
		responseCommitStarted: make(chan struct{}),
		closeDone:             make(chan struct{}),
	}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.CleanupTimeoutMS = 10
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive: []receiveResult{
			{request: requestHeaders(false)},
			{request: responseHeaders(false)},
		},
	}
	processDone := make(chan error, 1)
	go func() { processDone <- service.Process(stream) }()
	select {
	case <-transaction.responseCommitStarted:
	case <-time.After(time.Second):
		t.Fatal("successful response evidence did not enter the blocking hook")
	}
	assertProcessResultCode(t, processDone, codes.Internal, "Internal", "Process() remained blocked in native response evidence")
	assertTerminalFailureAndRejectsFollowUp(t, service, "response evidence remained blocked", "stuck-evidence terminal failure", "stuck response evidence did not report fatal")
	if got := atomic.LoadInt32(&transaction.closeCalls); got != 0 {
		t.Fatalf("cleanup called while response evidence was blocked: %d calls", got)
	}
	close(transaction.responseCommitBlock)
	select {
	case <-transaction.closeDone:
	case <-time.After(time.Second):
		t.Fatal("deferred response-evidence cleanup did not run after release")
	}
	if got := len(transaction.closed); got != 1 {
		t.Fatalf("deferred cleanup calls = %d, want exactly one", got)
	}
}

func TestProcessStuckTransactionCloseReportsFatalAndDoesNotRetry(t *testing.T) {
	transaction := &recordingTransaction{
		closeBlock:   make(chan struct{}),
		closeStarted: make(chan struct{}),
		closeDone:    make(chan struct{}),
	}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.CleanupTimeoutMS = 10
	processDone := make(chan error, 1)
	go func() {
		processDone <- service.Process(&fakeProcessStream{
			contextFactory: testStreamContext(context.Background()),
			receive:        []receiveResult{{request: requestHeaders(true)}},
		})
	}()
	select {
	case <-transaction.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("transaction cleanup did not enter the blocking hook")
	}
	assertProcessResultCode(t, processDone, codes.Internal, "Internal", "Process() remained blocked in transaction cleanup")
	assertTerminalFailureAndRejectsFollowUp(t, service, "cleanup remained blocked", "stuck-cleanup terminal failure", "stuck transaction cleanup did not report fatal")
	close(transaction.closeBlock)
	select {
	case <-transaction.closeDone:
	case <-time.After(time.Second):
		t.Fatal("transaction cleanup did not finish after release")
	}
	if got := atomic.LoadInt32(&transaction.closeCalls); got != 1 {
		t.Fatalf("transaction Close calls = %d, want exactly one", got)
	}
}

func TestProcessPromptNativeCancellationPreservesFollowUpAdmission(t *testing.T) {
	transaction := &recordingTransaction{headerBlock: make(chan struct{}), headerCancel: true}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamMaxLifetimeMS = 10
	service.config.CleanupTimeoutMS = 50
	if err := service.Process(&fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(false)}},
	}); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("Process() code = %s, want DeadlineExceeded (err=%v)", status.Code(err), err)
	}
	if fatal := service.terminalFailure(); fatal != nil {
		t.Fatalf("prompt cancellation reported fatal = %v", fatal)
	}
	transaction.headerBlock = nil
	transaction.headerCancel = false
	if err := service.Process(&fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(true)}},
	}); err != nil {
		t.Fatalf("follow-up Process() error = %v", err)
	}
}

func TestProcessRejectsFatalAdmissionWithoutOpeningTransaction(t *testing.T) {
	transaction := &recordingTransaction{}
	var openCalls atomic.Int32
	service, err := NewService(testConfig(LateActionSafe), countingRecordingEngine{
		transaction: transaction,
		openCalls:   &openCalls,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.reportFatal(errors.New("terminal cleanup failure"))

	err = service.Process(&fakeProcessStream{contextFactory: testStreamContext(context.Background())})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Process() code = %s, want Unavailable (err=%v)", status.Code(err), err)
	}
	if got := openCalls.Load(); got != 0 {
		t.Fatalf("engine Open calls = %d, want 0 after fatal admission rejection", got)
	}
	select {
	case <-service.admission:
		t.Fatal("fatal admission rejection left a reservation")
	default:
	}
}

func TestProcessAbsoluteLifetimeIsNotRenewedByActivity(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamIdleTimeoutMS = 20
	service.config.StreamMaxLifetimeMS = 25
	recvRelease := make(chan struct{})
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(false)}, {request: requestBody([]byte("a"), false)}, {request: requestBody([]byte("b"), false)}, {request: requestBody([]byte("c"), false)}},
		receiveDelays:  []time.Duration{0, 8 * time.Millisecond, 8 * time.Millisecond, 8 * time.Millisecond},
		recvBlock:      recvRelease,
	}
	err := service.Process(stream)
	close(recvRelease)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("Process() = %v, want max-lifetime DeadlineExceeded", err)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseStreamMaxLifetime {
		t.Fatalf("cleanup = %#v, want max-lifetime cleanup", transaction.closed)
	}
}

func TestProcessActiveStreamCompletesBeforeAbsoluteLifetime(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamIdleTimeoutMS = 20
	service.config.StreamMaxLifetimeMS = 100
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(true)}},
		receiveDelays:  []time.Duration{5 * time.Millisecond},
	}
	if err := service.Process(stream); err != nil {
		t.Fatalf("short active Process() error = %v", err)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != ClosePeerEOF {
		t.Fatalf("cleanup = %#v, want clean peer-EOF cleanup", transaction.closed)
	}
}

func TestConfigRequiresPositiveStreamMaximumLifetime(t *testing.T) {
	config := testConfig(LateActionSafe)
	config.StreamMaxLifetimeMS = 0
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "stream_max_lifetime_ms") {
		t.Fatalf("Validate() = %v, want positive stream_max_lifetime_ms error", err)
	}
	config.StreamMaxLifetimeMS = 1
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() with positive stream_max_lifetime_ms = %v", err)
	}
}
func TestEnvoyHeaderValidationRejectsUnsafeValuesBeforeEngine(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
	}{
		{name: "crlf", value: []byte("safe\r\nInjected: yes")},
		{name: "nul", value: []byte{'s', 'a', 'f', 0, 'e'}},
		{name: "control", value: []byte{'s', 0x01, 'e'}},
		{name: "invalid utf8", value: []byte{'\xc3', '('}},
	}
	for _, test := range cases {
		t.Run("request/"+test.name, func(t *testing.T) {
			transaction := &recordingTransaction{}
			service := newTestService(t, transaction, LateActionSafe)
			request := requestHeaders(false)
			request.GetRequestHeaders().Headers.Headers = append(request.GetRequestHeaders().Headers.Headers,
				&corev3.HeaderValue{Key: "x-unsafe", RawValue: test.value})
			stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{{request: request}}}
			if err := service.Process(stream); err == nil {
				t.Fatalf("Process() accepted unsafe request header")
			}
			if len(transaction.headerCalls) != 0 {
				t.Fatalf("engine received unsafe request headers: %v", transaction.headerCalls)
			}
		})
		t.Run("response/"+test.name, func(t *testing.T) {
			transaction := &recordingTransaction{}
			service := newTestService(t, transaction, LateActionSafe)
			response := responseHeaders(false)
			response.GetResponseHeaders().Headers.Headers = append(response.GetResponseHeaders().Headers.Headers,
				&corev3.HeaderValue{Key: "x-unsafe", RawValue: test.value})
			stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{
				{request: requestHeaders(true)}, {request: response},
			}}
			if err := service.Process(stream); err == nil {
				t.Fatalf("Process() accepted unsafe response header")
			}
			if got, want := transaction.headerCalls, []Direction{DirectionRequest}; !sameDirections(got, want) {
				t.Fatalf("engine header calls = %v, want %v", got, want)
			}
		})
	}
}

func TestEnvoyHeaderValidationAcceptsTokensUTF8AndHTAB(t *testing.T) {
	for _, name := range []string{"x-valid", "X_Custom.1", ":authority", ":status"} {
		if !validEnvoyHeaderName(name) {
			t.Fatalf("validEnvoyHeaderName(%q) = false", name)
		}
	}
	for _, value := range [][]byte{[]byte("text\tvalue"), []byte("Grüße"), []byte{0xff}} {
		if string(value) == string([]byte{0xff}) {
			if validEnvoyHeaderValue(value) {
				t.Fatalf("validEnvoyHeaderValue accepted invalid UTF-8")
			}
			continue
		}
		if !validEnvoyHeaderValue(value) {
			t.Fatalf("validEnvoyHeaderValue rejected %q", value)
		}
	}
	for _, name := range []string{"", ":", "bad name", "bad\\rname", "ümlaut"} {
		if validEnvoyHeaderName(name) {
			t.Fatalf("validEnvoyHeaderName accepted %q", name)
		}
	}
}

func TestRedirectDecisionRejectsUnsafeLocationValues(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{name: "crlf header splitting", url: "/safe\r\nX-Injected: yes"},
		{name: "nul", url: "/safe\x00target"},
		{name: "control", url: "/safe\x01target"},
		{name: "raw whitespace", url: "/safe target"},
		{name: "invalid utf8", url: string([]byte{'/', 's', 'a', 'f', 'e', 0xff})},
		{name: "oversize", url: "/" + strings.Repeat("a", maxRedirectURLBytes)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeDecision(Decision{
				Action:      ActionRedirect,
				Status:      302,
				RedirectURL: test.url,
			})
			if got.Action != ActionDeny || got.Status != int(typev3.StatusCode_Forbidden) || got.RedirectURL != "" {
				t.Fatalf("unsafe redirect normalized to %#v, want deny 403 without URL", got)
			}
			response := immediateResponse(Decision{Action: ActionRedirect, Status: 302, RedirectURL: test.url})
			if response.GetImmediateResponse().GetHeaders() != nil {
				t.Fatalf("unsafe redirect emitted location header: %#v", response)
			}
		})
	}
}

func TestRedirectDecisionPreservesValidRelativeAndAbsoluteURLs(t *testing.T) {
	for _, url := range []string{"/login?next=%2Fhome", "https://example.test/login"} {
		got := normalizeDecision(Decision{Action: ActionRedirect, Status: 307, RedirectURL: url})
		if got.Action != ActionRedirect || got.Status != 307 || got.RedirectURL != url {
			t.Fatalf("valid redirect normalized to %#v, want URL %q", got, url)
		}
		response := immediateResponse(got).GetImmediateResponse()
		if response.GetHeaders() == nil || len(response.GetHeaders().GetSetHeaders()) != 1 {
			t.Fatalf("valid redirect did not emit exactly one location header: %#v", response)
		}
		header := response.GetHeaders().GetSetHeaders()[0].GetHeader()
		if header.GetKey() != "location" || string(headerValueBytes(header)) != url {
			t.Fatalf("location header = %#v, want %q", header, url)
		}
	}
}

func TestRequestDenyUsesImmediateResponseBeforeResponseHeaders(t *testing.T) {
	transaction := &recordingTransaction{
		headerDecision: func(direction Direction) Decision {
			if direction == DirectionRequest {
				return Decision{Action: ActionDeny, Status: 403}
			}
			return allowDecision()
		},
	}
	service := newTestService(t, transaction, LateActionSafe)
	stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{{request: requestHeaders(false)}}}

	if err := service.Process(stream); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if got, want := len(stream.sent), 1; got != want {
		t.Fatalf("sent responses = %d, want %d", got, want)
	}
	if response := stream.sent[0].GetImmediateResponse(); response == nil || int(response.GetStatus().GetCode()) != 403 {
		t.Fatalf("expected a request immediate 403 response, got %#v", stream.sent[0])
	}
	if transaction.closed[0].CloseReason != CloseImmediateResponse {
		t.Fatalf("close reason = %q, want %q", transaction.closed[0].CloseReason, CloseImmediateResponse)
	}
	if got, want := transaction.hostActions, []HostAction{{
		Action: AppliedActionDeny, VisibleStatus: 403, TransportResult: "http_status",
	}}; !sameHostActions(got, want) {
		t.Fatalf("host actions = %#v, want %#v", got, want)
	}
}

func TestRequestBodyHasNoConnectorAggregateGate(t *testing.T) {
	transaction := &recordingTransaction{}
	service, err := NewService(testConfig(LateActionSafe), recordingEngine{transaction: transaction})
	if err != nil {
		t.Fatal(err)
	}
	stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{{request: requestHeaders(false)}, {request: requestBody([]byte("12345"), true)}}}
	if err := service.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(transaction.requestBodyLengths) != 1 || transaction.requestBodyLengths[0] != 5 {
		t.Fatalf("full input not dispatched: %v", transaction.requestBodyLengths)
	}
	if stream.sent[1].GetImmediateResponse() != nil {
		t.Fatal("connector selected an aggregate body rejection")
	}
}

func TestRedirectDecisionRejectsUnsafeHeaderTargets(t *testing.T) {
	for _, target := range []string{
		"https://example.test/next\r\nX-Injected: yes",
		"https://example.test/next\x1f",
		"https://example.test/next\x7f",
		strings.Repeat("a", maxRedirectURLBytes+1),
	} {
		decision := normalizeDecision(Decision{Action: ActionRedirect, Status: 302, RedirectURL: target})
		if decision.Action != ActionDeny || decision.Status != int(typev3.StatusCode_Forbidden) {
			t.Fatalf("unsafe redirect %q normalized to %#v, want deny/403", target, decision)
		}
		if response := immediateResponse(decision); response.GetImmediateResponse().GetHeaders() != nil {
			t.Fatalf("rejected redirect retained a Location mutation: %#v", response)
		}
	}
}

func TestResponseHeaderDecisionsUseImmediateResponseBeforeCommit(t *testing.T) {
	for _, test := range responseHeaderDecisionCases() {
		t.Run(test.name, func(t *testing.T) {
			transaction, response := processResponseHeaderDecision(t, test)
			assertResponseHeaderDecision(t, transaction, response, test)
		})
	}
}

type responseHeaderDecisionCase struct {
	name               string
	decision           Decision
	wantAction         AppliedAction
	wantLocation       bool
	wantHTTPHostAction bool
}

func responseHeaderDecisionCases() []responseHeaderDecisionCase {
	return []responseHeaderDecisionCase{
		{name: "deny", decision: Decision{Action: ActionDeny, Status: 403}, wantAction: AppliedActionDeny},
		{name: "redirect", decision: Decision{Action: ActionRedirect, Status: 302, RedirectURL: "/msconnector-p3-redirect-target"}, wantAction: AppliedActionRedirect, wantLocation: true, wantHTTPHostAction: true},
	}
}

func processResponseHeaderDecision(t *testing.T, test responseHeaderDecisionCase) (*recordingTransaction, *extprocv3.ImmediateResponse) {
	t.Helper()
	transaction := &recordingTransaction{
		headerDecision: func(direction Direction) Decision {
			if direction == DirectionResponse {
				return test.decision
			}
			return allowDecision()
		},
	}
	service := newTestService(t, transaction, LateActionSafe)
	stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{
		{request: requestHeaders(true)},
		{request: responseHeaders(false)},
	}}

	if err := service.Process(stream); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if got, want := len(stream.sent), 2; got != want {
		t.Fatalf("sent responses = %d, want %d", got, want)
	}
	if stream.sent[0].GetRequestHeaders() == nil {
		t.Fatalf("request headers did not receive a continue response: %#v", stream.sent[0])
	}
	return transaction, stream.sent[1].GetImmediateResponse()
}

func assertResponseHeaderDecision(t *testing.T, transaction *recordingTransaction, response *extprocv3.ImmediateResponse, test responseHeaderDecisionCase) {
	t.Helper()
	if response == nil || int(response.GetStatus().GetCode()) != test.decision.Status {
		t.Fatalf("expected a response-header immediate %d response, got %#v", test.decision.Status, response)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseImmediateResponse {
		t.Fatalf("unexpected cleanup after response-header decision: %#v", transaction.closed)
	}
	if len(transaction.hostActions) != 1 || transaction.hostActions[0].Action != test.wantAction {
		t.Fatalf("response-header host action = %#v", transaction.hostActions)
	}
	if test.wantHTTPHostAction {
		assertResponseHeaderHostAction(t, transaction, test)
	}
	if test.wantLocation {
		assertResponseHeaderLocation(t, response, test.decision.RedirectURL)
	}
}

func assertResponseHeaderHostAction(t *testing.T, transaction *recordingTransaction, test responseHeaderDecisionCase) {
	t.Helper()
	want := []HostAction{{
		Action: AppliedActionRedirect, VisibleStatus: test.decision.Status, TransportResult: "http_status",
	}}
	if !sameHostActions(transaction.hostActions, want) {
		t.Fatalf("response-header redirect host action = %#v", transaction.hostActions)
	}
}

func assertResponseHeaderLocation(t *testing.T, response *extprocv3.ImmediateResponse, redirectURL string) {
	t.Helper()
	headers := response.GetHeaders().GetSetHeaders()
	if len(headers) != 1 || headers[0].GetHeader().GetKey() != "location" || string(headers[0].GetHeader().GetRawValue()) != redirectURL || headers[0].GetHeader().GetValue() != "" || headers[0].GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
		t.Fatalf("response-header redirect location = %#v", headers)
	}
}

func TestExplicitEmptyRequestDoesNotSynthesizeBody(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{
		{request: requestHeadersWithExplicitEmptyBody()},
		{request: responseHeaders(false)},
	}}

	if err := service.Process(stream); err == nil {
		t.Fatal("response without EOS returned success")
	}
	if got, want := len(stream.sent), 2; got != want {
		t.Fatalf("sent responses = %d, want %d", got, want)
	}
	if stream.sent[0].GetRequestHeaders() == nil {
		t.Fatalf("request headers did not receive a continue response: %#v", stream.sent[0])
	}
	if stream.sent[1].GetResponseHeaders() == nil {
		t.Fatalf("response headers unexpectedly became an immediate response: %#v", stream.sent[1])
	}
	if got := transaction.requestBodyLengths; len(got) != 0 {
		t.Fatalf("explicitly empty request synthesized body chunks = %v", got)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != ClosePeerEOF {
		t.Fatalf("unexpected cleanup after explicit empty request: %#v", transaction.closed)
	}
	if len(transaction.hostActions) != 0 {
		t.Fatalf("explicitly empty request recorded host actions: %#v", transaction.hostActions)
	}
}

func TestFailedImmediateResponseDoesNotRecordHostAction(t *testing.T) {
	transaction := &recordingTransaction{
		headerDecision: func(direction Direction) Decision {
			if direction == DirectionRequest {
				return Decision{Action: ActionDeny, Status: 403}
			}
			return allowDecision()
		},
	}
	service := newTestService(t, transaction, LateActionSafe)
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		sendErr:        io.ErrClosedPipe,
		receive:        []receiveResult{{request: requestHeaders(false)}},
	}
	if err := service.Process(stream); err == nil {
		t.Fatal("Process() accepted a failed ImmediateResponse send")
	}
	if len(transaction.hostActions) != 0 {
		t.Fatalf("failed send recorded host action: %#v", transaction.hostActions)
	}
}

func TestResponseCommitRequiresSuccessfulResponseHeaderContinue(t *testing.T) {
	transaction := &recordingTransaction{}
	state := newStreamState(testConfig(LateActionSafe), recordingEngine{transaction: transaction}, discardObserver{})

	requestHeaderResponse, terminal, err := state.handle(context.Background(), requestHeaders(true))
	if err != nil || terminal || requestHeaderResponse.GetRequestHeaders() == nil {
		t.Fatalf("request header handling = response=%#v terminal=%t err=%v", requestHeaderResponse, terminal, err)
	}
	if err := state.markResponseCommittedAfterSuccessfulContinue(context.Background(), requestHeaders(true), requestHeaderResponse); err != nil {
		t.Fatalf("mark request response committed: %v", err)
	}
	if state.responseCommitted {
		t.Fatal("request-header continue must not commit the response")
	}

	upstreamHeaders := responseHeaders(false)
	responseHeaderResponse, terminal, err := state.handle(context.Background(), upstreamHeaders)
	if err != nil || terminal || responseHeaderResponse.GetResponseHeaders() == nil {
		t.Fatalf("response header handling = response=%#v terminal=%t err=%v", responseHeaderResponse, terminal, err)
	}
	if state.responseCommitted {
		t.Fatal("constructing a response-header continue must not commit the response")
	}
	if err := state.markResponseCommittedAfterSuccessfulContinue(context.Background(), upstreamHeaders, responseHeaderResponse); err != nil {
		t.Fatalf("mark response response committed: %v", err)
	}
	if !state.responseCommitted {
		t.Fatal("successful response-header continue must commit the response boundary")
	}
}

func TestStrictPolicyIsRejectedBeforeStreamAdmission(t *testing.T) {
	_, err := NewService(testConfig(LateActionStrict), recordingEngine{transaction: &recordingTransaction{}})
	if err == nil || !strings.Contains(err.Error(), "proven strict post-commit host action") {
		t.Fatalf("NewService() error = %v, want strict admission rejection", err)
	}
}

func TestLatePolicyAdmissionDelegatesToRuleEvaluatingEngine(t *testing.T) {
	engine := &policyValidationEngine{
		recordingEngine: recordingEngine{transaction: &recordingTransaction{}},
		rejection:       errors.New("phase4_mode=safe cannot prove strict"),
	}
	_, err := NewService(testConfig(LateActionStrict), engine)
	if err == nil || !strings.Contains(err.Error(), "phase4_mode=safe") {
		t.Fatalf("NewService() error = %v, want runtime policy rejection", err)
	}
	if got, want := engine.policies, []LateActionPolicy{LateActionStrict}; !sameLateActionPolicies(got, want) {
		t.Fatalf("validated policies = %v, want %v", got, want)
	}

	engine.rejection = nil
	if _, err := NewService(testConfig(LateActionSafe), engine); err != nil {
		t.Fatalf("NewService() safe policy error = %v", err)
	}
	if got, want := engine.policies, []LateActionPolicy{LateActionStrict, LateActionSafe}; !sameLateActionPolicies(got, want) {
		t.Fatalf("validated policies = %v, want %v", got, want)
	}
}

func TestCancellationCleansUpWithoutAttributingTheHTTPReset(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	contextValue, cancelCause := context.WithCancelCause(context.Background())
	defer cancelCause(nil)
	stream := &fakeProcessStream{contextFactory: testStreamContext(contextValue), cancel: func() { cancelCause(context.Canceled) }, receive: []receiveResult{
		{request: requestHeaders(false)},
		{cancel: true, err: context.Canceled},
	}}

	if err := service.Process(stream); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if len(transaction.closed) != 1 {
		t.Fatalf("close calls = %d, want 1", len(transaction.closed))
	}
	if got, want := transaction.closed[0].CloseReason, CloseContextCanceled; got != want {
		t.Fatalf("close reason = %q, want %q", got, want)
	}
}

func TestInheritedParentDeadlineIsCancellationNotStreamLifetime(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	service.config.StreamMaxLifetimeMS = 1000
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	recvRelease := make(chan struct{})
	stream := &fakeProcessStream{
		contextFactory: testStreamContext(parent),
		receive:        []receiveResult{{request: requestHeaders(false)}},
		recvBlock:      recvRelease,
	}
	err := service.Process(stream)
	close(recvRelease)
	if err != nil {
		t.Fatalf("Process() error = %v, want graceful cancellation", err)
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseContextCanceled {
		t.Fatalf("cleanup = %#v, want one parent-cancellation cleanup", transaction.closed)
	}
	if fatal := service.terminalFailure(); fatal != nil {
		t.Fatalf("inherited parent deadline reported fatal = %v", fatal)
	}
	if err := service.Process(&fakeProcessStream{
		contextFactory: testStreamContext(context.Background()),
		receive:        []receiveResult{{request: requestHeaders(true)}},
	}); err != nil {
		t.Fatalf("follow-up Process() error = %v", err)
	}
}

func TestPeerEOFCleansUpWithoutAttributingTheHTTPReset(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{
		{request: requestHeaders(false)},
		{err: io.EOF},
	}}

	if err := service.Process(stream); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if len(transaction.closed) != 1 {
		t.Fatalf("close calls = %d, want 1", len(transaction.closed))
	}
	if got, want := transaction.closed[0].CloseReason, ClosePeerEOF; got != want {
		t.Fatalf("close reason = %q, want %q", got, want)
	}
}

func TestTrailersFinalizeIncrementalBodiesAtEOS(t *testing.T) {
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, LateActionSafe)
	stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{
		{request: requestHeaders(false)},
		{request: requestTrailers()},
		{request: responseHeaders(false)},
		{request: responseTrailers()},
	}}

	if err := service.Process(stream); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if !sameInts(transaction.requestBodyLengths, []int{0}) {
		t.Fatalf("request trailer EOS body lengths = %v, want %v", transaction.requestBodyLengths, []int{0})
	}
	if !sameInts(transaction.responseBodyLengths, []int{0}) {
		t.Fatalf("response trailer EOS body lengths = %v, want %v", transaction.responseBodyLengths, []int{0})
	}
	if stream.sent[1].GetRequestTrailers() == nil {
		t.Fatalf("request trailer did not receive trailer response: %#v", stream.sent[1])
	}
	if stream.sent[3].GetResponseTrailers() == nil {
		t.Fatalf("response trailer did not receive trailer response: %#v", stream.sent[3])
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != CloseResponseEOS {
		t.Fatalf("trailer cleanup = %#v", transaction.closed)
	}
}

func TestRequestMetadataUsesEnvoyAttributesWithoutPeerInference(t *testing.T) {
	attributes, err := structpb.NewStruct(map[string]any{
		"request.protocol":    "HTTP/1.1",
		"source.address":      "192.0.2.10",
		"source.port":         45678,
		"destination.address": "198.51.100.7",
		"destination.port":    443,
	})
	if err != nil {
		t.Fatalf("NewStruct() error = %v", err)
	}
	metadata, err := requestMetadataFromEnvoy([]Header{
		{Name: ":method", Value: []byte("POST")},
		{Name: ":path", Value: []byte("/metadata")},
		{Name: ":authority", Value: []byte("example.test")},
	}, map[string]*structpb.Struct{"envoy.filters.http.ext_proc": attributes})
	if err != nil {
		t.Fatalf("requestMetadataFromEnvoy() error = %v", err)
	}
	if got, want := metadata, (RequestMetadata{
		Method: "POST", URI: "/metadata", Protocol: "HTTP/1.1", Hostname: "example.test",
		ClientAddress: "192.0.2.10", ClientPort: 45678,
		ServerAddress: "198.51.100.7", ServerPort: 443,
	}); got != want {
		t.Fatalf("metadata = %#v, want %#v", got, want)
	}
}

func TestRequestMetadataRejectsMismatchedAuthorityAndHost(t *testing.T) {
	authorityAndHost := func(authorityFirst bool) []Header {
		authority := Header{Name: ":authority", Value: []byte("trusted.example")}
		host := Header{Name: "Host", Value: []byte("attacker.example")}
		if authorityFirst {
			return []Header{authority, host}
		}
		return []Header{host, authority}
	}

	for name, headers := range map[string][]Header{
		"authority before Host": authorityAndHost(true),
		"Host before authority": authorityAndHost(false),
		"duplicate Host after matching Host": {
			{Name: ":authority", Value: []byte("trusted.example")},
			{Name: "Host", Value: []byte("trusted.example")},
			{Name: "Host", Value: []byte("attacker.example")},
		},
		"duplicate authority after matching authority": {
			{Name: ":authority", Value: []byte("trusted.example")},
			{Name: ":authority", Value: []byte("attacker.example")},
			{Name: "Host", Value: []byte("trusted.example")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := requestMetadataFromEnvoy(headers, map[string]*structpb.Struct{}); err == nil {
				t.Fatal("requestMetadataFromEnvoy() accepted mismatched :authority and Host")
			}
		})
	}
}

func TestRequestMetadataAcceptsCaseInsensitiveMatchingAuthorityAndHost(t *testing.T) {
	metadata, err := requestMetadataFromEnvoy([]Header{
		{Name: ":authority", Value: []byte("Example.TEST:8443")},
		{Name: "Host", Value: []byte("example.test:8443")},
	}, map[string]*structpb.Struct{})
	if err != nil {
		t.Fatalf("requestMetadataFromEnvoy() error = %v", err)
	}
	if got, want := metadata.Hostname, "Example.TEST:8443"; got != want {
		t.Fatalf("Hostname = %q, want authority %q", got, want)
	}
}

func TestRequestMetadataRejectsMissingAuthorityAndHost(t *testing.T) {
	_, err := requestMetadataFromEnvoy([]Header{{Name: ":method", Value: []byte("GET")}}, map[string]*structpb.Struct{})
	if err == nil {
		t.Fatal("requestMetadataFromEnvoy() accepted request without :authority or Host")
	}
}

func TestEnvoyEndpointAddressKeepsOnlyTheHostComponentOfSocketAttributes(t *testing.T) {
	for input, want := range map[string]string{
		"192.0.2.10:45678":  "192.0.2.10",
		"[2001:db8::1]:443": "2001:db8::1",
		"2001:db8::1":       "2001:db8::1",
		"example.test":      "example.test",
	} {
		if got := envoyEndpointAddress(input); got != want {
			t.Errorf("envoyEndpointAddress(%q) = %q, want %q", input, got, want)
		}
	}
}

func newTestService(t *testing.T, transaction *recordingTransaction, policy LateActionPolicy) *Service {
	return newTestServiceWithStreamLimit(t, recordingEngine{transaction: transaction}, policy, DefaultMaxActiveStreams)
}

func newTestServiceWithStreamLimit(t *testing.T, engine TransactionOpener, policy LateActionPolicy, streamLimit int) *Service {
	t.Helper()
	service, err := newServiceWithStreamLimit(testConfig(policy), engine, discardObserver{}, streamLimit)
	if err != nil {
		t.Fatalf("newServiceWithStreamLimit() error = %v", err)
	}
	return service
}

func testConfig(policy LateActionPolicy) Config {
	return Config{
		ListenAddress:        "127.0.0.1:18083",
		TransactionIDHeader:  "x-request-id",
		MaxHeaderCount:       128,
		MaxHeaderNameBytes:   256,
		MaxHeaderValueBytes:  8192,
		MaxTotalHeaderBytes:  32768,
		MaxBodyChunkBytes:    1024,
		MaxGRPCMessageBytes:  2048,
		EngineTimeoutMS:      100,
		StreamIdleTimeoutMS:  100,
		StreamMaxLifetimeMS:  1000,
		MaxConcurrentStreams: 4,
		CleanupTimeoutMS:     100,
		ShutdownTimeoutMS:    100,
		LateActionPolicy:     policy,
	}
}

type recordingEngine struct {
	transaction *recordingTransaction
}

func (engine recordingEngine) Open(context.Context, StreamMetadata) (Transaction, error) {
	return engine.transaction, nil
}

type countingRecordingEngine struct {
	transaction *recordingTransaction
	openCalls   *atomic.Int32
}

func (engine countingRecordingEngine) Open(context.Context, StreamMetadata) (Transaction, error) {
	engine.openCalls.Add(1)
	return engine.transaction, nil
}

type countingEngine struct {
	transaction Transaction
	opens       atomic.Int32
}

func (engine *countingEngine) Open(context.Context, StreamMetadata) (Transaction, error) {
	engine.opens.Add(1)
	return engine.transaction, nil
}

type policyValidationEngine struct {
	recordingEngine
	rejection error
	policies  []LateActionPolicy
}

func (engine *policyValidationEngine) ValidateLateActionPolicy(policy LateActionPolicy) error {
	engine.policies = append(engine.policies, policy)
	return engine.rejection
}

type recordingTransaction struct {
	headerDecision        func(Direction) Decision
	bodyDecision          func(Direction) Decision
	headerCalls           []Direction
	requestBodyLengths    []int
	responseBodyLengths   []int
	closed                []Summary
	hostActions           []HostAction
	responseCommits       int
	responseCommitError   error
	hostActionError       error
	headerBlock           chan struct{}
	headerStarted         chan<- struct{}
	headerCancel          bool
	closeDone             chan struct{}
	responseCommitBlock   chan struct{}
	responseCommitStarted chan struct{}
	closeBlock            chan struct{}
	closeStarted          chan struct{}
	closeCalls            int32
}

func (transaction *recordingTransaction) ProcessHeaders(ctx context.Context, direction Direction, _ []Header, _ bool) (Decision, error) {
	if transaction.headerStarted != nil {
		close(transaction.headerStarted)
		transaction.headerStarted = nil
	}
	if transaction.headerBlock != nil {
		if transaction.headerCancel {
			<-ctx.Done()
			return allowDecision(), ctx.Err()
		}
		<-transaction.headerBlock
	}
	transaction.headerCalls = append(transaction.headerCalls, direction)
	if transaction.headerDecision != nil {
		return transaction.headerDecision(direction), nil
	}
	return allowDecision(), nil
}

func sameDirections(left, right []Direction) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (transaction *recordingTransaction) ProcessBody(_ context.Context, direction Direction, body []byte, _ bool) (Decision, error) {
	// Intentionally keep only length metadata: the test exercises that the
	// stream adapter gives the transaction one chunk at a time.
	if direction == DirectionRequest {
		transaction.requestBodyLengths = append(transaction.requestBodyLengths, len(body))
	} else {
		transaction.responseBodyLengths = append(transaction.responseBodyLengths, len(body))
	}
	if transaction.bodyDecision != nil {
		return transaction.bodyDecision(direction), nil
	}
	return allowDecision(), nil
}

func (transaction *recordingTransaction) Close(_ context.Context, summary Summary) {
	atomic.AddInt32(&transaction.closeCalls, 1)
	if transaction.closeStarted != nil {
		close(transaction.closeStarted)
	}
	if transaction.closeBlock != nil {
		<-transaction.closeBlock
	}
	transaction.closed = append(transaction.closed, summary)
	if transaction.closeDone != nil {
		close(transaction.closeDone)
	}
}

func (transaction *recordingTransaction) MarkResponseCommitted(ctx context.Context) error {
	if transaction.responseCommitStarted != nil {
		close(transaction.responseCommitStarted)
	}
	if transaction.responseCommitBlock != nil {
		<-transaction.responseCommitBlock
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if transaction.responseCommitError != nil {
		return transaction.responseCommitError
	}
	transaction.responseCommits++
	return nil
}

func (transaction *recordingTransaction) RecordHostAction(ctx context.Context, action HostAction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if transaction.hostActionError != nil {
		return transaction.hostActionError
	}
	transaction.hostActions = append(transaction.hostActions, action)
	return nil
}

type receiveResult struct {
	request *extprocv3.ProcessingRequest
	err     error
	cancel  bool
}

func startBufconnProcessorServer(t *testing.T, service *Service) (extprocv3.ExternalProcessorClient, *grpc.Server, func()) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(server, service)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	dialContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := grpc.DialContext(
		dialContext,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("dial buffered ext_proc server: %v", err)
	}
	cleanup := func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("buffered ext_proc server did not stop")
		}
	}
	return extprocv3.NewExternalProcessorClient(connection), server, cleanup
}

func waitForPendingReceives(t *testing.T, service *Service, want int64) {
	waitForCondition(t, func() (bool, string) {
		got := service.pendingReceives.Load()
		return got == want, fmt.Sprintf("pending receives = %d, want %d", got, want)
	})
}

func waitForAdmission(t *testing.T, service *Service, want int) {
	waitForCondition(t, func() (bool, string) {
		got := len(service.admission)
		return got == want, fmt.Sprintf("admission reservations = %d, want %d", got, want)
	})
}

func waitForAtomicInt32(t *testing.T, counter *atomic.Int32, want int32) {
	waitForCondition(t, func() (bool, string) {
		got := counter.Load()
		return got == want, fmt.Sprintf("atomic counter = %d, want %d", got, want)
	})
}

func waitForCondition(t *testing.T, condition func() (bool, string)) {
	t.Helper()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		ready, failure := condition()
		if ready {
			return
		}
		select {
		case <-timeout.C:
			t.Fatal(failure)
		case <-tick.C:
		}
	}
}

type fakeProcessStream struct {
	contextFactory  func() context.Context
	cancel          context.CancelFunc
	receive         []receiveResult
	sent            []*extprocv3.ProcessingResponse
	sendErr         error
	index           int
	recvBlock       <-chan struct{}
	receiveDelays   []time.Duration
	sendBlock       <-chan struct{}
	sendDone        chan struct{}
	sendStarted     chan struct{}
	sendCalls       int
	blockOnSendCall int
}

func (stream *fakeProcessStream) Send(response *extprocv3.ProcessingResponse) error {
	stream.sendCalls++
	if stream.sendStarted != nil && (stream.blockOnSendCall == 0 || stream.sendCalls == stream.blockOnSendCall) {
		close(stream.sendStarted)
	}
	if stream.sendBlock != nil && (stream.blockOnSendCall == 0 || stream.sendCalls == stream.blockOnSendCall) {
		<-stream.sendBlock
	}
	if stream.sendDone != nil {
		close(stream.sendDone)
	}
	stream.sent = append(stream.sent, response)
	if stream.sendErr != nil {
		return stream.sendErr
	}
	return nil
}

func (stream *fakeProcessStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if stream.index < len(stream.receiveDelays) && stream.receiveDelays[stream.index] > 0 {
		time.Sleep(stream.receiveDelays[stream.index])
	}
	if stream.index >= len(stream.receive) && stream.recvBlock != nil {
		<-stream.recvBlock
	}
	if stream.index >= len(stream.receive) {
		return nil, io.EOF
	}
	result := stream.receive[stream.index]
	stream.index++
	if result.cancel && stream.cancel != nil {
		stream.cancel()
	}
	return result.request, result.err
}

func (stream *fakeProcessStream) SetHeader(metadata.MD) error  { return nil }
func (stream *fakeProcessStream) SendHeader(metadata.MD) error { return nil }
func (stream *fakeProcessStream) SetTrailer(metadata.MD)       {}
func (stream *fakeProcessStream) Context() context.Context {
	if stream.contextFactory == nil {
		return context.Background()
	}
	return stream.contextFactory()
}
func (stream *fakeProcessStream) SendMsg(any) error { return nil }
func (stream *fakeProcessStream) RecvMsg(any) error { return nil }

func testStreamContext(contextValue context.Context) func() context.Context {
	return func() context.Context {
		return contextValue
	}
}

type blockingProcessStream struct {
	contextFactory func() context.Context
	delivered      bool
	waiting        chan struct{}
	release        chan struct{}
}

func newBlockingProcessStream(contextValue context.Context) *blockingProcessStream {
	return &blockingProcessStream{
		contextFactory: func() context.Context { return contextValue },
		waiting:        make(chan struct{}),
		release:        make(chan struct{}),
	}
}

func (stream *blockingProcessStream) Send(*extprocv3.ProcessingResponse) error { return nil }

func (stream *blockingProcessStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if !stream.delivered {
		stream.delivered = true
		return requestHeaders(false), nil
	}
	close(stream.waiting)
	contextValue := stream.Context()
	select {
	case <-stream.release:
		return nil, io.EOF
	case <-contextValue.Done():
		return nil, contextValue.Err()
	}
}

func (stream *blockingProcessStream) SetHeader(metadata.MD) error  { return nil }
func (stream *blockingProcessStream) SendHeader(metadata.MD) error { return nil }
func (stream *blockingProcessStream) SetTrailer(metadata.MD)       {}
func (stream *blockingProcessStream) Context() context.Context     { return stream.contextFactory() }
func (stream *blockingProcessStream) SendMsg(any) error            { return nil }
func (stream *blockingProcessStream) RecvMsg(any) error            { return nil }

func requestHeaders(eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":method", Value: "POST"},
			{Key: ":path", Value: "/test"},
			{Key: ":authority", Value: "example.test"},
			{Key: "x-request-id", Value: "test-id"},
		}},
		EndOfStream: eos,
	}}}
}

func requestHeadersWithExplicitEmptyBody() *extprocv3.ProcessingRequest {
	request := requestHeaders(false)
	request.GetRequestHeaders().Headers.Headers = append(
		request.GetRequestHeaders().Headers.Headers,
		&corev3.HeaderValue{Key: "content-length", Value: "0"},
	)
	return request
}

func responseHeaders(eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{
		Headers:     &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}}},
		EndOfStream: eos,
	}}}
}

func requestBody(body []byte, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{RequestBody: &extprocv3.HttpBody{Body: body, EndOfStream: eos}}}
}

func responseBody(body []byte, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: body, EndOfStream: eos}}}
}

func requestTrailers() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{RequestTrailers: &extprocv3.HttpTrailers{
		Trailers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: "x-request-trailer", Value: "done"}}},
	}}}
}

func responseTrailers() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{ResponseTrailers: &extprocv3.HttpTrailers{
		Trailers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: "x-response-trailer", Value: "done"}}},
	}}}
}

func sameInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameLateActionPolicies(left, right []LateActionPolicy) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameHostActions(left, right []HostAction) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type reportedCleanupTransaction struct {
	*recordingTransaction
	err error
}

func (tx *reportedCleanupTransaction) CleanupFailure() error { return tx.err }
func TestStreamCloseKeepsIncompleteFinishLocalAndSinkFailureFatal(t *testing.T) {
	for _, mode := range []string{"sink", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			testStreamCloseFailureClassification(t, mode)
		})
	}
}

func testStreamCloseFailureClassification(t *testing.T, mode string) {
	t.Helper()
	first := errors.New("mandatory event sink failure")
	if mode == "incomplete" {
		first = fmt.Errorf("%w: incomplete body", ErrTransactionFinishPhaseSequence)
	}
	tx := &reportedCleanupTransaction{recordingTransaction: &recordingTransaction{}, err: first}
	state := newStreamState(testConfig(LateActionSafe), nil, discardObserver{})
	state.transaction = tx
	if got := state.closeOwned(CloseContextCanceled); !errors.Is(got, first) {
		t.Fatalf("closeOwned(cancel) = %v, want %v", got, first)
	}
	if mode == "sink" && !errors.Is(state.cleanupFailure, first) {
		t.Fatalf("cleanupFailure = %v, want fatal sink cause %v", state.cleanupFailure, first)
	}
	if mode == "incomplete" && state.cleanupFailure != nil {
		t.Fatalf("cleanupFailure = %v, want no process failure for incomplete lifecycle", state.cleanupFailure)
	}
	if got := state.closeOwned(CloseContextCanceled); got != nil {
		t.Fatalf("closeOwned(retry) = %v, want no duplicate work", got)
	}
	if len(tx.closed) != 1 {
		t.Fatalf("closeOwned(retry) close calls = %d, want 1", len(tx.closed))
	}
}

type cleanupEvidenceFailureObserver struct{ err error }

func (observer cleanupEvidenceFailureObserver) Record(Summary) error { return observer.err }
func TestStreamCloseMetadataSinkFailureRemainsFatalAfterIncompleteFinish(t *testing.T) {
	first := fmt.Errorf("%w: incomplete body", ErrTransactionFinishPhaseSequence)
	sinkErr := errors.New("metadata physical write failure")
	tx := &reportedCleanupTransaction{recordingTransaction: &recordingTransaction{}, err: first}
	state := newStreamState(testConfig(LateActionSafe), nil, cleanupEvidenceFailureObserver{err: sinkErr})
	state.transaction = tx
	got := state.closeOwned(CloseContextCanceled)
	if !errors.Is(got, first) || !errors.Is(got, sinkErr) {
		t.Fatalf("closeOwned(cancel) = %v, want both first finish and sink cause", got)
	}
	if state.cleanupFailure != got {
		t.Fatalf("cleanupFailure = %v, want fatal combined cause %v", state.cleanupFailure, got)
	}
}
