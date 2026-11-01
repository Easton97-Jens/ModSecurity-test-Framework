package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	processor "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type upstreamServer struct {
	processor.UnimplementedExternalProcessorServer
	handle func(processor.ExternalProcessor_ProcessServer) error
}

func (server *upstreamServer) Process(stream processor.ExternalProcessor_ProcessServer) error {
	return server.handle(stream)
}

func testConnection(t *testing.T, service processor.ExternalProcessorServer) (*grpc.ClientConn, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.WaitForHandlers(true))
	processor.RegisterExternalProcessorServer(server, service)
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	options := append(upstreamOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	conn, err := grpc.NewClient("passthrough:///bufnet", options...)
	if err != nil {
		t.Fatalf("NewClient(bufconn) = %v, want nil", err)
	}
	stop := func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close(client) = %v, want nil", err)
		}
		server.Stop()
		if err := <-finished; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("Serve(bufconn) = %v, want nil or server stopped", err)
		}
		if err := listener.Close(); err != nil {
			t.Errorf("Close(listener) = %v, want nil", err)
		}
	}
	return conn, stop
}

func testProxy(t *testing.T, upstream processor.ExternalProcessorServer, mode string) (processor.ExternalProcessorClient, *faultProxy, *bytes.Buffer) {
	t.Helper()
	conn, stopUpstream := testConnection(t, upstream)
	output := &bytes.Buffer{}
	proxy := &faultProxy{client: processor.NewExternalProcessorClient(conn), mode: mode, selectID: "selected", timeout: 5 * time.Second, log: newEventLog(output)}
	downstream, stopDownstream := testConnection(t, proxy)
	t.Cleanup(func() {
		stopDownstream()
		stopUpstream()
		proxy.workers.Wait()
	})
	return processor.NewExternalProcessorClient(downstream), proxy, output
}

func headerRequest(identity string) *processor.ProcessingRequest {
	return &processor.ProcessingRequest{Request: &processor.ProcessingRequest_RequestHeaders{RequestHeaders: &processor.HttpHeaders{
		Headers: &core.HeaderMap{Headers: []*core.HeaderValue{{Key: "x-request-id", RawValue: []byte(identity)}}},
	}}}
}

func bodyRequest(body string, eos bool) *processor.ProcessingRequest {
	return &processor.ProcessingRequest{Request: &processor.ProcessingRequest_ResponseBody{ResponseBody: &processor.HttpBody{Body: []byte(body), EndOfStream: eos}}}
}

func actualResponse() *processor.ProcessingResponse {
	return &processor.ProcessingResponse{Response: &processor.ProcessingResponse_ResponseBody{ResponseBody: &processor.BodyResponse{
		Response: &processor.CommonResponse{Status: processor.CommonResponse_CONTINUE},
	}}}
}

type observedStream struct {
	identity string
	requests []*processor.ProcessingRequest
}

func (observed *observedStream) record(request *processor.ProcessingRequest) {
	if identity := requestIdentity(request); identity != "" {
		observed.identity = identity
	}
	observed.requests = append(observed.requests, request)
}

func collectingUpstream(results chan<- observedStream, terminal error) *upstreamServer {
	return &upstreamServer{handle: func(stream processor.ExternalProcessor_ProcessServer) error {
		if err := stream.SendHeader(metadata.Pairs("actual-upstream-header", "preserved")); err != nil {
			return err
		}
		var observed observedStream
		for {
			request, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				stream.SetTrailer(metadata.Pairs("actual-upstream-trailer", "preserved"))
				results <- observed
				return terminal
			}
			if err != nil {
				return err
			}
			observed.record(request)
			if err := stream.Send(actualResponse()); err != nil {
				return err
			}
		}
	}}
}

func exchange(t *testing.T, client processor.ExternalProcessorClient, identity string) ([]*processor.ProcessingResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("Process(%s) = %v, want nil", identity, err)
	}
	for _, request := range []*processor.ProcessingRequest{headerRequest(identity), bodyRequest("first", false), bodyRequest("", true)} {
		if err := stream.Send(request); err != nil {
			t.Fatalf("Send(%s) = %v, want nil", identity, err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend(%s) = %v, want nil", identity, err)
	}
	var responses []*processor.ProcessingResponse
	for {
		response, recvErr := stream.Recv()
		if recvErr != nil {
			headers, headerErr := stream.Header()
			if headerErr != nil || len(headers.Get("actual-upstream-header")) != 1 || len(stream.Trailer().Get("actual-upstream-trailer")) != 1 {
				t.Errorf("Metadata(%s) = headers %v / trailers %v / error %v, want actual upstream metadata", identity, headers, stream.Trailer(), headerErr)
			}
			return responses, recvErr
		}
		responses = append(responses, response)
	}
}

func readEvents(t *testing.T, proxy *faultProxy, output *bytes.Buffer) []map[string]any {
	t.Helper()
	proxy.log.mu.Lock()
	defer proxy.log.mu.Unlock()
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	var events []map[string]any
	for {
		var event map[string]any
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			return events
		} else if err != nil {
			t.Fatalf("Decode(proxy events) = %v, want nil", err)
		}
		events = append(events, event)
	}
}

func TestProxyDropsOnlyFirstSelectedEOSAndPreservesNeighbor(t *testing.T) {
	t.Parallel()
	results := make(chan observedStream, 2) // Exactly two real RPCs report one terminal inventory each.
	client, proxy, output := testProxy(t, collectingUpstream(results, nil), dropMode)
	selected, err := exchange(t, client, "selected")
	if !errors.Is(err, io.EOF) || len(selected) != 2 {
		t.Fatalf("exchange(selected) = %d responses / %v, want 2 actual responses / EOF", len(selected), err)
	}
	neighbor, err := exchange(t, client, "neighbor")
	if !errors.Is(err, io.EOF) || len(neighbor) != 3 {
		t.Fatalf("exchange(neighbor) = %d responses / %v, want 3 actual responses / EOF", len(neighbor), err)
	}
	assertObservedRequests(t, results)
	assertSelectedEOSDrop(t, readEvents(t, proxy, output))
	for _, response := range append(selected, neighbor...) {
		if !proto.Equal(response, actualResponse()) {
			t.Errorf("forwarded response = %v, want actual unchanged upstream response", response)
		}
	}
}

func assertObservedRequests(t *testing.T, results <-chan observedStream) {
	t.Helper()
	for range 2 {
		observed := <-results
		want := []*processor.ProcessingRequest{headerRequest(observed.identity), bodyRequest("first", false), bodyRequest("", true)}
		if observed.identity == "selected" {
			want = want[:2]
		}
		if len(observed.requests) != len(want) {
			t.Fatalf("upstream(%s) = %d messages, want %d", observed.identity, len(observed.requests), len(want))
		}
		for index := range want {
			if !proto.Equal(observed.requests[index], want[index]) {
				t.Errorf("upstream(%s, %d) = %v, want %v", observed.identity, index, observed.requests[index], want[index])
			}
		}
	}
}

func assertSelectedEOSDrop(t *testing.T, events []map[string]any) {
	t.Helper()

	drops := 0
	for _, event := range events {
		if event["direction"] == "dropped_before_upstream_send" {
			drops++
			if event["request_id"] != "selected" || event["eos"] != true || event["body_bytes"] != float64(0) {
				t.Errorf("drop event = %v, want selected empty EOS", event)
			}
		}
		if event["event"] == "upstream_recv_end" && event["wire_grpc_status"] != nil {
			t.Errorf("wire status = %v, want null for API-only observation", event)
		}
	}
	if drops != 1 {
		t.Errorf("drop count = %d, want 1", drops)
	}
}

func TestProxyPassthroughPreservesAllMessagesAndActualError(t *testing.T) {
	t.Parallel()
	results := make(chan observedStream, 1)
	client, _, _ := testProxy(t, collectingUpstream(results, status.Error(codes.InvalidArgument, "actual upstream failure")), passMode)
	responses, err := exchange(t, client, "selected")
	if status.Code(err) != codes.InvalidArgument || len(responses) != 3 {
		t.Errorf("exchange(passthrough) = %d responses / %v, want 3 / InvalidArgument", len(responses), err)
	}
	observed := <-results
	if len(observed.requests) != 3 || !observed.requests[2].GetResponseBody().GetEndOfStream() {
		t.Errorf("upstream(passthrough) = %v, want all 3 requests including EOS", observed)
	}
}

func TestProxyDroppedEOSHalfClosesUpstreamAndForwardsActualUnavailable(t *testing.T) {
	t.Parallel()
	results := make(chan observedStream, 1)
	client, proxy, output := testProxy(t, collectingUpstream(results, status.Error(codes.Unavailable, "actual peer EOF before callback")), dropMode)
	responses, err := exchange(t, client, "selected")
	if status.Code(err) != codes.Unavailable || len(responses) != 2 {
		t.Fatalf("exchange(drop EOS) = %d / %v, want 2 / actual Unavailable", len(responses), err)
	}
	if observed := <-results; len(observed.requests) != 2 {
		t.Errorf("upstream after half-close = %d messages, want headers + unchanged body", len(observed.requests))
	}
	halfClosed, actualStatus := false, false
	for _, event := range readEvents(t, proxy, output) {
		switch event["event"] {
		case "upstream_close_send_return":
			halfClosed = event["close_send_error_nil"] == true && event["grpc_api_code"] == nil
		case "upstream_recv_end":
			actualStatus = event["grpc_api_code"] == float64(codes.Unavailable) && event["recv_eof"] == false
		}
	}
	if !halfClosed || !actualStatus {
		t.Errorf("drop EOS evidence = halfclose %v / actualstatus %v, want both true", halfClosed, actualStatus)
	}
}

func TestProxyDirectionEOFDoesNotInventRPCSuccess(t *testing.T) {
	t.Parallel()
	if fields := terminalFields(io.EOF); fields["grpc_api_code"] != nil || fields["wire_grpc_status"] != nil {
		t.Errorf("terminalFields(direction EOF) = %v, want unknown status", fields)
	}
}

func TestProxyAttemptGuardCancelsBeforeTransparentReplay(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := &bytes.Buffer{}
	state := &attemptState{log: &streamLog{log: newEventLog(output), id: 1}, cancel: cancel}
	ctx = context.WithValue(ctx, attemptKey{}, state)
	guard := attemptGuard{}
	guard.HandleRPC(ctx, &stats.Begin{})
	if ctx.Err() != nil {
		t.Error("first attempt was canceled")
	}
	guard.HandleRPC(ctx, &stats.Begin{IsTransparentRetryAttempt: true})
	if !errors.Is(ctx.Err(), context.Canceled) || state.count.Load() != 2 {
		t.Errorf("retry guard = %v / %d, want Canceled / 2 observed attempts", ctx.Err(), state.count.Load())
	}
}

func TestProxyStopBeforeServeJoinsAndReturnsZero(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	proxy := &faultProxy{}
	listener := bufconn.Listen(1 << 20)
	if err := serve(ctx, proxy, listener); err != nil {
		t.Errorf("serve(canceled) = %v, want nil after joined shutdown", err)
	}
}

func TestProxyRefusesToDropBodyBearingTerminalFrame(t *testing.T) {
	t.Parallel()
	upstreamEnd := make(chan error, 1)
	upstream := &upstreamServer{handle: func(stream processor.ExternalProcessor_ProcessServer) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(actualResponse()); err != nil {
			return err
		}
		_, err := stream.Recv()
		upstreamEnd <- err
		return err
	}}
	client, proxy, output := testProxy(t, upstream, dropMode)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(headerRequest("selected")); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(bodyRequest("must-not-disappear", true)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("Recv(body-bearing EOS) = %v, want FailedPrecondition", err)
	}
	select {
	case err := <-upstreamEnd:
		if err == nil {
			t.Error("upstream received a refused terminal frame")
		}
	case <-ctx.Done():
		t.Fatal("refused injection did not cancel upstream")
	}
	refused := 0
	for _, event := range readEvents(t, proxy, output) {
		if event["direction"] == "injection_refused_nonempty_terminal_body" {
			refused++
		}
		if event["direction"] == "dropped_before_upstream_send" {
			t.Error("body-bearing refusal falsely recorded an EOS-only drop")
		}
	}
	if refused != 1 {
		t.Errorf("refusal events = %d, want 1", refused)
	}
}

func TestProxyCancellationReachesActualUpstream(t *testing.T) {
	t.Parallel()
	entered, canceled := make(chan struct{}), make(chan struct{})
	upstream := &upstreamServer{handle: func(stream processor.ExternalProcessor_ProcessServer) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		close(entered)
		<-stream.Context().Done()
		close(canceled)
		return status.FromContextError(stream.Context().Err()).Err()
	}}
	client, _, _ := testProxy(t, upstream, passMode)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(headerRequest("selected")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("actual upstream did not receive selected request")
	}
	cancel()
	if _, err := stream.Recv(); status.Code(err) != codes.Canceled {
		t.Errorf("Recv(canceled) = %v, want Canceled", err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not reach actual upstream")
	}
}

func TestProxyUpstreamEOFFinishesWithoutClientHalfClose(t *testing.T) {
	t.Parallel()
	upstream := &upstreamServer{handle: func(stream processor.ExternalProcessor_ProcessServer) error {
		_, err := stream.Recv()
		return err
	}}
	client, proxy, _ := testProxy(t, upstream, passMode)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(headerRequest("selected")); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("Recv(upstream EOF) = %v, want EOF", err)
	}
	joined := make(chan struct{})
	go func() { proxy.workers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-ctx.Done():
		t.Fatal("proxy receive pumps did not exit after handler returned")
	}
}

func TestProxyRejectsPublicListenersAndUnsafeSelection(t *testing.T) {
	t.Parallel()
	const targetFlag = "--target"
	for _, address := range []string{"0.0.0.0:18084", "localhost:18084", "127.0.0.2:18084", "127.0.0.1:1", "[::]:18084"} {
		if validAddress(address) {
			t.Errorf("validAddress(%q) = true, want false", address)
		}
	}
	for _, args := range [][]string{{"--listen", "0.0.0.0:18084"}, {targetFlag, "contains\nnewline"}, {targetFlag, "selected", "--events", "/etc/passwd"}, {targetFlag, "selected", "--stream-timeout", "0s"}} {
		if err := run(t.Context(), args, io.Discard); err == nil {
			t.Errorf("run(%q) = nil, want validation rejection", args)
		}
	}
	if requestIdentity(headerRequest(strings.Repeat("x", 129))) != "" {
		t.Error("requestIdentity(overlong) accepted a value outside the selection contract")
	}
}
