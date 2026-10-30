// fault_proxy is a private I12 test transport, not a connector implementation.
// It forwards actual ext_proc messages and can omit one selected response EOS.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	processor "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	passMode           = "passthrough"
	dropMode           = "drop-response-eos"
	eventOutputFailure = "proxy event output failed"
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type eventLog struct {
	mu      sync.Mutex
	encoder *json.Encoder
	started time.Time
}

func newEventLog(writer io.Writer) *eventLog {
	return &eventLog{encoder: json.NewEncoder(writer), started: time.Now()}
}

func (log *eventLog) emit(value map[string]any) error {
	log.mu.Lock()
	defer log.mu.Unlock()
	value["wall_ns"] = time.Now().UnixNano()
	value["elapsed_ns"] = time.Since(log.started).Nanoseconds()
	return log.encoder.Encode(value)
}

type streamLog struct {
	mu        sync.Mutex
	log       *eventLog
	id        uint64
	sequence  uint64
	requestID string
	dropped   bool
}

func digest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func (stream *streamLog) emit(event string, fields map[string]any) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.sequence++
	fields["event"] = event
	fields["stream_id"] = stream.id
	fields["sequence"] = stream.sequence
	fields["request_id"] = stream.requestID
	return stream.log.emit(fields)
}

func requestIdentity(request *processor.ProcessingRequest) string {
	count, identity := 0, ""
	for _, header := range request.GetRequestHeaders().GetHeaders().GetHeaders() {
		if header.GetKey() != "x-request-id" {
			continue
		}
		count++
		identity = header.GetValue()
		if len(header.GetRawValue()) != 0 {
			identity = string(header.GetRawValue())
		}
	}
	if count != 1 || !safeID.MatchString(identity) {
		return ""
	}
	return identity
}

func (stream *streamLog) inspect(request *processor.ProcessingRequest, mode, selected string) (bool, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if request.GetRequestHeaders() != nil {
		stream.requestID = requestIdentity(request)
	}
	if mode != dropMode || stream.requestID != selected || stream.dropped {
		return false, nil
	}
	if body := request.GetResponseBody(); body != nil && body.GetEndOfStream() {
		if len(body.GetBody()) != 0 {
			return false, status.Error(codes.FailedPrecondition, "selected terminal frame contains body bytes; EOS-only injection refused")
		}
		stream.dropped = true
		return true, nil
	}
	return false, nil
}

func requestFields(request *processor.ProcessingRequest) map[string]any {
	fields := map[string]any{"message_type": fmt.Sprintf("%T", request.GetRequest())}
	var body *processor.HttpBody
	switch {
	case request.GetRequestBody() != nil:
		body = request.GetRequestBody()
	case request.GetResponseBody() != nil:
		body = request.GetResponseBody()
	case request.GetRequestHeaders() != nil:
		fields["eos"] = request.GetRequestHeaders().GetEndOfStream()
	case request.GetResponseHeaders() != nil:
		fields["eos"] = request.GetResponseHeaders().GetEndOfStream()
	}
	if body != nil {
		fields["body_bytes"] = len(body.GetBody())
		fields["body_sha256"] = digest(body.GetBody())
		fields["eos"] = body.GetEndOfStream()
	}
	return fields
}

func messageFields(message proto.Message) (map[string]any, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"message_bytes": len(encoded), "message_sha256": digest(encoded)}, nil
}

func (stream *streamLog) message(direction string, message proto.Message) error {
	fields, err := messageFields(message)
	if err != nil {
		return status.Error(codes.Internal, "proxy message measurement failed")
	}
	fields["direction"] = direction
	if request, ok := message.(*processor.ProcessingRequest); ok {
		for name, value := range requestFields(request) {
			fields[name] = value
		}
	}
	if err := stream.emit("message", fields); err != nil {
		return status.Error(codes.Internal, eventOutputFailure)
	}
	return nil
}

func metadataFields(values metadata.MD) map[string]any {
	fields := make(map[string]any, len(values))
	for name, entries := range values {
		encoded, _ := json.Marshal(entries) // A []string has no JSON error case.
		fields[name] = map[string]any{"values": len(entries), "bytes": len(encoded), "sha256": digest(encoded)}
	}
	return fields
}

func terminalFields(err error) map[string]any {
	fields := map[string]any{"recv_eof": errors.Is(err, io.EOF), "wire_grpc_status": nil}
	if errors.Is(err, io.EOF) {
		// EOF is direction-dependent: only actual client Recv owns RPC status.
		fields["grpc_api_code"] = nil
		return fields
	}
	fields["grpc_api_code"] = int(status.Code(err))
	if err != nil {
		fields["error_sha256"] = digest([]byte(err.Error()))
	}
	return fields
}

type faultProxy struct {
	processor.UnimplementedExternalProcessorServer
	client   processor.ExternalProcessorClient
	mode     string
	selectID string
	timeout  time.Duration
	log      *eventLog
	ids      atomic.Uint64
	workers  sync.WaitGroup
	injected atomic.Bool
}

type attemptKey struct{}

type attemptState struct {
	log    *streamLog
	cancel context.CancelFunc
	count  atomic.Uint64
}

type attemptGuard struct{}

func (attemptGuard) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (attemptGuard) HandleRPC(ctx context.Context, observation stats.RPCStats) {
	state, ok := ctx.Value(attemptKey{}).(*attemptState)
	if !ok {
		return
	}
	switch observation := observation.(type) {
	case *stats.Begin:
		count := state.count.Add(1)
		err := state.log.emit("upstream_attempt_begin", map[string]any{"attempt": count, "transparent_retry": observation.IsTransparentRetryAttempt})
		if count > 1 || err != nil {
			// grpc emits Begin before selecting transport for this attempt.
			// Cancellation refuses transparent retries before any replayed bytes.
			state.cancel()
		}
	case *stats.End:
		if err := state.log.emit("upstream_attempt_end", terminalFields(observation.Error)); err != nil {
			state.cancel()
		}
	}
}

func (attemptGuard) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (attemptGuard) HandleConn(context.Context, stats.ConnStats) {
	// Connection observations do not describe RPC attempts; HandleRPC owns them.
}

func upstreamOptions() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry(),
		grpc.WithDisableServiceConfig(), grpc.WithStatsHandler(attemptGuard{}),
		grpc.WithDefaultCallOptions(grpc.MaxRetryRPCBufferSize(0))}
}

func (proxy *faultProxy) forwardRequests(down processor.ExternalProcessor_ProcessServer, up processor.ExternalProcessor_ProcessClient, log *streamLog) error {
	for {
		request, err := down.Recv()
		if err != nil {
			return finishRequests(up, log, err)
		}
		if err := proxy.forwardRequest(up, log, request); err != nil {
			if errors.Is(err, io.EOF) {
				// Send EOF is not the remote status; the receive pump owns it.
				return nil
			}
			return err
		}
	}
}

func finishRequests(up processor.ExternalProcessor_ProcessClient, log *streamLog, err error) error {
	fields := terminalFields(err)
	fields["request_half_close"] = errors.Is(err, io.EOF)
	if log.emit("downstream_recv_end", fields) != nil {
		return status.Error(codes.Internal, eventOutputFailure)
	}
	if errors.Is(err, io.EOF) {
		return up.CloseSend()
	}
	return err
}

func (proxy *faultProxy) forwardRequest(up processor.ExternalProcessor_ProcessClient, log *streamLog, request *processor.ProcessingRequest) error {
	mode := proxy.mode
	if proxy.injected.Load() {
		mode = passMode
	}
	drop, injectionErr := log.inspect(request, mode, proxy.selectID)
	if drop && !proxy.injected.CompareAndSwap(false, true) {
		drop = false
	}
	if err := log.message("downstream_receive", request); err != nil {
		return err
	}
	if injectionErr != nil {
		if err := log.message("injection_refused_nonempty_terminal_body", request); err != nil {
			return err
		}
		return injectionErr
	}
	if drop {
		if err := log.message("dropped_before_upstream_send", request); err != nil {
			return err
		}
		return halfCloseAfterDrop(up, log)
	}
	if err := up.Send(request); err != nil {
		if log.emit("upstream_send_end", terminalFields(err)) != nil {
			return status.Error(codes.Internal, eventOutputFailure)
		}
		return err
	}
	return log.message("upstream_send", request)
}

func halfCloseAfterDrop(up processor.ExternalProcessor_ProcessClient, log *streamLog) error {
	err := up.CloseSend()
	fields := terminalFields(err)
	fields["grpc_api_code"] = nil
	fields["close_send_error_nil"] = err == nil
	if log.emit("upstream_close_send_return", fields) != nil {
		return status.Error(codes.Internal, eventOutputFailure)
	}
	if err != nil {
		return err
	}
	// Local pump control only. The receive pump still owns the actual status.
	// There is no later Send on this half-closed upstream request direction.
	return io.EOF
}

func (proxy *faultProxy) forwardResponses(down processor.ExternalProcessor_ProcessServer, up processor.ExternalProcessor_ProcessClient, log *streamLog) error {
	response, recvErr := up.Recv()
	if err := forwardHeaders(down, up, log); err != nil {
		return err
	}
	for {
		if recvErr != nil {
			return finishResponses(down, up, log, recvErr)
		}
		if err := forwardResponse(down, log, response); err != nil {
			return err
		}
		response, recvErr = up.Recv()
	}
}

func finishResponses(down processor.ExternalProcessor_ProcessServer, up processor.ExternalProcessor_ProcessClient, log *streamLog, err error) error {
	trailers := up.Trailer()
	down.SetTrailer(trailers)
	fields := terminalFields(err)
	if errors.Is(err, io.EOF) {
		fields["grpc_api_code"] = int(codes.OK) // Actual client Recv result, not wire trailer measurement.
	}
	fields["trailers"] = metadataFields(trailers)
	if log.emit("upstream_recv_end", fields) != nil {
		return status.Error(codes.Internal, eventOutputFailure)
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func forwardResponse(down processor.ExternalProcessor_ProcessServer, log *streamLog, response *processor.ProcessingResponse) error {
	if err := log.message("upstream_receive", response); err != nil {
		return err
	}
	if err := down.Send(response); err != nil {
		return err
	}
	return log.message("downstream_send", response)
}
func forwardHeaders(down processor.ExternalProcessor_ProcessServer, up processor.ExternalProcessor_ProcessClient, log *streamLog) error {
	headers, err := up.Header()
	if err != nil {
		// Recv owns the actual upstream terminal status, even without headers.
		return nil
	}
	if err := log.emit("upstream_headers", map[string]any{"metadata": metadataFields(headers)}); err != nil {
		return status.Error(codes.Internal, eventOutputFailure)
	}
	return down.SendHeader(headers)
}

func (proxy *faultProxy) Process(down processor.ExternalProcessor_ProcessServer) (result error) {
	log := &streamLog{log: proxy.log, id: proxy.ids.Add(1)}
	cause := "upstream_open"
	defer func() {
		fields := terminalFields(result)
		fields["return_source"] = cause
		if err := log.emit("downstream_return", fields); err != nil {
			result = status.Error(codes.Internal, eventOutputFailure)
		}
	}()
	ctx, cancel := context.WithTimeout(down.Context(), proxy.timeout)
	defer cancel()
	ctx = context.WithValue(ctx, attemptKey{}, &attemptState{log: log, cancel: cancel})
	if values, ok := metadata.FromIncomingContext(ctx); ok {
		ctx = metadata.NewOutgoingContext(ctx, values.Copy())
	}
	up, err := proxy.client.Process(ctx)
	if err != nil {
		return err
	}
	requests, responses := make(chan error, 1), make(chan error, 1)
	// Returning this handler cancels downstream Recv; cancel stops upstream Recv.
	// The process owner waits for both pumps after grpc.Server.Stop has joined
	// handlers. No pump is fire-and-forget or waits for an invented callback.
	proxy.workers.Add(2)
	go func() {
		defer proxy.workers.Done()
		requests <- proxy.forwardRequests(down, up, log)
	}()
	go func() {
		defer proxy.workers.Done()
		responses <- proxy.forwardResponses(down, up, log)
	}()
	result, cause = awaitStream(ctx, requests, responses)
	return result
}

func awaitStream(ctx context.Context, requests, responses <-chan error) (error, string) {
	for {
		select {
		case err := <-requests:
			if err != nil {
				return err, "request_forward"
			}
			requests = nil // Half-close is not an upstream status or RPC completion.
		case err := <-responses:
			return err, "upstream_receive"
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err(), "proxy_context"
		}
	}
}

func validAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	return err == nil && host == "127.0.0.1" && (port == "18083" || port == "18084")
}

func serve(ctx context.Context, proxy *faultProxy, listener net.Listener) error {
	server := grpc.NewServer(grpc.MaxRecvMsgSize(4<<20), grpc.WaitForHandlers(true))
	processor.RegisterExternalProcessorServer(server, proxy)
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	select {
	case err := <-finished:
		server.Stop()
		proxy.workers.Wait()
		return err
	case <-ctx.Done():
		server.Stop()
		proxy.workers.Wait()
		if err := <-finished; !errors.Is(err, grpc.ErrServerStopped) {
			return err
		}
		return nil
	}
}

func run(ctx context.Context, args []string, writer io.Writer) error {
	flags := flag.NewFlagSet("i12-envoy-fault-proxy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", "127.0.0.1:18084", "private proxy listener")
	upstream := flags.String("upstream", "127.0.0.1:18083", "private native SUT listener")
	mode := flags.String("mode", passMode, "passthrough or drop-response-eos")
	selected := flags.String("target", "", "exact selected x-request-id token")
	events := flags.String("events", "", "fixed private runtime event destination; empty means stdout")
	timeout := flags.Duration("stream-timeout", 15*time.Second, "bounded upstream stream duration")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid proxy flags")
	}
	if !validAddress(*listen) || !validAddress(*upstream) || *listen == *upstream {
		return errors.New("distinct fixed private loopback addresses required")
	}
	if (*mode != passMode && *mode != dropMode) || !safeID.MatchString(*selected) || *timeout <= 0 || *timeout > 120*time.Second || flags.NArg() != 0 {
		return errors.New("valid mode, exact request-id and bounded stream-timeout required")
	}
	if *events != "" {
		output, err := openEventFile(*events)
		if err != nil {
			return err
		}
		defer output.Close()
		writer = output
	}
	conn, err := grpc.NewClient("passthrough:///"+*upstream, upstreamOptions()...)
	if err != nil {
		return err
	}
	defer conn.Close()
	listener, err := net.Listen("tcp4", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	proxy := &faultProxy{client: processor.NewExternalProcessorClient(conn), mode: *mode, selectID: *selected, timeout: *timeout, log: newEventLog(writer)}
	if err := proxy.log.emit(map[string]any{"event": "ready", "mode": *mode, "listen": *listen, "upstream": *upstream}); err != nil {
		return err
	}
	return serve(ctx, proxy, listener)
}

func openEventFile(path string) (*os.File, error) {
	if path != "/task/runtime/proxy-events.jsonl" {
		return nil, errors.New("fixed private runtime event path required")
	}
	info, err := os.Lstat("/task/runtime")
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("owned physical private runtime directory required")
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "i12 fault proxy failed:", err)
		os.Exit(1)
	}
}
