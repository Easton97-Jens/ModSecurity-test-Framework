package compositeenvoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

type requestFaultOpener struct {
	stage string
	tx    *requestFaultTransaction
}

func (o *requestFaultOpener) Open(context.Context, processor.StreamMetadata) (processor.Transaction, error) {
	o.tx = &requestFaultTransaction{stage: o.stage}
	return o.tx, nil
}

type requestFaultTransaction struct {
	stage                          string
	headers, body, closed, actions int
}

func (t *requestFaultTransaction) ProcessHeaders(context.Context, processor.Direction, []processor.Header, bool) (processor.Decision, error) {
	t.headers++
	if t.stage == "p1" {
		return processor.Decision{Action: processor.ActionDeny, Status: 403}, errors.New("invalid engine response")
	}
	return processor.Decision{Action: processor.ActionAllow}, nil
}

func (t *requestFaultTransaction) ProcessBody(context.Context, processor.Direction, []byte, bool) (processor.Decision, error) {
	t.body++
	return processor.Decision{Action: processor.ActionDeny, Status: 403}, errors.New("engine timeout")
}

func (t *requestFaultTransaction) Close(context.Context, processor.Summary) { t.closed++ }
func (t *requestFaultTransaction) RecordHostAction(context.Context, processor.HostAction) error {
	t.actions++
	return nil
}

func TestI10AuthzTechnicalFailureCannotBecomeAllowOrStaleRule(t *testing.T) {
	for _, stage := range []string{"p1", "p2"} {
		t.Run(stage, func(t *testing.T) {
			assertAuthzTechnicalFailureRemainsTerminal(t, stage)
		})
	}
}

func TestI10CompanionPostCommitProtocolFailureStopsWithoutSecondResponse(t *testing.T) {
	server, opener, _, lease := newProcessFixture(t, processor.ActionAllow, 200)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		initialResponseHeaders(lease, "200", false),
		initialResponseHeaders(lease, "200", false),
		{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{EndOfStream: true}}},
	}}
	if err := server.Process(stream); err == nil {
		t.Fatal("postcommit protocol failure returned success")
	}
	if len(stream.responses) != 1 || stream.responses[0].GetResponseHeaders() == nil {
		t.Fatalf("second response after commit: %v", stream.responses)
	}
	if len(stream.requests) != 1 || opener.tx.commits != 1 || len(opener.tx.actions) != 0 {
		t.Fatal("failed callback continued processing or fabricated host action")
	}
}

func TestI10CompanionHeaderEOSStopsBeforeReenteredBody(t *testing.T) {
	server, _, _, lease := newProcessFixture(t, processor.ActionAllow, 200)
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		initialResponseHeaders(lease, "200", true),
		{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{EndOfStream: true}}},
	}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || len(stream.requests) != 1 {
		t.Fatalf("terminal header callback reentered: responses=%v remaining=%d", stream.responses, len(stream.requests))
	}
}

func TestI10CompanionPrecommitTechnicalReplyStopsBeforeReentry(t *testing.T) {
	server, _, _, lease := newProcessFixture(t, processor.ActionAllow, 200)
	first := initialResponseHeaders(lease, "200", false)
	first.GetResponseHeaders().Headers = nil
	stream := &processStream{requests: []*extprocv3.ProcessingRequest{
		first, initialResponseHeaders(lease, "200", false),
	}}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 1 || stream.responses[0].GetImmediateResponse() == nil || len(stream.requests) != 1 {
		t.Fatalf("precommit terminal error retried: responses=%v remaining=%d", stream.responses, len(stream.requests))
	}
}

type interruptedProcessStream struct {
	processStream
	err error
}

func (s *interruptedProcessStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if len(s.requests) == 0 {
		return nil, s.err
	}
	return s.processStream.Recv()
}

func TestI10CompanionMissingEOSAndCancelAreTerminalErrors(t *testing.T) {
	for _, recvErr := range []error{io.EOF, context.Canceled} {
		for _, bodyStarted := range []bool{false, true} {
			t.Run(recvErr.Error()+"/body="+fmt.Sprint(bodyStarted), func(t *testing.T) {
				assertCompanionInterruptionIsTerminal(t, recvErr, bodyStarted)
			})
		}
	}
}

func assertCompanionInterruptionIsTerminal(t *testing.T, recvErr error, bodyStarted bool) {
	t.Helper()
	server, opener, _, lease := newProcessFixture(t, processor.ActionAllow, 200)
	stream := &interruptedProcessStream{err: recvErr}
	stream.requests = []*extprocv3.ProcessingRequest{initialResponseHeaders(lease, "200", false)}
	if bodyStarted {
		stream.requests = append(stream.requests, &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("partial")}}})
	}
	if err := server.Process(stream); err == nil {
		t.Fatal("incomplete response stream returned success")
	}
	wantResponses := 1
	if bodyStarted {
		wantResponses++
	}
	if len(stream.responses) != wantResponses || opener.tx.commits != 1 || len(opener.tx.actions) != 0 {
		t.Fatal("interruption fabricated a second response or an observed action")
	}
}

func assertAuthzTechnicalFailureRemainsTerminal(t *testing.T, stage string) {
	t.Helper()
	opener := &requestFaultOpener{stage: stage}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 2}, opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Check(context.Background(), authCheckRequest([]byte("body")))
	if err == nil || response != nil {
		t.Fatalf("technical failure became successful authz response: response=%v error=%v", response, err)
	}
	if opener.tx.actions != 0 || opener.tx.headers != 1 || opener.tx.closed != 1 {
		t.Fatalf("callbacks/actions/cleanup: %+v", opener.tx)
	}
	if stage == "p1" && opener.tx.body != 0 {
		t.Fatal("P1 failure reached P2")
	}
}
