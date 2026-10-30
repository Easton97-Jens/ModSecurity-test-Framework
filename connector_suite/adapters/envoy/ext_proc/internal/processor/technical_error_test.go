package processor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestI10IncompleteResponseEOFIsTerminal(t *testing.T) {
	for _, policy := range []LateActionPolicy{LateActionOff, LateActionSafe} {
		for _, canceled := range []bool{false, true} {
			for _, bodyStarted := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/body=%t/canceled=%t", policy, bodyStarted, canceled), func(t *testing.T) {
					assertIncompleteResponseIsTerminal(t, policy, canceled, bodyStarted)
				})
			}
		}
	}
}

func assertIncompleteResponseIsTerminal(t *testing.T, policy LateActionPolicy, canceled, bodyStarted bool) {
	t.Helper()
	transaction := &recordingTransaction{}
	service := newTestService(t, transaction, policy)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeProcessStream{contextFactory: testStreamContext(ctx), cancel: cancel, receive: []receiveResult{
		{request: requestHeaders(true)}, {request: responseHeaders(false)},
	}}
	if bodyStarted {
		stream.receive = append(stream.receive, receiveResult{request: responseBody([]byte("partial"), false)})
	}
	stream.receive = append(stream.receive, receiveResult{err: io.EOF, cancel: canceled})
	if err := service.Process(stream); err == nil {
		t.Fatal("incomplete committed response returned success")
	}
	for _, reply := range stream.sent {
		if reply.GetImmediateResponse() != nil {
			t.Fatal("second response after response commit")
		}
	}
	wantReason := ClosePeerEOF
	if canceled {
		wantReason = CloseContextCanceled
	}
	if len(transaction.closed) != 1 || transaction.closed[0].CloseReason != wantReason {
		t.Fatal("missing once-only cleanup preserving interruption cause")
	}
}

type finishFailureTransaction struct{ recordingTransaction }

func (*finishFailureTransaction) CleanupFailure() error {
	return errors.New("controlled Common finish acknowledgement failure")
}

type finishFailureOpener struct{ tx *finishFailureTransaction }

func (o finishFailureOpener) Open(context.Context, StreamMetadata) (Transaction, error) {
	return o.tx, nil
}

func TestI10FinishFailurePropagatesAfterResponseEOS(t *testing.T) {
	for _, policy := range []LateActionPolicy{LateActionOff, LateActionSafe} {
		t.Run(string(policy), func(t *testing.T) {
			tx := &finishFailureTransaction{}
			service := newTestServiceWithStreamLimit(t, finishFailureOpener{tx}, policy, 1)
			stream := &fakeProcessStream{contextFactory: testStreamContext(context.Background()), receive: []receiveResult{
				{request: requestHeaders(true)}, {request: responseHeaders(true)},
			}}
			if err := service.Process(stream); err == nil {
				t.Fatal("failed finalization returned success")
			}
			if len(stream.sent) != 2 || stream.sent[1].GetResponseHeaders() == nil || len(tx.closed) != 1 {
				t.Fatal("failed cleanup fabricated a replacement response or repeated close")
			}
		})
	}
}
