package composite_middleware

import (
	"errors"
	"io"
	"testing"
)

func TestDecisionWriteFailureDoesNotAcknowledgeHostOutcome(t *testing.T) {
	for _, want := range []error{io.ErrShortWrite, errors.New("host write failed")} {
		t.Run(want.Error(), func(t *testing.T) {
			host := &failingResponseWriter{}
			if !errors.Is(want, io.ErrShortWrite) {
				host.err = want
			}
			rw := &responseWriter{writer: host}
			rw.writeDecision(result{decision: decisionDeny, status: 403})
			if !errors.Is(rw.transportErr, want) || rw.outcomeAction != 0 || !rw.committed {
				t.Fatalf("write failure acknowledged: err=%v action=%d committed=%v", rw.transportErr, rw.outcomeAction, rw.committed)
			}
		})
	}
}
