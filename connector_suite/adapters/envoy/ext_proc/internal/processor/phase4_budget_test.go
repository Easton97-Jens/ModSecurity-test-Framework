package processor

import (
	"math"
	"testing"
)

func TestConnectorResponseInspectionHasNoCumulativeBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		direction Direction
		current   int64
		chunk     int
		want      Action
	}{
		{"response-past-former-budget", DirectionResponse, 10485760, 1, ActionAllow},
		{"response-chunk-bound", DirectionResponse, 0, 17, ActionDeny},
		{"request-no-cumulative-bound", DirectionRequest, 8, 1, ActionAllow},
		{"response-accounting-overflow", DirectionResponse, math.MaxInt64, 1, ActionDeny},
		{"negative-length", DirectionResponse, 0, -1, ActionDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &streamState{config: Config{MaxBodyChunkBytes: 16}, engine: PassthroughEngine{}, summary: Summary{RequestBodyBytes: tc.current, ResponseBodyBytes: tc.current}}
			if got := state.bodyLimitDecision(tc.direction, tc.chunk); got.Action != tc.want {
				t.Fatalf("action=%s want=%s", got.Action, tc.want)
			}
		})
	}
}
