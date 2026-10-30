//go:build libmodsecurity

package compositeenvoy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type completenessOpener struct {
	engine   *processor.CommonRuntimeEngine
	opens    int
	bytes    int
	eos      int
	decision processor.Decision
}

func (o *completenessOpener) Open(ctx context.Context, metadata processor.StreamMetadata) (processor.Transaction, error) {
	o.opens++
	tx, err := o.engine.Open(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return &completenessTransaction{Transaction: tx, opener: o}, nil
}

type completenessTransaction struct {
	processor.Transaction
	opener *completenessOpener
}

func (tx *completenessTransaction) ProcessBody(ctx context.Context, direction processor.Direction, body []byte, eos bool) (processor.Decision, error) {
	tx.opener.bytes += len(body)
	if eos {
		tx.opener.eos++
	}
	decision, err := tx.Transaction.ProcessBody(ctx, direction, body, eos)
	tx.opener.decision = decision
	return decision, err
}

func (tx *completenessTransaction) RecordHostAction(ctx context.Context, action processor.HostAction) error {
	return tx.Transaction.(processor.HostActionRecorder).RecordHostAction(ctx, action)
}

func (tx *completenessTransaction) CleanupFailure() error {
	return tx.Transaction.(processor.CleanupFailureReporter).CleanupFailure()
}

type completenessEnginePolicy struct {
	mode           string
	requestLimit   int
	requestAction  string
	responseLimit  int
	responseAction string
}

func newCompletenessEngine(t *testing.T, policy completenessEnginePolicy) *processor.CommonRuntimeEngine {
	t.Helper()
	if policy.mode == "" || policy.requestLimit <= 0 || policy.requestAction == "" || policy.responseLimit <= 0 || policy.responseAction == "" {
		t.Fatal("completeness fixture requires explicit engine mode and request/response limit/action")
	}
	directory := t.TempDir()
	rulesPath := filepath.Join(directory, "rules.conf")
	rules := fmt.Sprintf(`SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit %d
SecRequestBodyLimitAction %s
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecResponseBodyLimit %d
SecResponseBodyLimitAction %s
SecAuditEngine Off
SecRule REQUEST_BODY "@contains completeness-tail-marker" "id:1200997,phase:2,deny,status:403,log,t:none"
`, policy.mode, policy.requestLimit, policy.requestLimit, policy.requestAction, policy.responseLimit, policy.responseAction)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "runtime.conf")
	config := fmt.Sprintf("enabled=on\nrules_file=%s\nrequest_body_mode=streaming\nresponse_body_mode=streaming\nphase4_mode=safe\nuse_error_log=off\nevent_path=%s\n", rulesPath, filepath.Join(directory, "events.jsonl"))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := processor.NewCommonRuntimeEngine(configPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeCommonRuntimeForTest(t, engine); err != nil {
			t.Error(err)
		}
	})
	return engine
}

func TestCheckCompletenessBoundaryWithRealCommonEngine(t *testing.T) {
	for _, mode := range []string{"On", "DetectionOnly"} {
		t.Run(mode, func(t *testing.T) {
			engine := newCompletenessEngine(t, completenessEnginePolicy{mode: mode, requestLimit: 4096, requestAction: "Reject", responseLimit: 8192, responseAction: "Reject"})
			for _, partial := range []bool{true, false} {
				for _, size := range []int{1, 256} {
					t.Run(fmt.Sprintf("partial=%t/size=%d", partial, size), func(t *testing.T) {
						runCompletenessBoundaryCase(t, engine, mode, partial, size)
					})
				}
			}
		})
	}
}

func runCompletenessBoundaryCase(t *testing.T, engine *processor.CommonRuntimeEngine, mode string, partial bool, size int) {
	t.Helper()
	opener := &completenessOpener{engine: engine}
	observer := &recordedLifecycleEvents{}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{Capacity: 1}, opener, observer)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("a", size) + "completeness-tail-marker")
	request := authCheckRequest(body)
	marker := "false"
	if partial {
		marker = "true"
	}
	request.GetAttributes().GetRequest().GetHttp().Headers = map[string]string{authPartialBodyHeader: marker, "content-type": "text/plain"}
	response, err := server.Check(context.Background(), request)
	if partial {
		assertPartialBodyRejectedBeforeNativeOpen(t, mode, response, err, opener, observer)
		return
	}
	assertCompleteBodyNativeResult(t, mode, response, err, opener, len(body))
}

func assertPartialBodyRejectedBeforeNativeOpen(t *testing.T, mode string, response *authv3.CheckResponse, err error, opener *completenessOpener, observer *recordedLifecycleEvents) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument || response != nil || opener.opens != 0 || opener.bytes != 0 || opener.eos != 0 || len(observer.snapshot()) != 0 {
		t.Fatalf("Check(partial,%s) response=%v err=%v native=%+v events=%v, want technical rejection before open/body/EOS/lease", mode, response, err, opener, observer.snapshot())
	}
}

func assertCompleteBodyNativeResult(t *testing.T, mode string, response *authv3.CheckResponse, err error, opener *completenessOpener, bodyLength int) {
	t.Helper()
	if err != nil || opener.opens != 1 || opener.bytes != bodyLength || opener.eos != 1 {
		t.Fatalf("Check(complete,%s) response=%v err=%v native=%+v, want one native open/full body/EOS", mode, response, err, opener)
	}
	if mode == "On" && (response.GetDeniedResponse().GetStatus().GetCode() != 403 || opener.decision.RuleID != "1200997") {
		t.Fatalf("Check(complete,%s) response=%v, want native tail-rule denial", mode, response)
	}
	if mode == "DetectionOnly" && (response.GetOkResponse() == nil || response.GetDynamicMetadata().GetFields()[metadataLease].GetStringValue() == "") {
		t.Fatalf("Check(complete,%s) response=%v, want native allow and lease", mode, response)
	}
}
