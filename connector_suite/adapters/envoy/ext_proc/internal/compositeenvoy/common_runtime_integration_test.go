//go:build libmodsecurity

package compositeenvoy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

type recordedLifecycleEvents struct {
	mu     sync.Mutex
	events []composite.Event
}

func (o *recordedLifecycleEvents) Observe(event composite.Event) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
	return nil
}

func (o *recordedLifecycleEvents) snapshot() []composite.Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]composite.Event(nil), o.events...)
}

func closeCommonRuntimeForTest(t *testing.T, engine *processor.CommonRuntimeEngine) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return engine.Close(ctx)
}

func TestAuthzServerAllowsRealCommonRequestAndEmitsBoundedPipelineMetadata(t *testing.T) {
	repositoryRoot, err := filepath.Abs("../../../../../")
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(repositoryRoot, "common", "rules", "modsecurity_p1_p4_vectors.conf")
	if info, statErr := os.Stat(rulesPath); statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("shared rules are unavailable: %v", statErr)
	}
	directory := t.TempDir()
	runtimeConfig := filepath.Join(directory, "runtime.conf")
	commonEventPath := filepath.Join(directory, "common-events.jsonl")
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
`, rulesPath, commonEventPath)
	if err := os.WriteFile(runtimeConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := processor.NewCommonRuntimeEngine(runtimeConfig)
	if err != nil {
		t.Fatalf("NewCommonRuntimeEngine: %v", err)
	}
	observer := &recordedLifecycleEvents{}
	coordinator, err := composite.New("envoy", make([]byte, 32), composite.Limits{
		Capacity:       1,
		TTL:            time.Second,
		IdleTTL:        time.Second,
		MaxHeaders:     256,
		MaxHeaderBytes: 64 << 10,
	}, engine, observer)
	if err != nil {
		_ = closeCommonRuntimeForTest(t, engine)
		t.Fatalf("composite.New: %v", err)
	}
	server, err := NewAuthzServer(coordinator)
	if err != nil {
		coordinator.Close()
		_ = closeCommonRuntimeForTest(t, engine)
		t.Fatal(err)
	}
	request := authCheckRequest(nil)
	request.GetAttributes().GetRequest().GetHttp().Headers = map[string]string{"x-request-id": "untrusted-client-request-id"}
	response, err := server.Check(context.Background(), request)
	if err != nil {
		coordinator.Close()
		_ = closeCommonRuntimeForTest(t, engine)
		t.Fatalf("Check() with real Common engine: %v", err)
	}
	if response.GetOkResponse() == nil || response.GetDynamicMetadata().GetFields()[metadataLease].GetStringValue() == "" {
		coordinator.Close()
		_ = closeCommonRuntimeForTest(t, engine)
		t.Fatalf("real Common allow response did not issue protected metadata: %#v", response)
	}
	coordinator.Close()
	if err := closeCommonRuntimeForTest(t, engine); err != nil {
		t.Fatalf("engine.Close: %v", err)
	}
	events := observer.snapshot()
	if len(events) < 4 {
		t.Fatalf("observer events=%#v, want P1/P2/lease/terminal", events)
	}
	decisionID := events[0].DecisionID
	for _, event := range events {
		if event.DecisionID != decisionID || len(event.DecisionID) < 16 {
			t.Fatalf("event has no shared server-generated decision ID: %#v", event)
		}
		if event.RequestPath != "envoy.ext_authz" || event.ResponsePath != "envoy.ext_proc" || event.Transport != "envoy_ext_authz_ext_proc_grpc" {
			t.Fatalf("event has incorrect bounded Envoy pipeline metadata: %#v", event)
		}
	}
}
