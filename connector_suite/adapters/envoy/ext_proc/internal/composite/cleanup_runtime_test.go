//go:build libmodsecurity

package composite

// Real Common/libmodsecurity control for the direct cleanup in BeginRequest
// (Connector PR #454): a transaction opened by the real engine, then closed
// because the coordinator faulted before registration, is cleaned up through
// the detached bounded context without making the engine unusable. A real
// never-returning native call cannot be produced deterministically; that
// bound is covered by the test doubles in cleanup_bounds_test.go.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

const (
	// cleanupRuntimeCapacity and cleanupRuntimeBudget leave ample headroom for
	// a real native close; the bound itself is covered by cleanup_bounds_test.go.
	cleanupRuntimeCapacity = 4
	cleanupRuntimeBudget   = time.Second
	cleanupRuntimeShutdown = 2 * time.Second
)

// cleanupRuntimeConfig mirrors the runtime configuration of the existing
// composite Envoy integration tests; %s are the rules file and event path.
const cleanupRuntimeConfig = "enabled=on\nrules_file=%s\ntransaction_id_header=x-request-id\nrequest_body_mode=streaming\nresponse_body_mode=streaming\nphase4_mode=safe\ndefault_block_status=403\ndefault_error_status=500\nuse_error_log=off\nmax_header_count=128\nmax_header_name_size=256\nmax_header_value_size=8192\nmax_total_header_bytes=32768\nmax_event_json_bytes=16384\nevent_path=%s\n"

func cleanupRuntimeEngine(t *testing.T) *processor.CommonRuntimeEngine {
	t.Helper()
	frameworkRoot := os.Getenv("TEST_ROOT")
	if !filepath.IsAbs(frameworkRoot) {
		t.Fatal("TEST_ROOT must explicitly select the Framework checkout")
	}
	rules := filepath.Join(frameworkRoot, "connector_suite", "common", "rules", "modsecurity_p1_p4_vectors.conf")
	if info, err := os.Stat(rules); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("shared rules are unavailable: %v", err)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "runtime.conf")
	content := fmt.Sprintf(cleanupRuntimeConfig, rules, filepath.Join(dir, "events.jsonl"))
	if err := os.WriteFile(config, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := processor.NewCommonRuntimeEngine(config)
	if err != nil {
		t.Fatalf("NewCommonRuntimeEngine: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupRuntimeShutdown)
		defer cancel()
		if err := engine.Close(ctx); err != nil {
			t.Errorf("closing the real Common runtime engine: %v", err)
		}
	})
	return engine
}

// faultAfterOpen opens through the real engine, then faults the coordinator
// (and optionally cancels the request context) before BeginRequest registers
// the entry.
type faultAfterOpen struct {
	engine *processor.CommonRuntimeEngine
	c      *Coordinator
	cancel context.CancelFunc
}

func (o *faultAfterOpen) Open(ctx context.Context, meta processor.StreamMetadata) (processor.Transaction, error) {
	tx, err := o.engine.Open(ctx, meta)
	if err == nil {
		o.c.setFault(errBoundTestFault)
		if o.cancel != nil {
			o.cancel()
		}
	}
	return tx, err
}

func TestCleanupRuntimeBeginRequestFaultAfterOpenClosesRealTransaction(t *testing.T) {
	engine := cleanupRuntimeEngine(t)
	// The fault path closes before any request phase, so nil headers are a
	// valid boundary input next to the normal host header.
	for _, tc := range []struct {
		name          string
		cancelRequest bool
		headers       []processor.Header
	}{
		{"active request", false, cleanupRuntimeHeaders()},
		{"canceled request", true, cleanupRuntimeHeaders()},
		{"canceled request without headers", true, nil},
	} {
		cancelRequest := tc.cancelRequest
		opener := &faultAfterOpen{engine: engine}
		c, err := New(boundConnector, boundKey, Limits{Capacity: cleanupRuntimeCapacity, CleanupTimeout: cleanupRuntimeBudget}, opener, nil)
		if err != nil {
			t.Fatal(err)
		}
		opener.c = c
		ctx, cancel := context.WithCancel(context.Background())
		if cancelRequest {
			opener.cancel = cancel
		}
		_, _, err = c.BeginRequest(ctx, cleanupRuntimeMetadata(), tc.headers, true)
		cancel()
		c.Close()
		if !errors.Is(err, errBoundTestFault) {
			t.Fatalf("%s: BeginRequest error = %v, want the coordinator fault, not a native cleanup failure", tc.name, err)
		}
	}

	// The real engine must still be healthy: a fresh coordinator completes a
	// request and its cleanup without a cleanup failure.
	fresh, err := New(boundConnector, boundKey, Limits{Capacity: cleanupRuntimeCapacity}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Close)
	admission, decision, err := fresh.BeginRequest(context.Background(), cleanupRuntimeMetadata(), cleanupRuntimeHeaders(), true)
	if err != nil || decision.Action != processor.ActionAllow {
		t.Fatalf("real engine request after the bounded direct cleanup = %#v / %v, want allow", decision, err)
	}
	admission.Finish(context.Background(), "finish")
	if err := fresh.Err(); err != nil {
		t.Fatalf("real engine unusable after the bounded direct cleanup: %v", err)
	}
}

// cleanupRuntimeMetadata supplies the request metadata the real Common runtime
// requires (protocol, host and server endpoint).
func cleanupRuntimeMetadata() processor.StreamMetadata {
	return processor.StreamMetadata{Request: processor.RequestMetadata{
		Method: "GET", URI: "/runtime-cleanup", Protocol: "HTTP/1.1", Hostname: "example.test",
		ServerAddress: "127.0.0.1", ServerPort: 8080, ClientAddress: "127.0.0.1", ClientPort: 40000,
	}}
}

func cleanupRuntimeHeaders() []processor.Header {
	return []processor.Header{{Name: "host", Value: []byte("example.test")}}
}
