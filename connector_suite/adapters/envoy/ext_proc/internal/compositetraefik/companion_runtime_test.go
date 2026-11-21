//go:build libmodsecurity

package compositetraefik

// Real Common/libmodsecurity variant of the ForwardAuth disconnect regression
// (Connector PR #454). TEST_ROOT must select the Framework checkout that holds
// the shared rules file.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/processor"
)

const (
	// companionRuntimeCapacity leaves room for the disconnect cases and the
	// follow-up request on one coordinator.
	companionRuntimeCapacity = 4
	companionRuntimeShutdown = 2 * time.Second
)

func companionRealEngine(t *testing.T) *processor.CommonRuntimeEngine {
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
	content := fmt.Sprintf(`enabled=on
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
`, rules, filepath.Join(dir, "events.jsonl"))
	if err := os.WriteFile(config, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := processor.NewCommonRuntimeEngine(config)
	if err != nil {
		t.Fatalf("NewCommonRuntimeEngine: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), companionRuntimeShutdown)
		defer cancel()
		if err := engine.Close(ctx); err != nil {
			t.Errorf("closing the real Common runtime engine: %v", err)
		}
	})
	return engine
}

func TestCompanionRealEngineClientDisconnectKeepsEngineUsable(t *testing.T) {
	engine := companionRealEngine(t)
	c, err := composite.New(companionConnector, companionKey, composite.Limits{Capacity: companionRuntimeCapacity}, engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)

	// A disconnect after a non-empty and after an empty first body read.
	for i, first := range [][]byte{[]byte("partial body"), {}} {
		path := fmt.Sprintf("/real-disconnect-%d", i)
		ctx, cancel := context.WithCancel(context.Background())
		rec := companionForwardAuth(c, ctx, companionReserve(t, c, fmt.Sprintf("real-disconnect-session-%d", i), http.MethodPost, path), http.MethodPost, path, &cancelAfterFirstRead{data: first, cancel: cancel})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("disconnect after %d body bytes: status = %d, want %d", len(first), rec.Code, http.StatusServiceUnavailable)
		}
		if err := c.Err(); err != nil {
			t.Fatalf("disconnect after %d body bytes faulted the composite coordinator: %v", len(first), err)
		}
	}
	// Boundary: the client is already gone before ForwardAuth reaches P1.
	gone, cancelGone := context.WithCancel(context.Background())
	cancelGone()
	const gonePath = "/real-gone-before-p1"
	if rec := companionForwardAuth(c, gone, companionReserve(t, c, "real-gone-session", http.MethodGet, gonePath), http.MethodGet, gonePath, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("request canceled before P1: status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("a request canceled before P1 faulted the composite coordinator: %v", err)
	}

	const nextPath = "/real-after-disconnect"
	if next := companionForwardAuth(c, context.Background(), companionReserve(t, c, "real-next-session", http.MethodGet, nextPath), http.MethodGet, nextPath, nil); next.Code != http.StatusOK {
		t.Fatalf("request after a client disconnect status = %d, want %d (engine unusable)", next.Code, http.StatusOK)
	}
}
