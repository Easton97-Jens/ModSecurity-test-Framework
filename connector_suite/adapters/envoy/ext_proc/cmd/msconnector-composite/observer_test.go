package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc/internal/composite"
)

// noProgressEventLogFile simulates a filesystem that accepts one byte and
// then violates the Writer contract by making no progress without an error.
// The observer must restore the original JSONL length in that defensive case.
type noProgressEventLogFile struct {
	*os.File
	writes int
}

func readEventRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}
	lines := strings.FieldsFunc(string(content), func(r rune) bool { return r == '\n' })
	records := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode event record: %v", err)
		}
		records = append(records, record)
	}
	return records
}

func assertObserverReset(t *testing.T, path string, observer *compositeObserver) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat reset log: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("oversized log was not reset: got %d bytes", info.Size())
	}
	if observer.Err() != nil {
		t.Fatalf("observer reset became a permanent failure: %v", observer.Err())
	}
}

func (f *noProgressEventLogFile) Write(p []byte) (int, error) {
	f.writes++
	if f.writes == 1 && len(p) > 0 {
		return f.File.Write(p[:1])
	}
	return 0, nil
}

func TestCompositeObserverWritesOnlyBoundedLifecycleMetadata(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	observer, closer, err := newCompositeObserver(path)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	defer closer.Close()
	if err := observer.Observe(composite.Event{
		DecisionID:       "decision-123",
		Connector:        "envoy",
		RuleID:           "1103001",
		Phase:            "response_body",
		Outcome:          "safe",
		Reason:           "response_after_commit",
		RequestedAction:  "deny",
		ActualHostAction: "log_only",
		VisibleStatus:    200,
		CleanupOutcome:   "completed",
		RequestPath:      "envoy.ext_authz",
		ResponsePath:     "envoy.ext_proc",
		Transport:        "envoy_ext_authz_ext_proc_grpc",
		EventTime:        time.Unix(1, 0),
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	for _, forbidden := range []string{"lease", "headers", "body", "payload"} {
		if _, present := record[forbidden]; present {
			t.Fatalf("evidence unexpectedly contains %q", forbidden)
		}
	}
	if record["decision_id"] != "decision-123" || record["rule_id"] != "1103001" || record["request_path"] != "envoy.ext_authz" || record["response_path"] != "envoy.ext_proc" || record["transport"] != "envoy_ext_authz_ext_proc_grpc" || record["actual_host_action"] != "log_only" || record["visible_status"] != float64(200) {
		t.Fatalf("lifecycle evidence missing expected fields: %#v", record)
	}
}

func TestCompositeObserverRecordsWriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	observer, closer, err := newCompositeObserver(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := observer.Observe(composite.Event{}); err == nil {
		t.Fatal("closed observer unexpectedly accepted an event")
	}
	if observer.Err() == nil {
		t.Fatal("closed observer failure was not retained")
	}
}

func TestCompositeObserverRollsBackNoProgressWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	observer, closer, err := newCompositeObserver(path)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	file, ok := observer.file.(*os.File)
	if !ok {
		t.Fatalf("observer did not retain an os.File: %T", observer.file)
	}
	observer.file = &noProgressEventLogFile{File: file}
	first := observer.Observe(composite.Event{DecisionID: "decision-no-progress", Connector: "envoy", Phase: "P1", Outcome: "observed", RequestPath: "envoy.ext_authz", ResponsePath: "envoy.ext_proc", Transport: "envoy_ext_authz_ext_proc_grpc", EventTime: time.Unix(1, 0)})
	if first == nil {
		t.Fatal("observer accepted a no-progress write")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rolled-back event log: %v", err)
	}
	if len(content) != 0 || observer.size != 0 {
		t.Fatalf("no-progress write was not rolled back: size=%d content=%q", observer.size, content)
	}
	if observer.Err() == nil {
		t.Fatal("no-progress failure was not retained")
	}
	if got := closer.Close(); got != first {
		t.Fatalf("Close() = %v, want first no-progress failure %v", got, first)
	}
}

func TestCompositeObserverRejectsUnboundedRuleID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	observer, closer, err := newCompositeObserver(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	defer closer.Close()
	err = observer.Observe(composite.Event{DecisionID: "id", Connector: "envoy", RuleID: string(make([]byte, 129)), Phase: "P1", Outcome: "observed", RequestPath: "envoy.ext_authz", ResponsePath: "envoy.ext_proc", Transport: "envoy_ext_authz_ext_proc_grpc", EventTime: time.Unix(1, 0)})
	if err == nil {
		t.Fatal("observer accepted an oversized rule identifier")
	}
}

func TestCompositeObserverDefersRotationUntilLifecycleTerminal(t *testing.T) {
	t.Parallel()
	const maxSize = maxCompositeEventRecordBytes + 1
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	observer, closer, err := newCompositeObserverWithLimit(path, maxSize)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	defer closer.Close()
	firstID := strings.Repeat("a", 255) + "1"
	secondID := strings.Repeat("b", 255) + "2"
	largeEvent := func(decisionID, phase string) composite.Event {
		return composite.Event{DecisionID: decisionID, Connector: strings.Repeat("c", 256), Phase: phase, Outcome: strings.Repeat("o", 256), Reason: strings.Repeat("r", 256), RequestPath: "r", ResponsePath: "s", Transport: "t", EventTime: time.Unix(1, 0)}
	}
	for _, phase := range []string{"P1", "P2"} {
		if err := observer.Observe(largeEvent(firstID, phase)); err != nil {
			t.Fatalf("observe active lifecycle event: %v", err)
		}
	}
	if err := observer.Observe(composite.Event{DecisionID: firstID, Connector: "envoy", Phase: "terminal", Outcome: "closed", CleanupOutcome: "closed", RequestPath: "envoy.ext_authz", ResponsePath: "envoy.ext_proc", Transport: "envoy_ext_authz_ext_proc_grpc", EventTime: time.Unix(1, 0)}); err != nil {
		t.Fatalf("observe terminal event: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat event log: %v", err)
	}
	if info.Size() <= maxSize {
		t.Fatalf("test did not cross deferred rotation threshold: got %d, want > %d", info.Size(), maxSize)
	}
	records := readEventRecords(t, path)
	if len(records) != 3 {
		t.Fatalf("active lifecycle was split before terminal: %#v", records)
	}
	for _, record := range records {
		if record["decision_id"] != firstID {
			t.Fatalf("active lifecycle retained wrong decision: %#v", record)
		}
	}
	if err := observer.Observe(largeEvent(secondID, "P1")); err != nil {
		t.Fatalf("observe post-rotation lifecycle: %v", err)
	}
	records = readEventRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("rotation did not start a fresh lifecycle window: %#v", records)
	}
	record := records[0]
	if record["decision_id"] != secondID {
		t.Fatalf("rotation retained wrong lifecycle: %#v", record)
	}
	if observer.Err() != nil {
		t.Fatalf("rotation became a permanent observer failure: %v", observer.Err())
	}
}

func TestCompositeObserverClosesRecoveredLifecycleBeforeRotation(t *testing.T) {
	t.Parallel()
	const maxSize = maxCompositeEventRecordBytes + 1
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	firstID := strings.Repeat("a", 255) + "1"
	secondID := strings.Repeat("b", 255) + "2"
	largeEvent := func(decisionID, phase string) composite.Event {
		return composite.Event{DecisionID: decisionID, Connector: strings.Repeat("c", 256), Phase: phase, Outcome: strings.Repeat("o", 256), Reason: strings.Repeat("r", 256), RequestPath: "r", ResponsePath: "s", Transport: "t", EventTime: time.Unix(1, 0)}
	}
	initial, initialCloser, err := newCompositeObserverWithLimit(path, maxSize)
	if err != nil {
		t.Fatalf("new initial observer: %v", err)
	}
	for _, phase := range []string{"P1", "P2"} {
		if err := initial.Observe(largeEvent(firstID, phase)); err != nil {
			t.Fatalf("observe pre-crash lifecycle event: %v", err)
		}
	}
	if err := initialCloser.Close(); err != nil {
		t.Fatalf("close pre-crash observer: %v", err)
	}

	recovered, recoveredCloser, err := newCompositeObserverWithLimit(path, maxSize)
	if err != nil {
		t.Fatalf("recover observer: %v", err)
	}
	defer recoveredCloser.Close()
	records := readEventRecords(t, path)
	if len(records) != 3 {
		t.Fatalf("restart recovery split or lost lifecycle: %#v", records)
	}
	terminal := records[2]
	if terminal["decision_id"] != firstID || terminal["phase"] != "terminal" || terminal["reason"] != "restart_recovery" || terminal["cleanup_outcome"] != "restart_recovery" {
		t.Fatalf("missing restart-recovery terminal: %#v", terminal)
	}
	if err := recovered.Observe(largeEvent(secondID, "P1")); err != nil {
		t.Fatalf("observe post-recovery lifecycle: %v", err)
	}
	records = readEventRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("post-recovery rotation did not start a fresh lifecycle: %#v", records)
	}
	record := records[0]
	if record["decision_id"] != secondID {
		t.Fatalf("post-recovery rotation retained wrong lifecycle: %#v", record)
	}
}

func TestCompositeObserverResetsOversizedExistingLog(t *testing.T) {
	t.Parallel()
	const maxSize = 4096
	const maxOverflow = 4096
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", int(maxSize+maxOverflow+1))), 0o600); err != nil {
		t.Fatalf("seed oversized log: %v", err)
	}
	observer, closer, err := newCompositeObserverWithBounds(path, maxSize, maxOverflow)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	defer closer.Close()
	assertObserverReset(t, path, observer)
}

func TestCompositeObserverRejectsOverflowedRetentionBounds(t *testing.T) {
	t.Parallel()
	_, _, err := newCompositeObserverWithBounds(filepath.Join(t.TempDir(), "events.jsonl"), maxCompositeEventRecordBytes+1, 1<<63-1)
	if err == nil {
		t.Fatal("observer accepted overflowed retention bounds")
	}
}

func TestCompositeObserverResetsHardBoundLogWithoutRecoveryReservation(t *testing.T) {
	t.Parallel()
	const maxSize = maxCompositeEventRecordBytes + 1
	const maxOverflow = maxCompositeEventRecordBytes + 1
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	record := compositeEventRecord{
		DecisionID:   "pre-crash",
		Connector:    "envoy",
		Phase:        "P1",
		Outcome:      "observed",
		EventTime:    "1970-01-01T00:00:01Z",
		RequestPath:  "envoy.ext_authz",
		ResponsePath: "envoy.ext_proc",
		Transport:    "envoy_ext_authz_ext_proc_grpc",
	}
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal active lifecycle: %v", err)
	}
	line = append(line, '\n')
	hardLimit := eventLogHardLimit(maxSize, maxOverflow)
	filler := strings.Repeat("{}\n", int((hardLimit-int64(len(line)))/3))
	seed := append([]byte(filler), line...)
	if int64(len(seed)) > hardLimit {
		t.Fatalf("seed exceeds hard limit: got %d, want <= %d", len(seed), hardLimit)
	}
	if eventLogHasRecoveryReservation(int64(len(seed)), 1, maxSize, maxOverflow) {
		t.Fatalf("test seed unexpectedly retains recovery-terminal capacity: size=%d", len(seed))
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatalf("seed legacy event log: %v", err)
	}

	observer, closer, err := newCompositeObserverWithBounds(path, maxSize, maxOverflow)
	if err != nil {
		t.Fatalf("recover legacy observer: %v", err)
	}
	defer closer.Close()
	assertObserverReset(t, path, observer)
	if err := observer.Observe(composite.Event{DecisionID: "after-reset", Connector: "envoy", Phase: "P1", Outcome: "observed", RequestPath: "envoy.ext_authz", ResponsePath: "envoy.ext_proc", Transport: "envoy_ext_authz_ext_proc_grpc", EventTime: time.Unix(1, 0)}); err != nil {
		t.Fatalf("observe after legacy reset: %v", err)
	}
}

func TestCompositeObserverRepairsIncompleteJSONLTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	valid := []byte("{\"event\":\"complete\"}\n")
	seed := append(append([]byte{}, valid...), []byte("{\"event\":")...)
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatalf("seed incomplete JSONL: %v", err)
	}
	observer, closer, err := newCompositeObserverWithLimit(path, 4096)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	defer closer.Close()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read repaired event log: %v", err)
	}
	if string(content) != string(valid) {
		t.Fatalf("incomplete tail was not removed: %q", content)
	}
	if err := observer.Observe(composite.Event{DecisionID: "decision-after-repair", Connector: "envoy", Phase: "P1", Outcome: "observed", RequestPath: "envoy.ext_authz", ResponsePath: "envoy.ext_proc", Transport: "envoy_ext_authz_ext_proc_grpc", EventTime: time.Unix(1, 0)}); err != nil {
		t.Fatalf("observe after repair: %v", err)
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read appended event log: %v", err)
	}
	for _, line := range strings.FieldsFunc(string(content), func(r rune) bool { return r == '\n' }) {
		if !json.Valid([]byte(line)) {
			t.Fatalf("retained JSONL line is invalid: %q", line)
		}
	}
}

func sinkTestEvent() composite.Event {
	return composite.Event{DecisionID: "sink-failure", Connector: "envoy", Phase: "P1", Outcome: "observed", RequestPath: "envoy.ext_authz", ResponsePath: "envoy.ext_proc", Transport: "envoy_ext_authz_ext_proc_grpc", EventTime: time.Unix(1, 0)}
}

func TestCompositeObserverRetainsSinkFailureWithoutRetry(t *testing.T) {
	for _, mode := range []string{"closed", "read-only", "no-progress"} {
		t.Run(mode, func(t *testing.T) {
			testCompositeObserverSinkFailure(t, mode)
		})
	}
}

func testCompositeObserverSinkFailure(t *testing.T, mode string) {
	t.Helper()
	t.Parallel()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	observer, _, err := newCompositeObserver(path)
	if err != nil {
		t.Fatal(err)
	}
	configureCompositeFailingSink(t, observer, path, mode)
	event := sinkTestEvent()
	first := observer.Observe(event)
	if first == nil {
		t.Fatal("Observe(failing sink) = nil, want failure")
	}
	_ = observer.file.Close()
	healthy, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	observer.file = healthy
	if got := observer.Observe(event); got != first {
		t.Fatalf("Observe(retry) = %v, want %v", got, first)
	}
	if got := observer.Observe(composite.Event{}); got != first {
		t.Fatalf("Observe(invalid retry) = %v, want %v", got, first)
	}
	if got := observer.Err(); got != first {
		t.Fatalf("Err() = %v, want %v", got, first)
	}
	if got := observer.Close(); got != first {
		t.Fatalf("Close() = %v, want %v", got, first)
	}
	if got := observer.Close(); got != first {
		t.Fatalf("Close(retry) = %v, want %v", got, first)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("Observe(retry) left %d bytes, want 0", len(content))
	}
}

func configureCompositeFailingSink(t *testing.T, observer *compositeObserver, path, mode string) {
	t.Helper()
	original := observer.file
	switch mode {
	case "closed":
		if err := original.Close(); err != nil {
			t.Fatal(err)
		}
	case "read-only":
		if err := original.Close(); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		observer.file = file
	case "no-progress":
		observer.file = &noProgressEventLogFile{File: original.(*os.File)}
	}
}

func TestCompositeObserverRetainsCloseAndValidationFailures(t *testing.T) {
	for _, mode := range []string{"close", "validation", "serialization"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			assertCompositeObserverFailureRetained(t, mode)
		})
	}
}

func assertCompositeObserverFailureRetained(t *testing.T, mode string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	observer, _, err := newCompositeObserver(path)
	if err != nil {
		t.Fatal(err)
	}
	var first error
	if mode == "close" {
		if err := observer.file.Close(); err != nil {
			t.Fatal(err)
		}
		first = observer.Close()
	} else if mode == "serialization" {
		event := sinkTestEvent()
		oversized := strings.Repeat("\x01", 256)
		event.DecisionID, event.Connector, event.Outcome, event.Reason = oversized, oversized, oversized, oversized
		event.RequestPath, event.ResponsePath, event.Transport = oversized, oversized, oversized
		if err := validateCompositeEvent(event); err != nil {
			t.Fatalf("serialization fixture validation = %v, want valid metadata", err)
		}
		first = observer.Observe(event)
	} else {
		first = observer.Observe(composite.Event{})
	}
	if first == nil {
		t.Fatal("failing operation = nil, want error")
	}
	if got := observer.Observe(sinkTestEvent()); got != first {
		t.Fatalf("Observe(after failure) = %v, want %v", got, first)
	}
	if got := observer.Close(); got != first {
		t.Fatalf("Close(after failure) = %v, want %v", got, first)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("Observe(after failure) wrote %d bytes, want 0", len(content))
	}
}
