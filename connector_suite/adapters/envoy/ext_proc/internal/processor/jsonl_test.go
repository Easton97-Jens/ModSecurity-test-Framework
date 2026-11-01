package processor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestJSONLObserverWritesMetadataOnlyCompletionRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	observer, err := NewJSONLObserver(path)
	if err != nil {
		t.Fatalf("NewJSONLObserver() error = %v", err)
	}
	var status unix.Stat_t
	if err := unix.Stat(path, &status); err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if status.Uid != uint32(unix.Geteuid()) || status.Mode&0o777 != 0o600 {
		t.Fatalf("event log ownership/mode = uid %d mode %o", status.Uid, status.Mode&0o777)
	}
	defer observer.Close()
	if err := observer.Record(Summary{
		TransactionID:      "test-transaction",
		RequestHeaderCount: 3,
		ResponseBodyBytes:  17,
		LateAction:         LateActionNone,
		CloseReason:        CloseResponseEOS,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	line := string(content)
	for _, expected := range []string{
		`"integration_mode":"ext_proc"`,
		`"evaluation_mode":"passthrough_nonpromoted"`,
		`"rule_evaluation":"not_wired"`,
		`"transaction_id":"test-transaction"`,
	} {
		if !strings.Contains(line, expected) {
			t.Fatalf("event record missing %s: %s", expected, line)
		}
	}
	for _, forbidden := range []string{`"headers"`, `"body":"`, `"request_body":"`, `"response_body":"`} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("event record contains payload-bearing field %s: %s", forbidden, line)
		}
	}
}

func TestJSONLObserverRecordCloseConcurrent(t *testing.T) {
	for iteration := 0; iteration < 128; iteration++ {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		observer, err := NewJSONLObserver(path)
		if err != nil {
			t.Fatalf("NewJSONLObserver() error = %v", err)
		}

		start := make(chan struct{})
		var group sync.WaitGroup
		var recordErr error
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			recordErr = observer.Record(Summary{TransactionID: "concurrent"})
		}()
		go func() {
			defer group.Done()
			<-start
			if err := observer.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		}()
		close(start)
		group.Wait()

		if recordErr != nil && recordErr.Error() != "event observer is closed" {
			t.Fatalf("Record() unexpected concurrent error = %v", recordErr)
		}
	}
}

func TestJSONLObserverRejectsRelativePath(t *testing.T) {
	if _, err := NewJSONLObserver("events.jsonl"); err == nil {
		t.Fatal("NewJSONLObserver() accepted relative path")
	}
}

func TestJSONLObserverRejectsNormalizedPathWithTraversal(t *testing.T) {
	path := t.TempDir() + "/nested/../events.jsonl"
	if _, err := NewJSONLObserver(path); err == nil {
		t.Fatal("NewJSONLObserver() accepted non-normalized path")
	}
}

func TestJSONLObserverRejectsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	link := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONLObserver(link); err == nil {
		t.Fatal("NewJSONLObserver() followed final symlink")
	}
}

func TestJSONLObserverRejectsAncestorSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(link, "nested", "events.jsonl")
	if _, err := NewJSONLObserver(path); err == nil {
		t.Fatal("NewJSONLObserver() followed ancestor symlink")
	}
}

func TestPrivateEventLogRetainsValidatedParentDescriptor(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "validated-parent")
	retainedParent := filepath.Join(root, "retained-parent")
	attackerParent := filepath.Join(root, "replacement-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(attackerParent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentFD, err := openPrivateEventParent(parent)
	if err != nil {
		t.Fatalf("openPrivateEventParent() error = %v", err)
	}
	defer func() { _ = unix.Close(parentFD) }()
	if err := os.Rename(parent, retainedParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attackerParent, parent); err != nil {
		t.Fatal(err)
	}
	observer, err := openPrivateEventLog(parentFD, "events.jsonl", filepath.Join(parent, "events.jsonl"))
	if err != nil {
		t.Fatalf("openPrivateEventLog() error = %v", err)
	}
	if _, err := observer.WriteString("anchored\\n"); err != nil {
		_ = observer.Close()
		t.Fatal(err)
	}
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	anchored, err := os.ReadFile(filepath.Join(retainedParent, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(anchored) != "anchored\\n" {
		t.Fatalf("anchored event content = %q", anchored)
	}
	if _, err := os.Stat(filepath.Join(attackerParent, "events.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement parent received an event log: %v", err)
	}
}

func TestJSONLObserverRejectsUnexpectedExistingFileTypes(t *testing.T) {
	dir := t.TempDir()
	directory := filepath.Join(dir, "events.jsonl")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONLObserver(directory); err == nil {
		t.Fatal("NewJSONLObserver() accepted directory")
	}

	fifo := filepath.Join(dir, "events.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONLObserver(fifo); err == nil {
		t.Fatal("NewJSONLObserver() accepted FIFO")
	}
}

func TestJSONLObserverRejectsExistingFileWithUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Establish the unsafe fixture explicitly: a restrictive runner umask
	// must not turn this rejection case into a valid private file.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONLObserver(path); err == nil {
		t.Fatal("NewJSONLObserver() accepted owner-readable file with unsafe permissions")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("rejected event log mode changed to %o", got)
	}
}

func TestJSONLObserverRetainsPhysicalSinkFailure(t *testing.T) {
	for _, mode := range []string{"closed", "read-only"} {
		t.Run(mode, func(t *testing.T) {
			testJSONLObserverPhysicalSinkFailure(t, mode)
		})
	}
}

func testJSONLObserverPhysicalSinkFailure(t *testing.T, mode string) {
	t.Helper()
	t.Parallel()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "closed" {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	observer := &JSONLObserver{file: file}
	first := observer.Record(Summary{TransactionID: "failed"})
	if first == nil {
		t.Fatal("Record(failing descriptor) = nil, want physical failure")
	}
	// Replace the file with a usable descriptor: a retry must not touch it.
	_ = file.Close()
	healthy, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	observer.file = healthy
	for i := 0; i < 3; i++ {
		if got := observer.Record(Summary{TransactionID: "retry"}); got != first {
			t.Fatalf("Record(retry) = %v, want first error %v", got, first)
		}
	}
	if got := observer.Close(); got != first {
		t.Fatalf("Close() = %v, want first error %v", got, first)
	}
	if got := observer.Record(Summary{}); got != first {
		t.Fatalf("Record(after close) = %v, want first error %v", got, first)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("Record(retry) wrote %d bytes, want 0", len(content))
	}
}

func TestJSONLObserverRetainsCloseFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	observer := &JSONLObserver{file: file}
	first := observer.Close()
	if first == nil {
		t.Fatal("Close(closed descriptor) = nil, want failure")
	}
	if got := observer.Close(); got != first {
		t.Fatalf("Close(retry) = %v, want %v", got, first)
	}
	if got := observer.Record(Summary{}); got != first {
		t.Fatalf("Record(after failed close) = %v, want %v", got, first)
	}
}
