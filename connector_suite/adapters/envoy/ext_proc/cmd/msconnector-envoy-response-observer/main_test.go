package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type failingResponseObserverListener struct{}

func (failingResponseObserverListener) Accept() (net.Conn, error) {
	return nil, errors.New("listener failed")
}
func (failingResponseObserverListener) Close() error   { return nil }
func (failingResponseObserverListener) Addr() net.Addr { return responseObserverTestAddr("failed") }

type responseObserverTestAddr string

func (a responseObserverTestAddr) Network() string { return "test" }
func (a responseObserverTestAddr) String() string  { return string(a) }

type replacingResponseObserverListener struct {
	path string
}

func (listener replacingResponseObserverListener) Accept() (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (listener replacingResponseObserverListener) Close() error {
	// Retain the old inode while creating a distinct replacement. Unlinking
	// first allows immediate inode reuse on some filesystems.
	if err := os.Rename(listener.path, listener.path+".original"); err != nil {
		return err
	}
	return os.WriteFile(listener.path, []byte("replacement"), 0600)
}
func (listener replacingResponseObserverListener) Addr() net.Addr {
	return responseObserverTestAddr("replacement")
}

type gatedResponseObserverListener struct {
	connection net.Conn
	accepted   chan struct{}
	release    chan struct{}
	closeOnce  sync.Once
}

func (listener *gatedResponseObserverListener) Accept() (net.Conn, error) {
	close(listener.accepted)
	<-listener.release
	return listener.connection, nil
}

func (listener *gatedResponseObserverListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.release) })
	return nil
}

func (listener *gatedResponseObserverListener) Addr() net.Addr {
	return responseObserverTestAddr("gated")
}

func TestServeResponseObserverReturnsUnexpectedServeFailure(t *testing.T) {
	err := serveResponseObserver(grpc.NewServer(), failingResponseObserverListener{}, make(chan os.Signal))
	if err == nil || err.Error() != "listener failed" {
		t.Fatalf("serveResponseObserver error = %v, want listener failure", err)
	}
}

func TestForceStopResponseObserverClosesPeerAcceptedAfterShutdownBegins(t *testing.T) {
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	baseListener := &gatedResponseObserverListener{
		connection: serverConnection,
		accepted:   make(chan struct{}),
		release:    make(chan struct{}),
	}
	listener := newTrackedResponseObserverListener(baseListener)
	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()
	select {
	case <-baseListener.accepted:
	case <-time.After(time.Second):
		t.Fatal("underlying listener did not accept the peer")
	}
	if err := clientConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	stopped := make(chan struct{})
	go func() {
		forceStopResponseObserver(grpc.NewServer(), listener)
		close(stopped)
	}()
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("tracked accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("tracked listener did not reject the late accepted peer")
	}
	if _, err := clientConnection.Read(make([]byte, 1)); err == nil {
		t.Fatal("late accepted peer remained open after forced stop")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("late accepted peer was not closed: %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("force stop did not finish")
	}
}

func TestTrackedResponseObserverListenerBoundsConnectionsAndReleasesSlots(t *testing.T) {
	baseListener := bufconn.Listen(1024)
	defer baseListener.Close()
	listener := newTrackedResponseObserverListenerWithLimit(baseListener, 1)

	firstAccepted := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		firstAccepted <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	firstClient, err := baseListener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	first := <-firstAccepted
	if first.err != nil {
		t.Fatalf("first Accept() error = %v", first.err)
	}

	secondDialed := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, dialErr := baseListener.Dial()
		secondDialed <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: dialErr}
	}()
	secondAccepted := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		secondAccepted <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	select {
	case result := <-secondAccepted:
		if result.conn != nil {
			_ = result.conn.Close()
		}
		t.Fatalf("second Accept() bypassed connection limit: %v", result.err)
	case <-time.After(25 * time.Millisecond):
	}

	if err := first.conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case second := <-secondAccepted:
		if second.err != nil {
			t.Fatalf("second Accept() after slot release error = %v", second.err)
		}
		dialed := <-secondDialed
		if dialed.err != nil {
			t.Fatalf("second Dial() error = %v", dialed.err)
		}
		defer dialed.conn.Close()
		if err := second.conn.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("connection slot was not released after Close")
	}
	if got := len(listener.slots); got != 0 {
		t.Fatalf("connection slots after close = %d, want 0", got)
	}
}

func TestTrackedResponseObserverListenerReleasesSlotAfterAcceptError(t *testing.T) {
	listener := newTrackedResponseObserverListenerWithLimit(failingResponseObserverListener{}, 1)
	if _, err := listener.Accept(); err == nil {
		t.Fatal("Accept() unexpectedly succeeded")
	}
	if got := len(listener.slots); got != 0 {
		t.Fatalf("connection slots after failed Accept() = %d, want 0", got)
	}
}

func TestOwnedListenerDoesNotRemoveReplacedSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observer.sock")
	if err := os.WriteFile(path, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	// Model the production listener's pinned filesystem inode in this regular-
	// file stand-in, so remove/create cannot recycle the original identity.
	original, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	info, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	identity := info.Sys().(*syscall.Stat_t)
	parentFile, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	listener := &ownedListener{
		Listener:   replacingResponseObserverListener{path: path},
		path:       path,
		name:       filepath.Base(path),
		dev:        identity.Dev,
		ino:        identity.Ino,
		parentFile: parentFile,
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(info, replacement) {
		t.Fatal("replacement fixture reused the owned file identity")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "replacement" {
		t.Fatalf("replacement socket contents = %q", contents)
	}
}

type closeHookResponseObserverListener struct {
	net.Listener
	afterClose func() error
}

func (listener closeHookResponseObserverListener) Close() error {
	return errors.Join(listener.Listener.Close(), listener.afterClose())
}

func TestOwnedListenerPreservesReplacementDuringClose(t *testing.T) {
	for _, kind := range []string{"file", "socket", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(testSocketDir(t), "observer.sock")
			base, err := secureListener(path)
			if err != nil {
				t.Fatal(err)
			}
			owned := base.(*ownedListener)
			closeFailure := errors.New("injected close failure")
			var replacement net.Listener
			owned.Listener = closeHookResponseObserverListener{Listener: owned.Listener, afterClose: func() error {
				var replaceErr error
				replacement, replaceErr = replaceResponseObserverSocketPath(path, kind)
				return errors.Join(closeFailure, replaceErr)
			}}
			if err := owned.Close(); !errors.Is(err, closeFailure) {
				t.Fatalf("Close() = %v, want injected close failure", err)
			}
			if replacement != nil {
				defer replacement.Close()
			}
			assertResponseObserverReplacement(t, path, kind)
		})
	}
}

func replaceResponseObserverSocketPath(path, kind string) (net.Listener, error) {
	if kind == "symlink" {
		// Its target deliberately has the owned identity.
		if err := os.Rename(path, path+".original"); err != nil {
			return nil, err
		}
	} else if err := os.Remove(path); err != nil {
		return nil, err
	}
	switch kind {
	case "file":
		return nil, os.WriteFile(path, []byte("replacement"), 0600)
	case "socket":
		return net.Listen("unix", path)
	default:
		return nil, os.Symlink(path+".original", path)
	}
}

func assertResponseObserverReplacement(t *testing.T, path, kind string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("replacement %s was removed: %v", kind, err)
	}
	switch kind {
	case "file":
		assertResponseObserverFileContents(t, path, "replacement")
	case "socket":
		if info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("replacement mode = %v, want socket", info.Mode())
		}
	case "symlink":
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("replacement mode = %v, want symlink", info.Mode())
		}
	}
}

func assertResponseObserverFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("file %q contents = %q, %v, want %q", path, data, err, want)
	}
}

func assertResponseObserverFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != want {
		t.Fatalf("file %q = %v, %v, want mode %v", path, info, err, want)
	}
}

func assertResponseObserverPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("path %q = %v, want absent", path, err)
	}
}

func assertResponseObserverFileClosed(t *testing.T, file *os.File, label string) {
	t.Helper()
	if file == nil {
		t.Fatalf("%s descriptor is nil, want a closed descriptor", label)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("%s = %v, want os.ErrClosed", label, err)
	}
}

func openResponseObserverTestParent(t *testing.T, dir string) *os.File {
	t.Helper()
	parent, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	return parent
}

func TestOwnedListenerPinsSocketIdentityUntilCleanup(t *testing.T) {
	path := filepath.Join(testSocketDir(t), "observer.sock")
	base, err := secureListener(path)
	if err != nil {
		t.Fatal(err)
	}
	owned := base.(*ownedListener)
	defer owned.Close()
	original, err := owned.identityFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(original, replacement) {
		t.Fatal("replacement reused pinned socket identity")
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owned.identityFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("identity descriptor after Close() = %v, want os.ErrClosed", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement after Close() = %q, %v, want replacement", data, err)
	}
}

func TestOwnedListenerCleansOwnedSocketAfterCloseFailure(t *testing.T) {
	path := filepath.Join(testSocketDir(t), "observer.sock")
	base, err := secureListener(path)
	if err != nil {
		t.Fatal(err)
	}
	owned := base.(*ownedListener)
	closeFailure := errors.New("injected close failure")
	owned.Listener = closeHookResponseObserverListener{Listener: owned.Listener, afterClose: func() error { return closeFailure }}
	if err := owned.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("Close() = %v, want injected close failure", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket after failed Close() = %v, want absent", err)
	}
	if _, err := owned.identityFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("identity after failed Close() = %v, want os.ErrClosed", err)
	}
}

func TestOwnedListenerRepeatedStartStopAndConcurrentClose(t *testing.T) {
	path := filepath.Join(testSocketDir(t), "observer.sock")
	for restart := 0; restart < 10; restart++ {
		listener, err := secureListener(path)
		if err != nil {
			t.Fatalf("secureListener() restart %d = %v", restart, err)
		}
		var wait sync.WaitGroup
		for closer := 0; closer < 4; closer++ {
			wait.Go(func() {
				if err := listener.Close(); err != nil {
					t.Errorf("Close() restart %d = %v", restart, err)
				}
			})
		}
		wait.Wait()
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("socket after restart %d Close() = %v, want absent", restart, err)
		}
	}
}

func TestSecureListenerPreservesExistingPath(t *testing.T) {
	path := filepath.Join(testSocketDir(t), "observer.sock")
	if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if listener, err := secureListener(path); err == nil {
		_ = listener.Close()
		t.Fatal("secureListener() accepted existing path")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "foreign" {
		t.Fatalf("existing file after secureListener() = %q, %v, want foreign", data, err)
	}
}

func TestOwnedListenerRemovesItsOwnSocketPath(t *testing.T) {
	dir := testSocketDir(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "observer.sock")
	listener, err := secureListener(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket path remains after close: %v", err)
	}
}

func TestOwnedListenerCleanupAnchorsOriginalDirectory(t *testing.T) {
	root := testSocketDir(t)
	dir := filepath.Join(root, "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "observer.sock")
	base, err := secureListener(path)
	if err != nil {
		t.Fatal(err)
	}
	owned := base.(*ownedListener)
	originalDir := filepath.Join(root, "original")
	owned.Listener = closeHookResponseObserverListener{Listener: owned.Listener, afterClose: func() error {
		if err := os.Rename(dir, originalDir); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("foreign"), 0600)
	}}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "foreign" {
		t.Fatalf("redirected path after Close() = %q, %v, want foreign", data, err)
	}
	if _, err := os.Lstat(filepath.Join(originalDir, "observer.sock")); !os.IsNotExist(err) {
		t.Fatalf("original socket after Close() = %v, want absent", err)
	}
	if _, err := owned.parentFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("directory descriptor after Close() = %v, want os.ErrClosed", err)
	}
}

func TestOwnedListenerBindAnchorsValidatedDirectory(t *testing.T) {
	root := testSocketDir(t)
	dir := filepath.Join(root, "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fd), dir)
	originalDir := filepath.Join(root, "original")
	if err := os.Rename(dir, originalDir); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	foreignPath := filepath.Join(dir, "foreign")
	if err := os.WriteFile(foreignPath, []byte("foreign"), 0640); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	path := filepath.Join(dir, "observer.sock")
	listener, err := bindOwnedResponseObserverListener(path, parent)
	if err != nil {
		t.Fatalf("bind after directory replacement = %v, want listener in original directory", err)
	}
	defer listener.Close()
	if got := listener.Addr().String(); got != path {
		t.Fatalf("Addr() = %q, want configured path %q", got, path)
	}
	info, err := os.Lstat(filepath.Join(originalDir, "observer.sock"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("original directory socket = %v, %v, want mode 0600", info, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("replacement directory socket = %v, want absent", err)
	}
	if data, err := os.ReadFile(foreignPath); err != nil || string(data) != "foreign" {
		t.Fatalf("foreign file after bind = %q, %v, want foreign", data, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(originalDir, "observer.sock")); !os.IsNotExist(err) {
		t.Fatalf("original socket after Close() = %v, want absent", err)
	}
}

func TestOwnedListenerBindFailsClosed(t *testing.T) {
	for _, kind := range []string{"existing-file", "oversized-name", "unavailable-descriptor"} {
		t.Run(kind, func(t *testing.T) {
			path, parent, wantEntries := prepareResponseObserverBindFailure(t, kind)
			if listener, err := bindOwnedResponseObserverListener(path, parent); err == nil {
				_ = listener.Close()
				t.Fatalf("bind(%s) succeeded, want failure", kind)
			}
			assertResponseObserverFileClosed(t, parent, "parent after failed bind("+kind+")")
			assertResponseObserverFailedBindPaths(t, path, wantEntries)
		})
	}
}

func prepareResponseObserverBindFailure(t *testing.T, kind string) (string, *os.File, int) {
	t.Helper()
	dir := testSocketDir(t)
	parent := openResponseObserverTestParent(t, dir)
	name := "observer.sock"
	if kind == "oversized-name" {
		name = strings.Repeat("s", 108)
	}
	path := filepath.Join(dir, name)
	switch kind {
	case "existing-file":
		if err := os.WriteFile(path, []byte("foreign"), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0640); err != nil {
			t.Fatal(err)
		}
		return path, parent, 1
	case "unavailable-descriptor":
		if err := parent.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return path, parent, 0
}

func assertResponseObserverFailedBindPaths(t *testing.T, path string, wantEntries int) {
	t.Helper()
	if wantEntries == 1 {
		assertResponseObserverFileContents(t, path, "foreign")
		assertResponseObserverFileMode(t, path, 0640)
	} else {
		assertResponseObserverPathAbsent(t, path)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != wantEntries {
		t.Fatalf("directory after failed bind = %v, want %d original entries and no temporary socket", entries, wantEntries)
	}
}

func TestOwnedListenerPreservesMaximumPublicPathLength(t *testing.T) {
	dir := testSocketDir(t)
	nameLength := len(unix.RawSockaddrUnix{}.Path) - 1 - len(dir) - 1
	if nameLength < 1 {
		t.Fatal("test directory exceeds Linux public socket path capacity")
	}
	path := filepath.Join(dir, strings.Repeat("s", nameLength))
	listener, err := secureListener(path)
	if err != nil {
		t.Fatalf("secureListener(maximum public path) = %v", err)
	}
	defer listener.Close()
	if got := listener.Addr().String(); got != path {
		t.Fatalf("Addr() = %q, want maximum configured path %q", got, path)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial(maximum public path) = %v", err)
	}
	_ = connection.Close()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("directory after maximum path Close() = %v, %v, want empty", entries, err)
	}
}

func TestOwnedListenerIdentityPinFailureCleansOnlyItsOwnTemporarySocket(t *testing.T) {
	for _, kind := range []string{"open-failure", "stat-failure", "type-mismatch", "replacement-preserved"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newResponseObserverPinFailureFixture(t, kind)
			owned, err := ownBoundResponseObserverListener(fixture.base, fixture.parent, filepath.Join(filepath.Dir(fixture.path), "observer.sock"), fixture.name, fixture.openIdentity)
			if err == nil {
				_ = owned.Close()
				t.Fatalf("identity pin(%s) succeeded, want failure", kind)
			}
			assertResponseObserverPinFailureError(t, kind, err)
			fixture.assertCleanup(t)
		})
	}
}

type responseObserverPinFailureFixture struct {
	kind   string
	name   string
	path   string
	base   *net.UnixListener
	parent *os.File
	pinned *os.File
}

func newResponseObserverPinFailureFixture(t *testing.T, kind string) *responseObserverPinFailureFixture {
	t.Helper()
	dir := testSocketDir(t)
	fixture := &responseObserverPinFailureFixture{kind: kind, name: ".observer-test"}
	fixture.path = filepath.Join(dir, fixture.name)
	base, err := net.ListenUnix("unix", &net.UnixAddr{Name: fixture.path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.base = base
	t.Cleanup(func() { _ = base.Close() })
	fixture.parent = openResponseObserverTestParent(t, dir)
	return fixture
}

func (fixture *responseObserverPinFailureFixture) openIdentity(parentFD int, name string) (*os.File, error) {
	switch fixture.kind {
	case "open-failure":
		return nil, unix.EMFILE
	case "replacement-preserved":
		if err := os.Rename(fixture.path, fixture.path+".original"); err != nil {
			return nil, err
		}
		if err := os.WriteFile(fixture.path, []byte("foreign"), 0640); err != nil {
			return nil, err
		}
		return nil, unix.EMFILE
	case "type-mismatch":
		foreign := filepath.Join(filepath.Dir(fixture.path), "foreign")
		if err := os.WriteFile(foreign, []byte("foreign"), 0640); err != nil {
			return nil, err
		}
		pinned, err := os.Open(foreign)
		fixture.pinned = pinned
		return pinned, err
	default:
		pinned, err := openResponseObserverSocketIdentity(parentFD, name)
		fixture.pinned = pinned
		if err == nil {
			err = pinned.Close()
		}
		return pinned, err
	}
}

func assertResponseObserverPinFailureError(t *testing.T, kind string, err error) {
	t.Helper()
	var want error
	switch kind {
	case "open-failure", "replacement-preserved":
		want = unix.EMFILE
	case "stat-failure":
		want = os.ErrClosed
	default:
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("identity pin(%s) = %v, want %v", kind, err, want)
	}
}

func (fixture *responseObserverPinFailureFixture) assertCleanup(t *testing.T) {
	t.Helper()
	if _, err := fixture.base.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after failed pin(%s) = %v, want net.ErrClosed", fixture.kind, err)
	}
	assertResponseObserverFileClosed(t, fixture.parent, "parent after failed pin("+fixture.kind+")")
	if fixture.pinned != nil {
		assertResponseObserverFileClosed(t, fixture.pinned, "inode descriptor after failed pin("+fixture.kind+")")
	}
	if fixture.kind == "replacement-preserved" {
		assertResponseObserverFileContents(t, fixture.path, "foreign")
	} else {
		assertResponseObserverPathAbsent(t, fixture.path)
	}
}

type blockingResponseObserverProbe struct {
	extprocv3.UnimplementedExternalProcessorServer
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (probe *blockingResponseObserverProbe) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	close(probe.started)
	defer close(probe.finished)
	<-probe.release
	return nil
}

func TestServeResponseObserverForcesStopAfterGracefulStopDeadline(t *testing.T) {
	previousTimeout := responseObserverGracefulStopTimeout
	responseObserverGracefulStopTimeout = 10 * time.Millisecond
	defer func() { responseObserverGracefulStopTimeout = previousTimeout }()

	baseListener := bufconn.Listen(1024 * 1024)
	listener := newTrackedResponseObserverListener(baseListener)
	probe := &blockingResponseObserverProbe{
		started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{}),
	}
	server := newResponseObserverGRPCServer(probe)
	signals := make(chan os.Signal, 1)
	result := make(chan error, 1)
	go func() { result <- serveResponseObserver(server, listener, signals) }()

	contextValue, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(
		contextValue,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return baseListener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	stream, err := extprocv3.NewExternalProcessorClient(connection).Process(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&extprocv3.ProcessingRequest{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probe.started:
	case <-contextValue.Done():
		t.Fatal("blocking stream did not start")
	}

	signals <- syscall.SIGTERM
	select {
	case err := <-result:
		if !errors.Is(err, errResponseObserverGracefulStopTimedOut) {
			t.Fatalf("serveResponseObserver error = %v, want graceful-stop timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveResponseObserver did not force-stop the stalled stream")
	}
	close(probe.release)
	select {
	case <-probe.finished:
	case <-time.After(time.Second):
		t.Fatal("stalled stream did not finish after forced stop")
	}
}

func TestServeResponseObserverStopsPreHandshakePeerAfterGracefulStopDeadline(t *testing.T) {
	previousTimeout := responseObserverGracefulStopTimeout
	responseObserverGracefulStopTimeout = 10 * time.Millisecond
	defer func() { responseObserverGracefulStopTimeout = previousTimeout }()

	dir := testSocketDir(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	base, err := secureListener(filepath.Join(dir, "observer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	tracked := newTrackedResponseObserverListener(base)
	tracked.accepted = make(chan struct{})
	listener := &peerCredListener{Listener: tracked, uid: os.Geteuid(), gid: os.Getegid()}
	server := newResponseObserverGRPCServer(&blockingResponseObserverProbe{})
	signals := make(chan os.Signal, 1)
	result := make(chan error, 1)
	go func() { result <- serveResponseObserver(server, listener, signals) }()

	connection, err := net.Dial("unix", filepath.Join(dir, "observer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case <-tracked.accepted:
	case <-time.After(time.Second):
		t.Fatal("pre-handshake peer was not accepted")
	}

	signals <- syscall.SIGTERM
	select {
	case err := <-result:
		if err != nil && !errors.Is(err, errResponseObserverGracefulStopTimedOut) {
			t.Fatalf("serveResponseObserver error = %v, want nil or graceful-stop timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveResponseObserver exceeded its shutdown bound for a pre-handshake peer")
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := connection.Read(make([]byte, 1024))
		if err == nil {
			continue
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatalf("pre-handshake peer was not closed: %v", err)
		}
		break
	}
}

type responseObserverReceiveProbe struct {
	extprocv3.UnimplementedExternalProcessorServer
	received chan int
}

func (probe *responseObserverReceiveProbe) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	probe.received <- len(request.GetResponseBody().GetBody())
	return stream.Send(&extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE},
			},
		},
	})
}

func TestResponseObserverGRPCReceiveLimitAdmitsBoundedResponseBody(t *testing.T) {
	body := make([]byte, 1<<20)
	request := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: body, EndOfStream: true},
		},
	}
	if size := proto.Size(request); size > responseObserverMaxRecvMessageBytes {
		t.Fatalf("bounded response body serializes to %d bytes, receive bound is only %d", size, responseObserverMaxRecvMessageBytes)
	}

	listener := bufconn.Listen(responseObserverMaxRecvMessageBytes + 1024)
	probe := &responseObserverReceiveProbe{received: make(chan int, 1)}
	server := newResponseObserverGRPCServer(probe)
	defer server.Stop()
	go func() { _ = server.Serve(listener) }()
	defer listener.Close()

	contextValue, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(
		contextValue,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial response observer: %v", err)
	}
	defer connection.Close()

	stream, err := extprocv3.NewExternalProcessorClient(connection).Process(contextValue)
	if err != nil {
		t.Fatalf("open response observer stream: %v", err)
	}
	if err := stream.Send(request); err != nil {
		t.Fatalf("send bounded response body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("receive response observer acknowledgement: %v", err)
	}
	select {
	case received := <-probe.received:
		if received != len(body) {
			t.Fatalf("response observer received %d bytes, want %d", received, len(body))
		}
	case <-contextValue.Done():
		t.Fatal("response observer did not receive the bounded body")
	}
}
