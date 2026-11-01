//go:build linux

package responseobserver

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func peerTestID(value int) *int {
	return &value
}

func TestDialWithExpectedPeerRejectsMismatchBeforeClaim(t *testing.T) {
	path := filepath.Join(testSocketDir(t), "companion.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	readCount := make(chan int, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			readCount <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1)
		n, _ := conn.Read(buffer)
		readCount <- n
	}()

	mismatchedUID := os.Geteuid() ^ 1
	client, err := dialWithExpectedPeer(path, time.Second, mismatchedUID, os.Getegid())
	if err == nil {
		_ = client.close()
		t.Fatal("dialWithExpectedPeer accepted a mismatched companion UID")
	}
	if got := <-readCount; got != 0 {
		t.Fatalf("companion received %d bytes before peer rejection, want 0", got)
	}
}

func TestExpectedResponseCompanionPeerCredentials(t *testing.T) {
	uid, gid, err := expectedResponseCompanionPeerCredentials(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if uid != os.Geteuid() || gid != os.Getegid() {
		t.Fatalf("default peer identity = %d:%d, want %d:%d", uid, gid, os.Geteuid(), os.Getegid())
	}

	expectedUID := os.Geteuid()
	expectedGID := os.Getegid()
	uid, gid, err = expectedResponseCompanionPeerCredentials(Config{
		ExpectedPeerUID: peerTestID(expectedUID),
		ExpectedPeerGID: peerTestID(expectedGID),
	})
	if err != nil || uid != expectedUID || gid != expectedGID {
		t.Fatalf("explicit peer identity = %d:%d, %v", uid, gid, err)
	}
	if _, _, err := expectedResponseCompanionPeerCredentials(Config{
		ExpectedPeerUID: peerTestID(expectedUID),
	}); err == nil {
		t.Fatal("accepted incomplete expected peer identity")
	}
	negative := -1
	if _, _, err := expectedResponseCompanionPeerCredentials(Config{
		ExpectedPeerUID: peerTestID(negative),
		ExpectedPeerGID: peerTestID(expectedGID),
	}); err == nil {
		t.Fatal("accepted negative expected peer UID")
	}
}
