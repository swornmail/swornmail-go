package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// socketDir is a short-lived directory with a short name: a unix socket path
// is limited to about a hundred octets, which t.TempDir can exceed.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// staleSocket leaves behind what a killed listener does: a socket file that
// nothing accepts on.
func staleSocket(t *testing.T, path string) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("test bug: no stale socket left behind: %v", err)
	}
}

func TestListenOnFreshUnixPath(t *testing.T) {
	path := filepath.Join(socketDir(t), "s")
	ln, release, err := listenOn("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the new socket does not accept connections: %v", err)
	}
	_ = conn.Close()
	release()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("release left the socket behind: %v", err)
	}
	release() // a second call has nothing left to do and must not fail
}

// A killed milter leaves its socket file; the next start has to get past it.
func TestListenOnReplacesAStaleSocket(t *testing.T) {
	path := filepath.Join(socketDir(t), "s")
	staleSocket(t, path)
	ln, release, err := listenOn("unix", path)
	if err != nil {
		t.Fatalf("a stale socket blocked startup: %v", err)
	}
	defer ln.Close()
	defer release()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the new socket does not accept connections: %v", err)
	}
	_ = conn.Close()
}

// A mistyped --listen unix: path must not be read as "delete this file".
func TestListenOnRefusesToRemoveWhatIsNotASocket(t *testing.T) {
	dir := socketDir(t)
	file := filepath.Join(dir, "main.cf")
	if err := os.WriteFile(file, []byte("smtpd_milters = ..."), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// A link to a dead socket is still a link: following it would remove or
	// shadow something other than the path that was named.
	stale := filepath.Join(dir, "stale")
	staleSocket(t, stale)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(stale, link); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}

	for name, path := range map[string]string{"regular file": file, "directory": sub, "symbolic link": link} {
		ln, _, err := listenOn("unix", path)
		if err == nil {
			_ = ln.Close()
			t.Errorf("%s: listening on it succeeded", name)
			continue
		}
		if !strings.Contains(err.Error(), "not a socket") {
			t.Errorf("%s: error does not say why: %v", name, err)
		}
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != "smtpd_milters = ..." {
		t.Errorf("the regular file was touched: %q, %v", got, err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the symbolic link was removed: %v", err)
	}
	if _, err := os.Lstat(stale); err != nil {
		t.Errorf("the link's target was removed: %v", err)
	}
}

// A second instance started on the path of a running one must not unlink the
// first one's socket: that leaves the first running and unreachable, and
// Postfix, failing open, delivers mail unstamped with forged results intact.
func TestListenOnRefusesALiveSocket(t *testing.T) {
	path := filepath.Join(socketDir(t), "s")
	first, release, err := listenOn("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer release()
	go func() {
		for {
			conn, err := first.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	second, _, err := listenOn("unix", path)
	if err == nil {
		_ = second.Close()
		t.Fatal("a second listener took over a socket in use")
	}
	if !strings.Contains(err.Error(), "in use") {
		t.Errorf("error does not say the socket is in use: %v", err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the first instance is no longer reachable: %v", err)
	}
	_ = conn.Close()
}

// Closing the listener must not unlink the path by name: by then the path may
// hold something else.
func TestCloseDoesNotUnlinkByName(t *testing.T) {
	path := filepath.Join(socketDir(t), "s")
	ln, release, err := listenOn("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("closing the listener removed the socket by name: %v", err)
	}
}

// On shutdown only the socket this process created is removed. If the path
// has been taken over since, what is there now belongs to someone else.
//
// The first listener stays open while the path is replaced, as it is in the
// milter, which releases before it closes. That also keeps the first
// socket's inode in use, so the replacement cannot be handed the same one
// and be mistaken for it.
func TestReleaseLeavesASocketItDidNotCreate(t *testing.T) {
	path := filepath.Join(socketDir(t), "s")
	ln, release, err := listenOn("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Someone else replaces the path.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	release()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("release removed a socket this process did not create: %v", err)
	}
	_ = conn.Close()
}

func TestListenOnTCPNeedsNoCleanup(t *testing.T) {
	ln, release, err := listenOn("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	release()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("release disturbed a TCP listener: %v", err)
	}
	_ = conn.Close()
}

// An abstract socket name is not a path: there is nothing to check for a
// stale listener and nothing to remove afterwards, so it is refused outright
// rather than half-handled.
func TestListenOnRefusesAnAbstractSocket(t *testing.T) {
	ln, _, err := listenOn("unix", "@sworn-milter")
	if err == nil {
		ln.Close()
		t.Fatal("abstract socket accepted")
	}
}
