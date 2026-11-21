package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// listenOn opens the milter's listener. release undoes what listening left on
// the filesystem and is safe to call more than once; for TCP it does nothing.
func listenOn(network, address string) (ln net.Listener, release func(), err error) {
	if network != "unix" {
		ln, err = net.Listen(network, address)
		return ln, func() {}, err
	}
	// An abstract socket has no path to check or to clean up, and the
	// checks below would misread its name as one.
	if strings.HasPrefix(address, "@") {
		return nil, nil, errors.New("abstract unix sockets are not supported; use a filesystem path")
	}
	if err := clearStaleSocket(address); err != nil {
		return nil, nil, err
	}
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	// Close would otherwise unlink the path by name, whatever is there by
	// then. Removal is done below, and only of the socket created here.
	ul.SetUnlinkOnClose(false)
	created, err := os.Lstat(address)
	if err != nil {
		_ = ul.Close()
		return nil, nil, err
	}
	return ul, func() { removeIfSame(address, created) }, nil
}

// clearStaleSocket makes way for a unix listener at path, and removes only
// what is provably a dead listener's leftover: a socket that refuses
// connections. Removing whatever sits at the path took a mistyped --listen
// as an instruction to delete that file, and a second instance started on
// the same path unlinked the first one's socket, leaving it running and
// unreachable while Postfix, failing open, delivered mail unstamped.
func clearStaleSocket(path string) error {
	// Lstat: a symbolic link is not a socket, wherever it points.
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket; refusing to remove it", path)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("%s is in use: something is accepting connections on it (another sworn-milter?)", path)
	}
	// Only a refused connection shows that nothing is listening. A timeout
	// or a permission error says nothing about that, so the socket stays.
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot tell whether %s is still in use, so it is left alone: %w", path, err)
	}
	return os.Remove(path)
}

// removeIfSame removes path if it is still the file created describes. A
// socket another process has put there since is not this process's to remove.
func removeIfSame(path string, created fs.FileInfo) {
	if now, err := os.Lstat(path); err == nil && os.SameFile(created, now) {
		_ = os.Remove(path)
	}
}
