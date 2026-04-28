//go:build linux

package main

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var androidProtectSocket string

func initAndroidProtect() {
	androidProtectSocket = os.Getenv("VLF_ANDROID_PROTECT_SOCKET")
}

// makeDialControl returns a Control function for net.Dialer/net.ListenConfig that
// sends each outbound socket FD to the Android VPN service for protect() before
// the underlying connect(). Returns nil when not on Android (env var unset).
func makeDialControl() func(network, address string, c syscall.RawConn) error {
	path := androidProtectSocket
	if path == "" {
		return nil
	}
	// Android abstract namespace: "@name" -> "\x00name" in Go net package
	if len(path) > 0 && path[0] == '@' {
		path = "\x00" + path[1:]
	}
	return func(network, address string, c syscall.RawConn) error {
		var innerErr error
		_ = c.Control(func(fd uintptr) {
			innerErr = protectFd(path, int(fd))
		})
		// Non-fatal: worst case the VPN service detects the loop via startup probe.
		_ = innerErr
		return nil
	}
}

// protectFd connects to the VPN service's abstract Unix socket, sends the socket
// FD via SCM_RIGHTS, and waits for a 1-byte ACK. Unix domain sockets are not
// captured by the VPN tunnel, so this call itself bypasses routing safely.
func protectFd(unixPath string, fd int) error {
	conn, err := net.Dial("unix", unixPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	uc := conn.(*net.UnixConn)
	rights := unix.UnixRights(fd)
	if _, _, err = uc.WriteMsgUnix([]byte{1}, rights, nil); err != nil {
		return err
	}
	ack := make([]byte, 1)
	_, _ = uc.Read(ack)
	return nil
}
