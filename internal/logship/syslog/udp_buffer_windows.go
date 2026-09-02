//go:build windows

package syslog

import (
	"net"
	"syscall"
)

func effectiveUDPReceiveBuffer(conn *net.UDPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var value int
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		value, controlErr = syscall.GetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return value, controlErr
}
