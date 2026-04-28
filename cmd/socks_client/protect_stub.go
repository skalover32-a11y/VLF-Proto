//go:build !linux

package main

import "syscall"

func initAndroidProtect() {}

func makeDialControl() func(network, address string, c syscall.RawConn) error {
	return nil
}
