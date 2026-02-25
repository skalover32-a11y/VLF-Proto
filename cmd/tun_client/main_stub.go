//go:build !windows

package main

import "log"

func main() {
	log.Fatal("cmd/tun_client is supported only on Windows")
}
