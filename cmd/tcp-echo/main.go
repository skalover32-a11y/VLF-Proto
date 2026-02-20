package main

import (
	"io"
	"log"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatalf("listen tcp: %v", err)
	}
	log.Printf("tcp echo listening on :9000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(conn)
	}
}
