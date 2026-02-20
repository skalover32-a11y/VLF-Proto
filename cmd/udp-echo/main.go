package main

import (
	"log"
	"net"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", ":9001")
	if err != nil {
		log.Fatalf("resolve udp addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	log.Printf("udp echo listening on :9001")

	buf := make([]byte, 64*1024)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}

		if _, err := conn.WriteToUDP(buf[:n], peer); err != nil {
			log.Printf("write error: %v", err)
		}
	}
}
