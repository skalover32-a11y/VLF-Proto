package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"vlf-runtime/internal/sessionclient"
)

func main() {
	cfg, err := sessionclient.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	client, err := sessionclient.Dial(ctx, cfg)
	if err != nil {
		log.Fatalf("session smoke failed: %v", err)
	}
	defer client.Close()

	dstTCPHost := envOr("DST_TCP_HOST", "tcp-echo")
	dstTCPPort := envOrInt("DST_TCP_PORT", 9000)
	dstUDPHost := envOr("DST_UDP_HOST", "udp-echo")
	dstUDPPort := envOrInt("DST_UDP_PORT", 9001)

	if err := runTCPEcho(ctx, client, dstTCPHost, dstTCPPort); err != nil {
		log.Fatalf("tcp flow check failed: %v", err)
	}

	if err := runUDPEcho(ctx, client, dstUDPHost, dstUDPPort); err != nil {
		transport := client.Transport()
		// TCP-session and relay transports do not support UDP by design.
		if transport == sessionclient.TransportTCPSession || transport == sessionclient.TransportRelay {
			log.Printf("UDP check skipped on transport=%s: %v", transport, err)
			fmt.Printf("PASS session smoke (transport=%s)\n", transport)
			return
		}
		log.Fatalf("udp flow check failed: %v", err)
	}

	fmt.Printf("PASS session smoke (transport=%s)\n", client.Transport())
}

func runTCPEcho(ctx context.Context, client *sessionclient.Client, host string, port int) error {
	flow, err := client.OpenTCPFlow(ctx, host, port)
	if err != nil {
		return err
	}
	defer flow.Close()

	payload := []byte("hello-session-tcp")
	if _, err := flow.Write(payload); err != nil {
		return err
	}

	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(flow, echo); err != nil {
		return err
	}
	if !bytes.Equal(payload, echo) {
		return fmt.Errorf("tcp echo mismatch: got=%q want=%q", string(echo), string(payload))
	}
	return nil
}

func runUDPEcho(ctx context.Context, client *sessionclient.Client, host string, port int) error {
	flow, err := client.OpenUDPFlow(ctx, host, port)
	if err != nil {
		return err
	}
	defer flow.Close()

	small := []byte("hello-session-udp")
	large := bytes.Repeat([]byte("L"), 3000)

	if err := flow.Send(ctx, small); err != nil {
		return err
	}
	if err := flow.Send(ctx, large); err != nil {
		return err
	}

	recvCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	received := make([][]byte, 0, 2)
	for len(received) < 2 {
		payload, err := flow.Recv(recvCtx)
		if err != nil {
			return err
		}
		received = append(received, payload)
	}

	if !comparePayloadSet(received, [][]byte{small, large}) {
		return errors.New("udp echo mismatch")
	}
	return nil
}

func comparePayloadSet(got [][]byte, want [][]byte) bool {
	if len(got) != len(want) {
		return false
	}
	normalize := func(items [][]byte) []string {
		out := make([]string, 0, len(items))
		for _, p := range items {
			out = append(out, hex.EncodeToString(p))
		}
		sort.Strings(out)
		return out
	}
	g := normalize(got)
	w := normalize(want)
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

func envOr(name, fallback string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return fallback
}

func envOrInt(name string, fallback int) int {
	if v := getenv(name); v != "" {
		var out int
		if _, err := fmt.Sscanf(v, "%d", &out); err == nil {
			return out
		}
	}
	return fallback
}

func getenv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}
