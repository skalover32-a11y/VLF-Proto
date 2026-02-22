package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/sessionclient"
)

const (
	socksVer5 = 0x05

	socksMethodNoAuth       = 0x00
	socksMethodNoAcceptable = 0xff

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksReplySuccess            = 0x00
	socksReplyGeneralFailure     = 0x01
	socksReplyHostUnreachable    = 0x04
	socksReplyCommandUnsupported = 0x07
	socksReplyAddrUnsupported    = 0x08
)

type socksTarget struct {
	Host string
	Port int
}

func main() {
	baseCfg, err := sessionclient.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load session config: %v", err)
	}

	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	serverHost := flag.String("server", baseCfg.GatewayHost, "gateway host")
	serverPort := flag.Int("port", baseCfg.GatewayUDP, "gateway port for QUIC and TCP session lanes")
	relayBase := flag.String("relay-base", baseCfg.RelayBase, "relay base URL (fallback)")
	connectTimeout := flag.Duration("connect-timeout", 10*time.Second, "dial/open timeout per CONNECT")
	preferQUIC := flag.Bool("prefer-quic", baseCfg.PreferQUIC, "prefer QUIC transport first")
	disableQUIC := flag.Bool("disable-quic", baseCfg.DisableQUIC, "disable QUIC transport")
	disableTCP := flag.Bool("disable-tcp-session", baseCfg.DisableTCPSession, "disable TCP session transport")
	allowRelay := flag.Bool("allow-relay-fallback", baseCfg.AllowRelay, "allow HTTP relay fallback")
	clientID := flag.String("client-id", "", "override client id")
	secret := flag.String("secret", "", "override secret (plain or b64:...)")
	debug := flag.Bool("debug", baseCfg.Debug, "enable sessionclient debug logs")
	flag.Parse()

	if *serverPort <= 0 || *serverPort > 65535 {
		log.Fatalf("invalid --port=%d", *serverPort)
	}
	if *connectTimeout <= 0 {
		*connectTimeout = 10 * time.Second
	}

	cfg := baseCfg
	cfg.GatewayHost = *serverHost
	cfg.GatewayUDP = *serverPort
	cfg.GatewayTCP = *serverPort
	cfg.RelayBase = *relayBase
	cfg.PreferQUIC = *preferQUIC
	cfg.DisableQUIC = *disableQUIC
	cfg.DisableTCPSession = *disableTCP
	cfg.AllowRelay = *allowRelay
	cfg.Debug = *debug

	if *clientID != "" {
		cfg.ClientID = *clientID
	}
	if *secret != "" {
		parsedSecret, parseErr := auth.ParseSecretString(*secret)
		if parseErr != nil {
			log.Fatalf("parse --secret: %v", parseErr)
		}
		cfg.Secret = parsedSecret
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	log.Printf("SOCKS5 listening on %s", *listenAddr)
	log.Printf("Gateway=%s:%d prefer_quic=%t disable_quic=%t disable_tcp=%t allow_relay=%t", cfg.GatewayHost, *serverPort, cfg.PreferQUIC, cfg.DisableQUIC, cfg.DisableTCPSession, cfg.AllowRelay)

	var wg sync.WaitGroup
	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				break
			}
			var ne net.Error
			if errors.As(acceptErr, &ne) && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Printf("accept failed: %v", acceptErr)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleConn(c, cfg, *connectTimeout)
		}(conn)
	}

	wg.Wait()
	log.Printf("SOCKS5 stopped")
}

func handleConn(conn net.Conn, cfg sessionclient.Config, connectTimeout time.Duration) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := negotiateSOCKS5(conn)
	if err != nil {
		log.Printf("SOCKS handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	dialCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	client, err := sessionclient.Dial(dialCtx, cfg)
	cancel()
	if err != nil {
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		log.Printf("session dial failed for %s -> %s:%d: %v", conn.RemoteAddr(), target.Host, target.Port, err)
		return
	}

	openCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	flow, err := client.OpenTCPFlow(openCtx, target.Host, target.Port)
	cancel()
	if err != nil {
		_ = writeSocksReply(conn, socksReplyHostUnreachable)
		_ = client.Close()
		log.Printf("open tcp flow failed for %s -> %s:%d: %v", conn.RemoteAddr(), target.Host, target.Port, err)
		return
	}

	if err := writeSocksReply(conn, socksReplySuccess); err != nil {
		_ = flow.Close()
		_ = client.Close()
		log.Printf("failed to send SOCKS success reply to %s: %v", conn.RemoteAddr(), err)
		return
	}

	log.Printf("proxy CONNECT %s -> %s:%d via %s", conn.RemoteAddr(), target.Host, target.Port, client.Transport())
	proxyBidirectional(conn, flow, client)
}

func negotiateSOCKS5(conn net.Conn) (socksTarget, error) {
	var greetHdr [2]byte
	if _, err := io.ReadFull(conn, greetHdr[:]); err != nil {
		return socksTarget{}, fmt.Errorf("read greeting header: %w", err)
	}
	if greetHdr[0] != socksVer5 {
		return socksTarget{}, fmt.Errorf("unsupported SOCKS version: %d", greetHdr[0])
	}

	nMethods := int(greetHdr[1])
	if nMethods <= 0 {
		return socksTarget{}, errors.New("no auth methods provided")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return socksTarget{}, fmt.Errorf("read methods: %w", err)
	}

	acceptNoAuth := false
	for _, m := range methods {
		if m == socksMethodNoAuth {
			acceptNoAuth = true
			break
		}
	}
	if !acceptNoAuth {
		_ = writeMethodSelection(conn, socksMethodNoAcceptable)
		return socksTarget{}, errors.New("client does not support no-auth")
	}
	if err := writeMethodSelection(conn, socksMethodNoAuth); err != nil {
		return socksTarget{}, fmt.Errorf("write method selection: %w", err)
	}

	var reqHdr [4]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
		return socksTarget{}, fmt.Errorf("read request header: %w", err)
	}
	if reqHdr[0] != socksVer5 {
		return socksTarget{}, fmt.Errorf("invalid request version: %d", reqHdr[0])
	}
	if reqHdr[1] != socksCmdConnect {
		_ = writeSocksReply(conn, socksReplyCommandUnsupported)
		return socksTarget{}, fmt.Errorf("unsupported cmd: %d", reqHdr[1])
	}

	host, err := readTargetHost(conn, reqHdr[3])
	if err != nil {
		_ = writeSocksReply(conn, socksReplyAddrUnsupported)
		return socksTarget{}, err
	}

	var portRaw [2]byte
	if _, err := io.ReadFull(conn, portRaw[:]); err != nil {
		return socksTarget{}, fmt.Errorf("read target port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portRaw[:]))
	if port <= 0 {
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		return socksTarget{}, errors.New("invalid target port")
	}

	return socksTarget{Host: host, Port: port}, nil
}

func readTargetHost(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		var ipRaw [4]byte
		if _, err := io.ReadFull(conn, ipRaw[:]); err != nil {
			return "", fmt.Errorf("read ipv4: %w", err)
		}
		return net.IP(ipRaw[:]).String(), nil
	case socksAtypIPv6:
		var ipRaw [16]byte
		if _, err := io.ReadFull(conn, ipRaw[:]); err != nil {
			return "", fmt.Errorf("read ipv6: %w", err)
		}
		return net.IP(ipRaw[:]).String(), nil
	case socksAtypDomain:
		var lnRaw [1]byte
		if _, err := io.ReadFull(conn, lnRaw[:]); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		ln := int(lnRaw[0])
		if ln <= 0 {
			return "", errors.New("empty domain")
		}
		hostRaw := make([]byte, ln)
		if _, err := io.ReadFull(conn, hostRaw); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		return string(hostRaw), nil
	default:
		return "", fmt.Errorf("unsupported atyp: %d", atyp)
	}
}

func writeMethodSelection(conn net.Conn, method byte) error {
	_, err := conn.Write([]byte{socksVer5, method})
	return err
}

func writeSocksReply(conn net.Conn, reply byte) error {
	// BND.ADDR/BND.PORT are not used by CONNECT client in this MVP.
	out := []byte{
		socksVer5,
		reply,
		0x00,
		socksAtypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	_, err := conn.Write(out)
	return err
}

func proxyBidirectional(local net.Conn, remote sessionclient.TCPFlow, client *sessionclient.Client) {
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = local.Close()
			_ = remote.Close()
			_ = client.Close()
		})
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, local)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(local, remote)
		errCh <- err
	}()

	first := <-errCh
	closeAll()
	second := <-errCh

	if !isExpectedPipeErr(first) {
		log.Printf("proxy copy ended with error: %v", first)
	}
	if !isExpectedPipeErr(second) {
		log.Printf("proxy copy ended with error: %v", second)
	}
}

func isExpectedPipeErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := err.Error()
	return msg == "use of closed network connection" || msg == "EOF"
}
