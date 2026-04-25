package transit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type Proxy struct {
	cfg     Config
	logger  *zap.Logger
	metrics *Metrics

	errCh chan error

	startedCh   chan struct{}
	startedOnce sync.Once

	shutdownOnce sync.Once
	waitGroup    sync.WaitGroup
	activeConns  sync.Map

	listenersMu  sync.Mutex
	tcpListeners []net.Listener
	udpLanes     []*udpLane
	metricsSrv   *http.Server
}

func NewProxy(cfg Config, logger *zap.Logger) *Proxy {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Proxy{
		cfg:       cfg,
		logger:    logger,
		metrics:   NewMetrics(),
		errCh:     make(chan error, 1),
		startedCh: make(chan struct{}),
	}
}

func (p *Proxy) Metrics() *Metrics {
	return p.metrics
}

// Started returns a channel that is closed once Run has successfully bound all
// configured listeners. Tests and supervisors should wait on this channel
// instead of probing the listen address, which races the bind step and can
// itself cause EADDRINUSE failures (UDP especially).
func (p *Proxy) Started() <-chan struct{} {
	return p.startedCh
}

// tcpListenAddr returns the real bound address for the TCP listener whose
// configured listen-address matches one of the lane configs. Because lanes
// are appended in start() in order (session_tcp, optional relay_tcp, optional
// metrics), we map by lane name through cfg lookup. After Started() this read
// is safe under listenersMu.
func (p *Proxy) tcpListenAddr(name string) string {
	p.listenersMu.Lock()
	defer p.listenersMu.Unlock()
	configured := ""
	switch name {
	case "session_tcp":
		configured = p.cfg.ListenTCP
	case "relay_tcp":
		configured = p.cfg.ListenRelay
	}
	// When configured was "127.0.0.1:0" we cannot match by string; fall back to
	// positional lookup: session_tcp is always index 0, relay_tcp index 1 if
	// EnableRelay, metrics last. Configured-string match handles non-zero ports.
	if configured != "" {
		for _, ln := range p.tcpListeners {
			if ln.Addr().String() == configured {
				return ln.Addr().String()
			}
		}
	}
	switch name {
	case "session_tcp":
		if len(p.tcpListeners) >= 1 {
			return p.tcpListeners[0].Addr().String()
		}
	case "relay_tcp":
		if p.cfg.EnableRelay && len(p.tcpListeners) >= 2 {
			return p.tcpListeners[1].Addr().String()
		}
	}
	return ""
}

// udpListenAddr returns the real bound address for the UDP lane with the given
// name. Lane name is set at construction in startUDPLane.
func (p *Proxy) udpListenAddr(name string) string {
	p.listenersMu.Lock()
	defer p.listenersMu.Unlock()
	for _, lane := range p.udpLanes {
		if lane.name == name {
			return lane.conn.LocalAddr().String()
		}
	}
	return ""
}

func (p *Proxy) Run(ctx context.Context) error {
	if err := p.start(ctx); err != nil {
		_ = p.Shutdown(context.Background())
		return err
	}
	p.startedOnce.Do(func() { close(p.startedCh) })

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeouts.ShutdownTimeout.Duration)
		defer cancel()
		return p.Shutdown(shutdownCtx)
	case err := <-p.errCh:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeouts.ShutdownTimeout.Duration)
		defer cancel()
		_ = p.Shutdown(shutdownCtx)
		return err
	}
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	var shutdownErr error
	p.shutdownOnce.Do(func() {
		p.listenersMu.Lock()
		for _, ln := range p.tcpListeners {
			_ = ln.Close()
		}
		for _, lane := range p.udpLanes {
			lane.Close()
		}
		metricsSrv := p.metricsSrv
		p.listenersMu.Unlock()

		p.activeConns.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})

		if metricsSrv != nil {
			shutdownCtx := ctx
			if shutdownCtx == nil {
				shutdownCtx = context.Background()
			}
			_ = metricsSrv.Shutdown(shutdownCtx)
		}

		done := make(chan struct{})
		go func() {
			p.waitGroup.Wait()
			close(done)
		}()

		waitCtx := ctx
		if waitCtx == nil {
			waitCtx = context.Background()
		}
		select {
		case <-done:
		case <-waitCtx.Done():
			shutdownErr = waitCtx.Err()
		}
	})
	return shutdownErr
}

func (p *Proxy) start(ctx context.Context) error {
	if err := p.startTCPListener(ctx, "session_tcp", p.cfg.ListenTCP, p.cfg.BackendTCP); err != nil {
		return err
	}
	if err := p.startUDPLane(ctx, "session_udp", p.cfg.ListenUDP, p.cfg.BackendUDP); err != nil {
		return err
	}
	if p.cfg.ListenUDPAlt != "" && p.cfg.ListenUDPAlt != p.cfg.ListenUDP {
		if err := p.startUDPLane(ctx, "session_udp_alt", p.cfg.ListenUDPAlt, p.cfg.BackendUDP); err != nil {
			return err
		}
	}
	if p.cfg.EnableRelay {
		if err := p.startTCPListener(ctx, "relay_tcp", p.cfg.ListenRelay, p.cfg.BackendRelay); err != nil {
			return err
		}
	}
	if p.cfg.EnableMetrics {
		if err := p.startMetricsServer(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *Proxy) startTCPListener(ctx context.Context, lane string, listenAddr string, backendAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s on %s: %w", lane, listenAddr, err)
	}
	p.listenersMu.Lock()
	p.tcpListeners = append(p.tcpListeners, ln)
	p.listenersMu.Unlock()
	p.logger.Info("transit TCP lane listening", zap.String("lane", lane), zap.String("listen_addr", ln.Addr().String()), zap.String("backend_addr", backendAddr))
	p.waitGroup.Add(1)
	go p.acceptLoop(ctx, lane, ln, backendAddr)
	return nil
}

func (p *Proxy) acceptLoop(ctx context.Context, lane string, ln net.Listener, backendAddr string) {
	defer p.waitGroup.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			p.metrics.AcceptErrors.WithLabelValues(lane).Inc()
			p.logger.Warn("transit accept failed", zap.String("lane", lane), zap.Error(err))
			continue
		}
		p.waitGroup.Add(1)
		go p.handleTCPConn(ctx, lane, conn, backendAddr)
	}
}

func (p *Proxy) handleTCPConn(ctx context.Context, lane string, clientConn net.Conn, backendAddr string) {
	defer p.waitGroup.Done()
	defer clientConn.Close()
	p.trackConn(clientConn)
	defer p.untrackConn(clientConn)

	p.metrics.ActiveTCPConns.WithLabelValues(lane).Inc()
	p.metrics.SessionsOpened.WithLabelValues(lane).Inc()
	defer p.metrics.ActiveTCPConns.WithLabelValues(lane).Dec()
	defer p.metrics.SessionsClosed.WithLabelValues(lane, "closed").Inc()

	setTCPKeepAlive(clientConn)

	dialer := net.Dialer{Timeout: p.cfg.Timeouts.DialTimeout.Duration, KeepAlive: 30 * time.Second}
	backendConn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		p.metrics.DialFailures.WithLabelValues(lane).Inc()
		p.logger.Warn("transit backend dial failed", zap.String("lane", lane), zap.String("backend_addr", backendAddr), zap.Error(err))
		return
	}
	defer backendConn.Close()
	p.trackConn(backendConn)
	defer p.untrackConn(backendConn)
	setTCPKeepAlive(backendConn)

	errCh := make(chan error, 2)
	go func() {
		_, copyErr := p.copyStream(backendConn, clientConn, p.metrics.BytesIn.WithLabelValues(lane))
		closeWrite(backendConn)
		errCh <- copyErr
	}()
	go func() {
		_, copyErr := p.copyStream(clientConn, backendConn, p.metrics.BytesOut.WithLabelValues(lane))
		closeWrite(clientConn)
		errCh <- copyErr
	}()

	firstErr := <-errCh
	_ = clientConn.Close()
	_ = backendConn.Close()
	secondErr := <-errCh
	if err := firstMeaningfulError(firstErr, secondErr); err != nil {
		p.logger.Debug("transit TCP session finished", zap.String("lane", lane), zap.Error(err))
	}
}

func (p *Proxy) copyStream(dst net.Conn, src net.Conn, counter interface{ Add(float64) }) (int64, error) {
	n, err := io.Copy(dst, src)
	if n > 0 {
		counter.Add(float64(n))
	}
	return n, err
}

func (p *Proxy) startUDPLane(ctx context.Context, lane string, listenAddr string, backendAddr string) error {
	listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve %s listen addr %s: %w", lane, listenAddr, err)
	}
	backendUDPAddr, err := net.ResolveUDPAddr("udp", backendAddr)
	if err != nil {
		return fmt.Errorf("resolve %s backend addr %s: %w", lane, backendAddr, err)
	}
	conn, err := net.ListenUDP("udp", listenUDPAddr)
	if err != nil {
		return fmt.Errorf("listen %s on %s: %w", lane, listenAddr, err)
	}
	udpLane := newUDPLane(lane, conn, backendUDPAddr, p.cfg.Timeouts.UDPIdle.Duration, p.metrics, p.logger)
	p.listenersMu.Lock()
	p.udpLanes = append(p.udpLanes, udpLane)
	p.listenersMu.Unlock()
	p.logger.Info("transit UDP lane listening", zap.String("lane", lane), zap.String("listen_addr", conn.LocalAddr().String()), zap.String("backend_addr", backendAddr))
	p.waitGroup.Add(1)
	go func() {
		defer p.waitGroup.Done()
		udpLane.Run(ctx)
	}()
	return nil
}

func (p *Proxy) startMetricsServer(ctx context.Context) error {
	srv := &http.Server{
		Addr:              p.cfg.MetricsListen,
		Handler:           p.metrics.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", p.cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("listen metrics on %s: %w", p.cfg.MetricsListen, err)
	}
	p.listenersMu.Lock()
	p.metricsSrv = srv
	p.tcpListeners = append(p.tcpListeners, ln)
	p.listenersMu.Unlock()
	p.logger.Info("transit metrics listening", zap.String("listen_addr", ln.Addr().String()))
	p.waitGroup.Add(1)
	go func() {
		defer p.waitGroup.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			select {
			case p.errCh <- fmt.Errorf("metrics server: %w", err):
			default:
			}
		}
	}()
	return nil
}

type udpLane struct {
	name        string
	conn        *net.UDPConn
	backendAddr *net.UDPAddr
	idleTimeout time.Duration
	metrics     *Metrics
	logger      *zap.Logger

	mu        sync.Mutex
	sessions  map[string]*udpSession
	closed    atomic.Bool
	waitGroup sync.WaitGroup
}

type udpSession struct {
	clientAddr  *net.UDPAddr
	backendConn *net.UDPConn
	lastSeen    atomic.Int64
	closeOnce   sync.Once
}

func newUDPLane(name string, conn *net.UDPConn, backendAddr *net.UDPAddr, idleTimeout time.Duration, metrics *Metrics, logger *zap.Logger) *udpLane {
	return &udpLane{
		name:        name,
		conn:        conn,
		backendAddr: backendAddr,
		idleTimeout: idleTimeout,
		metrics:     metrics,
		logger:      logger,
		sessions:    make(map[string]*udpSession),
	}
}

func (l *udpLane) Run(ctx context.Context) {
	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || l.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			l.metrics.AcceptErrors.WithLabelValues(l.name).Inc()
			l.logger.Warn("transit UDP read failed", zap.String("lane", l.name), zap.Error(err))
			continue
		}
		l.metrics.BytesIn.WithLabelValues(l.name).Add(float64(n))
		l.metrics.PacketsIn.WithLabelValues(l.name).Inc()

		session, err := l.getOrCreateSession(ctx, clientAddr)
		if err != nil {
			l.metrics.DialFailures.WithLabelValues(l.name).Inc()
			l.logger.Warn("transit UDP backend dial failed", zap.String("lane", l.name), zap.String("client_addr", clientAddr.String()), zap.String("backend_addr", l.backendAddr.String()), zap.Error(err))
			continue
		}
		session.touch()
		if _, err := session.backendConn.Write(buf[:n]); err != nil {
			l.logger.Warn("transit UDP write to backend failed", zap.String("lane", l.name), zap.String("client_addr", clientAddr.String()), zap.Error(err))
			l.closeSession(clientAddr.String(), session, "backend_write_error")
		}
	}
}

func (l *udpLane) Close() {
	if !l.closed.CompareAndSwap(false, true) {
		return
	}
	_ = l.conn.Close()
	l.mu.Lock()
	sessions := make(map[string]*udpSession, len(l.sessions))
	for key, session := range l.sessions {
		sessions[key] = session
	}
	l.sessions = make(map[string]*udpSession)
	l.mu.Unlock()
	for key, session := range sessions {
		session.closeOnce.Do(func() {
			l.finalizeSession(key, session, "shutdown")
		})
	}
	l.waitGroup.Wait()
}

func (l *udpLane) getOrCreateSession(ctx context.Context, clientAddr *net.UDPAddr) (*udpSession, error) {
	key := clientAddr.String()
	l.mu.Lock()
	if session, ok := l.sessions[key]; ok {
		l.mu.Unlock()
		return session, nil
	}
	backendConn, err := net.DialUDP("udp", nil, l.backendAddr)
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	session := &udpSession{clientAddr: cloneUDPAddr(clientAddr), backendConn: backendConn}
	session.touch()
	l.sessions[key] = session
	l.metrics.ActiveUDPSessions.WithLabelValues(l.name).Inc()
	l.metrics.SessionsOpened.WithLabelValues(l.name).Inc()
	l.mu.Unlock()

	l.waitGroup.Add(1)
	go l.pipeBackendToClient(ctx, key, session)
	return session, nil
}

func (l *udpLane) pipeBackendToClient(ctx context.Context, key string, session *udpSession) {
	defer l.waitGroup.Done()
	buf := make([]byte, 64*1024)
	readWindow := l.idleTimeout / 2
	if readWindow < 5*time.Second {
		readWindow = 5 * time.Second
	}
	for {
		_ = session.backendConn.SetReadDeadline(time.Now().Add(readWindow))
		n, err := session.backendConn.Read(buf)
		if err != nil {
			if ctx.Err() != nil || l.closed.Load() || errors.Is(err, net.ErrClosed) {
				l.closeSession(key, session, "shutdown")
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if session.idleFor() >= l.idleTimeout {
					l.closeSession(key, session, "idle_timeout")
					return
				}
				continue
			}
			l.logger.Warn("transit UDP read from backend failed", zap.String("lane", l.name), zap.String("client_addr", session.clientAddr.String()), zap.Error(err))
			l.closeSession(key, session, "backend_read_error")
			return
		}
		session.touch()
		if _, err := l.conn.WriteToUDP(buf[:n], session.clientAddr); err != nil {
			l.logger.Warn("transit UDP write to client failed", zap.String("lane", l.name), zap.String("client_addr", session.clientAddr.String()), zap.Error(err))
			l.closeSession(key, session, "client_write_error")
			return
		}
		l.metrics.BytesOut.WithLabelValues(l.name).Add(float64(n))
		l.metrics.PacketsOut.WithLabelValues(l.name).Inc()
	}
}

func (l *udpLane) closeSession(key string, session *udpSession, reason string) {
	session.closeOnce.Do(func() {
		l.mu.Lock()
		delete(l.sessions, key)
		l.mu.Unlock()
		l.finalizeSession(key, session, reason)
	})
}

func (l *udpLane) finalizeSession(_ string, session *udpSession, reason string) {
	session.close()
	l.metrics.ActiveUDPSessions.WithLabelValues(l.name).Dec()
	l.metrics.SessionsClosed.WithLabelValues(l.name, reason).Inc()
}

func (s *udpSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *udpSession) idleFor() time.Duration {
	last := s.lastSeen.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
}

func (s *udpSession) close() {
	_ = s.backendConn.Close()
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	copyAddr := *addr
	if addr.IP != nil {
		copyAddr.IP = append(net.IP(nil), addr.IP...)
	}
	return &copyAddr
}

func setTCPKeepAlive(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if conn == nil {
		return
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (p *Proxy) trackConn(conn net.Conn) {
	if conn != nil {
		p.activeConns.Store(conn, struct{}{})
	}
}

func (p *Proxy) untrackConn(conn net.Conn) {
	if conn != nil {
		p.activeConns.Delete(conn)
	}
}

func firstMeaningfulError(errs ...error) error {
	for _, err := range errs {
		if isMeaningfulNetErr(err) {
			return err
		}
	}
	return nil
}

func isMeaningfulNetErr(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNRESET) || errors.Is(opErr.Err, syscall.EPIPE) {
			return false
		}
	}
	return true
}
