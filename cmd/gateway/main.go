package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/config"
	"vlf-runtime/internal/limits"
	"vlf-runtime/internal/metrics"
	"vlf-runtime/internal/relay"
	"vlf-runtime/internal/session"
)

func main() {
	cfgPath := flag.String("config", "config/config.yaml", "Path to gateway YAML config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	if cfg.TLS.AutoGenerate {
		if err := config.EnsureSelfSigned(cfg.TLS.CertPath, cfg.TLS.KeyPath, []string{"localhost", "gateway", "127.0.0.1"}); err != nil {
			logger.Fatal("auto-generate TLS cert failed", zap.Error(err))
		}
	}

	tlsCert, err := tls.LoadX509KeyPair(cfg.TLS.CertPath, cfg.TLS.KeyPath)
	if err != nil {
		logger.Fatal("load TLS cert failed", zap.Error(err))
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{cfg.ProtocolID},
	}

	m := metrics.New()
	defer m.Close()

	secretProvider, err := auth.NewStaticSecretProvider(cfg.ClientSecrets)
	if err != nil {
		logger.Fatal("invalid client secret format", zap.Error(err))
	}
	replayCache := auth.NewReplayCache(cfg.Auth.ReplayTTL.Duration)
	verifier := auth.NewVerifier(secretProvider, replayCache, cfg.Auth.ClockSkew.Duration, auth.VerifyHooks{
		OnAuthFail: func(_ string) {
			m.AuthFailures.Inc()
		},
		OnReplayDrop: func(_ string) {
			m.ReplayDrops.Inc()
		},
	})

	limiter := limits.NewManager(limits.Config{
		MaxConnsPerClient:           cfg.Limits.MaxConnsPerClient,
		MaxTotalConns:               cfg.Limits.MaxTotalConns,
		MaxBytesPerMinutePerClient:  cfg.Limits.MaxBytesPerMinutePerClient,
		MaxBytesPerMinutePerSession: cfg.Limits.MaxBytesPerMinutePerSession,
		MaxUDPPPS:                   cfg.Limits.MaxUDPPPS,
	})

	relayManager := relay.NewManager(relay.ManagerConfig{
		DialTimeout: cfg.Timeouts.DialTimeout.Duration,
		IdleTimeout: cfg.Timeouts.RelayIdle.Duration,
		RecvWindow:  cfg.Limits.MaxRecvWindowBytes,
		SendWindow:  cfg.Limits.RelaySendWindowBytes,
	}, limiter, m, logger.With(zap.String("lane", "relay")))

	relayServer := relay.NewServer(relayManager, verifier, m, logger.With(zap.String("component", "relay_http")))

	sessionServer := session.NewServer(session.Config{
		ListenQUIC:      cfg.ListenQUIC,
		ListenTCP:       cfg.ListenTCP,
		TLSConfig:       tlsConf,
		IdleTimeout:     cfg.Timeouts.SessionIdle.Duration,
		DialTimeout:     cfg.Timeouts.DialTimeout.Duration,
		MaxFlows:        cfg.Limits.MaxFlowsPerSession,
		MaxDgramPayload: cfg.MaxDgramPayload,
		UpKbps:          cfg.Limits.SessionUpKbps,
		DownKbps:        cfg.Limits.SessionDownKbps,
		MaxUDPPPS:       cfg.Limits.MaxUDPPPS,
		KeepAlive:       12 * time.Second,
		DatagramWorkers: cfg.Limits.SessionDatagramWorkers,
		DatagramQueue:   cfg.Limits.SessionDatagramQueue,
	}, verifier, limiter, m, logger.With(zap.String("component", "session_quic")))

	httpSrv := &http.Server{
		Addr:              cfg.ListenHTTP,
		Handler:           relayServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	go func() {
		logger.Info("relay HTTP lane listening", zap.String("addr", cfg.ListenHTTP), zap.Bool("tls", !cfg.AllowInsecureHTTP))
		if cfg.AllowInsecureHTTP {
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("relay http server: %w", err)
			}
			return
		}
		if err := httpSrv.ListenAndServeTLS(cfg.TLS.CertPath, cfg.TLS.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("relay https server: %w", err)
		}
	}()

	go func() {
		if err := sessionServer.Start(ctx); err != nil {
			errCh <- fmt.Errorf("session server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("runtime error", zap.Error(err))
	}

	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http shutdown failed", zap.Error(err))
	}
	relayManager.Shutdown()
	sessionServer.Shutdown()

	logger.Info("gateway stopped")
}

func newLogger(level string) (*zap.Logger, error) {
	zapLevel := zap.InfoLevel
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, err
	}

	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Encoding:    "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return cfg.Build()
}
