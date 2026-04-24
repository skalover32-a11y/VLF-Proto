package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration for YAML strings like "20s".
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return errors.New("duration must be a scalar string")
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value.Value, err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

type TLSConfig struct {
	CertPath     string `yaml:"cert_path"`
	KeyPath      string `yaml:"key_path"`
	AutoGenerate bool   `yaml:"auto_generate"`
}

type LimitsConfig struct {
	MaxConnsPerClient           int   `yaml:"max_conns_per_client"`
	MaxTotalConns               int   `yaml:"max_total_conns"`
	MaxBytesPerMinutePerClient  int64 `yaml:"max_bytes_per_minute_per_client"`
	MaxRecvWindowBytes          int   `yaml:"max_recv_window_bytes"`
	RelaySendWindowBytes        int   `yaml:"relay_send_window_bytes"`
	MaxFlowsPerSession          int   `yaml:"max_flows_per_session"`
	MaxUDPPPS                   int   `yaml:"max_udp_pps"`
	SessionDatagramWorkers      int   `yaml:"session_datagram_workers"`
	SessionDatagramQueue        int   `yaml:"session_datagram_queue"`
	MaxBytesPerMinutePerSession int64 `yaml:"max_bytes_per_minute_per_session"`
	SessionUpKbps               int   `yaml:"session_up_kbps"`
	SessionDownKbps             int   `yaml:"session_down_kbps"`
}

type TimeoutsConfig struct {
	RelayIdle   Duration `yaml:"relay_idle"`
	SessionIdle Duration `yaml:"session_idle"`
	DialTimeout Duration `yaml:"dial_timeout"`
}

type AuthConfig struct {
	ClockSkew Duration `yaml:"clock_skew"`
	ReplayTTL Duration `yaml:"replay_ttl"`
}

type TransportConfig struct {
	ProfilesEnabled  bool     `yaml:"transport_profiles_enabled"`
	ScoringEnabled   bool     `yaml:"profile_scoring_enabled"`
	MigrationEnabled bool     `yaml:"profile_migration_enabled"`
	ResumeEnabled    bool     `yaml:"resume_tokens_enabled"`
	DefaultProfile   string   `yaml:"default_transport_profile"`
	ResumeSecret     string   `yaml:"resume_secret"`
	ResumeTokenTTL   Duration `yaml:"resume_token_ttl"`
	ResumeReplayTTL  Duration `yaml:"resume_replay_ttl"`
	ResumeEpochTTL   Duration `yaml:"resume_epoch_ttl"`
}

type Config struct {
	ListenHTTP        string            `yaml:"listen_http"`
	ListenQUIC        string            `yaml:"listen_quic"`
	ListenTCP         string            `yaml:"listen_tcp"`
	AllowInsecureHTTP bool              `yaml:"allow_insecure_http"`
	EnableMetrics     bool              `yaml:"enable_metrics"`
	ProtocolID        string            `yaml:"protocol_id"`
	LogLevel          string            `yaml:"log_level"`
	MaxDgramPayload   int               `yaml:"max_dgram_payload"`
	ClientSecrets     map[string]string `yaml:"client_secrets"`
	TLS               TLSConfig         `yaml:"tls"`
	Limits            LimitsConfig      `yaml:"limits"`
	Timeouts          TimeoutsConfig    `yaml:"timeouts"`
	Auth              AuthConfig        `yaml:"auth"`
	Transport         TransportConfig   `yaml:"transport"`
}

func Default() *Config {
	return &Config{
		ListenHTTP:        ":8080",
		ListenQUIC:        ":443",
		ListenTCP:         ":443",
		AllowInsecureHTTP: true,
		EnableMetrics:     true,
		ProtocolID:        "vlf-runtime/0.1",
		LogLevel:          "info",
		MaxDgramPayload:   1200,
		ClientSecrets: map[string]string{
			"smoke-client": "smoke-secret",
		},
		TLS: TLSConfig{
			CertPath:     "certs/dev.crt",
			KeyPath:      "certs/dev.key",
			AutoGenerate: true,
		},
		Limits: LimitsConfig{
			MaxConnsPerClient:           64,
			MaxTotalConns:               2048,
			MaxBytesPerMinutePerClient:  32 * 1024 * 1024,
			MaxRecvWindowBytes:          64 * 1024,
			RelaySendWindowBytes:        64 * 1024,
			MaxFlowsPerSession:          128,
			MaxUDPPPS:                   2000,
			SessionDatagramWorkers:      4,
			SessionDatagramQueue:        4096,
			MaxBytesPerMinutePerSession: 64 * 1024 * 1024,
			SessionUpKbps:               20000,
			SessionDownKbps:             20000,
		},
		Timeouts: TimeoutsConfig{
			RelayIdle:   Duration{Duration: 20 * time.Second},
			SessionIdle: Duration{Duration: 60 * time.Second},
			DialTimeout: Duration{Duration: 10 * time.Second},
		},
		Auth: AuthConfig{
			ClockSkew: Duration{Duration: 60 * time.Second},
			ReplayTTL: Duration{Duration: 60 * time.Second},
		},
		Transport: TransportConfig{
			ProfilesEnabled:  false,
			ScoringEnabled:   false,
			MigrationEnabled: false,
			ResumeEnabled:    false,
			DefaultProfile:   "balanced",
			ResumeTokenTTL:   Duration{Duration: 2 * time.Minute},
			ResumeReplayTTL:  Duration{Duration: 2 * time.Minute},
			ResumeEpochTTL:   Duration{Duration: 15 * time.Minute},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	def := Default()

	if c.ListenHTTP == "" {
		c.ListenHTTP = def.ListenHTTP
	}
	if c.ListenQUIC == "" {
		c.ListenQUIC = def.ListenQUIC
	}
	if c.ListenTCP == "" {
		c.ListenTCP = def.ListenTCP
	}
	if c.ProtocolID == "" {
		c.ProtocolID = def.ProtocolID
	}
	if c.LogLevel == "" {
		c.LogLevel = def.LogLevel
	}
	if c.MaxDgramPayload == 0 {
		c.MaxDgramPayload = def.MaxDgramPayload
	}
	if c.ClientSecrets == nil {
		c.ClientSecrets = def.ClientSecrets
	}

	if c.TLS.CertPath == "" {
		c.TLS.CertPath = def.TLS.CertPath
	}
	if c.TLS.KeyPath == "" {
		c.TLS.KeyPath = def.TLS.KeyPath
	}

	if c.Limits.MaxConnsPerClient == 0 {
		c.Limits.MaxConnsPerClient = def.Limits.MaxConnsPerClient
	}
	if c.Limits.MaxTotalConns == 0 {
		c.Limits.MaxTotalConns = def.Limits.MaxTotalConns
	}
	if c.Limits.MaxBytesPerMinutePerClient == 0 {
		c.Limits.MaxBytesPerMinutePerClient = def.Limits.MaxBytesPerMinutePerClient
	}
	if c.Limits.MaxRecvWindowBytes == 0 {
		c.Limits.MaxRecvWindowBytes = def.Limits.MaxRecvWindowBytes
	}
	if c.Limits.RelaySendWindowBytes == 0 {
		c.Limits.RelaySendWindowBytes = def.Limits.RelaySendWindowBytes
	}
	if c.Limits.MaxFlowsPerSession == 0 {
		c.Limits.MaxFlowsPerSession = def.Limits.MaxFlowsPerSession
	}
	if c.Limits.MaxUDPPPS == 0 {
		c.Limits.MaxUDPPPS = def.Limits.MaxUDPPPS
	}
	if c.Limits.SessionDatagramWorkers == 0 {
		c.Limits.SessionDatagramWorkers = def.Limits.SessionDatagramWorkers
	}
	if c.Limits.SessionDatagramQueue == 0 {
		c.Limits.SessionDatagramQueue = def.Limits.SessionDatagramQueue
	}
	if c.Limits.MaxBytesPerMinutePerSession == 0 {
		c.Limits.MaxBytesPerMinutePerSession = def.Limits.MaxBytesPerMinutePerSession
	}
	if c.Limits.SessionUpKbps == 0 {
		c.Limits.SessionUpKbps = def.Limits.SessionUpKbps
	}
	if c.Limits.SessionDownKbps == 0 {
		c.Limits.SessionDownKbps = def.Limits.SessionDownKbps
	}

	if c.Timeouts.RelayIdle.Duration == 0 {
		c.Timeouts.RelayIdle = def.Timeouts.RelayIdle
	}
	if c.Timeouts.SessionIdle.Duration == 0 {
		c.Timeouts.SessionIdle = def.Timeouts.SessionIdle
	}
	if c.Timeouts.DialTimeout.Duration == 0 {
		c.Timeouts.DialTimeout = def.Timeouts.DialTimeout
	}

	if c.Auth.ClockSkew.Duration == 0 {
		c.Auth.ClockSkew = def.Auth.ClockSkew
	}
	if c.Auth.ReplayTTL.Duration == 0 {
		c.Auth.ReplayTTL = def.Auth.ReplayTTL
	}

	if c.Transport.DefaultProfile == "" {
		c.Transport.DefaultProfile = def.Transport.DefaultProfile
	}
	if c.Transport.ResumeTokenTTL.Duration == 0 {
		c.Transport.ResumeTokenTTL = def.Transport.ResumeTokenTTL
	}
	if c.Transport.ResumeReplayTTL.Duration == 0 {
		c.Transport.ResumeReplayTTL = def.Transport.ResumeReplayTTL
	}
	if c.Transport.ResumeEpochTTL.Duration == 0 {
		c.Transport.ResumeEpochTTL = def.Transport.ResumeEpochTTL
	}
}

func (c *Config) Validate() error {
	if len(c.ClientSecrets) == 0 {
		return errors.New("client_secrets is required")
	}
	if c.MaxDgramPayload < 256 {
		return fmt.Errorf("max_dgram_payload must be >= 256, got %d", c.MaxDgramPayload)
	}
	if c.Limits.MaxRecvWindowBytes <= 0 {
		return errors.New("limits.max_recv_window_bytes must be > 0")
	}
	if c.Limits.RelaySendWindowBytes <= 0 {
		return errors.New("limits.relay_send_window_bytes must be > 0")
	}
	if c.Limits.SessionDatagramWorkers <= 0 {
		return errors.New("limits.session_datagram_workers must be > 0")
	}
	if c.Limits.SessionDatagramQueue <= 0 {
		return errors.New("limits.session_datagram_queue must be > 0")
	}
	if c.Timeouts.RelayIdle.Duration <= 0 {
		return errors.New("timeouts.relay_idle must be > 0")
	}
	if c.Timeouts.SessionIdle.Duration <= 0 {
		return errors.New("timeouts.session_idle must be > 0")
	}
	if c.Timeouts.DialTimeout.Duration <= 0 {
		return errors.New("timeouts.dial_timeout must be > 0")
	}
	if c.Auth.ClockSkew.Duration <= 0 {
		return errors.New("auth.clock_skew must be > 0")
	}
	if c.Auth.ReplayTTL.Duration <= 0 {
		return errors.New("auth.replay_ttl must be > 0")
	}
	if c.Transport.ResumeEnabled && c.Transport.ResumeSecret == "" {
		return errors.New("transport.resume_secret is required when resume_tokens_enabled=true")
	}
	if c.Transport.ResumeEnabled && c.Transport.ResumeTokenTTL.Duration <= 0 {
		return errors.New("transport.resume_token_ttl must be > 0")
	}
	if c.Transport.ResumeEnabled && c.Transport.ResumeReplayTTL.Duration <= 0 {
		return errors.New("transport.resume_replay_ttl must be > 0")
	}
	if c.Transport.ResumeEnabled && c.Transport.ResumeEpochTTL.Duration <= 0 {
		return errors.New("transport.resume_epoch_ttl must be > 0")
	}
	return nil
}
