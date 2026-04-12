package transit

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar string")
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

type TimeoutsConfig struct {
	DialTimeout     Duration `yaml:"dial_timeout"`
	UDPIdle         Duration `yaml:"udp_idle"`
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`
}

type Config struct {
	LogLevel      string         `yaml:"log_level"`
	ListenTCP     string         `yaml:"listen_tcp"`
	BackendTCP    string         `yaml:"backend_tcp"`
	ListenUDP     string         `yaml:"listen_udp"`
	ListenUDPAlt  string         `yaml:"listen_udp_alt"`
	BackendUDP    string         `yaml:"backend_udp"`
	EnableRelay   bool           `yaml:"enable_relay"`
	ListenRelay   string         `yaml:"listen_relay"`
	BackendRelay  string         `yaml:"backend_relay"`
	EnableMetrics bool           `yaml:"enable_metrics"`
	MetricsListen string         `yaml:"metrics_listen"`
	Timeouts      TimeoutsConfig `yaml:"timeouts"`
}

func DefaultConfig() Config {
	return Config{
		LogLevel:      "info",
		ListenTCP:     "0.0.0.0:443",
		BackendTCP:    "127.0.0.1:443",
		ListenUDP:     "0.0.0.0:443",
		ListenUDPAlt:  "0.0.0.0:8443",
		BackendUDP:    "127.0.0.1:443",
		EnableRelay:   true,
		ListenRelay:   "0.0.0.0:8080",
		BackendRelay:  "127.0.0.1:8080",
		EnableMetrics: true,
		MetricsListen: "127.0.0.1:9091",
		Timeouts: TimeoutsConfig{
			DialTimeout:     Duration{Duration: 10 * time.Second},
			UDPIdle:         Duration{Duration: 60 * time.Second},
			ShutdownTimeout: Duration{Duration: 10 * time.Second},
		},
	}
}

func Load(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read transit config: %w", err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal transit config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	def := DefaultConfig()
	if c.LogLevel == "" {
		c.LogLevel = def.LogLevel
	}
	if c.ListenTCP == "" {
		c.ListenTCP = def.ListenTCP
	}
	if c.ListenUDP == "" {
		c.ListenUDP = def.ListenUDP
	}
	if c.BackendTCP == "" {
		c.BackendTCP = def.BackendTCP
	}
	if c.BackendUDP == "" {
		c.BackendUDP = def.BackendUDP
	}
	if c.EnableRelay {
		if c.ListenRelay == "" {
			c.ListenRelay = def.ListenRelay
		}
		if c.BackendRelay == "" {
			c.BackendRelay = def.BackendRelay
		}
	}
	if c.EnableMetrics && c.MetricsListen == "" {
		c.MetricsListen = def.MetricsListen
	}
	if c.Timeouts.DialTimeout.Duration == 0 {
		c.Timeouts.DialTimeout = def.Timeouts.DialTimeout
	}
	if c.Timeouts.UDPIdle.Duration == 0 {
		c.Timeouts.UDPIdle = def.Timeouts.UDPIdle
	}
	if c.Timeouts.ShutdownTimeout.Duration == 0 {
		c.Timeouts.ShutdownTimeout = def.Timeouts.ShutdownTimeout
	}
}

func (c Config) Validate() error {
	if err := validateAddr(c.ListenTCP); err != nil {
		return fmt.Errorf("invalid listen_tcp: %w", err)
	}
	if err := validateAddr(c.BackendTCP); err != nil {
		return fmt.Errorf("invalid backend_tcp: %w", err)
	}
	if err := validateAddr(c.ListenUDP); err != nil {
		return fmt.Errorf("invalid listen_udp: %w", err)
	}
	if err := validateAddr(c.BackendUDP); err != nil {
		return fmt.Errorf("invalid backend_udp: %w", err)
	}
	if c.ListenUDPAlt != "" {
		if err := validateAddr(c.ListenUDPAlt); err != nil {
			return fmt.Errorf("invalid listen_udp_alt: %w", err)
		}
	}
	if c.EnableRelay {
		if err := validateAddr(c.ListenRelay); err != nil {
			return fmt.Errorf("invalid listen_relay: %w", err)
		}
		if err := validateAddr(c.BackendRelay); err != nil {
			return fmt.Errorf("invalid backend_relay: %w", err)
		}
	}
	if c.EnableMetrics {
		if err := validateAddr(c.MetricsListen); err != nil {
			return fmt.Errorf("invalid metrics_listen: %w", err)
		}
	}
	if c.Timeouts.DialTimeout.Duration <= 0 {
		return fmt.Errorf("dial_timeout must be positive")
	}
	if c.Timeouts.UDPIdle.Duration <= 0 {
		return fmt.Errorf("udp_idle must be positive")
	}
	if c.Timeouts.ShutdownTimeout.Duration <= 0 {
		return fmt.Errorf("shutdown_timeout must be positive")
	}
	return nil
}

func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}
	if parsedPort < 1 || parsedPort > 65535 {
		return fmt.Errorf("port %d out of range", parsedPort)
	}
	return nil
}
