package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config holds the full configuration loaded from config.yaml
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	OIDC     OIDCConfig     `mapstructure:"oidc"`
	Policies PolicyConfig   `mapstructure:"policies"`
	Proxies  []ProxyTarget  `mapstructure:"proxies"`
}

type ServerConfig struct {
	Addr     string `mapstructure:"addr"`
	TLSMode  string `mapstructure:"tls_mode"` // "auto", "manual", "disabled"
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type OIDCConfig struct {
	Issuer       string `mapstructure:"issuer"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
	CookieName   string `mapstructure:"cookie_name"`
	JWKSURL      string `mapstructure:"jwks_url"`
}

type PolicyConfig struct {
	AllowedUsers  []string `mapstructure:"allowed_users"`
	AllowedGroups []string `mapstructure:"allowed_groups"`
}

type ProxyTarget struct {
	Route     string `mapstructure:"route"`
	To        string `mapstructure:"to"`
	Target    Target `mapstructure:"target"`
	StripPath bool   `mapstructure:"strip_path"`
}

type Target struct {
	Type string `mapstructure:"type"` // "ip", "asg", etc.
	IP   string `mapstructure:"ip"`
	// Extendable later with ASG/EC2 integration
}

func LoadConfig(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &cfg, nil
}

func MustLoad(path string) *Config {
	cfg, err := LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}
