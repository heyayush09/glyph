package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config holds the full configuration loaded from config.yaml
type Config struct {
	Listen string            `mapstructure:"listen"`
	TLS    TLSConfig         `mapstructure:"tls"`
	OIDC   OIDCConfig        `mapstructure:"oidc"`
	Routes map[string]Route  `mapstructure:"routes"`
}

type TLSConfig struct {
	Mode     string `mapstructure:"mode"` // "auto", "manual", "disabled"
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type OIDCConfig struct {
	Issuer           string   `mapstructure:"issuer"`
	ClientID         string   `mapstructure:"client_id"`
	ClientSecretEnv  string   `mapstructure:"client_secret_env"`
	ClientSecret     string   `mapstructure:"client_secret"`
	RedirectURL      string   `mapstructure:"redirect_url"`
	Scopes           []string `mapstructure:"scopes"`
}

type Route struct {
	To            string       `mapstructure:"to"`
	Target        Target       `mapstructure:"target"`
	AllowedUsers  []string     `mapstructure:"allowed_users"`
	AllowedGroups []string     `mapstructure:"allowed_groups"`
	StripPath     bool         `mapstructure:"strip_path"`
}

type Target struct {
	Type string `mapstructure:"type"` // "ip", "url", "service"
	IP   string `mapstructure:"ip"`
	Port int    `mapstructure:"port"`
	URL  string `mapstructure:"url"`
}

func LoadConfig(path string) (*AtomicConfig, error) {
	viper.SetConfigFile(path)
	viper.AutomaticEnv()

	// Set defaults
	viper.SetDefault("listen", ":8080")
	viper.SetDefault("tls.mode", "disabled")
	viper.SetDefault("oidc.scopes", []string{"openid", "profile", "email"})

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse routes from the YAML structure you showed
	// The YAML has routes as an array, but your engine expects a map by host
	var rawConfig struct {
		Listen string      `mapstructure:"listen"`
		TLS    TLSConfig   `mapstructure:"tls"`
		OIDC   OIDCConfig  `mapstructure:"oidc"`
		Routes []RouteItem `mapstructure:"routes"`
	}

	if err := viper.Unmarshal(&rawConfig); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Convert routes array to map indexed by host
	routeMap := make(map[string]Route)
	for _, routeItem := range rawConfig.Routes {
		routeMap[routeItem.From] = Route{
			To:            routeItem.To,
			Target:        routeItem.Target,
			AllowedUsers:  routeItem.AllowedUsers,
			AllowedGroups: routeItem.AllowedGroups,
			StripPath:     routeItem.StripPath,
		}
	}

	cfg := &Config{
		Listen: rawConfig.Listen,
		TLS:    rawConfig.TLS,
		OIDC:   rawConfig.OIDC,
		Routes: routeMap,
	}

	// Post-process configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Resolve client secret from environment if specified
	if cfg.OIDC.ClientSecretEnv != "" {
		cfg.OIDC.ClientSecret = os.Getenv(cfg.OIDC.ClientSecretEnv)
		if cfg.OIDC.ClientSecret == "" {
			return nil, fmt.Errorf("environment variable %s is not set", cfg.OIDC.ClientSecretEnv)
		}
	}

	return NewAtomicConfig(cfg), nil
}

type RouteItem struct {
	From          string   `mapstructure:"from"`
	To            string   `mapstructure:"to"`
	Target        Target   `mapstructure:"target"`
	AllowedUsers  []string `mapstructure:"allowed_users"`
	AllowedGroups []string `mapstructure:"allowed_groups"`
	StripPath     bool     `mapstructure:"strip_path"`
}

func (c *Config) validate() error {
	if c.OIDC.Issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}
	if c.OIDC.ClientID == "" {
		return fmt.Errorf("oidc.client_id is required")
	}
	if c.OIDC.ClientSecret == "" && c.OIDC.ClientSecretEnv == "" {
		return fmt.Errorf("either oidc.client_secret or oidc.client_secret_env is required")
	}

	for host, route := range c.Routes {
		if route.To == "" && route.Target.Type == "" {
			return fmt.Errorf("route '%s' must have either 'to' or 'target' specified", host)
		}
		if route.Target.Type == "ip" && route.Target.IP == "" {
			return fmt.Errorf("route '%s' target.ip is required when type is 'ip'", host)
		}
	}

	return nil
}

func MustLoad(path string) *AtomicConfig {
	cfg, err := LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}