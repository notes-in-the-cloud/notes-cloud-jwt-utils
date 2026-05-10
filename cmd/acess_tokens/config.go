package access_token

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type AccessTokenConfig struct {
	Secret   string        `json:"secret"`
	Issuer   string        `json:"issuer"`
	Audience string        `json:"audience"`
	TTL      time.Duration `json:"TTL"`
}

func Load() (*AccessTokenConfig, error) {
	cfg := &AccessTokenConfig{}

	if v := getEnv("JWT_SECRET"); v != "" {
		cfg.Secret = v
	}
	if v := getEnv("JWT_ISSUER"); v != "" {
		cfg.Issuer = v
	}
	if v := getEnv("JWT_AUDIENCE"); v != "" {
		cfg.Audience = v
	}
	if v := getEnv("JWT_TTL"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_TTL %q: %w", v, err)
		}
		cfg.TTL = ttl
	}

	return cfg, nil
}

func getEnv(key string) string {
	if path := os.Getenv(key + "_FILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimRight(string(data), "\r\n")
		}
	}
	return os.Getenv(key)
}
