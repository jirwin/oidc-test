package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Port            int
	BaseURL         string
	DBPath          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	AuthCodeTTL     time.Duration
	CORSOrigins     string
	AdminToken      string
}

func Parse() *Config {
	c := &Config{}
	flag.IntVar(&c.Port, "port", 8080, "HTTP listen port")
	flag.StringVar(&c.BaseURL, "base-url", "", "External base URL (e.g., https://oidc-test.example.com)")
	flag.StringVar(&c.DBPath, "db-path", "oidc-test.db", "SQLite database file path")
	flag.DurationVar(&c.AccessTokenTTL, "access-token-ttl", 1*time.Hour, "Access token lifetime")
	flag.DurationVar(&c.RefreshTokenTTL, "refresh-token-ttl", 30*24*time.Hour, "Refresh token lifetime")
	flag.DurationVar(&c.AuthCodeTTL, "auth-code-ttl", 10*time.Minute, "Authorization code lifetime")
	flag.StringVar(&c.CORSOrigins, "cors-origins", "*", "Allowed CORS origins (comma-separated, or * for all)")
	flag.StringVar(&c.AdminToken, "admin-token", "", "Optional Bearer token to protect the management API")
	flag.Parse()

	if c.BaseURL == "" {
		if env := os.Getenv("BASE_URL"); env != "" {
			c.BaseURL = env
		} else {
			c.BaseURL = fmt.Sprintf("http://localhost:%d", c.Port)
		}
	}

	return c
}
