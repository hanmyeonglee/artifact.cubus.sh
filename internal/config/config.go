package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultListenAddr = ":8000"
	DefaultAdminPort  = 9090
	DefaultPublicBase = "http://127.0.0.1:8000"
	MinAdminTokenLen  = 16
)

type Config struct {
	ListenAddr             string
	AdminPort              int
	AdminBindCIDR          *netip.Prefix
	AdminAPIToken          string
	PublicBaseURL          string
	PublicIsHTTPS          bool
	DBBrokerURL            string
	DatabaseURL            string
	BootstrapAdminUsername string
	BootstrapAdminPassword string
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen_addr", c.ListenAddr),
		slog.Int("admin_port", c.AdminPort),
		slog.Bool("admin_api_enabled", c.AdminAPIToken != ""),
		slog.String("public_base_url", c.PublicBaseURL),
		slog.Bool("public_is_https", c.PublicIsHTTPS),
		slog.String("db_broker_url", c.DBBrokerURL),
		slog.Bool("database_url_set", c.DatabaseURL != ""),
		slog.String("bootstrap_admin_username", c.BootstrapAdminUsername),
		slog.String("bootstrap_admin_password", "[redacted]"),
		slog.String("admin_api_token", "[redacted]"),
	)
}

func (c Config) String() string {
	return fmt.Sprintf("Config{ListenAddr:%q PublicBaseURL:%q AdminAPIEnabled:%t DBBrokerSet:%t}",
		c.ListenAddr, c.PublicBaseURL, c.AdminAPIToken != "", c.DBBrokerURL != "")
}

func LoadFromEnv() (Config, error) {
	return Load(os.Getenv)
}

func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		ListenAddr:             envOrDefault(getenv, "LISTEN_ADDR", DefaultListenAddr),
		AdminPort:              DefaultAdminPort,
		AdminAPIToken:          strings.TrimSpace(getenv("ADMIN_API_TOKEN")),
		PublicBaseURL:          envOrDefault(getenv, "PUBLIC_BASE_URL", DefaultPublicBase),
		DBBrokerURL:            strings.TrimSpace(getenv("DB_BROKER_URL")),
		DatabaseURL:            strings.TrimSpace(getenv("DATABASE_URL")),
		BootstrapAdminUsername: strings.TrimSpace(getenv("BOOTSTRAP_ADMIN_USERNAME")),
		BootstrapAdminPassword: getenv("BOOTSTRAP_ADMIN_PASSWORD"),
	}

	if _, port, err := net.SplitHostPort(cfg.ListenAddr); err != nil || port == "" {
		return Config{}, fmt.Errorf("invalid LISTEN_ADDR %q: %w", cfg.ListenAddr, err)
	}

	if rawAdminPort := strings.TrimSpace(getenv("ADMIN_PORT")); rawAdminPort != "" {
		p, err := strconv.Atoi(rawAdminPort)
		if err != nil || p < 1 || p > 65535 {
			return Config{}, fmt.Errorf("invalid ADMIN_PORT %q: must be 1..65535", rawAdminPort)
		}
		cfg.AdminPort = p
	}

	if rawCIDR := strings.TrimSpace(getenv("ADMIN_BIND_CIDR")); rawCIDR != "" {
		pfx, err := netip.ParsePrefix(rawCIDR)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ADMIN_BIND_CIDR %q: %w", rawCIDR, err)
		}
		pfx = pfx.Masked()
		cfg.AdminBindCIDR = &pfx
	}

	if cfg.AdminAPIToken != "" {
		if IsPlaceholder(cfg.AdminAPIToken) {
			return Config{}, errors.New("ADMIN_API_TOKEN must not be a placeholder")
		}
		if len(cfg.AdminAPIToken) < MinAdminTokenLen {
			return Config{}, fmt.Errorf("ADMIN_API_TOKEN must be at least %d bytes", MinAdminTokenLen)
		}
	}

	normalizedBase, isHTTPS, err := NormalizePublicBaseURL(cfg.PublicBaseURL)
	if err != nil {
		return Config{}, err
	}
	cfg.PublicBaseURL = normalizedBase
	cfg.PublicIsHTTPS = isHTTPS

	if cfg.DBBrokerURL == "" && cfg.DatabaseURL == "" {
		return Config{}, errors.New("set DB_BROKER_URL or DATABASE_URL")
	}

	if cfg.BootstrapAdminPassword != "" && IsPlaceholder(cfg.BootstrapAdminPassword) {
		return Config{}, errors.New("BOOTSTRAP_ADMIN_PASSWORD must not be a placeholder")
	}

	return cfg, nil
}

// NormalizePublicBaseURL validates and canonicalizes PUBLIC_BASE_URL.
// Plain HTTP is permitted strictly for loopback development hosts.
func NormalizePublicBaseURL(raw string) (string, bool, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false, fmt.Errorf("invalid PUBLIC_BASE_URL %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false, fmt.Errorf("PUBLIC_BASE_URL %q must not contain userinfo, query, or fragment", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	switch scheme {
	case "https":
		u.Scheme = "https"
	case "http":
		if !isLoopbackHost(host) {
			return "", false, fmt.Errorf("PUBLIC_BASE_URL %q must use https:// for non-loopback hosts", raw)
		}
		u.Scheme = "http"
	default:
		return "", false, fmt.Errorf("unsupported PUBLIC_BASE_URL scheme %q", u.Scheme)
	}
	// Strip default ports and trailing slash for canonical OAuth issuer/resource URLs.
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		u.Host = host
	} else if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path != "" {
		return "", false, fmt.Errorf("PUBLIC_BASE_URL %q must not include a path prefix", raw)
	}
	return u.String(), scheme == "https", nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func IsPlaceholder(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(low, "replace-with-") || low == "changeme" || low == "change-me"
}

func HealthcheckURL(listenAddr string) (string, error) {
	if strings.TrimSpace(listenAddr) == "" {
		listenAddr = DefaultListenAddr
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "", fmt.Errorf("invalid LISTEN_ADDR %q", listenAddr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func envOrDefault(getenv func(string) string, key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}
