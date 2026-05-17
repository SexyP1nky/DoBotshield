package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	TargetURL                string
	ProxyPort                string
	RateLimit                float64
	BurstLimit               int
	MaxConnsPerIP            int
	EnableSanitizer          bool
	EnableRateLimit          bool
	CertFile                 string
	KeyFile                  string
	MaxBodySize              int64
	TrustedProxies           []string
	BlockedIPs               []string
	MaxTrackedIPs            int
	InsecureSkipVerify       bool
	ContentSecurityPolicy    string
	WAFMode                  string
	EnableResponseInspection bool
	ResponseInspectionLimit  int64
	WAFAllowlist             []WAFAllowRule
	RateLimitStateFile       string
}

type WAFAllowRule struct {
	Category   string
	PathPrefix string
}

func Load() Config {
	return Config{
		TargetURL:                getEnv("TARGET_URL", "http://localhost:4280"),
		ProxyPort:                getEnv("PROXY_PORT", ":443"),
		RateLimit:                parseFloat(getEnv("RATE_LIMIT", "10.0"), 10.0),
		BurstLimit:               parseInt(getEnv("BURST_LIMIT", "20"), 20),
		MaxConnsPerIP:            parseInt(getEnv("MAX_CONNS", "10"), 10),
		EnableSanitizer:          parseBool(getEnv("ENABLE_WAF", "true"), true),
		EnableRateLimit:          parseBool(getEnv("ENABLE_RATE_LIMIT", "true"), true),
		CertFile:                 getEnv("CERT_FILE", "server.crt"),
		KeyFile:                  getEnv("KEY_FILE", "server.key"),
		MaxBodySize:              parseInt64(getEnv("MAX_BODY_SIZE", "1048576"), 1024*1024),
		TrustedProxies:           parseCSV(getEnv("TRUSTED_PROXIES", "127.0.0.1,::1")),
		BlockedIPs:               parseCSV(getEnv("BLOCKED_IPS", "")),
		MaxTrackedIPs:            parseInt(getEnv("MAX_TRACKED_IPS", "10000"), 10000),
		InsecureSkipVerify:       parseBool(getEnv("INSECURE_SKIP_VERIFY", "false"), false),
		ContentSecurityPolicy:    strings.TrimSpace(getEnv("CONTENT_SECURITY_POLICY", "")),
		WAFMode:                  parseWAFMode(getEnv("WAF_MODE", "block")),
		EnableResponseInspection: parseBool(getEnv("ENABLE_RESPONSE_INSPECTION", "true"), true),
		ResponseInspectionLimit:  parseInt64(getEnv("RESPONSE_INSPECTION_LIMIT", "1048576"), 1024*1024),
		WAFAllowlist:             parseWAFAllowlist(getEnv("WAF_ALLOWLIST", "")),
		RateLimitStateFile:       strings.TrimSpace(getEnv("RATE_LIMIT_STATE_FILE", "")),
	}
}

func (c Config) RequestWAFEnabled() bool {
	return c.EnableSanitizer && c.WAFMode != "off"
}

func (c Config) ResponseWAFEnabled() bool {
	return c.EnableResponseInspection && c.WAFMode != "off"
}

func (c Config) WAFBlocks() bool {
	return c.WAFMode == "block"
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func parseInt(s string, defaultVal int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}

func parseFloat(s string, defaultVal float64) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}

func parseInt64(s string, defaultVal int64) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}

func parseBool(s string, defaultVal bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes", "y", "on", "enabled":
		return true
	case "0", "false", "f", "no", "n", "off", "disabled":
		return false
	default:
		return defaultVal
	}
}

func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func parseWAFMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block", "enforce", "blocking":
		return "block"
	case "monitor", "observe", "dry-run", "dryrun", "detect", "detect-only":
		return "monitor"
	case "off", "disabled", "disable":
		return "off"
	default:
		return "block"
	}
}

func parseWAFAllowlist(s string) []WAFAllowRule {
	entries := parseCSV(s)
	rules := make([]WAFAllowRule, 0, len(entries))

	for _, entry := range entries {
		category := "*"
		pathPrefix := strings.TrimSpace(entry)

		if left, right, found := strings.Cut(entry, ":"); found && strings.TrimSpace(right) != "" {
			category = normalizeWAFCategory(left)
			pathPrefix = strings.TrimSpace(right)
		}

		if pathPrefix == "" {
			continue
		}
		if !strings.HasPrefix(pathPrefix, "/") {
			pathPrefix = "/" + pathPrefix
		}

		rules = append(rules, WAFAllowRule{
			Category:   category,
			PathPrefix: pathPrefix,
		})
	}

	return rules
}

func IsWAFAllowed(rules []WAFAllowRule, category, path string) bool {
	if path == "" {
		path = "/"
	}

	category = normalizeWAFCategory(category)
	for _, rule := range rules {
		if rule.PathPrefix == "" || !strings.HasPrefix(path, rule.PathPrefix) {
			continue
		}
		if rule.Category == "*" || rule.Category == category {
			return true
		}
	}

	return false
}

func normalizeWAFCategory(category string) string {
	clean := strings.TrimSpace(category)
	if clean == "" || clean == "*" {
		return "*"
	}

	fields := strings.Fields(clean)
	if len(fields) > 0 {
		clean = fields[0]
	}

	return strings.ToUpper(clean)
}
