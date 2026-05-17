package config

import "testing"

func TestLoadReadsSecurityTogglesFromEnv(t *testing.T) {
	t.Setenv("ENABLE_WAF", "false")
	t.Setenv("ENABLE_RATE_LIMIT", "off")
	t.Setenv("MAX_BODY_SIZE", "2097152")
	t.Setenv("CONTENT_SECURITY_POLICY", "default-src 'self'")
	t.Setenv("INSECURE_SKIP_VERIFY", "true")
	t.Setenv("WAF_MODE", "monitor")
	t.Setenv("ENABLE_RESPONSE_INSPECTION", "false")
	t.Setenv("RESPONSE_INSPECTION_LIMIT", "524288")
	t.Setenv("MAX_TRACKED_IPS", "500")
	t.Setenv("WAF_ALLOWLIST", "SQLi:/api/search,XSS:/content-editor,/health")
	t.Setenv("RATE_LIMIT_STATE_FILE", "state/ratelimit.json")

	cfg := Load()

	if cfg.EnableSanitizer {
		t.Fatalf("expected ENABLE_WAF=false to disable sanitizer")
	}
	if cfg.EnableRateLimit {
		t.Fatalf("expected ENABLE_RATE_LIMIT=off to disable rate limit")
	}
	if cfg.MaxBodySize != 2097152 {
		t.Fatalf("expected MAX_BODY_SIZE to be read, got %d", cfg.MaxBodySize)
	}
	if cfg.ContentSecurityPolicy != "default-src 'self'" {
		t.Fatalf("expected CONTENT_SECURITY_POLICY to be read")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatalf("expected INSECURE_SKIP_VERIFY=true to be read")
	}
	if cfg.WAFMode != "monitor" {
		t.Fatalf("expected WAF_MODE=monitor, got %q", cfg.WAFMode)
	}
	if cfg.EnableResponseInspection {
		t.Fatalf("expected ENABLE_RESPONSE_INSPECTION=false to be read")
	}
	if cfg.ResponseInspectionLimit != 524288 {
		t.Fatalf("expected RESPONSE_INSPECTION_LIMIT to be read, got %d", cfg.ResponseInspectionLimit)
	}
	if cfg.MaxTrackedIPs != 500 {
		t.Fatalf("expected MAX_TRACKED_IPS to be read, got %d", cfg.MaxTrackedIPs)
	}
	if cfg.RateLimitStateFile != "state/ratelimit.json" {
		t.Fatalf("expected RATE_LIMIT_STATE_FILE to be read")
	}
	if !IsWAFAllowed(cfg.WAFAllowlist, "SQLi in Query", "/api/search") {
		t.Fatalf("expected SQLi allowlist rule to match /api/search")
	}
	if !IsWAFAllowed(cfg.WAFAllowlist, "XSS in Body", "/content-editor/post") {
		t.Fatalf("expected XSS allowlist rule to match /content-editor/post")
	}
	if !IsWAFAllowed(cfg.WAFAllowlist, "CMD_INJ in Query", "/health") {
		t.Fatalf("expected catch-all allowlist rule to match /health")
	}
	if IsWAFAllowed(cfg.WAFAllowlist, "XSS in Query", "/api/search") {
		t.Fatalf("did not expect XSS to match SQLi-only allowlist rule")
	}
}

func TestLoadFallsBackForInvalidNumbers(t *testing.T) {
	t.Setenv("RATE_LIMIT", "0")
	t.Setenv("BURST_LIMIT", "-1")
	t.Setenv("MAX_CONNS", "not-a-number")
	t.Setenv("MAX_BODY_SIZE", "-100")

	cfg := Load()

	if cfg.RateLimit != 10.0 {
		t.Fatalf("expected default rate limit, got %f", cfg.RateLimit)
	}
	if cfg.BurstLimit != 20 {
		t.Fatalf("expected default burst limit, got %d", cfg.BurstLimit)
	}
	if cfg.MaxConnsPerIP != 10 {
		t.Fatalf("expected default max connections, got %d", cfg.MaxConnsPerIP)
	}
	if cfg.MaxBodySize != 1024*1024 {
		t.Fatalf("expected default body size, got %d", cfg.MaxBodySize)
	}
}
