package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"dobotshield/config"
)

func TestInjectForwardedHeadersStripsUntrustedForwarding(t *testing.T) {
	r := httptest.NewRequest("GET", "https://shield.local/", nil)
	r.RemoteAddr = "203.0.113.10:49152"
	r.Header.Set("Forwarded", "for=198.51.100.20")
	r.Header.Set("X-Forwarded-For", "198.51.100.20")

	injectForwardedHeaders(r, "203.0.113.10", "203.0.113.10", false)

	if got := r.Header.Get("Forwarded"); got != "" {
		t.Fatalf("expected Forwarded to be removed, got %q", got)
	}
	if got := r.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Fatalf("expected sanitized X-Forwarded-For, got %q", got)
	}
	if got := r.Header.Get("X-Real-IP"); got != "203.0.113.10" {
		t.Fatalf("expected X-Real-IP to use client IP, got %q", got)
	}
}

func TestInjectForwardedHeadersRebuildsTrustedProxyChain(t *testing.T) {
	r := httptest.NewRequest("GET", "https://shield.local/", nil)
	r.RemoteAddr = "10.0.0.5:49152"
	r.Header.Set("X-Forwarded-For", "198.51.100.20, 10.0.0.4")

	injectForwardedHeaders(r, "198.51.100.20", "10.0.0.5", true)

	if got := r.Header.Get("X-Forwarded-For"); got != "198.51.100.20, 10.0.0.5" {
		t.Fatalf("expected rebuilt X-Forwarded-For, got %q", got)
	}
	if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("expected X-Forwarded-Proto=https, got %q", got)
	}
}

func TestWriteJSONErrorUsesGenericReason(t *testing.T) {
	w := httptest.NewRecorder()

	writeJSONError(w, http.StatusBadRequest, "Security Violation", "Request blocked by security policy")

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}
	if body["reason"] != "Request blocked by security policy" {
		t.Fatalf("expected generic reason, got %q", body["reason"])
	}
}

func TestBlockedMethods(t *testing.T) {
	if !isBlockedMethod(http.MethodTrace) {
		t.Fatalf("expected TRACE to be blocked")
	}
	if !isBlockedMethod("TRACK") {
		t.Fatalf("expected TRACK to be blocked")
	}
	if isBlockedMethod(http.MethodGet) {
		t.Fatalf("expected GET to be allowed")
	}
}

func TestBuildProxyDoesNotSetCSPByDefault(t *testing.T) {
	proxy, err := BuildProxy(config.Config{TargetURL: "http://localhost:4280"})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	resp := &http.Response{Header: make(http.Header)}
	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "" {
		t.Fatalf("expected CSP to be omitted by default, got %q", got)
	}
}

func TestBuildProxySetsConfiguredCSP(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:             "http://localhost:4280",
		ContentSecurityPolicy: "default-src 'self'",
	})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	resp := &http.Response{Header: make(http.Header)}
	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Fatalf("expected configured CSP, got %q", got)
	}
}

func TestBuildProxyBlocksBackendSQLLeak(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:                "http://localhost:4280",
		WAFMode:                  "block",
		EnableResponseInspection: true,
		ResponseInspectionLimit:  1024,
	})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	req := httptest.NewRequest("GET", "https://shield.local/items", nil)
	req.Header.Set("X-Request-ID", "test-request")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	resp := &http.Response{
		StatusCode:    http.StatusInternalServerError,
		Status:        "500 Internal Server Error",
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewBufferString("SQLSTATE[42000]: syntax error near 'DROP'")),
		ContentLength: int64(len("SQLSTATE[42000]: syntax error near 'DROP'")),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain")

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected blocked response status 502, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Shield-Action"); got != "Blocked-Response-WAF" {
		t.Fatalf("expected blocked response action, got %q", got)
	}
}

func TestBuildProxyMonitorModeDoesNotBlockBackendLeak(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:                "http://localhost:4280",
		WAFMode:                  "monitor",
		EnableResponseInspection: true,
		ResponseInspectionLimit:  1024,
	})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	req := httptest.NewRequest("GET", "https://shield.local/items", nil)
	req.Header.Set("X-Request-ID", "test-request")
	resp := &http.Response{
		StatusCode:    http.StatusInternalServerError,
		Status:        "500 Internal Server Error",
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewBufferString("SQLSTATE[42000]: syntax error near 'DROP'")),
		ContentLength: int64(len("SQLSTATE[42000]: syntax error near 'DROP'")),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain")

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected monitor mode to keep backend status, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Shield-Action"); got != "Forwarded" {
		t.Fatalf("expected forwarded action in monitor mode, got %q", got)
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	r := httptest.NewRequest("GET", "https://shield.local/ws", nil)
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Upgrade", "websocket")

	if !isWebSocketUpgrade(r) {
		t.Fatalf("expected websocket upgrade to be detected")
	}
}
