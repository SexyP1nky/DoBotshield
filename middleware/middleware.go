package middleware

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"dobotshield/blocklist"
	"dobotshield/config"
	"dobotshield/ratelimit"
	"dobotshield/utils"
	"dobotshield/waf"
)

func BuildProxy(cfg config.Config) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		if cfg.ResponseWAFEnabled() {
			req.Header.Del("Accept-Encoding")
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		hardenResponseHeaders(resp, cfg)
		inspectBackendResponse(resp, cfg)
		return nil
	}

	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		requestID := r.Header.Get("X-Request-ID")
		clientIP := r.Header.Get("X-Real-IP")
		if requestID == "" {
			requestID = utils.NewRequestID()
		}
		utils.LogEventWithRequestID(requestID, "PROXY_ERROR", clientIP, err.Error(), r.URL.Path)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Shield-Action", "Proxy-Error")
		writeJSONError(w, http.StatusBadGateway, "Bad Gateway", "Backend unavailable")
	}

	return proxy, nil
}

func MakeSecureHandler(proxy *httputil.ReverseProxy, fw *ratelimit.Manager, bl *blocklist.List, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := utils.GetOrCreateRequestID(r)
		directIP := utils.GetRealIP(r)
		directTrusted := utils.IsTrustedProxy(directIP, cfg.TrustedProxies)
		clientIP := utils.GetClientIP(r, cfg.TrustedProxies)

		w.Header().Set("X-Request-ID", requestID)
		r.Header.Set("X-Request-ID", requestID)

		if bl.Contains(clientIP) {
			utils.LogEventWithRequestID(requestID, "IP_BLOCK", clientIP, "blocked IP", r.URL.Path)
			w.Header().Set("X-Shield-Action", "Blocked-IP")
			writeJSONError(w, http.StatusForbidden, "Forbidden", "Access denied")
			return
		}

		if isBlockedMethod(r.Method) {
			utils.LogEventWithRequestID(requestID, "METHOD_BLOCK", clientIP, r.Method, r.URL.Path)
			w.Header().Set("X-Shield-Action", "Blocked-Method")
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if cfg.EnableRateLimit {
			allowed, reason := fw.Allow(clientIP)
			if !allowed {
				utils.LogEventWithRequestID(requestID, "DoS_BLOCK", clientIP, reason, r.URL.Path)
				w.Header().Set("X-Shield-Action", "Blocked-DoS")
				w.Header().Set("Retry-After", "30")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer fw.Release(clientIP)
		}

		if cfg.RequestWAFEnabled() {
			if blocked := inspectRequest(w, r, cfg, requestID, clientIP); blocked {
				return
			}
		} else if !isWebSocketUpgrade(r) {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodySize)
		}

		injectForwardedHeaders(r, clientIP, directIP, directTrusted)

		log.Printf("[ACCESS] request_id:%s | %s %s from %s", requestID, r.Method, r.URL.Path, clientIP)
		proxy.ServeHTTP(w, r)
	}
}

func inspectRequest(w http.ResponseWriter, r *http.Request, cfg config.Config, requestID, clientIP string) bool {
	var bodyBytes []byte

	if !isWebSocketUpgrade(r) {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodySize)

		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				utils.LogEventWithRequestID(requestID, "BODY_BLOCK", clientIP, "Request body too large", r.URL.Path)
				w.Header().Set("X-Shield-Action", "Blocked-Body-Size")
				http.Error(w, "413 Payload Too Large", http.StatusRequestEntityTooLarge)
				return true
			}
			utils.LogEventWithRequestID(requestID, "BODY_READ_ERROR", clientIP, err.Error(), r.URL.Path)
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return true
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	if malicious, details, _ := waf.CheckRequest(r, bodyBytes); malicious {
		if config.IsWAFAllowed(cfg.WAFAllowlist, details, r.URL.Path) {
			utils.LogEventWithRequestID(requestID, "WAF_ALLOW", clientIP, details, r.URL.Path)
			return false
		}
		if cfg.WAFBlocks() {
			utils.LogEventWithRequestID(requestID, "WAF_BLOCK", clientIP, details, r.URL.Path)
			w.Header().Set("X-Shield-Action", "Blocked-WAF")
			writeJSONError(w, http.StatusBadRequest, "Security Violation", "Request blocked by security policy")
			return true
		}
		utils.LogEventWithRequestID(requestID, "WAF_DETECT", clientIP, details, r.URL.Path)
	}

	return false
}

func hardenResponseHeaders(resp *http.Response, cfg config.Config) {
	requestID := ""
	if resp.Request != nil {
		requestID = resp.Request.Header.Get("X-Request-ID")
	}

	resp.Header.Del("Server")
	resp.Header.Del("X-Powered-By")
	resp.Header.Del("X-AspNet-Version")
	resp.Header.Del("X-AspNetMvc-Version")

	resp.Header.Set("X-Shield-Action", "Forwarded")
	if requestID != "" {
		resp.Header.Set("X-Request-ID", requestID)
	}
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	if cfg.ContentSecurityPolicy != "" {
		resp.Header.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
	}
	resp.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	resp.Header.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

func inspectBackendResponse(resp *http.Response, cfg config.Config) {
	if !shouldInspectBackendResponse(resp, cfg) {
		return
	}

	requestID, clientIP, path := responseLogContext(resp)
	if resp.ContentLength > cfg.ResponseInspectionLimit {
		utils.LogEventWithRequestID(requestID, "RESPONSE_INSPECTION_SKIP", clientIP, "Response body too large", path)
		return
	}

	bodyBytes, overLimit, err := readResponseForInspection(resp, cfg.ResponseInspectionLimit)
	if err != nil {
		utils.LogEventWithRequestID(requestID, "RESPONSE_READ_ERROR", clientIP, err.Error(), path)
		return
	}
	if overLimit {
		utils.LogEventWithRequestID(requestID, "RESPONSE_INSPECTION_SKIP", clientIP, "Response body exceeds inspection limit", path)
		return
	}

	if malicious, details, _ := waf.CheckResponse(resp, bodyBytes); malicious {
		if config.IsWAFAllowed(cfg.WAFAllowlist, details, path) {
			utils.LogEventWithRequestID(requestID, "RESPONSE_WAF_ALLOW", clientIP, details, path)
			return
		}
		if cfg.WAFBlocks() {
			utils.LogEventWithRequestID(requestID, "RESPONSE_WAF_BLOCK", clientIP, details, path)
			blockBackendResponse(resp)
			return
		}
		utils.LogEventWithRequestID(requestID, "RESPONSE_WAF_DETECT", clientIP, details, path)
	}
}

func shouldInspectBackendResponse(resp *http.Response, cfg config.Config) bool {
	if !cfg.ResponseWAFEnabled() || resp == nil || resp.Body == nil {
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return false
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return false
	}
	if resp.Request != nil && strings.EqualFold(resp.Request.Method, http.MethodHead) {
		return false
	}
	if resp.Request != nil && isWebSocketUpgrade(resp.Request) {
		return false
	}
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return false
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Disposition")), "attachment") {
		return false
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType == "" {
		return true
	}

	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "x-www-form-urlencoded")
}

func readResponseForInspection(resp *http.Response, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 1024 * 1024
	}

	originalBody := resp.Body
	bodyBytes, err := io.ReadAll(io.LimitReader(originalBody, limit+1))
	if err != nil {
		return nil, false, err
	}

	if int64(len(bodyBytes)) > limit {
		resp.Body = readCloser{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), originalBody),
			Closer: originalBody,
		}
		return bodyBytes, true, nil
	}

	if err := originalBody.Close(); err != nil {
		return nil, false, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	return bodyBytes, false, nil
}

func blockBackendResponse(resp *http.Response) {
	body := []byte("{\"error\":\"Security Violation\",\"reason\":\"Backend response blocked by security policy\"}\n")

	resp.StatusCode = http.StatusBadGateway
	resp.Status = "502 Bad Gateway"
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("X-Shield-Action", "Blocked-Response-WAF")
}

func responseLogContext(resp *http.Response) (string, string, string) {
	if resp == nil || resp.Request == nil {
		return utils.NewRequestID(), "", ""
	}

	requestID := resp.Request.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = utils.NewRequestID()
	}

	return requestID, resp.Request.Header.Get("X-Real-IP"), resp.Request.URL.Path
}

type readCloser struct {
	io.Reader
	io.Closer
}

func isBlockedMethod(method string) bool {
	return strings.EqualFold(method, http.MethodTrace) || strings.EqualFold(method, "TRACK")
}

func isWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header.Get("Connection"), "upgrade")
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func injectForwardedHeaders(r *http.Request, clientIP, directIP string, directTrusted bool) {
	r.Header.Del("Forwarded")
	r.Header.Del("X-Forwarded-For")

	if directTrusted && clientIP != "" && clientIP != directIP {
		r.Header.Set("X-Forwarded-For", clientIP+", "+directIP)
	} else {
		r.Header.Set("X-Forwarded-For", directIP)
	}

	r.Header.Set("X-Real-IP", clientIP)
	r.Header.Set("X-Shield-Request-ID", r.Header.Get("X-Request-ID"))
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", r.Host)
}

func writeJSONError(w http.ResponseWriter, status int, message, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  message,
		"reason": reason,
	})
}
