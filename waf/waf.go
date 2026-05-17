package waf

import (
	"bytes"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type patternGroup struct {
	name     string
	patterns []*regexp.Regexp
}

var allGroups = []patternGroup{
	{"XSS", xssPatterns},
	{"SQLi", sqliPatterns},
	{"CMD_INJ", cmdPatterns},
	{"PATH_TRAVERSAL", traversalPatterns},
	{"SSRF", ssrfPatterns},
	{"XXE", xxePatterns},
	{"JNDI", jndiPatterns},
	{"NoSQLi", nosqlPatterns},
	{"SSTI", sstiPatterns},
	{"PROTOTYPE_POLLUTION", prototypePollutionPatterns},
	{"OPEN_REDIRECT", openRedirectPatterns},
	{"HTTP_HEADER_INJECTION", headerInjectionPatterns},
}

var responseGroups = []patternGroup{
	{"RESPONSE_SQL_ERROR", responseSQLLeakPatterns},
	{"RESPONSE_STACK_TRACE", responseStackTracePatterns},
	{"RESPONSE_XSS_REFLECTION", responseXSSPatterns},
	{"RESPONSE_FILE_LEAK", responseFileLeakPatterns},
}

var (
	unicodeEscapePattern = regexp.MustCompile(`(?i)(?:\\u|%u)([0-9a-f]{4})`)
	hexEscapePattern     = regexp.MustCompile(`(?i)\\x([0-9a-f]{2})`)
	blockCommentPattern  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	inspectedHeaders     = []string{
		"Authorization",
		"Cookie",
		"Forwarded",
		"Referer",
		"User-Agent",
		"X-Forwarded-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
	}
)

const (
	maxMultipartParts     = 64
	maxMultipartPartBytes = 256 * 1024
)

func fullyURLDecode(s string) string {
	decoded := s
	for i := 0; i < 5; i++ {
		d, err := url.QueryUnescape(decoded)
		if err != nil || d == decoded {
			break
		}
		decoded = d
	}
	return decoded
}

func analyzePayload(input string) (bool, string, string) {
	return analyzePayloadWithGroups(input, allGroups)
}

func analyzePayloadWithGroups(input string, groups []patternGroup) (bool, string, string) {
	for _, t := range buildInspectionVariants(input) {
		for _, group := range groups {
			for _, p := range group.patterns {
				if p.MatchString(t) {
					return true, group.name, p.String()
				}
			}
		}
	}
	return false, "", ""
}

func buildInspectionVariants(input string) []string {
	var variants []string
	addVariant := func(value string) {
		if value == "" {
			return
		}
		for _, existing := range variants {
			if existing == value {
				return
			}
		}
		variants = append(variants, value)
	}

	decodedURL := fullyURLDecode(input)
	decodedHTML := fullyHTMLDecode(decodedURL)
	decodedEscapes := decodeScriptEscapes(decodedHTML)
	commentless := blockCommentPattern.ReplaceAllString(decodedEscapes, "")
	normalized := normalizeSeparators(commentless)
	compact := compactPayload(normalized)

	addVariant(input)
	addVariant(decodedURL)
	addVariant(decodedHTML)
	addVariant(decodedEscapes)
	addVariant(commentless)
	addVariant(normalized)
	addVariant(compact)

	return variants
}

func fullyHTMLDecode(s string) string {
	decoded := s
	for i := 0; i < 3; i++ {
		d := html.UnescapeString(decoded)
		if d == decoded {
			break
		}
		decoded = d
	}
	return decoded
}

func decodeScriptEscapes(s string) string {
	decoded := unicodeEscapePattern.ReplaceAllStringFunc(s, decodeUnicodeEscape)
	decoded = hexEscapePattern.ReplaceAllStringFunc(decoded, decodeHexEscape)
	return decoded
}

func decodeUnicodeEscape(match string) string {
	value, err := strconv.ParseInt(match[len(match)-4:], 16, 32)
	if err != nil {
		return match
	}
	return string(rune(value))
}

func decodeHexEscape(match string) string {
	value, err := strconv.ParseInt(match[len(match)-2:], 16, 8)
	if err != nil {
		return match
	}
	return string(rune(value))
}

func normalizeSeparators(s string) string {
	var b strings.Builder
	previousWasSpace := false

	for _, r := range s {
		if r == 0 {
			continue
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			if !previousWasSpace {
				b.WriteByte(' ')
				previousWasSpace = true
			}
			continue
		}
		previousWasSpace = false
		b.WriteRune(r)
	}

	return strings.TrimSpace(b.String())
}

func compactPayload(s string) string {
	var b strings.Builder

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(`<>/:;._-=$'"()\[]{}@`, r) {
			b.WriteRune(r)
		}
	}

	return b.String()
}

func CheckRequest(r *http.Request, bodyBytes []byte) (bool, string, string) {
	path := r.URL.EscapedPath()
	if path != "" && path != "/" {
		if mal, typ, pat := analyzePayload(path); mal {
			return true, typ + " in Path", pat
		}
	}

	if r.Host != "" {
		if mal, typ, pat := analyzePayload(r.Host); mal {
			return true, typ + " in Host", pat
		}
	}

	if r.URL.RawQuery != "" {
		if mal, typ, pat := analyzePayload(r.URL.RawQuery); mal {
			return true, typ + " in Query", pat
		}
	}

	for header, values := range r.Header {
		for _, value := range values {
			if mal, typ, pat := analyzePayloadWithGroups(value, []patternGroup{{"HTTP_HEADER_INJECTION", headerInjectionPatterns}}); mal {
				return true, typ + " in Header " + header, pat
			}
		}
	}

	for _, header := range inspectedHeaders {
		for _, value := range r.Header.Values(header) {
			if mal, typ, pat := analyzePayload(value); mal {
				return true, typ + " in Header " + header, pat
			}
		}
	}

	if len(bodyBytes) > 0 {
		if mal, typ, pat := inspectMultipart(r, bodyBytes); mal {
			return true, typ, pat
		}

		if mal, typ, pat := analyzePayload(string(bodyBytes)); mal {
			return true, typ + " in Body", pat
		}
	}

	return false, "", ""
}

func CheckResponse(resp *http.Response, bodyBytes []byte) (bool, string, string) {
	if resp != nil {
		if resp.Header.Get("Location") != "" {
			if mal, typ, pat := analyzePayloadWithGroups("redirect="+resp.Header.Get("Location"), []patternGroup{{"OPEN_REDIRECT", openRedirectPatterns}}); mal {
				return true, typ + " in Response Header Location", pat
			}
		}
	}

	if len(bodyBytes) == 0 {
		return false, "", ""
	}

	if mal, typ, pat := analyzePayloadWithGroups(string(bodyBytes), responseGroups); mal {
		return true, typ + " in Response Body", pat
	}

	return false, "", ""
}

func inspectMultipart(r *http.Request, bodyBytes []byte) (bool, string, string) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		return false, "", ""
	}

	boundary := params["boundary"]
	if boundary == "" {
		return false, "", ""
	}

	reader := multipart.NewReader(bytes.NewReader(bodyBytes), boundary)
	for i := 0; i < maxMultipartParts; i++ {
		part, err := reader.NextPart()
		if err == io.EOF {
			return false, "", ""
		}
		if err != nil {
			return true, "MALFORMED_MULTIPART", err.Error()
		}

		if mal, typ, pat := inspectMultipartPart(part); mal {
			return true, typ, pat
		}
	}

	part, err := reader.NextPart()
	if err == io.EOF {
		return false, "", ""
	}
	if err != nil {
		return true, "MALFORMED_MULTIPART", err.Error()
	}
	_ = part.Close()
	return true, "MULTIPART_LIMIT", "too many multipart parts"
}

func inspectMultipartPart(part *multipart.Part) (bool, string, string) {
	defer part.Close()

	metadata := []string{part.FormName(), part.FileName(), part.Header.Get("Content-Type")}
	for _, value := range metadata {
		if mal, typ, pat := analyzePayload(value); mal {
			return true, typ + " in Multipart Metadata", pat
		}
	}

	content, err := io.ReadAll(io.LimitReader(part, maxMultipartPartBytes+1))
	if err != nil {
		return true, "MULTIPART_READ_ERROR", err.Error()
	}
	if len(content) > maxMultipartPartBytes {
		return true, "MULTIPART_PART_TOO_LARGE", "multipart part exceeds inspection limit"
	}
	if len(content) == 0 {
		return false, "", ""
	}

	if mal, typ, pat := analyzePayload(string(content)); mal {
		return true, typ + " in Multipart Body", pat
	}

	return false, "", ""
}
