// Package scanner implements the hacklith analysis modules: port
// scanning, HTTP fingerprinting, fuzzing and web vulnerability probes.
// Everything is pure Go (stdlib only) so it builds offline and runs
// without external language runtimes.
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Level is the severity class of an emitted line.
type Level string

const (
	LInfo Level = "info"
	LOk   Level = "ok"
	LWarn Level = "warn"
	LCrit Level = "crit"
	LDim  Level = "dim"
	LHl   Level = "hl"
)

// Emit streams findings from a module to the caller (TUI or CLI).
type Emit func(Level, string)

// Resp is a captured HTTP response.
type Resp struct {
	Status int
	Header http.Header
	Body   []byte
	URL    string
	Dur    time.Duration
}

func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Req performs a single HTTP request and returns the captured response.
// Redirects are not followed so 3xx statuses are observable.
func Req(ctx context.Context, method, rawURL string, body io.Reader, headers map[string]string, timeout time.Duration) (*Resp, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hacklith/1.0 (authorized security testing)")
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := httpClient(timeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return &Resp{Status: resp.StatusCode, Header: resp.Header, Body: data, URL: resp.Request.URL.String(), Dur: time.Since(start)}, err
}

// Normalize ensures the target has a scheme and no trailing slash noise.
func Normalize(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return t
	}
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	t = strings.TrimSuffix(t, "/")
	return t
}

// JoinURL joins a base URL and a path safely.
func JoinURL(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	p := strings.TrimPrefix(path, "/")
	return base + "/" + p
}

// HasString is a case-insensitive substring check.
func HasString(hay, needle string) bool {
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

var titleRx = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var generatorRx = regexp.MustCompile(`(?is)<meta[^>]+name=["']?generator["']?[^>]+content=["']([^"']+)["']`)

// PageTitle extracts the <title> content, empty when absent.
func PageTitle(body []byte) string {
	m := titleRx.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// GeneratorMeta extracts a generator meta tag, empty when absent.
func GeneratorMeta(body []byte) string {
	m := generatorRx.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// HostFromTarget strips scheme, port and path from a target string.
func HostFromTarget(target string) string {
	h := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		h = u.Host
	}
	h = strings.TrimSuffix(h, "/")
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return h
}

// HeadersString renders a header map for report output.
func HeadersString(h http.Header) []string {
	var out []string
	for k, v := range h {
		out = append(out, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}
	return out
}

