package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qingethical/hacklith/internal/wordlists"
)

// headerBlob flattens response headers into a single lower-cased string
// so signature checks can scan both names and values at once.
func headerBlob(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		b.WriteString(strings.ToLower(k))
		b.WriteString(":")
		for _, v := range vs {
			b.WriteString(strings.ToLower(v))
			b.WriteString(" ")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// WAFDetect detects web application firewalls by inspecting response
// headers and body for vendor signatures (Cloudflare, Imperva, etc.).
func WAFDetect(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "waf detection — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		emit(LWarn, "request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	sigs := []struct{ sig, name string }{
		{"cloudflare", "Cloudflare"},
		{"cf-ray", "Cloudflare"},
		{"__cfduid", "Cloudflare"},
		{"cf-cache-status", "Cloudflare"},
		{"akamai", "Akamai"},
		{"x-akamai", "Akamai"},
		{"incap_ses", "Imperva/Incapsula"},
		{"visid_incap", "Imperva/Incapsula"},
		{"x-iinfo", "Imperva/Incapsula"},
		{"imperva", "Imperva/Incapsula"},
		{"sucuri", "Sucuri"},
		{"x-sucuri", "Sucuri"},
		{"mod_security", "ModSecurity"},
		{"modsecurity", "ModSecurity"},
		{"wordfence", "Wordfence"},
		{"barra_counter_session", "Barracuda"},
		{"bigipserver", "F5 BIG-IP"},
		{"ts01", "F5 BIG-IP"},
		{"awselb", "AWS ELB/WAF"},
		{"x-amzn-", "AWS WAF/Shield"},
		{"fortiwaf", "Fortinet FortiWeb"},
		{"denyall", "DenyAll"},
		{"x-protected-by", "Unknown WAF"},
	}

	headers := headerBlob(r.Header)
	body := strings.ToLower(string(r.Body))
	uniq := map[string]bool{}
	for _, s := range sigs {
		if strings.Contains(headers, s.sig) || strings.Contains(body, s.sig) {
			uniq[s.name] = true
		}
	}
	if len(uniq) > 0 {
		var names []string
		for n := range uniq {
			names = append(names, n)
		}
		sort.Strings(names)
		emit(LCrit, "WAF detected: "+strings.Join(names, ", "))
	} else {
		emit(LOk, "no WAF signatures detected (clear)")
	}
	return nil
}

// CDNDetect detects content delivery networks by inspecting headers such
// as CF-Ray, X-Cache, X-Served-By and X-CDN.
func CDNDetect(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "cdn detection — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		emit(LWarn, "request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	headers := headerBlob(r.Header)
	body := strings.ToLower(string(r.Body))

	sigs := []struct {
		sig  string
		name string
	}{
		{"cf-ray", "Cloudflare"},
		{"cf-cache-status", "Cloudflare"},
		{"cloudfront", "Amazon CloudFront"},
		{"x-amz-cf-id", "Amazon CloudFront"},
		{"x-amz-cf-pop", "Amazon CloudFront"},
		{"x-akamai", "Akamai"},
		{"akamaighost", "Akamai"},
		{"fastly", "Fastly"},
		{"x-served-by", "Fastly/Varnish"},
		{"varnish", "Varnish"},
		{"x-goog-", "Google Cloud"},
		{"gstatic", "Google Cloud"},
		{"azureedge", "Microsoft Azure"},
		{"x-msedge-", "Microsoft Azure"},
		{"x-cache", "CDN (generic X-Cache)"},
		{"x-cdn", "CDN (generic X-CDN)"},
		{"x-cdn-provider", "CDN (provider header)"},
		{"keycdn", "KeyCDN"},
		{"bunnycdn", "BunnyCDN"},
		{"cachefly", "CacheFly"},
		{"cdn77", "CDN77"},
	}

	uniq := map[string]bool{}
	for _, s := range sigs {
		if strings.Contains(headers, s.sig) || strings.Contains(body, s.sig) {
			uniq[s.name] = true
		}
	}
	for _, h := range []string{"X-CDN", "X-CDN-Provider", "X-Served-By", "X-Cache", "Server"} {
		if v := r.Header.Get(h); v != "" {
			emit(LDim, fmt.Sprintf("%s: %s", h, v))
		}
	}
	if len(uniq) > 0 {
		var names []string
		for n := range uniq {
			names = append(names, n)
		}
		sort.Strings(names)
		emit(LOk, "CDN detected: "+strings.Join(names, ", "))
	} else {
		emit(LDim, "no CDN signatures detected")
	}
	return nil
}

// CORSCheck sends a cross-origin request and inspects the
// Access-Control-Allow-Origin response for reflection or wildcard-with-
// credentials misconfigurations.
func CORSCheck(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "cors misconfiguration check — "+base)

	origin := fmt.Sprintf("https://%d.example.com", time.Now().UnixNano()%1000000)
	r, err := Req(ctx, "GET", base, nil, map[string]string{"Origin": origin}, 10*time.Second)
	if err != nil {
		emit(LWarn, "request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	acao := r.Header.Get("Access-Control-Allow-Origin")
	acac := r.Header.Get("Access-Control-Allow-Credentials")
	if acao == "" {
		emit(LDim, "no Access-Control-Allow-Origin header returned")
		return nil
	}
	if acao == "*" {
		if strings.EqualFold(acac, "true") {
			emit(LCrit, "wildcard ACAO (*) with credentials allowed — CORS misconfiguration")
		} else {
			emit(LWarn, "wildcard ACAO (*) present (no credentials allowed)")
		}
	} else if strings.EqualFold(acao, origin) {
		emit(LCrit, "ACAO reflects arbitrary Origin — CORS misconfiguration (origin: "+origin+")")
		emit(LInfo, "ACAC: "+acac)
	} else {
		emit(LOk, "ACAO fixed to "+acao+" (not reflected)")
	}
	return nil
}

// OpenRedirect tests common redirect parameters with an external URL
// payload and flags 3xx responses that send the victim off-site.
func OpenRedirect(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "open redirect check — "+base)

	params := []string{"url", "redirect", "redir", "redirecturl", "redirect_uri",
		"next", "nexturl", "return", "returnurl", "return_url", "goto", "continue",
		"cont", "dest", "destination", "rurl", "u", "link", "out", "view", "to"}
	external := "https://evil-example.net/evil"
	baseHost := HostFromTarget(base)

	found := false
	for _, p := range params {
		if ctx.Err() != nil {
			return nil
		}
		u := base + "?" + url.QueryEscape(p) + "=" + url.QueryEscape(external)
		r, err := Req(ctx, "GET", u, nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		if r.Status >= 300 && r.Status < 400 {
			loc := r.Header.Get("Location")
			if loc == "" {
				continue
			}
			lu, err := url.Parse(loc)
			if err != nil || lu.Host == "" {
				if strings.Contains(loc, "evil-example.net") {
					found = true
					emit(LCrit, fmt.Sprintf("[OPEN REDIRECT] param %q -> %s", p, loc))
				}
				continue
			}
			if lu.Host != baseHost && !strings.EqualFold(lu.Host, "evil-example.net") {
				found = true
				emit(LCrit, fmt.Sprintf("[OPEN REDIRECT] param %q -> %s", p, loc))
			}
		}
	}
	if !found {
		emit(LOk, "no open redirect via common parameters detected")
	}
	return nil
}

// HostHeaderInjection sends a tampered Host header and checks whether the
// injected value is reflected in the response or changes the response.
func HostHeaderInjection(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "host header injection — "+base)

	payload := fmt.Sprintf("evil-%d.example.com", time.Now().UnixNano()%1000000)

	baseline, err := Req(ctx, "GET", base, nil, nil, 8*time.Second)
	if err != nil {
		emit(LWarn, "baseline request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", base, nil)
	if err != nil {
		emit(LWarn, "request build failed: "+err.Error())
		return nil
	}
	req.Host = payload
	req.Header.Set("User-Agent", "hacklith/1.0 (authorized security testing)")
	resp, err := httpClient(8 * time.Second).Do(req)
	if err != nil {
		emit(LWarn, "host-header request failed: "+err.Error())
		return nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if ctx.Err() != nil {
		return nil
	}
	body := string(data)
	statusChanged := resp.StatusCode != baseline.Status
	reflected := strings.Contains(body, payload) || strings.Contains(headerBlob(resp.Header), payload)

	switch {
	case reflected:
		emit(LCrit, "Host header value reflected in response (potential cache poisoning / routing injection)")
	case statusChanged:
		emit(LWarn, fmt.Sprintf("Host header altered response: %d -> %d", baseline.Status, resp.StatusCode))
	default:
		emit(LOk, "Host header injection not observed (status unchanged, not reflected)")
	}
	return nil
}

// LFIProbe tests for local file inclusion / path traversal by injecting
// traversal sequences into common parameters and looking for file
// contents in the response.
func LFIProbe(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "local file inclusion probe — "+base)

	traversals := []string{
		"../../../../etc/passwd",
		"../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"....//....//....//etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"../../windows/win.ini",
		"/etc/passwd",
		"/proc/self/environ",
	}
	params := []string{"file", "page", "path", "include", "doc", "view", "cat", "dir", "download", "f", "p", "read", "content", "folder", "name"}

	signatures := []struct {
		sig, label string
	}{
		{"root:x:", "Unix /etc/passwd"},
		{"root:!:","Unix /etc/passwd"},
		{"[extensions]", "Windows win.ini"},
		{"for 16-bit app support", "Windows win.ini"},
		{"PATH=", "Unix /proc/self/environ"},
	}

	found := false
	for _, p := range params {
		if ctx.Err() != nil {
			return nil
		}
		for _, t := range traversals {
			if ctx.Err() != nil {
				return nil
			}
			u := base + "?" + url.QueryEscape(p) + "=" + url.QueryEscape(t)
			r, err := Req(ctx, "GET", u, nil, nil, 8*time.Second)
			if err != nil {
				continue
			}
			body := string(r.Body)
			for _, s := range signatures {
				if strings.Contains(body, s.sig) {
					found = true
					emit(LCrit, fmt.Sprintf("[LFI] param %q with traversal %q -> %s", p, t, s.label))
					break
				}
			}
		}
	}
	if !found {
		emit(LOk, "no local file inclusion signatures detected")
	}
	return nil
}

// CMDIProbe tests for OS command injection by injecting shell metacharacters
// carrying id/whoami/pwd payloads and looking for command output.
func CMDIProbe(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "command injection probe — "+base)

	payloads := []string{
		";id", "|id", "`id`", "$(id)", "||id", "&&id",
		";whoami", "|whoami", ";cat /etc/passwd",
		"| ping -c 1 127.0.0.1", ";uname -a",
	}
	params := []string{"cmd", "command", "exec", "execute", "ping", "query", "host", "ip", "url", "uri", "path", "file", "input", "date", "name", "id", "c", "q"}

	signatures := []string{"uid=", "gid=", "groups=", "root:", "windows", "no such file", "bin/bash", "daemon:"}

	found := false
	for _, p := range params {
		if ctx.Err() != nil {
			return nil
		}
		for _, pl := range payloads {
			if ctx.Err() != nil {
				return nil
			}
			u := base + "?" + url.QueryEscape(p) + "=" + url.QueryEscape(pl)
			r, err := Req(ctx, "GET", u, nil, nil, 8*time.Second)
			if err != nil {
				continue
			}
			body := strings.ToLower(string(r.Body))
			for _, s := range signatures {
				if strings.Contains(body, s) {
					found = true
					emit(LCrit, fmt.Sprintf("[CMDi] param %q payload %q -> output signature %q", p, pl, s))
					break
				}
			}
		}
	}
	if !found {
		emit(LOk, "no command injection signatures detected")
	}
	return nil
}

// CSRFCheck inspects HTML forms for anti-CSRF tokens and warns when
// state-changing forms lack them.
func CSRFCheck(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "csrf token audit — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		emit(LWarn, "request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	formRx := regexp.MustCompile(`(?is)<form\b.*?</form>`)
	hiddenRx := regexp.MustCompile(`(?is)<input[^>]*type=["']?hidden["']?[^>]*name=["']?([^"'\s>]+)`)
	csrfWords := []string{"csrf", "token", "_token", "xsrf", "authenticity", "csrf_token", "csrfmiddlewaretoken", "nonce", "secret", "state"}

	forms := formRx.FindAllString(string(r.Body), -1)
	if len(forms) == 0 {
		emit(LDim, "no <form> elements found on target page")
		return nil
	}
	emit(LInfo, fmt.Sprintf("%d form(s) found", len(forms)))

	total := 0
	withToken := 0
	for _, f := range forms {
		total++
		has := false
		for _, m := range hiddenRx.FindAllStringSubmatch(f, -1) {
			name := strings.ToLower(m[1])
			for _, w := range csrfWords {
				if strings.Contains(name, w) {
					has = true
					break
				}
			}
			if has {
				break
			}
		}
		if has {
			withToken++
		}
	}
	if withToken == total {
		emit(LOk, fmt.Sprintf("all %d form(s) include a CSRF token field", total))
	} else {
		emit(LWarn, fmt.Sprintf("%d/%d form(s) lack a detectable CSRF token — potential CSRF exposure", total-withToken, total))
	}
	return nil
}

// RateLimitTest sends 10 rapid requests and warns if no throttling
// (429 / 403 / connection reset) is observed.
func RateLimitTest(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "rate limiting test — "+base)

	blocked := 0
	reset := 0
	for i := 0; i < 10; i++ {
		if ctx.Err() != nil {
			return nil
		}
		r, err := Req(ctx, "GET", base, nil, nil, 6*time.Second)
		if err != nil {
			if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "reset by peer") {
				reset++
			}
			continue
		}
		if r.Status == 429 || r.Status == 503 {
			blocked++
		} else if r.Status == 403 {
			emit(LDim, "403 observed (may indicate rate limiting)")
			blocked++
		}
	}
	if blocked > 0 || reset > 0 {
		emit(LOk, fmt.Sprintf("rate limiting detected (blocked=%d conn-reset=%d)", blocked, reset))
	} else {
		emit(LWarn, "no rate limiting detected across 10 rapid requests")
	}
	return nil
}

// SSLComprehensive performs a TLS audit: supported protocol versions,
// certificate chain details, HSTS and a note on certificate transparency.
func SSLComprehensive(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "comprehensive tls audit — "+base)

	host := HostFromTarget(base)
	port := 443
	if u, err := url.Parse(base); err == nil && u.Port() != "" {
		if p, e := net.LookupPort("tcp", u.Port()); e == nil {
			port = p
		} else if n, e2 := atoiSafe(u.Port()); e2 == nil {
			port = n
		}
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	emit(LDim, "target: "+addr)

	// Negotiated protocol & cert chain.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		emit(LWarn, "tls handshake failed: "+err.Error())
		return nil
	}
	st := conn.ConnectionState()
	emit(LOk, fmt.Sprintf("negotiated protocol: %s (version 0x%x)", orElse(st.NegotiatedProtocol, "http/1.1", st.NegotiatedProtocol), st.Version))
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		emit(LInfo, fmt.Sprintf("subject: %s", c.Subject))
		emit(LInfo, fmt.Sprintf("issuer: %s", c.Issuer))
		emit(LInfo, fmt.Sprintf("valid until: %s", c.NotAfter.Format("2006-01-02")))
		if len(c.DNSNames) > 0 {
			emit(LDim, "SANs: "+strings.Join(c.DNSNames, ", "))
		}
		emit(LDim, fmt.Sprintf("key algo: %v", c.PublicKeyAlgorithm))
	}
	conn.Close()

	// Supported protocol version matrix.
	for _, v := range []struct {
		ver uint16
		name string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
	} {
		if ctx.Err() != nil {
			return nil
		}
		ok := tlsVersionSupported(addr, v.ver)
		lvl := LOk
		if (v.ver == tls.VersionTLS10 || v.ver == tls.VersionTLS11) && ok {
			lvl = LWarn
		}
		emit(lvl, fmt.Sprintf("%s: %s", v.name, mapTrue(ok)))
	}

	// HSTS.
	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err == nil {
		if h := r.Header.Get("Strict-Transport-Security"); h != "" {
			emit(LOk, "HSTS: "+h)
		} else {
			emit(LWarn, "HSTS header not present")
		}
	}

	emit(LDim, "certificate transparency: verify via crt.sh / Google CT logs manually")
	return nil
}

func tlsVersionSupported(addr string, ver uint16) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, MinVersion: ver, MaxVersion: ver})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func atoiSafe(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func mapTrue(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// GitExposure checks for exposed .git metadata (config, HEAD, objects).
func GitExposure(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "exposed git metadata — "+base)

	checks := []struct {
		path, sig, label string
	}{
		{".git/config", "[core]", ".git/config"},
		{".git/HEAD", "ref:", ".git/HEAD"},
		{".git/objects/info/packs", "P pack", ".git/objects/info/packs"},
		{".git/index", "", ".git/index"},
		{".git/logs/HEAD", "commit", ".git/logs/HEAD"},
	}
	found := false
	for _, c := range checks {
		if ctx.Err() != nil {
			return nil
		}
		r, err := Req(ctx, "GET", JoinURL(base, c.path), nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		if r.Status == 200 && (c.sig == "" || strings.Contains(string(r.Body), c.sig)) {
			found = true
			emit(LCrit, fmt.Sprintf("[GIT] %s exposed (HTTP %d, %d bytes)", c.label, r.Status, len(r.Body)))
		}
	}
	if !found {
		emit(LOk, "no exposed .git metadata detected")
	}
	return nil
}

// DotEnvExposure checks for exposed environment / secrets files.
func DotEnvExposure(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "exposed env/secrets files — "+base)

	paths := []string{".env", ".env.bak", ".env.local", ".env.prod", ".env.save", ".env.dev", ".env.example"}
	sigs := []string{"APP_", "DB_", "SECRET", "API_KEY", "PASSWORD", "TOKEN", "AWS_", "DATABASE_URL"}
	found := false
	for _, p := range paths {
		if ctx.Err() != nil {
			return nil
		}
		r, err := Req(ctx, "GET", JoinURL(base, p), nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		if r.Status != 200 {
			continue
		}
		body := string(r.Body)
		hit := false
		for _, s := range sigs {
			if strings.Contains(body, s) {
				hit = true
				break
			}
		}
		if hit {
			found = true
			emit(LCrit, fmt.Sprintf("[ENV] %s exposed (HTTP %d, %d bytes)", p, r.Status, len(r.Body)))
		}
	}
	if !found {
		emit(LOk, "no exposed .env/secrets files detected")
	}
	return nil
}

// RobotsAnalysis fetches robots.txt and inspects Disallow entries for
// sensitive paths and a sitemap directive.
func RobotsAnalysis(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "robots.txt analysis — "+base)

	r, err := Req(ctx, "GET", JoinURL(base, "robots.txt"), nil, nil, 8*time.Second)
	if err != nil || r.Status != 200 {
		emit(LDim, "robots.txt not available (HTTP " + strconv.Itoa(r.Status) + ")")
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	body := string(r.Body)
	disallowRx := regexp.MustCompile(`(?im)^\s*disallow\s*:\s*(.+)$`)
	sitemapRx := regexp.MustCompile(`(?im)^\s*sitemap\s*:\s*(.+)$`)
	sensitive := []string{"admin", "wp-admin", "login", "config", "backup", ".git", "api", "private", "secret", "user", "account", ".env"}

	var disallows []string
	for _, m := range disallowRx.FindAllStringSubmatch(body, -1) {
		disallows = append(disallows, strings.TrimSpace(m[1]))
	}
	emit(LInfo, fmt.Sprintf("%d Disallow directive(s)", len(disallows)))
	for _, d := range disallows {
		lc := strings.ToLower(d)
		for _, s := range sensitive {
			if strings.Contains(lc, s) {
				emit(LWarn, "sensitive disallow: "+d)
				break
			}
		}
	}
	if m := sitemapRx.FindStringSubmatch(body); len(m) > 1 {
		emit(LOk, "sitemap directive: "+strings.TrimSpace(m[1]))
	} else {
		emit(LDim, "no sitemap directive present")
	}
	return nil
}

// SitemapAnalysis fetches sitemap.xml, parses <loc> URLs and looks for
// sensitive paths being exposed.
func SitemapAnalysis(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "sitemap.xml analysis — "+base)

	r, err := Req(ctx, "GET", JoinURL(base, "sitemap.xml"), nil, nil, 8*time.Second)
	if err != nil || r.Status != 200 {
		emit(LDim, "sitemap.xml not available (HTTP " + strconv.Itoa(r.Status) + ")")
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	locRx := regexp.MustCompile(`(?is)<loc>([^<]+)</loc>`)
	locs := locRx.FindAllStringSubmatch(string(r.Body), -1)
	emit(LInfo, fmt.Sprintf("%d <loc> URL(s) found", len(locs)))
	sensitive := []string{"admin", "wp-admin", "login", "config", "backup", "api", "private", ".git", "user", "account", ".env", "phpmyadmin"}
	for _, m := range locs {
		u := strings.TrimSpace(m[1])
		lc := strings.ToLower(u)
		for _, s := range sensitive {
			if strings.Contains(lc, s) {
				emit(LWarn, "sensitive sitemap entry: "+u)
				break
			}
		}
	}
	if len(locs) == 0 {
		emit(LDim, "no <loc> entries parsed")
	}
	return nil
}

// WPEnum enumerates WordPress users/version and checks xmlrpc.
func WPEnum(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "wordpress enumeration — "+base)

	// Users via REST API.
	for _, endpoint := range []string{"/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"} {
		if ctx.Err() != nil {
			return nil
		}
		r, err := Req(ctx, "GET", JoinURL(base, endpoint), nil, nil, 8*time.Second)
		if err != nil || r.Status != 200 {
			continue
		}
		if strings.Contains(string(r.Body), "slug") && strings.Contains(string(r.Body), "name") {
			emit(LCrit, "[WP] users enumerated via "+endpoint)
			break
		}
	}

	// xmlrpc.php presence.
	if ctx.Err() == nil {
		if r, err := Req(ctx, "GET", JoinURL(base, "xmlrpc.php"), nil, nil, 8*time.Second); err == nil {
			if r.Status == 200 || r.Status == 405 {
				emit(LWarn, "[WP] xmlrpc.php present (HTTP "+strconv.Itoa(r.Status)+") — brute-force amplification risk")
			}
		}
	}

	// Version from generator meta.
	if ctx.Err() == nil {
		if r, err := Req(ctx, "GET", base, nil, nil, 8*time.Second); err == nil {
			if v := GeneratorMeta(r.Body); strings.Contains(strings.ToLower(v), "wordpress") {
				emit(LInfo, "[WP] version hint: "+v)
			} else if strings.Contains(strings.ToLower(string(r.Body)), "wp-content") {
				emit(LDim, "[WP] WordPress indicators present (wp-content)")
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	emit(LDim, "wordpress enumeration complete")
	return nil
}

// JSSecrets fetches linked JavaScript files and scans them for API keys,
// tokens and private-key material using regex patterns.
func JSSecrets(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "javascript secret scanning — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		emit(LWarn, "request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	srcRx := regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
	seen := map[string]bool{}
	var jsURLs []string
	for _, m := range srcRx.FindAllStringSubmatch(string(r.Body), -1) {
		u := m[1]
		if strings.HasPrefix(u, "//") {
			u = "http:" + u
		} else if strings.HasPrefix(u, "/") {
			u = JoinURL(base, u)
		} else if !strings.Contains(u, "://") {
			u = JoinURL(base, u)
		}
		if !seen[u] {
			seen[u] = true
			jsURLs = append(jsURLs, u)
		}
	}
	emit(LDim, fmt.Sprintf("%d script src(s) to scan", len(jsURLs)))

	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"AWS secret", regexp.MustCompile(`(?i)aws_secret_access_key["'\s:=]+([A-Za-z0-9/+=]{40})`)},
		{"GitHub token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
		{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
		{"Slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]+`)},
		{"Stripe key", regexp.MustCompile(`sk_live_[0-9A-Za-z]+`)},
		{"Private key", regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`)},
		{"Generic API key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["'\s:=]+([A-Za-z0-9_\-]{16,})`)},
	}

	found := 0
	for _, u := range jsURLs {
		if ctx.Err() != nil {
			return nil
		}
		jr, err := Req(ctx, "GET", u, nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		body := string(jr.Body)
		for _, p := range patterns {
			if m := p.re.FindString(body); m != "" {
				found++
				emit(LCrit, fmt.Sprintf("[SECRET] %s in %s -> %s", p.name, u, truncate(m, 48)))
			}
		}
	}
	if found == 0 {
		emit(LOk, "no obvious secrets found in linked JS")
	}
	return nil
}

// BannerGrab performs a lightweight port scan of common ports and grabs
// service banners where available.
func BannerGrab(ctx context.Context, target string, opts Options, emit Emit) error {
	host := HostFromTarget(target)
	emit(LHl, "banner grab / service fingerprint — "+host)

	ports := wordlists.CommonPorts
	var open []struct {
		port int
		banner string
	}
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
		if err != nil {
			continue
		}
		conn.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		banner := strings.TrimSpace(string(buf[:n]))
		conn.Close()
		svc := wordlists.PortServices[p]
		open = append(open, struct {
			port int
			banner string
		}{p, banner})
		if svc != "" {
			emit(LOk, fmt.Sprintf("open %-6d %-18s %s", p, svc, truncate(banner, 60)))
		} else {
			emit(LOk, fmt.Sprintf("open %-6d %-18s %s", p, "unknown", truncate(banner, 60)))
		}
	}
	if len(open) == 0 {
		emit(LWarn, "no open ports responded (host filtered or unreachable)")
	}
	return nil
}

// CVEMatch fingerprints technologies on the target and matches detected
// versions against known-vulnerable advisories (best-effort, not CVE db).
func CVEMatch(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "technology / cve correlation — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		emit(LWarn, "request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	hblob := headerBlob(r.Header)
	body := strings.ToLower(string(r.Body))
	gen := strings.ToLower(GeneratorMeta(r.Body))

	techs := map[string]string{}
	for name, sig := range map[string]string{
		"nginx":        "nginx",
		"apache":       "apache",
		"microsoft-iis": "iis",
		"openssl":      "openssl",
		"php":          "php/",
		"jetty":        "jetty",
		"tomcat":       "tomcat",
		"node.js":      "express",
		"wordpress":    "wordpress",
		"drupal":       "drupal",
		"joomla":       "joomla",
	} {
		if strings.Contains(hblob, sig) || strings.Contains(body, sig) || strings.Contains(gen, sig) {
			techs[name] = ""
		}
	}
	// Capture versioned techs (e.g. nginx/1.16.1, PHP/7.2).
	verRx := regexp.MustCompile(`(?i)(nginx|apache|php|openssl|iis|tomcat|jetty)/([0-9][0-9a-z.\-]+)`)
	for _, m := range verRx.FindAllStringSubmatch(hblob+gen, -1) {
		techs[strings.ToLower(m[1])] = m[2]
	}

	if len(techs) == 0 {
		emit(LDim, "no recognizable technologies fingerprinted")
		return nil
	}

	cves := map[string][]string{
		"nginx":   {"CVE-2019-9511..9516 (HTTP/2 DoS in some builds)", "CVE-2018-16843/16844 (mp4 module)"},
		"apache":  {"CVE-2021-41773 / CVE-2021-42013 (path traversal RCE in 2.4.49/2.4.50)"},
		"php":     {"CVE-2019-11043 (php-fpm RCE on some builds)", "CVE-2012-1823 (CGI RCE in old PHP)"},
		"openssl": {"CVE-2014-0160 (Heartbleed)", "CVE-2022-3602 / CVE-2022-3786 (X.509 buffer overflow)"},
		"tomcat":  {"CVE-2020-1938 (Ghostcat AJP file read/inclusion)", "CVE-2019-0232 (CGI RCE on Windows)"},
		"iis":     {"CVE-2015-1635 (HTTP.sys RCE)", "CVE-2017-7269 (WebDAV RCE on IIS 6)"},
		"wordpress": {"Numerous plugin CVEs — verify plugin versions separately"},
	}
	for name, ver := range techs {
		emit(LInfo, fmt.Sprintf("tech: %s %s", name, orElse(ver, "(version unknown)", ver)))
		if adv, ok := cves[name]; ok {
			for _, a := range adv {
				emit(LWarn, fmt.Sprintf("potential advisory for %s: %s", name, a))
			}
		}
	}
	emit(LDim, "manual CVE verification recommended against exact detected versions")
	return nil
}

// DirListDetect probes common directories for enabled directory listing
// ("Index of /").
func DirListDetect(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "directory listing detection — "+base)

	dirs := []string{"", "images", "uploads", "assets", "js", "css", "static", "includes", "tmp", "backup", "backups", "files", "media", "logs", "admin", "api", "docs"}
	found := false
	for _, d := range dirs {
		if ctx.Err() != nil {
			return nil
		}
		u := base
		if d != "" {
			u = JoinURL(base, d)
		}
		r, err := Req(ctx, "GET", u+"/", nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		if strings.Contains(string(r.Body), "Index of /") {
			found = true
			emit(LCrit, fmt.Sprintf("[DIR LIST] listing enabled: %s (HTTP %d)", u+"/", r.Status))
		}
	}
	if !found {
		emit(LOk, "no directory listing detected on probed paths")
	}
	return nil
}

// BackupHunt looks for backup/source archives on common paths.
func BackupHunt(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "backup & source file hunting — "+base)

	files := []string{
		"index.php.bak", "index.php~", "index.php.old", "index.php.save", "index.php.swp",
		"config.php.bak", "config.php~", "config.php.old", "config.php.save",
		"wp-config.php.bak", "wp-config.php~", "wp-config.php.old",
		"login.php.bak", ".htaccess.bak", ".htpasswd.bak",
		"backup.zip", "backup.tar.gz", "site.zip", "site.tar.gz", "www.zip", "wwwroot.zip",
		"db.sql", "database.sql", "dump.sql", "app.sql", "site.sql",
		"backup.sql", "old.sql", "db.dump", "dump",
	}
	found := false
	for _, f := range files {
		if ctx.Err() != nil {
			return nil
		}
		r, err := Req(ctx, "GET", JoinURL(base, f), nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		if r.Status == 200 && len(r.Body) > 0 {
			found = true
			emit(LCrit, fmt.Sprintf("[BACKUP] %s exposed (HTTP %d, %d bytes)", f, r.Status, len(r.Body)))
		}
	}
	if !found {
		emit(LOk, "no backup/source files exposed on probed paths")
	}
	return nil
}

// EmailHarvest extracts email addresses from HTTP responses.
func EmailHarvest(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "email address harvesting — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		emit(LWarn, "request failed: "+err.Error())
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	emailRx := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	seen := map[string]bool{}
	var emails []string
	for _, m := range emailRx.FindAllString(string(r.Body), -1) {
		if !seen[m] {
			seen[m] = true
			emails = append(emails, m)
		}
	}
	if len(emails) == 0 {
		emit(LDim, "no email addresses found on target page")
		return nil
	}
	emit(LInfo, fmt.Sprintf("%d email address(es) found", len(emails)))
	for _, e := range emails {
		emit(LWarn, "email: "+e)
	}
	return nil
}

// WaybackURLs queries the Wayback Machine CDX API for historical URLs of
// the target host. Requires curl; otherwise a skip notice is emitted.
func WaybackURLs(ctx context.Context, target string, opts Options, emit Emit) error {
	host := HostFromTarget(target)
	emit(LHl, "wayback machine url discovery — "+host)

	if _, err := exec.LookPath("curl"); err != nil {
		emit(LInfo, "curl not available — skipping wayback enumeration (install curl or run manually)")
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	api := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&collapse=urlkey", host)
	cmd := exec.CommandContext(ctx, "curl", "-s", "--max-time", "20", api)
	out, err := cmd.Output()
	if err != nil {
		emit(LWarn, "wayback query failed: "+err.Error())
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	uniq := map[string]bool{}
	var urls []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || uniq[l] {
			continue
		}
		uniq[l] = true
		urls = append(urls, l)
	}
	if len(urls) == 0 {
		emit(LDim, "no wayback URLs returned")
		return nil
	}
	emit(LOk, fmt.Sprintf("%d historical URL(s) from Wayback Machine", len(urls)))
	for _, u := range urls[:min(len(urls), 25)] {
		emit(LDim, u)
	}
	return nil
}

// GraphQLIntrospection probes common GraphQL endpoints with an
// introspection query and reports enabled endpoints.
func GraphQLIntrospection(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "graphql introspection probe — "+base)

	endpoints := []string{"/graphql", "/api/graphql", "/graphql/v1", "/query", "/gql", "/api/graphql/v1"}
	query := `{"query":"{__schema{queryType{name}}}"}`
	found := false
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			return nil
		}
		u := JoinURL(base, ep)
		r, err := Req(ctx, "POST", u, strings.NewReader(query),
			map[string]string{"Content-Type": "application/json"}, 8*time.Second)
		if err != nil {
			continue
		}
		body := strings.ToLower(string(r.Body))
		if strings.Contains(body, "__schema") || strings.Contains(body, "querytype") {
			found = true
			emit(LCrit, fmt.Sprintf("[GRAPHQL] introspection enabled: %s (HTTP %d)", u, r.Status))
		}
	}
	if !found {
		emit(LOk, "no GraphQL introspection endpoint detected on probed paths")
	}
	return nil
}

// APIFuzz probes common API paths for exposed (non-404) endpoints.
func APIFuzz(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "api endpoint fuzzing — "+base)

	paths := []string{
		"/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
		"/swagger", "/swagger.json", "/swagger-ui", "/swagger-ui/", "/openapi.json", "/openapi",
		"/graphql", "/api/graphql", "/rest", "/api/rest", "/api/docs", "/docs", "/redoc",
		"/actuator", "/metrics", "/health",
	}
	found := 0
	for _, p := range paths {
		if ctx.Err() != nil {
			return nil
		}
		r, err := Req(ctx, "GET", JoinURL(base, p), nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		switch {
		case r.Status == 200:
			found++
			emit(LOk, fmt.Sprintf("%-6d %s  [api responds]", r.Status, p))
		case r.Status == 401 || r.Status == 403:
			found++
			emit(LWarn, fmt.Sprintf("%-6d %s  [exists but restricted]", r.Status, p))
		case r.Status == 405:
			found++
			emit(LInfo, fmt.Sprintf("%-6d %s  [exists, method not allowed]", r.Status, p))
		}
	}
	if found == 0 {
		emit(LDim, "no exposed API endpoints on probed paths")
	}
	return nil
}

// HTTP2Check determines whether the server advertises/supports HTTP/2 via
// the Alt-Svc header or a direct ALPN negotiation test.
func HTTP2Check(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "http/2 support check — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err == nil {
		if v := r.Header.Get("Alt-Svc"); v != "" {
			if strings.Contains(strings.ToLower(v), "h2") || strings.Contains(strings.ToLower(v), "h2c") {
				emit(LOk, "HTTP/2 advertised via Alt-Svc: "+v)
			} else {
				emit(LDim, "Alt-Svc present but no h2: "+v)
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}

	host := HostFromTarget(base)
	port := 443
	if u, e := url.Parse(base); e == nil && u.Port() != "" {
		if n, e2 := atoiSafe(u.Port()); e2 == nil {
			port = n
		}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		emit(LWarn, "tls connect for h2 test failed: "+err.Error())
		return nil
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		emit(LOk, "HTTP/2 negotiated successfully (ALPN h2)")
	} else {
		emit(LDim, "HTTP/2 not negotiated (ALPN: "+orElse(conn.ConnectionState().NegotiatedProtocol, "none", conn.ConnectionState().NegotiatedProtocol)+")")
	}
	return nil
}
