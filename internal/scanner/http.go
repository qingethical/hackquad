package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/qingethical/hacklith/internal/wordlists"
)

// Probe fingerprints a web target: status, headers, title, generator,
// cookies and TLS certificate info.
func Probe(ctx context.Context, target string, _ Options, emit Emit) error {
	base := Normalize(target)
	emit(LHl, "target: "+base)

	attempts := []string{base}
	if !strings.Contains(base, "://") {
		attempts = []string{"http://" + base, "https://" + base}
	}
	var r *Resp
	var used string
	for _, u := range attempts {
		resp, err := Req(ctx, "GET", u, nil, nil, 12*time.Second)
		if err != nil {
			emit(LDim, fmt.Sprintf("request failed (%s): %v", u, err))
			continue
		}
		r = resp
		used = u
		break
	}
	if r == nil {
		emit(LCrit, "could not reach target over http or https")
		return nil
	}

	emit(LOk, fmt.Sprintf("status   %d", r.Status))
	if s := r.Header.Get("Server"); s != "" {
		emit(LHl, "server   "+s)
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		emit(LInfo, "content-type  "+ct)
	}
	if p := r.Header.Get("X-Powered-By"); p != "" {
		emit(LHl, "x-powered-by  "+p)
	}
	if loc := r.Header.Get("Location"); loc != "" {
		emit(LWarn, "redirects to: "+loc)
	}
	if t := PageTitle(r.Body); t != "" {
		emit(LInfo, "title    "+t)
	}
	if g := GeneratorMeta(r.Body); g != "" {
		emit(LHl, "generator: "+g)
	}
	emit(LInfo, fmt.Sprintf("response %d bytes in %s", len(r.Body), r.Dur.Round(time.Millisecond)))

	if len(r.Header["Set-Cookie"]) > 0 {
		emit(LInfo, fmt.Sprintf("%d cookie(s) set:", len(r.Header["Set-Cookie"])))
		for _, c := range r.Header["Set-Cookie"] {
			flagNote := cookieFlags(c)
			if flagNote == "" {
				emit(LWarn, "  cookie  "+c+"  [missing Secure/HttpOnly flags]")
			} else {
				emit(LInfo, "  cookie  "+c+"  ["+flagNote+"]")
			}
		}
	}

	// TLS certificate info when https.
	if strings.HasPrefix(used, "https://") {
		emitTLSInfo(ctx, used, emit)
	}
	return nil
}

func emitTLSInfo(ctx context.Context, u string, emit Emit) {
	host := HostFromTarget(u)
	conn, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		emit(LDim, "tls: "+err.Error())
		return
	}
	defer conn.Close()
	tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tconn.Handshake(); err != nil {
		emit(LDim, "tls handshake: "+err.Error())
		return
	}
	cs := tconn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		emit(LDim, "tls: no peer certificate")
		return
	}
	cert := cs.PeerCertificates[0]
	emit(LInfo, "tls: "+cert.Subject.CommonName)
	emit(LInfo, "tls: issuer "+cert.Issuer.String())
	emit(LInfo, "tls: valid "+cert.NotBefore.Format("2006-01-02")+" .. "+cert.NotAfter.Format("2006-01-02"))
	expires := time.Until(cert.NotAfter)
	if expires < 30*24*time.Hour {
		emit(LWarn, fmt.Sprintf("tls: certificate expires in %s (renew soon)", expires.Round(time.Hour)))
	}
}

func cookieFlags(c string) string {
	var flags []string
	lc := strings.ToLower(c)
	if strings.Contains(lc, "secure") {
		flags = append(flags, "Secure")
	}
	if strings.Contains(lc, "httponly") {
		flags = append(flags, "HttpOnly")
	}
	if strings.Contains(lc, "samesite") {
		flags = append(flags, "SameSite")
	}
	return strings.Join(flags, ",")
}

// HeadersAudit checks for the presence of security-relevant response
// headers on the target root page.
func HeadersAudit(ctx context.Context, target string, _ Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	r, err := Req(ctx, "GET", base, nil, nil, 12*time.Second)
	if err != nil {
		emit(LCrit, "request failed: "+err.Error())
		return nil
	}
	emit(LHl, fmt.Sprintf("security header audit — %s (HTTP %d)", base, r.Status))

	type hdr struct {
		name string
		desc string
	}
	required := []hdr{
		{"Strict-Transport-Security", "forces HTTPS (missing = MITM risk)"},
		{"Content-Security-Policy", "limits script/source loading (missing = XSS risk)"},
		{"X-Frame-Options", "clickjacking protection"},
		{"X-Content-Type-Options", "MIME-sniffing protection"},
		{"Referrer-Policy", "controls referrer leakage"},
		{"Permissions-Policy", "limits browser feature access"},
		{"X-XSS-Protection", "legacy XSS filter"},
		{"Cross-Origin-Embedder-Policy", "prevents cross-origin embedding (missing = COEP risk)"},
		{"Cross-Origin-Opener-Policy", "prevents cross-origin window access (missing = COOP risk)"},
		{"Cross-Origin-Resource-Policy", "prevents cross-origin resource sharing (missing = CORP risk)"},
		{"X-Permitted-Cross-Domain-Policies", "restricts Flash cross-domain (missing = legacy risk)"},
	}
	for _, h := range required {
		if v := r.Header.Get(h.name); v != "" {
			emit(LOk, fmt.Sprintf("%-28s present: %s", h.name, v))
		} else {
			emit(LWarn, fmt.Sprintf("%-28s MISSING — %s", h.name, h.desc))
		}
	}
	if s := r.Header.Get("Server"); s != "" {
		emit(LInfo, "server banner disclosed: "+s)
	}
	if via := r.Header.Get("Via"); via != "" {
		emit(LInfo, "via: "+via)
	}
	if cc := r.Header.Get("Cache-Control"); cc != "" {
		emit(LInfo, "cache-control: "+cc)
		if strings.Contains(strings.ToLower(cc), "no-store") || strings.Contains(strings.ToLower(cc), "no-cache") {
			emit(LHl, "cache-control has no-store/no-cache (good for sensitive data)")
		}
	}
	if pragma := r.Header.Get("Pragma"); pragma != "" {
		emit(LInfo, "pragma: "+pragma)
	}
	if hsts := r.Header.Get("Strict-Transport-Security"); hsts != "" {
		if !strings.Contains(strings.ToLower(hsts), "max-age") {
			emit(LWarn, "hsts missing max-age")
		}
		if !strings.Contains(strings.ToLower(hsts), "includesubdomains") && !strings.Contains(strings.ToLower(hsts), "includeSubDomains") {
			emit(LWarn, "hsts missing includeSubDomains")
		}
	}
	if csp := r.Header.Get("Content-Security-Policy"); csp != "" {
		if strings.Contains(strings.ToLower(csp), "unsafe-inline") || strings.Contains(strings.ToLower(csp), "unsafe-eval") {
			emit(LWarn, "csp contains unsafe-inline or unsafe-eval (weakens xss protection)")
		}
		if strings.Contains(strings.ToLower(csp), "*") && strings.Contains(strings.ToLower(csp), "script-src") {
			emit(LWarn, "csp script-src contains wildcard")
		}
	}
	return nil
}

// CookieAudit inspects the flags of every cookie the target sets.
func CookieAudit(ctx context.Context, target string, _ Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	r, err := Req(ctx, "GET", base, nil, nil, 12*time.Second)
	if err != nil {
		emit(LCrit, "request failed: "+err.Error())
		return nil
	}
	cookies := r.Header["Set-Cookie"]
	if len(cookies) == 0 {
		emit(LDim, "no cookies set on "+base)
		return nil
	}
	emit(LHl, fmt.Sprintf("cookie audit — %d cookie(s) set", len(cookies)))
	for _, c := range cookies {
		name := c
		if i := strings.Index(c, "="); i > 0 {
			name = c[:i]
		}
		flags := cookieFlags(c)
		parts := []string{}
		if flags == "" {
			parts = append(parts, "no Secure/HttpOnly/SameSite flags")
		} else {
			parts = append(parts, flags)
		}
		if !strings.Contains(strings.ToLower(c), "secure") {
			parts = append(parts, "transmitted over http")
		}
		emit(LWarn, fmt.Sprintf("cookie %-24s [%s]", name, strings.Join(parts, ", ")))
	}
	emit(LInfo, "recommendation: Secure + HttpOnly + SameSite=Lax/Strict on every cookie")
	return nil
}

// MethodsCheck probes dangerous and unusual HTTP methods.
func MethodsCheck(ctx context.Context, target string, _ Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	emit(LHl, "http method check — "+base)
	for _, m := range wordlists.Methods {
		if ctx.Err() != nil {
			return nil
		}
		r, err := Req(ctx, m, base, nil, nil, 10*time.Second)
		if err != nil {
			emit(LDim, fmt.Sprintf("%-10s connection error: %v", m, err))
			continue
		}
		extra := ""
		if m == "OPTIONS" {
			if allow := r.Header.Get("Allow"); allow != "" {
				extra = "  allow: " + allow
			}
		}
		switch {
		case m == "TRACE" && r.Status == 200:
			emit(LCrit, fmt.Sprintf("%-10s %d  [TRACE enabled — XST risk]%s", m, r.Status, extra))
		case (m == "PUT" || m == "DELETE" || m == "PATCH" || m == "PROPFIND") && (r.Status == 200 || r.Status == 201 || r.Status == 204 || r.Status == 207):
			emit(LWarn, fmt.Sprintf("%-10s %d  [method allowed — possible file manipulation]%s", m, r.Status, extra))
		default:
			emit(LInfo, fmt.Sprintf("%-10s %d%s", m, r.Status, extra))
		}
	}
	return nil
}

// TechFingerprint identifies the technology stack from headers and HTML.
func TechFingerprint(ctx context.Context, target string, _ Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	r, err := Req(ctx, "GET", base, nil, nil, 12*time.Second)
	if err != nil {
		emit(LCrit, "request failed: "+err.Error())
		return nil
	}
	blob := ""
	for k, v := range r.Header {
		blob += k + ": " + strings.Join(v, ", ") + "\n"
	}
	blob += string(r.Body)

	// Cookie-based fingerprinting (most reliable).
	cookies := ""
	for _, c := range r.Header["Set-Cookie"] {
		cookies += c + " "
	}
	cookieTechs := map[string]string{
		"phpsessid":              "PHP",
		"laravel_session":        "Laravel (PHP)",
		"jsessionid":             "Java (JSP/Servlet)",
		"asp.net_sessionid":      "ASP.NET",
		"csrftoken":              "Django (Python)",
		"django_language":        "Django (Python)",
		"__cfduid":               "Cloudflare",
		"cf_clearance":           "Cloudflare",
		"wp-settings":            "WordPress",
		"wordpress_logged_in":    "WordPress",
		"wp-session":             "WordPress",
		"xtemplate":              "Express (Node.js)",
		"connect.sid":            "Express (Node.js)",
		"sails.sid":              "Sails (Node.js)",
		"rack.session":           "Ruby on Rails",
		"_rails_session":         "Ruby on Rails",
		"tz=":                    "",
	}

	emit(LHl, "tech fingerprint — "+base)
	lc := strings.ToLower(cookies)
	found := map[string]bool{}
	for key, name := range cookieTechs {
		if name == "" {
			continue
		}
		if strings.Contains(lc, key) && !found[name] {
			found[name] = true
			emit(LOk, "cookie → "+name)
		}
	}

	techs := []struct{ name, re string }{
		{"nginx", `nginx`},
		{"Apache", `apache`},
		{"IIS", `microsoft-iis|iis/`},
		{"LiteSpeed", `litespeed`},
		{"Caddy", `caddy`},
		{"Tomcat", `tomcat|coyote`},
		{"Jetty", `jetty`},
		{"Express (Node.js)", `express`},
		{"Node.js", `node\.js|nodejs`},
		{"PHP", `\bphp\b|x-powered-by:\s*php|phpsessid`},
		{"ASP.NET", `asp\.net|x-aspnet-version`},
		{"Java", `jsessionid|\.jsp|java/`},
		{"Ruby on Rails", `rails|ruby on rails|phusion`},
		{"Django", `django|csrftoken`},
		{"Flask", `flask|werkzeug`},
		{"Laravel", `laravel`},
		{"WordPress", `wp-content|wp-includes|wordpress`},
		{"Joomla", `joomla`},
		{"Drupal", `drupal`},
		{"Magento", `magento`},
		{"PrestaShop", `prestashop`},
		{"Grafana", `grafana`},
		{"Jenkins", `jenkins|x-hudson`},
		{"GitLab", `gitlab`},
		{"GitHub Pages", `github pages|github\.com`},
		{"React/Next.js", `_next|__next`},
		{"Vue.js", `vue\.js|__vue__`},
		{"Angular", `ng-version|angular`},
		{"Bootstrap", `bootstrap`},
		{"jQuery", `jquery`},
		{"Webpack", `webpack`},
		{"Cloudflare", `cloudflare|cf-ray|__cfduid`},
		{"Akamai", `akamai`},
		{"Sucuri", `sucuri`},
		{"Varnish", `x-varnish`},
		{"CDN/proxy", `x-cache:|x-served-by`},
		{"HSTS preload", `strict-transport-security`},
	}
	lb := strings.ToLower(blob)
	for _, t := range techs {
		if found[t.name] {
			continue
		}
		if matchAny(lb, t.re) {
			found[t.name] = true
			emit(LOk, "fingerprint → "+t.name)
		}
	}
	if len(found) == 0 {
		emit(LDim, "no obvious technology fingerprints")
	}
	if g := GeneratorMeta(r.Body); g != "" {
		emit(LHl, "generator meta: "+g)
	}
	return nil
}

func matchAny(s, re string) bool {
	parts := strings.Split(re, "|")
	for _, p := range parts {
		if strings.Contains(s, strings.TrimSpace(p)) {
			return true
		}
	}
	return false
}

// Options carries per-module options (wordlist path, port spec).
type Options struct {
	Wordlist string
	Ports    string
}

var _ = sort.Strings

