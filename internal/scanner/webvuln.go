package scanner

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/qingethical/hacklith/internal/wordlists"
)

// AdminFind locates admin panels and sensitive files.
func AdminFind(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	paths := wordlists.AdminPaths
	if opts.Wordlist != "" {
		if loaded, err := loadWordlist(opts.Wordlist); err == nil && len(loaded) > 0 {
			paths = loaded
		}
	}
	emit(LHl, fmt.Sprintf("admin/sensitive path discovery — %s", base))

	nf := sniffNotFound(ctx, base)
	var hits int
	for _, p := range paths {
		if ctx.Err() != nil {
			return nil
		}
		u := JoinURL(base, p)
		r, err := Req(ctx, "GET", u, nil, nil, 8*time.Second)
		if err != nil {
			continue
		}
		if nf != nil && r.Status == nf.Status {
			if nf.Body != "" && string(r.Body) == nf.Body {
				continue
			}
			if nf.Body == "" && len(r.Body) == nf.Size {
				continue
			}
		}
		hits++
		desc := classifyAdminPath(p, r)
		emit(LOk, fmt.Sprintf("%-6d %-5d %s  %s", r.Status, len(r.Body), u, desc))
	}
	if hits == 0 {
		emit(LWarn, "no admin/sensitive paths exposed (or all return 404)")
	} else {
		emit(LInfo, fmt.Sprintf("%d interesting path(s) found", hits))
	}
	return nil
}

func classifyAdminPath(path string, r *Resp) string {
	lc := strings.ToLower(path + " " + string(r.Body[:min(len(r.Body), 512)]))
	hasLogin := strings.Contains(lc, "password") || strings.Contains(lc, "login") ||
		strings.Contains(lc, "username") || strings.Contains(lc, "sign in")
	switch {
	case strings.Contains(path, ".git"):
		return "[exposed git metadata]"
	case strings.Contains(path, "config.php.bak") || strings.Contains(path, "wp-config"):
		return "[source/backup file exposed]"
	case strings.Contains(path, "phpmyadmin") || strings.Contains(path, "adminer"):
		return "[database admin panel]"
	case strings.Contains(path, "server-status"):
		return "[apache server-status exposed]"
	case r.Status == 401 || r.Status == 403:
		return "[restricted]"
	case r.Status >= 200 && r.Status < 300 && hasLogin:
		return "[login panel]"
	case r.Status >= 200 && r.Status < 300:
		return "[admin-ish page]"
	}
	return ""
}

// LoginProbe tries weak default credentials against HTML login forms.
// It detects the form fields from the page and submits via POST.
func LoginProbe(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	emit(LHl, "weak credential probe — "+base)

	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		emit(LCrit, "request failed: "+err.Error())
		return nil
	}
	form, err := findLoginForm(r.Body)
	if err != nil {
		emit(LWarn, "no login form detected on "+base+" — try the admin module to locate a panel")
		return nil
	}
	action := form.action
	if action == "" {
		action = base
	} else if strings.HasPrefix(action, "/") {
		action = Normalize(base) + action
	} else if !strings.Contains(action, "://") {
		action = strings.TrimSuffix(base, "/") + "/" + action
	}
	emit(LInfo, fmt.Sprintf("form -> %s  (user=%q pass=%q%s)", action, form.userField, form.passField, orElse(form.csrfField, " no-csrf", " csrf="+form.csrfField)))

	creds := wordlists.WeakCreds
	if opts.Wordlist != "" {
		if loaded, err := loadCreds(opts.Wordlist); err == nil && len(loaded) > 0 {
			creds = loaded
		}
	}
	emit(LInfo, fmt.Sprintf("trying %d credential pair(s)", len(creds)))

	var found bool
	for _, c := range creds {
		if ctx.Err() != nil {
			return nil
		}
		formData := url.Values{}
		formData.Set(form.userField, c.User)
		formData.Set(form.passField, c.Pass)
		if form.csrfField != "" {
			formData.Set(form.csrfField, form.csrfValue)
		}
		body := strings.NewReader(formData.Encode())
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		resp, err := Req(ctx, "POST", action, body, headers, 12*time.Second)
		if err != nil {
			emit(LDim, fmt.Sprintf("%s:%s — request error: %v", c.User, c.Pass, err))
			continue
		}
		if loginSucceeded(resp) {
			found = true
			emit(LCrit, fmt.Sprintf("VALID CREDENTIALS  %s : %s  (HTTP %d, %s)", c.User, c.Pass, resp.Status, resp.URL))
			break
		}
		emit(LDim, fmt.Sprintf("%s:%s -> HTTP %d (rejected)", c.User, c.Pass, resp.Status))
	}
	if !found {
		emit(LWarn, "no weak credentials accepted (or login blocks/rate-limits)")
	} else {
		emit(LCrit, "LOGIN COMPROMISED — rotate credentials and enforce strong passwords immediately")
	}
	return nil
}

type loginForm struct {
	action     string
	userField  string
	passField  string
	csrfField  string
	csrfValue  string
}

func findLoginForm(body []byte) (loginForm, error) {
	s := string(body)
	idx := strings.Index(strings.ToLower(s), "<form")
	if idx < 0 {
		return loginForm{}, fmt.Errorf("no form tag")
	}
	end := strings.Index(s[idx:], "</form>")
	if end < 0 {
		end = len(s) - idx
	}
	seg := s[idx : idx+end]
	f := loginForm{userField: "username", passField: "password"}
	if m := regexpAction.FindStringSubmatch(seg); len(m) > 1 {
		f.action = m[1]
	}
	for _, m := range regexpInput.FindAllStringSubmatch(seg, -1) {
		if len(m) < 3 {
			continue
		}
		name, typ := m[1], m[2]
		switch {
		case strings.Contains(typ, "password"):
			f.passField = name
		case strings.Contains(typ, "text") || strings.Contains(typ, "email"):
			if f.userField == "" || f.userField == "username" {
				f.userField = name
			}
		case strings.Contains(typ, "hidden") && strings.Contains(strings.ToLower(name), "csrf"):
			f.csrfField = name
			if vm := regexpValue.FindStringSubmatch(m[0]); len(vm) > 1 {
				f.csrfValue = vm[1]
			}
		case strings.Contains(typ, "hidden"):
			f.csrfField = name
			if vm := regexpValue.FindStringSubmatch(m[0]); len(vm) > 1 {
				f.csrfValue = vm[1]
			}
		}
	}
	if f.userField == "" || f.passField == "" {
		return loginForm{}, fmt.Errorf("no user/pass fields")
	}
	return f, nil
}

var regexpAction = regexp.MustCompile(`(?is)<form[^>]*action=["']([^"']*)["']`)
var regexpInput = regexp.MustCompile(`(?is)<input[^>]*name=["']([^"']*)["'][^>]*type=["']([^"']*)["']`)
var regexpValue = regexp.MustCompile(`(?is)value=["']([^"']*)["']`)

func loginSucceeded(resp *Resp) bool {
	lc := strings.ToLower(string(resp.Body))
	// The 302/303 redirect dance is the most reliable signal.
	if resp.Status == 302 || resp.Status == 303 || resp.Status == 301 {
		loc := strings.ToLower(resp.Header.Get("Location"))
		if strings.Contains(loc, "login") || strings.Contains(loc, "error") {
			return false
		}
		return true
	}
	// For 200-based logins: look for the welcome indicators.
	succ := []string{"welcome", "dashboard", "logout", "logged in", "logout.php", "panel"}
	fail := []string{"invalid", "incorrect", "wrong password", "login failed", "try again", "error"}
	hasSucc := false
	for _, s := range succ {
		if strings.Contains(lc, s) {
			hasSucc = true
			break
		}
	}
	if !hasSucc {
		return false
	}
	for _, s := range fail {
		if strings.Contains(lc, s) {
			return false
		}
	}
	return hasSucc
}

func loadCreds(path string) ([]wordlists.Cred, error) {
	lines, err := loadWordlist(path)
	if err != nil {
		return nil, err
	}
	var out []wordlists.Cred
	for _, l := range lines {
		parts := strings.SplitN(l, ":", 2)
		if len(parts) == 2 {
			out = append(out, wordlists.Cred{User: parts[0], Pass: parts[1]})
		} else if parts[0] != "" {
			out = append(out, wordlists.Cred{User: parts[0], Pass: parts[0]})
		}
	}
	return out, nil
}

// SQLiDetect scans GET parameters for SQL injection symptoms.
// It looks for DB error signatures, boolean differences and timing.
func SQLiDetect(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	emit(LHl, "sql injection scan — "+base)

	params := discoverParams(ctx, base, emit)
	if len(params) == 0 {
		emit(LWarn, "no GET parameters found to inject (try fuzzing with dirb for search forms)")
		return nil
	}
	emit(LInfo, fmt.Sprintf("%d parameter(s) to test: %s", len(params), strings.Join(params, ", ")))

	found := false
	for _, param := range params {
		if ctx.Err() != nil {
			return nil
		}
		baseline := requestParam(ctx, base, param, "1", 8*time.Second)
		if baseline == nil {
			emit(LDim, param+": baseline request failed")
			continue
		}
		trueResp := requestParam(ctx, base, param, "1' AND '1'='1", 8*time.Second)
		falseResp := requestParam(ctx, base, param, "1' AND '1'='2", 8*time.Second)

		for _, payload := range wordlists.SQLi {
			if ctx.Err() != nil {
				return nil
			}
			resp := requestParam(ctx, base, param, payload, 10*time.Second)
			if resp == nil {
				continue
			}
			lc := strings.ToLower(string(resp.Body))
			for sig, db := range wordlists.SQLiSignatures {
				if strings.Contains(lc, sig) {
					found = true
					emit(LCrit, fmt.Sprintf("[SQLI] %s=%s  -> %s error signature in response", param, payload, db))
					break
				}
			}
		}
		// Boolean-based check.
		if trueResp != nil && falseResp != nil &&
			trueResp.Status == falseResp.Status &&
			len(trueResp.Body) != len(falseResp.Body) &&
			len(trueResp.Body) != len(baseline.Body) {
			found = true
			emit(LCrit, fmt.Sprintf("[SQLI] boolean-based: param %s with payload '%s' yields a different response size (%d vs %d bytes)", param, "1' AND '1'='1", len(trueResp.Body), len(falseResp.Body)))
		}
		// Time-based check.
		start := time.Now()
		_ = requestParam(ctx, base, param, "' OR SLEEP(3)-- -", 10*time.Second)
		if time.Since(start) >= 2500*time.Millisecond {
			found = true
			emit(LCrit, fmt.Sprintf("[SQLI] time-based: SLEEP(3) payload delayed response by %s", time.Since(start).Round(100*time.Millisecond)))
		}
	}
	if !found {
		emit(LOk, "no obvious SQL injection signals detected (manual review still recommended)")
	}
	return nil
}

func discoverParams(ctx context.Context, base string, emit Emit) []string {
	r, err := Req(ctx, "GET", base, nil, nil, 10*time.Second)
	if err != nil {
		return nil
	}
	// Extract links with query strings.
	seen := map[string]bool{}
	var out []string
	for _, m := range regexpHref.FindAllStringSubmatch(string(r.Body), -1) {
		if len(m) < 2 {
			continue
		}
		href := m[1]
		if strings.HasPrefix(href, "javascript:") {
			continue
		}
		if i := strings.Index(href, "?"); i >= 0 {
			qs := href[i+1:]
			for _, kv := range strings.Split(qs, "&") {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) >= 1 && parts[0] != "" && !seen[parts[0]] {
					seen[parts[0]] = true
					out = append(out, parts[0])
				}
			}
		}
	}
	// Include the page's own query parameters.
	if u, err := url.Parse(base); err == nil && u.RawQuery != "" {
		for k := range u.Query() {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	// Fall back to the classic ones when nothing found.
	if len(out) == 0 {
		out = []string{"id", "q", "search", "name", "user", "page", "cat", "file"}
	}
	return out
}

func requestParam(ctx context.Context, base, param, value string, timeout time.Duration) *Resp {
	u := base
	if strings.Contains(base, "?") {
		u = base + "&" + url.QueryEscape(param) + "=" + url.QueryEscape(value)
	} else {
		u = base + "?" + url.QueryEscape(param) + "=" + url.QueryEscape(value)
	}
	r, err := Req(ctx, "GET", u, nil, nil, timeout)
	if err != nil {
		return nil
	}
	return r
}

var regexpHref = regexp.MustCompile(`(?is)<a[^>]+href=["']([^"']+)["']`)

// XSSDetect checks whether XSS payloads are reflected unescaped.
func XSSDetect(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	emit(LHl, "reflected xss scan — "+base)

	params := discoverParams(ctx, base, emit)
	if len(params) == 0 {
		emit(LWarn, "no parameters to test")
		return nil
	}
	emit(LInfo, fmt.Sprintf("%d parameter(s) to test: %s", len(params), strings.Join(params, ", ")))

	payloads := wordlists.XSS
	if opts.Wordlist != "" {
		if loaded, err := loadWordlist(opts.Wordlist); err == nil && len(loaded) > 0 {
			payloads = loaded
		}
	}
	found := false
	for _, param := range params {
		if ctx.Err() != nil {
			return nil
		}
		for _, payload := range payloads {
			if ctx.Err() != nil {
				return nil
			}
			resp := requestParam(ctx, base, param, payload, 10*time.Second)
			if resp == nil {
				continue
			}
			body := string(resp.Body)
			if strings.Contains(body, payload) {
				found = true
				emit(LCrit, fmt.Sprintf("[XSS] %s parameter reflects payload unescaped: %s", param, payload))
				emit(LCrit, "      confirm with: "+resp.URL)
			} else if strings.Contains(body, strings.ReplaceAll(payload, " ", "+")) {
				found = true
				emit(LCrit, fmt.Sprintf("[XSS] %s parameter reflects payload (plus-encoded): %s", param, payload))
				emit(LCrit, "      confirm with: "+resp.URL)
			}
		}
	}
	if !found {
		emit(LOk, "no unescaped reflections detected (context-dependent XSS may still exist)")
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func orElse(v, empty, full string) string {
	if v == "" {
		return empty
	}
	return full
}



