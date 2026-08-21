// Package modules defines the hacklith module registry: every
// actionable unit (probe, portscan, sqli, xss, ...) is registered here
// under a stable name usable from the TUI or headless CLI.
package modules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/qingethical/hacklith/internal/scanner"
	"github.com/qingethical/hacklith/internal/shellx"
)

// Options carries per-run knobs shared by all modules.
type Options = scanner.Options

// Module is one hacklith unit of work.
type Module struct {
	Name        string
	Desc        string
	NeedsTarget bool
	Run         func(ctx context.Context, target string, opts Options, emit scanner.Emit) error
}

// Registry is the canonical module list, in display order.
var Registry = []Module{
	{Name: "probe", Desc: "fingerprint the web server (status, headers, title, tls)", NeedsTarget: true, Run: scanner.Probe},
	{Name: "headers", Desc: "audit security-relevant response headers", NeedsTarget: true, Run: scanner.HeadersAudit},
	{Name: "cookies", Desc: "audit cookie flags (secure/httponly/samesite)", NeedsTarget: true, Run: scanner.CookieAudit},
	{Name: "methods", Desc: "test dangerous http methods (PUT/TRACE/...)", NeedsTarget: true, Run: scanner.MethodsCheck},
	{Name: "tech", Desc: "fingerprint the technology stack", NeedsTarget: true, Run: scanner.TechFingerprint},
	{Name: "portscan", Desc: "tcp connect port scan (common/top/all/1-65535)", NeedsTarget: true, Run: portScanRun},
	{Name: "dirb", Desc: "brute-force directories and files", NeedsTarget: true, Run: scanner.DirFuzz},
	{Name: "admin", Desc: "hunt admin panels and sensitive files", NeedsTarget: true, Run: scanner.AdminFind},
	{Name: "login", Desc: "probe weak credentials on login forms", NeedsTarget: true, Run: scanner.LoginProbe},
	{Name: "sqli", Desc: "sql injection scan (error/boolean/time based)", NeedsTarget: true, Run: scanner.SQLiDetect},
	{Name: "xss", Desc: "reflected xss scan on discovered parameters", NeedsTarget: true, Run: scanner.XSSDetect},
	{Name: "subenum", Desc: "subdomain brute-force via dns", NeedsTarget: true, Run: scanner.SubEnum},
	{Name: "dns", Desc: "gather dns records (a/mx/ns/txt/cname)", NeedsTarget: true, Run: scanner.DNSInfo},
	{Name: "shell", Desc: "run bundled bash helpers (recon_all, nmap_quick, ssl_check)", NeedsTarget: true, Run: shellRun},
	{Name: "about", Desc: "show hacklith banner and usage", NeedsTarget: false, Run: aboutRun},
}

// ByName returns the module with the given name, or nil.
func ByName(name string) *Module {
	for i := range Registry {
		if Registry[i].Name == name {
			return &Registry[i]
		}
	}
	return nil
}

// Names returns all module names, sorted.
func Names() []string {
	var out []string
	for _, m := range Registry {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// Alias returns the display alias for a module (uppercased short name).
func Alias(name string) string {
	if len(name) <= 4 {
		return strings.ToUpper(name)
	}
	return strings.ToUpper(name[:4])
}

func portScanRun(ctx context.Context, target string, opts Options, emit scanner.Emit) error {
	return scanner.PortScan(ctx, target, opts.Ports, emit)
}

func shellRun(ctx context.Context, target string, opts Options, emit scanner.Emit) error {
	scripts := shellx.ListScripts()
	if len(scripts) == 0 {
		emit(scanner.LWarn, "no shell scripts found under modules/shell/")
		return nil
	}
	emit(scanner.LInfo, "available shell modules: "+strings.Join(scripts, ", "))
	script := opts.Wordlist
	if script == "" {
		script = "recon_all"
	}
	if !contains(scripts, script) {
		emit(scanner.LWarn, fmt.Sprintf("script %q not found; running recon_all", script))
		script = "recon_all"
	}
	return shellx.RunScript(ctx, script, target, emit)
}

func aboutRun(ctx context.Context, _ string, _ Options, emit scanner.Emit) error {
	emit(scanner.LHl, "HACKLITH — offensive web testing toolkit (Go + bash, no python)")
	emit(scanner.LInfo, "modules: probe, headers, cookies, methods, tech, portscan, dirb, admin, login, sqli, xss, subenum, dns, shell, about")
	emit(scanner.LInfo, "usage:  hacklith.sh --run <module> --target <url> [--ports spec] [--wordlist file]")
	emit(scanner.LInfo, "        hacklith.sh                (interactive terminal UI)")
	emit(scanner.LInfo, "each module emits tagged lines: [*] info  [+] ok  [!] warn  [x] crit  [~] dim  [>] highlight")
	emit(scanner.LInfo, "authorized use only — test targets you own or are contracted to assess.")
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}




