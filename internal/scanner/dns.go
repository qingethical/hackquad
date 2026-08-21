package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/qingethical/hacklith/internal/wordlists"
)

// SubEnum brute-forces subdomains via DNS A/AAAA lookups.
// Note: wildcard DNS causes false positives; the module reports them.
func SubEnum(ctx context.Context, target string, opts Options, emit Emit) error {
	domain := HostFromTarget(target)
	if domain == "" {
		return fmt.Errorf("empty target")
	}
	words := wordlists.Subdomains
	if opts.Wordlist != "" {
		if loaded, err := loadWordlist(opts.Wordlist); err == nil && len(loaded) > 0 {
			words = loaded
		}
	}
	emit(LHl, fmt.Sprintf("subdomain enumeration — %s (%d names)", domain, len(words)))

	// Detect wildcard DNS so we can warn about false positives.
	wildcard := checkWildcard(ctx, domain)
	if wildcard {
		emit(LWarn, "wildcard DNS detected — responses below may be false positives")
	}

	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 4 * time.Second}
		return d.DialContext(ctx, network, address)
	}}

	var (
		mu   sync.Mutex
		hits int
	)
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			fqdn := w + "." + domain
			ips, err := resolver.LookupHost(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				return
			}
			mu.Lock()
			hits++
			mu.Unlock()
			emit(LOk, fmt.Sprintf("%-45s %s", fqdn, strings.Join(ips, ", ")))
		}(w)
	}
	wg.Wait()
	if ctx.Err() != nil {
		emit(LWarn, "enumeration cancelled mid-way")
	}
	emit(LInfo, fmt.Sprintf("finished: %d subdomain(s) resolved", hits))
	return nil
}

func checkWildcard(ctx context.Context, domain string) bool {
	rand := fmt.Sprintf("hq-wc-%d.invalid", time.Now().UnixNano()%100000)
	ips, err := net.DefaultResolver.LookupHost(ctx, rand+"."+domain)
	return err == nil && len(ips) > 0
}

// DNSInfo gathers A, AAAA, MX, NS, TXT, CNAME and SOA records.
func DNSInfo(ctx context.Context, target string, _ Options, emit Emit) error {
	domain := HostFromTarget(target)
	if domain == "" {
		return fmt.Errorf("empty target")
	}
	resolver := &net.Resolver{PreferGo: true}
	emit(LHl, "dns records — "+domain)

	if ips, err := resolver.LookupHost(ctx, domain); err == nil {
		emit(LOk, fmt.Sprintf("A/AAAA   %s", strings.Join(ips, ", ")))
	} else {
		emit(LWarn, "A/AAAA lookup failed: "+err.Error())
	}
	if mx, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, r := range mx {
			emit(LInfo, fmt.Sprintf("MX       %-40s pref %d", r.Host, r.Pref))
		}
	} else {
		emit(LDim, "MX: "+err.Error())
	}
	if ns, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, r := range ns {
			emit(LInfo, "NS       "+r.Host)
		}
	} else {
		emit(LDim, "NS: "+err.Error())
	}
	if txt, err := resolver.LookupTXT(ctx, domain); err == nil {
		for _, r := range txt {
			emit(LInfo, "TXT      "+truncate(r, 100))
		}
	} else {
		emit(LDim, "TXT: "+err.Error())
	}
	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil && cname != "" {
		emit(LInfo, "CNAME    "+cname)
	}
	emit(LInfo, "for reverse lookups / zone transfer checks use: --run shell --target <domain> (recon_all)")
	return nil
}

