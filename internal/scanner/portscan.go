package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qingethical/hacklith/internal/wordlists"
)

// PortScan performs a concurrent TCP connect scan against the target.
// spec may be "common" (default), "all", "top", or a list like
// "80,443,8000-8100".
func PortScan(ctx context.Context, target, spec string, emit Emit) error {
	host := HostFromTarget(target)
	ports, err := parsePorts(spec)
	if err != nil {
		return err
	}
	emit(LInfo, fmt.Sprintf("scanning %s (%d ports, connect scan)", host, len(ports)))

	sem := make(chan struct{}, 300)
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), 900*time.Millisecond)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	if ctx.Err() != nil {
		emit(LWarn, "scan cancelled mid-way, showing partial results")
	}

	sort.Ints(open)
	for _, p := range open {
		if svc, ok := wordlists.PortServices[p]; ok {
			emit(LOk, fmt.Sprintf("open  %-6d %s", p, svc))
		} else {
			emit(LOk, fmt.Sprintf("open  %-6d unknown-service", p))
		}
	}
	if len(open) == 0 {
		emit(LWarn, "no open ports found (filtered by firewall?)")
	} else {
		emit(LInfo, fmt.Sprintf("detected %d open port(s)", len(open)))
	}
	return nil
}

func parsePorts(spec string) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "", "common":
		return wordlists.CommonPorts, nil
	case "top":
		return wordlists.TopPorts, nil
	case "all", "1-65535", "full":
		var all []int
		for i := 1; i <= 65535; i++ {
			all = append(all, i)
		}
		return all, nil
	}

	seen := map[int]bool{}
	var ports []int
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "-") {
			parts := strings.SplitN(tok, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid port range %q", tok)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(tok)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", tok)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports in %q", spec)
	}
	sort.Ints(ports)
	return ports, nil
}

