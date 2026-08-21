package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/qingethical/hacklith/internal/wordlists"
)

// NotFound is a signature that reliably means "no such resource" for a
// given target: status code plus response size/body fingerprint.
type NotFound struct {
	Status int
	Size   int
	Body   string
}

// sniffNotFound requests a random path to learn how the target renders
// 404s, so fuzzing can filter false positives.
func sniffNotFound(ctx context.Context, base string) *NotFound {
	randPath := fmt.Sprintf("hq-nf-%d-zzz.html", time.Now().UnixNano()%100000)
	r, err := Req(ctx, "GET", JoinURL(base, randPath), nil, nil, 10*time.Second)
	if err != nil {
		return nil
	}
	nf := &NotFound{Status: r.Status, Size: len(r.Body), Body: string(r.Body)}
	if nf.Size > 4096 {
		nf.Body = ""
	}
	return nf
}

// DirFuzz brute-forces directories and files, reporting interesting
// findings. opts.Wordlist may point at a newline-delimited custom list.
func DirFuzz(ctx context.Context, target string, opts Options, emit Emit) error {
	base := Normalize(target)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	words := wordlists.Dirs
	if opts.Wordlist != "" {
		loaded, err := loadWordlist(opts.Wordlist)
		if err != nil {
			emit(LWarn, "wordlist: "+err.Error())
		} else if len(loaded) > 0 {
			words = loaded
			emit(LInfo, fmt.Sprintf("using custom wordlist (%d entries)", len(words)))
		}
	}
	exts := []string{"", "/", ".php", ".html", ".txt", ".bak", ".old", ".save"}

	nf := sniffNotFound(ctx, base)
	if nf == nil {
		emit(LWarn, "could not fingerprint 404 handling; filtering will be weaker")
	} else {
		emit(LDim, fmt.Sprintf("404 baseline: status=%d size=%d", nf.Status, nf.Size))
	}

	emit(LHl, fmt.Sprintf("dir fuzz — %s (%d base words)", base, len(words)))

	var (
		mu       sync.Mutex
		found    int
		requests int
	)
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup

	check := func(path string) {
		defer wg.Done()
		if ctx.Err() != nil {
			return
		}
		sem <- struct{}{}
		defer func() { <-sem }()

		u := JoinURL(base, path)
		r, err := Req(ctx, "GET", u, nil, nil, 8*time.Second)
		if err != nil {
			return
		}
		mu.Lock()
		requests++
		mu.Unlock()

		// Filter against the custom-404 fingerprint.
		if nf != nil && r.Status == nf.Status {
			if nf.Body != "" && string(r.Body) == nf.Body {
				return
			}
			if nf.Body == "" && len(r.Body) == nf.Size {
				return
			}
		}

		switch {
		case r.Status == 200:
			mu.Lock()
			found++
			mu.Unlock()
			note := ""
			if t := PageTitle(r.Body); t != "" {
				note = "  [" + truncate(t, 40) + "]"
			}
			emit(LOk, fmt.Sprintf("%-6d %-5d %s%s", r.Status, len(r.Body), u, note))
		case r.Status == 301 || r.Status == 302 || r.Status == 303 || r.Status == 307 || r.Status == 308:
			mu.Lock()
			found++
			mu.Unlock()
			emit(LHl, fmt.Sprintf("%-6d %-5d %s  -> %s", r.Status, len(r.Body), u, r.Header.Get("Location")))
		case r.Status == 401 || r.Status == 403:
			mu.Lock()
			found++
			mu.Unlock()
			emit(LWarn, fmt.Sprintf("%-6d %-5d %s  [restricted area]", r.Status, len(r.Body), u))
		case r.Status >= 500:
			mu.Lock()
			found++
			mu.Unlock()
			emit(LCrit, fmt.Sprintf("%-6d %-5d %s  [server error — possible bug]", r.Status, len(r.Body), u))
		case r.Status == 405:
			mu.Lock()
			found++
			mu.Unlock()
			emit(LInfo, fmt.Sprintf("%-6d %-5d %s  [exists, method not allowed]", r.Status, len(r.Body), u))
		}
	}

	seen := map[string]bool{}
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" || seen[w] {
			continue
		}
		seen[w] = true
		for _, ext := range exts {
			if ctx.Err() != nil {
				break
			}
			if ext != "" && strings.ContainsAny(w, ".") && !strings.HasSuffix(w, "/") {
				continue // words that already have an extension get no extra ext
			}
			wg.Add(1)
			go check(w + ext)
		}
	}
	wg.Wait()

	if ctx.Err() != nil {
		emit(LWarn, "fuzz cancelled mid-way")
	}
	emit(LInfo, fmt.Sprintf("finished: %d requests, %d interesting response(s)", requests, found))
	return nil
}

func loadWordlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

