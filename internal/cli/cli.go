// Package cli implements the headless runner: hacklith.sh --run <mod>
// executes one module and prints color-tagged lines to stdout.
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/qingethical/hacklith/internal/modules"
	"github.com/qingethical/hacklith/internal/scanner"
)

// Colors are the ANSI codes used for the terminal UI and CLI.
const (
	CReset  = "\x1b[0m"
	CBold   = "\x1b[1m"
	CDim    = "\x1b[2m"
	CRed    = "\x1b[31m"
	CGreen  = "\x1b[32m"
	CYellow = "\x1b[33m"
	CBlue   = "\x1b[34m"
	CMag    = "\x1b[35m"
	CCyan   = "\x1b[36m"
	CWhite  = "\x1b[37m"
)

// Tag returns the line tag for a level, e.g. "[+]".
func Tag(l scanner.Level) string {
	switch l {
	case scanner.LInfo:
		return "[*]"
	case scanner.LOk:
		return "[+]"
	case scanner.LWarn:
		return "[!]"
	case scanner.LCrit:
		return "[x]"
	case scanner.LDim:
		return "[~]"
	case scanner.LHl:
		return "[>]"
	}
	return "[*]"
}

// Color returns the ANSI color code for a level.
func Color(l scanner.Level) string {
	switch l {
	case scanner.LOk:
		return CGreen
	case scanner.LWarn:
		return CYellow
	case scanner.LCrit:
		return CRed + CBold
	case scanner.LDim:
		return CDim
	case scanner.LHl:
		return CCyan + CBold
	}
	return CReset
}

// Run executes a module headlessly and returns its exit code.
func Run(ctx context.Context, name, target string, opts modules.Options, timeout time.Duration) int {
	mod := modules.ByName(name)
	if mod == nil {
		fmt.Fprintf(os.Stderr, "hacklith: unknown module %q\navailable: %s\n", name, strings.Join(modules.Names(), ", "))
		return 2
	}
	if mod.NeedsTarget && target == "" {
		fmt.Fprintln(os.Stderr, "hacklith: module "+name+" requires --target")
		return 2
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	emit := func(l scanner.Level, msg string) {
		fmt.Printf("%s%s %s%s\n", Color(l), Tag(l), msg, CReset)
	}
	fmt.Printf("%s[>] hacklith — %s%s\n", Color(scanner.LHl), name, CReset)
	start := time.Now()
	if err := mod.Run(ctx, target, opts, emit); err != nil {
		fmt.Fprintf(os.Stderr, "hacklith: %s failed: %v\n", name, err)
		return 1
	}
	fmt.Printf("%s[~] %s finished in %s%s\n", CDim, name, time.Since(start).Round(time.Millisecond), CReset)
	return 0
}

