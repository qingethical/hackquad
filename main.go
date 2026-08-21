// Command hacklith is an offensive web-testing toolkit in pure Go +
// bash (no Python). Run `hacklith.sh` for the interactive terminal UI
// or `hacklith.sh --run <module> --target <url>` headlessly.
//
// Authorized use only: only scan systems you own or are contracted to
// assess.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/qingethical/hacklith/internal/cli"
	"github.com/qingethical/hacklith/internal/modules"
	"github.com/qingethical/hacklith/internal/tui"
)

func main() {
	var (
		run      = flag.String("run", "", "module to run headlessly (probe, dirb, sqli, ...)")
		target   = flag.String("target", "", "target URL or host:port")
		wordlist = flag.String("wordlist", "", "custom wordlist/creds/script path")
		ports    = flag.String("ports", "common", "port spec for portscan: common|top|all|80,443,8000-8100")
		timeout  = flag.Duration("timeout", 0, "overall timeout (e.g. 5m)")
		help     = flag.Bool("help", false, "show help")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "hacklith — offensive web testing toolkit (Go + bash, no Python)\n\n")
		fmt.Fprintf(os.Stderr, "usage:\n  hacklith.sh                      interactive terminal UI\n")
		fmt.Fprintf(os.Stderr, "  hacklith.sh --run <module> --target <url> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "modules: %v\n\n", modules.Names())
		fmt.Fprintf(os.Stderr, "flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	opts := modules.Options{Wordlist: *wordlist, Ports: *ports}
	ctx := context.Background()

	if *run != "" {
		os.Exit(cli.Run(ctx, *run, *target, opts, *timeout))
	}

	// Interactive TUI.
	if err := tui.Run(ctx, *target); err != nil {
		fmt.Fprintln(os.Stderr, "hacklith:", err)
		os.Exit(1)
	}
}


